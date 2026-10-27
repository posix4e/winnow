import Winnow.Bytes

/-! # Reading a JSON object the way Foundation's `JSONDecoder` does

`CensusSignature.decode` hands untrusted bytes to `JSONDecoder`, which is not a strict RFC 8259 parser.
Measured against it (macOS 27), its scanner:

* detects UTF-16/UTF-32 from a byte-order mark or from the pattern of zero bytes, and skips a UTF-8 BOM;
* allows a trailing comma in objects and arrays; whitespace is space, tab, CR and LF only;
* scans numbers loosely (a `-` or digit, then any of `0-9 . e E + -`) and literals exactly;
* scans strings lazily: a backslash skips the next byte (`\u` skips five), nothing else is checked, until
  a string is actually decoded; the keys of the top-level object are always decoded;
* decodes strings strictly: the escapes of RFC 8259 (`\u` with surrogate pairs), no raw control
  characters, well-formed UTF-8;
* nests at most 512 containers deep;
* takes the first of duplicate keys.

`members` returns the top-level object's keys with, for string values, the raw bytes between the
quotes (decoded with `decodeString` when used). -/

namespace Winnow.Keys.FoundationJSON

def isWS (c : UInt8) : Bool := c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D

def pushUTF8 (out : ByteArray) (v : Nat) : ByteArray :=
  if v < 0x80 then out.push v.toUInt8
  else if v < 0x800 then (out.push (0xC0 ||| (v >>> 6)).toUInt8).push (0x80 ||| (v &&& 0x3F)).toUInt8
  else if v < 0x10000 then
    ((out.push (0xE0 ||| (v >>> 12)).toUInt8).push (0x80 ||| ((v >>> 6) &&& 0x3F)).toUInt8).push (0x80 ||| (v &&& 0x3F)).toUInt8
  else
    (((out.push (0xF0 ||| (v >>> 18)).toUInt8).push (0x80 ||| ((v >>> 12) &&& 0x3F)).toUInt8).push
      (0x80 ||| ((v >>> 6) &&& 0x3F)).toUInt8).push (0x80 ||| (v &&& 0x3F)).toUInt8

def utf16 (d : ByteArray) (bigEndian : Bool) : Option ByteArray := Id.run do
  if d.size % 2 != 0 then return none
  let unit (i : Nat) : Nat :=
    if bigEndian then d[2 * i]!.toNat * 256 + d[2 * i + 1]!.toNat else d[2 * i + 1]!.toNat * 256 + d[2 * i]!.toNat
  let n := d.size / 2
  let mut out := ByteArray.empty
  let mut i := 0
  while i < n do
    let u := unit i
    if 0xD800 ≤ u && u < 0xDC00 then
      if i + 1 < n && 0xDC00 ≤ unit (i + 1) && unit (i + 1) < 0xE000 then
        out := pushUTF8 out (0x10000 + (u - 0xD800) * 0x400 + (unit (i + 1) - 0xDC00)); i := i + 2
      else return none
    else if 0xDC00 ≤ u && u < 0xE000 then return none
    else out := pushUTF8 out u; i := i + 1
  return some out

def utf32 (d : ByteArray) (bigEndian : Bool) : Option ByteArray := Id.run do
  if d.size % 4 != 0 then return none
  let mut out := ByteArray.empty
  for i in [0:d.size / 4] do
    let v := if bigEndian then readBE d (4 * i) 4 else readLE d (4 * i) 4
    let v := v.toNat
    if v ≥ 0x110000 || (0xD800 ≤ v && v < 0xE000) then return none
    out := pushUTF8 out v
  return some out

def startsWith (d : ByteArray) (p : List UInt8) : Bool := d.size ≥ p.length && (d.extract 0 p.length).toList == p

/-- The document as UTF-8 bytes (encoding detection as `JSONDecoder` does it). -/
def transcode (d : ByteArray) : Option ByteArray :=
  if d.size ≥ 4 && startsWith d [0xEF, 0xBB, 0xBF] then some (d.extract 3 d.size)
  else if d.size ≥ 4 && startsWith d [0, 0, 0xFE, 0xFF] then utf32 (d.extract 4 d.size) true
  else if d.size ≥ 4 && startsWith d [0xFF, 0xFE] then utf16 (d.extract 2 d.size) false
  else if d.size ≥ 4 && startsWith d [0xFE, 0xFF] then utf16 (d.extract 2 d.size) true
  else if d.size ≥ 4 then
    let (a, b, c, e) := (d[0]!, d[1]!, d[2]!, d[3]!)
    if a == 0 && b == 0 && c == 0 then utf32 d true
    else if b == 0 && c == 0 && e == 0 then utf32 d false
    else if a == 0 && c == 0 then utf16 d true
    else if b == 0 && e == 0 then utf16 d false
    else some d
  else if d.size ≥ 2 then
    if d[0]! == 0 then utf16 d true else if d[1]! == 0 then utf16 d false else some d
  else some d

def maxDepth : Nat := 512

partial def skipWS (b : ByteArray) (i : Nat) : Nat := if i < b.size && isWS b[i]! then skipWS b (i + 1) else i

/-- Lazy string scan from just after the opening quote: the position after the closing quote. -/
partial def scanString (b : ByteArray) (i : Nat) : Option Nat :=
  if i ≥ b.size then none
  else
    let c := b[i]!
    if c == 0x22 then some (i + 1)
    else if c == 0x5C then
      if i + 1 < b.size && b[i + 1]! == 0x75 then scanString b (i + 6) else scanString b (i + 2)
    else scanString b (i + 1)

def isNumberByte (c : UInt8) : Bool :=
  (0x30 ≤ c && c ≤ 0x39) || c == 0x2E || c == 0x65 || c == 0x45 || c == 0x2B || c == 0x2D

partial def skipNumber (b : ByteArray) (i : Nat) : Nat := if i < b.size && isNumberByte b[i]! then skipNumber b (i + 1) else i

def literal (b : ByteArray) (i : Nat) (s : String) : Option Nat :=
  let l := s.toUTF8
  if b.size ≥ i + l.size && b.extract i (i + l.size) == l then some (i + l.size) else none

mutual
/-- One value starting at `i` (no leading whitespace), inside `depth` containers. -/
partial def scanValue (b : ByteArray) (i depth : Nat) : Option Nat :=
  if i ≥ b.size then none else
  let c := b[i]!
  if c == 0x22 then scanString b (i + 1)
  else if c == 0x7B then scanObject b (i + 1) (depth + 1)
  else if c == 0x5B then scanArray b (i + 1) (depth + 1)
  else if c == 0x74 then literal b i "true"
  else if c == 0x66 then literal b i "false"
  else if c == 0x6E then literal b i "null"
  else if c == 0x2D || (0x30 ≤ c && c ≤ 0x39) then some (skipNumber b (i + 1))
  else none

partial def scanObject (b : ByteArray) (i depth : Nat) : Option Nat :=
  if depth > maxDepth then none else
  let i := skipWS b i
  if b[i]? == some 0x7D then some (i + 1)
  else if b[i]? == some 0x22 then do
    let i ← scanString b (i + 1)
    let i := skipWS b i
    if b[i]? != some 0x3A then none
    let i ← scanValue b (skipWS b (i + 1)) depth
    let i := skipWS b i
    if b[i]? == some 0x2C then scanObject b (i + 1) depth
    else if b[i]? == some 0x7D then some (i + 1)
    else none
  else none

partial def scanArray (b : ByteArray) (i depth : Nat) : Option Nat :=
  if depth > maxDepth then none else
  let i := skipWS b i
  if b[i]? == some 0x5D then some (i + 1)
  else do
    let i ← scanValue b i depth
    let i := skipWS b i
    if b[i]? == some 0x2C then scanArray b (i + 1) depth
    else if b[i]? == some 0x5D then some (i + 1)
    else none
end

def hexVal (c : UInt8) : Option Nat :=
  if 0x30 ≤ c && c ≤ 0x39 then some (c.toNat - 0x30)
  else if 0x61 ≤ c && c ≤ 0x66 then some (c.toNat - 0x61 + 10)
  else if 0x41 ≤ c && c ≤ 0x46 then some (c.toNat - 0x41 + 10)
  else none

def hex4 (b : ByteArray) (i : Nat) : Option Nat :=
  if i + 4 > b.size then none else
  (List.range 4).foldlM (fun acc k => return acc * 16 + (← hexVal b[i + k]!)) 0

/-- Strict decoding of the bytes between a string's quotes. -/
def decodeString (raw : ByteArray) : Option String := Id.run do
  let mut out := ByteArray.empty
  let mut i := 0
  while i < raw.size do
    let c := raw[i]!
    if c < 0x20 then return none
    if c != 0x5C then
      out := out.push c; i := i + 1
    else
      if i + 1 ≥ raw.size then return none
      let e := raw[i + 1]!
      if e == 0x75 then
        let some v := hex4 raw (i + 2) | return none
        if 0xD800 ≤ v && v < 0xDC00 then
          if !(i + 7 < raw.size && raw[i + 6]! == 0x5C && raw[i + 7]! == 0x75) then return none
          let some w := hex4 raw (i + 8) | return none
          if !(0xDC00 ≤ w && w < 0xE000) then return none
          out := pushUTF8 out (0x10000 + (v - 0xD800) * 0x400 + (w - 0xDC00)); i := i + 12
        else if 0xDC00 ≤ v && v < 0xE000 then return none
        else out := pushUTF8 out v; i := i + 6
      else
        let r : Option UInt8 :=
          if e == 0x22 then some 0x22 else if e == 0x5C then some 0x5C else if e == 0x2F then some 0x2F
          else if e == 0x62 then some 0x08 else if e == 0x66 then some 0x0C else if e == 0x6E then some 0x0A
          else if e == 0x72 then some 0x0D else if e == 0x74 then some 0x09 else none
        match r with
        | some x => out := out.push x; i := i + 2
        | none => return none
  return String.fromUTF8? out

/-- A top-level member's value: the raw bytes of a string, or `none` for any other value. -/
abbrev Member := String × Option ByteArray

partial def membersLoop (b : ByteArray) (i : Nat) (acc : Array Member) : Option (Array Member × Nat) := do
  let i := skipWS b i
  if b[i]? == some 0x7D then return (acc, i + 1)
  if b[i]? != some 0x22 then none
  let kEnd ← scanString b (i + 1)
  let key ← decodeString (b.extract (i + 1) (kEnd - 1))
  let j := skipWS b kEnd
  if b[j]? != some 0x3A then none
  let j := skipWS b (j + 1)
  let vEnd ← scanValue b j 1
  let v := if b[j]? == some 0x22 then some (b.extract (j + 1) (vEnd - 1)) else none
  let acc := acc.push (key, v)
  let k := skipWS b vEnd
  if b[k]? == some 0x2C then membersLoop b (k + 1) acc
  else if b[k]? == some 0x7D then return (acc, k + 1)
  else none

/-- The members of a document whose top-level value is an object; `none` when the document does not
scan, or its top-level value is not an object. -/
def members (data : ByteArray) : Option (Array Member) := do
  let b ← transcode data
  let i := skipWS b 0
  if b[i]? != some 0x7B then none
  let (ms, e) ← membersLoop b (i + 1) #[]
  if skipWS b e != b.size then none
  return ms

/-- `decode(String.self, forKey:)`: the first member with that key, which must be a string. -/
def stringField (ms : Array Member) (key : String) : Option String := do
  let (_, v) ← ms.find? (·.1 == key)
  decodeString (← v)

end Winnow.Keys.FoundationJSON
