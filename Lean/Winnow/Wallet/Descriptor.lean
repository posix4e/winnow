import Winnow.Keys
import Winnow.Tx.Multisig
import Winnow.Tx.AddressDecoder

/-! # Output descriptors (BIP380 / 386 / 387 / 389 / 390)

Port of `Sources/WalletCore/Descriptors/Descriptor.swift`: parse (with the optional `#checksum`),
canonical serialization, validation, and derivation of `tr(KEY)`, `tr(KEY,TREE)` and `rawtr(KEY)` with
`pk` / `multi_a` / `sortedmulti_a` leaves, BIP389 multipath and BIP390 `musig()` keys.

The Swift parser walks `Character`s and classifies them with `isLetter` / `isNumber`. Descriptors are
ASCII (the BIP380 charset); for other characters `isLetter`/`isNumber` here cover the Latin, Greek,
Cyrillic, CJK, Arabic-Indic, Devanagari, full-width and super/subscript/fraction ranges — enough to
classify a stray non-ASCII character the way Swift does (refused, with the same error), not a full
Unicode table. Combining sequences (multi-scalar `Character`s) are not modelled.

Tree leaves are their own type here (`Leaf`), so the Swift `invalidContext` of a `tr` nested in a
tree, which the parser can never produce, has no counterpart; `resolvedTaproot` of a `rawtr` still
throws it. -/

namespace Winnow
open Keys

inductive DescriptorError where
  | invalidChecksum | invalidCharacter | unexpectedEnd
  | unexpectedCharacter (c : Char)
  | unknownExpression (s : String)
  | invalidOrigin | originTooDeep | keyDepthExhausted | invalidKey | invalidPath | invalidThreshold
  | invalidContext | invalidMuSig | derivationFailed | treeTooDeep
  deriving Inhabited, BEq

def DescriptorError.name : DescriptorError → String
  | .invalidChecksum => "invalidChecksum" | .invalidCharacter => "invalidCharacter"
  | .unexpectedEnd => "unexpectedEnd" | .unexpectedCharacter _ => "unexpectedCharacter"
  | .unknownExpression _ => "unknownExpression" | .invalidOrigin => "invalidOrigin"
  | .originTooDeep => "originTooDeep" | .keyDepthExhausted => "keyDepthExhausted" | .invalidKey => "invalidKey"
  | .invalidPath => "invalidPath" | .invalidThreshold => "invalidThreshold" | .invalidContext => "invalidContext"
  | .invalidMuSig => "invalidMuSig" | .derivationFailed => "derivationFailed" | .treeTooDeep => "treeTooDeep"

/-- What derivation can throw: the descriptor's own errors, or those of the layers it calls (as the Swift
original lets them through). -/
inductive DescriptorFailure where
  | descriptor (e : DescriptorError)
  | taproot (e : TaprootError)
  | musig (e : MuSigError)
  | multisig (e : MultisigError)
  | bech32 (e : Bech32Error)
  deriving Inhabited

def DescriptorFailure.name : DescriptorFailure → String
  | .descriptor e => e.name | .taproot e => e.name | .musig e => e.name | .multisig e => e.name
  | .bech32 e => e.name

/-- Legacy address prefix of an extended-key network. -/
def _root_.Winnow.Keys.HDKey.Network.hrp : HDKey.Network → String | .mainnet => "bc" | .testnet => "tb"

namespace Descriptor

structure KeyOrigin where
  fingerprint : UInt32
  path : Array UInt32
  deriving Inhabited, BEq

inductive KeyBase where
  | publicKey (data : ByteArray)
  | privateKey (secret : ByteArray) (compressed : Bool) (network : HDKey.Network)
  | extended (key : HDKey) (network : HDKey.Network)
  deriving Inhabited

def KeyBase.isExtended : KeyBase → Bool | .extended .. => true | _ => false

inductive Element where
  | step (index : UInt32)
  | multipath (values : Array UInt32)
  | wildcard (hardened : Bool)
  deriving Inhabited, BEq

structure Derivation where
  elements : Array Element := #[]
  deriving Inhabited

namespace Derivation
def multipathCount (d : Derivation) : Nat :=
  match d.elements.findSome? (fun | .multipath vs => some vs.size | _ => none) with
  | some n => n
  | none => 1
def isRanged (d : Derivation) : Bool := d.elements.any fun | .wildcard _ => true | _ => false
end Derivation

structure SingleKey where
  origin : Option KeyOrigin
  base : KeyBase
  derivation : Derivation := {}
  deriving Inhabited

inductive KeyExpression where
  | single (k : SingleKey)
  | musig (participants : Array SingleKey) (derivation : Derivation)
  deriving Inhabited

inductive Leaf where
  | pk (key : KeyExpression)
  | multiA (threshold : Int) (keys : Array KeyExpression)
  | sortedMultiA (threshold : Int) (keys : Array KeyExpression)
  deriving Inhabited

inductive ScriptTree where
  | leaf (l : Leaf)
  | branch (left right : ScriptTree)
  deriving Inhabited

inductive ScriptExpression where
  | tr (key : KeyExpression) (tree : Option ScriptTree)
  | rawtr (key : KeyExpression)
  deriving Inhabited

structure DerivedOutput where
  scriptPubKey : ByteArray
  address : String
  deriving Inhabited

/-! ## BIP380 checksum -/

namespace Checksum

def inputCharset : List UInt8 :=
  "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ".toUTF8.toList
def checksumCharset : List UInt8 := "qpzry9x8gf2tvdw0s3jn54khce6mua7l".toUTF8.toList
def generator : List UInt64 := [0xF5DE_E519_89, 0xA9FD_CA33_12, 0x1BAB_10E3_2D, 0x3706_B167_7A, 0x644D_626F_FD]

def polymod (symbols : List UInt64) : UInt64 := Id.run do
  let mut chk : UInt64 := 1
  for value in symbols do
    let top := chk >>> 35
    chk := ((chk &&& 0x7_FFFF_FFFF) <<< 5) ^^^ value
    for h : i in [0:5] do
      if (top >>> i.toUInt64) &&& 1 == 1 then chk := chk ^^^ generator[i]!
  return chk

def expand (s : String) : Option (List UInt64) := Id.run do
  let mut groups : Array UInt64 := #[]
  let mut symbols : Array UInt64 := #[]
  for byte in s.toUTF8.toList do
    let some position := inputCharset.idxOf? byte | return none
    symbols := symbols.push (position % 32).toUInt64
    groups := groups.push (position / 32).toUInt64
    if groups.size == 3 then
      symbols := symbols.push (groups[0]! * (9 : UInt64) + groups[1]! * (3 : UInt64) + groups[2]!)
      groups := #[]
  if groups.size == 1 then symbols := symbols.push groups[0]!
  else if groups.size == 2 then symbols := symbols.push (groups[0]! * (3 : UInt64) + groups[1]!)
  return some symbols.toList

def verify (body checksum : String) : Bool :=
  match expand body with
  | none => false
  | some symbols =>
    let cs := checksum.toUTF8.toList
    if !cs.all checksumCharset.contains then false
    else polymod (symbols ++ cs.map fun b => (checksumCharset.idxOf b).toUInt64) == 1

def create (body : String) : String :=
  match expand body with
  | none => ""
  | some symbols =>
    let c := polymod (symbols ++ List.replicate 8 0) ^^^ 1
    String.ofList ((List.range 8).map fun i =>
      Char.ofNat (checksumCharset[((c >>> (5 * (7 - i)).toUInt64) &&& 31).toNat]!).toNat)

end Checksum

/-! ## Character classes (`Character.isLetter` / `isNumber`) -/

def inRanges (n : Nat) (rs : List (Nat × Nat)) : Bool := rs.any fun (a, b) => a ≤ n && n ≤ b

def isLetter (c : Char) : Bool :=
  let n := c.toNat
  if n < 0x80 then ('a' ≤ c && c ≤ 'z') || ('A' ≤ c && c ≤ 'Z')
  else inRanges n [(0xAA, 0xAA), (0xB5, 0xB5), (0xBA, 0xBA), (0xC0, 0xD6), (0xD8, 0xF6), (0xF8, 0x2C1),
    (0x2C6, 0x2D1), (0x2E0, 0x2E4), (0x370, 0x374), (0x376, 0x377), (0x37A, 0x37D), (0x386, 0x386),
    (0x388, 0x3FF), (0x400, 0x481), (0x48A, 0x52F), (0x2160, 0x2188), (0x4E00, 0x9FFF)]

def isNumber (c : Char) : Bool :=
  let n := c.toNat
  if n < 0x80 then '0' ≤ c && c ≤ '9'
  else inRanges n [(0xB2, 0xB3), (0xB9, 0xB9), (0xBC, 0xBE), (0x660, 0x669), (0x6F0, 0x6F9), (0x966, 0x96F),
    (0x2070, 0x2070), (0x2074, 0x2079), (0x2080, 0x2089), (0x2150, 0x2189), (0x2460, 0x249B), (0xFF10, 0xFF19)]

def isHexLetterOrDigit (c : Char) : Bool := isLetter c || isNumber c

/-- Swift's `UInt32(text, radix:)`: an optional sign, then digits of the radix; `-` only for zero. -/
def parseRadix (s : String) (radix : Nat) : Option Nat := Id.run do
  let cs := s.toList
  let (neg, digits) := match cs with
    | '+' :: r => (false, r)
    | '-' :: r => (true, r)
    | r => (false, r)
  if digits.isEmpty then return none
  let mut v := 0
  for c in digits do
    let d? : Option Nat :=
      if '0' ≤ c && c ≤ '9' then some (c.toNat - '0'.toNat)
      else if 'a' ≤ c && c ≤ 'z' then some (c.toNat - 'a'.toNat + 10)
      else if 'A' ≤ c && c ≤ 'Z' then some (c.toNat - 'A'.toNat + 10)
      else none
    match d? with
    | some d => if d < radix then v := v * radix + d else return none
    | none => return none
  if neg && v != 0 then return none
  return some v

/-! ## Parser -/

structure P where
  cs : Array Char
  i : Nat

abbrev PM := StateT P (Except DescriptorError)

def atEnd : PM Bool := do let s ← get; return s.i ≥ s.cs.size
def peek : PM (Option Char) := do let s ← get; return s.cs[s.i]?

def consume (c : Char) : PM Bool := do
  let s ← get
  if s.cs[s.i]? == some c then set { s with i := s.i + 1 }; return true
  return false

def consumeStr (t : String) : PM Bool := do
  let s ← get
  let ts := t.toList.toArray
  if s.i + ts.size ≤ s.cs.size && (s.cs.extract s.i (s.i + ts.size)) == ts then
    set { s with i := s.i + ts.size }; return true
  return false

def expect (c : Char) : PM Unit := do
  unless ← consume c do
    match ← peek with
    | none => throw .unexpectedEnd
    | some x => throw (.unexpectedCharacter x)

def takeWhile (p : Char → Bool) : PM String := do
  let s ← get
  let mut j := s.i
  while h : j < s.cs.size do
    if p s.cs[j] then j := j + 1 else break
  set { s with i := j }
  return String.ofList (s.cs.extract s.i j).toList

def take (n : Nat) : PM (Option String) := do
  let s ← get
  if s.cs.size - s.i < n then return none
  set { s with i := s.i + n }
  return some (String.ofList (s.cs.extract s.i (s.i + n)).toList)

def maximumTreeDepth : Nat := 128
def maximumOriginSteps : Nat := 255

def parsePathStep : PM UInt32 := do
  let digits ← takeWhile isNumber
  let value? := if digits.toList.all (fun c => '0' ≤ c && c ≤ '9') then parseRadix digits 10 else none
  let some value := value? | throw .invalidPath
  unless value < HDKey.hardenedOffset.toNat do throw .invalidPath
  let hardened ← (do if ← consume '\'' then pure true else consume 'h')
  return (value + (if hardened then HDKey.hardenedOffset.toNat else 0)).toUInt32

def parseDerivation : PM Derivation := do
  let mut elements : Array Element := #[]
  let mut sawMultipath := false
  while ← consume '/' do
    if ← consume '*' then
      let hardened ← (do if ← consume '\'' then pure true else consume 'h')
      elements := elements.push (.wildcard hardened)
      if ← consume '/' then throw .invalidPath
    else if ← consume '<' then
      if sawMultipath then throw .invalidPath
      sawMultipath := true
      let mut values := #[← parsePathStep]
      while ← consume ';' do values := values.push (← parsePathStep)
      expect '>'
      unless values.size ≥ 2 do throw .invalidPath
      elements := elements.push (.multipath values)
    else
      elements := elements.push (.step (← parsePathStep))
  return { elements }

def parseOrigin : PM (Option KeyOrigin) := do
  unless ← consume '[' do return none
  let some text ← take 8 | throw .invalidOrigin
  let some fingerprint := parseRadix text 16 | throw .invalidOrigin
  if fingerprint ≥ 2 ^ 32 then throw .invalidOrigin
  let mut path : Array UInt32 := #[]
  while ← consume '/' do
    if (← peek) == some '*' then throw .invalidOrigin
    unless path.size < maximumOriginSteps do throw .originTooDeep
    path := path.push (← parsePathStep)
  expect ']'
  return some { fingerprint := fingerprint.toUInt32, path }

def rawPublicKey (data : ByteArray) : Except DescriptorError KeyBase := do
  if data.size == 33 && !(data[0]! == 0x02 || data[0]! == 0x03) then throw .invalidKey
  if data.size == 65 && data[0]! != 0x04 then throw .invalidKey
  return .publicKey data

def wifPrivateKey (token : String) : Except DescriptorError KeyBase := do
  let payload ← match Base58Check.decode token with
    | .ok p => pure p
    | .error _ => throw .invalidKey
  unless (payload.size == 33 || payload.size == 34) && (payload[0]! == 0x80 || payload[0]! == 0xEF) do
    throw .invalidKey
  let network : HDKey.Network := if payload[0]! == 0x80 then .mainnet else .testnet
  let secret := payload.extract 1 33
  if payload.size == 34 then
    unless payload[33]! == 0x01 do throw .invalidKey
    return .privateKey secret true network
  return .privateKey secret false network

/-- `Data(hex:)` on a token of letters and digits. -/
def tokenHex? (t : String) : Option ByteArray :=
  if t.toList.all (fun c => c.toNat < 0x80) then Wire.dataOfHex? t else none

def parseKeyBase : PM KeyBase := do
  let token ← takeWhile isHexLetterOrDigit
  if token.isEmpty then throw .invalidKey
  if let some data := tokenHex? token then
    if [32, 33, 65].contains data.size then return ← StateT.lift (rawPublicKey data)
  if token.startsWith "xpub" || token.startsWith "xprv" || token.startsWith "tpub" || token.startsWith "tprv" then
    let key ← match HDKey.deserialize token with
      | .ok k => pure k
      | .error _ => throw .invalidKey
    return .extended key (if token.startsWith "t" then .testnet else .mainnet)
  StateT.lift (wifPrivateKey token)

def parseSingle : PM SingleKey := do
  let origin ← parseOrigin
  let base ← parseKeyBase
  let derivation ← parseDerivation
  if !base.isExtended && !derivation.elements.isEmpty then throw .invalidPath
  return { origin, base, derivation }

def parseKeyExpression : PM KeyExpression := do
  let s0 ← get
  let origin ← parseOrigin
  if ← consumeStr "musig(" then
    let mut participants : Array SingleKey := #[]
    repeat
      participants := participants.push (← parseSingle)
      unless ← consume ',' do break
    expect ')'
    if origin.isSome then throw .invalidMuSig
    return .musig participants (← parseDerivation)
  -- not musig: the origin parsed above belongs to a single key
  set s0
  return .single (← parseSingle)

partial def parseTree (depth : Nat := 0) : PM ScriptTree := do
  unless depth ≤ maximumTreeDepth do throw .treeTooDeep
  if ← consume '{' then
    let left ← parseTree (depth + 1)
    expect ','
    let right ← parseTree (depth + 1)
    expect '}'
    return .branch left right
  let name ← takeWhile fun c => isLetter c || c == '_'
  expect '('
  match name with
  | "pk" =>
    let key ← parseKeyExpression
    expect ')'
    return .leaf (.pk key)
  | "multi_a" | "sortedmulti_a" =>
    let thresholdText ← takeWhile isNumber
    let threshold? : Option Int :=
      if thresholdText.toList.all (fun c => '0' ≤ c && c ≤ '9') then
        (parseRadix thresholdText 10).bind fun v => if v < 2 ^ 63 then some (v : Int) else none
      else none
    let some threshold := threshold? | throw .invalidThreshold
    let mut keys : Array KeyExpression := #[]
    while ← consume ',' do keys := keys.push (← parseKeyExpression)
    expect ')'
    unless threshold ≥ 1 && threshold ≤ keys.size && keys.size ≤ Multisig.maxKeys do throw .invalidThreshold
    return .leaf (if name == "multi_a" then .multiA threshold keys else .sortedMultiA threshold keys)
  | _ => throw (.unknownExpression name)

def parseTopLevel : PM ScriptExpression := do
  let name ← takeWhile fun c => isLetter c || c == '_'
  expect '('
  match name with
  | "tr" =>
    let key ← parseKeyExpression
    let tree ← if ← consume ',' then some <$> parseTree else pure none
    expect ')'
    return .tr key tree
  | "rawtr" =>
    let key ← parseKeyExpression
    expect ')'
    return .rawtr key
  | _ => throw (.unknownExpression name)

end Descriptor

structure Descriptor where
  expression : Descriptor.ScriptExpression
  deriving Inhabited

namespace Descriptor

partial def collectKeys : ScriptTree → Array KeyExpression
  | .leaf (.pk k) => #[k]
  | .leaf (.multiA _ ks) | .leaf (.sortedMultiA _ ks) => ks
  | .branch l r => collectKeys l ++ collectKeys r

def allKeys (d : Descriptor) : Array KeyExpression :=
  match d.expression with
  | .tr k t => #[k] ++ (t.map collectKeys).getD #[]
  | .rawtr k => #[k]

def keyCounts : KeyExpression → Array Nat
  | .single s => #[s.derivation.multipathCount]
  | .musig ps d => ps.map (·.derivation.multipathCount) |>.push d.multipathCount

def validate (d : Descriptor) : Except DescriptorError Unit := do
  for key in d.allKeys do
    let .musig participants derivation := key | continue
    for e in derivation.elements do
      match e with
      | .step s => if s ≥ HDKey.hardenedOffset then throw .invalidMuSig
      | .multipath vs => if vs.any (· ≥ HDKey.hardenedOffset) then throw .invalidMuSig
      | .wildcard true => throw .invalidMuSig
      | _ => pure ()
    if !derivation.elements.isEmpty then
      for p in participants do
        unless p.base.isExtended && !p.derivation.isRanged && p.derivation.multipathCount == 1 do throw .invalidMuSig
  let counts := (d.allKeys.flatMap keyCounts).filter (· > 1)
  if let some first := counts[0]? then
    if counts.any (· != first) then throw .invalidPath

def multipathCount (d : Descriptor) : Nat := (d.allKeys.flatMap keyCounts).foldl max 1

/-- `Descriptor(_:)`: parse, with the `#checksum` (when present) validated. -/
def parse (string : String) : Except DescriptorError Descriptor := do
  let cs := string.toList.toArray
  let mut body := cs
  if let some sep := (cs.toList.zipIdx.filter (·.1 == '#')).getLast?.map (·.2) then
    let checksum := cs.extract (sep + 1) cs.size
    unless checksum.size == 8 do throw .invalidChecksum
    body := cs.extract 0 sep
    unless Checksum.verify (String.ofList body.toList) (String.ofList checksum.toList) do throw .invalidChecksum
  let (expression, st) ← parseTopLevel.run ⟨body, 0⟩
  if let some c := st.cs[st.i]? then throw (.unexpectedCharacter c)
  let d : Descriptor := { expression }
  d.validate
  return d

/-! ## Serializer -/

def stepText (s : UInt32) : String :=
  s!"{(s &&& ~~~HDKey.hardenedOffset).toNat}{if s ≥ HDKey.hardenedOffset then "'" else ""}"

def serializeDerivation (d : Derivation) : String :=
  String.join (d.elements.toList.map fun
    | .step s => "/" ++ stepText s
    | .multipath vs => "/<" ++ ";".intercalate (vs.toList.map stepText) ++ ">"
    | .wildcard h => if h then "/*'" else "/*")

def hex8 (n : UInt32) : String :=
  let h := String.ofList (Nat.toDigits 16 n.toNat)
  String.ofList (List.replicate (8 - h.length) '0') ++ h

def serializeSingle (k : SingleKey) : String :=
  let origin := match k.origin with
    | some o => "[" ++ hex8 o.fingerprint ++ String.join (o.path.toList.map ("/" ++ stepText ·)) ++ "]"
    | none => ""
  let base := match k.base with
    | .publicKey data => hex data
    | .privateKey secret compressed network =>
      let payload := ByteArray.mk #[if network == .mainnet then 0x80 else 0xEF] ++ secret
      Base58Check.encode (if compressed then payload.push 0x01 else payload)
    | .extended key network => key.serialized network
  origin ++ base ++ serializeDerivation k.derivation

def serializeKey : KeyExpression → String
  | .single s => serializeSingle s
  | .musig ps d => "musig(" ++ ",".intercalate (ps.toList.map serializeSingle) ++ ")" ++ serializeDerivation d

def serializeLeaf : Leaf → String
  | .pk k => s!"pk({serializeKey k})"
  | .multiA t ks => s!"multi_a({t},{",".intercalate (ks.toList.map serializeKey)})"
  | .sortedMultiA t ks => s!"sortedmulti_a({t},{",".intercalate (ks.toList.map serializeKey)})"

partial def serializeTree : ScriptTree → String
  | .leaf l => serializeLeaf l
  | .branch l r => "{" ++ serializeTree l ++ "," ++ serializeTree r ++ "}"

def serializeExpression : ScriptExpression → String
  | .tr k (some t) => s!"tr({serializeKey k},{serializeTree t})"
  | .tr k none => s!"tr({serializeKey k})"
  | .rawtr k => s!"rawtr({serializeKey k})"

/-- Canonical text with a freshly computed checksum. -/
def serialized (d : Descriptor) : String :=
  let body := serializeExpression d.expression
  body ++ "#" ++ Checksum.create body

def isRanged (d : Descriptor) : Bool :=
  d.allKeys.any fun
    | .single s => s.derivation.isRanged
    | .musig ps dv => dv.isRanged || ps.any (·.derivation.isRanged)

/-! ## Derivation -/

abbrev DM := Except DescriptorFailure

def dErr {α} (e : DescriptorError) : DM α := throw (.descriptor e)

def apply (derivation : Derivation) (key : HDKey) (index : UInt32) (choice : Nat) : DM HDKey := do
  let mut key := key
  for e in derivation.elements do
    let r : Except BIP32Error HDKey ← match e with
      | .step s => pure (key.child s)
      | .multipath vs => pure (key.child vs[choice]!)
      | .wildcard hardened =>
        unless index < HDKey.hardenedOffset do dErr .invalidPath
        pure (key.child (index + (if hardened then HDKey.hardenedOffset else 0)))
    match r with
    | .ok k => key := k
    | .error .depthExhausted => dErr .keyDepthExhausted
    | .error _ => dErr .derivationFailed
  return key

def deriveSingle (k : SingleKey) (index : UInt32) (choice : Nat) : DM KeyBase := do
  match k.base with
  | .extended key network => return .extended (← apply k.derivation key index choice) network
  | base =>
    unless k.derivation.elements.isEmpty do dErr .invalidPath
    return base

def compressed : KeyBase → DM ByteArray
  | .publicKey data =>
    if data.size == 33 then pure data
    else if data.size == 32 then pure (ByteArray.mk #[0x02] ++ data)
    else dErr .invalidKey
  | .privateKey secret c _ => do
    unless c do dErr .invalidKey
    match publicKeyOf secret with
    | .ok pub => pure pub
    | .error _ => dErr .invalidKey
  | .extended key _ => pure key.publicKey

def xonly (k : ByteArray) : ByteArray := k.extract 1 k.size

def resolveKey (key : KeyExpression) (index : UInt32) (choice : Nat) : DM ByteArray := do
  match key with
  | .single s => compressed (← deriveSingle s index choice)
  | .musig ps derivation =>
    let keys ← ps.mapM fun p => do compressed (← deriveSingle p index choice)
    let aggregate ← (MuSig.aggregate (MuSig.keySort keys.toList)).mapError .musig
    if derivation.elements.isEmpty then return aggregate
    let synthetic ← (MuSig.syntheticExtendedKey aggregate).mapError .musig
    return (← apply derivation synthetic index choice).publicKey

def resolveLeaf (l : Leaf) (index : UInt32) (choice : Nat) : DM ByteArray := do
  match l with
  | .pk key =>
    let k := xonly (← resolveKey key index choice)
    return (Script.build fun s => (s.appendPush k).appendOpcode Script.Op.checkSig).bytes
  | .multiA t keys =>
    let xs ← keys.mapM fun k => do pure (xonly (← resolveKey k index choice))
    return (← (Multisig.script t xs false).mapError .multisig).bytes
  | .sortedMultiA t keys =>
    let xs ← keys.mapM fun k => do pure (xonly (← resolveKey k index choice))
    return (← (Multisig.script t xs true).mapError .multisig).bytes

partial def resolveTree (t : ScriptTree) (index : UInt32) (choice : Nat) : DM Taproot.Tree := do
  match t with
  | .leaf l => return .leaf Taproot.leafVersion (← resolveLeaf l index choice)
  | .branch a b => return .branch (← resolveTree a index choice) (← resolveTree b index choice)

def resolveExpression (e : ScriptExpression) (index : UInt32) (choice : Nat) : DM ByteArray := do
  match e with
  | .tr key tree =>
    let internal := xonly (← resolveKey key index choice)
    let root ← match tree with
      | some t => pure (some (Taproot.merkleRoot (← resolveTree t index choice)))
      | none => pure none
    (Taproot.scriptPubKey internal root).mapError .taproot
  | .rawtr key => return ByteArray.mk #[0x51, 0x20] ++ xonly (← resolveKey key index choice)

/-- The output(s) at `index`, one per multipath choice, with the Bitcoin network's address prefix. -/
def derived (d : Descriptor) (index : UInt32) (network : Tx.BitcoinNetwork) : DM (Array DerivedOutput) := do
  let mut out := #[]
  for choice in [0:d.multipathCount] do
    let spk ← resolveExpression d.expression index choice
    let program := spk.extract (spk.size - min 32 spk.size) spk.size
    let address ← (SegwitAddress.encode (AddressDecoder.hrp network) 1 program).mapError .bech32
    out := out.push { scriptPubKey := spk, address }
  return out

/-- `derived(index:network:)` for extended-key networks (testnet keys ↦ signet addresses). -/
def derivedForKeyNetwork (d : Descriptor) (index : UInt32) (network : HDKey.Network := .mainnet) : DM (Array DerivedOutput) :=
  d.derived index (if network == .mainnet then .mainnet else .signet)

/-- The `tr()` internal key and resolved script tree at (`index`, `choice`). -/
def resolvedTaproot (d : Descriptor) (index : UInt32) (choice : Nat := 0) : DM (ByteArray × Option Taproot.Tree) := do
  let .tr key tree := d.expression | dErr .invalidContext
  let internal := xonly (← resolveKey key index choice)
  let t ← match tree with
    | some t => pure (some (← resolveTree t index choice))
    | none => pure none
  return (internal, t)

/-- A key expression's compressed public key at (`index`, `choice`). -/
def publicKey (key : KeyExpression) (index : UInt32) (choice : Nat := 0) : DM ByteArray :=
  resolveKey key index choice

end Descriptor
end Winnow
