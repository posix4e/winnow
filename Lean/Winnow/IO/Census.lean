import Winnow.IO.Diversity
import Winnow.Keys.Census

/-! # The census peer list (`Network/Peers/CensusCatalog.swift`, `CensusCatalogStore.swift`)

Untrusted discovery input: a signed daily list of reachable nodes (`peers.json` + `peers.json.sig`,
the signature being the Keys area's `CensusSignature`). Validation keeps the clearnet array only:
schema 1, a strict `yyyy-MM-dd` UTC date no newer than today (and, when fresh is required, at most
7 days old), a positive tip; entries on port 8333 with a printable user agent ≤ 256 bytes, a numeric
public host (canonicalized: IPv4-mapped IPv6 collapses to IPv4, IPv6 is printed as `inet_ntop` does),
within 100 blocks of the tip, unique by endpoint and by netblock; sorted by (host, port).

The store keeps the original bytes and the signature beside them (atomic writes) and verifies both on
every load. The fetch of a fresh list is the routed HTTP client (`CensusCatalog.endpoint`); it is not
exercised by the tests (no network). -/

namespace Winnow.IO
open Winnow.Net Lean

structure CensusEntry where
  host : String
  port : UInt16
  userAgent : String
  startHeight : Int32
  deriving BEq, Inhabited, Repr

def CensusEntry.endpoint (e : CensusEntry) : PeerEndpoint := { host := e.host, port := e.port }

structure CensusCatalog where
  schemaVersion : Int := 1
  date : String
  tip : Int32
  /-- Network name → entries, in the order the JSON lists them. -/
  networks : Array (String × Array CensusEntry)
  deriving BEq, Inhabited, Repr

inductive CensusInvalid where
  | schema | date | expired | future | size | endpoint | height | duplicate | diversity | thin
  deriving BEq, Inhabited, Repr

def CensusInvalid.name : CensusInvalid → String
  | .schema => "schema" | .date => "date" | .expired => "expired" | .future => "future" | .size => "size"
  | .endpoint => "endpoint" | .height => "height" | .duplicate => "duplicate" | .diversity => "diversity"
  | .thin => "thin"

inductive CensusError where
  | invalid (e : CensusInvalid)
  | signature (e : Winnow.Keys.CensusSignature.Invalid)
  /-- `JSONDecoder` refused the document's shape. -/
  | decoding (reason : String)
  | io (reason : String)
  deriving Inhabited

def CensusError.name : CensusError → String
  | .invalid e => e.name | .signature e => e.name | .decoding _ => "dataCorrupted" | .io _ => "io"

namespace CensusCatalog

def endpointURL : String := "https://census.winnowwallet.com/census/peers.json"
def maximumBytes : Nat := 4 * 1_024 * 1_024
def maximumEntries : Nat := 65_536
def maximumAgeDays : Int := 7
def minimumClearnetEntries : Nat := 50

def clearnet (c : CensusCatalog) : Option (Array CensusEntry) := (c.networks.find? (·.1 == "clearnet")).map (·.2)

/-- Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's `days_from_civil`). -/
def daysFromCivil (y m d : Int) : Int :=
  let y := if m ≤ 2 then y - 1 else y
  let era := (if y ≥ 0 then y else y - 399) / 400
  let yoe := y - era * 400
  let mp := (m + 9) % 12
  let doy := (153 * mp + 2) / 5 + d - 1
  let doe := yoe * 365 + yoe / 4 - yoe / 100 + doy
  era * 146097 + doe - 719468

def isLeap (y : Nat) : Bool := (y % 4 == 0 && y % 100 != 0) || y % 400 == 0

/-- `CensusCatalog.day`: a strict `yyyy-MM-dd` (it must round-trip through the formatter). -/
def day (text : String) : Option Int := do
  if text.utf8ByteSize != 10 then none
  let cs := text.toList
  if cs[4]? != some '-' || cs[7]? != some '-' then none
  let digits (a b : Nat) : Option Nat :=
    let part := (cs.drop a).take (b - a)
    if part.all Char.isDigit then some (String.ofList part).toNat! else none
  let y ← digits 0 4
  let m ← digits 5 7
  let d ← digits 8 10
  if y == 0 || m == 0 || m > 12 || d == 0 then none
  let dim := match m with
    | 2 => if isLeap y then 29 else 28
    | 4 | 6 | 9 | 11 => 30
    | _ => 31
  if d > dim then none
  return daysFromCivil y m d

def nearTip (height tip : Int32) : Bool :=
  height ≥ 0 && tip > 0 && (height.toInt - tip.toInt).natAbs ≤ 100

private def publicV4 (b : Array UInt8) : Bool :=
  let (a, x, y) := (b[0]!, b[1]!, b[2]!)
  if a == 0 || a == 10 || a == 127 || a ≥ 224 then false
  else !((a == 100 && 64 ≤ x && x ≤ 127) || (a == 169 && x == 254) || (a == 172 && 16 ≤ x && x ≤ 31) ||
    (a == 192 && x == 168) || (a == 192 && x == 0 && y == 0) || (a == 192 && x == 0 && y == 2) ||
    (a == 192 && x == 88 && y == 99) || (a == 198 && (x == 18 || x == 19)) || (a == 198 && x == 51 && y == 100) ||
    (a == 203 && x == 0 && y == 113))

/-- `inet_ntop(AF_INET6)` for an address with no embedded IPv4 form (global unicast). -/
def ntop6 (b : Array UInt8) : String :=
  (PeerAddress.host { services := 0, ip := ⟨b⟩, port := 0 })

private def canonicalIP (host : String) : Option String := do
  if let some v4 := inetPton4 host then
    if publicV4 v4 then return ".".intercalate (v4.toList.map toString) else none
  let b ← inetPton6 host
  if (b.extract 0 10).all (· == 0) && b[10]! == 255 && b[11]! == 255 then
    let m := b.extract 12 16
    if publicV4 m then return ".".intercalate (m.toList.map toString) else none
  if !((b[0]! &&& 0xe0) == 0x20) then none
  if b[0]! == 0x20 && b[1]! == 0x01 && b[2]! < 2 then none
  if b[0]! == 0x20 && b[1]! == 0x01 && b[2]! == 0x0d && b[3]! == 0xb8 then none
  if b[0]! == 0x20 && b[1]! == 0x02 then none
  if b[0]! == 0x3f && b[1]! == 0xff && b[2]! < 0x10 then none
  return ntop6 b

/-- Numeric public clearnet only; never resolves a name. -/
def canonicalHost (text : String) : Option String :=
  if text.utf8ByteSize > 255 || text != Winnow.Keys.Unicode.trimWhitespace text then none
  else canonicalIP text.toLower

private def validatedEntry (tip : Int32) (e : CensusEntry) : Except CensusInvalid CensusEntry := do
  if e.port != 8333 || e.userAgent.utf8ByteSize > 256 || e.userAgent.toList.any (fun c => c.toNat < 32 || c.toNat == 127) then
    throw .endpoint
  let some host := canonicalHost e.host | throw .endpoint
  if !nearTip e.startHeight tip then throw .height
  return { e with host }

private def validatedEntries (tip : Int32) (entries : Array CensusEntry) (minimum : Nat) :
    Except CensusInvalid (Array CensusEntry) := do
  if entries.size < minimum then throw .thin
  if entries.size > maximumEntries then throw .size
  let mut seen : Array PeerEndpoint := #[]
  let mut blocks : Array String := #[]
  let mut out := #[]
  for input in entries do
    let e ← validatedEntry tip input
    if seen.contains e.endpoint then throw .duplicate
    seen := seen.push e.endpoint
    let some block := netblock e.host | throw .endpoint
    if blocks.contains block then throw .diversity
    blocks := blocks.push block
    out := out.push e
  return out.qsort fun a b => a.host < b.host || (a.host == b.host && a.port < b.port)

/-- `validated(now:requireFresh:minimumEntries:)`; `nowSeconds` is the wall clock. -/
def validated (c : CensusCatalog) (nowSeconds : Int) (requireFresh : Bool := true) (minimumEntries : Nat := 0) :
    Except CensusInvalid CensusCatalog := do
  let some entries := (if c.schemaVersion == 1 then c.clearnet else none) | throw .schema
  let some observed := day c.date | throw .date
  let age := nowSeconds / 86_400 - observed   -- Int division floors here
  if age < 0 then throw .future
  if requireFresh && age > maximumAgeDays then throw .expired
  if !(c.tip > 0) then throw .height
  return { c with networks := #[("clearnet", ← validatedEntries c.tip entries minimumEntries)] }

private def entryOf (j : Json) : Except String CensusEntry := do
  let .str host ← j.getObjVal? "host" | throw "host"
  let some port := PersistedPeers.jsonNat? (← j.getObjVal? "port") 65535 | throw "port"
  let .str userAgent ← j.getObjVal? "userAgent" | throw "userAgent"
  let some h := PersistedPeers.jsonInt? (← j.getObjVal? "startHeight") (-2147483648) 2147483647 | throw "startHeight"
  return { host, port := port.toUInt16, userAgent, startHeight := Int32.ofInt h }

/-- `JSONDecoder().decode(CensusCatalog.self, …)`: every network must hold well-formed entries. -/
def ofJson (j : Json) : Except String CensusCatalog := do
  let some schemaVersion := PersistedPeers.jsonInt? (← j.getObjVal? "schemaVersion") (-(2 ^ 63)) (2 ^ 63 - 1) | throw "schemaVersion"
  let .str date ← j.getObjVal? "date" | throw "date"
  let some tip := PersistedPeers.jsonInt? (← j.getObjVal? "tip") (-2147483648) 2147483647 | throw "tip"
  let .obj kvs ← j.getObjVal? "networks" | throw "networks"
  let mut networks := #[]
  for (k, v) in kvs.toArray do
    let .arr xs := v | throw s!"networks.{k}"
    networks := networks.push (k, ← xs.mapM entryOf)
  return { schemaVersion, date, tip := Int32.ofInt tip, networks }

def decode (data : ByteArray) (nowSeconds : Int) (requireFresh : Bool := true) (minimumEntries : Nat := 0) :
    Except CensusError CensusCatalog := do
  if data.size > maximumBytes then throw (.invalid .size)
  let some text := String.fromUTF8? data | throw (.decoding "not UTF-8")
  let j ← (Json.parse text).mapError CensusError.decoding
  let c ← (ofJson j).mapError CensusError.decoding
  (c.validated nowSeconds requireFresh minimumEntries).mapError CensusError.invalid

/-- Whether the catalog's date is 0 … 7 days before `nowSeconds` (the pool's freshness rule). -/
def isFresh (c : CensusCatalog) (nowSeconds : Int) : Bool :=
  match day c.date with
  | some d => let age := nowSeconds / 86_400 - d; 0 ≤ age && age ≤ maximumAgeDays
  | none => false

end CensusCatalog

/-! ## The store -/

structure CensusDownload where
  catalog : CensusCatalog
  sha256 : String

structure CensusCatalogStore where
  path : System.FilePath
  minimumEntries : Nat := CensusCatalog.minimumClearnetEntries

namespace CensusCatalogStore

def signaturePath (s : CensusCatalogStore) : System.FilePath := s.path.toString ++ ".sig"

private def readUpToMax (p : System.FilePath) (limit : Nat) : IO (Option ByteArray) := do
  try return some (← readUpTo p limit) catch _ => return none

/-- The stored list, when it still verifies and validates. -/
def load (s : CensusCatalogStore) (nowSeconds : Int) (keys : List ByteArray := Winnow.Keys.CensusPublisher.trustedKeys) :
    IO (Option CensusDownload) := do
  let some data ← readUpToMax s.path CensusCatalog.maximumBytes | return none
  let sig ← readUpToMax s.signaturePath Winnow.Keys.CensusSignature.maximumBytes
  if (Winnow.Keys.CensusPublisher.verify data sig keys).toBool == false then return none
  match CensusCatalog.decode data nowSeconds (minimumEntries := s.minimumEntries) with
  | .ok catalog => return some { catalog, sha256 := hex (sha256 data) }
  | .error _ => return none

/-- Verifies, validates, then stores the list and its signature (a missing signature removes the old one). -/
def replace (s : CensusCatalogStore) (data : ByteArray) (signature : Option ByteArray) (nowSeconds : Int)
    (keys : List ByteArray := Winnow.Keys.CensusPublisher.trustedKeys) : IO (Except CensusError CensusDownload) := do
  match Winnow.Keys.CensusPublisher.verify data signature keys with
  | .error e => return .error (.signature e)
  | .ok () => pure ()
  match CensusCatalog.decode data nowSeconds (minimumEntries := s.minimumEntries) with
  | .error e => return .error e
  | .ok catalog =>
    try
      if let some dir := s.path.parent then IO.FS.createDirAll dir
      writeAtomic s.path data
      match signature with
      | some sig => writeAtomic s.signaturePath sig
      | none => try IO.FS.removeFile s.signaturePath catch _ => pure ()
      return .ok { catalog, sha256 := hex (sha256 data) }
    catch e => return .error (.io (toString e))

end CensusCatalogStore
end Winnow.IO
