import Winnow.Wallet.Vault
import Winnow.Wallet.Characters

/-! # People, cards and payment labels (port of `Sources/WalletCore/Wallet/People.swift`)

Pay-to keys (`PersonPayTo`), signer identities and their human-comparable fingerprints (`PersonKeys`),
the three cards (`PersonCard`, `SharedSavingsCard`, `ApprovalRequest`) in their one JSON shape (sorted
keys, unescaped slashes, a `winnow` kind field, a 64 KiB ceiling), `DisplayName`, the Add-person paste
parser and `PaymentLabeler`. -/

namespace Winnow
open SwiftJSON Keys
open Tx (BitcoinNetwork)

/-! ## Pay-to -/

inductive PersonPayTo where
  | descriptor (canonical : String)
  | address (address : String)
  deriving Inhabited, BEq

inductive PersonPayToError where
  | malformed | privateKey | singleAddressKey | notSingleKey
  | wrongNetwork (expected : BitcoinNetwork)
  | unsupportedDerivation
  deriving Inhabited, BEq

namespace PersonPayToError
def name : PersonPayToError → String
  | .malformed => "malformed" | .privateKey => "privateKey" | .singleAddressKey => "singleAddressKey"
  | .notSingleKey => "notSingleKey" | .wrongNetwork _ => "wrongNetwork" | .unsupportedDerivation => "unsupportedDerivation"

def description : PersonPayToError → String
  | .malformed => "That isn't a valid pay-to key. Paste the person's Winnow card or their public account key."
  | .privateKey => "That is a private key. For safety, paste only the public account key—never a seed phrase or private key."
  | .singleAddressKey => "This key gives one address only — paste the address itself instead."
  | .notSingleKey =>
    "Winnow pays a person from a single-key descriptor such as tr([…]xpub…/<0;1>/*). Multi-key descriptors belong in shared savings."
  | .wrongNetwork n => s!"That key is for a different Bitcoin network. This wallet is on {Wallet.networkName n}."
  | .unsupportedDerivation =>
    "This key derives addresses in a way Winnow cannot follow. Paste the account key ending in /<0;1>/* or /0/*."
end PersonPayToError

/-- Failures of the people module: a domain error, or another module's by case name. -/
abbrev PM := Except String

namespace PersonPayTo

def receiveOnlyDerivation : Array Descriptor.Element := #[.step 0, .wildcard false]

/-- Validates a pay-to descriptor and returns it in canonical form. -/
def ofDescriptor (text : String) (network : BitcoinNetwork) : Except PersonPayToError PersonPayTo := do
  let trimmed := Unicode.trimWhitespace text
  let some d := (Descriptor.parse trimmed).toOption | throw .malformed
  let .tr keyExpression tree := d.expression | throw .notSingleKey
  let (none, .single key) := (tree, keyExpression) | throw .notSingleKey
  match key.base with
  | .privateKey .. => throw .privateKey
  | .publicKey _ => throw .singleAddressKey
  | .extended hd keyNetwork =>
    if hd.isPrivate then throw .privateKey
    unless keyNetwork == Vault.hdNetwork network do throw (.wrongNetwork network)
  let els := key.derivation.elements
  unless els == VaultCosignerRole.scriptPath.requiredDerivation || els == receiveOnlyDerivation do
    throw (if key.derivation.isRanged then .unsupportedDerivation else .singleAddressKey)
  if (d.derived 0 network).toOption.isNone then throw .malformed
  return .descriptor d.serialized

/-- Validates a plain address (with `AddressError`'s own case). -/
def ofAddress (text : String) (network : BitcoinNetwork) : Except String PersonPayTo := do
  let trimmed := Unicode.trimWhitespace text
  discard <| (AddressDecoder.scriptPubKey trimmed network).mapError (·.name)
  return .address trimmed

def derivesFreshAddresses : PersonPayTo → Bool | .descriptor _ => true | _ => false
def text : PersonPayTo → String | .descriptor v | .address v => v

def derivedAt (text : String) (index : UInt32) (network : BitcoinNetwork) : PM Descriptor.DerivedOutput := do
  let d ← (Descriptor.parse text).mapError (·.name)
  let outs ← (d.derived index network).mapError (·.name)
  let some o := outs[0]? | throw "indexOutOfRange"
  return o

def addressAt (p : PersonPayTo) (index : UInt32) (network : BitcoinNetwork) : PM String :=
  match p with
  | .address a => pure a
  | .descriptor t => return (← derivedAt t index network).address

def scriptPubKeyAt (p : PersonPayTo) (index : UInt32) (network : BitcoinNetwork) : PM ByteArray :=
  match p with
  | .address a => (AddressDecoder.scriptPubKey a network).mapError (·.name)
  | .descriptor t => return (← derivedAt t index network).scriptPubKey

def scripts (p : PersonPayTo) (count : UInt32) (network : BitcoinNetwork) : PM (Array ByteArray) :=
  match p with
  | .address _ => return #[← p.scriptPubKeyAt 0 network]
  | .descriptor _ => (Array.range count.toNat).mapM fun i => p.scriptPubKeyAt i.toUInt32 network

def identity (p : PersonPayTo) (network : BitcoinNetwork) : PM ByteArray := p.scriptPubKeyAt 0 network

def toJV : PersonPayTo → JV
  | .descriptor v => .obj #[("kind", .str "descriptor"), ("value", .str v)]
  | .address v => .obj #[("kind", .str "address"), ("value", .str v)]

def ofJV (v : JV) : D PersonPayTo := do
  let kvs ← asObject v
  let kind ← key kvs "kind" asString
  let value ← key kvs "value" asString
  match kind with
  | "descriptor" => pure (.descriptor value)
  | "address" => pure (.address value)
  | _ => dataCorrupted

end PersonPayTo

/-! ## Signer keys -/

namespace PersonKeys

def signerIdentity (expression : String) (network : BitcoinNetwork) : PM ByteArray := do
  let k ← (VaultCosignerKey.make expression .scriptPath network).mapError (·.name)
  k.publicKey 0 0

/-- The first four bytes of the identity's SHA-256, as `ab12 cd34`. -/
def fingerprint (identity : ByteArray) : String :=
  let h := hex ((sha256 identity).extract 0 4)
  (h.take 4).toString ++ " " ++ (h.drop 4).toString

def signerFingerprint (expression : String) (network : BitcoinNetwork) : PM String :=
  return fingerprint (← signerIdentity expression network)

end PersonKeys

/-! ## Display names -/

namespace DisplayName

def maximumLength : Nat := 120

def cfRanges : List (Nat × Nat) :=
  [(0xAD, 0xAD), (0x600, 0x605), (0x61C, 0x61C), (0x6DD, 0x6DD), (0x70F, 0x70F), (0x890, 0x891), (0x8E2, 0x8E2),
   (0x180E, 0x180E), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x206F), (0xFEFF, 0xFEFF),
   (0xFFF9, 0xFFFB), (0x110BD, 0x110BD), (0x110CD, 0x110CD), (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3),
   (0x1D173, 0x1D17A), (0xE0001, 0xE0001), (0xE0020, 0xE007F)]

/-- `CharacterSet.controlCharacters` (Cc, Cf) or `.newlines`. -/
def isControlOrNewline (c : Char) : Bool :=
  let n := c.toNat
  n < 0x20 || (0x7F ≤ n && n ≤ 0x9F) || n == 0x85 || n == 0x2028 || n == 0x2029 ||
    cfRanges.any fun (a, b) => a ≤ n && n ≤ b

/-- Trimmed, at most 120 `Character`s, single-line, free of control characters. -/
def normalized (text : String) : Option String :=
  let name := Unicode.trimWhitespace text
  if name.isEmpty || Characters.count name > maximumLength || name.toList.any isControlOrNewline then none else some name

end DisplayName

/-! ## Cards -/

inductive PersonCardError where
  | notACard
  | unsupportedVersion (version : Int)
  | wrongNetwork (card : String) (wallet : BitcoinNetwork)
  deriving Inhabited

def PersonCardError.name : PersonCardError → String
  | .notACard => "notACard" | .unsupportedVersion _ => "unsupportedVersion" | .wrongNetwork .. => "wrongNetwork"

def PersonCardError.description : PersonCardError → String
  | .notACard => "That isn't a Winnow card."
  | .unsupportedVersion v => s!"This card was made by a newer Winnow (card version {v}). Update the app to read it."
  | .wrongNetwork card wallet => s!"This card is for {card}; this wallet is on {Wallet.networkName wallet}."

/-- What a paste on the Add-person screen can fail with (thrown by case name: `empty`, `unrecognised`). -/
inductive PersonPasteError where
  | empty | unrecognised
  deriving Inhabited, BEq

def PersonPasteError.name : PersonPasteError → String | .empty => "empty" | .unrecognised => "unrecognised"

def PersonPasteError.description : PersonPasteError → String
  | .empty => "Paste the person's Winnow card, their public account key, or a Bitcoin address."
  | .unrecognised => "That doesn't look like a Winnow card, a public account key or a Bitcoin address."

namespace WinnowCardCoding

def maximumBytes : Nat := 64 * 1024

def serialize (v : JV) : String := writeUnescaped v

/-- The envelope's `winnow` must name `kind`; any other decoding failure is `notACard`. -/
def decode {α} (text : String) (kind : String) (f : JV → D α) : Except PersonCardError α := do
  let trimmed := Unicode.trimWhitespace text
  if trimmed.toUTF8.size > maximumBytes then throw .notACard
  let envelope : D (Option String) := decodeText trimmed fun v => do
    let kvs ← asObject v
    keyIfPresent kvs "winnow" asString
  match envelope with
  | .ok (some k) => if k != kind then throw .notACard
  | _ => throw .notACard
  match decodeText trimmed f with
  | .ok a => pure a
  | .error _ => throw .notACard

end WinnowCardCoding

def cardVersionOK (v : Int) : Bool := 1 ≤ v && v ≤ 1

structure PersonCard where
  winnow : String := "person-card"
  version : Int := 1
  network : String
  name : String
  payTo : Option String := none
  signerKey : Option String := none
  deriving Inhabited, BEq

namespace PersonCard
def kind : String := "person-card"

def make (network : BitcoinNetwork) (name : String) (payTo signerKey : Option String) : PersonCard :=
  { network := Wallet.networkName network, name, payTo, signerKey }

def toJV (c : PersonCard) : JV :=
  obj [("winnow", some (.str c.winnow)), ("version", some (ofInt c.version)), ("network", some (.str c.network)),
    ("name", some (.str c.name)), ("payTo", c.payTo.map .str), ("signerKey", c.signerKey.map .str)]

def ofJV (v : JV) : D PersonCard := do
  let kvs ← asObject v
  return { winnow := ← key kvs "winnow" asString, version := ← key kvs "version" asInt, network := ← key kvs "network" asString,
           name := ← key kvs "name" asString, payTo := ← keyIfPresent kvs "payTo" asString,
           signerKey := ← keyIfPresent kvs "signerKey" asString }

def serialized (c : PersonCard) : String := WinnowCardCoding.serialize c.toJV

def decode (text : String) : Except PersonCardError PersonCard := do
  let c ← WinnowCardCoding.decode text kind ofJV
  unless cardVersionOK c.version do throw (.unsupportedVersion c.version)
  return c
end PersonCard

structure SharedSavingsCard where
  winnow : String := "shared-savings"
  version : Int := 1
  network : String
  name : String
  descriptor : String
  deriving Inhabited, BEq

namespace SharedSavingsCard
def kind : String := "shared-savings"

def make (network : BitcoinNetwork) (name descriptor : String) : SharedSavingsCard :=
  { network := Wallet.networkName network, name, descriptor }

def toJV (c : SharedSavingsCard) : JV :=
  .obj #[("winnow", .str c.winnow), ("version", ofInt c.version), ("network", .str c.network), ("name", .str c.name),
    ("descriptor", .str c.descriptor)]

def ofJV (v : JV) : D SharedSavingsCard := do
  let kvs ← asObject v
  return { winnow := ← key kvs "winnow" asString, version := ← key kvs "version" asInt, network := ← key kvs "network" asString,
           name := ← key kvs "name" asString, descriptor := ← key kvs "descriptor" asString }

def serialized (c : SharedSavingsCard) : String := WinnowCardCoding.serialize c.toJV

/-- Decodes and proves the descriptor is a vault this wallet's network can hold. -/
def decode (text : String) (network : BitcoinNetwork) : PM (SharedSavingsCard × Vault) := do
  let c ← (WinnowCardCoding.decode text kind ofJV).mapError (·.name)
  unless cardVersionOK c.version do throw "unsupportedVersion"
  unless c.network == Wallet.networkName network do throw "wrongNetwork"
  let v ← (Vault.parse c.descriptor network).mapError (·.name)
  return (c, v)
end SharedSavingsCard

structure ApprovalRequest where
  winnow : String := "approval"
  version : Int := 1
  network : String
  vault : Option String := none
  name : Option String := none
  psbt : String
  deriving Inhabited, BEq

namespace ApprovalRequest
def kind : String := "approval"

def make (network : BitcoinNetwork) (vault name : Option String) (psbt : PSBT) : ApprovalRequest :=
  { network := Wallet.networkName network, vault, name, psbt := psbt.base64 }

def toJV (r : ApprovalRequest) : JV :=
  obj [("winnow", some (.str r.winnow)), ("version", some (ofInt r.version)), ("network", some (.str r.network)),
    ("vault", r.vault.map .str), ("name", r.name.map .str), ("psbt", some (.str r.psbt))]

def ofJV (v : JV) : D ApprovalRequest := do
  let kvs ← asObject v
  return { winnow := ← key kvs "winnow" asString, version := ← key kvs "version" asInt, network := ← key kvs "network" asString,
           vault := ← keyIfPresent kvs "vault" asString, name := ← keyIfPresent kvs "name" asString,
           psbt := ← key kvs "psbt" asString }

def serialized (r : ApprovalRequest) : String := WinnowCardCoding.serialize r.toJV

/-- The envelope, or a bare Base64 PSBT. -/
def decode (text : String) (network : BitcoinNetwork) : PM ApprovalRequest := do
  let trimmed := Unicode.trimWhitespace text
  if trimmed.startsWith "{" then
    let r ← (WinnowCardCoding.decode trimmed kind ofJV).mapError (·.name)
    unless cardVersionOK r.version do throw "unsupportedVersion"
    unless r.network == Wallet.networkName network do throw "wrongNetwork"
    return r
  let p ← (PSBT.ofBase64 trimmed).mapError (·.name)
  return make network none none p

def decodedPSBT (r : ApprovalRequest) : PM PSBT := (PSBT.ofBase64 r.psbt).mapError (·.name)
end ApprovalRequest

/-! ## Paste -/

inductive PersonImport.Source where
  | card | keyExpression | descriptor | address
  deriving Inhabited, BEq

def PersonImport.Source.name : PersonImport.Source → String
  | .card => "card" | .keyExpression => "keyExpression" | .descriptor => "descriptor" | .address => "address"

structure PersonImport where
  name : Option String
  payTo : Option PersonPayTo
  signerKey : Option String
  source : PersonImport.Source
  deriving Inhabited, BEq

namespace PersonPaste

/-- `tr(KEY)#checksum` → `KEY`. -/
def innerKeyExpression (canonical : String) : Option String :=
  if !canonical.startsWith "tr(" then none
  else
    let body := match canonical.splitOn "#" with
      | b :: _ => if b.isEmpty then canonical else b
      | [] => canonical
    if !body.endsWith ")" then none
    else some ((body.drop 3).dropEnd 1).toString

def asciiLower (s : String) : String := s.map Char.toLower

/-- An address-shaped paste keeps its address error (a wrong network, say). -/
def addressError (text : String) (network : BitcoinNetwork) : Option String :=
  let lowered := asciiLower text
  let looks := ["bc1", "tb1", "1", "3", "m", "n", "2"].any (lowered.startsWith ·) && !((lowered.splitOn "pub").length > 1)
  if !looks then none
  else match AddressDecoder.scriptPubKey text network with
    | .ok _ => none
    | .error e => some e.name

def parseCard (text : String) (network : BitcoinNetwork) : PM PersonImport := do
  let card ← (PersonCard.decode text).mapError (·.name)
  unless card.network == Wallet.networkName network do throw "wrongNetwork"
  let mut payTo : Option PersonPayTo := none
  if let some raw := card.payTo.map Unicode.trimWhitespace then
    if !raw.isEmpty then
      payTo ← if raw.startsWith "tr(" then (PersonPayTo.ofDescriptor raw network).mapError (·.name) |>.map some
        else (PersonPayTo.ofAddress raw network).map some
  let mut signerKey : Option String := none
  if let some raw := card.signerKey.map Unicode.trimWhitespace then
    if !raw.isEmpty then
      signerKey := some (← (VaultCosignerKey.make raw .scriptPath network).mapError (·.name)).expression
  return { name := DisplayName.normalized card.name, payTo, signerKey, source := .card }

def parseDescriptor (text : String) (network : BitcoinNetwork) : PM PersonImport := do
  let payTo ← (PersonPayTo.ofDescriptor text network).mapError (·.name)
  let mut signerKey : Option String := none
  if let .descriptor canonical := payTo then
    if let some inner := innerKeyExpression canonical then
      if let .ok s := VaultCosignerKey.make inner .scriptPath network then signerKey := some s.expression
  return { name := none, payTo := some payTo, signerKey, source := .descriptor }

def parseKeyExpression (text : String) (network : BitcoinNetwork) : PM PersonImport := do
  match VaultCosignerKey.make text .scriptPath network with
  | .ok signer =>
    let payTo ← (PersonPayTo.ofDescriptor s!"tr({signer.expression})" network).mapError (·.name)
    return { name := none, payTo := some payTo, signerKey := some signer.expression, source := .keyExpression }
  | .error .scriptPathDerivationRequired =>
    let some signer := (VaultCosignerKey.make (text ++ "/<0;1>/*") .scriptPath network).toOption | throw "unrecognised"
    let some payTo := (PersonPayTo.ofDescriptor s!"tr({signer.expression})" network).toOption | throw "unrecognised"
    return { name := none, payTo := some payTo, signerKey := some signer.expression, source := .keyExpression }
  | .error .missingOrigin =>
    for candidate in [text, text ++ "/0/*"] do
      if let .ok payTo := PersonPayTo.ofDescriptor s!"tr({candidate})" network then
        return { name := none, payTo := some payTo, signerKey := none, source := .keyExpression }
    discard <| (PersonPayTo.ofDescriptor s!"tr({text}/0/*)" network).mapError (·.name)
    throw "unrecognised"
  | .error .malformed => throw "unrecognised"
  | .error e => throw e.name

/-- Whatever was pasted on the Add-person screen, validated into a person's fields. -/
def parse (text : String) (network : BitcoinNetwork) : PM PersonImport := do
  let trimmed := Unicode.trimWhitespace text
  if trimmed.isEmpty then throw "empty"
  if trimmed.startsWith "{" then return ← parseCard trimmed network
  if trimmed.startsWith "tr(" || trimmed.startsWith "rawtr(" then return ← parseDescriptor trimmed network
  if let .ok payTo := PersonPayTo.ofAddress trimmed network then
    return { name := none, payTo := some payTo, signerKey := none, source := .address }
  if let some e := addressError trimmed network then throw e
  parseKeyExpression trimmed network

end PersonPaste

/-! ## Labels -/

inductive PaymentLabel where
  | savings (name : String) | person (name : String) | you | unknown
  deriving Inhabited, BEq

structure PaymentLabeler where
  savingsName : String
  personScripts : Array (ByteArray × String)
  ownScripts : Array ByteArray
  deriving Inhabited

def PaymentLabeler.label (l : PaymentLabeler) (script : ByteArray) (isVaultOwned : Bool) : PaymentLabel :=
  if isVaultOwned then .savings l.savingsName
  else match (l.personScripts.reverse.find? (·.1 == script)) with
    | some (_, n) => .person n
    | none => if l.ownScripts.contains script then .you else .unknown

end Winnow
