import Winnow.Wallet.Descriptor

/-! # Vault signer keys and the vault draft (port of `Sources/WalletCore/Wallet/VaultSetup.swift`)

`VaultCosignerRole` pins each policy's derivation suffix, `VaultCosignerKey` validates a public-only signer
expression (identity = the neutered account key plus its derivation, so relabelling an origin cannot make
a second signer), `VaultDraft` is the creation screen's state machine, `VaultThreshold` its threshold
rules. -/

namespace Winnow
open Keys

/-- Swift's synthesized `HDKey` equality: every stored field. -/
def hdKeyEq (a b : HDKey) : Bool :=
  a.depth == b.depth && a.parentFingerprint == b.parentFingerprint && a.childIndex == b.childIndex &&
    a.chainCode == b.chainCode && a.privateKey == b.privateKey && a.publicKey == b.publicKey

inductive VaultCosignerRole where
  | scriptPath | muSig2
  deriving Inhabited, BEq, Repr

def VaultCosignerRole.requiredDerivation : VaultCosignerRole → Array Descriptor.Element
  | .scriptPath => #[.multipath #[0, 1], .wildcard false]
  | .muSig2 => #[]

inductive VaultCosignerKeyError where
  | malformed | privateKey | extendedPublicKeyRequired | missingOrigin | originPathMismatch
  | wrongNetwork (expectedPrefix : String)
  | scriptPathDerivationRequired | muSig2DerivationForbidden | duplicateKey
  deriving Inhabited, BEq

namespace VaultCosignerKeyError
def name : VaultCosignerKeyError → String
  | .malformed => "malformed" | .privateKey => "privateKey" | .extendedPublicKeyRequired => "extendedPublicKeyRequired"
  | .missingOrigin => "missingOrigin" | .originPathMismatch => "originPathMismatch" | .wrongNetwork _ => "wrongNetwork"
  | .scriptPathDerivationRequired => "scriptPathDerivationRequired"
  | .muSig2DerivationForbidden => "muSig2DerivationForbidden" | .duplicateKey => "duplicateKey"

def description : VaultCosignerKeyError → String
  | .malformed => "That signer key isn't valid. Paste the public account key exported by the other signer."
  | .privateKey => "That is a private key. For safety, paste only the public account key—never a seed phrase or private key."
  | .extendedPublicKeyRequired =>
    "A vault signer must be an extended public account key, not a single Bitcoin address or public key."
  | .missingOrigin =>
    "This signer key is missing its fingerprint and account path. Export the complete key expression from Winnow or a compatible wallet."
  | .originPathMismatch =>
    "This signer's account path does not match the public key. Export the complete signer key again instead of editing its path by hand."
  | .wrongNetwork p => s!"That signer key is for a different Bitcoin network. This wallet needs a key beginning with {p}."
  | .scriptPathDerivationRequired =>
    "For a k-of-n vault, the signer key must end in /<0;1>/* so Winnow can derive receive and change addresses."
  | .muSig2DerivationForbidden =>
    "For a MuSig2 vault, paste the bare signer account key without /<0;1>/*. Winnow adds the shared derivation after combining the keys."
  | .duplicateKey => "That public signer key is already in this vault. Each signer must use a different key."
end VaultCosignerKeyError

structure VaultCosignerKey.Identity where
  key : HDKey
  derivation : Array Descriptor.Element
  deriving Inhabited

instance : BEq VaultCosignerKey.Identity := ⟨fun a b => hdKeyEq a.key b.key && a.derivation == b.derivation⟩

/-- A validated, public-only signer key expression. -/
structure VaultCosignerKey where
  expression : String
  identity : VaultCosignerKey.Identity
  deriving Inhabited

namespace VaultCosignerKey

def validate (expression : String) (role : VaultCosignerRole) (expectedNetwork : Option HDKey.Network) :
    Except VaultCosignerKeyError VaultCosignerKey := do
  let trimmed := Unicode.trimWhitespace expression
  if trimmed.isEmpty then throw .malformed
  let some descriptor := (Descriptor.parse s!"rawtr({trimmed})").toOption | throw .malformed
  let .rawtr (.single key) := descriptor.expression | throw .malformed
  match key.base with
  | .privateKey .. => throw .privateKey
  | .publicKey _ => throw .extendedPublicKeyRequired
  | .extended hd keyNetwork =>
    if hd.isPrivate then throw .privateKey
    let some origin := key.origin | throw .missingOrigin
    unless origin.path.size == hd.depth.toNat && (hd.depth == 0 || origin.path.back? == some hd.childIndex) do
      throw .originPathMismatch
    if let some expected := expectedNetwork then
      if keyNetwork != expected then
        throw (.wrongNetwork (if expected == .mainnet then "xpub" else "tpub"))
    unless key.derivation.elements == role.requiredDerivation do
      throw (match role with | .scriptPath => .scriptPathDerivationRequired | .muSig2 => .muSig2DerivationForbidden)
    if (descriptor.derivedForKeyNetwork 0).toOption.isNone then throw .malformed
    return { expression := trimmed, identity := { key := hd.neutered, derivation := key.derivation.elements } }

def make (expression : String) (role : VaultCosignerRole) (network : Tx.BitcoinNetwork) :
    Except VaultCosignerKeyError VaultCosignerKey :=
  validate expression role (some (if network == .mainnet then .mainnet else .testnet))

def validateWithoutNetwork (expression : String) (role : VaultCosignerRole) : Except VaultCosignerKeyError VaultCosignerKey :=
  validate expression role none

/-- The compressed public key this signer resolves to at (`index`, `choice`). -/
def publicKey (k : VaultCosignerKey) (index : UInt32) (choice : Nat := 0) : Except String ByteArray := do
  let d ← (Descriptor.parse s!"rawtr({k.expression})").mapError (·.name)
  let .rawtr key := d.expression | throw "malformed"
  (Descriptor.publicKey key index choice).mapError (·.name)

end VaultCosignerKey

/-! ## Threshold and draft -/

namespace VaultThreshold
def clamped (threshold keyCount : Int) : Int := min (max threshold 1) (max keyCount 1)

def reconciled (threshold previousKeyCount keyCount : Int) : Int :=
  if previousKeyCount < 2 && keyCount ≥ 2 then 2 else clamped threshold keyCount
end VaultThreshold

structure VaultDraft where
  role : VaultCosignerRole := .scriptPath
  threshold : Int := 1
  cosigners : Array VaultCosignerKey := #[]
  deriving Inhabited

namespace VaultDraft

def canBuild (d : VaultDraft) : Bool := d.cosigners.size ≥ 2

def setRole (d : VaultDraft) (role : VaultCosignerRole) : VaultDraft × Bool :=
  if !d.cosigners.isEmpty then (d, false) else ({ d with role, threshold := 1 }, true)

def add (d : VaultDraft) (expression : String) (network : Tx.BitcoinNetwork) : Except VaultCosignerKeyError VaultDraft := do
  let candidate ← VaultCosignerKey.make expression d.role network
  if d.cosigners.any (·.identity == candidate.identity) then throw .duplicateKey
  let previous := d.cosigners.size
  let cosigners := d.cosigners.push candidate
  return { d with cosigners, threshold := VaultThreshold.reconciled d.threshold previous cosigners.size }

/-- `remove(at:)` with an `IndexSet` (duplicates collapse; out-of-range offsets are ignored). -/
def remove (d : VaultDraft) (offsets : Array Nat) : VaultDraft := Id.run do
  let previous := d.cosigners.size
  let sorted := (offsets.toList.eraseDups.mergeSort (fun a b => a ≥ b))
  let mut cs := d.cosigners
  for i in sorted do
    if i < cs.size then cs := cs.eraseIdx! i
  return { d with cosigners := cs, threshold := VaultThreshold.reconciled d.threshold previous cs.size }

def setThreshold (d : VaultDraft) (value : Int) : VaultDraft :=
  { d with threshold := VaultThreshold.clamped value d.cosigners.size }

end VaultDraft
end Winnow
