import Winnow.Ledger.Client
import Winnow.Wallet.PSBTRoles
import Winnow.Wallet.SwiftJSON

/-! # A Ledger as a signer of a multisig account (the account-free part)

Port of `Sources/WalletCore/Ledger/LedgerMultisig.swift` (upstream 1cf93fb) without
`MultisigAccount`, which Phase B ports: every function here takes what Swift reads from the account
(its signers, the policy built from it, the address it derives) as arguments. The account-level
wrappers (`LedgerMultisig.register(_:name:fingerprint:client:)`, `displayAddress`, `sign`) are each a
line on top of these once `MultisigAccount` lands; the report of Phase C lists
them. -/

namespace Winnow.Ledger
open Keys SwiftJSON

/-- What the phone keeps to work with a Ledger signer of one multisig account
(`LedgerRegistration`). None of it is secret: the HMAC only proves to that Ledger that it approved
this exact policy before. -/
structure Registration where
  /-- The name the Ledger shows for the account. -/
  policyName : String
  policyID : ByteArray
  hmac : ByteArray
  masterFingerprint : UInt32
  /-- The Ledger signer's account path, hardened bits included. -/
  keyPath : Array UInt32
  deriving Inhabited, BEq

namespace Registration

/-- Swift's synthesized `Codable` form: `Data` as base64, numbers as JSON numbers. -/
def toJV (r : Registration) : JV :=
  .obj #[("policyName", .str r.policyName), ("policyID", ofData r.policyID), ("hmac", ofData r.hmac),
    ("masterFingerprint", ofInt r.masterFingerprint.toNat), ("keyPath", .arr (r.keyPath.map (ofInt ·.toNat)))]

def ofJV (v : JV) : D Registration := do
  let kvs ← asObject v
  return { policyName := ← key kvs "policyName" asString, policyID := ← key kvs "policyID" asData,
           hmac := ← key kvs "hmac" asData, masterFingerprint := ← key kvs "masterFingerprint" asUInt32,
           keyPath := ← key kvs "keyPath" (asArray asUInt32) }

end Registration

/-- What `LedgerMultisig.sign` can throw: the Ledger's errors, or the PSBT's while it is checked. -/
inductive SignError where
  | ledger (e : LedgerError)
  | psbt (e : PSBTError)
  deriving Inhabited

def SignError.name : SignError → String
  | .ledger e => e.name | .psbt e => e.name

namespace Multisig

/-- The Ledger's signer key: BIP87 multisig account 0, `m/87'/coin'/0'`, which the app exports
without a warning. -/
def keyPath (network : Tx.BitcoinNetwork) : Array UInt32 :=
  let coin : UInt32 := if network == .mainnet then 0 else 1
  #[87 + HDKey.hardenedOffset, coin + HDKey.hardenedOffset, HDKey.hardenedOffset]

/-- `signerExpression(client:network:)`: the Ledger's signer key expression,
`[fp/87'/1'/0']tpub…/<0;1>/*`, and its fingerprint. The key must sit where its origin says. -/
def signerExpression (network : Tx.BitcoinNetwork) : Program (String × UInt32) := do
  let fingerprint ← Client.masterFingerprint
  let path := keyPath network
  let text ← Client.extendedPublicKey path false
  let key ← match HDKey.deserialize text with
    | .ok k => pure k
    | .error _ => throw (LedgerError.protocolViolation "an extended key that does not parse")
  let isTestKey := text.startsWith "tpub"
  unless isTestKey == (network != .mainnet) && key.depth.toNat == path.size && some key.childIndex == path.back?
      && key.privateKey.isNone do
    throw (LedgerError.mismatch "the Ledger's key is for another network or path; open the Bitcoin app for this network")
  let origin := "/".intercalate (path.toList.map fun s => s!"{(s &&& ~~~HDKey.hardenedOffset).toNat}'")
  return (s!"[{Descriptor.hex8 fingerprint}/{origin}]{text}/<0;1>/*", fingerprint)

/-- `ledgerSigner(of:fingerprint:path:)` over the account's signers: the one whose origin is the
Ledger's fingerprint and key path. -/
def ledgerSigner (signers : Array Descriptor.SingleKey) (fingerprint : UInt32) (path : Array UInt32) :
    Option Descriptor.SingleKey :=
  signers.find? fun s => match s.origin with
    | some o => o.fingerprint == fingerprint && o.path == path
    | none => false

/-- The body of `register(_:name:fingerprint:client:)` once the account's policy is built: registers
it after the user approves it on the Ledger, then checks that the Ledger derives the account's first
receive address `firstAddress` (`account.address(index: 0, choice: 0)`). -/
def registerPolicy (policy : WalletPolicy) (fingerprint : UInt32) (path : Array UInt32) (firstAddress : String) :
    Program Registration := do
  let (id, hmac) ← Client.register policy
  let registration : Registration :=
    { policyName := policy.name, policyID := id, hmac, masterFingerprint := fingerprint, keyPath := path }
  let first ← Client.address policy hmac false 0 false
  unless first == firstAddress do throw (LedgerError.mismatch "the Ledger derives a different first address")
  return registration

/-- `register(_:name:fingerprint:client:)` with the account given by its signers, its network, the
policy built from it under a name (`WalletPolicy.ofTree`/`ofDescriptor`) and its first receive
address. -/
def register (signers : Array Descriptor.SingleKey) (network : Tx.BitcoinNetwork)
    (makePolicy : String → Except LedgerError WalletPolicy) (name : String) (fingerprint : UInt32)
    (firstAddress : String) : Program Registration := do
  let path := keyPath network
  if (ledgerSigner signers fingerprint path).isNone then
    throw (LedgerError.mismatch "this account has no signer for this Ledger")
  let policy ← Program.ofExcept (makePolicy name)
  registerPolicy policy fingerprint path firstAddress

/-- `policy(_:_:)`: the account's policy under the stored name, which must be the registered one. -/
def policy (makePolicy : String → Except LedgerError WalletPolicy) (registration : Registration) :
    Except LedgerError WalletPolicy := do
  let policy ← makePolicy registration.policyName
  unless policy.id == registration.policyID do
    throw (.mismatch "the stored Ledger registration belongs to another account")
  return policy

/-- `displayAddress(_:registration:choice:index:client:)`: shows the address at (choice, index) on
the Ledger; it must equal `expected`, the phone's own derivation. -/
def displayAddress (makePolicy : String → Except LedgerError WalletPolicy) (registration : Registration)
    (choice : Nat := 0) (index : UInt32) (expected : String) : Program String := do
  let policy ← Program.ofExcept (policy makePolicy registration)
  let shown ← Client.address policy registration.hmac (choice == 1) index true
  unless shown == expected do throw (LedgerError.mismatch "the Ledger shows a different address")
  return shown

/-- The keys of one leaf whose script-path signatures on `input` verify (Swift's
`PSBT.verifiedScriptPathSigners(input:leafHash:tx:spentOutputs:)`, upstream 1cf93fb). Leaves parse
with `Multisig.parse` (`multi_a`/`sortedmulti_a`); Phase B's `Multisig.parsePolicy` adds the timelocked
leaves, and this then becomes that port's function. -/
def verifiedScriptPathSigners (p : PSBT) (index : Nat) (leafHash : ByteArray) (tx : Transaction)
    (spent : Array SighashBIP341.SpentOutput) : Except PSBTError (Array ByteArray) := do
  let some input := p.inputs[index]? | throw (.missingField s!"input {index}")
  let leaves := input.tapLeafScripts
  if leaves.isEmpty then throw (.missingField s!"input {index} tap leaf script")
  match PSBT.committingHashType input with
  | .error (.psbt e) => throw e
  | .error (.sign _) => throw (.malformed "sighash type")
  | .ok _ => pure ()
  let contexts := leaves.filterMap fun leaf => (_root_.Winnow.Multisig.parse ⟨leaf.script⟩).map (leaf, ·.2)
  if contexts.isEmpty then throw (.malformed s!"input {index} leaf script")
  let some (leaf, keys) := contexts.find? (·.1.leafHash == leafHash) | return #[]
  return (p.validScriptPathSignatures index leaf tx spent keys).map (·.1)

/-- The body of `sign(_:account:registration:client:)` after the device answered: every signature
must verify for the leaf it names, on its input; otherwise the PSBT is left untouched (the caller
keeps its own). Returns the signed PSBT and the number of signatures added. -/
def applySignatures (psbt : PSBT) (signatures : Array Signature) : Except SignError (PSBT × Nat) := do
  let mut signed := psbt
  let mut added := 0
  for s in signatures do
    let some leafHash := s.leafHash
      | throw (.ledger (.protocolViolation "a signature this account cannot use"))
    unless s.publicKey.size == 32 && s.inputIndex < signed.inputs.size do
      throw (.ledger (.protocolViolation "a signature this account cannot use"))
    let input := signed.inputs[s.inputIndex]!
    let existing := input.tapScriptSignatures
    let isNew := (existing.find? fun (id, _) => id.publicKey == s.publicKey && id.leafHash == leafHash).isNone
    if isNew then added := added + 1
    let updated := match existing.findIdx? fun (id, _) => id.publicKey == s.publicKey && id.leafHash == leafHash with
      | some j => existing.set! j ({ publicKey := s.publicKey, leafHash }, s.signature)
      | none => existing.push ({ publicKey := s.publicKey, leafHash }, s.signature)
    signed := signed.modifyInput s.inputIndex (·.setTapScriptSignatures updated)
  let tx ← signed.unsignedTransaction.mapError .psbt
  let spent ← signed.spentOutputs.mapError .psbt
  for s in signatures do
    -- Checked on its own leaf: the same key may already hold a valid signature elsewhere, which must
    -- not vouch for this one.
    let verified ← (verifiedScriptPathSigners signed s.inputIndex (s.leafHash.getD .empty) tx spent).mapError .psbt
    unless verified.contains s.publicKey do throw (.ledger (.mismatch "a Ledger signature does not verify"))
  unless added > 0 do throw (.ledger (.mismatch "the Ledger added no signature"))
  return (signed, added)

/-- `sign(_:account:registration:client:)`: asks the Ledger to sign `psbt`, which the caller has
reviewed, under the account's policy (`makePolicy`, checked against the registration), then
`applySignatures`. The outer `Program` fails with the device's errors; the inner `Except` is the
check of what it returned. -/
def sign (psbt : PSBT) (makePolicy : String → Except LedgerError WalletPolicy) (registration : Registration) :
    Program (Except SignError (PSBT × Nat)) := do
  let policy ← Program.ofExcept (policy makePolicy registration)
  let signatures ← Client.signPSBT psbt policy registration.hmac
  return applySignatures psbt signatures

end Multisig
end Winnow.Ledger
