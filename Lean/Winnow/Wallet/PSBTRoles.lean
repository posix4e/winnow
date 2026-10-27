import Winnow.Tx.PSBT
import Winnow.Wallet.Signer

/-! # PSBT roles (BIP370 / 371 / 373)

Port of `Sources/WalletCore/PSBT/PSBTRoles.swift` on top of the Tx area's PSBT document: creator,
signer (key path, `multi_a` script path), combiner, finalizer and extractor (the MuSig2 rounds went
with MuSig2 upstream).
(`unsignedTransaction` itself is in `Winnow.Tx.PSBT`.) Dictionaries of the Swift original are arrays of
pairs here, with the last value per key kept and keys in byte order (`PSBT.dictSorted`). -/

namespace Winnow
open Keys

/-- What the roles can throw: the document's errors or signing's. -/
inductive PSBTRoleError where
  | psbt (e : PSBTError)
  | sign (e : SignFailure)
  deriving Inhabited

def PSBTRoleError.name : PSBTRoleError → String
  | .psbt e => e.name | .sign e => e.name

namespace PSBT

abbrev RM := Except PSBTRoleError

def perr {α} (e : PSBTError) : RM α := throw (.psbt e)
def liftP {α} (r : Except PSBTError α) : RM α := r.mapError .psbt

/-- A Taproot key's origin: the x-only internal key and its path from the master fingerprint. -/
structure TaprootKey where
  internalKey : ByteArray
  masterFingerprint : UInt32
  path : Array UInt32
  deriving Inhabited

def TaprootKey.origin (k : TaprootKey) : KeyOrigin := { leafHashes := #[], masterFingerprint := k.masterFingerprint, path := k.path }

structure InputInfo where
  spentOutput : SighashBIP341.SpentOutput
  key : Option TaprootKey := none
  deriving Inhabited

structure OutputInfo where
  key : Option TaprootKey := none
  deriving Inhabited

/-! ## Creator -/

/-- A PSBTv2 for an unsigned transaction, with witness UTXOs, an explicit SIGHASH_DEFAULT and the BIP371
key fields of wallet-owned in/outputs. -/
def create (tx : Transaction) (inputInfo : Array InputInfo) (outputInfo : Array OutputInfo) : RM PSBT := do
  unless inputInfo.size == tx.inputs.size do perr .inconsistentCounts
  unless outputInfo.size == tx.outputs.size do perr .inconsistentCounts
  let globals := #[KeyValue.make GlobalType.version .empty (u32LE 2), KeyValue.make GlobalType.txVersion .empty (i32LE tx.version),
    KeyValue.make GlobalType.fallbackLocktime .empty (u32LE tx.locktime),
    KeyValue.make GlobalType.inputCount .empty (compactSize tx.inputs.size.toUInt64),
    KeyValue.make GlobalType.outputCount .empty (compactSize tx.outputs.size.toUInt64)]
  let mut inputs : Array Input := #[]
  for (input, info) in tx.inputs.zip inputInfo do
    if info.spentOutput.amount < 0 then perr (.malformed "negative amount")
    let pairs := #[KeyValue.make InType.previousTxid .empty input.previousOutput.txid,
      KeyValue.make InType.outputIndex .empty (u32LE input.previousOutput.vout),
      KeyValue.make InType.sequence .empty (u32LE input.sequence),
      KeyValue.make InType.sighashType .empty (u32LE 0),
      KeyValue.make InType.witnessUTXO .empty (Wire.appendVarData (i64LE info.spentOutput.amount) info.spentOutput.scriptPubKey)]
    let mut r : Input := ⟨pairs⟩
    if let some k := info.key then
      r := (r.setTapInternalKey (some k.internalKey)).setTapBIP32Derivation #[(k.internalKey, k.origin)]
    inputs := inputs.push r
  let mut outputs : Array Output := #[]
  for (output, info) in tx.outputs.zip outputInfo do
    let mut r : Output := ⟨#[KeyValue.make OutType.amount .empty (i64LE output.value), KeyValue.make OutType.script .empty output.scriptPubKey]⟩
    if let some k := info.key then
      r := (r.setTapInternalKey (some k.internalKey)).setTapBIP32Derivation #[(k.internalKey, k.origin)]
    outputs := outputs.push r
  return { globals := sortPairs globals, inputs := inputs.map (⟨sortPairs ·.pairs⟩), outputs := outputs.map (⟨sortPairs ·.pairs⟩) }

/-- Every input's witness UTXO (the BIP341 spent outputs). -/
def spentOutputs (p : PSBT) : Except PSBTError (Array SighashBIP341.SpentOutput) := do
  let mut out := #[]
  for h : k in [0:p.inputs.size] do
    let some u := p.inputs[k].witnessUTXO | throw (.missingField s!"input {k} witness utxo")
    out := out.push u
  return out

def checkIndex (p : PSBT) (index : Int) : RM Nat := do
  unless 0 ≤ index && index < p.inputs.size do perr (.missingField s!"input {index}")
  return index.toNat

def modifyInput (p : PSBT) (k : Nat) (f : Input → Input) : PSBT := { p with inputs := p.inputs.modify k f }

/-- The input's sighash type, refused unless it commits to every output. -/
def committingHashType (i : Input) : RM SighashBIP341.HashType := do
  let rawType := i.sighashType.getD 0
  if rawType > 255 then perr (.malformed s!"sighash type {rawType}")
  let hashType : SighashBIP341.HashType := ⟨rawType.toUInt8⟩
  unless hashType.commitsToAllOutputs do perr (.malformed s!"refusing non-DEFAULT/ALL sighash type {rawType}")
  return hashType

/-! ## Signer -/

/-- PSBT_IN_TAP_KEY_SIG for input `index`. -/
def signKeyPath (p : PSBT) (index : Int) (tweakedPrivateKey : ByteArray) (auxiliaryRand : ByteArray) : RM PSBT := do
  let k ← p.checkIndex index
  let tx ← liftP p.unsignedTransaction
  let spent ← liftP p.spentOutputs
  let hashType ← committingHashType p.inputs[k]!
  let w ← (Signer.witness tx k spent tweakedPrivateKey hashType auxiliaryRand).mapError .sign
  return p.modifyInput k (·.setTapKeySignature (some w[0]!))

/-- Script-path fields of a `multi_a` input: internal key, the one leaf script, leaf-hashed key origins. -/
def attachScriptPath (p : PSBT) (index : Int) (controlBlock : Tx.Taproot.ControlBlock) (leafScript : Script)
    (leafVersion : UInt8 := Tx.Taproot.leafVersion) (keyOrigins : Array (ByteArray × KeyOrigin) := #[]) : RM PSBT := do
  let k ← p.checkIndex index
  let leaf : TapLeafScript := { controlBlock, script := leafScript.bytes, leafVersion }
  let mut i := (p.inputs[k]!.setTapInternalKey (some controlBlock.internalKey)).setTapLeafScripts #[leaf]
  if !keyOrigins.isEmpty then
    let origins := i.tapBIP32Derivation ++ keyOrigins.map fun (key, o) => (key, { o with leafHashes := #[leaf.leafHash] })
    i := i.setTapBIP32Derivation origins
  return p.modifyInput k fun _ => i

/-- The signable leaf, its keys and its hash type. -/
def leafSigningContext (p : PSBT) (index : Int) : RM (Nat × TapLeafScript × Array ByteArray × SighashBIP341.HashType) := do
  let k ← p.checkIndex index
  let some leaf := p.inputs[k]!.tapLeafScripts[0]? | perr (.missingField s!"input {k} tap leaf script")
  let some (_, leafKeys) := Multisig.parse ⟨leaf.script⟩ | perr (.malformed s!"input {k} leaf script")
  let hashType ← committingHashType p.inputs[k]!
  return (k, leaf, leafKeys, hashType)

def isP2TR (s : ByteArray) : Bool := s.size == 34 && s[0]! == 0x51 && s[1]! == 0x20

/-- One self-verified leaf signature, or `none` when the secret's key is not a leaf key. -/
def selfVerifiedLeafSignature (secret : ByteArray) (k : Nat) (leaf : TapLeafScript) (leafKeys : Array ByteArray)
    (tx : Transaction) (spent : Array SighashBIP341.SpentOutput) (hashType : SighashBIP341.HashType)
    (aux : ByteArray) : RM (Option (TapScriptSignatureID × ByteArray)) := do
  let xonly ← match secretOf secret with
    | .ok d => match pointOfSecret d with
      | .ok pt => pure (xonlyBytes pt)
      | .error _ => perr (.malformed "invalid private key")
    | .error _ => perr (.malformed "invalid private key")
  if !leafKeys.contains xonly then return none
  let sig ← (Signer.scriptPathSignature tx k spent ⟨leaf.script⟩ leaf.leafVersion hashType none secret aux).mapError .sign
  let sighash ← (SighashBIP341.sighash tx k spent hashType (some (SighashBIP341.ScriptPath.ofLeaf ⟨leaf.script⟩ leaf.leafVersion))).mapError
    (PSBTRoleError.sign ∘ .sighash)
  let ok ← (schnorrVerify xonly sighash (sig.extract 0 64)).mapError (PSBTRoleError.sign ∘ .crypto)
  unless ok do perr (.malformed "self-produced signature failed verification")
  return some ({ publicKey := xonly, leafHash := leaf.leafHash }, sig)

/-- PSBT_IN_TAP_SCRIPT_SIG for every given secret whose x-only key is a leaf key. -/
def signScriptPath (p : PSBT) (index : Int) (privateKeys : Array ByteArray) (auxiliaryRand : ByteArray) : RM PSBT := do
  let (k, leaf, leafKeys, hashType) ← p.leafSigningContext index
  let tx ← liftP p.unsignedTransaction
  let spent ← liftP p.spentOutputs
  let mut signatures := p.inputs[k]!.tapScriptSignatures
  let mut signed := 0
  for secret in privateKeys do
    let some (id, sig) ← selfVerifiedLeafSignature secret k leaf leafKeys tx spent hashType auxiliaryRand | continue
    signatures := signatures.push (id, sig)
    signed := signed + 1
  if signed == 0 then perr (.missingField s!"input {k} matching leaf key")
  return p.modifyInput k (·.setTapScriptSignatures signatures)

def mergeMaps (maps : Array (Array KeyValue)) : RM (Array KeyValue) := do
  let mut merged : Array KeyValue := #[]
  for m in maps do
    for pair in m do
      match merged.findIdx? (·.key == pair.key) with
      | some j =>
        if merged[j]!.value != pair.value then perr (.conflict pair.key)
        merged := merged.set! j pair
      | none => merged := merged.push pair
  return sortPairs merged

/-- The union of several partial PSBTs of the same unsigned transaction. -/
def combined (p : PSBT) (others : Array PSBT) : RM PSBT := do
  let all := #[p] ++ others
  let reference ← liftP p.unsignedTransaction
  unless all.all (fun o => o.inputs.size == p.inputs.size && o.outputs.size == p.outputs.size) do perr .inconsistentCounts
  for o in all do
    unless (← liftP o.unsignedTransaction) == reference do perr .inconsistentCounts
  let mut inputs : Array Input := #[]
  for h : k in [0:p.inputs.size] do inputs := inputs.push ⟨← mergeMaps (all.map (·.inputs[k]!.pairs))⟩
  let mut outputs : Array Output := #[]
  for h : k in [0:p.outputs.size] do outputs := outputs.push ⟨← mergeMaps (all.map (·.outputs[k]!.pairs))⟩
  return { globals := ← mergeMaps (all.map (·.globals)), inputs, outputs }

/-! ## Finalizer / extractor -/

def keyPathHashType (sig : ByteArray) : Option SighashBIP341.HashType :=
  if sig.size == 64 then some .default else if sig.size == 65 then some ⟨sig[64]!⟩ else none

def validatedKeyPathWitness (k : Nat) (signature : ByteArray) (tx : Transaction) (spent : Array SighashBIP341.SpentOutput) :
    RM (Array ByteArray) := do
  let some hashType := keyPathHashType signature | perr (.malformed s!"input {k} tap key signature length")
  unless hashType.commitsToAllOutputs && (hashType.rawValue != 0 || signature.size == 64) do
    perr (.malformed s!"input {k} unsafe tap key sighash type")
  let script := spent[k]!.scriptPubKey
  unless isP2TR script do perr (.malformed s!"input {k} witness utxo is not P2TR")
  let sighash ← (SighashBIP341.sighash tx k spent hashType).mapError (PSBTRoleError.sign ∘ .sighash)
  let valid := (schnorrVerify (script.extract 2 34) sighash (signature.extract 0 64)).toOption.getD false
  unless valid do perr (.malformed s!"input {k} invalid tap key signature")
  return #[signature]

def leafCommitsToOutput (leaf : TapLeafScript) (spentScript : ByteArray) : Bool := Id.run do
  let mut root := leaf.leafHash
  for sibling in leaf.controlBlock.path do
    if sibling.size != 32 then return false
    root := Tx.Taproot.branchHash root sibling
  match Tx.Taproot.tweakedOutputKey leaf.controlBlock.internalKey (some root) with
  | none => return false
  | some (key, parity) => return key == spentScript.extract (spentScript.size - 32) spentScript.size &&
      parity == leaf.controlBlock.outputKeyParity

/-- The valid script-path signatures of one leaf, keyed by signer; anything else is skipped. -/
def validScriptPathSignatures (p : PSBT) (k : Nat) (leaf : TapLeafScript) (tx : Transaction)
    (spent : Array SighashBIP341.SpentOutput) (leafKeys : Array ByteArray) : Array (ByteArray × ByteArray) := Id.run do
  let mut valid : Array (ByteArray × ByteArray) := #[]
  for (id, signature) in p.inputs[k]!.tapScriptSignatures do
    if id.leafHash != leaf.leafHash || !leafKeys.contains id.publicKey then continue
    let some hashType := keyPathHashType signature | continue
    unless hashType.commitsToAllOutputs && (hashType.rawValue != 0 || signature.size == 64) do continue
    let .ok sighash := SighashBIP341.sighash tx k spent hashType (some (SighashBIP341.ScriptPath.ofLeaf ⟨leaf.script⟩ leaf.leafVersion))
      | continue
    unless (schnorrVerify id.publicKey sighash (signature.extract 0 64)).toOption.getD false do continue
    valid := match valid.findIdx? (·.1 == id.publicKey) with
      | some j => valid.set! j (id.publicKey, signature)
      | none => valid.push (id.publicKey, signature)
  return valid

def finalizedScriptPathWitness (p : PSBT) (k : Nat) (leaf : TapLeafScript) (tx : Transaction)
    (spent : Array SighashBIP341.SpentOutput) : RM (Option (Array ByteArray)) := do
  if leaf.leafVersion != leaf.controlBlock.leafVersion then return none
  let spentScript := spent[k]!.scriptPubKey
  unless isP2TR spentScript do perr (.malformed s!"input {k} witness utxo is not P2TR")
  if !leafCommitsToOutput leaf spentScript then return none
  let some (threshold, leafKeys) := Multisig.parse ⟨leaf.script⟩ | return none
  let valid := p.validScriptPathSignatures k leaf tx spent leafKeys
  if (valid.size : Int) < threshold then return none
  return some (← (Signer.multisigWitness valid ⟨leaf.script⟩ leaf.controlBlock).mapError (PSBTRoleError.sign ∘ .signer))

/-- The leaf keys whose signatures on input `index` verify (what the finalizer will count). -/
def verifiedScriptPathSigners (p : PSBT) (index : Int) (tx : Transaction) (spent : Array SighashBIP341.SpentOutput) :
    RM (Array ByteArray) := do
  let (k, leaf, leafKeys, _) ← p.leafSigningContext index
  return sortBytes id ((p.validScriptPathSignatures k leaf tx spent leafKeys).map (·.1))

/-- Final witnesses for every input, the partial fields removed — all or nothing. -/
def finalize (p : PSBT) : RM PSBT := do
  let tx ← liftP p.unsignedTransaction
  let spent ← liftP p.spentOutputs
  let mut witnesses : Array (Array ByteArray) := #[]
  for h : k in [0:p.inputs.size] do
    let i := p.inputs[k]
    if let some sig := i.tapKeySignature then
      witnesses := witnesses.push (← validatedKeyPathWitness k sig tx spent)
    else if !i.tapLeafScripts.isEmpty then
      let mut witness : Option (Array ByteArray) := none
      for leaf in i.tapLeafScripts do
        witness ← p.finalizedScriptPathWitness k leaf tx spent
        if witness.isSome then break
      let some w := witness | perr (.missingField s!"input {k} tap script sigs below threshold")
      witnesses := witnesses.push w
    else perr (.missingField s!"input {k} tap key sig")
  let removed : List UInt8 := [InType.tapKeySignature, InType.sighashType, InType.tapScriptSignature, InType.tapLeafScript]
  let inputs := (p.inputs.zip witnesses).map fun (i, w) =>
    let i := i.setFinalScriptWitness (some w)
    (⟨i.pairs.filter (fun q => !removed.contains q.type)⟩ : Input)
  return { p with inputs }

/-- The fully signed transaction. -/
def extractedTransaction (p : PSBT) : RM Transaction := do
  let mut tx ← liftP p.unsignedTransaction
  for h : k in [0:tx.inputs.size] do
    let some w := p.inputs[k]!.finalScriptWitness | perr (.missingField s!"input {k} final witness")
    tx := { tx with inputs := tx.inputs.modify k fun inp => { inp with witness := w } }
  return tx

end PSBT
end Winnow
