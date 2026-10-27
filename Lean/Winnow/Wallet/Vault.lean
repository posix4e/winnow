import Winnow.Wallet.VaultSetup
import Winnow.Wallet.Wallet

/-! # Shared-custody vaults (port of `Sources/WalletCore/Wallet/Vault.swift`)

A vault is a Taproot descriptor of one of two shapes — script-path k-of-n
(`tr(NUMS, multi_a/sortedmulti_a(k, …))`) or key-path n-of-n MuSig2 (`tr(musig(…)/<0;1>/*)`) — validated
so that signer independence is provable. Spends run as a PSBTv2 workflow: `createSpend` (creator),
`reviewSpend` (every cosigner's check of an untrusted proposal), `partialSign` (multi_a), the MuSig2
rounds, and `finalizeSpend`.

Randomness (change position, locktime draws, BIP340 auxiliary randomness, MuSig2 nonce randomness) is
injected as a `Randomness` (`Winnow.Wallet.Wallet`). -/

namespace Winnow
open Keys
open Tx (BitcoinNetwork)

inductive VaultError where
  | invalidDescriptor (reason : String)
  | scriptMismatch (index : UInt32) (choice : Nat)
  | noCosignerKey (input : Nat)
  | invalidSpend (reason : String)
  deriving Inhabited, BEq

namespace VaultError
def name : VaultError → String
  | .invalidDescriptor _ => "invalidDescriptor" | .scriptMismatch .. => "scriptMismatch"
  | .noCosignerKey _ => "noCosignerKey" | .invalidSpend _ => "invalidSpend"

def description : VaultError → String
  | .invalidDescriptor r => s!"The vault descriptor is invalid: {r}."
  | .scriptMismatch index choice => s!"Vault key {choice}/{index} does not produce the stored Bitcoin output."
  | .noCosignerKey input => s!"This device has no matching key for vault input {input + 1}."
  | .invalidSpend r => s!"This vault spend is unsafe: {r}."
end VaultError

/-- Vault failures: a `VaultError`, or another module's error by case name. -/
inductive VaultFailure where
  | vault (e : VaultError)
  | named (name : String)
  deriving Inhabited

def VaultFailure.name : VaultFailure → String | .vault e => e.name | .named n => n

abbrev VM := Except VaultFailure

def VM.lift {ε α} (name : ε → String) (r : Except ε α) : VM α := r.mapError (.named ∘ name)
def vfail {α} (e : VaultError) : VM α := throw (.vault e)

structure Vault.OutputCoordinate where
  choice : Int
  index : UInt32
  deriving Inhabited, BEq, Hashable

structure Vault.SpendReview.Output where
  amount : Int64
  scriptPubKey : ByteArray
  isVaultOwned : Bool
  deriving Inhabited, BEq

structure Vault.SpendReview where
  outputs : Array Vault.SpendReview.Output
  inputTotal : Int64
  outputTotal : Int64
  fee : Int64
  sighashTypes : Array UInt32
  transactionVersion : Int32
  fallbackLocktime : UInt32
  sequences : Array UInt32
  deriving Inhabited, BEq

inductive Vault.Policy where
  | multiA (threshold : Int) (sorted : Bool) (cosigners : Array Descriptor.KeyExpression) (internalKey : Descriptor.KeyExpression)
  | muSig2 (participants : Array Descriptor.SingleKey) (derivation : Descriptor.Derivation)
  deriving Inhabited

structure Vault.MuSig2Context where
  choice : Nat
  index : UInt32
  participants : Array ByteArray
  aggregate : ByteArray
  internalKey : ByteArray
  tweaks : Array ByteArray
  isXOnlyTweaks : Array Bool
  signingKey : ByteArray
  deriving Inhabited, BEq

def Vault.MuSig2Context.outputKey (c : Vault.MuSig2Context) : ByteArray := c.signingKey.extract 1 c.signingKey.size

structure Vault where
  descriptor : Descriptor
  network : BitcoinNetwork
  policy : Vault.Policy
  deriving Inhabited

namespace Vault

def maxMoney : Int64 := 2_100_000_000_000_000

def hdNetwork (n : BitcoinNetwork) : HDKey.Network := if n == .mainnet then .mainnet else .testnet

def publicKeyOf (d : Descriptor) (k : Descriptor.KeyExpression) (index : UInt32) (choice : Nat) : VM ByteArray :=
  VM.lift (·.name) (Descriptor.publicKey k index choice)

def xonly (k : ByteArray) : ByteArray := k.extract 1 k.size

def requireSuffix (d : Descriptor.Derivation) (role : VaultCosignerRole) : VM Unit := do
  unless d.elements == role.requiredDerivation do
    vfail (.invalidDescriptor "this vault's signer derivation paths are not the supported form, so its signers cannot be shown to be independent of one another")

def requireAccountKey (single : Descriptor.SingleKey) (role : VaultCosignerRole) (network : BitcoinNetwork) (what : String) : VM Unit := do
  let ok := match single.base with
    | .extended key _ => key.privateKey.isNone && single.origin.isSome
    | _ => false
  unless ok do vfail (.invalidDescriptor s!"every {what} must be an extended public key carrying its origin")
  let .extended _ keyNetwork := single.base | vfail (.invalidDescriptor s!"every {what} must be an extended public key carrying its origin")
  unless keyNetwork == hdNetwork network do
    vfail (.invalidDescriptor s!"a {what}'s extended key belongs to a different network than this vault")
  requireSuffix single.derivation role

def requireSupportedShape (policy : Policy) (d : Descriptor) (network : BitcoinNetwork) : VM Unit := do
  match policy with
  | .multiA _ _ cosigners internalKey =>
    let key ← publicKeyOf d internalKey 0 0
    unless xonly key == Taproot.unspendableInternalKey do
      vfail (.invalidDescriptor "this vault's internal key can spend on its own, which would bypass the signers it lists")
    for c in cosigners do
      let .single s := c | vfail (.invalidDescriptor "this vault nests an aggregated key where a single cosigner is required")
      requireAccountKey s .scriptPath network "cosigner"
  | .muSig2 participants derivation =>
    requireSuffix derivation .scriptPath
    for p in participants do requireAccountKey p .muSig2 network "participant"

def signerExpressions : Policy → Array Descriptor.KeyExpression
  | .multiA _ _ cs _ => cs
  | .muSig2 ps _ => ps.map .single

def requireDistinctSigners (policy : Policy) (d : Descriptor) : VM Unit := do
  let mut seen : Array ByteArray := #[]
  for s in signerExpressions policy do
    let key ← publicKeyOf d s 0 0
    if seen.contains key then
      vfail (.invalidDescriptor "the same signing key appears more than once, so this policy needs fewer independent signers than it claims")
    seen := seen.push key

def ofDescriptor (descriptor : Descriptor) (network : BitcoinNetwork) : VM Vault := do
  let policy ← match descriptor.expression with
    | .tr internalKey (some (.leaf (.multiA t keys))) => pure (Policy.multiA t false keys internalKey)
    | .tr internalKey (some (.leaf (.sortedMultiA t keys))) => pure (Policy.multiA t true keys internalKey)
    | .tr (.musig ps d) none => pure (Policy.muSig2 ps d)
    | _ => vfail (.invalidDescriptor "expected tr(KEY, multi_a(k, …)) or tr(musig(…)/…)")
  requireSupportedShape policy descriptor network
  requireDistinctSigners policy descriptor
  return { descriptor, network, policy }

def parse (text : String) (network : BitcoinNetwork) : VM Vault := do
  ofDescriptor (← VM.lift (·.name) (Descriptor.parse text)) network

/-- `tr(NUMS, sortedmulti_a(k, …))` over validated, distinct script-path signer expressions. -/
def multiADescriptor (k : Int) (cosigners : Array String) : VM Descriptor := do
  let validated ← cosigners.mapM fun c => VM.lift (·.name) (VaultCosignerKey.validateWithoutNetwork c .scriptPath)
  for i in [0:validated.size] do
    if (validated.extract 0 i).any (·.identity == validated[i]!.identity) then throw (.named "duplicateKey")
  let text := s!"tr({hex Taproot.unspendableInternalKey},sortedmulti_a({k},{",".intercalate (validated.map (·.expression)).toList}))"
  VM.lift (·.name) (Descriptor.parse text)

def usesUnspendableInternalKey (v : Vault) : Bool :=
  match v.policy with
  | .multiA _ _ _ internalKey => match publicKeyOf v.descriptor internalKey 0 0 with
    | .ok key => xonly key == Taproot.unspendableInternalKey
    | .error _ => false
  | _ => false

def threshold (v : Vault) : Int := match v.policy with | .multiA t .. => t | .muSig2 ps _ => ps.size
def signerCount (v : Vault) : Nat := match v.policy with | .multiA _ _ cs _ => cs.size | .muSig2 ps _ => ps.size
def isScriptPath (v : Vault) : Bool := match v.policy with | .multiA .. => true | _ => false

def signerKeys (v : Vault) (index : UInt32 := 0) (choice : Nat := 0) : VM (Array ByteArray) :=
  (signerExpressions v.policy).mapM fun s => publicKeyOf v.descriptor s index choice

/-- The `multi_a(` argument list as written (after the threshold); `[]` for MuSig2. The first
`multi_a(` of the text is used, which `sortedmulti_a(` also contains. -/
def cosignerExpressions (v : Vault) : Array String := Id.run do
  let .multiA .. := v.policy | return #[]
  let text := v.descriptor.serialized
  let parts := text.splitOn "multi_a("
  if parts.length < 2 then return #[]
  let rest := (text.drop (parts.head!.length + "multi_a(".length)).toString
  let mut depth := 0
  let mut current := ""
  let mut out : Array String := #[]
  for c in rest.toList do
    if c == '(' then depth := depth + 1; current := current.push c
    else if c == ')' then
      if depth == 0 then
        out := out.push current
        return out.extract 1 out.size
      depth := depth - 1; current := current.push c
    else if c == ',' && depth == 0 then out := out.push current; current := ""
    else current := current.push c
  return #[]

/-! ### Watching -/

def derivedAt (v : Vault) (index : UInt32) (choice : Nat) : VM Descriptor.DerivedOutput := do
  let outs ← VM.lift (·.name) (v.descriptor.derived index v.network)
  let some o := outs[choice]? | throw (.named "indexOutOfRange")
  return o

def scriptPubKey (v : Vault) (index : UInt32) (choice : Nat := 0) : VM ByteArray := return (← v.derivedAt index choice).scriptPubKey
def address (v : Vault) (index : UInt32) (choice : Nat := 0) : VM String := return (← v.derivedAt index choice).address

def watchScripts (v : Vault) (count : UInt32) : VM (Array ByteArray) := do
  let mut out := #[]
  for i in [0:count.toNat] do
    for o in ← VM.lift (·.name) (v.descriptor.derived i.toUInt32 v.network) do out := out.push o.scriptPubKey
  return out

/-! ### MuSig2 context -/

def muSig2Context (v : Vault) (choice : Nat) (index : UInt32) : VM MuSig2Context := do
  let .muSig2 participantKeys derivation := v.policy | vfail (.invalidDescriptor "not a musig vault")
  let resolved ← participantKeys.mapM fun p => publicKeyOf v.descriptor (.single p) index choice
  let sorted := (MuSig.keySort resolved.toList).toArray
  let aggregate ← VM.lift (·.name) (MuSig.aggregate sorted.toList)
  let mut synthetic ← VM.lift (·.name) (MuSig.syntheticExtendedKey aggregate)
  let mut tweaks : Array ByteArray := #[]
  let mut isXOnly : Array Bool := #[]
  for e in derivation.elements do
    let step ← match e with
      | .step s => pure s
      | .multipath vs => match vs[choice]? with | some s => pure s | none => throw (.named "indexOutOfRange")
      | .wildcard hardened => if hardened then vfail (.invalidDescriptor "hardened musig wildcard") else pure index
    tweaks := tweaks.push (MuSig.bip328Tweak synthetic.chainCode synthetic.publicKey step)
    isXOnly := isXOnly.push false
    synthetic ← VM.lift (·.name) (synthetic.child step)
  let internalKey := xonly synthetic.publicKey
  tweaks := tweaks.push (Taproot.tweak internalKey none)
  isXOnly := isXOnly.push true
  let signingKey ← VM.lift (·.name) (MuSig.aggregateTweaked sorted.toList tweaks.toList isXOnly.toList)
  unless (← v.scriptPubKey index choice) == ByteArray.mk #[0x51, 0x20] ++ xonly signingKey do
    vfail (.invalidDescriptor "musig tweak chain mismatch")
  return { choice, index, participants := sorted, aggregate, internalKey, tweaks, isXOnlyTweaks := isXOnly, signingKey }

/-! ### Review -/

def checkFeeCeiling (fee inputTotal : Int64) : VM Unit := do
  unless fee ≤ inputTotal / 10 do
    vfail (.invalidSpend s!"the {fee.toInt}-sat fee exceeds the 10% safety limit for these inputs")

def checkSpendShape (p : PSBT) : VM Unit := do
  if p.inputs.isEmpty then vfail (.invalidSpend "it has no inputs")
  if p.outputs.isEmpty then vfail (.invalidSpend "it has no outputs")
  if p.outputs.size > 1000 then vfail (.invalidSpend "it has more than 1,000 outputs")
  unless p.txVersion == 1 || p.txVersion == 2 do vfail (.invalidSpend s!"transaction version {p.txVersion} is not supported")

def tapLeafEq (a b : PSBT.TapLeafScript) : Bool :=
  a.controlBlock == b.controlBlock && a.script == b.script && a.leafVersion == b.leafVersion

def toTxControlBlock (c : Taproot.ControlBlock) : Tx.Taproot.ControlBlock :=
  { leafVersion := c.leafVersion, outputKeyParity := c.outputKeyParity, internalKey := c.internalKey, path := c.path.toArray }

def validatePolicyFields (v : Vault) (input : PSBT.Input) (inputIndex : Nat) (u : WalletUTXO) : VM Unit := do
  match v.policy with
  | .multiA .. =>
    let (internalKey, tree) ← VM.lift (·.name) (v.descriptor.resolvedTaproot u.index u.chain.rawValue)
    let some t@(.leaf version script) := tree | vfail (.invalidSpend s!"input {inputIndex + 1} has no expected vault leaf")
    let control ← VM.lift (·.name) (Taproot.controlBlock internalKey t 0)
    let expected : PSBT.TapLeafScript := { controlBlock := toTxControlBlock control, script, leafVersion := version }
    let leaves := input.tapLeafScripts
    unless input.tapInternalKey == some internalKey && leaves.size == 1 && tapLeafEq leaves[0]! expected do
      vfail (.invalidSpend s!"input {inputIndex + 1} changes the vault spending policy")
  | .muSig2 .. =>
    let c ← v.muSig2Context u.chain.rawValue u.index
    let m := input.musig2ParticipantPubKeys
    unless input.tapInternalKey == some c.internalKey && m.size == 1 &&
        (m.find? (·.1 == c.aggregate)).map (·.2) == some c.participants do
      vfail (.invalidSpend s!"input {inputIndex + 1} changes the MuSig2 participants")

def checkedInputFields (v : Vault) (input : PSBT.Input) (inputIndex : Nat) (u : WalletUTXO) (chainTip : UInt32) :
    VM (UInt32 × UInt32) := do
  unless u.amount > 0 && u.amount ≤ maxMoney && input.witnessUTXO == some u.spentOutput do
    vfail (.invalidSpend s!"input {inputIndex + 1} has the wrong amount or locking script")
  if u.isCoinbase then
    let matureAt := u.height + Wallet.coinbaseMaturity - 1
    unless chainTip ≥ matureAt do
      vfail (.invalidSpend s!"input {inputIndex + 1} spends a coinbase that matures in {matureAt - chainTip} blocks")
  unless (← v.scriptPubKey u.index u.chain.rawValue) == u.scriptPubKey do
    vfail (.invalidSpend s!"input {inputIndex + 1} does not belong to this descriptor")
  let raw := input.sighashType.getD 0
  unless raw == 0 || raw == 1 do vfail (.invalidSpend s!"input {inputIndex + 1} does not commit to every output")
  v.validatePolicyFields input inputIndex u
  return (raw, input.sequence.getD 0xFFFF_FFFF)

def u32LE (n : UInt32) : ByteArray := ByteArray.mk #[n.toUInt8, (n >>> 8).toUInt8, (n >>> 16).toUInt8, (n >>> 24).toUInt8]

def reviewedInputs (v : Vault) (p : PSBT) (known : Array WalletUTXO) (chainTip : UInt32) :
    VM (Int64 × Array UInt32 × Array UInt32) := do
  let mut seen : Array ByteArray := #[]
  let mut total : Int := 0
  let mut sighashTypes := #[]
  let mut sequences := #[]
  for h : k in [0:p.inputs.size] do
    let input := p.inputs[k]
    let (some txid, some vout) := (input.previousTxid, input.outputIndex)
      | vfail (.invalidSpend s!"input {k + 1} has no complete outpoint")
    unless txid.size == 32 do vfail (.invalidSpend s!"input {k + 1} has no complete outpoint")
    let id := txid ++ u32LE vout
    if seen.contains id then vfail (.invalidSpend s!"input {k + 1} repeats an earlier outpoint")
    seen := seen.push id
    let some u := known.find? (fun c => c.txid == txid && c.vout == vout)
      | vfail (.invalidSpend s!"input {k + 1} is not an available vault coin")
    let (sh, sq) ← v.checkedInputFields input k u chainTip
    sighashTypes := sighashTypes.push sh
    sequences := sequences.push sq
    total := total + u.amount.toInt
    unless total ≤ maxMoney.toInt do vfail (.invalidSpend "input amounts exceed Bitcoin's supply")
  return (Int64.ofInt total, sighashTypes, sequences)

def ownedScripts (v : Vault) (coordinates : Array OutputCoordinate) : VM (Array ByteArray) := do
  let mut candidates : Array OutputCoordinate := #[]
  for c in coordinates do
    if 0 ≤ c.choice && c.choice ≤ 1 && !candidates.contains c then candidates := candidates.push c
  if candidates.size > 1024 then vfail (.invalidSpend "too many candidate vault output paths")
  candidates.mapM fun c => v.scriptPubKey c.index c.choice.toNat

def reviewedOutputs (v : Vault) (p : PSBT) (inputTotal : Int64) (coordinates : Array OutputCoordinate) :
    VM (Array SpendReview.Output × Int64) := do
  let owned ← v.ownedScripts coordinates
  let mut total : Int := 0
  let mut reviewed := #[]
  for h : k in [0:p.outputs.size] do
    let o := p.outputs[k]
    let (some amount, some script) := (o.amount, o.script)
      | vfail (.invalidSpend s!"output {k + 1} has an invalid amount or script")
    unless amount > 0 && amount ≤ maxMoney && !script.isEmpty do
      vfail (.invalidSpend s!"output {k + 1} has an invalid amount or script")
    total := total + amount.toInt
    unless total ≤ maxMoney.toInt do vfail (.invalidSpend "output amounts exceed Bitcoin's supply")
    reviewed := reviewed.push { amount, scriptPubKey := script, isVaultOwned := owned.contains script }
  unless total ≤ inputTotal.toInt do vfail (.invalidSpend "outputs exceed its known inputs")
  return (reviewed, Int64.ofInt total)

/-- Validates an untrusted spend proposal before it is displayed, signed, finalized or broadcast. -/
def reviewSpend (v : Vault) (p : PSBT) (known : Array WalletUTXO) (coordinates : Array OutputCoordinate) (chainTip : UInt32) :
    VM SpendReview := do
  checkSpendShape p
  let (inputTotal, sighashTypes, sequences) ← v.reviewedInputs p known chainTip
  let (outputs, outputTotal) ← v.reviewedOutputs p inputTotal coordinates
  let fee := inputTotal - outputTotal
  checkFeeCeiling fee inputTotal
  return { outputs, inputTotal, outputTotal, fee, sighashTypes, transactionVersion := p.txVersion,
           fallbackLocktime := p.fallbackLocktime, sequences }

/-- Which signers (by position) approved every input, by verified script signatures. -/
def signers (v : Vault) (p : PSBT) (known : Array WalletUTXO) : VM (Array Nat) := do
  let .multiA _ _ cosigners _ := v.policy | return #[]
  let tx ← VM.lift (·.name) p.unsignedTransaction
  let spent ← VM.lift (·.name) p.spentOutputs
  let mut approved : Option (Array Nat) := none
  for h : k in [0:p.inputs.size] do
    let input := p.inputs[k]
    let (some txid, some vout) := (input.previousTxid, input.outputIndex)
      | vfail (.invalidSpend s!"input {k + 1} is not an available vault coin")
    let some u := known.find? (fun c => c.txid == txid && c.vout == vout)
      | vfail (.invalidSpend s!"input {k + 1} is not an available vault coin")
    let signed ← VM.lift (·.name) (p.verifiedScriptPathSigners k tx spent)
    let mut here : Array Nat := #[]
    for i in [0:cosigners.size] do
      let key ← publicKeyOf v.descriptor cosigners[i]! u.index u.chain.rawValue
      if signed.contains (xonly key) then here := here.push i
    approved := some (match approved with | some a => a.filter here.contains | none => here)
  return approved.getD #[]

/-! ### Creating a spend -/

def witnessBytesPerInput (v : Vault) (index : UInt32) : Int :=
  match v.policy with
  | .multiA _ _ cosigners _ =>
    let keyCount : Int := cosigners.size
    let scriptSize : Int := match v.descriptor.resolvedTaproot index 0 with
      | .ok (_, some (.leaf _ script)) => script.size
      | .ok (_, some _) => 0
      | _ => keyCount * 34 + 2
    1 + keyCount * 65 + (1 + scriptSize) + (1 + 33)
  | .muSig2 .. => 66

def cosignerKeyExpressions (v : Vault) : Array Descriptor.KeyExpression :=
  match v.policy with | .multiA _ _ cs _ => cs | _ => #[]

/-- BIP371 origins of every cosigner at (choice, index), keyed by x-only key (a later equal key wins, as
in the Swift dictionary). -/
def keyOrigins (v : Vault) (choice : Nat) (index : UInt32) (leafHashes : Array ByteArray) : VM (Array (ByteArray × PSBT.KeyOrigin)) := do
  let mut out : Array (ByteArray × PSBT.KeyOrigin) := #[]
  for e in v.cosignerKeyExpressions do
    let .single s := e | continue
    let some origin := s.origin | continue
    let .extended .. := s.base | continue
    let compressed ← publicKeyOf v.descriptor e index choice
    let mut suffix : Array UInt32 := #[]
    for el in s.derivation.elements do
      match el with
      | .step st => suffix := suffix.push st
      | .multipath vs => match vs[choice]? with
        | some x => suffix := suffix.push x
        | none => throw (.named "indexOutOfRange")
      | .wildcard hardened => suffix := suffix.push (index + (if hardened then HDKey.hardenedOffset else 0))
    let x := xonly compressed
    out := (out.filter (·.1 != x)).push (x, { leafHashes, masterFingerprint := origin.fingerprint, path := origin.path ++ suffix })
  return out

def attachVaultFields (v : Vault) (p : PSBT) (input : Nat) (choice : Nat) (index : UInt32) : VM PSBT := do
  match v.policy with
  | .multiA .. =>
    let (internalKey, tree) ← VM.lift (·.name) (v.descriptor.resolvedTaproot index choice)
    let some t@(.leaf version script) := tree | vfail (.invalidDescriptor "multi_a vault must have a single leaf")
    let control ← VM.lift (·.name) (Taproot.controlBlock internalKey t 0)
    let origins ← v.keyOrigins choice index #[]
    VM.lift (·.name) (p.attachScriptPath input (toTxControlBlock control) ⟨script⟩ version origins)
  | .muSig2 .. =>
    let c ← v.muSig2Context choice index
    VM.lift (·.name) (p.attachMuSig2 input c.internalKey c.aggregate c.participants)

partial def collectLeaves (t : Taproot.Tree) (depth : UInt8) (acc : Array (UInt8 × UInt8 × ByteArray)) : Array (UInt8 × UInt8 × ByteArray) :=
  match t with
  | .leaf version script => acc.push (depth, version, script)
  | .branch l r => collectLeaves r (depth + 1) (collectLeaves l (depth + 1) acc)

def attachVaultOutputFields (v : Vault) (p : PSBT) (output : Nat) (choice : Nat) (index : UInt32) : VM PSBT := do
  let (internalKey, tree) ← VM.lift (·.name) (v.descriptor.resolvedTaproot index choice)
  let mut o := p.outputs[output]!.setTapInternalKey (some internalKey)
  if let some t := tree then
    let tuples := collectLeaves t 0 #[]
    o := o.setTapTree (some tuples)
    if let .multiA .. := v.policy then
      if tuples.size == 1 then
        let (_, leafVersion, script) := tuples[0]!
        let leafHash := Tx.Taproot.leafHash leafVersion ⟨script⟩
        o := o.setTapBIP32Derivation (← v.keyOrigins choice index #[leafHash])
  return { p with outputs := p.outputs.set! output o }

/-- The creator role: coin selection, the unsigned transaction and every vault field. -/
def createSpend (v : Vault) (utxos : Array WalletUTXO) (payments : Array Payment) (changeIndex : UInt32)
    (feeRateSatPerVByte : Float) (chainTip : UInt32) (random : Randomness := .system) : ExceptT VaultFailure IO PSBT := do
  for u in utxos do
    unless (← v.scriptPubKey u.index u.chain.rawValue) == u.scriptPubKey do
      throw (.vault (.scriptMismatch u.index u.chain.rawValue))
  let changeScript ← v.scriptPubKey changeIndex 1
  let selection ← VM.lift (·.name) (CoinSelection.select utxos payments changeScript feeRateSatPerVByte
    (v.witnessBytesPerInput ((utxos[0]?.map (·.index)).getD 0)))
  checkFeeCeiling selection.fee (selection.selected.foldl (fun a u => a + u.amount) 0)
  let change : Option Payment := selection.changeAmount.map fun a => { amount := a, scriptPubKey := changeScript }
  let first ← random.draw
  let lt ← if !(TransactionBuilder.draw first < 0.1) then pure chainTip
    else do pure (TransactionBuilder.antiFeeSnipingLocktime chainTip first (← random.draw))
  let position ← match change with
    | some _ => some <$> random.changePosition payments.size
    | none => pure none
  let tx ← VM.lift (·.name) (TransactionBuilder.build (selection.selected.map (·.outpoint)) payments change
    (changePosition := position.map Int.ofNat) (locktime := lt))
  let mut psbt ← VM.lift (·.name) (PSBT.create tx (selection.selected.map fun u => { spentOutput := u.spentOutput })
    (tx.outputs.map fun _ => {}))
  for h : k in [0:selection.selected.size] do
    let u := selection.selected[k]
    psbt ← v.attachVaultFields psbt k u.chain.rawValue u.index
  if let some c := change then
    for k in [0:tx.outputs.size] do
      let o := tx.outputs[k]!
      if o.scriptPubKey == c.scriptPubKey && o.value == c.amount then
        psbt ← v.attachVaultOutputFields psbt k 1 changeIndex
  return psbt

/-! ### Signing -/

/-- The master walked along a PSBT origin path; `none` when no BIP32 key can have that path. -/
def keyAlong (path : Array UInt32) (master : HDKey) : VM (Option HDKey) := do
  let mut key := master
  for step in path do
    match key.child step with
    | .ok k => key := k
    | .error .depthExhausted => return none
    | .error e => throw (.named e.name)
  return some key

def partialSignUnchecked (v : Vault) (p : PSBT) (master : HDKey) (aux : IO ByteArray) : ExceptT VaultFailure IO PSBT := do
  let .multiA .. := v.policy | throw (.vault (.invalidDescriptor "not a multi_a vault"))
  let mut p := p
  for k in [0:p.inputs.size] do
    let mut secrets : Array ByteArray := #[]
    for (x, origin) in p.inputs[k]!.tapBIP32Derivation do
      if origin.masterFingerprint != master.fingerprint then continue
      let some key ← keyAlong origin.path master | continue
      let some secret := key.privateKey | continue
      unless xonly key.publicKey == x do continue
      secrets := secrets.push secret
    if secrets.isEmpty then throw (.vault (.noCosignerKey k))
    p ← VM.lift (·.name) (p.signScriptPath k secrets (← aux))
  return p

/-- Partial-signs every input with the cosigner keys derived from `master` (after review). -/
def partialSign (v : Vault) (p : PSBT) (master : HDKey) (known : Array WalletUTXO) (coordinates : Array OutputCoordinate)
    (chainTip : UInt32) (aux : IO ByteArray := IO.getRandomBytes 32) : ExceptT VaultFailure IO PSBT := do
  discard <| (v.reviewSpend p known coordinates chainTip : VM SpendReview)
  v.partialSignUnchecked p master aux

/-- The key-path sighash a MuSig2 cosigner signs (DEFAULT / ALL only). -/
def keyPathSighash (p : PSBT) (input : Nat) : VM ByteArray := do
  let some i := p.inputs[input]? | throw (.named "indexOutOfRange")
  let raw := i.sighashType.getD 0
  unless raw ≤ 255 do throw (.named "malformed")
  let hashType : SighashBIP341.HashType := ⟨raw.toUInt8⟩
  unless hashType.commitsToAllOutputs do throw (.named "malformed")
  let tx ← VM.lift (·.name) p.unsignedTransaction
  let spent ← VM.lift (·.name) p.spentOutputs
  VM.lift (·.name) (SighashBIP341.sighash tx input spent hashType)

def privateKeyFor (single : Descriptor.SingleKey) (master : HDKey) (c : MuSig2Context) : VM (Option ByteArray) := do
  let some origin := single.origin | return none
  if origin.fingerprint != master.fingerprint then return none
  let .extended base _ := single.base | return none
  let mut key := master
  for step in origin.path do key ← VM.lift (·.name) (key.child step)
  if key.publicKey != base.publicKey then return none
  for e in single.derivation.elements do
    match e with
    | .step s => key ← VM.lift (·.name) (key.child s)
    | .multipath vs => key ← VM.lift (·.name) (key.child (vs[c.choice]?.getD 0))
    | .wildcard hardened => if hardened then return none else key ← VM.lift (·.name) (key.child c.index)
  return key.privateKey

def participantSecrets (v : Vault) (c : MuSig2Context) (master : HDKey) : VM (Array (ByteArray × ByteArray)) := do
  let .muSig2 participantKeys _ := v.policy | return #[]
  let mut out := #[]
  for single in participantKeys do
    let some secret ← privateKeyFor single master c | continue
    let some participant := (publicKeyOf? secret) | continue
    if c.participants.contains participant then out := out.push (participant, secret)
  return out
where
  publicKeyOf? (secret : ByteArray) : Option ByteArray := (Keys.publicKeyOf secret).toOption

def muSig2AttachNonceUnchecked (v : Vault) (p : PSBT) (input : Nat) (c : MuSig2Context) (master : HDKey)
    (rand : IO ByteArray) (extraInput : Option ByteArray := none) :
    ExceptT VaultFailure IO (PSBT × Array (ByteArray × ByteArray)) := do
  let message ← (keyPathSighash p input : VM ByteArray)
  let mut p := p
  let mut secretNonces : Array (ByteArray × ByteArray) := #[]
  for (participant, secret) in ← (v.participantSecrets c master : VM _) do
    let (sec, pub) ← (VM.lift (·.name) (MuSig.nonceGenerate (some secret) participant (some c.outputKey) (some message)
      extraInput (← rand)) : VM _)
    p ← (VM.lift (·.name) (p.attachMuSig2PubNonce input { participant, aggregate := c.signingKey } pub) : VM _)
    secretNonces := (secretNonces.filter (·.1 != participant)).push (participant, sec)
  if secretNonces.isEmpty then throw (.vault (.noCosignerKey input))
  return (p, secretNonces)

/-- MuSig2 round 1 (after review): this cosigner's public nonces; the secret nonces to keep. -/
def muSig2AttachNonce (v : Vault) (p : PSBT) (input : Nat) (c : MuSig2Context) (master : HDKey) (known : Array WalletUTXO)
    (coordinates : Array OutputCoordinate) (chainTip : UInt32) (rand : IO ByteArray := IO.getRandomBytes 32)
    (extraInput : Option ByteArray := none) : ExceptT VaultFailure IO (PSBT × Array (ByteArray × ByteArray)) := do
  discard <| (v.reviewSpend p known coordinates chainTip : VM SpendReview)
  v.muSig2AttachNonceUnchecked p input c master rand extraInput

def session (p : PSBT) (input : Nat) (c : MuSig2Context) : VM MuSig.Session := do
  VM.lift (·.name) (p.muSig2Session input c.aggregate c.tweaks c.isXOnlyTweaks (← keyPathSighash p input))

/-- MuSig2 round 2: partial signatures; the secret nonces come back zeroed once used. -/
def muSig2SignUnchecked (v : Vault) (p : PSBT) (input : Nat) (c : MuSig2Context) (master : HDKey)
    (secretNonces : Array (ByteArray × ByteArray)) : VM (PSBT × Array (ByteArray × ByteArray)) := do
  let s ← session p input c
  let mut p := p
  let mut nonces := secretNonces
  let mut signed := 0
  for (participant, secret) in ← v.participantSecrets c master do
    let some sec := (nonces.find? (·.1 == participant)).map (·.2) | continue
    let (r, zeroed) := p.signMuSig2 input { participant, aggregate := c.signingKey } sec secret s
    p ← VM.lift (·.name) r
    nonces := nonces.map fun (k, x) => if k == participant then (k, zeroed) else (k, x)
    signed := signed + 1
  if signed == 0 then vfail (.noCosignerKey input)
  return (p, nonces)

def muSig2Sign (v : Vault) (p : PSBT) (input : Nat) (c : MuSig2Context) (master : HDKey) (secretNonces : Array (ByteArray × ByteArray))
    (known : Array WalletUTXO) (coordinates : Array OutputCoordinate) (chainTip : UInt32) : VM (PSBT × Array (ByteArray × ByteArray)) := do
  discard <| v.reviewSpend p known coordinates chainTip
  v.muSig2SignUnchecked p input c master secretNonces

/-- MuSig2 final step: the aggregate signature. -/
def muSig2Aggregate (v : Vault) (p : PSBT) (input : Nat) (c : MuSig2Context) (known : Array WalletUTXO)
    (coordinates : Array OutputCoordinate) (chainTip : UInt32) : VM PSBT := do
  discard <| v.reviewSpend p known coordinates chainTip
  VM.lift (·.name) (p.aggregateMuSig2 input (← session p input c))

/-- Finalizes the fully signed spend and extracts the raw transaction (standard size enforced). -/
def finalizeSpend (v : Vault) (p : PSBT) (known : Array WalletUTXO) (coordinates : Array OutputCoordinate) (chainTip : UInt32) :
    VM (PSBT × Transaction) := do
  discard <| v.reviewSpend p known coordinates chainTip
  let p ← VM.lift (·.name) p.finalize
  let tx ← VM.lift (·.name) p.extractedTransaction
  (Wallet.checkStandardSize tx).mapError (.named ·.name)
  return (p, tx)

end Vault
end Winnow
