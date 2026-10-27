import Winnow.Wallet.Types
import Winnow.Wallet.CoinSelection
import Winnow.Wallet.Descriptor
import Winnow.Wallet.PSBTRoles

/-! # Taproot multisig accounts (port of `Sources/WalletCore/Wallet/MultisigAccount.swift`, upstream 1cf93fb)

A raw k-of-n script-path account `tr(NUMS, sortedmulti_a(k, XPUB/<0;1>/*, …))` (BIP386, BIP387), optionally
with a timelocked recovery leaf beside the signers' leaf (`and_v(v:pk(K),older(N))` or
`and_v(v:multi_a(m,…),older(N))`). The internal key is BIP341's NUMS point (bare, or as Liana's xpub on it),
so the leaves are the only way to spend. Spends travel as PSBTs with the BIP371 leaf, origin and signature
fields: `createSpend` builds one, `sign` adds a signer's script-path signatures after reviewing it,
`approvals` counts verified signatures, `finalizeSpend` assembles the BIP387 witness.

Differences of form from the Swift struct:
* Failures are `MultisigFailure`: this module's `MultisigAccountError` (same cases and reason texts), or
  another module's error by its case name (`named`), as `WalletFailure` does.
* Swift `Set`s and dictionaries are arrays here: `approvals` is the positions in ascending order, key
  origins are (x-only key, origin) pairs with the last value per key kept.
* Randomness is an argument: `createSpend` takes the two anti-fee-sniping draws (Swift's `randomness`
  closure, called once or twice) and the change position (Swift's `Int.random(in: 0 ... n)` inside
  `TransactionBuilder.build`); `sign` takes the BIP340 auxiliary randomness (Swift passes nil, so P256K
  draws it).
* `MultisigAccountRecord.checkLedgerRegistration` needs `LedgerWalletPolicy` (Phase C); the record's
  `ledger` field is carried and coded here, the check is not. -/

namespace Winnow
open Keys SwiftJSON
open Tx (BitcoinNetwork)

/-! ## Errors -/

inductive MultisigAccountError where
  /-- Not a supported account shape. `reason` is always a literal written here, never input. -/
  | invalidDescriptor (reason : String)
  /-- A coin's scriptPubKey does not match the descriptor at its coordinates. -/
  | scriptMismatch (index : UInt32) (choice : Nat)
  /-- No signer key for this input derives from the loaded key. -/
  | noSignerKey (input : Nat)
  /-- An imported spend is not an exact, safe spend of known account coins. -/
  | invalidSpend (reason : String)
  deriving Inhabited, BEq, Repr

namespace MultisigAccountError
def name : MultisigAccountError → String
  | .invalidDescriptor _ => "invalidDescriptor" | .scriptMismatch .. => "scriptMismatch"
  | .noSignerKey _ => "noSignerKey" | .invalidSpend _ => "invalidSpend"

/-- `errorDescription`. -/
def description : MultisigAccountError → String
  | .invalidDescriptor reason => s!"The multisig descriptor is invalid: {reason}."
  | .scriptMismatch index choice => s!"Multisig key {choice}/{index} does not produce the stored Bitcoin output."
  | .noSignerKey input => s!"This device holds no signer key for input {input + 1}."
  | .invalidSpend reason => s!"This multisig spend is refuse: {reason}."
end MultisigAccountError

inductive MultisigFailure where
  | account (e : MultisigAccountError)
  /-- An error of another module (descriptor, PSBT, coin selection, BIP32, …), by its case name. -/
  | named (name : String)
  deriving Inhabited, BEq, Repr

def MultisigFailure.name : MultisigFailure → String | .account e => e.name | .named n => n

abbrev MAM := Except MultisigFailure

namespace MultisigAccount
def fail {α} (e : MultisigAccountError) : MAM α := throw (.account e)
def invalid {α} (reason : String) : MAM α := fail (.invalidDescriptor reason)
def refuse {α} (reason : String) : MAM α := fail (.invalidSpend reason)
def lift {ε α} (name : ε → String) (r : Except ε α) : MAM α := r.mapError (.named ∘ name)
end MultisigAccount

/-! ## Ledger registration (data only; the protocol is Phase C) -/

/-- `LedgerRegistration` (Ledger/LedgerMultisig.swift): what a Ledger returned when it registered the
account. Coded as Swift's synthesized `Codable` (`Data` fields base64). -/
structure LedgerRegistration where
  /-- The name the Ledger shows for the account. -/
  policyName : String
  policyID : ByteArray
  hmac : ByteArray
  masterFingerprint : UInt32
  /-- The Ledger signer's account path, hardened bits included. -/
  keyPath : Array UInt32
  deriving Inhabited, BEq

namespace LedgerRegistration
def toJV (r : LedgerRegistration) : JV :=
  obj [("policyName", some (.str r.policyName)), ("policyID", some (ofData r.policyID)), ("hmac", some (ofData r.hmac)),
    ("masterFingerprint", some (ofInt r.masterFingerprint.toNat)),
    ("keyPath", some (.arr (r.keyPath.map (ofInt ·.toNat))))]

def ofJV (v : JV) : D LedgerRegistration := do
  let kvs ← asObject v
  let policyName ← key kvs "policyName" asString
  let policyID ← key kvs "policyID" asData
  let hmac ← key kvs "hmac" asData
  let masterFingerprint ← key kvs "masterFingerprint" asUInt32
  let keyPath ← key kvs "keyPath" (asArray asUInt32)
  return { policyName, policyID, hmac, masterFingerprint, keyPath }
end LedgerRegistration

/-! ## The stored record -/

/-- One stored multisig account: the descriptor, its address frontiers and the coins the wallet's filter
scan found for it (spent ones kept as tombstones). JSON keys match the shared-account Winnow's vault
records (`utxos` for `allUtxos`). -/
structure MultisigAccountRecord where
  /-- The descriptor's BIP380 checksum. -/
  id : String
  name : String
  descriptor : String
  createdAtHeight : UInt32
  nextReceiveIndex : UInt32 := 0
  nextChangeIndex : UInt32 := 0
  allUtxos : Array WalletUTXO := #[]
  /-- Present when a Ledger is one of the signers and has registered this account. -/
  ledger : Option LedgerRegistration := none
  deriving Inhabited, BEq

namespace MultisigAccountRecord
def utxos (r : MultisigAccountRecord) : Array WalletUTXO := r.allUtxos.filter (!·.isSpent)
def balance (r : MultisigAccountRecord) : Int64 := r.utxos.foldl (fun a u => a + u.amount) 0

def toJV (r : MultisigAccountRecord) : JV :=
  obj [("id", some (.str r.id)), ("name", some (.str r.name)), ("descriptor", some (.str r.descriptor)),
    ("createdAtHeight", some (ofInt r.createdAtHeight.toNat)), ("nextReceiveIndex", some (ofInt r.nextReceiveIndex.toNat)),
    ("nextChangeIndex", some (ofInt r.nextChangeIndex.toNat)), ("utxos", some (.arr (r.allUtxos.map WalletUTXO.toJV))),
    ("ledger", r.ledger.map LedgerRegistration.toJV)]

/-- The synthesized decoder, in declaration order: every key but `ledger` is required. -/
def ofJV (v : JV) : D MultisigAccountRecord := do
  let kvs ← asObject v
  let id ← key kvs "id" asString
  let name ← key kvs "name" asString
  let descriptor ← key kvs "descriptor" asString
  let createdAtHeight ← key kvs "createdAtHeight" asUInt32
  let nextReceiveIndex ← key kvs "nextReceiveIndex" asUInt32
  let nextChangeIndex ← key kvs "nextChangeIndex" asUInt32
  let allUtxos ← key kvs "utxos" (asArray WalletUTXO.ofJV)
  let ledger ← keyIfPresent kvs "ledger" LedgerRegistration.ofJV
  return { id, name, descriptor, createdAtHeight, nextReceiveIndex, nextChangeIndex, allUtxos, ledger }
end MultisigAccountRecord

/-! ## The account -/

namespace MultisigAccount

/-- A descriptor coordinate that may legitimately receive money back into this account. -/
structure OutputCoordinate where
  choice : Int
  index : UInt32
  deriving Inhabited, BEq, Repr

/-- The two ways an account can spend. -/
inductive SpendPath where
  /-- Any `threshold` of the signers, at once. -/
  | signers
  /-- The recovery keys, once each coin is `Recovery.blocks` old. -/
  | recovery
  deriving Inhabited, BEq, Repr

structure SpendReview.Output where
  amount : Int64
  scriptPubKey : ByteArray
  isAccountOwned : Bool
  deriving Inhabited, BEq

structure SpendReview where
  outputs : Array SpendReview.Output
  inputTotal : Int64
  outputTotal : Int64
  fee : Int64
  /-- `.recovery` when every input's sequence meets the recovery lock. -/
  path : SpendPath := .signers
  deriving Inhabited, BEq

/-- The optional second leaf: after a coin has not moved for `blocks` blocks, `threshold` of these keys may
spend it without the signers. -/
structure Recovery where
  threshold : Int
  keys : Array Descriptor.SingleKey
  /-- BIP68 relative lock in blocks, 1…65535. -/
  blocks : UInt32
  deriving Inhabited

/-- How a new account's recovery leaf is chosen. -/
inductive RecoveryPlan where
  /-- After the delay, `threshold` of the same signers, each on its second path `/<2;3>/*`. -/
  | fewerSigners (threshold : Int) (blocks : UInt32)
  /-- After the delay, `threshold` of these other keys (`…/<0;1>/*`). -/
  | separateKeys (threshold : Int) (keys : Array String) (blocks : UInt32)
  deriving Inhabited

end MultisigAccount

structure MultisigAccount where
  descriptor : Descriptor
  network : BitcoinNetwork
  /-- Signatures a spend needs. -/
  threshold : Int
  /-- The signers in descriptor order. -/
  signers : Array Descriptor.SingleKey
  /-- Whether the leaf is `sortedmulti_a`. -/
  isSorted : Bool
  /-- The timelocked recovery leaf, if the account has one. -/
  recovery : Option MultisigAccount.Recovery
  /-- Whether the recovery leaf is the tree's first leaf. -/
  recoveryLeafFirst : Bool
  deriving Inhabited

namespace MultisigAccount

/-- The longest relative lock accepted: BIP68's 16-bit block count. -/
def maximumRecoveryBlocks : UInt32 := 0xFFFF
/-- A signer's key on its second path, for the recovery leaf only. -/
def recoverySuffix : Array Descriptor.Element := #[.multipath #[2, 3], .wildcard false]
/-- The only signer suffix accepted (SEC-019). -/
def signerSuffix : Array Descriptor.Element := #[.multipath #[0, 1], .wildcard false]
def maxMoney : Int := 2_100_000_000_000_000

def hdNetwork (n : BitcoinNetwork) : HDKey.Network := if n == .mainnet then .mainnet else .testnet

def extendedKey? (k : Descriptor.SingleKey) : Option (HDKey × HDKey.Network) :=
  match k.base with | .extended key n => some (key, n) | _ => none

def suffixReason (suffix : Array Descriptor.Element) : String :=
  if suffix == signerSuffix then "every signer must use the /<0;1>/* suffix, so the signers can be shown to be independent"
  else "a signer reused for recovery must use its /<2;3>/* path there"

/-- A signer as accepted here: an extended public key with its origin, on this network, under the fixed
suffix; the origin names as many steps as the key is deep and ends at the key's own child index. -/
def requireAccountKey (single : Descriptor.SingleKey) (network : BitcoinNetwork)
    (suffix : Array Descriptor.Element := signerSuffix) : MAM Unit := do
  let some (key, keyNetwork) := extendedKey? single
    | invalid "every signer must be an extended public key carrying its origin"
  let some origin := single.origin | invalid "every signer must be an extended public key carrying its origin"
  if key.privateKey.isSome then invalid "every signer must be an extended public key carrying its origin"
  unless origin.path.size == key.depth.toNat && (key.depth == 0 || origin.path.back? == some key.childIndex) do
    invalid "a signer's origin path does not match its key"
  unless keyNetwork == hdNetwork network do invalid "a signer's extended key belongs to a different network"
  unless single.derivation.elements == suffix do invalid (suffixReason suffix)

/-- SEC-020: the bare NUMS key H, or an origin-less xpub on H under the signers' suffix on this network. -/
def isUnspendable (key : Descriptor.SingleKey) (network : BitcoinNetwork) : Bool :=
  if key.origin.isSome then false
  else match key.base with
    | .publicKey raw =>
      key.derivation.elements.isEmpty &&
        (if raw.size == 32 then raw else raw.extract 1 raw.size) == Taproot.unspendableInternalKey
    | .extended xpub keyNetwork =>
      xpub.privateKey.isNone && keyNetwork == hdNetwork network &&
        xpub.publicKey == ByteArray.mk #[0x02] ++ Taproot.unspendableInternalKey &&
        key.derivation.elements == signerSuffix
    | .privateKey .. => false

/-- One recovery key: an extended key not seen before in the leaf; a signer's key keeps that signer's
origin and `/<2;3>/*`, any other key `/<0;1>/*`. -/
def requireRecoveryKey (key : Descriptor.SingleKey) (signerOrigins : Array (ByteArray × Descriptor.KeyOrigin))
    (seen : Array ByteArray) (network : BitcoinNetwork) : MAM (Array ByteArray) := do
  let some (xpub, _) := extendedKey? key | invalid "every recovery key must be an extended public key"
  if seen.contains xpub.publicKey then invalid "the same recovery key appears more than once"
  let signerOrigin := (signerOrigins.find? (·.1 == xpub.publicKey)).map (·.2)
  unless signerOrigin.isNone || key.origin == signerOrigin do
    invalid "a signer reused for recovery must keep its own fingerprint and path there"
  requireAccountKey key network (if signerOrigin.isNone then signerSuffix else recoverySuffix)
  return seen.push xpub.publicKey

def recoveryOf (leaf : Descriptor.Leaf) (signers : Array Descriptor.SingleKey) (network : BitcoinNetwork) : MAM Recovery := do
  let .timelocked condition blocks := leaf | invalid "the second leaf must be a timelocked recovery path"
  unless 1 ≤ blocks && blocks ≤ maximumRecoveryBlocks do invalid "a recovery delay must be 1 to 65535 blocks"
  -- A dictionary keyed by public key: a later signer's origin replaces an earlier one's.
  let mut signerOrigins : Array (ByteArray × Descriptor.KeyOrigin) := #[]
  for signer in signers do
    if let (some (key, _), some origin) := (extendedKey? signer, signer.origin) then
      signerOrigins := match signerOrigins.findIdx? (·.1 == key.publicKey) with
        | some j => signerOrigins.set! j (key.publicKey, origin)
        | none => signerOrigins.push (key.publicKey, origin)
  let mut seen : Array ByteArray := #[]
  for key in condition.keys do
    seen ← requireRecoveryKey key signerOrigins seen network
  return { threshold := condition.threshold, keys := condition.keys, blocks }

/-- `MultisigAccount(descriptor:network:)`: admission (SEC-009, SEC-019, SEC-020). -/
def make (descriptor : Descriptor) (network : BitcoinNetwork) : MAM MultisigAccount := do
  let .trTree internalKey tree := descriptor.expression | invalid "expected tr(NUMS, sortedmulti_a(k, …))"
  let (primaryLeaf, recoveryLeaf, recoveryFirst) ← match tree with
    | .leaf leaf => pure (leaf, none, false)
    | .branch (.leaf left) (.leaf right) =>
      match left with
      | .timelocked .. => pure (right, some left, true)
      | _ => pure (left, some right, false)
    | _ => invalid "a multisig account has one multi_a leaf, and at most one timelocked recovery leaf beside it"
  let (threshold, signers, sorted) ← match primaryLeaf with
    | .sortedMultiA k keys => pure (k, keys, true)
    | .multiA k keys => pure (k, keys, false)
    | _ => invalid "a multisig account has exactly one multi_a leaf"
  unless isUnspendable internalKey network do
    invalid "the internal key can spend on its own, which would bypass the signers it lists"
  unless signers.size ≥ 2 do invalid "a multisig account needs at least two signers"
  unless 1 ≤ threshold && threshold ≤ signers.size do
    invalid "the threshold must be between one and the number of signers"
  for signer in signers do requireAccountKey signer network
  let recovery ← match recoveryLeaf with
    | some leaf => some <$> recoveryOf leaf signers network
    | none => pure none
  -- SEC-009: n distinct keys, compared as key material.
  let mut seen : Array ByteArray := #[]
  for signer in signers do
    let some (key, _) := extendedKey? signer
      | invalid "the same signing key appears more than once, so this account needs fewer signers than it claims"
    if seen.contains key.publicKey then
      invalid "the same signing key appears more than once, so this account needs fewer signers than it claims"
    seen := seen.push key.publicKey
  return { descriptor, network, threshold, signers, isSorted := sorted, recovery, recoveryLeafFirst := recoveryFirst }

/-- `MultisigAccount(_ string:network:)`. -/
def parse (string : String) (network : BitcoinNetwork) : MAM MultisigAccount := do
  make (← lift (·.name) (Descriptor.parse string)) network

/-- Liana's unspendable internal key: an xpub on H with chain code SHA-256 of the leaf keys' compressed
public keys in descriptor order, depth 0, no origin, the shared `/<0;1>/*` suffix. -/
def unspendableKeyExpression (leafKeys : Array Descriptor.SingleKey) (network : BitcoinNetwork) : MAM String := do
  let mut concatenated := ByteArray.empty
  for key in leafKeys do
    let some (xpub, _) := extendedKey? key
      | invalid "every signer must be an extended public key carrying its origin"
    concatenated := concatenated ++ xpub.publicKey
  let nums : HDKey := { depth := 0, parentFingerprint := 0, childIndex := 0, chainCode := sha256 concatenated,
                        privateKey := none, publicKey := ByteArray.mk #[0x02] ++ Taproot.unspendableInternalKey }
  return nums.serialized (hdNetwork network) ++ "/<0;1>/*"

/-- Key expressions sorted by their x-only account key, ascending (stable among equal keys). -/
def canonicalOrder (expressions : Array String) : MAM (Array String) := do
  let keyed ← expressions.mapM fun expression => do
    let some single := (match Descriptor.parse s!"tr({expression})" with
      | .ok d => match d.expression with | .tr k => some k | _ => none
      | .error _ => none) | invalid "a signer key expression does not parse"
    let some (xpub, _) := extendedKey? single | invalid "a signer key expression does not parse"
    pure (xpub.publicKey.extract 1 xpub.publicKey.size, expression)
  return (keyed.toList.mergeSort (fun a b => !lexPrecedes b.1 a.1)).toArray.map (·.2)

/-- The recovery leaf's text; reused signers move to their `/<2;3>/*` path. -/
def recoveryLeafText (plan : RecoveryPlan) (signers : Array String) : MAM String := do
  let (threshold, keys, blocks) ← match plan with
    | .fewerSigners m n =>
      let suffix := "/<0;1>/*"
      unless signers.all (·.endsWith suffix) do
        invalid "every signer must use the /<0;1>/* suffix, so the signers can be shown to be independent"
      pure (m, signers.map fun s => String.ofList (s.toList.take (s.length - suffix.length)) ++ "/<2;3>/*", n)
    | .separateKeys m others n => pure (m, others, n)
  unless 1 ≤ blocks && blocks ≤ maximumRecoveryBlocks do invalid "a recovery delay must be 1 to 65535 blocks"
  unless 1 ≤ threshold && threshold ≤ keys.size do
    invalid "the recovery threshold must be between one and its number of keys"
  if keys.size == 1 then return s!"and_v(v:pk({keys[0]!}),older({blocks}))"
  return s!"and_v(v:multi_a({threshold},{",".intercalate keys.toList}),older({blocks}))"

/-- The canonical account descriptor `tr(NUMS-xpub/<0;1>/*, sortedmulti_a(k, …))` over the given signer key
expressions (and recovery plan), in canonical key order, validated as an account for `network`. -/
def makeDescriptor (threshold : Int) (signers : Array String) (recovery : Option RecoveryPlan := none)
    (network : BitcoinNetwork) : MAM Descriptor := do
  let signers ← canonicalOrder signers
  let recovery ← match recovery with
    | some (.separateKeys m keys blocks) => pure (some (RecoveryPlan.separateKeys m (← canonicalOrder keys) blocks))
    | other => pure other
  let mut leaf := s!"sortedmulti_a({threshold},{",".intercalate signers.toList})"
  if let some plan := recovery then leaf := "{" ++ leaf ++ "," ++ (← recoveryLeafText plan signers) ++ "}"
  -- A failure that is not this module's own is reported as an unparsable signer expression.
  let parsed : MAM Descriptor := do
    let notParsed : MultisigFailure := .account (.invalidDescriptor "a signer key expression does not parse")
    let draft ← (Descriptor.parse s!"tr({hex Taproot.unspendableInternalKey},{leaf})").mapError fun _ => notParsed
    let internalKey ← unspendableKeyExpression (draft.allKeys.extract 1 draft.allKeys.size) network
    (Descriptor.parse s!"tr({internalKey},{leaf})").mapError fun _ => notParsed
  let descriptor ← parsed
  discard (make descriptor network)
  return descriptor

/-- The account's stable identifier: the descriptor's BIP380 checksum. -/
def id (a : MultisigAccount) : String :=
  let s := a.descriptor.serialized
  String.ofList (s.toList.drop (s.length - 8))

/-- Every key expression in the account: the signers, then the recovery keys. -/
def allKeys (a : MultisigAccount) : Array Descriptor.SingleKey :=
  a.signers ++ ((a.recovery.map (·.keys)).getD #[])

/-- The keys of `path`'s leaf, in descriptor order; none for a recovery path the account does not have. -/
def keysOn (a : MultisigAccount) (path : SpendPath) : Array Descriptor.SingleKey :=
  if path == .recovery then (a.recovery.map (·.keys)).getD #[] else a.signers

/-- How many of `path`'s keys must sign. -/
def thresholdOn (a : MultisigAccount) (path : SpendPath) : Int :=
  if path == .recovery then (a.recovery.map (·.threshold)).getD 0 else a.threshold

/-- Whether one key of the account is this account public key, whatever origin label it carries. -/
def includes (a : MultisigAccount) (accountKey : HDKey) : Bool :=
  a.allKeys.any fun k => match extendedKey? k with
    | some (base, _) => base.publicKey == accountKey.publicKey
    | none => false

/-- The signer's account key with its private half, when `key` is that account key itself or the master its
origin descends from; `none` otherwise. -/
def accountSecretKey (single : Descriptor.SingleKey) (key : HDKey) : MAM (Option HDKey) := do
  let some (base, _) := extendedKey? single | return none
  if key.privateKey.isNone then return none
  if key.publicKey == base.publicKey && key.chainCode == base.chainCode then return some key
  let some origin := single.origin | return none
  if origin.fingerprint != key.fingerprint then return none
  let derived ← lift (·.name) (key.derivedPath origin.path)
  unless derived.publicKey == base.publicKey && derived.chainCode == base.chainCode do return none
  return some derived

/-- Whether `key` (a master or BIP86 account key) holds one of the account's keys. -/
def hasSigner (a : MultisigAccount) (key : HDKey) : Bool :=
  a.allKeys.any fun k => match accountSecretKey k key with | .ok (some _) => true | _ => false

/-! ### Watching -/

def derivedOutput (a : MultisigAccount) (index : UInt32) (choice : Nat) : MAM Descriptor.DerivedOutput := do
  let outputs ← lift (·.name) (a.descriptor.derived index a.network)
  let some o := outputs[choice]? | throw (.named "indexOutOfRange")
  return o

/-- scriptPubKey at (multipath choice, index): choice 0 receive, 1 change. -/
def scriptPubKey (a : MultisigAccount) (index : UInt32) (choice : Nat := 0) : MAM ByteArray :=
  return (← a.derivedOutput index choice).scriptPubKey

def address (a : MultisigAccount) (index : UInt32) (choice : Nat := 0) : MAM String :=
  return (← a.derivedOutput index choice).address

/-- Both multipath choices for indices `0 ..< count`. -/
def watchScripts (a : MultisigAccount) (count : UInt32) : MAM (Array ByteArray) := do
  let mut scripts := #[]
  for index in [0:count.toNat] do
    for o in ← lift (·.name) (a.descriptor.derived index.toUInt32 a.network) do
      scripts := scripts.push o.scriptPubKey
  return scripts

/-- One leaf at (choice, index), with its control block and the internal key. -/
structure Leaf where
  internalKey : ByteArray
  version : UInt8
  script : ByteArray
  controlBlock : Tx.Taproot.ControlBlock
  isRecovery : Bool
  deriving Inhabited

def Leaf.hash (l : Leaf) : ByteArray := Taproot.leafHash l.version l.script

def treeLeaves : Taproot.Tree → List (UInt8 × ByteArray)
  | .leaf v s => [(v, s)]
  | .branch l r => treeLeaves l ++ treeLeaves r

def txControlBlock (c : Taproot.ControlBlock) : Tx.Taproot.ControlBlock :=
  { leafVersion := c.leafVersion, outputKeyParity := c.outputKeyParity, internalKey := c.internalKey, path := c.path.toArray }

/-- Every leaf at (choice, index) in tree order, with its control block. -/
def leaves (a : MultisigAccount) (choice : Nat) (index : UInt32) : MAM (Array Leaf) := do
  let (internalKey, tree) ← lift (·.name) (a.descriptor.resolvedTaproot index choice)
  let blocks ← lift (·.name) (Taproot.controlBlocks internalKey tree)
  let scripts := treeLeaves tree
  unless scripts.length == blocks.length && scripts.length == (if a.recovery.isNone then 1 else 2) do
    invalid "the account's tree does not resolve to its leaves"
  return ((scripts.zip blocks).zipIdx.map fun (((v, s), cb), position) =>
    ({ internalKey, version := v, script := s, controlBlock := txControlBlock cb,
       isRecovery := a.recovery.isSome && (position == 0) == a.recoveryLeafFirst } : Leaf)).toArray

/-- The signers' leaf at (choice, index). -/
def signersLeaf (a : MultisigAccount) (choice : Nat) (index : UInt32) : MAM Leaf := do
  let some l := (← a.leaves choice index).find? (!·.isRecovery) | invalid "the account's tree does not resolve to its leaves"
  return l

/-- Whether `coin` may already be spent on the recovery path in the next block. -/
def isUnlockedForRecovery (a : MultisigAccount) (coin : WalletUTXO) (chainTip : UInt32) : Bool :=
  match a.recovery with
  | some r => coin.height > 0 && chainTip ≥ coin.height && chainTip.toNat - coin.height.toNat + 1 ≥ r.blocks.toNat
  | none => false

/-- The first block in which `coin` can be spent on the recovery path; `none` when unconfirmed or past
`UInt32.max`. -/
def recoveryUnlockHeight (a : MultisigAccount) (coin : WalletUTXO) : Option UInt32 := do
  let r ← a.recovery
  guard (coin.height > 0)
  let unlock := coin.height.toNat + r.blocks.toNat
  guard (unlock < 2 ^ 32)
  return unlock.toUInt32

/-! ### Review -/

def inputTxid? (i : PSBT.Input) : Option (ByteArray × UInt32) := do
  let txid ← i.previousTxid
  guard (txid.size == 32)
  return (txid, ← i.outputIndex)

/-- The recovery path when every input's sequence meets the recovery lock, otherwise the signers'. -/
def spendPath (a : MultisigAccount) (psbt : PSBT) : MAM SpendPath := do
  let some r := a.recovery | return .signers
  let tx ← lift (·.name) psbt.unsignedTransaction
  return if tx.inputs.all (fun i => RelativeLock.isSatisfied r.blocks i.sequence tx.version) then .recovery else .signers

/-- At most 10% of the inputs may go to the miner. -/
def checkFeeCeiling (fee inputTotal : Int64) : MAM Unit := do
  unless fee ≤ inputTotal / 10 do
    refuse s!"the {fee.toInt}-sat fee exceeds the 10% safety limit for these inputs"

def leafKey (l : PSBT.TapLeafScript) : ByteArray := l.controlBlock.serialized ++ l.script

def sameLeaves (xs ys : Array PSBT.TapLeafScript) : Bool :=
  xs.size == ys.size && (xs.zip ys).all fun (x, y) =>
    x.controlBlock == y.controlBlock && x.script == y.script && x.leafVersion == y.leafVersion

def checkInput (a : MultisigAccount) (input : PSBT.Input) (inputIndex : Nat) (known : WalletUTXO) (chainTip : UInt32) :
    MAM Unit := do
  let n := inputIndex + 1
  let claimedOK := match input.witnessUTXO with
    | some c => c.amount == known.amount && c.scriptPubKey == known.scriptPubKey
    | none => false
  unless known.amount > 0 && known.amount.toInt ≤ maxMoney && claimedOK do
    refuse s!"input {n} has the wrong amount or locking script"
  if known.isCoinbase then
    let matureAt := known.height.toNat + Wallet.coinbaseMaturity.toNat - 1
    unless chainTip.toNat ≥ matureAt do
      refuse s!"input {n} spends a coinbase that matures in {matureAt - chainTip.toNat} blocks"
  unless (← a.scriptPubKey known.index known.chain.rawValue) == known.scriptPubKey do
    refuse s!"input {n} does not belong to this descriptor"
  let rawSighash := input.sighashType.getD 0
  unless rawSighash == 0 || rawSighash == 1 do refuse s!"input {n} does not commit to every output"
  let expected ← a.leaves known.chain.rawValue known.index
  let expectedLeaves : Array PSBT.TapLeafScript :=
    expected.map fun l => { controlBlock := l.controlBlock, script := l.script, leafVersion := l.version }
  let attached := sortBytes leafKey input.tapLeafScripts
  unless input.tapInternalKey == (expected[0]?.map (·.internalKey)) &&
      sameLeaves attached (sortBytes leafKey expectedLeaves) do
    refuse s!"input {n} changes the spending policy"

def reviewedInputTotal (a : MultisigAccount) (psbt : PSBT) (knownUTXOs : Array WalletUTXO) (chainTip : UInt32)
    (path : SpendPath) : MAM Int64 := do
  let mut seen : Array Transaction.Outpoint := #[]
  let mut total : Int := 0
  for h : k in [0:psbt.inputs.size] do
    let input := psbt.inputs[k]
    let some (txid, vout) := inputTxid? input | refuse s!"input {k + 1} has no complete outpoint"
    let outpoint : Transaction.Outpoint := ⟨txid, vout⟩
    if seen.contains outpoint then refuse s!"input {k + 1} repeats an earlier outpoint"
    seen := seen.push outpoint
    let some known := knownUTXOs.find? (·.outpoint == outpoint)
      | refuse s!"input {k + 1} is not an available coin of this account"
    a.checkInput input k known chainTip
    if path == .recovery && !a.isUnlockedForRecovery known chainTip then
      let unlock := match a.recoveryUnlockHeight known with
        | some h => s!"at block {h}"
        | none => if known.height > 0 then "past the last block height" else "once it confirms"
      refuse s!"input {k + 1} unlocks for recovery only {unlock}"
    let sum := total + known.amount.toInt
    unless sum ≤ maxMoney do refuse "input amounts exceed Bitcoin's supply"
    total := sum
  return Int64.ofInt total

def reviewedOutputs (a : MultisigAccount) (psbt : PSBT) (inputTotal : Int64) (owned : Array OutputCoordinate) :
    MAM (Array SpendReview.Output × Int64) := do
  let mut candidates : Array OutputCoordinate := #[]
  for c in owned do
    if (c.choice == 0 || c.choice == 1) && !candidates.contains c then candidates := candidates.push c
  unless candidates.size ≤ 1_024 do refuse "too many candidate account output paths"
  let ownedScripts ← candidates.mapM fun c => a.scriptPubKey c.index c.choice.toNat
  let mut total : Int := 0
  let mut reviewed : Array SpendReview.Output := #[]
  for h : k in [0:psbt.outputs.size] do
    let output := psbt.outputs[k]
    let some amount := output.amount | refuse s!"output {k + 1} has an invalid amount or script"
    let some script := output.script | refuse s!"output {k + 1} has an invalid amount or script"
    unless amount > 0 && amount.toInt ≤ maxMoney && !script.isEmpty do
      refuse s!"output {k + 1} has an invalid amount or script"
    let sum := total + amount.toInt
    unless sum ≤ maxMoney do refuse "output amounts exceed Bitcoin's supply"
    total := sum
    reviewed := reviewed.push { amount, scriptPubKey := script, isAccountOwned := ownedScripts.contains script }
  unless total ≤ inputTotal.toInt do refuse "outputs exceed its known inputs"
  return (reviewed, Int64.ofInt total)

/-- Validates a PSBT before it is shown, signed, finalized or broadcast (SEC-004): every input a unique
known coin of this account with the exact amount, script, leaves and internal key; every signature
committing to all outputs; valid amounts; a fee of at most 10%. Output ownership comes only from the
caller's coordinates. -/
def reviewSpend (a : MultisigAccount) (psbt : PSBT) (knownUTXOs : Array WalletUTXO)
    (ownedOutputCoordinates : Array OutputCoordinate) (chainTip : UInt32) : MAM SpendReview := do
  if psbt.inputs.isEmpty then refuse "it has no inputs"
  unless !psbt.outputs.isEmpty && psbt.outputs.size ≤ 1_000 do refuse "it has no outputs or more than 1,000"
  unless psbt.txVersion == 1 || psbt.txVersion == 2 do
    refuse s!"transaction version {psbt.txVersion.toInt} is not supported"
  let path ← a.spendPath psbt
  let inputTotal ← a.reviewedInputTotal psbt knownUTXOs chainTip path
  let (outputs, outputTotal) ← a.reviewedOutputs psbt inputTotal ownedOutputCoordinates
  let fee := inputTotal - outputTotal
  checkFeeCeiling fee inputTotal
  return { outputs, inputTotal, outputTotal, fee, path }

/-! ### Creating a spend -/

def compactSizeLength (value : Nat) : Nat := if value < 0xFD then 1 else if value ≤ 0xFFFF then 3 else 5

/-- Per-input witness bytes for fee estimation on `path`: item count, one 65-byte slot per key of that
leaf, the leaf script and its control block, each length-prefixed. -/
def witnessBytesPerInput (a : MultisigAccount) (path : SpendPath := .signers) : MAM Int := do
  let leaves ← a.leaves 0 0
  let some leaf := leaves.find? (·.isRecovery == (path == .recovery)) | refuse "this account has no recovery path"
  let slots := (a.keysOn path).size
  let scriptSize := leaf.script.size
  let controlBlockSize := 33 + 32 * (leaves.size - 1)
  return (1 + slots * 65 + compactSizeLength scriptSize + scriptSize + 1 + controlBlockSize : Nat)

/-- The suffix steps a key expression takes at (choice, index). -/
def suffixSteps (key : Descriptor.SingleKey) (choice : Nat) (index : UInt32) : Array UInt32 :=
  key.derivation.elements.map fun
    | .step s => s
    | .multipath vs => vs[choice]!
    | .wildcard hardened => index + (if hardened then HDKey.hardenedOffset else 0)

/-- BIP371 key origins for every key at (choice, index): master fingerprint, the full path and the leaf
hash the key signs for (last value per x-only key, as the Swift dictionary keeps). -/
def keyOrigins (a : MultisigAccount) (choice : Nat) (index : UInt32) : MAM (Array (ByteArray × PSBT.KeyOrigin)) := do
  let leaves ← a.leaves choice index
  let some signerLeaf := leaves.find? (!·.isRecovery) | invalid "the account's tree does not resolve to its leaves"
  let recoveryLeaf := (leaves.find? (·.isRecovery)).map (·.hash)
  let tagged := a.signers.map (·, signerLeaf.hash) ++
    (match recoveryLeaf with
     | some h => ((a.recovery.map (·.keys)).getD #[]).map (·, h)
     | none => #[])
  let mut origins : Array (ByteArray × PSBT.KeyOrigin) := #[]
  for (key, leafHash) in tagged do
    let some origin := key.origin | continue
    let pub ← lift (·.name) (Descriptor.publicKey key index choice)
    let xonly := pub.extract 1 pub.size
    let entry : PSBT.KeyOrigin := { leafHashes := #[leafHash], masterFingerprint := origin.fingerprint,
                                    path := origin.path ++ suffixSteps key choice index }
    origins := match origins.findIdx? (·.1 == xonly) with
      | some j => origins.set! j (xonly, entry)
      | none => origins.push (xonly, entry)
  return origins

/-- The coins a spend on `path` may use and the sequence its inputs carry. -/
def spendableCoins (a : MultisigAccount) (utxos : Array WalletUTXO) (path : SpendPath) (chainTip : UInt32) :
    MAM (Array WalletUTXO × UInt32) := do
  if path != .recovery then return (utxos, TransactionBuilder.defaultSequence)
  let some r := a.recovery | refuse "this account has no recovery path"
  let unlocked := utxos.filter (a.isUnlockedForRecovery · chainTip)
  if unlocked.isEmpty then
    refuse s!"no coin has stayed unmoved for {r.blocks} blocks yet, so none can be recovered"
  return (unlocked, r.blocks)

/-- The internal key, tap tree (right subtree first, as Bitcoin Core lists it) and key origins on the
change output. -/
def describeChange (a : MultisigAccount) (change : Payment) (changeIndex : UInt32) (psbt : PSBT) : MAM PSBT := do
  let leaves ← a.leaves AddressChain.change.rawValue changeIndex
  let depth : UInt8 := if leaves.size == 1 then 0 else 1
  let origins ← a.keyOrigins AddressChain.change.rawValue changeIndex
  let tree := leaves.reverse.map fun l => (depth, l.version, l.script)
  let outputs := psbt.outputs.map fun o =>
    if o.script == some change.scriptPubKey && o.amount == some change.amount then
      ((o.setTapInternalKey (some leaves[0]!.internalKey)).setTapTree (some tree)).setTapBIP32Derivation origins
    else o
  return { psbt with outputs }

/-- Builds the unsigned spend PSBT: coin selection sized for this account's witness on `path`, the
transaction with an anti-fee-sniping locktime from `draws` and the change at `changePosition n` among the
`n` payments, the BIP371 leaves and per-key origins on every input, and the internal key, tap tree and
origins on the change output. -/
def createSpend (a : MultisigAccount) (utxos : Array WalletUTXO) (payments : Array Payment) (changeIndex : UInt32)
    (feeRateSatPerVByte : Float) (chainTip : UInt32) (path : SpendPath := .signers)
    (draws : Float × Float := (0.5, 0.5)) (changePosition : Nat → Nat := fun n => n) : MAM PSBT := do
  for u in utxos do
    unless (← a.scriptPubKey u.index u.chain.rawValue) == u.scriptPubKey do
      fail (.scriptMismatch u.index u.chain.rawValue)
  let (spendable, sequence) ← a.spendableCoins utxos path chainTip
  let changeScript ← a.scriptPubKey changeIndex AddressChain.change.rawValue
  let witness ← a.witnessBytesPerInput path
  let selection ← lift (·.name) (CoinSelection.select spendable payments changeScript feeRateSatPerVByte witness)
  checkFeeCeiling selection.fee (selection.selected.foldl (fun t u => t + u.amount) 0)
  let change : Option Payment := selection.changeAmount.map fun amt => { amount := amt, scriptPubKey := changeScript }
  let locktime := TransactionBuilder.antiFeeSnipingLocktime chainTip draws.1 draws.2
  let tx ← lift (·.name) (TransactionBuilder.build (selection.selected.map (·.outpoint)) payments change
    (randomPosition := changePosition) (sequence := sequence) (locktime := locktime))
  let mut psbt ← lift (·.name) (PSBT.create tx (selection.selected.map fun u => { spentOutput := u.spentOutput })
    (tx.outputs.map fun _ => {}))
  for h : k in [0:selection.selected.size] do
    let u := selection.selected[k]
    let leaves ← a.leaves u.chain.rawValue u.index
    let origins ← a.keyOrigins u.chain.rawValue u.index
    psbt ← lift (·.name) (psbt.attachScriptPaths k (leaves.map fun l => (l.controlBlock, ⟨l.script⟩, l.version)) origins)
  if let some c := change then psbt ← a.describeChange c changeIndex psbt
  return psbt

/-! ### Signing -/

/-- The input's coordinates, from the known coin it spends. -/
def coin (psbt : PSBT) (input : Nat) (knownUTXOs : Array WalletUTXO) : MAM WalletUTXO := do
  let notKnown : MAM WalletUTXO := refuse s!"input {input + 1} is not an available coin of this account"
  let some i := psbt.inputs[input]? | notKnown
  let some txid := i.previousTxid | notKnown
  let some vout := i.outputIndex | notKnown
  let some known := knownUTXOs.find? (·.outpoint == ⟨txid, vout⟩) | notKnown
  return known

/-- Reviews the spend, then adds a script-path signature to every input for each key `key` holds (a master
or a BIP86 account key itself); `noSignerKey` when an input has none. The PSBT is replaced only when every
input signs. -/
def sign (a : MultisigAccount) (psbt : PSBT) (signingKey : HDKey) (knownUTXOs : Array WalletUTXO)
    (ownedOutputCoordinates : Array OutputCoordinate) (chainTip : UInt32) (auxiliaryRand : ByteArray) : MAM PSBT := do
  discard (a.reviewSpend psbt knownUTXOs ownedOutputCoordinates chainTip)
  let mut signed := psbt
  for k in [0:signed.inputs.size] do
    let u ← coin signed k knownUTXOs
    let mut secrets : Array ByteArray := #[]
    for signer in a.allKeys do
      let some account ← accountSecretKey signer signingKey | continue
      let child ← lift (·.name) (account.derivedPath (suffixSteps signer u.chain.rawValue u.index))
      let some secret := child.privateKey | continue
      secrets := secrets.push secret
    if secrets.isEmpty then fail (.noSignerKey k)
    signed ← lift (·.name) (signed.signScriptPath k secrets auxiliaryRand)
  return signed

/-- Which keys of `path`'s leaf (by position: signers, or recovery keys) have a verified signature on that
leaf of every input, judged by BIP340 verification against the recomputed sighash. Ascending positions. -/
def approvals (a : MultisigAccount) (psbt : PSBT) (knownUTXOs : Array WalletUTXO) (path : SpendPath := .signers) :
    MAM (Array Nat) := do
  let keys := a.keysOn path
  if keys.isEmpty then return #[]
  let tx ← lift (·.name) psbt.unsignedTransaction
  let spent ← lift (·.name) psbt.spentOutputs
  let mut approved : Option (Array Nat) := none
  for k in [0:psbt.inputs.size] do
    let u ← coin psbt k knownUTXOs
    let some leaf := (← a.leaves u.chain.rawValue u.index).find? (·.isRecovery == (path == .recovery)) | return #[]
    let verified ← lift (·.name) (psbt.verifiedScriptPathSigners k leaf.hash tx spent)
    let mut here : Array Nat := #[]
    for h : position in [0:keys.size] do
      let derived ← lift (·.name) (Descriptor.publicKey keys[position] u.index u.chain.rawValue)
      if verified.contains (derived.extract 1 derived.size) then here := here.push position
    approved := some (match approved with | some prev => prev.filter here.contains | none => here)
  return approved.getD #[]

/-- Finalizes a PSBT with at least the threshold of verified signatures per input and extracts the raw
transaction, after one more review. Returns the finalized PSBT and the transaction. -/
def finalizeSpend (a : MultisigAccount) (psbt : PSBT) (knownUTXOs : Array WalletUTXO)
    (ownedOutputCoordinates : Array OutputCoordinate) (chainTip : UInt32) : MAM (PSBT × Transaction) := do
  discard (a.reviewSpend psbt knownUTXOs ownedOutputCoordinates chainTip)
  let finalized ← lift (·.name) psbt.finalize
  let tx ← lift (·.name) finalized.extractedTransaction
  lift (·.name) (Wallet.checkStandardSize tx)
  return (finalized, tx)

end MultisigAccount
end Winnow
