import Winnow
import Lean.Data.Json

/-! `multisig-test`: upstream 1cf93fb's multisig tests, ported.

* `Tests/WalletCoreTests/MultisigAccountTests.swift` (all 16 tests but the bundle one, which is in
  `bundleAccounts` here too),
* `Tests/WalletCoreTests/TimelockedMultisigTests.swift` (all 10),
* the script-path half of `SighashBIP341Tests.swift` over `bip341-scriptpath-test-vectors.json` (shape,
  sighash, signatures, BIP387 witness), since `Multisig.parse` and `Signer.multisigWitness` changed,
* `core-timelocked-multisig.json` (Bitcoin Core 31.1's checksums and addresses).

Fixtures as `Tests/Support/TestKeys.swift`: masters from BIP39 over 16 repeated bytes (0xA1, 0xB2, 0xC3;
0x0D a stranger; 0xD4–0xD6 recovery keys), signet keys at m/86'/1'/0', `testChainTip` 840 000, BIP340
auxiliary randomness zero. Run from `Lean/` (reads `Vectors/`). Exits 1 on any failure. -/

open Winnow Keys
open Tx (BitcoinNetwork)
open MultisigAccount (OutputCoordinate SpendPath RecoveryPlan)

initialize passed : IO.Ref Nat ← IO.mkRef 0
initialize failures : IO.Ref (Array String) ← IO.mkRef #[]

abbrev TM := ExceptT String IO

def check (name : String) (ok : Bool) (detail : String := "") : TM Unit := do
  if ok then passed.modify (· + 1)
  else
    failures.modify (·.push name)
    IO.println s!"FAIL {name}{if detail.isEmpty then "" else ": " ++ detail}"

def need {α} (name : String) (r : MAM α) : TM α :=
  match r with
  | .ok a => pure a
  | .error e => throw s!"{name}: {e.name}{match e with | .account a => " (" ++ a.description ++ ")" | _ => ""}"

def needE {ε α} (name : String) (render : ε → String) (r : Except ε α) : TM α :=
  match r with | .ok a => pure a | .error e => throw s!"{name}: {render e}"

/-- Expects a failure; `kind` the case name, `account` an account error (any case), or neither (any). -/
def refused {α} (name : String) (r : MAM α) (kind : Option String := none) (account : Bool := false) : TM Unit :=
  match r with
  | .ok _ => check name false "accepted"
  | .error e =>
    let isAccount := match e with | .account _ => true | _ => false
    check name ((kind.map (· == e.name)).getD true && (!account || isAccount)) s!"got {e.name}"

def refusedWith {α} (name : String) (r : MAM α) (expected : MultisigAccountError) : TM Unit :=
  match r with
  | .ok _ => check name false "accepted"
  | .error (.account e) => check name (e == expected) s!"got {e.description}"
  | .error e => check name false s!"got {e.name}"

def runTest (name : String) (t : TM Unit) : IO Unit := do
  match ← t.run with
  | .ok () => pure ()
  | .error msg =>
    failures.modify (·.push name)
    IO.println s!"FAIL {name} (aborted): {msg}"

/-! ## Fixtures -/

def testChainTip : UInt32 := 840_000
def aux0 : ByteArray := ByteArray.mk (Array.replicate 32 0)
def destination : ByteArray := ByteArray.mk (#[0x51, 0x20] ++ Array.replicate 32 0x77)
def owned : Array OutputCoordinate := #[{ choice := 1, index := 0 }]

def master (entropyByte : UInt8) : TM HDKey := do
  let words ← needE "mnemonic" (fun _ => "bip39") (BIP39.mnemonic (ByteArray.mk (Array.replicate 16 entropyByte)))
  needE "master" (·.name) (HDKey.ofSeed (BIP39.seed words))

def masters : TM (Array HDKey) := #[0xA1, 0xB2, 0xC3].mapM master

def accountKeyOf (m : HDKey) : TM HDKey := needE "account key" (·.name) (m.derived "m/86'/1'/0'")

def bareKeyExpression (m : HDKey) : TM String := do
  let account ← accountKeyOf m
  return s!"[{Descriptor.hex8 m.fingerprint}/86'/1'/0']{account.neutered.serialized .testnet}"

def keyExpression (m : HDKey) : TM String := return (← bareKeyExpression m) ++ "/<0;1>/*"

/-- `masters` in the order the account lists their keys. -/
def inSignerOrder (ms : Array HDKey) (a : MultisigAccount) : TM (Array HDKey) := do
  let listed := a.signers.filterMap fun s => (MultisigAccount.extendedKey? s).map (·.1.publicKey)
  let keyed ← ms.mapM fun m => do
    let pub := (← accountKeyOf m).publicKey
    return (m, (listed.findIdx? (· == pub)).getD 1_000_000)
  return (keyed.toList.mergeSort (fun a b => a.2 ≤ b.2)).toArray.map (·.1)

def accountWith (threshold : Int := 2) (count : Nat := 3) : TM (MultisigAccount × Array HDKey) := do
  let ms := (← masters).extract 0 count
  let d ← need "descriptor" (MultisigAccount.makeDescriptor threshold (← ms.mapM keyExpression) none .signet)
  let a ← need "account" (MultisigAccount.make d .signet)
  return (a, ← inSignerOrder ms a)

def funding (a : MultisigAccount) (amount : Int64) (chain : AddressChain := .receive) (index : UInt32 := 0)
    (height : UInt32 := 100) (txidByte : UInt8 := 0x5A) : TM WalletUTXO := do
  return { txid := ByteArray.mk (Array.replicate 32 txidByte), vout := 0, amount,
           scriptPubKey := ← need "spk" (a.scriptPubKey index chain.rawValue), chain, index, height }

def spend (a : MultisigAccount) (u : WalletUTXO) (amount : Int64 := 50_000) (tip : UInt32 := testChainTip)
    (path : SpendPath := .signers) : MAM PSBT :=
  a.createSpend #[u] #[{ amount, scriptPubKey := destination }] 0 2 tip path (0.5, 0.5)

def sign (a : MultisigAccount) (p : PSBT) (key : HDKey) (known : Array WalletUTXO) (tip : UInt32 := testChainTip) :
    MAM PSBT := a.sign p key known owned tip aux0

def finalize (a : MultisigAccount) (p : PSBT) (known : Array WalletUTXO) (tip : UInt32 := testChainTip) :
    MAM Transaction := return (← a.finalizeSpend p known owned tip).2

def sameP (a b : PSBT) : Bool := a.serialized == b.serialized

def suffixBytes (b : ByteArray) (n : Nat) : ByteArray := b.extract (b.size - n) b.size

/-- BIP342 multi_a validation replayed for input 0 of a finalized spend: the control block commits the
leaf to the spent output key, then each witness item is verified against its key. The valid count. -/
def verifiedSignatures (tx : Transaction) (spent : SighashBIP341.SpentOutput) : TM Nat := do
  let some input := tx.inputs[0]? | throw "no input"
  let w := input.witness
  unless w.size ≥ 2 do throw "short witness"
  let leafScript := w[w.size - 2]!
  let cb ← needE "control block" (·.name) (Taproot.ControlBlock.parse w[w.size - 1]!)
  let root := cb.path.foldl Taproot.branchHash (Taproot.leafHash cb.leafVersion leafScript)
  let (outputKey, parity) ← needE "tweak" (·.name) (Taproot.tweakedOutputKey cb.internalKey (some root))
  check "replay: output key" (outputKey == suffixBytes spent.scriptPubKey 32)
  check "replay: parity" (cb.outputKeyParity == parity)
  let some (_, keys) := Multisig.parse ⟨leafScript⟩ | throw "leaf does not parse"
  let sighash ← needE "sighash" (·.name)
    (SighashBIP341.sighash tx 0 #[spent] .default (some (SighashBIP341.ScriptPath.ofLeaf ⟨leafScript⟩)))
  let mut valid := 0
  for h : position in [0:keys.size] do
    let item := w[keys.size - 1 - position]!
    if !item.isEmpty then
      if (schnorrVerify keys[position] sighash (item.extract 0 64)).toOption.getD false then valid := valid + 1
  return valid

def witnessSize (w : Array ByteArray) : Nat :=
  let compact := fun (v : Nat) => if v < 0xFD then 1 else 3
  compact w.size + w.foldl (fun t x => t + compact x.size + x.size) 0

def hexOf (s : String) : TM ByteArray := match Wire.dataOfHex? s with | some b => pure b | none => throw s!"hex {s}"

/-! ## MultisigAccountTests -/

def twoOfThree : TM Unit := do
  let (account, ms) ← accountWith
  check "2of3: threshold" (account.threshold == 2)
  check "2of3: signers" (account.signers.size == 3)
  let address ← need "address" (account.address 0)
  check "2of3: tb1p address" (address.startsWith "tb1p")
  check "2of3: watch scripts" ((← need "watch" (account.watchScripts 2)).size == 4)
  let reparsed ← need "reparse" (MultisigAccount.parse account.descriptor.serialized .signet)
  check "2of3: reparsed address" ((← need "address" (reparsed.address 0)) == address)
  let utxo ← funding account 100_000
  let created ← need "create" (spend account utxo)
  let input := created.inputs[0]!
  let (internal0, _) ← need "taproot" (MultisigAccount.lift (·.name) (account.descriptor.resolvedTaproot 0 0))
  let (internal1, _) ← need "taproot" (MultisigAccount.lift (·.name) (account.descriptor.resolvedTaproot 0 1))
  check "2of3: input internal key" (input.tapInternalKey == some internal0)
  check "2of3: one leaf" (input.tapLeafScripts.size == 1)
  check "2of3: no signatures" input.tapScriptSignatures.isEmpty
  check "2of3: three origins" (input.tapBIP32Derivation.size == 3)
  check "2of3: one leaf hash each" (input.tapBIP32Derivation.all (·.2.leafHashes.size == 1))
  let changeScript ← need "spk" (account.scriptPubKey 0 1)
  let some change := created.outputs.find? (·.script == some changeScript) | throw "no change output"
  check "2of3: change tap tree" ((change.tapTree.map (·.size)) == some 1)
  check "2of3: change internal key" (change.tapInternalKey == some internal1)
  check "2of3: change origins" (change.tapBIP32Derivation.size == 3)
  let base64 := created.base64
  check "2of3: base64 round trip" (match PSBT.ofBase64 base64 with | .ok p => sameP p created | .error _ => false)
  let wrongCoin := { utxo with amount := utxo.amount + 1 }
  refused "2of3: review refuses a wrong coin" (sign account created ms[0]! #[wrongCoin]) (account := true)
  let partialC ← need "sign C" (sign account created ms[2]! #[utxo])
  let partialA ← need "sign A" (sign account created ms[0]! #[utxo])
  check "2of3: one signature" (partialA.inputs[0]!.tapScriptSignatures.size == 1)
  check "2of3: approvals A" ((← need "approvals" (account.approvals partialA #[utxo])) == #[0])
  let combined ← need "combine" (MultisigAccount.lift (·.name) (partialC.combined #[partialA]))
  check "2of3: approvals A+C" ((← need "approvals" (account.approvals combined #[utxo])) == #[0, 2])
  -- A hostile combiner appends an unrelated leaf.
  let some realLeaf := combined.inputs[0]!.tapLeafScripts[0]? | throw "no leaf"
  let bogus : PSBT.TapLeafScript :=
    { controlBlock := { leafVersion := realLeaf.leafVersion, outputKeyParity := false,
                        internalKey := ByteArray.mk (Array.replicate 32 0), path := #[] },
      script := realLeaf.script, leafVersion := realLeaf.leafVersion }
  let hostile := combined.modifyInput 0 (·.setTapLeafScripts #[bogus, realLeaf])
  refused "2of3: hostile leaf refused" (finalize account hostile #[utxo]) (account := true)
  let generic ← need "generic finalize" (MultisigAccount.lift (·.name) hostile.finalize)
  let genericTx ← need "extract" (MultisigAccount.lift (·.name) generic.extractedTransaction)
  check "2of3: generic finalizer picks the committing leaf" ((← verifiedSignatures genericTx utxo.spentOutput) == 2)
  let signed ← need "finalize" (finalize account combined #[utxo])
  check "2of3: two valid signatures" ((← verifiedSignatures signed utxo.spentOutput) == 2)
  let witness := signed.inputs[0]!.witness
  check "2of3: witness items" (witness.size == 5)
  let estimate ← need "witness bytes" (account.witnessBytesPerInput)
  check "2of3: estimate covers witness" (estimate ≥ (1 + witness.foldl (fun t x => t + 1 + x.size) 0 : Nat))

def everyPairCanSpend : TM Unit := do
  let (account, ms) ← accountWith
  let utxo ← funding account 100_000
  for (i, j) in [(0, 1), (0, 2), (1, 2)] do
    let psbt ← need "sign" (do sign account (← spend account utxo) ms[i]! #[utxo])
    refused s!"pairs: {i} alone cannot finalize" (finalize account psbt #[utxo])
    let both ← need "sign" (sign account psbt ms[j]! #[utxo])
    let tx ← need "finalize" (finalize account both #[utxo])
    check s!"pairs: {i}+{j}" ((← verifiedSignatures tx utxo.spentOutput) == 2)

def threeOfThree : TM Unit := do
  let (account, ms) ← accountWith 3
  let utxo ← funding account 100_000
  let mut psbt ← need "create" (spend account utxo)
  for m in ms.extract 0 2 do psbt ← need "sign" (sign account psbt m #[utxo])
  refused "3of3: two refused" (finalize account psbt #[utxo])
  psbt ← need "sign" (sign account psbt ms[2]! #[utxo])
  let tx ← need "finalize" (finalize account psbt #[utxo])
  check "3of3: three valid" ((← verifiedSignatures tx utxo.spentOutput) == 3)

def accountKeySigning : TM Unit := do
  let (account, ms) ← accountWith
  let accountKey ← accountKeyOf ms[1]!
  check "account key: hasSigner" (account.hasSigner accountKey)
  check "account key: includes" (account.includes accountKey.neutered)
  let stranger ← master 0x0D
  check "account key: stranger" (!account.hasSigner stranger)
  let utxo ← funding account 100_000 .change 7
  let psbt ← need "sign" (do sign account (← spend account utxo) accountKey #[utxo])
  check "account key: approvals" ((← need "approvals" (account.approvals psbt #[utxo])) == #[1])
  refusedWith "account key: stranger noSignerKey" (sign account psbt stranger #[utxo]) (.noSignerKey 0)

def forgedApprovalNotCounted : TM Unit := do
  let (account, ms) ← accountWith
  let utxo ← funding account 100_000
  let psbt ← need "sign" (do sign account (← spend account utxo) ms[0]! #[utxo])
  let leafHash := psbt.inputs[0]!.tapLeafScripts[0]!.leafHash
  let two ← need "pub" (MultisigAccount.lift (·.name) (Descriptor.publicKey account.signers[2]! 0 0))
  let forged := psbt.modifyInput 0 fun i =>
    i.setTapScriptSignatures (i.tapScriptSignatures.push
      ({ publicKey := two.extract 1 33, leafHash }, ByteArray.mk (Array.replicate 64 0x42)))
  check "forged: approvals" ((← need "approvals" (account.approvals forged #[utxo])) == #[0])
  refused "forged: finalize refused" (finalize account forged #[utxo])

def permutations : List (List Nat) := [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]]

def signerOrderDoesNotMatter : TM Unit := do
  let expressions ← (← masters).mapM keyExpression
  let built ← permutations.mapM fun order =>
    need "descriptor" (MultisigAccount.makeDescriptor 2 (order.toArray.map (expressions[·]!)) none .signet)
  let texts := built.map (·.serialized)
  check "order: one descriptor" (texts.all (· == texts.head!))
  let account ← need "account" (MultisigAccount.make built.head! .signet)
  let reversed := expressions.reverse
  let leaf := s!"sortedmulti_a(2,{",".intercalate reversed.toList})"
  let draft ← needE "draft" (·.name) (Descriptor.parse s!"tr({hex Taproot.unspendableInternalKey},{leaf})")
  let olderKey ← need "nums" (MultisigAccount.unspendableKeyExpression (draft.allKeys.extract 1 draft.allKeys.size) .signet)
  let older ← need "older" (MultisigAccount.parse s!"tr({olderKey},{leaf})" .signet)
  check "order: older descriptor differs" (older.descriptor.serialized != account.descriptor.serialized)
  check "order: older addresses differ" ((← need "a" (older.address 0)) != (← need "a" (account.address 0)))
  let reparsed ← need "reparse" (MultisigAccount.parse older.descriptor.serialized .signet)
  check "order: older keeps its addresses" ((← need "a" (reparsed.address 0)) == (← need "a" (older.address 0)))

def changeByScriptOnly : TM Unit := do
  let (account, _) ← accountWith
  let utxo ← funding account 100_000
  let psbt ← need "create" (spend account utxo)
  let review ← need "review" (account.reviewSpend psbt #[utxo] owned testChainTip)
  check "change: one owned" ((review.outputs.filter (·.isAccountOwned)).size == 1)
  check "change: fee" (review.fee == review.inputTotal - review.outputTotal)
  let unowned ← need "review" (account.reviewSpend psbt #[utxo] #[] testChainTip)
  check "change: none owned without coordinates" (unowned.outputs.all (!·.isAccountOwned))
  let changeScript ← need "spk" (account.scriptPubKey 0 1)
  let some changeIndex := psbt.outputs.findIdx? (·.script == some changeScript) | throw "no change"
  let paymentIndex := 1 - changeIndex
  let derivation := psbt.outputs[changeIndex]!.tapBIP32Derivation
  let relabelled := { psbt with outputs := psbt.outputs.modify paymentIndex (·.setTapBIP32Derivation derivation) }
  let review2 ← need "review" (account.reviewSpend relabelled #[utxo] owned testChainTip)
  check "change: a copied label is not ownership" (!review2.outputs[paymentIndex]!.isAccountOwned)

def reviewRefusals : TM Unit := do
  let (account, _) ← accountWith
  let utxo ← funding account 100_000
  let psbt ← need "create" (spend account utxo)
  refused "review: unknown coin" (account.reviewSpend psbt #[] owned testChainTip) (account := true)
  let none2 := psbt.modifyInput 0 (·.setSighashType (some 2))
  refused "review: SIGHASH_NONE" (account.reviewSpend none2 #[utxo] owned testChainTip) (account := true)
  let young := { utxo with isCoinbase := true, height := testChainTip - 10 }
  refused "review: immature coinbase" (account.reviewSpend psbt #[young] owned testChainTip) (account := true)
  let mature := { young with height := testChainTip - Wallet.coinbaseMaturity }
  check "review: mature coinbase" (account.reviewSpend psbt #[mature] owned testChainTip).toBool
  refused "review: creator refuses a big fee"
    (account.createSpend #[utxo] #[{ amount := 50_000, scriptPubKey := destination }] 0 100 testChainTip)

def realInternalKeyRefused : TM Unit := do
  let ms ← masters
  let signers ← ms.mapM keyExpression
  let internalKey := hex (← needE "key" (·.name) (ms[0]!.derived "m/86'/1'/0'/0/0")).publicKey
  refused "internal: a real key" (MultisigAccount.parse s!"tr({internalKey},sortedmulti_a(2,{",".intercalate signers.toList}))" .signet)
    (account := true)
  refused "internal: a signer" (MultisigAccount.parse s!"tr({signers[0]!},sortedmulti_a(2,{signers[1]!},{signers[2]!}))" .signet)
    (account := true)

def unspendableXpubInternalKey : TM Unit := do
  let (account, _) ← accountWith
  let .trTree internalKey _ := account.descriptor.expression | throw "expected a tree"
  let .extended xpub keyNetwork := internalKey.base | throw "expected an extended internal key"
  check "nums xpub: no origin" internalKey.origin.isNone
  check "nums xpub: suffix" (internalKey.derivation.elements == MultisigAccount.signerSuffix)
  check "nums xpub: testnet" (keyNetwork == .testnet)
  check "nums xpub: H" (xpub.publicKey == ByteArray.mk #[0x02] ++ Taproot.unspendableInternalKey)
  check "nums xpub: depth 0" (xpub.depth == 0 && xpub.parentFingerprint == 0 && xpub.childIndex == 0)
  let concatenated := account.signers.foldl (fun acc s => match s.base with
    | .extended k _ => acc ++ k.publicKey | _ => acc) ByteArray.empty
  check "nums xpub: chain code" (xpub.chainCode == sha256 concatenated)
  let (first, _) ← need "t" (MultisigAccount.lift (·.name) (account.descriptor.resolvedTaproot 0 0))
  let (second, _) ← need "t" (MultisigAccount.lift (·.name) (account.descriptor.resolvedTaproot 1 0))
  check "nums xpub: a child of H" (first != Taproot.unspendableInternalKey)
  check "nums xpub: children differ" (first != second)
  let reparsed ← need "reparse" (MultisigAccount.parse account.descriptor.serialized .signet)
  check "nums xpub: round trip" ((← need "a" (reparsed.address 3 1)) == (← need "a" (account.address 3 1)))

def unspendableXpubLookAlikesRefused : TM Unit := do
  let ms ← masters
  let signers ← ms.mapM keyExpression
  let leaf := s!"sortedmulti_a(2,{",".intercalate signers.toList})"
  let chainCode := ByteArray.mk (Array.replicate 32 0x42)
  let nums : HDKey := { depth := 0, parentFingerprint := 0, childIndex := 0, chainCode, privateKey := none,
                        publicKey := ByteArray.mk #[0x02] ++ Taproot.unspendableInternalKey }
  let held ← accountKeyOf ms[0]!
  let realKey : HDKey := { nums with publicKey := held.publicKey }
  check "look-alikes: any chain code on H" (MultisigAccount.parse s!"tr({nums.serialized .testnet}/<0;1>/*,{leaf})" .signet).toBool
  let refusedKeys := [s!"{realKey.serialized .testnet}/<0;1>/*", s!"[00000000]{nums.serialized .testnet}/<0;1>/*",
    s!"{nums.serialized .testnet}/0/*", nums.serialized .testnet, s!"{nums.serialized .mainnet}/<0;1>/*"]
  for (k, n) in refusedKeys.zipIdx do
    refused s!"look-alikes: refused {n}" (MultisigAccount.parse s!"tr({k},{leaf})" .signet) (account := true)

def repeatedSignerRefused : TM Unit := do
  let ms ← masters
  let first ← keyExpression ms[0]!
  let second ← keyExpression ms[1]!
  refused "repeat: same key twice" (MultisigAccount.makeDescriptor 2 #[first, first, second] none .signet) (account := true)
  let relabelled := "[00000001" ++ String.ofList (first.toList.dropWhile (· != '/'))
  refused "repeat: relabelled" (MultisigAccount.makeDescriptor 2 #[first, relabelled, second] none .signet) (account := true)
  check "repeat: distinct accepted" (MultisigAccount.makeDescriptor 2 (← ms.mapM keyExpression) none .signet).toBool

def suffixPinned : TM Unit := do
  let ms ← masters
  let bare ← ms.mapM bareKeyExpression
  for suffix in ["/0/*", "/<0;1>/0", "/*", "", "/<1;0>/*", "/<0;1>/*'"] do
    refused s!"suffix: {suffix}"
      (MultisigAccount.makeDescriptor 2 #[bare[0]! ++ "/<0;1>/*", bare[1]! ++ "/<0;1>/*", bare[2]! ++ suffix] none .signet)

def signerKeyShape : TM Unit := do
  let ms ← masters
  let m := ms[0]!
  let other ← keyExpression ms[1]!
  let account ← accountKeyOf m
  let fp := Descriptor.hex8 m.fingerprint
  let bad := [s!"[{fp}/86'/1'/0']{account.serialized .testnet}/<0;1>/*", s!"{account.neutered.serialized .testnet}/<0;1>/*",
    s!"[{fp}/86'/1']{account.neutered.serialized .testnet}/<0;1>/*"]
  for (b, n) in bad.zipIdx do
    refused s!"key shape: refused {n}" (MultisigAccount.makeDescriptor 1 #[b, other] none .signet)
  refused "key shape: other network" (MultisigAccount.makeDescriptor 1 #[← keyExpression m, other] none .mainnet) (account := true)

def shapeRefusals : TM Unit := do
  let signers ← (← masters).mapM keyExpression
  let nums := hex Taproot.unspendableInternalKey
  refused "shape: threshold 0" (MultisigAccount.makeDescriptor 0 signers none .signet)
  refused "shape: threshold 4" (MultisigAccount.makeDescriptor 4 signers none .signet)
  refused "shape: one signer" (MultisigAccount.makeDescriptor 1 #[signers[0]!] none .signet) (account := true)
  refused "shape: a pk leaf beside"
    (MultisigAccount.parse s!"tr({nums},\{sortedmulti_a(1,{signers[0]!},{signers[1]!}),pk({signers[2]!})})" .signet) (account := true)
  let unsorted ← need "unsorted" (MultisigAccount.parse s!"tr({nums},multi_a(2,{",".intercalate signers.toList}))" .signet)
  check "shape: multi_a accepted, unsorted" (!unsorted.isSorted)

def recordCoding : TM Unit := do
  let (account, _) ← accountWith
  let coin ← funding account 5_000
  let record : MultisigAccountRecord :=
    { id := account.id, name := "Household", descriptor := account.descriptor.serialized,
      createdAtHeight := 100, nextReceiveIndex := 3, allUtxos := #[coin] }
  let text := SwiftJSON.write record.toJV
  let keys := match SwiftJSON.parse? text with
    | some (.obj kvs) => kvs.map (·.1) |>.toList
    | _ => []
  let expected := ["id", "name", "descriptor", "createdAtHeight", "nextReceiveIndex", "nextChangeIndex", "utxos"]
  check "record: JSON keys" (keys.length == expected.length && expected.all keys.contains) s!"{keys}"
  check "record: round trip" (match SwiftJSON.decodeText text MultisigAccountRecord.ofJV with | .ok r => r == record | .error _ => false)
  check "record: balance" (record.balance == 5_000)
  let withLedger := { record with ledger := some { policyName := "Household", policyID := ByteArray.mk (Array.replicate 32 1),
    hmac := ByteArray.mk (Array.replicate 32 2), masterFingerprint := 0xF5ACC2FD, keyPath := #[0x8000_0057, 0x8000_0001, 0x8000_0000] } }
  check "record: ledger round trip"
    (match SwiftJSON.decodeText (SwiftJSON.write withLedger.toJV) MultisigAccountRecord.ofJV with
     | .ok r => r == withLedger | .error _ => false)

def bundleAccounts : TM Unit := do
  let (account, ms) ← accountWith
  let coin ← funding account 5_000
  let record : MultisigAccountRecord :=
    { id := account.id, name := "Household", descriptor := account.descriptor.serialized,
      createdAtHeight := 90, nextReceiveIndex := 1, allUtxos := #[coin] }
  let bundle : ImportBundle := { network := "signet", lastKnownHeight := 200 }
  check "bundle: no vaults key without accounts" (!(bundle.serialized.splitOn "vaults").length > 1)
  let withAccount := { bundle with vaults := some #[record] }
  check "bundle: account restores"
    (match ImportBundle.decode withAccount.serialized with | .ok b => b.vaults == some #[record] | .error _ => false)
  let keys ← ms.mapM bareKeyExpression
  let muSig2 := { record with descriptor := s!"tr(musig({keys[0]!},{keys[1]!})/<0;1>/*)" }
  for (vs, n) in [(#[muSig2], 1), (#[record, muSig2], 2)] do
    check s!"bundle: MuSig2 refused {n}"
      (match ImportBundle.decode { bundle with vaults := some vs }.serialized with
       | .error e => e.name == "unsupportedWalletData" | .ok _ => false)
  check "bundle: mainnet refused"
    (match ImportBundle.decode { withAccount with network := "mainnet" }.serialized with
     | .error e => e.name == "unsupportedWalletData" | .ok _ => false)
  check "bundle: too many accounts"
    (match ImportBundle.decode { bundle with vaults := some (Array.replicate (ImportBundle.maximumVaults + 1) record) }.serialized with
     | .error (.wallet _) => true | _ => false)

/-! ## TimelockedMultisigTests -/

def coreVectors : TM Unit := do
  let text ← IO.FS.readFile "Vectors/core-timelocked-multisig.json"
  let json ← needE "json" id (Lean.Json.parse text)
  let cases ← needE "cases" id (json.getObjValAs? (Array Lean.Json) "cases")
  check "core: four cases" (cases.size == 4)
  for c in cases do
    let name ← needE "name" id (c.getObjValAs? String "name")
    let descriptor ← needE "descriptor" id (c.getObjValAs? String "descriptor")
    let checksum ← needE "checksum" id (c.getObjValAs? String "checksum")
    let d ← needE s!"{name} parse" (·.name) (Descriptor.parse descriptor)
    check s!"core {name}: checksum" (d.serialized == descriptor ++ "#" ++ checksum) d.serialized
    let addresses ← needE "addresses" id (c.getObjVal? "addresses")
    for choice in [0, 1] do
      let expected ← needE "choice" id (addresses.getObjValAs? (Array String) (toString choice))
      for (address, index) in expected.toList.zipIdx do
        let derived ← needE "derive" (·.name) (d.derived index.toUInt32 .regtest)
        check s!"core {name}: {choice}/{index}" (derived[choice]!.address == address)

def leafPolicies : TM Unit := do
  let keys := (List.range 3).toArray.map fun i => ByteArray.mk (Array.replicate 32 (i + 1).toUInt8)
  for blocks in ([1, 16, 17, 144, 4320, 65535, 0x7FFF_FFFF] : List UInt32) do
    let multi ← needE "multi" (·.name) (Multisig.timelockedMultiScript 2 keys blocks)
    check s!"policy: multi {blocks}" (Multisig.parsePolicy multi == some { threshold := 2, keys, relativeLock := some blocks })
    check s!"policy: multi {blocks} is not plain" (Multisig.parse multi).isNone
    let single ← needE "single" (·.name) (Multisig.timelockedKeyScript keys[0]! blocks)
    check s!"policy: pk {blocks}" (Multisig.parsePolicy single == some { threshold := 1, keys := #[keys[0]!], relativeLock := some blocks })
  check "policy: older(0) refused" (match Multisig.timelockedKeyScript keys[0]! 0 with | .error .invalidTimelock => true | _ => false)
  let five ← needE "five" (·.name) (Multisig.timelockedKeyScript keys[0]! 5)
  let nonMinimal := five.bytes.extract 0 34 ++ ByteArray.mk #[0x01, 0x05] ++ five.bytes.extract 35 five.bytes.size
  check "policy: non-minimal lock" (Multisig.parsePolicy ⟨nonMinimal⟩).isNone
  check "policy: trailing opcode" (Multisig.parsePolicy ⟨five.bytes.push Script.Op.checkSig⟩).isNone
  check "bip68: equal" (RelativeLock.isSatisfied 10 10 2)
  check "bip68: more" (RelativeLock.isSatisfied 10 11 2)
  check "bip68: fewer" (!RelativeLock.isSatisfied 10 9 2)
  check "bip68: version 1" (!RelativeLock.isSatisfied 10 10 1)
  check "bip68: disabled" (!RelativeLock.isSatisfied 10 0xFFFF_FFFD 2)
  check "bip68: time flag" (!RelativeLock.isSatisfied 10 (10 ||| 0x40_0000) 2)

def tfunding (a : MultisigAccount) (amount : Int64) (index : UInt32 := 0) (height : UInt32) : TM WalletUTXO :=
  funding a amount .receive index height (0x5B + index.toUInt8)

def tspend (a : MultisigAccount) (u : WalletUTXO) (tip : UInt32) (path : SpendPath) : MAM PSBT :=
  spend a u 40_000 tip path

def recoveryKeyOrderDoesNotMatter : TM Unit := do
  let signers ← (← masters).mapM keyExpression
  let others ← (#[0xD4, 0xD5, 0xD6] : Array UInt8).mapM fun b => do keyExpression (← master b)
  let separate ← [others, others.reverse, #[others[1]!, others[2]!, others[0]!]].mapM fun ks => do
    return (← need "d" (MultisigAccount.makeDescriptor 2 (signers.extract 0 2) (some (.separateKeys 2 ks 144)) .signet)).serialized
  check "recovery order: separate keys" (separate.all (· == separate.head!))
  let reused ← [signers, signers.reverse].mapM fun ss => do
    return (← need "d" (MultisigAccount.makeDescriptor 2 ss (some (.fewerSigners 1 10)) .signet)).serialized
  check "recovery order: reused signers" (reused.all (· == reused.head!))

def fewerSigners : TM Unit := do
  let unordered ← masters
  let d ← need "d" (MultisigAccount.makeDescriptor 2 (← unordered.mapM keyExpression) (some (.fewerSigners 1 10)) .signet)
  let account ← need "account" (MultisigAccount.make d .signet)
  let ms ← inSignerOrder unordered account
  let some recovery := account.recovery | throw "no recovery"
  check "fewer: recovery shape" (recovery.threshold == 1 && recovery.blocks == 10 && recovery.keys.size == 3)
  let reparsed ← need "reparse" (MultisigAccount.parse d.serialized .signet)
  check "fewer: round trip" ((← need "a" (reparsed.address 2)) == (← need "a" (account.address 2)))
  let coin ← tfunding account 100_000 0 100
  let now ← need "create" (tspend account coin 101 .signers)
  check "fewer: two leaves" (now.inputs[0]!.tapLeafScripts.size == 2)
  let some changeTree := now.outputs.findSome? (·.tapTree) | throw "no change tree"
  let changeLeaves := (← need "leaves" (account.leaves 1 0)).map (·.script)
  check "fewer: change tree right leaf first" (changeTree.map (·.2.2) == changeLeaves.reverse)
  check "fewer: change tree depth/version" (changeTree.all fun (d, v, _) => d == 1 && v == 0xC0)
  let now ← need "sign 0" (sign account now ms[0]! #[coin] 101)
  check "fewer: one signer cannot finalize" (!now.finalize.toBool)
  let now ← need "sign 2" (sign account now ms[2]! #[coin] 101)
  check "fewer: approvals" ((← need "ap" (account.approvals now #[coin])) == #[0, 2])
  check "fewer: no recovery approvals" ((← need "ap" (account.approvals now #[coin] .recovery)).isEmpty)
  let fast ← need "finalize" (finalize account now #[coin] 101)
  check "fewer: default sequence" (fast.inputs[0]!.sequence == TransactionBuilder.defaultSequence)
  check "fewer: five witness items" (fast.inputs[0]!.witness.size == 5)
  check "fewer: estimate covers signers' witness"
    ((witnessSize fast.inputs[0]!.witness : Int) ≤ (← need "w" (account.witnessBytesPerInput .signers)))
  check "fewer: unlock height 110" (account.recoveryUnlockHeight coin == some 110)
  check "fewer: unlock boundary" (!account.isUnlockedForRecovery coin 108 && account.isUnlockedForRecovery coin 109)
  refused "fewer: young coin refused" (tspend account coin 108 .recovery) (account := true)
  let later ← need "create recovery" (tspend account coin 109 .recovery)
  check "fewer: review path recovery"
    ((← need "review" (account.reviewSpend later #[coin] owned 109)).path == .recovery)
  refused "fewer: review at 108 refused" (account.reviewSpend later #[coin] owned 108) (account := true)
  let later ← need "sign 1" (sign account later ms[1]! #[coin] 109)
  check "fewer: recovery approvals" ((← need "ap" (account.approvals later #[coin] .recovery)) == #[1])
  let slow ← need "finalize slow" (finalize account later #[coin] 109)
  check "fewer: sequence 10" (slow.inputs[0]!.sequence == 10)
  let leaves ← need "leaves" (account.leaves 0 0)
  let some recoveryLeaf := leaves.find? (·.isRecovery) | throw "no recovery leaf"
  let w := slow.inputs[0]!.witness
  check "fewer: recovery leaf in witness" (w[w.size - 2]! == recoveryLeaf.script)
  check "fewer: estimate covers recovery witness"
    ((witnessSize w : Int) ≤ (← need "w" (account.witnessBytesPerInput .recovery)))

def separateKey : TM Unit := do
  let ms ← masters
  let recoveryMaster ← master 0xD4
  let d ← need "d" (MultisigAccount.makeDescriptor 2 (← (ms.extract 0 2).mapM keyExpression)
    (some (.separateKeys 1 #[← keyExpression recoveryMaster] 144)) .signet)
  check "separate: pk leaf" ((d.serialized.splitOn "and_v(v:pk(").length > 1)
  let account ← need "account" (MultisigAccount.make d .signet)
  check "separate: hasSigner" (account.hasSigner recoveryMaster)
  let coin ← tfunding account 80_000 0 500
  let now ← need "create" (tspend account coin 600 .signers)
  refused "separate: recovery key signs nothing on the signers' path" (sign account now recoveryMaster #[coin] 600)
  let later ← need "create" (tspend account coin 643 .recovery)
  let later ← need "sign" (sign account later recoveryMaster #[coin] 643)
  let tx ← need "finalize" (finalize account later #[coin] 643)
  check "separate: sequence 144" (tx.inputs[0]!.sequence == 144)
  check "separate: three witness items" (tx.inputs[0]!.witness.size == 3)

def surplusRecoverySignatureLeftOut : TM Unit := do
  let ms ← masters
  let account ← need "account" (do
    MultisigAccount.make (← MultisigAccount.makeDescriptor 3 (← ms.mapM keyExpression) (some (.fewerSigners 1 10)) .signet) .signet)
  let coin ← tfunding account 100_000 0 100
  let mut later ← need "create" (tspend account coin 109 .recovery)
  for m in ms.extract 0 2 do later ← need "sign" (sign account later m #[coin] 109)
  check "surplus: two recovery approvals" ((← need "ap" (account.approvals later #[coin] .recovery)) == #[0, 1])
  let tx ← need "finalize" (finalize account later #[coin] 109)
  let w := tx.inputs[0]!.witness
  let some recoveryLeaf := (← need "leaves" (account.leaves 0 0)).find? (·.isRecovery) | throw "no recovery leaf"
  check "surplus: recovery leaf" (w[w.size - 2]! == recoveryLeaf.script)
  check "surplus: exactly one signature" (((w.extract 0 3).filter (!·.isEmpty)).size == 1)

def bip326OldCoins : TM Unit := do
  let ms ← masters
  let recoveryMaster ← master 0xD4
  let account ← need "account" (do
    MultisigAccount.make (← MultisigAccount.makeDescriptor 2 (← (ms.extract 0 2).mapM keyExpression)
      (some (.separateKeys 1 #[← keyExpression recoveryMaster] 144)) .signet) .signet)
  let coins := #[← tfunding account 60_000 1 1, ← tfunding account 60_000 2 2]
  let mut psbt ← need "create" (account.createSpend coins #[{ amount := 100_000, scriptPubKey := destination }] 0 2 200 .signers (0.5, 0.5))
  let tx ← need "tx" (MultisigAccount.lift (·.name) psbt.unsignedTransaction)
  for h : k in [0:tx.inputs.size] do
    let some c := coins.find? (·.outpoint == tx.inputs[k].previousOutput) | throw "coin"
    psbt := psbt.modifyInput k (·.setSequence (some (200 - c.height + 1)))
  check "bip326: review path recovery" ((← need "review" (account.reviewSpend psbt coins owned 200)).path == .recovery)
  for m in ms.extract 0 2 do psbt ← need "sign" (sign account psbt m coins 200)
  let finished ← need "finalize" (finalize account psbt coins 200)
  for input in finished.inputs do
    let w := input.witness
    check "bip326: signers' leaf finishes" (((Multisig.parsePolicy ⟨w[w.size - 2]!⟩).bind (·.relativeLock)).isNone)

def timelockedReviewRefusals : TM Unit := do
  let ms ← masters
  let account ← need "account" (do
    MultisigAccount.make (← MultisigAccount.makeDescriptor 2 (← ms.mapM keyExpression) (some (.fewerSigners 1 10)) .signet) .signet)
  let first ← tfunding account 60_000 0 100
  let second ← tfunding account 60_000 1 100
  let mixed ← need "create" (account.createSpend #[first, second] #[{ amount := 100_000, scriptPubKey := destination }] 0 2 200
    .recovery (0.5, 0.5))
  let rebuilt := mixed.modifyInput 1 fun i =>
    ⟨(i.pairs.filter (·.type != PSBT.InType.sequence)).push (PSBT.KeyValue.make PSBT.InType.sequence .empty (ByteArray.mk #[0xFD, 0xFF, 0xFF, 0xFF]))⟩
  check "tl review: mixed is the signers' path"
    ((← need "review" (account.reviewSpend rebuilt #[first, second] owned 200)).path == .signers)
  let stripped ← need "create" (tspend account first 200 .signers)
  let stripped := stripped.modifyInput 0 fun i => i.setTapLeafScripts (i.tapLeafScripts.extract 0 1)
  refused "tl review: a missing leaf" (account.reviewSpend stripped #[first] owned 200) (account := true)

def topOfHeightRange : TM Unit := do
  let ms ← masters
  let account ← need "account" (do
    MultisigAccount.make (← MultisigAccount.makeDescriptor 2 (← ms.mapM keyExpression) (some (.fewerSigners 1 10)) .signet) .signet)
  let coin ← tfunding account 60_000 0 (0xFFFF_FFFF - 4)
  check "top: no unlock height" (account.recoveryUnlockHeight coin).isNone
  let psbt ← need "create" (tspend account coin 200 .signers)
  let psbt := psbt.modifyInput 0 (·.setSequence (some 10))
  refusedWith "top: past the last block height" (account.reviewSpend psbt #[coin] owned 0xFFFF_FFFF)
    (.invalidSpend "input 1 unlocks for recovery only past the last block height")
  let coinbase := { coin with isCoinbase := true }
  let psbt := psbt.modifyInput 0 (·.setSequence (some TransactionBuilder.defaultSequence))
  refusedWith "top: coinbase maturity" (account.reviewSpend psbt #[coinbase] owned 0xFFFF_FFFF)
    (.invalidSpend "input 1 spends a coinbase that matures in 95 blocks")

def admissionRefusals : TM Unit := do
  let ms ← masters
  let signers ← ms.mapM keyExpression
  let bare ← ms.mapM bareKeyExpression
  let other ← keyExpression (← master 0xD4)
  let primary := s!"sortedmulti_a(2,{",".intercalate signers.toList})"
  let nums := hex Taproot.unspendableInternalKey
  let otherBare := String.ofList (other.toList.take (other.length - 8))
  let bare0 := bare[0]!
  let refusedLeaves := [
    s!"and_v(v:pk({other}),older(65536))",
    s!"and_v(v:pk({other}),older(4194314))",
    s!"and_v(v:pk({signers[0]!}),older(10))",
    s!"and_v(v:pk({otherBare}/<2;3>/*),older(10))",
    s!"and_v(v:multi_a(1,{bare0}/<2;3>/*,{bare0}/<2;3>/*),older(10))",
    s!"and_v(v:pk([deadbeef{String.ofList (bare0.toList.drop 9)}/<2;3>/*),older(10))",
    s!"and_v(v:pk({bare0.replace "/86'/" "/87'/"}/<2;3>/*),older(10))",
    s!"multi_a(1,{other})"]
  check "admission: positive control"
    (MultisigAccount.parse s!"tr({nums},\{{primary},and_v(v:pk({other}),older(10))})" .signet).toBool
  for (leaf, n) in refusedLeaves.zipIdx do
    refused s!"admission: refused {n}" (MultisigAccount.parse s!"tr({nums},\{{primary},{leaf}})" .signet)
  refusedWith "admission: bare recovery key"
    (MultisigAccount.parse s!"tr({nums},\{{primary},and_v(v:pk({nums}),older(10))})" .signet)
    (.invalidDescriptor "every recovery key must be an extended public key")
  refused "admission: a timelocked leaf alone" (MultisigAccount.parse s!"tr({nums},and_v(v:pk({other}),older(10)))" .signet)
  check "admission: older(0) is invalidTimelock"
    (match Descriptor.parse s!"tr({nums},\{{primary},and_v(v:pk({other}),older(0))})" with
     | .error .invalidTimelock => true | _ => false)
  refused "admission: recovery threshold 4" (MultisigAccount.makeDescriptor 2 signers (some (.fewerSigners 4 10)) .signet)

/-! ## BIP341 script-path vectors (`SighashBIP341Tests`, script-path half) -/

def scriptPathVectors : TM Unit := do
  let json ← needE "json" id (Lean.Json.parse (← IO.FS.readFile "Vectors/bip341-scriptpath-test-vectors.json"))
  let given ← needE "given" id (json.getObjVal? "given")
  let tx ← needE "tx" (·.name) (Transaction.decode (← hexOf (← needE "raw" id (given.getObjValAs? String "rawUnsignedTx"))))
  let utxos ← needE "utxos" id (given.getObjValAs? (Array Lean.Json) "utxosSpent")
  let spent ← utxos.mapM fun u => do
    return ({ amount := Int64.ofInt (← needE "amount" id (u.getObjValAs? Int "amountSats")),
              scriptPubKey := ← hexOf (← needE "spk" id (u.getObjValAs? String "scriptPubKey")) } : SighashBIP341.SpentOutput)
  let internalKey ← hexOf (← needE "ik" id (given.getObjValAs? String "internalKey"))
  let leafKeys ← (← needE "lk" id (given.getObjValAs? (Array String) "leafKeys")).mapM hexOf
  let threshold ← needE "t" id (given.getObjValAs? Int "threshold")
  check "vectors: NUMS internal key" (internalKey == Taproot.unspendableInternalKey)
  let inputs ← needE "inputs" id (json.getObjValAs? (Array Lean.Json) "inputSpending")
  for entry in inputs do
    let g ← needE "g" id (entry.getObjVal? "given")
    let inter ← needE "i" id (entry.getObjVal? "intermediary")
    let expected ← needE "e" id (entry.getObjVal? "expected")
    let index ← needE "index" id (g.getObjValAs? Nat "txinIndex")
    let leafScript ← hexOf (← needE "leaf" id (g.getObjValAs? String "leafScript"))
    let cbBytes ← hexOf (← needE "cb" id (g.getObjValAs? String "controlBlock"))
    let some cb := Tx.Taproot.ControlBlock.parse? cbBytes | throw "control block"
    let hashType : SighashBIP341.HashType := ⟨(← needE "ht" id (g.getObjValAs? Nat "hashType")).toUInt8⟩
    let annex ← match g.getObjValAs? String "annex" with
      | .ok s => some <$> hexOf s
      | .error _ => pure none
    let secrets ← (← needE "secrets" id (g.getObjValAs? (Array String) "signingSecrets")).mapM hexOf
    let sigMsg ← hexOf (← needE "sigMsg" id (inter.getObjValAs? String "sigMsg"))
    let sigHash ← hexOf (← needE "sigHash" id (inter.getObjValAs? String "sigHash"))
    let sigObj ← needE "sigs" id (expected.getObjVal? "signatures")
    let sigPairs ← match sigObj with
      | .obj kvs => kvs.toArray.mapM fun ⟨k, v⟩ => do return (← hexOf k, ← hexOf (← needE "sig" id v.getStr?))
      | _ => throw "signatures"
    let witness ← (← needE "w" id (expected.getObjValAs? (Array String) "witness")).mapM fun s =>
      pure ((Wire.dataOfHex? s).getD .empty)
    let label := s!"input {index} hashType {hashType.rawValue}"
    let some (t, ks) := Multisig.parse ⟨leafScript⟩ | throw s!"{label}: leaf does not parse"
    check s!"vectors {label}: leaf shape" (t == threshold && ks == leafKeys && cb.internalKey == internalKey)
    let committed := Tx.Taproot.tweakedOutputKey internalKey (some (Tx.Taproot.leafHash Tx.Taproot.leafVersion ⟨leafScript⟩))
    check s!"vectors {label}: commitment"
      (committed == some (suffixBytes spent[index]!.scriptPubKey 32, cb.outputKeyParity))
    let sp := some (SighashBIP341.ScriptPath.ofLeaf ⟨leafScript⟩)
    check s!"vectors {label}: sigMsg" ((SighashBIP341.signatureMessage tx index spent hashType sp annex).toOption == some sigMsg)
    check s!"vectors {label}: sigHash" ((SighashBIP341.sighash tx index spent hashType sp annex).toOption == some sigHash)
    for secret in secrets do
      let xonly ← needE "x" (fun _ => "key") (do pure (xonlyBytes (← pointOfSecret (← secretOf secret))))
      let some (_, expectedSig) := sigPairs.find? (·.1 == xonly) | throw "missing signature"
      check s!"vectors {label}: signature verifies"
        ((schnorrVerify xonly sigHash (expectedSig.extract 0 64)).toOption.getD false)
      let mine := Signer.scriptPathSignature tx index spent ⟨leafScript⟩ Tx.Taproot.leafVersion hashType annex secret aux0
      check s!"vectors {label}: signature reproduced" (mine.toOption == some expectedSig)
    match Signer.multisigWitness sigPairs ⟨leafScript⟩ cb with
    | .ok w =>
      check s!"vectors {label}: witness" (w == witness)
      check s!"vectors {label}: layout" (w.size == leafKeys.size + 2 && w[leafKeys.size]! == leafScript &&
        w.back? == some cb.serialized && w[1]! == .empty)
    | .error e => check s!"vectors {label}: witness" false e.name

def main : IO UInt32 := do
  runTest "twoOfThree" twoOfThree
  runTest "everyPairCanSpend" everyPairCanSpend
  runTest "threeOfThree" threeOfThree
  runTest "accountKeySigning" accountKeySigning
  runTest "forgedApprovalNotCounted" forgedApprovalNotCounted
  runTest "signerOrderDoesNotMatter" signerOrderDoesNotMatter
  runTest "changeByScriptOnly" changeByScriptOnly
  runTest "reviewRefusals" reviewRefusals
  runTest "realInternalKeyRefused" realInternalKeyRefused
  runTest "unspendableXpubInternalKey" unspendableXpubInternalKey
  runTest "unspendableXpubLookAlikesRefused" unspendableXpubLookAlikesRefused
  runTest "repeatedSignerRefused" repeatedSignerRefused
  runTest "suffixPinned" suffixPinned
  runTest "signerKeyShape" signerKeyShape
  runTest "shapeRefusals" shapeRefusals
  runTest "recordCoding" recordCoding
  runTest "bundleAccounts" bundleAccounts
  runTest "coreVectors" coreVectors
  runTest "leafPolicies" leafPolicies
  runTest "recoveryKeyOrderDoesNotMatter" recoveryKeyOrderDoesNotMatter
  runTest "fewerSigners" fewerSigners
  runTest "separateKey" separateKey
  runTest "surplusRecoverySignatureLeftOut" surplusRecoverySignatureLeftOut
  runTest "bip326OldCoins" bip326OldCoins
  runTest "timelockedReviewRefusals" timelockedReviewRefusals
  runTest "topOfHeightRange" topOfHeightRange
  runTest "admissionRefusals" admissionRefusals
  runTest "scriptPathVectors" scriptPathVectors
  let f ← failures.get
  IO.println s!"multisig-test: {← passed.get} passed, {f.size} failed"
  return if f.isEmpty then 0 else 1
