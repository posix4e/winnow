import WinnowApp.Real.RecordsBackend

/-! `records-test`: a scripted run of every records operation against a temporary directory, with the
in-memory key store and two wallets made by `Wallet.create` (two phones: A and B).

Covers people (add, rename, label, attach, remove), every kind of paste, receive and sender labels, a
2-of-2 script-path vault from creation to a finalized spend approved on both phones, a MuSig2 vault through
both rounds to a finalized transaction, store tamper detection, a wrong-network store, a first write that
fails, and reopening everything from disk. Exits 1 on any failure. -/

open Winnow WinnowApp WinnowApp.RecordsReal
open Tx (BitcoinNetwork)

structure T where
  passed : IO.Ref Nat
  failed : IO.Ref (Array String)

def T.check (t : T) (name : String) (ok : Bool) (detail : String := "") : IO Unit := do
  if ok then t.passed.modify (· + 1)
  else
    t.failed.modify (·.push name)
    IO.println s!"FAIL {name}{if detail.isEmpty then "" else ": " ++ detail}"

/-- Runs `x`; a failure is a test failure (and `none`). -/
def T.ok {α} (t : T) (name : String) (x : RM α) : IO (Option α) := do
  match ← x.run with
  | .ok a => t.check name true; return some a
  | .error e => t.check name false s!"{e.name}: {e.description}"; return none

/-- Runs `x`, expecting the failure `kind`. -/
def T.err {α} (t : T) (name kind : String) (x : RM α) : IO Unit := do
  match ← x.run with
  | .ok _ => t.check name false s!"expected {kind}, it succeeded"
  | .error e => t.check name (e.name == kind) s!"expected {kind}, got {e.name}: {e.description}"

def T.get {α} [Inhabited α] (t : T) (name : String) (x : RM α) : IO α := do
  match ← t.ok name x with
  | some a => return a
  | none => throw (IO.userError s!"cannot continue after {name}")

def network : BitcoinNetwork := .regtest

def wm {α} (x : WM α) : RM α := liftWallet network x

def coinbaseInput : Transaction.Input :=
  { previousOutput := ⟨ByteArray.mk (Array.replicate 32 0), 0xFFFF_FFFF⟩, scriptSig := ByteArray.mk #[0x01], sequence := 0xFFFF_FFFF }

def fakeMatch (height : UInt32) (txs : Array Transaction) : Net.BlockMatch :=
  let header : Net.BlockHeader := {
    version := 2, previousHash := ByteArray.mk (Array.replicate 32 0),
    merkleRoot := ByteArray.mk (Array.replicate 32 0xAA), time := 1_700_000_000 + height, bits := 0x207F_FFFF, nonce := 0,
    hash := .empty }
  { height := height, blockHash := .empty, block := { header := header, transactions := txs } }

/-- A block at `height` whose second transaction pays `outputs` (the first is an unrelated coinbase). -/
def fundingBlock (height : UInt32) (seed : UInt8) (outputs : Array (ByteArray × Int64)) : Net.BlockMatch :=
  let coinbase : Transaction := {
    version := 2, inputs := #[coinbaseInput],
    outputs := #[{ value := 50, scriptPubKey := ByteArray.mk #[0x6a] }], locktime := height }
  let funding : Transaction := {
    version := 2,
    inputs := #[{ previousOutput := ⟨ByteArray.mk (Array.replicate 32 seed), 0⟩, scriptSig := .empty, sequence := 0xFFFF_FFFD }],
    outputs := outputs.map fun (s, v) => { value := v, scriptPubKey := s }, locktime := 0 }
  fakeMatch height #[coinbase, funding]

structure Phone where
  name : String
  dir : System.FilePath
  secrets : IO.Ref Keys.InMemorySecrets
  wallet : Wallet
  store : RecordsStore
  sessions : MusigSessions

def Phone.keyStore (p : Phone) : Keys.KeyStore IO := inMemoryKeyStore p.secrets
def Phone.keys (p : Phone) : StoreKeyVault := StoreKeyVault.ofKeyStore p.keyStore

def newPhone (root : System.FilePath) (name : String) : IO Phone := do
  let dir := root / name / "regtest"
  IO.FS.createDirAll dir
  let secrets ← IO.mkRef ({} : Keys.InMemorySecrets)
  let ks := inMemoryKeyStore secrets
  let wallet ← match ← (Wallet.create network ks (some (dir / "wallet.json"))).run with
    | .ok w => pure w
    | .error e => throw (IO.userError s!"Wallet.create: {e.name}")
  let (store, _) ← RecordsStore.open network (some dir) (StoreKeyVault.ofKeyStore ks)
  return { name, dir, secrets, wallet, store, sessions := ← MusigSessions.new }

def Phone.reopen (p : Phone) : IO (Phone × OpenResult) := do
  let (store, r) ← RecordsStore.open network (some p.dir) p.keys
  return ({ p with store }, r)

def Phone.records (p : Phone) : IO Records := RecordsReal.records p.store (some p.wallet)

def vaultScript (p : Phone) (vaultID : String) (index : UInt32) (choice : Nat := 0) : RM ByteArray := do
  let r ← vaultRecord p.store vaultID
  let v ← vaultOf p.store r
  liftVault network (v.scriptPubKey index choice)

def mutateByte (b : ByteArray) (i : Nat) : ByteArray := b.set! i (b[i]! ^^^ 0x01)

/-! ## The script -/

def peopleAndPastes (t : T) (a b : Phone) : IO Unit := do
  -- cards and own keys
  let cardB ← t.get "ownCard B" (do return (← ownPersonCard b.wallet "Bob").serialized)
  let keyB ← t.get "ownKeyExpression B" (ownKeyExpression b.wallet false)
  let keyBm ← t.get "ownKeyExpression B multipath" (ownKeyExpression b.wallet true)
  t.check "own key expression shape" (keyB.startsWith "[" && (keyB.splitOn "/86'/1'/0']tpub").length == 2 && keyBm == keyB ++ "/<0;1>/*") keyB
  -- pastes of each kind
  let pCard ← t.get "paste card" (parsePaste network cardB)
  t.check "paste card reads name, fresh pay-to, signer" (pCard.name == some "Bob" && pCard.payTo == some true && pCard.hasSignerKey)
  let pKey ← t.get "paste key expression" (parsePaste network keyB)
  t.check "paste bare key: fresh pay-to and signer" (pKey.payTo == some true && pKey.hasSignerKey && pKey.name.isNone)
  let pKeyM ← t.get "paste multipath key" (parsePaste network keyBm)
  t.check "paste multipath key" (pKeyM.payTo == some true && pKeyM.hasSignerKey)
  let pDesc ← t.get "paste descriptor" (parsePaste network s!"tr({keyBm})")
  t.check "paste descriptor: pay-to and signer" (pDesc.payTo == some true && pDesc.hasSignerKey)
  let addrB ← t.get "B address" (wm (b.wallet.address .receive 7))
  let pAddr ← t.get "paste address" (parsePaste network addrB)
  t.check "paste address: one address, no signer" (pAddr.payTo == some false && !pAddr.hasSignerKey)
  t.err "paste empty" "empty" (parsePaste network "   ")
  t.err "paste garbage" "unrecognised" (parsePaste network "hello world")
  t.err "paste mainnet address on regtest" "wrongNetwork" (parsePaste network "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
  let otherNet ← t.get "card for another network" (do
    let c := PersonCard.make .mainnet "Eve" none none
    return c.serialized)
  t.err "paste card of another network" "wrongNetwork" (parsePaste network otherNet)
  -- add / rename / duplicates
  let r ← t.get "add Bob from card" (addPerson a.store (some a.wallet) "Bob" (some cardB) false none none none)
  let some bob := r.people.find? (·.name == "Bob") | t.check "Bob saved" false; return
  t.check "Bob can co-own and is paid at fresh addresses" (bob.signerKey.isSome && bob.payTo == some true && bob.signerFingerprint.isSome)
  t.check "recipientByScript covers Bob's first scripts" ((r.recipientByScript.filter (·.2 == bob.id)).length == 20)
  t.err "duplicate card refused" "duplicate" (addPerson a.store (some a.wallet) "Bobby" (some cardB) false none none none)
  t.err "a name over two lines is refused" "invalidState" (addPerson a.store (some a.wallet) "Bo\nb" (some addrB) false none none none)
  t.err "for signing, an address is not enough" "noSignerKey" (addPerson a.store (some a.wallet) "Carl" (some addrB) true none none none)
  let r ← t.get "rename Bob" (updateRecipient a.store (some a.wallet) bob.id (some "Robert") true)
  t.check "renamed" ((r.people.find? (·.id == bob.id)).map (·.name) == some "Robert")
  let r ← t.get "add Carol from an address" (addPerson a.store (some a.wallet) "Carol" (some addrB) false none none none)
  let some carol := r.people.find? (·.name == "Carol") | t.check "Carol saved" false; return
  t.check "Carol pays one address" (carol.payTo == some false && carol.signerKey.isNone)
  -- sender labels
  let txid := hex (ByteArray.mk (Array.replicate 32 0x5a))
  let r ← t.get "add Dave as the sender of a payment" (addPerson a.store (some a.wallet) "Dave" none false none none (some txid))
  let some dave := r.people.find? (·.name == "Dave") | t.check "Dave saved" false; return
  t.check "Dave is name-only and labels the payment" (dave.payTo.isNone && r.senderByTxid == [(txid, dave.id)])
  t.err "label with an unknown person" "unknownPerson" (labelSender a.store (some a.wallet) txid "nobody")
  t.err "label with an invalid txid" "invalidState" (labelSender a.store (some a.wallet) "abcd" dave.id)
  t.err "a sender with an invalid txid" "invalidState" (addPerson a.store (some a.wallet) "Eve" none false none none (some "abcd"))
  let r ← RM.toIO (RM.io (RecordsReal.records a.store (some a.wallet)))
  t.check "the person is saved even when the label is refused (as AppModel's two steps)" (r.people.any (·.name == "Eve"))
  let some eve := r.people.find? (·.name == "Eve") | t.check "Eve saved" false; return
  let (aR, _) ← a.reopen
  t.check "and disk agrees with memory" ((← RecordsReal.records aR.store (some a.wallet)).people.any (·.name == "Eve"))
  discard <| t.get "remove Eve" (removePerson a.store (some a.wallet) eve.id)
  let addrB2 ← t.get "B address 8" (wm (b.wallet.address .receive 8))
  let r ← t.get "attach a funding address to Dave" (attachDestination a.store (some a.wallet) dave.id addrB2 .localFunding (some txid))
  t.check "Dave now has an unverified funding destination"
    (((r.people.find? (·.id == dave.id)).map fun p => p.payTo == some false && p.provenance == some .localFunding) == some true)
  t.err "a second destination is refused" "invalidState" (attachDestination a.store (some a.wallet) dave.id addrB .supplied none)
  let r ← t.get "remove the sender label" (removeSenderLabel a.store (some a.wallet) txid)
  t.check "label removed" r.senderByTxid.isEmpty
  discard <| t.get "label again" (labelSender a.store (some a.wallet) txid dave.id)
  let r ← t.get "remove Dave" (removePerson a.store (some a.wallet) dave.id)
  t.check "removing a person prunes their labels" (r.senderByTxid.isEmpty && !(r.people.any (·.id == dave.id)))
  let r ← t.get "remove Carol" (removePerson a.store (some a.wallet) carol.id)
  t.check "Carol removed" (!(r.people.any (·.id == carol.id)))
  t.err "remove twice" "unknownPerson" (removePerson a.store (some a.wallet) carol.id)
  -- hide and re-save a recipient keeps the record
  let r ← t.get "hide Robert" (updateRecipient a.store (some a.wallet) bob.id none false)
  t.check "hidden" (((r.people.find? (·.id == bob.id)).map (·.isSavedRecipient)) == some false)
  let r ← t.get "re-saving the hidden card restores it" (addPerson a.store (some a.wallet) "Bob" (some cardB) false none none none)
  t.check "same record, saved again, renamed" (((r.people.find? (·.id == bob.id)).map fun p => p.isSavedRecipient && p.name == "Bob") == some true)
  -- B knows A too (for the savings screens)
  let cardA ← t.get "ownCard A" (do return (← ownPersonCard a.wallet "Alice").serialized)
  discard <| t.get "B adds Alice" (addPerson b.store (some b.wallet) "Alice" (some cardA) true none none none)

def receiveLabels (t : T) (a b : Phone) : IO Unit := do
  let addr ← t.get "A receive address" (wm (a.wallet.address .receive 0))
  let foreign ← t.get "B receive address" (wm (b.wallet.address .receive 0))
  let r ← t.get "set a receive label" (setReceiveLabel a.store a.wallet addr "Invoice 12")
  t.check "label shown by address" (r.receiveLabels == [(addr, "Invoice 12")])
  t.err "a label for someone else's address is refused" "noWallet"
    (setReceiveLabel a.store a.wallet foreign "x")
  t.err "a two-line label is refused" "invalidLabel" (setReceiveLabel a.store a.wallet addr "a\nb")
  let addr1 ← t.get "A receive address 1" (wm (a.wallet.address .receive 1))
  discard <| t.get "second label" (setReceiveLabel a.store a.wallet addr1 "  Rent  ")
  let r ← t.get "empty text removes a label" (setReceiveLabel a.store a.wallet addr "")
  t.check "one label left, trimmed" (r.receiveLabels == [(addr1, "Rent")])
  let file ← IO.FS.readFile (a.dir / "receive-labels.json")
  let script ← t.get "script of address 1" (RM.lift (fun e => namedError e.name network) (AddressDecoder.scriptPubKey addr1 network))
  t.check "labels file in the Swift shape"
    (file == s!"\{\"labels\":\{\"{hex script}\":\"Rent\"},\"network\":\"regtest\",\"version\":1,\"walletID\":\"{a.wallet.id}\"}") file

def lookupSenderTest (t : T) (b : Phone) : IO Unit := do
  let txid := hex (ByteArray.mk (Array.replicate 32 0x11))
  let funder ← t.get "B address 9" (wm (b.wallet.address .receive 9))
  let answer := s!"\{\"txid\":\"{txid}\",\"vin\":[\{\"prevout\":\{\"scriptpubkey_address\":\"{funder}\"}},\{\"prevout\":null},\{\"prevout\":\{\"scriptpubkey_address\":\"{funder}\"}}]}"
  let urls ← IO.mkRef ([] : List String)
  let get : String → Nat → IO ByteArray := fun url _ => do urls.modify (url :: ·); return answer.toUTF8
  let addrs ← t.get "lookupSender" (lookupSender get network txid "https://example.org/api/")
  t.check "distinct funding addresses, in input order" (addrs == [funder])
  t.check "GET {base}/tx/{txid}" ((← urls.get) == [s!"https://example.org/api/tx/{txid}"])
  let other : String → Nat → IO ByteArray := fun _ _ => return "{\"txid\":\"00\",\"vin\":[]}".toUTF8
  t.err "a different transaction is refused" "unavailable" (lookupSender other network txid "https://example.org/api")
  let bad : String → Nat → IO ByteArray := fun _ _ => return "[]".toUTF8
  t.err "a wrong shape is refused" "unavailable" (lookupSender bad network txid "https://example.org/api")
  t.err "an invalid txid is refused" "unavailable" (lookupSender get network "abc" "https://example.org/api")

/-- The 2-of-2 script-path savings: created on A with Bob, added on B from the card, funded, spent with
both approvals, finalized on B. -/
def scriptPathVault (t : T) (a b : Phone) : IO Unit := do
  let ra ← a.records
  let some bob := ra.people.find? (·.name == "Bob") | t.check "Bob present" false; return
  let (vaultID, r) ← t.get "createSharedSavings" (createSharedSavings a.store a.wallet 5 "Rainy day" [bob.id] 2)
  let some v := r.vaults.find? (·.id == vaultID) | t.check "vault listed" false; return
  t.check "2-of-2 savings with Bob and you"
    (v.threshold == 2 && v.signerCount == 2 && v.isScriptPath && v.includesYou && v.coOwners == ["Bob"] &&
     v.signers.length == 2 && v.signers.any (·.isYou) && v.signers.any (·.name == some "Bob")) (reprStr v)
  t.err "the same savings twice" "duplicateVault" (createSharedSavings a.store a.wallet 5 "Again" [bob.id] 2)
  t.err "co-owner without a signer key" "unknownPerson" (createSharedSavings a.store a.wallet 5 "X" ["nobody"] 2)
  let card ← t.get "sharedSavingsCard" (sharedSavingsCard a.store vaultID)
  let rb ← t.get "B adds the savings from the card" (addSharedSavings b.store (some b.wallet) 5 card)
  let some vb := rb.vaults.find? (·.id == vaultID) | t.check "B sees the same vault id" false; return
  t.check "B reads Alice and itself" (vb.includesYou && vb.coOwners == ["Alice"] && vb.name == "Rainy day")
  -- receive addresses
  let first := v.receiveAddress
  let r ← t.get "advance receive" (do RM.io (advanceVaultReceive a.store (some a.wallet) vaultID))
  let v1 := r.vaults.find? (·.id == vaultID)
  t.check "the receive address moved" ((v1.bind (·.receiveAddress)) != first && (v1.bind (·.receiveAddress)).isSome)
  -- fund both phones' views at height 10
  let s0 ← t.get "vault script 0" (vaultScript a vaultID 0)
  let s1 ← t.get "vault script 1" (vaultScript a vaultID 1)
  let block := fundingBlock 10 0x77 #[(s0, 60_000), (s1, 40_000)]
  discard <| t.get "A applies the funding block" (applyVaultMatch a.store block)
  discard <| t.get "B applies the funding block" (applyVaultMatch b.store block)
  let ra ← a.records
  t.check "balance 100000 in two coins" (((ra.vaults.find? (·.id == vaultID)).map fun v => (v.balance, v.utxos.length)) == some (100_000, 2))
  let scripts ← t.get "vault watch scripts" (vaultWatchScripts a.store)
  t.check "watch scripts include the funded ones" (scripts.contains s0 && scripts.contains s1)
  -- A proposes paying Bob 30000 (Bob's next fresh address)
  let tip : UInt32 := 200
  let (vp, preview) ← t.get "previewVaultSend to Bob" (previewVaultSend a.store vaultID "" 30_000 2_000 tip false (some bob.id))
  t.check "preview is a vault spend paying 30000 with change"
    (preview.amount == 30_000 && preview.change.isSome && preview.recipient.map (·.name) == some "Bob" &&
     (match preview.source with | .vault id _ _ sp th n => id == vaultID && sp && th == 2 && n == 2 | _ => false))
  let r ← t.get "prepareVaultApproval" (prepareVaultApproval a.store (some a.wallet) vp tip)
  t.check "Bob's payment counter moved past the reserved address"
    (((r.people.find? (·.id == bob.id)).map (·.nextPaymentIndex)) == some 1)
  t.err "the same preview cannot be prepared twice" "sendReviewChanged" (prepareVaultApproval a.store (some a.wallet) vp tip)
  -- the approval exchange
  let rev ← t.get "A reviews its request" (approvalAdd a.store (some a.wallet) vaultID none vp.psbt.base64 tip)
  t.check "review: lines, no approvals yet, you are a signer"
    (rev.lines.isSome && rev.approvals.isEmpty && rev.threshold == 2 && rev.ownPosition.isSome &&
     ((rev.lines.getD []).any fun l => l.label == .person "Bob" && l.amount == 30_000) &&
     ((rev.lines.getD []).any fun l => l.isVaultOwned)) (reprStr rev.lines)
  t.err "finish without approvals" "notReady" (approvalFinish a.store (some a.wallet) vaultID rev.working tip)
  let revA ← t.get "A approves" (approvalApprove a.store a.wallet vaultID rev.working tip)
  t.check "A's approval counted" (revA.approvals == [revA.ownPosition.getD 99])
  t.err "approving twice is refused" "notReady" (approvalApprove a.store a.wallet vaultID revA.working tip)
  t.err "1 of 2 cannot finish" "notReady" (approvalFinish a.store (some a.wallet) vaultID revA.working tip)
  t.err "a request for unknown savings" "unknownSavings"
    (approvalAdd a.store (some a.wallet) "nope" none revA.output tip)
  let revB ← t.get "B reviews A's envelope" (approvalAdd b.store (some b.wallet) vaultID none revA.output tip)
  t.check "B sees Alice's approval" (revB.approvals.length == 1 && revB.signerNames.any (·.2 == "Alice"))
  let revB2 ← t.get "B approves" (approvalApprove b.store b.wallet vaultID revB.working tip)
  t.check "2 of 2" (revB2.approvals.length == 2)
  let rec ← t.get "B rechecks" (approvalRecheck b.store (some b.wallet) vaultID revB2.working tip)
  t.check "recheck keeps the review" (rec.lines.isSome && rec.approvals.length == 2)
  let fin ← t.get "B finishes" (approvalFinish b.store (some b.wallet) vaultID revB2.working tip)
  t.check "a finalized transaction with witnesses"
    (fin.transaction.inputs.all (!·.witness.isEmpty) && fin.txid == displayHex fin.transaction.txid && fin.rawHex.length > 0)
  let rb ← t.get "B records the broadcast spend" (commitVaultSpend b.store (some b.wallet) fin)
  let some vb := rb.vaults.find? (·.id == vaultID) | t.check "vault still there" false; return
  let fee := (rev.fee.getD 0)
  t.check "B's coins: inputs out, change pending" (vb.balance == 100_000 - 30_000 - fee && vb.utxos.any (·.height == 0)) (reprStr vb.utxos)
  let rb2 ← t.get "recording twice is harmless" (commitVaultSpend b.store (some b.wallet) fin)
  t.check "unchanged" (((rb2.vaults.find? (·.id == vaultID)).map (·.balance)) == some vb.balance)
  -- A sees the spend in a block: its coins follow; the stale proposal no longer reviews
  let confirm := fakeMatch 11 #[{ version := 2, inputs := #[coinbaseInput], outputs := #[], locktime := 0 }, fin.transaction]
  discard <| t.get "A applies the spend's block" (applyVaultMatch a.store confirm)
  let ra ← a.records
  t.check "A: change confirmed" (((ra.vaults.find? (·.id == vaultID)).map fun v => v.balance == vb.balance && v.utxos.any (·.height == 11) && !(v.utxos.any (·.height == 0))) == some true)
    (reprStr ((ra.vaults.find? (·.id == vaultID)).map fun v => (v.balance, v.utxos)) ++ s!" B {vb.balance}")
  let stale ← t.get "A rechecks the spent request" (approvalRecheck a.store (some a.wallet) vaultID revA.working tip)
  t.check "a spent request loses its review" (stale.lines.isNone && stale.reviewError.isSome && stale.approvals.isEmpty)
  discard <| t.get "B applies the spend's block" (applyVaultMatch b.store confirm)
  discard <| t.get "backup records once confirmed" (backupVaultRecords b.store)

/-- MuSig2 2-of-2 on both phones, round 1, round 2, aggregate, finalize. -/
def muSig2Vault (t : T) (a b : Phone) : IO Unit := do
  let ka ← t.get "A bare key" (ownKeyExpression a.wallet false)
  let kb ← t.get "B bare key" (ownKeyExpression b.wallet false)
  t.err "a multipath key is not a MuSig2 participant" "muSig2DerivationForbidden"
    (checkCosigner network .muSig2 [ka] (kb ++ "/<0;1>/*"))
  t.err "the same key twice" "duplicateKey" (checkCosigner network .muSig2 [ka] ka)
  discard <| t.ok "checkCosigner" (checkCosigner network .muSig2 [ka] kb)
  let built ← t.get "buildVault MuSig2" (buildVault network .muSig2 2 [ka, kb])
  t.check "n-of-n key path" (!built.isScriptPath && built.threshold == 2 && built.signerCount == 2 && built.firstAddress.isSome)
  let ra ← t.get "A adds the MuSig2 vault" (addVault a.store (some a.wallet) 20 "Joint" built.descriptor)
  discard <| t.get "B adds the MuSig2 vault" (addVault b.store (some b.wallet) 20 "Joint" built.descriptor)
  let some v := ra.vaults.find? (·.name == "Joint") | t.check "listed" false; return
  t.check "a MuSig2 vault has no shared-savings reading" (v.coOwners.isEmpty && v.signers.isEmpty)
  let s0 ← t.get "musig script" (vaultScript a v.id 0)
  let block := fundingBlock 30 0x99 #[(s0, 50_000)]
  discard <| t.get "A funds" (applyVaultMatch a.store block)
  discard <| t.get "B funds" (applyVaultMatch b.store block)
  let tip : UInt32 := 300
  let dest ← t.get "B address" (wm (b.wallet.address .receive 3))
  let (vp, _) ← t.get "previewVaultSend MuSig2" (previewVaultSend a.store v.id dest 20_000 1_000 tip false)
  let m0 ← t.get "A musigAdd" (musigAdd a.store (some a.wallet) v.id none vp.psbt.base64 tip)
  t.check "proposal reviews, no nonces" (m0.lines.isSome && m0.minNonces == 0 && m0.participantCount == some 2)
  t.err "sign before round 1" "notReady" (musigSign a.store a.sessions a.wallet v.id m0.working tip)
  let m1 ← t.get "A round 1" (musigNonces a.store a.sessions a.wallet v.id m0.working tip)
  t.check "A's nonce attached" (m1.minNonces == 1 && (← musigHasNonces a.sessions v.id))
  t.err "a second round 1 is refused" "notReady" (musigNonces a.store a.sessions a.wallet v.id m1.working tip)
  let b0 ← t.get "B musigAdd A's reply" (musigAdd b.store (some b.wallet) v.id none m1.output tip)
  let b1 ← t.get "B round 1" (musigNonces b.store b.sessions b.wallet v.id b0.working tip)
  t.check "both nonces on B" (b1.minNonces == 2)
  t.err "A cannot sign before it has B's nonce" "notReady" (musigSign a.store a.sessions a.wallet v.id m1.working tip)
  let m2 ← t.get "A combines B's reply" (musigAdd a.store (some a.wallet) v.id (some m1.working) b1.output tip)
  t.check "A has both nonces" (m2.minNonces == 2)
  let m3 ← t.get "A round 2" (musigSign a.store a.sessions a.wallet v.id m2.working tip)
  t.check "A's partial signature, nonces scrubbed" (m3.minPartialSigs == 1 && !(← musigHasNonces a.sessions v.id))
  t.err "A cannot sign twice" "notReady" (musigSign a.store a.sessions a.wallet v.id m2.working tip)
  t.err "not ready to send with one signature" "notReady" (musigBroadcast a.store v.id m3.working tip)
  let b2 ← t.get "B combines A's signature" (musigAdd b.store (some b.wallet) v.id (some b1.working) m3.output tip)
  let b3 ← t.get "B round 2" (musigSign b.store b.sessions b.wallet v.id b2.working tip)
  t.check "every approval" (b3.minPartialSigs == 2)
  let fin ← t.get "B aggregates and finalizes" (musigBroadcast b.store v.id b3.working tip)
  t.check "a key-path spend (one 64-byte signature per input)"
    (fin.transaction.inputs.all fun i => i.witness.size == 1 && i.witness[0]!.size == 64)
  let rb ← t.get "B records it" (commitVaultSpend b.store (some b.wallet) fin)
  t.check "B: vault balance follows" (((rb.vaults.find? (·.id == v.id)).map (·.balance)) == some (50_000 - 20_000 - (m0.fee.getD 0)))
  -- restart and clear on a fresh exchange
  let ra ← a.records
  let some va := ra.vaults.find? (·.id == v.id) | return
  t.check "A has not recorded it yet" (va.balance == 50_000)
  let r0 ← t.get "restart strips nonces and signatures" (musigRestart a.store a.sessions (some a.wallet) v.id m3.working tip)
  t.check "stripped" (r0.minNonces == 0 && r0.minPartialSigs == 0 && r0.lines.isSome)
  let r1 ← t.get "round 1 again after restart" (musigNonces a.store a.sessions a.wallet v.id r0.working tip)
  t.check "fresh nonces held" (r1.minNonces == 1 && (← musigHasNonces a.sessions v.id))
  musigClear a.sessions
  t.check "musigClear scrubs" (!(← musigHasNonces a.sessions v.id))

def tamper (t : T) (root : System.FilePath) (a : Phone) : IO Unit := do
  -- tampered people.json: a notice, and every mutation refused
  let peoplePath := a.dir / "people.json"
  let good ← IO.FS.readBinFile peoplePath
  t.check "people.json is sealed" (SealedStoreFile.isSealed good)
  IO.FS.writeBinFile peoplePath (mutateByte good (good.size - 3))
  let (a2, _) ← a.reopen
  let r ← a2.records
  t.check "tampered people: unverified notice, no people"
    (r.peopleStorageNotice == some PeopleStore.unverifiedStorageMessage && r.people.isEmpty)
  t.err "a damaged people store refuses mutations" "damaged"
    (addPerson a2.store (some a.wallet) "Zed" none false none none (some (hex (ByteArray.mk (Array.replicate 32 1)))))
  IO.FS.writeBinFile peoplePath good
  -- unsealed file while a key exists
  match SealedStoreFile.open good "people" network ((← (a.keys.key "people.regtest").run).toOption.join.getD .empty) with
  | .ok payload =>
    IO.FS.writeBinFile peoplePath payload
    let (a3, _) ← a.reopen
    t.check "an unsealed file once a key exists reads as unverified"
      ((← a3.records).peopleStorageNotice == some PeopleStore.unverifiedStorageMessage)
    -- a valid seal around invalid content is damage, not substitution
    let key := ((← (a.keys.key "people.regtest").run).toOption.join).getD .empty
    IO.FS.writeBinFile peoplePath (SealedStoreFile.sealed "{\"people\":[{\"id\":\"x\"}]}".toUTF8 "people" network key)
    let (a4, _) ← a.reopen
    t.check "valid seal, invalid records: the damaged message"
      ((← a4.records).peopleStorageNotice == some PeopleStore.damagedStorageMessage)
  | .error e => t.check "own people file opens" false e.name
  IO.FS.writeBinFile peoplePath good
  -- tampered vaults.json: damaged (the app's storageDamaged stage)
  let vaultsPath := a.dir / "vaults.json"
  let vgood ← IO.FS.readBinFile vaultsPath
  IO.FS.writeBinFile vaultsPath (mutateByte vgood 30)
  let (_, res) ← a.reopen
  t.check "tampered vaults: unverified" (res == .damaged VaultStore.unverifiedStorageMessage) (reprStr res)
  IO.FS.writeBinFile vaultsPath vgood
  -- a people file sealed for another store name
  IO.FS.writeBinFile vaultsPath good
  let (_, res) ← a.reopen
  t.check "people.json dropped in as vaults.json is refused" (res == .damaged VaultStore.unverifiedStorageMessage)
  IO.FS.writeBinFile vaultsPath vgood
  -- wrong network, same device: a regtest file under signet, where signet has a key
  let sigDir := root / "A-signet"
  IO.FS.createDirAll sigDir
  let (sig, _) ← RecordsStore.open .signet (some sigDir) a.keys
  discard <| t.get "signet store's first write establishes its key"
    (addPerson sig none "Sam" none false none none (some (hex (ByteArray.mk (Array.replicate 32 2)))))
  IO.FS.writeBinFile (sigDir / "vaults.json") vgood
  let (_, _) ← RecordsStore.open .signet (some sigDir) a.keys
  discard <| (a.keys.establishKey "vaults.signet").run
  let (_, res) ← RecordsStore.open .signet (some sigDir) a.keys
  t.check "a regtest vault file under signet fails verification" (res == .damaged VaultStore.unverifiedStorageMessage)
  -- wrong network, fresh device: sealed file, no key at all
  let fresh ← IO.mkRef ({} : Std.HashMap String ByteArray)
  let freshDir := root / "fresh"
  IO.FS.createDirAll freshDir
  IO.FS.writeBinFile (freshDir / "vaults.json") vgood
  let (_, res) ← RecordsStore.open network (some freshDir) (StoreKeyVault.inMemory fresh)
  t.check "a sealed file without its key is refused (keyMissing)" (res == .damaged VaultStore.unverifiedStorageMessage)
  -- a file from before sealing is adopted and sealed
  let legacyDir := root / "legacy"
  IO.FS.createDirAll legacyDir
  let legacyKeys ← IO.mkRef ({} : Std.HashMap String ByteArray)
  match SealedStoreFile.open vgood "vaults" network ((← (a.keys.key "vaults.regtest").run).toOption.join.getD .empty) with
  | .ok payload =>
    IO.FS.writeBinFile (legacyDir / "vaults.json") payload
    let (ls, res) ← RecordsStore.open network (some legacyDir) (StoreKeyVault.inMemory legacyKeys)
    t.check "an unsealed legacy file loads" (res == .loaded)
    t.check "and is sealed now" (SealedStoreFile.isSealed (← IO.FS.readBinFile (legacyDir / "vaults.json")))
    t.check "with its vaults" (!(← ls.read).vaults.records.isEmpty)
  | .error e => t.check "own vault file opens" false e.name
  -- a first write that fails discards the new key
  let failKeys ← IO.mkRef ({} : Std.HashMap String ByteArray)
  let failDir := root / "fail"
  IO.FS.createDirAll failDir
  let (fs, _) ← RecordsStore.open network (some failDir) (StoreKeyVault.inMemory failKeys)
    (writeData := fun _ _ => throw (IO.userError "disk full"))
  t.err "a failed first write fails" "ioError"
    (addPerson fs none "Nia" none false none none (some (hex (ByteArray.mk (Array.replicate 32 3)))))
  t.check "and leaves no key behind" (!(← failKeys.get).contains "people.regtest")
  t.check "and no person" (← records fs none).people.isEmpty
  -- a damaged label file: a notice, sets refused
  let labelsPath := a.dir / "receive-labels.json"
  let lgood ← IO.FS.readBinFile labelsPath
  IO.FS.writeBinFile labelsPath "{\"version\":2}".toUTF8
  let (a5, _) ← a.reopen
  let r ← a5.records
  t.check "damaged labels: notice" (r.receiveLabelStorageNotice == some (RecordsError.labels .damaged).description && r.receiveLabels.isEmpty)
  let addr ← t.get "address" (wm (a.wallet.address .receive 2))
  t.err "a damaged label store refuses sets" "damaged" (setReceiveLabel a5.store a.wallet addr "x")
  IO.FS.writeBinFile labelsPath lgood

def reopenFromDisk (t : T) (a : Phone) (before : Records) : IO Unit := do
  let (a2, res) ← a.reopen
  t.check "reopen: vaults load" (res == .loaded)
  let r ← a2.records
  t.check "reopen: the same people" (r.people == before.people) s!"{reprStr r.people}"
  t.check "reopen: the same vaults" (r.vaults == before.vaults)
  t.check "reopen: the same labels" (r.receiveLabels == before.receiveLabels && r.senderByTxid == before.senderByTxid)
  t.check "reopen: no notices" (r.peopleStorageNotice.isNone && r.receiveLabelStorageNotice.isNone)
  t.check "own fingerprint" r.ownSignerFingerprint.isSome
  -- the people file is exactly what the Swift encoder writes for these records
  let st ← a2.store.read
  let file ← IO.FS.readBinFile (a.dir / "people.json")
  let key := ((← (a.keys.key "people.regtest").run).toOption.join).getD .empty
  t.check "people.json: seal over the sorted-key envelope"
    (file == SealedStoreFile.sealed (PeopleStore.encode st.people.records st.people.senderByTxid) "people" network key)

def main : IO UInt32 := do
  let t : T := { passed := ← IO.mkRef 0, failed := ← IO.mkRef #[] }
  let root ← IO.FS.createTempDir
  IO.println s!"records-test in {root}"
  try
    let a ← newPhone root "A"
    let b ← newPhone root "B"
    peopleAndPastes t a b
    receiveLabels t a b
    lookupSenderTest t b
    scriptPathVault t a b
    muSig2Vault t a b
    let before ← a.records
    tamper t root a
    reopenFromDisk t a before
  catch e =>
    t.check "the script ran to the end" false (toString e)
  let failed ← t.failed.get
  IO.println s!"records-test: {← t.passed.get} passed, {failed.size} failed"
  return if failed.isEmpty then 0 else 1
