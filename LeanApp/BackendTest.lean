import WinnowApp.Real
open Lean Winnow Winnow.IO Winnow.Net WinnowApp

/-! `backend-test`: `Backend.real` end to end against a disposable regtest bitcoind, through the
Backend fields only (plus the diagnostics handle for "no loop survives a stop").

The node is started as `Lean/IOTest.lean` does (temp datadir, random free ports, compact-filter
serving) and killed by PID at the end, also on failure. The backend runs with an in-memory key store
and `curlFetch`, the app's settings on the regtest network with the node as the manual peer.

create → start networking → sync to tip → receive address → fund + mine → syncNow → balance and
history → fee rate + preview → send → the node's mempool → mine → confirmed, balance arithmetic →
a second send, fee bump (RBF accepted by the node) → mine → export → import into a fresh directory
(same balance) → stop networking (no loop, no peer, no file change while blocks arrive) → reopen from
disk → delete. One `ok`/`FAIL` line per check; the exit code is the verdict. -/

def bitcoind := "/opt/homebrew/bin/bitcoind"
def bitcoinCli := "/opt/homebrew/bin/bitcoin-cli"

initialize failures : IO.Ref (Array String) ← IO.mkRef #[]
/-- Every `Deps.journal` line of the run: which backend (A, B, C), the event, its fields. -/
initialize journalEvents : IO.Ref (Array (String × String × List (String × String))) ← IO.mkRef #[]
initialize passes : IO.Ref Nat ← IO.mkRef 0

def say (s : String) : IO Unit := do IO.println s; (← IO.getStdout).flush

def check (name : String) (cond : Bool) (detail : String := "") : IO Unit := do
  if cond then
    passes.modify (· + 1)
    say s!"  ok   {name}{if detail.isEmpty then "" else " — " ++ detail}"
  else
    failures.modify (·.push name)
    say s!"  FAIL {name}{if detail.isEmpty then "" else " — " ++ detail}"

/-! ## The node (as IOTest) -/

structure Node where
  datadir : String
  p2p : UInt16
  rpc : UInt16
  pid : UInt32

def Node.cli (n : Node) (args : Array String) : IO String := do
  let out ← IO.Process.output { cmd := bitcoinCli, args := #["-regtest", s!"-datadir={n.datadir}", s!"-rpcport={n.rpc}"] ++ args }
  if out.exitCode != 0 then throw (IO.userError s!"bitcoin-cli {args}: {out.stderr.trimAscii}")
  return out.stdout.trimAscii.toString

def Node.wallet (n : Node) (args : Array String) : IO String := n.cli (#["-rpcwallet=w"] ++ args)

def Node.json (n : Node) (args : Array String) : IO Json := do
  match Json.parse (← n.cli args) with
  | .ok j => return j
  | .error e => throw (IO.userError s!"json {args}: {e}")

def Node.height (n : Node) : IO Nat := do return (← n.cli #["getblockcount"]).toNat!
def Node.mine (n : Node) (count : Nat) (addr : String) : IO Unit := do
  let mut left := count
  while left > 0 do
    let k := min left 500
    discard <| n.cli #["generatetoaddress", toString k, addr]
    left := left - k

def killPid (pid : UInt32) (signal : String := "-TERM") : IO Unit := do
  discard <| IO.Process.output { cmd := "kill", args := #[signal, toString pid] }

def startNode (dir : String) : IO Node := do
  for attempt in [0:5] do
    let r ← randomU64
    let p2p := (30000 + r.toNat % 25000).toUInt16
    let rpc := p2p + 1
    let datadir := s!"{dir}/node{attempt}"
    IO.FS.createDirAll datadir
    let child ← IO.Process.spawn {
      cmd := bitcoind
      args := #["-regtest", s!"-datadir={datadir}", s!"-port={p2p}", s!"-rpcport={rpc}", "-bind=127.0.0.1",
        "-listen=1", "-server=1", "-blockfilterindex=1", "-peerblockfilters=1", "-fallbackfee=0.0002",
        "-printtoconsole=0", "-dnsseed=0", "-discover=0", "-listenonion=0", "-whitelist=noban@127.0.0.1"]
      stdout := .null, stderr := .null, stdin := .null }
    let n : Node := { datadir, p2p, rpc, pid := child.pid }
    let mut ready := false
    for _ in [0:100] do
      IO.sleep 200
      if (← child.tryWait).isSome then break
      match ← (n.cli #["getblockchaininfo"]).toBaseIO with
      | .ok _ => ready := true; break
      | .error _ => pure ()
    if ready then return n
    killPid child.pid "-KILL"
  throw (IO.userError "bitcoind did not start")

def Node.waitFilterIndex (n : Node) : IO Unit := do
  for _ in [0:300] do
    let tip ← n.height
    let info ← n.json #["getindexinfo"]
    match info.getObjVal? "basic block filter index" with
    | .ok idx =>
      let synced := (idx.getObjValAs? Bool "synced").toOption.getD false
      let best := (idx.getObjValAs? Nat "best_block_height").toOption.getD 0
      if synced && best == tip then return
    | .error _ => pure ()
    IO.sleep 100
  throw (IO.userError "filter index did not catch up")

def Node.mempool (n : Node) : IO (Array String) := do
  match ← n.json #["getrawmempool"] with
  | .arr xs => return xs.filterMap fun | .str s => some s | _ => none
  | _ => return #[]

def Node.winnowPeers (n : Node) : IO Nat := do
  match ← n.json #["getpeerinfo"] with
  | .arr xs => return (xs.filter fun p => (p.getObjValAs? String "subver").toOption == some "/winnow:0.1/").size
  | _ => return 0

def waitUntil (ms : Nat) (cond : IO Bool) : IO Bool := do
  let deadline := (← IO.monoMsNow) + ms
  while (← IO.monoMsNow) < deadline do
    if ← cond then return true
    IO.sleep 250
  cond

/-! ## The flow -/

def regtestSettings (n : Node) : Settings :=
  { network := .regtest, regtest := { manualPeers := [s!"127.0.0.1:{n.p2p}"] } }

def deps (keys : IO.Ref Keys.InMemorySecrets) (tag : String := "A") : Real.Deps :=
  { keyStore := inMemoryKeyStore keys, fetch := curlFetch "/usr/bin/curl", peerCount := 1,
    journal := fun name fields => journalEvents.modify (·.push (tag, name, fields)) }

/-! ## The journal (test mode's `story-events.jsonl`, captured) -/

def sortedKeys (fields : List (String × String)) : List String := ((fields.map (·.1)).toArray.qsort (· < ·)).toList

def journaled (name : String) : IO (Array (String × List (String × String))) := do
  return (← journalEvents.get).filterMap fun (tag, n, f) => if n == name then some (tag, f) else none

def field (f : List (String × String)) (k : String) : String := (f.lookup k).getD "<missing>"

/-- At least one `name` event, every one of them with exactly `keys`, and one satisfying `ok`. -/
def checkJournal (name : String) (keys : List String) (ok : List (String × String) → Bool := fun _ => true)
    (what : String := "") : IO Unit := do
  let es ← journaled name
  let want := (keys.toArray.qsort (· < ·)).toList
  let shaped := es.all fun (_, f) => sortedKeys f == want
  check s!"journal: {name} {keys}{if what.isEmpty then "" else " — " ++ what}" (!es.isEmpty && shaped && es.any (ok ·.2))
    s!"{es.size} event(s){match es.find? (fun (_, f) => sortedKeys f != want) with
      | some (_, f) => s!", one with {sortedKeys f}" | none => ""}"

/-- A journaled `raw` decodes to the transaction the journal names. -/
def rawIsTxid (raw txid : String) : Bool :=
  match Winnow.ofHex? raw with
  | some bytes => match Transaction.decode bytes with
    | .ok tx => Winnow.displayHex tx.txid == txid
    | .error _ => false
  | none => false

def attempt {α} (x : IO α) : IO (Except String α) := do
  try return .ok (← x) catch e => return .error (toString e)

/-- syncNow until `cond` holds of the snapshot (the loop may hold the pass; syncNow then returns at once). -/
def syncUntil (b : Backend) (ms : Nat) (cond : Status → SyncPhase → Bool) : IO (Status × SyncPhase) := do
  let deadline := (← IO.monoMsNow) + ms
  repeat
    b.syncNow
    let (s, p) ← b.snapshot
    if cond s p || (← IO.monoMsNow) ≥ deadline then return (s, p)
    IO.sleep 500
  b.snapshot

def history? (s : Status) (txid : String) : Option HistoryItem := s.history.find? (·.txid == txid)

def showPhase : SyncPhase → String
  | .idle => "idle" | .connecting c t => s!"connecting {c}/{t}" | .headers s e => s!"headers {s}/{e}"
  | .filters s t => s!"filters {s}/{t}" | .synced => "synced" | .peerDiscoveryFailed => "peerDiscoveryFailed"

def flow (dir : String) (n : Node) : IO Unit := do
  say s!"node: bitcoind regtest pid {n.pid}, p2p {n.p2p}"
  discard <| n.cli #["createwallet", "w"]
  let mineAddr ← n.wallet #["getnewaddress"]
  n.mine 101 mineAddr
  n.waitFilterIndex
  let settings := regtestSettings n
  let keysA ← IO.mkRef ({} : Keys.InMemorySecrets)
  let (a, envA) ← Backend.realWithEnv (deps keysA)
  let dirA := s!"{dir}/A/BTCSwift/regtest"
  IO.FS.createDirAll dirA
  -- 1. Boot with no wallet, networking, create.
  let boot ← a.openWallet .regtest dirA
  check "openWallet on an empty directory is missing" (boot matches .missing)
  a.startNetworking settings
  let words ← a.createWallet .regtest dirA
  check "createWallet returns 12 recovery words" (words.length == 12) s!"{words.length} words"
  let walletFile ← (System.FilePath.mk dirA / "wallet.json").pathExists
  check "wallet.json written, secret in the key store" (walletFile && (← keysA.get).size == 1)
  let pendingBoot ← a.openWallet .regtest dirA
  check "until the backup is confirmed the wallet boots as backup-pending" (pendingBoot matches .backupPending _)
  let again ← a.pendingBackupWords
  check "pendingBackupWords returns the same words" (again == words)
  a.finishOnboarding
  let readyBoot ← a.openWallet .regtest dirA
  check "after finishOnboarding the wallet boots as opened" (readyBoot matches .opened _)
  let gone ← (try discard a.pendingBackupWords; pure false catch _ => pure true)
  check "pendingBackupWords refuses once the backup is confirmed" gone
  a.startNetworking settings
  -- 2. Sync to the tip.
  let tip ← n.height
  let (s0, p0) ← syncUntil a 90_000 fun s p => s.tipHeight == tip && s.nextScanHeight == tip + 1 && p == .synced
  check "sync reaches the node's tip" (s0.tipHeight == tip && s0.nextScanHeight == tip + 1)
    s!"tip {s0.tipHeight}/{tip}, next scan {s0.nextScanHeight}, peers {s0.peerCount}, error {s0.lastSyncError}"
  check "phase is synced" (p0 == .synced) (showPhase p0)
  -- Core sends its (bucketed) relay floor as BIP133 feefilter, in sat/kvB: the app's milli-sat/vB.
  check "fee floor from the peer's feefilter" (match s0.feeFloorMilli with | some f => 0 < f && f ≤ 1000 | none => false)
    s!"{s0.feeFloorMilli}"
  -- 3. Receive and fund.
  let addr ← a.receiveAddress false
  check "receive address is a regtest taproot address" (addr.startsWith "bcrt1p") addr
  let again ← a.receiveAddress false
  check "the current receive address is peeked, not advanced" (again == addr)
  let fundTxid ← n.wallet #["sendtoaddress", addr, "1.0"]
  n.mine 1 mineAddr
  let fundHeight ← n.height
  n.waitFilterIndex
  let (s1, _) ← syncUntil a 60_000 fun s _ => s.balance == 100_000_000
  check "balance after funding" (s1.balance == 100_000_000 && s1.utxoCount == 1) s!"{s1.balance} sat, {s1.utxoCount} coin(s), error {s1.lastSyncError}"
  let fundRow := history? s1 fundTxid
  check "history has the funding payment, confirmed" (match fundRow with
    | some h => h.height == fundHeight && h.received == 100_000_000 && h.spent == 0
    | none => false) s!"{fundRow.map (·.height)}"
  check "history row carries its decoded outputs" (match fundRow.bind (·.outputs) with
    | some outs => outs.any fun o => o.address == some addr && o.amount == 100_000_000 && o.ownedByWallet
    | none => false)
  let fresh ← a.receiveAddress true
  check "a fresh receive address moves past a used one" (fresh != addr && fresh.startsWith "bcrt1p")
  -- 4. Fee rate and preview.
  let rate ← a.resolveFeeRate 1 none
  check "resolveFeeRate: the medium preset (no observed rates), above the floor" (rate == 5000) s!"{rate} milli-sat/vB"
  let dest ← n.wallet #["getnewaddress"]
  let amount : Nat := 25_000_000
  let inputs : SendInputs := { destination := dest, amount := toString amount, network := .regtest }
  let p ← a.previewSend inputs
  check "previewSend: amount, fee, one input, change" (p.amount == amount && p.fee > 0 && p.inputCount == 1 &&
    p.change == some (100_000_000 - amount - p.fee) && p.feeRateMilli == 5000) s!"fee {p.fee}, change {p.change}"
  check "previewSend: synced, so the locktime does not lag" (!p.locktimeLagsTip)
  -- A summary the review never produced is refused.
  let forged ← attempt (a.sendPayment inputs { p with fee := p.fee + 1 })
  check "sendPayment refuses a summary that was not reviewed" (match forged with
    | .error e => e == "The available coins, fee, or change changed. Review the payment again before signing." | _ => false)
  -- 5. Send.
  let txid ← a.sendPayment inputs p
  let inMempool ← waitUntil 20_000 (do return (← n.mempool).contains txid)
  check "sendPayment: the node's mempool holds the txid" inMempool txid
  let raw ← a.rawTransactionHex txid
  check "rawTransactionHex while pending" raw.isSome
  let (s2, _) ← a.snapshot
  check "pending send in history at height 0" (match history? s2 txid with
    | some h => h.height == 0 && h.fee == some p.fee | none => false)
  n.mine 1 mineAddr
  let sendHeight ← n.height
  n.waitFilterIndex
  let expected : Int := 100_000_000 - amount - p.fee
  let (s3, _) ← syncUntil a 60_000 fun s _ => (history? s txid).any (·.height > 0)
  check "send confirmed in history" ((history? s3 txid).any (·.height == sendHeight)) s!"{(history? s3 txid).map (·.height)}"
  check "balance = previous − amount − fee" (s3.balance == expected) s!"{s3.balance} vs {expected}"
  check "relay entry gone once confirmed" ((← a.rawTransactionHex txid).isNone)
  -- 6. Fee bump an unconfirmed send.
  let dest2 ← n.wallet #["getnewaddress"]
  let inputs2 : SendInputs := { destination := dest2, amount := "10000000", network := .regtest }
  let p2 ← a.previewSend inputs2
  let txid2 ← a.sendPayment inputs2 p2
  discard <| waitUntil 20_000 (do return (← n.mempool).contains txid2)
  let (s4, _) ← a.snapshot
  check "the unconfirmed send is fee-bumpable" (s4.feeBumpable.contains txid2)
  let (current, _) ← a.pendingFeeRate txid2
  check "pendingFeeRate of the send" (current ≥ 4900 && current ≤ 5100) s!"{current}"
  let bp ← a.previewFeeBump txid2 (current + 5000)
  check "previewFeeBump: a higher rate and fee" (bp.fee > p2.fee && bp.feeRateMilli > current) s!"fee {bp.fee}, rate {bp.feeRateMilli}"
  let replacement ← match ← attempt (a.bumpFee txid2 bp) with
    | .ok r => pure r
    | .error e => check "bumpFee" false e; pure ""
  let replaced ← waitUntil 20_000 (do
    let mp ← n.mempool
    return mp.contains replacement && !mp.contains txid2)
  check "bumpFee: the node accepted the replacement and dropped the original" (replacement != "" && replaced) replacement
  let relayed ← IO.mkRef (#[] : Array String)
  a.watchRelay replacement fun e => relayed.modify (·.push (match e with
    | .announced k => s!"announced {k}" | .requested p => s!"requested {p}" | .echoed p => s!"echoed {p}"
    | .feeFloorExceeded => "feeFloorExceeded" | .confirmed => "confirmed"))
  let (s5, _) ← a.snapshot
  check "history marks the original replaced" ((history? s5 txid2).any (·.replacedBy == some replacement))
  n.mine 1 mineAddr
  n.waitFilterIndex
  let expected2 : Int := expected - 10_000_000 - bp.fee
  let (s6, _) ← syncUntil a 60_000 fun s _ => (history? s replacement).any (·.height > 0)
  check "replacement confirmed; balance = previous − amount − replacement fee" (s6.balance == expected2 &&
    (history? s6 replacement).any (·.height > 0)) s!"{s6.balance} vs {expected2}"
  let confirmedEvent ← waitUntil 10_000 (do return (← relayed.get).contains "confirmed")
  check "watchRelay reports the confirmation" confirmedEvent s!"{← relayed.get}"
  -- 7. The receive window sees a relayed payment.
  let watched ← a.receiveAddress false
  let seen ← IO.mkRef (#[] : Array (String × Int))
  -- a window on an earlier address first: the second call replaces it
  a.watchAddress addr fun t amt => seen.modify (·.push (t, amt))
  a.watchAddress watched fun t amt => seen.modify (·.push (t, amt))
  let incoming ← n.wallet #["sendtoaddress", watched, "0.001"]
  let sawIt ← waitUntil 45_000 (do return (← seen.get).any (·.1 == incoming))
  check "watchAddress: the mempool window reports the payment" sawIt
  a.stopWatchingAddress
  n.mine 1 mineAddr
  n.waitFilterIndex
  let expected3 := expected2 + 100_000
  let (s7, _) ← syncUntil a 60_000 fun s _ => s.balance == expected3
  check "the watched payment confirms" (s7.balance == expected3) s!"{s7.balance}"
  -- 7b. Shared savings with a second phone's key: funded from the wallet, credited by the sync loop.
  let keysBob ← IO.mkRef ({} : Keys.InMemorySecrets)
  let bob ← match ← (Wallet.create .regtest (inMemoryKeyStore keysBob)).run with
    | .ok w => pure w
    | .error e => throw (IO.userError s!"Wallet.create: {e.name}")
  let cardBob ← RecordsReal.RM.toIO (do return (← RecordsReal.ownPersonCard bob "Bob").serialized)
  let r0 ← a.records
  check "records: none yet, own signer known" (r0.people.isEmpty && r0.vaults.isEmpty && r0.ownSignerFingerprint.isSome)
  let r1 ← a.addPerson "Bob" (some cardBob) true (some .supplied) none none
  let some bobID := (r1.people.find? (·.name == "Bob")).map (·.id) | check "addPerson Bob" false; return
  let (vaultID, r2) ← a.createSharedSavings "Joint" [bobID] 2
  let some vault := r2.vaults.find? (·.id == vaultID) | check "createSharedSavings" false; return
  check "createSharedSavings: 2 of 2, script path, a receive address"
    (vault.threshold == 2 && vault.signerCount == 2 && vault.isScriptPath && (vault.receiveAddress.any (·.startsWith "bcrt1p")))
    (reprStr vault)
  let some vaultAddr := vault.receiveAddress | return
  let toVault : SendInputs := { destination := vaultAddr, amount := "200000", network := .regtest }
  let pv ← a.previewSend toVault
  let fundTxid ← a.sendPayment toVault pv
  check "the payment into the vault reaches the node's mempool" (← waitUntil 20_000 (do return (← n.mempool).contains fundTxid))
  n.mine 1 mineAddr
  n.waitFilterIndex
  let vaultBalance : IO Nat := do return ((← a.records).vaults.find? (·.id == vaultID)).map (·.balance) |>.getD 0
  let (s7v, _) ← syncUntil a 60_000 fun s _ => (history? s fundTxid).any (·.height > 0)
  let credited ← waitUntil 30_000 (do return (← vaultBalance) == 200_000)
  check "the sync loop credits the vault (vault watch scripts + apply)" credited s!"{← vaultBalance}"
  let fundRow := history? s7v fundTxid
  let recs ← a.records
  check "the wallet's payment into the vault is marked vault-owned, not a payment to someone"
    ((fundRow.bind (·.outputs)).any (·.any fun o => o.ownedByVault && o.amount == 200_000) &&
     (fundRow.map fun h => (paymentRecipients recs h).isEmpty) == some true)
  -- A vault payment is reviewed, then prepared for approval only as reviewed.
  let fromVault : SendInputs := { destination := ← n.wallet #["getnewaddress"], amount := "50000", network := .regtest,
                                  accountID := some vaultID }
  let vp ← a.previewSend fromVault
  check "previewSend from the vault: a vault source, amount, change"
    (vp.amount == 50_000 && vp.change == some (200_000 - 50_000 - vp.fee) &&
     (match vp.source with | .vault id _ _ sp th k => id == vaultID && sp && th == 2 && k == 2 | _ => false))
  let forgedVault ← attempt (a.prepareVaultApproval fromVault { vp with amount := vp.amount + 1 })
  check "prepareVaultApproval refuses a summary that was not reviewed" (forgedVault matches .error _)
  let prepared ← attempt (a.prepareVaultApproval fromVault vp)
  check "prepareVaultApproval accepts the reviewed vault spend" (prepared matches .ok _)
  let s7 := s7v
  -- 8. Export, and import into a fresh directory.
  let bundle ← a.exportBundle false
  check "exportBundle (watch-only)" ((bundle.splitOn "\"regtest\"").length > 1 && (bundle.splitOn "mnemonic").length == 1)
  check "exportBundle carries the vault" ((bundle.splitOn vaultID).length > 1)
  let keysB ← IO.mkRef ({} : Keys.InMemorySecrets)
  let (bImp, envB) ← Backend.realWithEnv (deps keysB "B")
  let dirB := s!"{dir}/B/BTCSwift/regtest"
  IO.FS.createDirAll dirB
  discard <| bImp.openWallet .regtest dirB
  bImp.startNetworking settings
  let report ← bImp.importBundle .regtest dirB bundle
  say s!"  import report: {report.replace "\n" " | "}"
  let (sb, _) ← bImp.snapshot
  check "importBundle reproduces the balance" (sb.balance == s7.balance && sb.utxoCount == s7.utxoCount)
    s!"{sb.balance} vs {s7.balance}"
  check "import report: scanned and confirmed every claim" (report.startsWith "Scanned from block" &&
    (report.splitOn "Claimed but spent since: 0").length > 1)
  let rb ← bImp.records
  check "importBundle restores the vault and its coins" (((rb.vaults.find? (·.id == vaultID)).map (·.balance)) == some 200_000)
    (reprStr (rb.vaults.map fun v => (v.id, v.balance)))
  bImp.stopNetworking
  -- 9. Stop networking: nothing keeps running.
  a.stopNetworking
  let quiet ← waitUntil 5_000 (do
    return (← envA.diagnostics).liveLoops == 0 && (← envB.diagnostics).liveLoops == 0)
  check "stopNetworking: no loop thread left" quiet s!"{repr (← envA.diagnostics)}"
  let (sStop, pStop) ← a.snapshot
  check "after stop: no stack, idle, no peers" (pStop == .idle && sStop.peerCount == 0 && !(← envA.diagnostics).hasStack)
  let gone ← waitUntil 5_000 (do return (← n.winnowPeers) == 0)
  check "after stop: the node has no Winnow peer" gone
  let headersBefore ← IO.FS.readBinFile (System.FilePath.mk dirA / "headers.bin")
  let filtersBefore ← IO.FS.readBinFile (System.FilePath.mk dirA / "filters.json")
  let walletBefore ← IO.FS.readBinFile (System.FilePath.mk dirA / "wallet.json")
  let d0 ← envA.diagnostics
  n.mine 2 mineAddr
  IO.sleep 6_000
  let d1 ← envA.diagnostics
  check "after stop: no sync pass and no phase tick while blocks arrive"
    (d1.syncPasses == d0.syncPasses && d1.phaseTicks == d0.phaseTicks && !d1.syncing) s!"{repr d0} → {repr d1}"
  check "after stop: still no Winnow peer (no reconnect)" ((← n.winnowPeers) == 0)
  check "after stop: headers.bin, filters.json, wallet.json unchanged"
    (headersBefore == (← IO.FS.readBinFile (System.FilePath.mk dirA / "headers.bin")) &&
     filtersBefore == (← IO.FS.readBinFile (System.FilePath.mk dirA / "filters.json")) &&
     walletBefore == (← IO.FS.readBinFile (System.FilePath.mk dirA / "wallet.json")))
  let late ← attempt a.syncNow
  let d2 ← envA.diagnostics
  check "after stop: syncNow without a stack does nothing" (late matches .ok _ && d2.syncPasses == d1.syncPasses)
  -- 10. Open the wallet again from disk (a new backend, the same key store).
  let (c, envC) ← Backend.realWithEnv (deps keysA "C")
  let reopened ← c.openWallet .regtest dirA
  let (sc, _) ← c.snapshot
  check "openWallet from disk: same wallet, same balance and history" (match reopened with
    | .opened _ => sc.balance == s7.balance && sc.history.length == s7.history.length | _ => false) s!"{sc.balance}"
  let words2 ← c.revealMnemonic
  check "revealMnemonic reads the same words back" (words2 == words)
  c.deleteWallet
  -- AppModel deletes the wallet's key only; the records' store keys stay (as in the Keychain)
  check "deleteWallet removes the wallet key and wallet.json" ((← keysA.get).keys.all (·.startsWith "store-key.") &&
    !(← (System.FilePath.mk dirA / "wallet.json").pathExists))
  let afterDelete ← c.openWallet .regtest dirA
  check "after deleteWallet the directory opens as missing" (afterDelete matches .missing)
  check "no loop thread in the reopened backend" ((← envC.diagnostics).liveLoops == 0)
  -- 11. The journal: the events AppModel writes, with its field names and value formats.
  let walletID := match pendingBoot with | .backupPending id => id | _ => ""
  checkJournal "wallet.created" ["walletID", "height", "headersContinueInBackground"]
    (fun f => field f "walletID" == walletID && (field f "height").toNat?.isSome && field f "headersContinueInBackground" == "true")
  checkJournal "backup.completed" ["walletID"] (field · "walletID" == walletID)
  checkJournal "wallet.ready" ["walletID", "balance", "utxoCount", "historyCount", "nextScanHeight"]
    (fun f => field f "walletID" == walletID && field f "balance" == "0")
  let receives ← journaled "address.receive"
  checkJournal "address.receive" ["address"] (field · "address" == addr)
  check "journal: address.receive once per current-address peek, never for New address" (receives.size == 3) s!"{receives.size}"
  checkJournal "transaction.broadcast" ["txid", "raw"] (fun f => field f "txid" == txid && rawIsTxid (field f "raw") txid)
  check "journal: every transaction.broadcast raw decodes to its txid"
    ((← journaled "transaction.broadcast").all fun (_, f) => rawIsTxid (field f "raw") (field f "txid"))
  checkJournal "transaction.sent" ["txid", "raw"] (fun f => field f "txid" == txid && rawIsTxid (field f "raw") txid)
    "its raw decodes to the sent txid"
  checkJournal "transaction.replaced" ["original", "replacement", "raw"]
    (fun f => field f "original" == txid2 && field f "replacement" == replacement && rawIsTxid (field f "raw") replacement)
  checkJournal "vault.created" ["name", "descriptor", "height"] (fun f => field f "name" == "Joint" && field f "descriptor" == vault.descriptor)
  checkJournal "savings.created" ["name", "descriptor", "coOwners"] (fun f => field f "name" == "Joint" && field f "coOwners" == "Bob")
  checkJournal "person.added" ["name", "payToKind", "hasSignerKey"]
    (fun f => field f "name" == "Bob" && field f "payToKind" == "descriptor" && field f "hasSignerKey" == "true")
  checkJournal "psbt.generated" ["stage", "base64", "inputCount", "outputCount"]
    (fun f => field f "stage" == "vault-spend-created" && field f "inputCount" == "1" && field f "outputCount" == "2")
  checkJournal "approval.requested" ["base64", "vaultID"] (field · "vaultID" == vaultID)
  checkJournal "wallet.exported" ["bundleVersion", "seedBearing", "lastKnownHeight", "utxoCount", "historyCount"]
    (fun f => field f "seedBearing" == "false" && field f "bundleVersion" == "2")
  checkJournal "import.started" ["bundleVersion", "seedBearing", "lastKnownHeight", "utxoCount", "historyCount"]
    (fun f => field f "seedBearing" == "false")
  checkJournal "import.verified" ["scannedFromHeight", "scannedToHeight", "matchesBundle", "confirmedUTXOCount",
      "spentSinceBundleCount", "discoveredUTXOCount", "balance", "utxoCount", "historyCount", "nextScanHeight"]
    (fun f => field f "matchesBundle" == "true" && field f "balance" == toString s7.balance && field f "spentSinceBundleCount" == "0")
  check "journal: import events come from the importing backend"
    ((← journaled "import.started").all (·.1 == "B") && (← journaled "import.verified").all (·.1 == "B"))
  check "journal: no import.verificationWaiting (the import verified)" (← journaled "import.verificationWaiting").isEmpty
  checkJournal "wallet.destroyed" ["walletID"] (field · "walletID" == walletID)
  checkJournal "peers.status" ["connected", "target", "dialing", "exhausted", "peers", "rejected"]
    (fun f => field f "connected" == "1" && field f "dialing" ∈ ["true", "false"] && (field f "peers").startsWith "127.0.0.1:")
  checkJournal "wallet.snapshot" ["walletID", "balance", "utxoCount", "historyCount", "nextScanHeight", "tipHeight",
      "peerCount", "confirmedTransactions", "pendingTransactions", "replacements", "vaults"]
    (fun f => field f "walletID" == walletID && ((field f "confirmedTransactions").splitOn s!"{txid}@{sendHeight}").length > 1 &&
       ((field f "replacements").splitOn s!"{txid2}>{replacement}").length > 1 &&
       ((field f "vaults").splitOn s!"{vaultID}:200000:1:1").length > 1)
  let deduped (name : String) : IO Bool := do
    let es ← journaled name
    return ["A", "B", "C"].all fun tag =>
      let fs := (es.filter (·.1 == tag)).map (·.2)
      (List.range (fs.size - 1)).all fun i => fs[i]! != fs[i + 1]!
  check "journal: peers.status and wallet.snapshot are journaled only when they change"
    ((← deduped "peers.status") && (← deduped "wallet.snapshot"))
  let phrase := " ".intercalate words
  check "journal: no field carries the recovery phrase"
    ((← journalEvents.get).all fun (_, _, f) => f.all fun (_, v) => (v.splitOn phrase).length == 1)

/-- `backend-test --fixture <dir>`: a regtest node left running (for driving the iOS app against it) and a
funded wallet's watch-only backup at `<dir>/bundle.json`; prints the node's pid and ports. -/
def fixture (dir : String) : IO UInt32 := do
  IO.FS.createDirAll dir
  let n ← startNode dir
  discard <| n.cli #["createwallet", "w"]
  let mineAddr ← n.wallet #["getnewaddress"]
  n.mine 101 mineAddr
  n.waitFilterIndex
  let keys ← IO.mkRef ({} : Keys.InMemorySecrets)
  let (a, _) ← Backend.realWithEnv (deps keys)
  let wdir := s!"{dir}/wallet/regtest"
  IO.FS.createDirAll wdir
  discard <| a.openWallet .regtest wdir
  a.startNetworking (regtestSettings n)
  discard <| a.createWallet .regtest wdir
  a.finishOnboarding
  let addr ← a.receiveAddress false
  discard <| n.wallet #["sendtoaddress", addr, "0.5"]
  n.mine 1 mineAddr
  n.waitFilterIndex
  let tip ← n.height
  let (s, _) ← syncUntil a 90_000 fun s _ => s.tipHeight == tip && s.balance > 0
  IO.FS.writeFile s!"{dir}/bundle.json" (← a.exportBundle false)
  -- with the recovery phrase: imported, it can spend (the UI test's normal-mode send)
  IO.FS.writeFile s!"{dir}/bundle-seed.json" (← a.exportBundle true)
  IO.FS.writeFile s!"{dir}/fixture.json"
    s!"\{\"p2p\": {n.p2p}, \"rpc\": {n.rpc}, \"pid\": {n.pid}, \"datadir\": \"{n.datadir}\"}"
  a.stopNetworking
  say s!"fixture: node pid {n.pid} p2p {n.p2p} rpc {n.rpc} datadir {n.datadir}; wallet balance {s.balance} at {tip}"
  return 0

def main (args : List String) : IO UInt32 := do
  if let ["--fixture", dir] := args then return ← fixture dir
  let tmp ← IO.FS.createTempDir
  let dir := tmp.toString
  say s!"backend-test: work dir {dir}"
  let node ← (startNode dir).toBaseIO
  let n ← match node with
    | .ok n => pure n
    | .error e => say s!"FAIL could not start bitcoind: {e}"; return 1
  spawn do
    IO.sleep 900_000
    say "FAIL watchdog: the test ran for 15 minutes"
    killPid n.pid "-KILL"
    IO.Process.exit 2
  try
    flow dir n
  catch e =>
    failures.modify (·.push s!"exception: {e}")
    say s!"  FAIL exception: {e}"
  finally
    discard <| (n.cli #["stop"]).toBaseIO
    discard <| waitUntil 10_000 (do
      let r ← IO.Process.output { cmd := "kill", args := #["-0", toString n.pid] }
      return r.exitCode != 0)
    killPid n.pid "-KILL"
    try IO.FS.removeDirAll tmp catch _ => pure ()
  let fs ← failures.get
  say s!"backend-test: {← passes.get} passed, {fs.size} failed{if fs.isEmpty then "" else ": " ++ ", ".intercalate fs.toList}"
  IO.Process.exit (if fs.isEmpty then 0 else 1)
