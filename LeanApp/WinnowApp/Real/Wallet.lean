import WinnowApp.Real.Stack

/-! # The wallet's lifecycle and the UI snapshot

AppModel.swift: `boot` / `openPersistedWallet` (:470, :535), `switchNetwork` (:2507: here, opening
another network's directory), `refresh` (:1033), `creationHeightForNewWallet` (:1095), `createWallet`
(:1115), `importWallet` (:1148), `exportWalletBundle` (:1215), `adopt` (:1247), `finishOnboarding`
(:1319), `revealMnemonic` (:1366), `destroyWallet` (:1393), `waitForPeer` (:1445),
`currentReceiveAddress` / `freshReceiveAddress` (:1459, :1468). -/

namespace WinnowApp.Real
open Winnow Winnow.IO Winnow.Net

/-- The network's directory becomes current; another network or directory first ends the old one
(`switchNetwork`: stop, drop the wallet, nothing carried over). -/
def switchTo (env : Env) (n : WinnowApp.Network) (dir : String) : IO Unit := do
  let c ← env.get
  if c.network == some n && c.dir == some dir then return
  suspendAndStop env false
  env.modify fun c => { c with network := some n, dir := some dir, wallet := none, reviews := #[], bumps := #[],
                               lastSyncError := none, relayStoreQuarantined := none, phase := .idle }

def damagedWalletText : String :=
  "Winnow found local wallet data but could not safely read it. The files and protected key were left untouched. Retry; if this continues, restore from a known-good wallet bundle or ask for help before changing anything."

/-- `DefaultsKey.backupPending(walletID)`, kept as a file next to the wallet: present from creation
until the user confirms the words are written down (`finishOnboarding`). -/
def backupPendingPath (dir walletID : String) : System.FilePath := dirFile dir s!"backup-pending.{walletID}"

/-- `.opened`, or `.backupPending` while the created wallet's backup was never confirmed. -/
def bootResult (dir walletID : String) : IO BootResult := do
  return if ← (backupPendingPath dir walletID).pathExists then .backupPending walletID else .opened walletID

/-- A `String` as Swift's `debugDescription` quotes it (inside `String(describing:)` of an enum payload). -/
def swiftQuoted (s : String) : String :=
  "\"" ++ String.join (s.toList.map fun c => match c with
    | '"' => "\\\"" | '\\' => "\\\\" | '\n' => "\\n" | '\r' => "\\r" | '\t' => "\\t" | '\x00' => "\\0"
    | c => if c.toNat < 0x20 || c.toNat == 0x7F then s!"\\u\{{String.mk (Nat.toDigits 16 c.toNat)}}" else c.toString) ++ "\""

/-- `String(describing: error)` of a `KeyStoreError`, as the journal records it. -/
def keyStoreErrorDescribing : Keys.KeyStoreError → String
  | .notFound w => s!"notFound(walletID: {swiftQuoted w})"
  | .alreadyExists w => s!"alreadyExists(walletID: {swiftQuoted w})"
  | .malformedSecret => "malformedSecret"
  | .keychain status => s!"keychain({status})"

/-- `boot()` / `openPersistedWallet(at:)` for `dir`. -/
def openWallet (env : Env) (n : WinnowApp.Network) (dir : String) : IO BootResult := do
  switchTo env n dir
  if let some message ← env.hooks.configure n dir then return .damaged message
  if let some w := (← env.get).wallet then return ← bootResult dir w.id
  let path := walletPath dir
  if !(← path.pathExists) then return .missing
  match ← (Wallet.open path env.deps.keyStore env.deps.random).run with
  | .error _ => return .damaged damagedWalletText
  | .ok w =>
    let installed ← env.modifyGet fun c =>
      if c.dir == some dir && c.wallet.isNone then (true, { c with wallet := some w }) else (false, c)
    if !installed then
      if let some w' := (← env.get).wallet then return ← bootResult dir w'.id
    -- `upgradeKeyProtection`: best effort, attributes only
    match ← (env.deps.keyStore.upgradeProtection w.id).run with
    | .ok true => env.journal "keychain.protectionUpgraded" [("walletID", w.id)]
    | .ok false => pure ()
    | .error e => env.journal "keychain.protectionUpgradeFailed" [("walletID", w.id), ("error", keyStoreErrorDescribing e)]
    return ← bootResult dir w.id

/-! ## The snapshot -/

/-- One history row with its transaction decoded (what the payment screens read). -/
def historyItem (e : HistoryEntry) (owned vaults : Std.HashSet ByteArray) (net : Tx.BitcoinNetwork) : HistoryItem :=
  let outputs : Option (List TxOut) := match e.transaction with
    | .ok (some tx) => some ((List.range tx.outputs.size).zip tx.outputs.toList |>.map fun (i, o) =>
        { index := i, address := AddressDecoder.address o.scriptPubKey net, script := hex o.scriptPubKey,
          amount := natOf o.value, ownedByWallet := owned.contains o.scriptPubKey,
          ownedByVault := vaults.contains o.scriptPubKey })
    | _ => none
  { txid := Winnow.displayHex e.txid, height := e.height.toNat, received := e.received.toInt, spent := e.spent.toInt,
    fee := e.fee.map (·.toInt), replacedBy := e.replacedBy.map Winnow.displayHex, outputs,
    fundingAddresses := e.fundingScripts.toList.filterMap (AddressDecoder.address · net) }

/-- `feeFilterFloorSatPerVByte()` in thousandths: the strictest BIP133 filter (sat/kvB). -/
def feeFloorMilli (pool : PeerPool) : IO (Option Nat) := do
  let mut floors : Array Int64 := #[]
  for peer in ← pool.connectedPeers do
    if let some f ← peer.feeFilter then floors := floors.push f
  return floors.foldl (fun acc f => some (max (acc.getD 0) (natOf f))) none

/-- `journalSnapshotIfChanged()`: public facts only (txids, heights, counts, vault coin summaries),
journaled when they changed. `status.history` is the display order (`historyForDisplay`). -/
def journalSnapshotIfChanged (env : Env) (s : Status) : IO Unit := do
  let some w := (← env.get).wallet | return
  let history := historyForDisplay s.history
  let confirmed := (history.filter (·.height > 0)).map fun e => s!"{e.txid}@{e.height}"
  let pending := (history.filter fun e => e.height == 0 && e.replacedBy.isNone).map (·.txid)
  let replacements := history.filterMap fun e => e.replacedBy.map fun r => s!"{e.txid}>{r}"
  let vaults := (← env.hooks.vaultSummaries).toList.map fun (id, balance, coins, confirmedCoins) =>
    s!"{id}:{balance}:{coins}:{confirmedCoins}"
  env.journalIfChanged "wallet.snapshot"
    [("walletID", w.id), ("balance", toString s.balance), ("utxoCount", toString s.utxoCount),
     ("historyCount", toString s.history.length), ("nextScanHeight", toString s.nextScanHeight),
     ("tipHeight", toString s.tipHeight), ("peerCount", toString s.peerCount),
     ("confirmedTransactions", ",".intercalate confirmed), ("pendingTransactions", ",".intercalate pending),
     ("replacements", ",".intercalate replacements), ("vaults", ",".intercalate vaults)]
    (·.lastSnapshotFingerprint) fun c fp => { c with lastSnapshotFingerprint := fp }

/-- `refresh()`'s `Status`, with the phase as the ticker last stored it (re-read now). -/
def snapshot (env : Env) : IO (Status × SyncPhase) := do
  let phase ← updateSyncPhase env
  let c ← env.get
  let mut s : Status := {}
  if let some w := c.wallet then
    let st ← w.state
    let owned : Std.HashSet ByteArray := ((← (w.watchScripts).run).toOption.getD #[]).foldl (·.insert ·) {}
    let vaults : Std.HashSet ByteArray := (← env.hooks.ownedVaultScripts).foldl (·.insert ·) {}
    let utxos := st.utxos
    s := { s with balance := (utxos.foldl (fun (a : Int64) (u : WalletUTXO) => a + u.amount) 0).toInt, utxoCount := utxos.size
                  history := st.history.toList.map (historyItem · owned vaults w.network)
                  feeBumpable := (← w.feeBumpableTxids).toList.map Winnow.displayHex
                  nextScanHeight := st.nextScanHeight.toNat }
  if let some stack := c.stack then
    s := { s with peerCount := (← stack.pool.connectedPeers).size, tipHeight := (← stack.chain.height).toNat
                  feeFloorMilli := ← feeFloorMilli stack.pool }
    if let some f := stack.filters then s := { s with nextScanHeight := (← f.nextScanHeight).toNat }
  s := { s with syncing := c.syncing, lastSyncError := c.lastSyncError, relayStoreQuarantined := c.relayStoreQuarantined }
  journalSnapshotIfChanged env s
  return (s, phase)

/-! ## Creating, adopting, importing -/

/-- `creationHeightForNewWallet()`: the best advertised tip less 500, never below the local tip. -/
def creationHeightForNewWallet (s : Stack) : IO UInt32 := do
  let localTip ← s.chain.height
  let mut advertised : UInt32 := 0
  for peer in ← s.pool.connectedPeers do
    let h ← peer.peerStartHeight
    if h > 0 && h.toInt.toNat.toUInt32 > advertised then advertised := h.toInt.toNat.toUInt32
  let margin : UInt32 := 500
  let peerBirthday := if advertised > margin then advertised - margin else 0
  return max localTip peerBirthday

/-- `adopt(wallet:startSync:)`: the previous wallet's chain-facing files go; an existing stack gets
new filters and a new broadcaster (or is rebuilt from genesis when the wallet is older than it). -/
def adopt (env : Env) (w : Wallet) (startSync : Bool) : IO Unit := do
  let (stack, dir, n) ← env.modifyGet fun c =>
    ((c.stack, c.dir, c.network), { c with loopToken := c.loopToken + 1, syncLoop := none })
  let some dir := dir | failWith .noWallet
  if let some s := stack then s.broadcaster.shutdown
  for name in ["filters.json", "broadcast.json", "vaults.json", "receive-labels.json"] do
    removeQuietly (dirFile dir name)
  if let some n := n then
    if let some message ← env.hooks.configure n dir then failWith (.storageDamaged message)
  env.modify fun c => { c with wallet := some w, stack := none, reviews := #[], bumps := #[] }
  if let some existing := stack then
    if (← existing.chain.startHeight) > (← w.nextScanHeight) then
      -- the windows watch the pool that stops here
      let windows ← env.modifyGet fun c =>
        (c.receiveWindow.toList ++ c.relayWindows.toList.map (·.2), { c with receiveWindow := none, relayWindows := #[] })
      for win in windows do win.close
      existing.pool.stop
      buildStackIfNeeded env
    else
      let filters ← runNet (FilterSyncIO.new existing.pool existing.chain (← w.nextScanHeight) (some (dirFile dir "filters.json")))
      let broadcaster ← runNet (TxBroadcaster.new existing.pool (some (dirFile dir "broadcast.json")))
      let gen ← env.modifyGet fun c => (c.generation, { c with stack := some { existing with filters := some filters, broadcaster } })
      observeBroadcasterFailures env broadcaster gen
  if startSync then startSyncLoop env

def readMnemonic (env : Env) (walletID : String) : IO (Option String) := do
  match ← (env.deps.keyStore.load walletID).run with
  | .ok (.mnemonic words) => return some words
  | .ok (.masterKey _) => return none
  | .error e => failText (keyStoreErrorText e)

/-- `createWallet()`: a fresh wallet dated at the chain tip, adopted; its recovery words. -/
def createWallet (env : Env) (n : WinnowApp.Network) (dir : String) : IO (List String) := do
  switchTo env n dir
  buildStackIfNeeded env
  let some stack := (← env.get).stack | failWith .noStack
  let knownHeight ← creationHeightForNewWallet stack
  let w ← runWM (Wallet.create (Network.tx n) env.deps.keyStore (some (walletPath dir)) (entropy := env.deps.entropy) (creationHeight := knownHeight)
    (random := env.deps.random))
  -- flagged before `adopt`: the secret is already stored, so a throw below must not leave the wallet
  -- looking backed up (a stale flag only shows the words again)
  IO.FS.writeFile (backupPendingPath dir w.id) ""
  adopt env w true
  let some words ← readMnemonic env w.id | failWith .mnemonicUnavailable
  env.journal "wallet.created" [("walletID", w.id), ("height", toString knownHeight), ("headersContinueInBackground", "true")]
  return words.splitOn " "

/-- `finishOnboarding()`: the backup is confirmed (or the import report read). -/
def finishOnboarding (env : Env) : IO Unit := do
  let c ← env.get
  if let (some dir, some w) := (c.dir, c.wallet) then
    let p := backupPendingPath dir w.id
    let wasBackupPending ← p.pathExists
    if wasBackupPending then IO.FS.removeFile p
    env.journal (if wasBackupPending then "backup.completed" else "import.onboardingCompleted") [("walletID", w.id)]
    let (s, _) ← snapshot env
    env.journal "wallet.ready" [("walletID", w.id), ("balance", toString s.balance), ("utxoCount", toString s.utxoCount),
      ("historyCount", toString s.history.length), ("nextScanHeight", toString s.nextScanHeight)]

/-- `pendingBackupMnemonic()` (the caller has authenticated): the words while the backup is pending. -/
def pendingBackupWords (env : Env) : IO (List String) := do
  let c ← env.get
  let (some dir, some w) := (c.dir, c.wallet) | failWith .noWallet
  if !(← (backupPendingPath dir w.id).pathExists) then failWith .mnemonicUnavailable
  let some words ← readMnemonic env w.id | failWith .mnemonicUnavailable
  return words.splitOn " "

/-- `waitForPeer(timeout:)`, polling once a second. -/
def waitForPeer (env : Env) (pool : PeerPool) (ms : Nat) (gen : Nat) : IO Bool := do
  let deadline := (← IO.monoMsNow) + ms
  while (← IO.monoMsNow) < deadline do
    if (← env.get).generation != gen then return false
    if (← pool.randomPeer).isSome then return true
    IO.sleep 1000
  return false

/-- The verification report as OnboardingView lays it out. -/
def reportText (r : ImportReport) : String :=
  let lines := [s!"Scanned from block {r.scannedFromHeight}"] ++
    (match r.scannedToHeight with | some h => [s!"Scanned to block {h}"] | none => []) ++
    [s!"Claimed UTXOs confirmed: {r.confirmedUTXOs.size}", s!"Claimed but spent since: {r.spentSinceBundle.size}",
     s!"Discovered since bundle: {r.discoveredUTXOs.size}"] ++
    (if r.matchesBundle then [] else
      ["Some claimed UTXOs were already spent — the bundle was stale or wrong. The chain won; check the report above."])
  "\n".intercalate lines

/-- What the app shows when `importWallet` returns no report (no peer yet). -/
def verificationWaitingText : String :=
  "Imported. Verification is waiting for Bitcoin peers; the regular sync checks the same blocks once Winnow connects."

/-- A `ScanSource` over the stack's filter sync (`verifyImport(_:using:)`). -/
def scanSource (f : FilterSyncIO) : ScanSource where
  nextScanHeight := f.nextScanHeight
  lastScannedHeight := f.lastScannedHeight
  sync scripts cb := NetM.toWM (f.sync scripts (onMatch := fun m => WM.toNet (cb m)))

/-- What `import.started` and `wallet.exported` say of a bundle (never its phrase). -/
def bundleFields (b : ImportBundle) : List (String × String) :=
  [("bundleVersion", toString b.version), ("seedBearing", toString b.mnemonic.isSome),
   ("lastKnownHeight", toString b.lastKnownHeight), ("utxoCount", toString b.utxos.size),
   ("historyCount", toString b.transactions.size)]

/-- `importWallet(bundleJSON:)`: decode, check, seed the wallet, adopt it without the loop, then verify
by a forward scan (the loop starts on the way out). -/
def importBundle (env : Env) (n : WinnowApp.Network) (dir : String) (json : String) : IO String := do
  let bundle ← match ImportBundle.decode json with
    | .ok b => pure b
    | .error e => failText (importFailureText e)
  env.hooks.validateBundleVaults (bundle.vaults.getD #[]) n
  unless bundle.network == n.name do failWith (.wrongNetwork bundle.network)
  env.journal "import.started" (bundleFields bundle)
  switchTo env n dir
  let w ← runWM (Wallet.importing bundle env.deps.keyStore (some (walletPath dir)) env.deps.random)
  adopt env w false
  env.hooks.restoreVaults (bundle.vaults.getD #[])
  try
    buildStackIfNeeded env
    let c ← env.get
    let waiting (reason : String) : IO String := do
      env.journal "import.verificationWaiting" [("reason", reason)]
      return verificationWaitingText
    let some stack := c.stack | waiting "sync stack unavailable"
    let some filters := stack.filters | waiting "sync stack unavailable"
    stack.pool.start
    if !(← waitForPeer env stack.pool 60_000 c.generation) then return ← waiting "public peers unavailable"
    let report ← runWM (w.verifyImport bundle (scanSource filters) (← env.hooks.vaultWatchScripts)
      (onMatch := fun m => WM.io (env.hooks.vaultApply m)))
    -- `await refresh()`, then the journal reads the refreshed status
    let (s, _) ← snapshot env
    env.journal "import.verified"
      [("scannedFromHeight", toString report.scannedFromHeight),
       ("scannedToHeight", (report.scannedToHeight.map toString).getD "waiting"),
       ("matchesBundle", toString report.matchesBundle),
       ("confirmedUTXOCount", toString report.confirmedUTXOs.size),
       ("spentSinceBundleCount", toString report.spentSinceBundle.size),
       ("discoveredUTXOCount", toString report.discoveredUTXOs.size),
       ("balance", toString s.balance), ("utxoCount", toString s.utxoCount),
       ("historyCount", toString s.history.length), ("nextScanHeight", toString s.nextScanHeight)]
    return reportText report
  finally
    startSyncLoop env

/-- `exportWalletBundle(includeMnemonic:)`. -/
def exportBundle (env : Env) (includeMnemonic : Bool) : IO String := do
  let c ← env.get
  let some w := c.wallet | failWith .noWallet
  if let some f := c.stack.bind (·.filters) then env.walletOp (w.recordScanHeight (← f.nextScanHeight))
  let b ← runWM (w.exportBundle includeMnemonic)
  let b := { b with vaults := ← env.hooks.backupVaults }
  let serialized := b.serialized
  env.journal "wallet.exported" (bundleFields b)
  return serialized

/-- `revealMnemonic()` (after authentication in `perform`). -/
def revealMnemonic (env : Env) : IO (List String) := do
  let some w := (← env.get).wallet | failWith .noWallet
  let some words ← readMnemonic env w.id | failText WalletError.mnemonicUnavailable.description
  return words.splitOn " "

/-- `destroyWallet()`: networking down, the key first, then the per-wallet files (headers and peers stay). -/
def deleteWallet (env : Env) : IO Unit := do
  let c ← env.get
  let some w := c.wallet | failWith .noWallet
  suspendAndStop env false
  match ← (env.deps.keyStore.delete w.id).run with
  | .ok () => pure ()
  | .error e => failText (keyStoreErrorText e)
  if let some dir := c.dir then
    for name in ["wallet.json", "filters.json", "broadcast.json", "vaults.json", "receive-labels.json"] do
      removeQuietly (dirFile dir name)
  env.modify fun c => { c with wallet := none, lastSyncError := none, relayStoreQuarantined := none, phase := .idle,
                               reviews := #[], bumps := #[] }
  if let (some n, some dir) := (c.network, c.dir) then
    if let some message ← env.hooks.configure n dir then failWith (.storageDamaged message)
  env.journal "wallet.destroyed" [("walletID", w.id)]

/-! ## Receiving -/

/-- `currentReceiveAddress()` (peeked) or `freshReceiveAddress()` (marks it used, shows the next). -/
def receiveAddress (env : Env) (fresh : Bool) : IO String := do
  let some w := (← env.get).wallet | failWith .noWallet
  if fresh then discard <| env.walletOp w.freshReceiveAddress
  let address ← runWM (w.address .receive (← w.nextReceiveIndex))
  -- `currentReceiveAddress()` journals what it shows; `freshReceiveAddress()` does not
  unless fresh do env.journal "address.receive" [("address", address)]
  return address

end WinnowApp.Real
