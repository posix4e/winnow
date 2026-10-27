import ElmLean.Native
import WinnowApp.View
import WinnowApp.Update
import WinnowApp.Backend
import WinnowApp.Sample
import WinnowApp.Real
import WinnowApp.E2E

/-! The Winnow app in ElmLean native mode: the model and screens (Update, View and the area modules),
the commands run by `perform` against the `Backend` (the Lean wallet and network) and the shell's
capabilities (auth, clipboard, open). -/

namespace WinnowApp
open ElmLean ElmLean.Native Lean

/-- Where the app keeps its files: `<Application Support>/BTCSwift`, as the Swift app did. -/
initialize rootDir : IO.Ref String ← IO.mkRef ""
/-- The temporary directory (`paths.tmp`): backup files are staged there for the share sheet. -/
initialize tmpDir : IO.Ref String ← IO.mkRef ""
initialize backendRef : IO.Ref Backend ← IO.mkRef Backend.pending
/-- The running status watcher's token: starting or stopping networking bumps it, ending the old one. -/
initialize watcherToken : IO.Ref Nat ← IO.mkRef 0
/-- Test mode (`E2E.lean`), resolved at boot in a Debug build only. -/
initialize e2eRef : IO.Ref (Option E2E.Mode) ← IO.mkRef none
/-- `<Application Support>` itself: test mode's journal lives in its run directory there. -/
initialize supportDir : IO.Ref String ← IO.mkRef ""

/-- `e2e?.journal(_:fields:)`: nothing outside test mode. -/
def journal (name : String) (fields : List (String × String) := []) : IO Unit := do
  if let some m ← e2eRef.get then m.journal (← supportDir.get) name fields

/-- The launch-environment names test mode reads. -/
def e2eVariables : List String :=
  ["WINNOW_E2E", "WINNOW_E2E_ENTROPY", "WINNOW_E2E_MNEMONIC", "WINNOW_E2E_RUN", "WINNOW_E2E_PEER",
   "WINNOW_E2E_CHALLENGE", "WINNOW_E2E_RESET", "WINNOW_E2E_CLIPBOARD", "WINNOW_E2E_NETWORK", "WINNOW_E2E_TAB",
   "WINNOW_E2E_DEVICE_AUTH", "WINNOW_E2E_ADVANCED", "WINNOW_E2E_CONTROL_FILE", "WINNOW_E2E_PEER_COUNT",
   "WINNOW_E2E_SYNC_INTERVAL"]

/-- `E2EMode.current` in a Debug build: inactive, active, or — without pinned entropy — a stop, because a
capture run that generated a real seed would publish it. -/
def resolveE2E : IO (Option E2E.Mode) := do
  let mut env : List (String × String) := []
  for k in e2eVariables do
    if let some v ← IO.getEnv k then env := (k, v) :: env
  match E2E.resolve (fun k => env.lookup k) with
  | .inactive => return none
  | .active m => return some m
  | .missingPinnedEntropy =>
    IO.eprintln "WINNOW_E2E=1 without a readable WINNOW_E2E_ENTROPY or WINNOW_E2E_MNEMONIC. A capture run must never generate a real seed: its screenshots are published."
    IO.Process.exit 1

def settingsPath : IO System.FilePath := return System.FilePath.mk (← rootDir.get) / "settings.json"
def walletDir (n : Network) : IO String := return ((System.FilePath.mk (← rootDir.get)) / n.name).toString

def loadSettings : IO Settings := do
  let p ← settingsPath
  if !(← p.pathExists) then return {}
  match Json.parse (← IO.FS.readFile p) >>= fromJson? with
  | .ok s => pure s
  | .error _ => pure {}

/-- The settings and whether they name a network (test mode starts on signet when they do not). -/
def loadSettingsNoting : IO (Settings × Bool) := do
  let p ← settingsPath
  if !(← p.pathExists) then return ({}, false)
  match Json.parse (← IO.FS.readFile p) with
  | .ok j => return ((fromJson? j).toOption.getD {}, (j.getObjVal? "network").isOk)
  | .error _ => return ({}, false)

def trace (msg : String) : IO Unit := do
  if (← IO.getEnv "WINNOW_LEAN_TRACE") == some "1" then IO.eprintln s!"[trace] {msg}"

/-- Run `act` in a task and post its answer, or `failed gen ctx message`. -/
def background (fx : Effects Host) (gen : Nat) (ctx : String) (act : IO Host) : IO Unit :=
  discard <| IO.asTask do
    try fx.post (← act) catch e => do trace s!"failed {gen} {ctx}: {e}"; fx.post (.failed gen ctx (toString e))

/-- `authenticateSensitiveAction`: device-owner authentication before `act` (inside a task). A
cancelled prompt is a decision, not a failure: `ctx ++ ".cancelled"` clears the busy state quietly. -/
def authenticated (fx : Effects Host) (gen : Nat) (ctx reason : String) (act : IO Host) : IO Unit :=
  discard <| IO.asTask do
    -- automated Debug runs skip it unless they ask for it (`WINNOW_E2E_DEVICE_AUTH=1`)
    if let some m ← e2eRef.get then
      if !m.requireDeviceAuthentication then
        try fx.post (← act) catch e => fx.post (.failed gen ctx (toString e))
        return
    let auth ← IO.wait (← fx.ask "auth" (Json.mkObj [("reason", Json.str reason)]))
    if (auth.getObjValAs? Bool "ok").toOption.getD false then
      try fx.post (← act) catch e => fx.post (.failed gen ctx (toString e))
    else
      let err := (auth.getObjValAs? String "error").toOption.getD "Device authentication failed."
      let cancelled := (err.toLower.splitOn "cancel").length > 1
      fx.post (.failed gen (if cancelled then ctx ++ ".cancelled" else ctx) err)

def clipPolicyArgs (text : String) : ClipPolicy → Json
  -- the shell's `clipboard.set` takes `text`; the policy rides along for a shell that honours it
  | .recoveryPhrase => Json.mkObj [("text", Json.str text), ("localOnly", Json.bool true), ("expiresIn", toJson (120 : Nat))]
  | .interchange => Json.mkObj [("text", Json.str text), ("localOnly", Json.bool false), ("expiresIn", toJson (300 : Nat))]

/-- The backend, chosen once at boot: `Backend.real` over the shell's Keychain and `http.get`
capabilities. `WINNOW_LEAN_SAMPLE=1` (passed with `SIMCTL_CHILD_` by `simctl launch`) runs the screens
on sample data instead — a UI harness like Winnow's E2EMode. -/
def chooseBackend (fx : Effects Host) (mode : Option E2E.Mode := none) : IO Unit := do
  if (← IO.getEnv "WINNOW_LEAN_SAMPLE") == some "1" then backendRef.set Backend.sample
  else
    let service := (mode.map (·.keychainService)).getD Real.walletService
    let deps : Real.Deps := { keyStore := Real.shellKeyStore fx.ask service, fetch := Real.shellFetch fx.ask }
    let deps := match mode with
      | none => deps
      | some m =>
        { deps with
          peerCount := m.peerCount.getD deps.peerCount
          syncIntervalMs := (m.syncIntervalSeconds.map fun s => (s * 1000).toUInt64.toNat).getD deps.syncIntervalMs
          networkParams := m.networkParams
          entropy := m.entropy
          journal := fun n f => journal n f }
    backendRef.set (← Backend.real deps)

def perform (c : Cmd) (fx : Effects Host) : IO Unit := do
  let b ← backendRef.get
  match c with
  | .refresh g => trace s!"refresh {g}"
  | .syncNow g => trace s!"syncNow {g}"
  | .exportBundle g _ _ name => trace s!"exportBundle {g} {name}"
  | .removeExport file => trace s!"removeExport {file}"
  | .startNetworking g _ => trace s!"startNetworking {g}"
  | .stopNetworking => trace "stopNetworking"
  | .openWallet g _ _ => trace s!"openWallet {g}"
  | _ => pure ()
  let records (g : Nat) (d : Done) (r : IO Records) : IO Host := do return .updated g d (← r)
  match c with
  | .boot => discard <| IO.asTask do
      let build := (← IO.wait (← fx.ask "build" Json.null))
      let mode ← if (build.getObjValAs? Bool "debug").toOption.getD false then resolveE2E else pure none
      let paths := (← IO.wait (← fx.ask "paths" Json.null))
      let support := (paths.getObjValAs? String "support").toOption.getD "."
      supportDir.set support
      let root := System.FilePath.mk support / ((mode.map (·.storageDirectoryName)).getD "BTCSwift")
      if let some m := mode then
        -- `wipeIfRequested()`: this run's storage and its Keychain namespace
        if m.reset then
          try IO.FS.removeDirAll root catch _ => pure ()
          discard <| IO.wait (← fx.ask "keychain.clear" (Json.mkObj [("service", Json.str m.keychainService)]))
      e2eRef.set mode
      chooseBackend fx mode
      IO.FS.createDirAll root
      let _ ← fx.ask "exclude-from-backup" (Json.mkObj [("path", Json.str root.toString)])
      rootDir.set root.toString
      -- `ExportStagingFile.sweep()`: a crash with the export sheet open leaves a file that may hold the phrase
      let tmp := (paths.getObjValAs? String "tmp").toOption.getD ""
      tmpDir.set tmp
      unless tmp.isEmpty do Winnow.ExportStagingFile.sweep tmp
      let settings ← match mode with
        | none => loadSettings
        | some m => do
          let (s, hadNetwork) ← loadSettingsNoting
          -- the fixture is a signet (or a forced network); advanced mode and the local node as the only peer
          let network := m.forcedNetwork.getD (if hadNetwork then s.network else .signet)
          let s := { s with network, advancedMode := s.advancedMode || m.advancedMode }
          let s := match m.peer with
            | some p => if s.scoped.manualPeers.contains p then s else s.withScoped fun n => { n with manualPeers := [p] }
            | none => s
          IO.FS.writeFile (← settingsPath) (toJson s).pretty
          if let some text := m.clipboard then
            discard <| IO.wait (← fx.ask "clipboard.set" (Json.mkObj [("text", Json.str text)]))
          let tab := match m.initialTab with | some "send" => 1 | some "settings" => 2 | _ => 0
          fx.post (.launched m.forcedNetwork tab)
          journal "app.initialized" [("network", s.network.name)]
          pure s
      fx.post (.settingsLoaded settings)
  | .saveSettings s => discard <| IO.asTask do
      IO.FS.writeFile (← settingsPath) (toJson s).pretty
  | .openWallet g n isBoot => background fx g "open" do
      let dir ← walletDir n
      IO.FS.createDirAll dir
      let r ← b.openWallet n dir
      if isBoot then
        -- `boot()`: a resumed backup, then the stage it lands on (a damaged store journals nothing)
        match r with
        | .opened id => journal "app.booted" [("stage", "ready"), ("walletID", id)]
        | .backupPending id =>
          journal "backup.pendingResumed" [("walletID", id)]
          journal "app.booted" [("stage", "onboarding"), ("walletID", id)]
        | .missing => journal "app.booted" [("stage", "onboarding"), ("walletID", "")]
        | .damaged _ => pure ()
      return .booted g r
  | .createWallet g n => authenticated fx g "create" "Create and reveal a new wallet recovery phrase" do
      return .created g (← b.createWallet n (← walletDir n))
  | .resumeBackup g => authenticated fx g "create" "Resume this wallet's recovery-phrase backup" do
      return .created g (← b.pendingBackupWords)
  | .importWallet g n json =>
    let act : IO Host := do return .imported g (← b.importBundle n (← walletDir n) json)
    -- a bundle carrying recovery words is imported only after device authentication, as AppModel
    let seeded := match Json.parse json with
      | .ok j => match j.getObjVal? "mnemonic" with | .ok .null | .error _ => false | .ok _ => true
      | .error _ => false
    if seeded then authenticated fx g "import" "Import this wallet's recovery phrase" act
    else background fx g "import" act
  | .finishOnboarding _ => discard <| IO.asTask b.finishOnboarding
  | .refresh g => do
      background fx g "refresh" do
        let (s, p) ← b.snapshot
        return .snapshot g s p
      background fx g "refresh" do return .records g (← b.records)
  | .syncNow g => background fx g "sync" do
      b.syncNow
      let (s, p) ← b.snapshot
      return .snapshot g s p
  | .retryPeers g => background fx g "sync" do
      b.retryPeers
      let (s, p) ← b.snapshot
      return .snapshot g s p
  | .reconnect g s => background fx g "sync" do
      b.reconnect s
      let (st, p) ← b.snapshot
      return .snapshot g st p
  | .receiveAddress g fresh => background fx g "receive" do return .receiveAddress g (← b.receiveAddress fresh)
  | .watchAddress g address => discard <| IO.asTask do
      try b.watchAddress address (fun txid amount => fx.post (.unconfirmed g address txid amount)) catch _ => pure ()
  | .stopWatchingAddress => discard <| IO.asTask b.stopWatchingAddress
  | .setReceiveLabel g address label => background fx g "label" (records g .labelSaved (b.setReceiveLabel address label))
  | .copy text policy => fx.cap "clipboard.set" (clipPolicyArgs text policy) fun _ => .copiedExpired ""
  | .timer ms h => discard <| IO.asTask do
      IO.sleep ms.toUInt32
      fx.post h
  | .openURL url => fx.cap "open" (Json.mkObj [("url", Json.str url)]) fun _ => .copiedExpired ""
  | .deleteWallet g => background fx g "delete" do
      b.deleteWallet
      return .deleted g
  | .startNetworking g s => do
      discard <| IO.asTask (b.startNetworking s)
      -- AppModel's 1 s `phaseTask`: what the sync loop changed reaches the model as a snapshot
      let token ← watcherToken.modifyGet fun t => (t + 1, t + 1)
      discard <| IO.asTask do
        let mut last := ""
        while (← watcherToken.get) == token do
          try
            let (st, p) ← b.snapshot
            let key := reprStr (st, p)
            if key != last then
              last := key
              trace s!"watcher {g} posts balance {st.balance} peers {st.peerCount} tip {st.tipHeight} scan {st.nextScanHeight} error {st.lastSyncError}"
              fx.post (.snapshot g st p)
          catch e => trace s!"watcher {g}: {e}"
          IO.sleep 1000
  | .stopNetworking => do
      watcherToken.modify (· + 1)
      discard <| IO.asTask b.stopNetworking
  | .resolveRate g inputs _ => background fx g "rate" do
      return .resolvedRate g inputs (← b.resolveFeeRate inputs.priority (parseRateMilli inputs.override))
  | .previewSend g inputs => background fx g "send" do return .previewed g inputs (← b.previewSend inputs)
  | .sendPayment g inputs p =>
      authenticated fx g "send" s!"Send {satsText p.amount} to {p.destination}" do
        return .sent g (← b.sendPayment inputs p)
  | .rawTransaction g txid => background fx g "refresh" do return .rawTransaction g txid (← b.rawTransactionHex txid)
  | .watchRelay g txid => discard <| IO.asTask do
      try b.watchRelay txid (fun e => fx.post (.relay g txid e)) catch _ => pure ()
  | .loadPaymentDetails g txid => background fx g "payment" do
      b.loadPaymentDetails txid
      return .paymentLoaded g txid
  | .pendingFeeRate g txid => background fx g "feeBump" do
      let (milli, suggested) ← b.pendingFeeRate txid
      return .pendingRate g txid milli suggested
  | .previewFeeBump g txid text milli => background fx g "feeBump" do
      return .bumpPreviewed g txid text (← b.previewFeeBump txid milli)
  | .bumpFee g txid p =>
      authenticated fx g "feeBump" "Replace this transaction with a higher fee" do
        return .bumped g txid (← b.bumpFee txid p)
  | .catalogStatus g => background fx g "catalog" do return .catalogStored g (← b.catalogStatus)
  | .connectedPeers g => background fx g "peers" do return .peers g (← b.connectedPeers)
  | .resetPeers g => background fx g "peers" do
      b.resetPeers
      return .peersReset g
  | .exportBundle g e withPhrase name => background fx g "export" do
      let text ← b.exportBundle withPhrase
      let staging ← Winnow.ExportStagingFile.new (← tmpDir.get)
      let file ← staging.write text name
      -- `protect`: the file and its directory are excluded from backup and readable only while unlocked
      for p in [file, file.parent.getD file] do
        let r ← IO.wait (← fx.ask "exclude-from-backup" (Json.mkObj [("path", Json.str p.toString), ("complete", Json.bool true)]))
        unless (r.getObjValAs? Bool "ok").toOption.getD false do
          staging.remove
          throw (IO.userError "The backup file could not be protected on this device.")
      return .exported g e file.toString
  | .removeExport file => discard <| IO.asTask do
      -- only a staging directory, never anything else a stale path could name
      let some dir := (System.FilePath.mk file).parent | return
      if (dir.fileName.getD "").startsWith Winnow.ExportStagingFile.prefix_ then
        try IO.FS.removeDirAll dir catch _ => pure ()
  | .revealPhrase g e =>
      authenticated fx g "reveal" "Show your recovery phrase" do
        let words ← b.revealMnemonic
        let required := (← e2eRef.get).any (·.requireDeviceAuthentication)
        journal "backup.phraseRevealReady" [("deviceAuthenticationRequired", toString required)]
        return .revealed g e words
  | .ownCard g name => background fx g "card" do return .card g name (← b.ownCard name)
  | .parsePaste g text => discard <| IO.asTask do
      try fx.post (.pasteParsed g text (.ok (← b.parsePaste text)))
      catch e => fx.post (.pasteParsed g text (.error (toString e)))
  | .addPerson g name paste prov source labelTxid => background fx g "person" do
      return .updated g (if labelTxid.isSome then .senderLabeled else .personSaved)
        (← b.addPerson name paste prov source labelTxid)
  | .editPerson g pid name attach => background fx g "person" do
      if let some (paste, prov, source) := attach then discard <| b.attachDestination pid paste prov source
      return .updated g .personSaved (← b.updateRecipient pid (some name) true)
  | .updateRecipient g pid name saved ctx => background fx g ctx (records g .none (b.updateRecipient pid name saved))
  | .labelSender g txid pid => background fx g "person" (records g .senderLabeled (b.labelSender txid pid))
  | .removeSenderLabel g txid => background fx g "payment" (records g .none (b.removeSenderLabel txid))
  | .lookupSender g txid base => background fx g "person" do return .senderLookup g txid base (← b.lookupSender txid base)
  | .journal name fields => journal name fields
  | .paste target => discard <| IO.asTask do
      -- `pasteboardText()`: the runner's control file under test mode, the pasteboard otherwise
      let fromControl ← match ← e2eRef.get with
        | some m => pure ((← m.control).bind (·.clipboard))
        | none => pure none
      match fromControl with
      | some text => fx.post (.pasted target text)
      | none =>
        let j ← IO.wait (← fx.ask "clipboard.get" Json.null)
        fx.post (.pasted target ((j.getObjValAs? String "text").toOption.getD ""))

/-- The shell's system events: scene phase as `scenePhaseChanged` reads it (`active` activates,
`background` suspends; `inactive` is still foreground: a system prompt such as Face ID or paste must
neither stop syncing nor discard the result it is waiting for) and screen capture. The privacy cover
over an inactive scene is the shell's. -/
def system (j : Json) : Option Host :=
  match j.getObjValAs? String "scene", j.getObjValAs? Bool "captured" with
  | .ok "active", _ => some (.scene true)
  | .ok "background", _ => some (.scene false)
  | .ok "inactive", _ => some .sceneInactive
  | .ok _, _ => none
  | _, .ok on => some (.captured on)
  | _, _ => none

def app : Native.App Model Msg Cmd Host :=
  { init := {}, update, view, cmds, host := Msg.host, perform := fun c fx => do
      perform c fx
    boot := [.boot], system }

initialize Native.register app

end WinnowApp
