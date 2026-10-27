import WinnowApp.Backup

/-! SettingsView.swift: network, backup, the census peer list, manual peers, the external block
explorer, chain verification, connected peers (with the reset confirmation), about and the design
papers (Components.swift `DesignPapersView`, bundled HTML), and the danger zone. -/

namespace WinnowApp
open ElmLean

def explorers : List Explorer := [.blockstream, .mempool, .custom]

/-- `DesignPapersView.papers`: the bundled resource (docs/<name>.html), title, blurb. -/
def papers : List (String × String × String) :=
  [ ("mobile", "A phone wallet", "What the device forces, and what the product refuses.")
  , ("read-side", "The read side", "How the phone learns which coins are its own.")
  , ("write-side", "The write side", "Build, price, sign, and get a transaction out.")
  , ("import", "Import", "The bundle is the history. There is no back-scan.") ]

/-- What the Settings tab loads when it appears in Advanced mode (`.task(id: advancedMode)`). -/
def Model.settingsAppear (m : Model) : List Cmd :=
  if m.settings.advancedMode && m.stage == .ready then [.connectedPeers m.generation, .catalogStatus m.generation] else []

def stepSettings (msg : SettingsMsg) (m : Model) : Model × List Cmd :=
  let g := m.generation
  let d := m.settingsDraft
  let save (s : Settings) : Model × List Cmd := ({ m with settings := s }, [.saveSettings s])
  match msg with
  | .setManualPeer s => ({ m with settingsDraft := { d with manualPeer := s, error := none } }, [])
  | .addManualPeer =>
    match parsePeer d.manualPeer with
    | .error e => ({ m with settingsDraft := { d with error := some e } }, [])
    | .ok p =>
      if m.settings.manualPeers.contains p then ({ m with settingsDraft := { d with manualPeer := "", error := none } }, []) else
      let s := m.settings.withScoped fun n => { n with manualPeers := n.manualPeers ++ [p] }
      ({ m with settings := s, settingsDraft := { d with manualPeer := "", error := none } }, [.saveSettings s])
  | .removeManualPeer i => save (m.settings.withScoped fun n => { n with manualPeers := n.manualPeers.eraseIdx i })
  | .reconnect => (m, [.reconnect g m.settings])
  | .setVerifyFromGenesis b =>
    if b == m.settings.verifyFromGenesis then (m, []) else
    let s := { m.settings with verifyFromGenesis := b }
    ({ m with settings := s }, [.saveSettings s, .journal "setting.verifyFromGenesis" [("enabled", toString b)], .reconnect g s])
  | .setExplorer i => match explorers[i]? with
    | some e => save (m.settings.withScoped fun n => { n with explorer := e })
    | none => (m, [])
  | .setEsploraURL s => save (m.settings.withScoped fun n => { n with esploraURL := s.trimAscii.copy })
  | .openReadSide => (m.present .readSide, [])
  | .openPapers => ({ m with paper := none }.present .papers, [])
  | .openPaper i => ({ m with paper := some i }, [])
  | .closePaper => ({ m with paper := none }, [])
  | .refreshPeers => (m, [.connectedPeers g])
  | .askResetPeers => ({ m with confirm := some .resetPeers }, [])
  | .resetPeers => ({ m with confirm := none, settingsDraft := { d with resettingPeers := true } }, [.resetPeers g])
  | .askDelete => ({ m with confirm := some .deleteWallet }, [])
  | .deleteWallet => ({ m with confirm := none }, [.deleteWallet g])
  | .dismissTor => save { m.settings with torRemovedNotice := false }

/-! ## View -/

def networkIndex (n : Network) : Nat := if n == .mainnet then 0 else 1

/-- The picker, or the network alone when a test session is locked to it (SettingsView disables the picker). -/
def networkPicker (m : Model) : H :=
  if m.forcedNetwork.isSome then .labeled "Network" (if m.settings.network == .mainnet then "Mainnet" else "Signet")
  else .picker "Network" ["Mainnet", "Signet"] (networkIndex m.settings.network) Msg.setNetwork

/-- SettingsView's footer under the network picker. -/
def networkFooter (m : Model) : String :=
  if m.forcedNetwork.isSome then
    s!"This debug session is locked to {if m.settings.network == .mainnet then "mainnet" else "public signet"}."
  else "Each network has a separate wallet. Signet uses test coins with no value."

def settingsSections (m : Model) : List H :=
  let s := m.settings
  let d := m.settingsDraft
  let set (f : String → SettingsMsg) : String → Msg := fun v => .settings (f v)
  (if s.showsNetworkPicker then
    [.section "" (networkFooter m) [networkPicker m]] else []) ++
  [backupSection m] ++
  (if s.advancedMode then
    [.section "Mainnet peer list" "Each release carries the census of its day, the list it starts from. Every selected peer still undergoes Winnow's normal checks."
      (match d.catalog with | some line => [body line] | none => [])] else []) ++
  (if s.showsManualPeers then
    [.section "Manual peers" "Manual peers are tried first. Seeds resolve over HTTPS (Cloudflare 1.1.1.1), with system DNS as the fallback. The default port is 8333 (mainnet) / 38333 (signet). Peers must advertise compact filters and pass Winnow's checks."
      ((s.manualPeers.zipIdx.map fun (p, i) => .row [caption p, .spacer, .button "Remove" .destructive (some (.settings (.removeManualPeer i)))]) ++
       [.row [.input .plain "" "host:port" d.manualPeer (set .setManualPeer) (some (.settings .addManualPeer)),
              .button "Add" .plain (if d.manualPeer.trimAscii.isEmpty then none else some (.settings .addManualPeer))]] ++
       errorRows d.error ++
       [.button "Reconnect peers" .plain (some (.settings .reconnect))])] else []) ++
  (if s.showsExplorerSettings then
    [.section "External block explorer" "Winnow does not use the explorer for balances, synchronization, fees or broadcasting. Every funding-address lookup asks for consent and explains the transaction-ID disclosure; you must explicitly select any result. External browser links have their own warning: the browser shares its IP address with the site. On signet, the blockstream.info preset uses mempool.space."
      ([ .picker "Block explorer" ["blockstream.info", "mempool.space", "Custom"] (explorers.idxOf s.scoped.explorer) (fun i => .settings (.setExplorer i)) ] ++
       (if s.scoped.explorer == .custom then
         [.input .plain "" "Esplora-compatible website URL" s.scoped.esploraURL (set .setEsploraURL) none] else []) ++
       [ caption s!"Selected: {s.esploraBaseURL}"
       , .button "What this trades away" .plain (some (.settings .openReadSide)) ])] else []) ++
  (if s.showsChainVerification then
    [.section "Chain verification" "Winnow normally starts from a block header built into the app, then verifies every block after it. That header was produced by syncing this same code from block 0, and anyone can reproduce it — but on your phone it begins as a value you are taking from us rather than one you computed. Turn this on to skip it and re-derive the entire chain from block 0 instead. It downloads and proof-of-work-checks every header ever mined, which takes several minutes and discards the headers already stored."
      ([.toggle "Verify the chain from genesis" s.verifyFromGenesis (fun b => .settings (.setVerifyFromGenesis b))] ++
       (if s.verifyFromGenesis then [caption "Turning this off later keeps the chain you already verified."] else []))] else []) ++
  (if s.advancedMode then
    [.section "Connected peers" ""
      ((d.peers.map fun p =>
          .col [caption p.endpoint,
                caption (s!"{p.userAgent} · height {p.startHeight}" ++ (match p.feeFilter with | some f => s!" · floor {f} sat/kvB" | none => ""))]) ++
       (if d.peers.isEmpty then [caption "No peers connected."] else []) ++
       [ .button "Refresh" .plain (some (.settings .refreshPeers))
       , .button (if d.resettingPeers then "Resetting…" else "Reset and shuffle peers") .plain
           (if d.resettingPeers then none else some (.settings .askResetPeers)) ])] else []) ++
  [.section "About" ""
    ([.labeled "Version" appVersionText] ++
     (if s.advancedMode then [.labeled "Wallet ID" (m.walletID.getD "—")] else []) ++
     [.button "Design papers" .plain (some (.settings .openPapers))])] ++
  (if m.walletID.isSome then
    [.section "Danger zone" s!"Removes this {s.network.name} wallet so you can create or import another. The key is deleted from this device — without your recovery phrase the money is gone. People you added stay on this phone, and block headers are kept, so the next wallet does not re-sync the chain."
      [.button "Delete wallet from this device" .destructive (some (.settings .askDelete))]] else [])

/-- `DesignPapersView` and `DesignPaperView`. The pages are the HTML files the site serves, bundled
with the app (`<name>.html` in the bundle's resources). -/
def papersSheet (m : Model) (inner : List H) : H :=
  match m.paper.bind (papers[·]?) with
  | some (resource, title, _) =>
    .sheet title (some .closeSheet)
      ([.row [.button "Design papers" .plain (some (.settings .closePaper)), .spacer, .button "Done" .plain (some .closeSheet)],
        .page s!"{resource}.html"] ++ inner)
  | none =>
    .sheet "Design papers" (some .closeSheet)
      ([closeRow "Done"] ++
       (papers.zipIdx.map fun ((_, title, blurb), i) =>
          .col [.button title .plain (some (.settings (.openPaper i))), caption blurb]) ++ inner)

/-- `ReadSideDocumentView`. -/
def readSideSheet (inner : List H) : H :=
  .sheet "The Read Side" (some .closeSheet) ([closeRow "Done", .page "read-side.html"] ++ inner)

end WinnowApp
