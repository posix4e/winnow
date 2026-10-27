import WinnowApp.Home
import WinnowApp.Send
import WinnowApp.Receive
import WinnowApp.Settings
import WinnowApp.People
import WinnowApp.Vaults
import WinnowApp.Approval

/-! `step msg m = (m', cmds)`; `update` and `cmds` of the app are its two halves (same pre-state).
User messages go to their area's `step`; host answers are checked here — a network answer only
for the current generation, a sensitive one only for the current epoch while active. -/

namespace WinnowApp

/-- Records changed: re-review an open approval or MuSig2 proposal against the new trusted state. -/
def Model.onRecords (m : Model) (r : Records) : Model × List Cmd :=
  let g := m.generation
  let m := { m with records := r }
  let cs : List Cmd :=
    (match m.approval.review with
     | some rv => if m.hasSheet .approval && m.approval.broadcastTxid.isNone then [.approvalRecheck g m.approval.vaultID rv.working] else []
     | none => []) ++
    (match m.musig.review with
     | some rv => if m.hasSheet .musig && m.musig.broadcastTxid.isNone then [.musigRecheck g m.musig.vaultID rv.working] else []
     | none => [])
  -- a send from a vault that is gone falls back to the everyday wallet
  let m := match m.send.inputs.accountID with
    | some id => if (m.vault? id).isNone then { m with send := { m.send with inputs := { m.send.inputs with accountID := none } } } else m
    | none => m
  (m, cs)

/-- Background: networking stops, answers in flight are dropped, sensitive presentations close and
forget (the receive window closes; Receive itself stays). -/
def Model.background (m : Model) : Model × List Cmd :=
  let m0 := m.nextGeneration
  let m1 := { m0 with
    active := false
    onboarding := { m.onboarding with words := [], importText := "", busy := false }
    reveal := {}
    exportState := {} }
  let (m2, cs) := match m1.sheets.findIdx? Sheet.isSensitive with
    | some i => m1.closeFrom i
    | none => (m1, [])
  (m2, [.stopNetworking, .stopWatchingAddress] ++ m.discardExport ++ cs)

def onHost (h : Host) (m : Model) : Model × List Cmd :=
  let current (g : Nat) := g == m.generation
  let sensitive (g e : Nat) := g == m.generation && e == m.epoch && m.active
  match h with
  | .launched forced tab => ({ m with forcedNetwork := forced, tab := tab }, [])
  | .settingsLoaded s =>
    let m := { m with settings := s }
    (m, [.openWallet m.generation s.network true])
  | .booted g r =>
    if !current g then (m, []) else
    match r with
    | .opened id => ({ m with stage := .ready, walletID := some id }, [.refresh g, .startNetworking g m.settings])
    | .backupPending id =>
      ({ m with stage := .onboarding, walletID := some id, onboarding := { m.onboarding with busy := true, error := none } },
       [.refresh g, .startNetworking g m.settings, .resumeBackup g])
    -- `boot` activates networking whatever the stage, so a new wallet is dated at a synced tip
    | .missing => ({ m with stage := .onboarding, walletID := none }, [.startNetworking g m.settings])
    | .damaged msg => ({ m with stage := .storageDamaged msg }, [])
  | .created g words =>
    if !current g then (m, []) else
    ({ m with onboarding := { m.onboarding with busy := false, words, writtenDown := false, error := none } }.present .mnemonic, [])
  | .imported g report =>
    if !current g then (m, []) else
    ({ m with onboarding := { m.onboarding with busy := false, importReport := some report, error := none } }, [])
  | .snapshot g s p =>
    if !current g then (m, []) else
    let wasSyncing := m.status.syncing
    let s := { s with history := historyForDisplay s.history }
    let m := { m with status := s, phase := p }
    -- the mempool window owns only the temporary rows: a payment seen in a block drops its row
    let m := { m with receive := { m.receive with unconfirmed := m.receive.unconfirmed.filter fun (t, _) =>
                 !(s.history.any fun e => e.txid == t && e.height > 0) } }
    let m := match m.send.sentTxid with
      | some t => if m.send.confirmedHeight.isNone then
          match s.history.find? (·.txid == t) with
          | some e => if e.height > 0 then { m with send := { m.send with confirmedHeight := some e.height } } else m
          | none => m
        else m
      | none => m
    if wasSyncing && !s.syncing then m.loadPayment else (m, [])
  | .records g r => if current g then m.onRecords r else (m, [])
  | .updated g d r =>
    if !current g then (m, []) else
    let (m, cs) := m.onRecords r
    let (m, cs2) := match d with
      | .none => (m, [])
      | .personSaved | .senderLabeled => m.closeSheet .addPerson
      | .vaultSaved => m.closeSheet .vaultCreate
      | .vaultRemoved id =>
        if m.routes.getLast? == some (.account id) then ({ m with routes := m.routes.dropLast }, []) else (m, [])
      | .savingsCreated id =>
        ({ m with savingsCreate := { m.savingsCreate with creating := false, created := some id } }, [.savingsCard g id])
      | .savingsAdded => m.closeSheet .addSharedSavings
      | .labelSaved => m.finishLabel
    (m, cs ++ cs2)
  | .receiveAddress g a =>
    if current g && m.hasSheet .receive then m.onReceiveAddress a else (m, [])
  | .unconfirmed g address txid amount =>
    if current g && m.receive.address == address && !(m.receive.unconfirmed.any (·.1 == txid)) then
      ({ m with receive := { m.receive with unconfirmed := m.receive.unconfirmed ++ [(txid, amount)] } }, [])
    else (m, [])
  | .failed g ctx msg => if current g then (m.fail ctx msg, []) else (m, [])
  | .resolvedRate g forInputs milli =>
    let i := m.sendInputs
    if current g && forInputs.priority == i.priority && forInputs.override == i.override then
      ({ m with send := { m.send with resolvedRateMilli := some milli } }, [])
    else (m, [])
  | .previewed g forInputs p =>
    -- a preview counts only for the inputs it was made for (SendReviewInputs)
    if current g && forInputs == m.sendInputs then
      ({ m with send := { m.send with preview := some p, reviewing := false, error := none } }, [])
    else ({ m with send := { m.send with reviewing := false } }, [])
  | .sent g txid =>
    if !current g then (m, []) else
    ({ m with send := { m.send with sending := false, sentTxid := some txid }, spendingInFlight := false },
     [.refresh g, .rawTransaction g txid, .watchRelay g txid])
  | .rawTransaction g txid hex =>
    if current g && m.send.sentTxid == some txid then ({ m with send := { m.send with rawTransaction := hex } }, []) else (m, [])
  | .relay g txid e => if current g then (m.onRelay txid e, []) else (m, [])
  | .approvalPrepared g forInputs =>
    if !current g || forInputs != m.sendInputs then ({ m with send := { m.send with sending := false } }, []) else
    match m.send.preview with
    | some { source := .vault id _ psbt isScriptPath .., .. } =>
      let m := { m with send := { m.send with sending := false } }
      if isScriptPath then ({ m with approval := { vaultID := id } }.present .approval, [.approvalAdd g id none psbt])
      else ({ m with musig := { vaultID := id } }.present .musig, [.musigAdd g id none psbt])
    | _ => ({ m with send := { m.send with sending := false } }, [])
  | .paymentLoaded g _ => if current g then ({ m with payment := { m.payment with loading := false } }, [.refresh g]) else (m, [])
  | .pendingRate g txid milli text =>
    if !current g || m.feeBump.txid != txid then (m, []) else
    ({ m with feeBump := { m.feeBump with currentRateMilli := some milli, targetText := text } },
     match parseRateMilli text (trimNewlines := true) with | some r => [.previewFeeBump g txid text r] | none => [])
  | .bumpPreviewed g txid text p =>
    if current g && m.feeBump.txid == txid && m.feeBump.targetText == text then
      ({ m with feeBump := { m.feeBump with reviewed := some (text, p), error := none } }, [])
    else (m, [])
  | .bumped g txid r =>
    if !current g then ({ m with spendingInFlight := false }, []) else
    if m.feeBump.txid != txid then ({ m with spendingInFlight := false }, [.refresh g]) else
    ({ m with feeBump := { m.feeBump with replacement := some r, bumping := false }, spendingInFlight := false }, [.refresh g])
  | .catalogProgress g bytes =>
    let d := m.settingsDraft
    if current g then ({ m with settingsDraft := { d with catalog := { d.catalog with bytes } } }, []) else (m, [])
  | .catalogRefreshed g notice =>
    let d := m.settingsDraft
    if current g then ({ m with settingsDraft := { d with catalog := { d.catalog with refreshing := false, notice := some notice } } }, []) else (m, [])
  | .catalogStored g stored =>
    let d := m.settingsDraft
    if current g then ({ m with settingsDraft := { d with catalog := { d.catalog with stored := some stored } } }, []) else (m, [])
  | .peers g ps => if current g then ({ m with settingsDraft := { m.settingsDraft with peers := ps } }, []) else (m, [])
  | .peersReset g =>
    if !current g then (m, []) else
    ({ m with settingsDraft := { m.settingsDraft with resettingPeers := false } }, [.connectedPeers g, .refresh g])
  | .exported g e file =>
    if sensitive g e && m.hasSheet .exportBundle then
      ({ m with exportState := { m.exportState with file := some file, busy := false, error := none } }, [])
    else (m, [.removeExport file])
  | .revealed g e words =>
    if sensitive g e then ({ m with reveal := { words } }.present .revealPhrase, [])
    else (m, [])
  | .card g name card =>
    if current g && m.settings.ownDisplayName.trimAscii.copy == name then ({ m with shareCard := { card := some card } }, []) else (m, [])
  | .pasteParsed g text r =>
    if !current g || m.person.pasted != text then (m, []) else
    match r with
    | .ok p => ({ m with person := { m.person with parsed := some p, error := none } }, [])
    | .error e => ({ m with person := { m.person with parsed := none, error := some e } }, [])
  | .senderLookup g txid source addresses =>
    if current g && m.person.mode.txid == some txid then
      ({ m with person := { m.person with inferring := false, inferredAddresses := addresses, inferredSource := some source } }, [])
    else (m, [])
  | .ownKey g expr =>
    if current g then (m, [.checkCosigner g m.vaultCreate.role m.vaultCreate.cosigners expr]) else (m, [])
  | .cosignerChecked g expr =>
    if !current g then (m, []) else
    let v := m.vaultCreate
    if v.cosigners.contains expr then (m, []) else
    let cs := v.cosigners ++ [expr]
    ({ m with vaultCreate := { v with cosigners := cs, threshold := reconcileThreshold v.threshold v.cosigners.length cs.length,
                                      error := none, built := none,
                                      pasted := if v.pasted.trimAscii.copy == expr then "" else v.pasted } }, [])
  | .vaultBuilt g cs b =>
    if current g && cs == m.vaultCreate.cosigners then ({ m with vaultCreate := { m.vaultCreate with built := some b, error := none } }, [])
    else (m, [])
  | .savingsCard g id card => if current g then ({ m with savingsCardText := some (id, card) }, []) else (m, [])
  | .approvalReviewed g id r clr =>
    if current g && m.approval.vaultID == id && m.hasSheet .approval then
      let pasted := if clr then "" else m.approval.pasted
      ({ m with approval := { m.approval with review := some r, busy := false, error := r.reviewError, pasted } }, [])
    else (m, [])
  | .approvalSent g id txid =>
    let m := { m with spendingInFlight := false }
    if current g && m.approval.vaultID == id then
      ({ m with approval := { m.approval with broadcastTxid := some txid, busy := false } }, [.refresh g])
    else (m, [.refresh m.generation])
  | .musigReviewed g id r clr =>
    if current g && m.musig.vaultID == id && m.hasSheet .musig then
      ({ m with musig := { m.musig with review := some r, error := none, pasted := if clr then "" else m.musig.pasted } }, [])
    else (m, [])
  | .musigNonces g e id r =>
    -- nonces made for a presentation that is gone are scrubbed, never installed
    if sensitive g e && m.musig.vaultID == id && m.hasSheet .musig then
      ({ m with musig := { m.musig with review := some r, holdsNonces := true, nonceSessionStarted := true, authorizing := false } }, [])
    -- a live session's nonces are never scrubbed by a stale answer (closing already scrubbed the old one)
    else (m, if m.musig.holdsNonces then [] else [.musigClear])
  | .musigSigned g e id r =>
    if sensitive g e && m.musig.vaultID == id && m.hasSheet .musig then
      ({ m with musig := { m.musig with review := some r, holdsNonces := false, signedThisSession := true, authorizing := false } }, [])
    else (m, if m.musig.holdsNonces then [] else [.musigClear])
  | .musigSent g e id txid =>
    let m := { m with spendingInFlight := false }
    if sensitive g e && m.musig.vaultID == id then
      ({ m with musig := { m.musig with broadcastTxid := some txid, broadcasting := false } }, [.refresh g])
    else (m, [.refresh m.generation])
  | .pasted target text =>
    match target with
    | .destination =>
      m.editSend fun i => { i with destination := text.trimAscii.copy }
    | .person => m.setPersonPasted text
    | .savingsCard => ({ m with savingsAdd := { m.savingsAdd with pasted := text } }, [])
    | .approval => ({ m with approval := { m.approval with pasted := text } }, [])
    | .musig => ({ m with musig := { m.musig with pasted := text } }, [])
    | .importBundle => ({ m with onboarding := { m.onboarding with importText := text } }, [])
  | .copiedExpired key => if m.copied == some key then ({ m with copied := none }, []) else (m, [])
  | .deleted g =>
    if !current g then (m, []) else
    let m' := m.nextGeneration
    let m' := { m' with stage := Stage.onboarding, walletID := none, status := ({} : Status), records := ({} : Records) }
    let m' := { m' with phase := SyncPhase.idle, confirm := none, sheets := [], routes := [], tab := 0 }
    (m', [.stopNetworking])
  | .captured on => ({ m with captured := on }, [])
  | .scene active =>
    -- `scenePhaseChanged` journals the phase before acting on it
    let phase : Cmd := .journal "app.scenePhase" [("phase", if active then "active" else "background")]
    if active then
      let m := { m with active := true }
      let resume := if m.stage == .ready then [.startNetworking m.generation m.settings, .refresh m.generation] else []
      let window := if m.hasSheet .receive && !m.receive.address.isEmpty then [.watchAddress m.generation m.receive.address] else []
      (m, [phase] ++ resume ++ window)
    else
      let (m, cs) := m.background
      (m, phase :: cs)
  | .sceneInactive => (m, [.journal "app.scenePhase" [("phase", "inactive")]])

/-- Switch to the other network's wallet (`switchNetwork`): a new generation, nothing carried over. -/
def Model.switchNetwork (m : Model) (net : Network) : Model × List Cmd :=
  if net == m.settings.network then (m, []) else
  -- a test session locked to one network stays there
  if m.forcedNetwork.any (· != net) then (m, []) else
  let s := { m.settings with network := net }
  let m0 := m.nextGeneration
  let m' := { m0 with settings := s, stage := Stage.loading, status := ({} : Status), records := ({} : Records),
                      phase := SyncPhase.idle, walletID := none, routes := [], sheets := [], confirm := none,
                      send := ({} : SendState), tab := 0 }
  (m', [.stopNetworking, .stopWatchingAddress, .musigClear, .saveSettings s, .openWallet m'.generation net false])

def step (msg : Msg) (m : Model) : Model × List Cmd :=
  let g := m.generation
  match msg with
  | .createWallet =>
    ({ m with onboarding := { m.onboarding with busy := true, error := none } }, [.createWallet g m.settings.network])
  | .resumeBackup =>
    ({ m with onboarding := { m.onboarding with busy := true, error := none } }, [.resumeBackup g])
  | .openImport => ({ m with onboarding := { m.onboarding with importReport := none, error := none } }.present .importWallet, [])
  | .setImportText s => ({ m with onboarding := { m.onboarding with importText := s } }, [])
  | .pasteImport => (m, [.paste .importBundle])
  | .importWallet =>
    ({ m with onboarding := { m.onboarding with busy := true, error := none } },
     [.importWallet g m.settings.network m.onboarding.importText])
  | .setWrittenDown b => ({ m with onboarding := { m.onboarding with writtenDown := b } }, [])
  | .copyBackupPhrase =>
    ({ m with onboarding := { m.onboarding with phraseCopied := true } }, [.copy (" ".intercalate m.onboarding.words) .recoveryPhrase])
  | .finishOnboarding =>
    if !m.onboarding.words.isEmpty && !m.onboarding.writtenDown then (m, []) else
    ({ m with stage := .ready, sheets := [], onboarding := ({} : Onboarding) },
     [.finishOnboarding g, .refresh g, .startNetworking g m.settings])
  | .closeSheet =>
    -- the backup sheet only closes through Done
    if m.topSheet == some .mnemonic then (m, []) else m.closeTop
  | .setNetwork i =>
    match networks[i]? with
    | some net => m.switchNetwork net
    | none => (m, [])
  | .switchNetwork net => m.switchNetwork net
  | .askAdvanced => ({ m with confirm := some .advancedMode }, [])
  | .setAdvanced b =>
    if b == m.settings.advancedMode then ({ m with confirm := none }, []) else
    let s := { m.settings with advancedMode := b }
    ({ m with settings := s, confirm := none, tab := 0, routes := [] },
     [.saveSettings s, .journal "setting.advancedMode" [("enabled", toString b)]])
  | .dismissConfirm => ({ m with confirm := none }, [])
  | .selectTab i =>
    let m' := { m with tab := i }
    (m', if i == 2 then m'.settingsAppear else if i == 1 then [.resolveRate g m.sendInputs m.status.feeFloorMilli] else [])
  | .openReceive => ({ m with receive := ({} : Receive) }.present .receive, [.receiveAddress g false])
  | .openSend =>
    let m := { m with send := { inputs := { network := m.settings.network } } }.present .send
    (m, [.resolveRate g m.sendInputs m.status.feeFloorMilli])
  | .copy key t => ({ m with copied := some key }, [.copy t .interchange, .timer 2000 (.copiedExpired key)])
  | .openExplorer url exposed => ({ m with confirm := some (.openExternal url exposed) }, [])
  | .openURL url => ({ m with confirm := none }, [.openURL url])
  | .setExpanded key b =>
    ({ m with expanded := if b then (if m.expanded.contains key then m.expanded else m.expanded ++ [key]) else m.expanded.erase key }, [])
  | .syncNow => (m, [.syncNow g])
  | .retryPeers => (m, [.retryPeers g])
  | .retryOpen => ({ m with stage := .loading }, [.openWallet g m.settings.network true])
  | .send s => stepSend s m
  | .receive r => stepReceive r m
  | .home h => stepHome h m
  | .settings s => stepSettings s m
  | .backup b => stepBackup b m
  | .people p => stepPeople p m
  | .vault v => stepVault v m
  | .approval a => stepApproval a m
  | .musig s => stepMusig s m
  | .host h => onHost h m

def update (msg : Msg) (m : Model) : Model := (step msg m).1
def cmds (msg : Msg) (m : Model) : List Cmd := (step msg m).2

end WinnowApp
