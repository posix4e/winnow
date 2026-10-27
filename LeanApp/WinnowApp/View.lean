import WinnowApp.Update

/-! The root view (WinnowApp.swift: loading, onboarding, ready as beginner home or the three tabs,
StorageDamagedView, the Tor alert), the onboarding screen and sheets, and the presentation stack: each
sheet presents the next one inside itself, and the one alert in the tree goes on the innermost sheet
(an alert behind a sheet never shows). Each area's screens are in its own module. -/

namespace WinnowApp
open ElmLean

/-! ## Onboarding -/

def mnemonicSheet (m : Model) (inner : List H) : H :=
  let words := m.onboarding.words
  .sheet "Wallet backup" none
    ([ body s!"Write these {words.length} words down, in order, and keep them offline. These words protect your signing keys. Keep a backup file too: Winnow needs both to restore your wallet."
     , wordGrid words m.captured
     , .button (if m.onboarding.phraseCopied then "Copied for 2 minutes" else "Copy recovery phrase") .plain (some .copyBackupPhrase)
     , caption "Copying is less private than paper. The clipboard item stays on this device and expires after two minutes."
     , .divider ] ++
     -- shown only while there is sync progress to report (`model.syncStatusText`)
     (match syncStatusText m.phase with
      | some progress =>
        [.section "Connecting to Bitcoin" "You can finish writing down the words while Winnow connects." [.progress progress]]
      | none => []) ++
     [ .toggle "I have written the words down" m.onboarding.writtenDown Msg.setWrittenDown
     , .button "Done" .primary (if m.onboarding.writtenDown then some .finishOnboarding else none) ] ++ inner)

def importSheet (m : Model) (inner : List H) : H :=
  .sheet "Import wallet" (some .closeSheet)
    ([ closeRow "Close"
     , .input .multiline "Paste your backup file (JSON)" "" m.onboarding.importText Msg.setImportText none
     , .button "Paste from clipboard" .plain (some .pasteImport)
     , caption "Use the file saved from Back up wallet. Keep your recovery words too. Backups from other wallets may not include every coin type." ] ++
     (match m.onboarding.importReport with
      | some r => [.section "Verification report" "" [body r], .button "Continue" .primary (some .finishOnboarding)]
      | none => [.button "Import and verify" .primary
                  (if m.onboarding.busy || m.onboarding.importText.trimAscii.isEmpty then none else some .importWallet)]) ++
     errorRows m.onboarding.error ++ inner)

/-! ## Presentations -/

def sheetView (m : Model) (s : Sheet) (inner : List H) : H :=
  match s with
  | .receive => receiveSheet m inner
  | .send => sendSheet m inner
  | .mnemonic => mnemonicSheet m inner
  | .importWallet => importSheet m inner
  | .feeBump => feeBumpSheet m inner
  | .addPerson => addPersonSheet m inner
  | .savedRecipients => savedRecipientsSheet m inner
  | .shareCard => shareCardSheet m inner
  | .labelEditor => labelSheet m inner
  | .exportBundle => exportSheet m inner
  | .revealPhrase => revealSheet m inner
  | .papers => papersSheet m inner
  | .readSide => readSideSheet inner

def cancel : H := .button "Cancel" .plain (some .dismissConfirm)

def confirms (m : Model) : List H :=
  match m.confirm with
  | some .advancedMode =>
    [.alert "Turn on Advanced mode?" "The app changes to three tabs — Wallet, Send and Settings — with fee controls, network settings and technical details. Simple, on the Wallet tab, brings this screen back and keeps every setting you changed."
       [.button "Turn on" .primary (some (.setAdvanced true)), cancel]]
  | some .deleteWallet =>
    [.alert "Delete this wallet?" "This deletes the key from this device. Anyone holding the recovery phrase can still restore it; without that phrase, any money in this wallet is unrecoverable. Check you have the phrase written down before continuing."
       [.button "Delete wallet" .destructive (some (.settings .deleteWallet)), cancel]]
  | some (.deleteFailed msg) =>
    [.alert "Could not delete the wallet" msg [.button "OK" .plain (some .dismissConfirm)]]
  | some .resetPeers =>
    [.alert "Reset and shuffle peers?" "Disconnects all peers, forgets saved peers, and finds new ones from the downloaded peer list and, when clearnet is allowed, DNS seeds. Your manual peers and downloaded catalog are kept."
       [.button "Reset and shuffle peers" .destructive (some (.settings .resetPeers)), cancel]]
  | some .exportWithPhrase =>
    [.alert "Include the recovery phrase?" "This adds your phone's signing key to the file. Anyone with the file can use that key."
       [.button "Export with phrase" .destructive (some (.backup .confirmExport)), cancel]]
  | some .inferSender =>
    let host := match m.person.lookupConsent with
      | some (base, _) => (urlHost base).getD "the explorer"
      | none => m.settings.explorerHost
    [.alert s!"Look up funding addresses with {host}?"
       ((if m.person.lookupConsent.isSome then lookupDisclosure else "No lookup selected.") ++ " Funding addresses do not establish who sent the payment or where they want a payment sent.")
       [.button s!"Look up with {host}" .plain (some (.people .infer)), cancel]]
  | some (.openExternal url exposed) =>
    let host := urlHost url
    [.alert "Open external block explorer?"
       s!"Opening {host.getD "this explorer"} opens an external browser, which shares its IP address and this exact {exposed} with that service. Winnow does not use its response for wallet balance, history, fees, synchronization, or broadcasting."
       [.button s!"Open {host.getD "explorer"}" .plain (some (.openURL url)), cancel]]
  | none =>
    if m.settings.torRemovedNotice then
      [.alert "Tor is no longer part of Winnow" "This version connects to Bitcoin peers directly. Your Tor setting was on, and it no longer applies: peers and the explorer see your connection's IP address. Tor and I2P are on the roadmap at winnowwallet.com/roadmap."
         [.button "OK" .plain (some (.settings .dismissTor))]]
    else []

/-- The presentation stack, outermost first; the alert goes on the innermost sheet. -/
def nestSheets (m : Model) : List Sheet → List H
  | [] => confirms m
  | s :: rest => [sheetView m s (nestSheets m rest)]

def overlays (m : Model) : List H := nestSheets m m.sheets

/-! ## Screens -/

def onboardingView (m : Model) : H :=
  .screen "Winnow" none
    ([ .list
        [ .section "" "" [body "Your bitcoin, on your phone. Winnow connects directly to the Bitcoin network. Keep the app open while it syncs."]
        , .section "" "First, write down your recovery words. Then save a backup file from Back up wallet on the main screen."
            (match m.walletID with
             | some _ =>
               [ .button "Continue backup" .primary (if m.onboarding.busy then none else some .resumeBackup)
               , caption "This wallet's recovery words were never confirmed written down." ]
             | none =>
               [ .button "Create new wallet" .primary (if m.onboarding.busy then none else some .createWallet)
               , .button "Restore from backup" .plain (some .openImport) ])
        , .section "" "" [networkPicker m]
        , .section "" "" (errorRows m.onboarding.error) ] ] ++ overlays m)

/-- Beginner home or the Wallet tab (both pull to refresh: `syncNow`), or the screen pushed on top of it. -/
def mainScreen (m : Model) : H :=
  match m.routes.getLast? with
  | some (.payment t) => .screen "Payment" (some (.home .pop)) ([.list (paymentSections m t)] ++ overlays m)
  | some .backup => backupScreen m (overlays m)
  | none =>
    if m.settings.advancedMode then
      .screen "Winnow" none
        ([ .toolbar [.button "Simple" .plain (some (.setAdvanced false)), .button "Receive" .plain (some .openReceive)]
         , .list (walletSections m) ] ++ overlays m) (onRefresh := some .syncNow)
    else
      .screen "Winnow" none
        ([ .toolbar [.button "Advanced" .plain (some .askAdvanced)], .list (beginnerSections m) ] ++ overlays m)
        (onRefresh := some .syncNow)

def otherNetwork (n : Network) : Network := if n == .mainnet then .signet else .mainnet

def view (m : Model) : H :=
  match m.stage with
  | .loading => .screen "Winnow" none ([.progress "Opening wallet…"] ++ confirms m)
  | .storageDamaged msg =>
    let other := otherNetwork m.settings.network
    .screen "Winnow" none
      ([.empty "Wallet data needs attention" "externaldrive.badge.exclamationmark" msg
        [ .button "Retry without changing anything" .primary (some .retryOpen)
        , .button s!"Open the {other.name} wallet instead" .plain (some (.switchNetwork other)) ]] ++ confirms m)
  | .onboarding => onboardingView m
  | .ready =>
    if m.settings.advancedMode then
      .tabs ["Wallet", "Send", "Settings"] ["bitcoinsign.circle", "arrow.up.circle", "gear"] m.tab Msg.selectTab
        [if m.tab == 1 then .screen (sendTitle m) none ([.list (sendContent m)] ++ overlays m)
         else if m.tab == 2 then .screen "Settings" none ([.list (settingsSections m)] ++ overlays m)
         else mainScreen m]
    else mainScreen m

end WinnowApp
