import WinnowApp.Types
import WinnowApp.Format

/-! The app's state, messages and commands (AppModel + the views' @State, as one Elm model).

The state of each area is its own structure (Send, Receive, People, Vaults, Approval, MuSig2, …);
user messages are grouped per area (`SendMsg`, `PeopleMsg`, …), host answers are one `Host` type, and
commands one `Cmd` type, because `perform` runs them all. The area modules (`WinnowApp/Send.lean`,
`People.lean`, `Vaults.lean`, …) hold each area's `step` and its views. -/

namespace WinnowApp
open Lean

/-! ## Presentations -/

/-- What AddPersonView is for (its initialiser's arguments). -/
structure PersonMode where
  /-- Editing this person (rename, or adding a destination when it has none). -/
  personID : Option String := none
  /-- Adding a co-owner: a signer key is what counts. -/
  forSigning : Bool := false
  /-- Labelling the sender of this received payment. -/
  txid : Option String := none
  deriving Repr, BEq, Inhabited

inductive Sheet where
  | send
  | receive
  | importWallet
  | mnemonic
  | feeBump
  | addPerson
  | savedRecipients
  | shareCard
  /-- PaymentDetailView's "Address label" sheet. -/
  | labelEditor
  | exportBundle
  | revealPhrase
  | papers
  | readSide
  | vaultCreate
  | sharedSavingsCreate
  | savingsShare (vaultID : String)
  | addSharedSavings
  | savingsChooser
  | approval
  | musig
  deriving Repr, BEq, Inhabited

/-- A pushed screen (NavigationLink destinations). -/
inductive Route where
  | payment (txid : String)
  | account (vaultID : String)
  /-- Beginner mode's Back up page. -/
  | backup
  deriving Repr, BEq, Inhabited

/-- A confirmation the user must answer (alerts and confirmation dialogs). -/
inductive Confirm where
  | advancedMode
  | deleteWallet
  | deleteFailed (message : String)
  | resetPeers
  | removeSavings (vaultID : String)
  | exportWithPhrase
  | inferSender
  /-- WarnedExplorerLink / DesignPaperView: an external URL, and what it exposes. -/
  | openExternal (url : String) (exposedItem : String)
  deriving Repr, BEq, Inhabited

/-- Which clipboard policy a copy uses (`ClipboardPolicy`). -/
inductive ClipPolicy where
  /-- Recovery words: local only, 120 s. -/
  | recoveryPhrase
  /-- Addresses, descriptors, PSBTs, txids: may cross devices, 300 s. -/
  | interchange
  deriving Repr, BEq, Inhabited

/-- Where a Paste button's text goes. -/
inductive PasteTarget where
  | destination
  | person
  | savingsCard
  | approval
  | musig
  | importBundle
  deriving Repr, BEq, Inhabited

/-! ## Area state -/

structure Onboarding where
  busy : Bool := false
  error : Option String := none
  /-- The recovery phrase being backed up (cleared on background). -/
  words : List String := []
  writtenDown : Bool := false
  importText : String := ""
  importReport : Option String := none
  phraseCopied : Bool := false
  deriving Repr, Inhabited

/-- ReceiveAddressLabelEditor, for the receive screen and a payment's labelled outputs. -/
structure LabelEditor where
  address : String := ""
  draft : String := ""
  saving : Bool := false
  error : Option String := none
  deriving Repr, Inhabited

structure Receive where
  address : String := ""
  error : Option String := none
  editingLabel : Bool := false
  changing : Bool := false
  /-- Payments the mempool window saw: txid, amount. -/
  unconfirmed : List (String × Int) := []
  deriving Repr, Inhabited

/-- What a preview was computed for (Winnow's `SendReviewInputs`): any change voids the preview. -/
structure SendInputs where
  destination : String := ""
  amount : String := ""
  priority : Nat := 1
  override : String := ""
  network : Network := .mainnet
  /-- A payment to a saved person, and the index its fresh address is derived at. -/
  personID : Option String := none
  paymentIndex : Option Nat := none
  /-- none: the everyday wallet; some: a vault. -/
  accountID : Option String := none
  walletID : Option String := none
  deriving Repr, Inhabited, BEq

inductive PreviewSource where
  | wallet
  /-- A vault spend: its PSBT goes to the approval screen. -/
  | vault (vaultID name : String) (psbt : String) (isScriptPath : Bool) (threshold signerCount : Nat)
  deriving Repr, Inhabited, BEq

structure PreviewRecipient where
  personID : String
  name : String
  derivesFreshAddresses : Bool
  hasUnverifiedFundingDestination : Bool
  deriving Repr, Inhabited, BEq

/-- Winnow's `SendPreview` as the screen shows it. -/
structure Preview where
  source : PreviewSource := .wallet
  recipient : Option PreviewRecipient := none
  destination : String
  /-- `amountSent` -/
  amount : Nat
  fee : Nat
  feeRateMilli : Nat
  inputCount : Nat
  change : Option Nat
  locktimeLagsTip : Bool
  deriving Repr, Inhabited

structure SendState where
  inputs : SendInputs := {}
  preview : Option Preview := none
  reviewing : Bool := false
  sending : Bool := false
  error : Option String := none
  sentTxid : Option String := none
  rawTransaction : Option String := none
  relayLog : List String := []
  relayedPeers : List String := []
  feeFloorNotice : Bool := false
  confirmedHeight : Option Nat := none
  resolvedRateMilli : Option Nat := none
  deriving Repr, Inhabited

structure PaymentDetail where
  loading : Bool := false
  error : Option String := none
  deriving Repr, Inhabited

structure FeeBump where
  txid : String := ""
  currentRateMilli : Option Nat := none
  targetText : String := ""
  /-- The preview and the rate text it was made for (`FeeBumpReviewInputs`). -/
  reviewed : Option (String × FeeBumpPreview) := none
  error : Option String := none
  bumping : Bool := false
  replacement : Option String := none
  deriving Repr, Inhabited

structure Catalog where
  refreshing : Bool := false
  bytes : Nat := 0
  notice : Option String := none
  /-- What is on disk: "Observed …" or the bundled-candidates sentence. -/
  stored : Option String := none
  error : Option String := none
  deriving Repr, Inhabited

structure SettingsDraft where
  manualPeer : String := ""
  error : Option String := none
  peers : List PeerInfo := []
  resettingPeers : Bool := false
  catalog : Catalog := {}
  deriving Repr, Inhabited

structure ExportState where
  includeMnemonic : Bool := false
  /-- The staged backup file (ExportStagingFile), shared by path. -/
  file : Option String := none
  error : Option String := none
  busy : Bool := false
  deriving Repr, Inhabited

structure RevealState where
  words : List String := []
  revealing : Bool := false
  error : Option String := none
  copied : Bool := false
  deriving Repr, Inhabited

/-- AddPersonView's state. -/
structure PersonForm where
  mode : PersonMode := {}
  name : String := ""
  pasted : String := ""
  parsed : Option PastePreview := none
  error : Option String := none
  saving : Bool := false
  inferring : Bool := false
  inferredAddresses : List String := []
  inferredSource : Option String := none
  /-- The funding address picked, and where it came from. -/
  selectedFunding : Option (String × Provenance) := none
  /-- The lookup consent: the explorer and generation it was given for. -/
  lookupConsent : Option (String × Nat) := none
  deriving Repr, Inhabited

structure ShareCard where
  card : Option String := none
  error : Option String := none
  deriving Repr, Inhabited

inductive VaultRole where
  | scriptPath
  | muSig2
  deriving Repr, BEq, Inhabited

structure VaultCreate where
  name : String := ""
  role : VaultRole := .scriptPath
  threshold : Nat := 1
  cosigners : List String := []
  pasted : String := ""
  built : Option VaultBuild := none
  error : Option String := none
  saving : Bool := false
  deriving Repr, Inhabited

structure SavingsCreate where
  selected : List String := []
  threshold : Nat := 2
  name : String := ""
  nameEdited : Bool := false
  error : Option String := none
  creating : Bool := false
  created : Option String := none
  deriving Repr, Inhabited

structure SavingsAdd where
  pasted : String := ""
  error : Option String := none
  adding : Bool := false
  deriving Repr, Inhabited

/-- ApprovalView / VaultSpendSession. -/
structure ApprovalState where
  vaultID : String := ""
  pasted : String := ""
  review : Option ApprovalReview := none
  error : Option String := none
  busy : Bool := false
  broadcastTxid : Option String := none
  deriving Repr, Inhabited

/-- MuSig2SignView. Only flags here: the secret nonces live in the backend's signing session. -/
structure MusigState where
  vaultID : String := ""
  pasted : String := ""
  review : Option MusigReview := none
  error : Option String := none
  broadcastTxid : Option String := none
  broadcasting : Bool := false
  authorizing : Bool := false
  nonceSessionStarted : Bool := false
  signedThisSession : Bool := false
  /-- The backend holds round-1 secret nonces for this session. -/
  holdsNonces : Bool := false
  deriving Repr, Inhabited

/-- The wallet's answer at boot. -/
inductive BootResult where
  | opened (walletID : String)
  /-- A wallet created here whose recovery words were never confirmed written down: onboarding again. -/
  | backupPending (walletID : String)
  | missing
  | damaged (message : String)
  deriving Repr, Inhabited

structure Model where
  /-- While the screen is captured, recovery words are not drawn (ScreenCaptureMonitor). -/
  captured : Bool := false
  stage : Stage := .loading
  settings : Settings := {}
  status : Status := {}
  phase : SyncPhase := .idle
  walletID : Option String := none
  records : Records := {}
  /-- Advanced mode's tab: 0 wallet, 1 send, 2 settings. -/
  tab : Nat := 0
  /-- Test mode's `WINNOW_E2E_NETWORK`: the network cannot be switched away from it. -/
  forcedNetwork : Option Network := none
  /-- Pushed screens of the main navigation (beginner home, or the Wallet tab), innermost last. -/
  routes : List Route := []
  /-- Presented sheets, innermost last (a sheet presents the next one over itself). -/
  sheets : List Sheet := []
  confirm : Option Confirm := none
  /-- Expanded disclosure groups, by key. -/
  expanded : List String := []
  /-- The copy button showing "Copied", by key. -/
  copied : Option String := none
  onboarding : Onboarding := {}
  receive : Receive := {}
  labelEditor : LabelEditor := {}
  settingsDraft : SettingsDraft := {}
  send : SendState := {}
  payment : PaymentDetail := {}
  feeBump : FeeBump := {}
  exportState : ExportState := {}
  reveal : RevealState := {}
  person : PersonForm := {}
  shareCard : ShareCard := {}
  recipientsError : Option String := none
  vaultCreate : VaultCreate := {}
  savingsCreate : SavingsCreate := {}
  savingsAdd : SavingsAdd := {}
  /-- The savings card being shown: vault id, card text. -/
  savingsCardText : Option (String × String) := none
  approval : ApprovalState := {}
  musig : MusigState := {}
  /-- Paper shown in the Design papers sheet. -/
  paper : Option Nat := none
  /-- Bumped on suspend, network switch and rebuild: an answer from an older generation is dropped. -/
  generation : Nat := 0
  /-- `SensitivePresentationEpoch`: bumped whenever a sensitive presentation opens, resets or closes,
  and on background. A sensitive answer (phrase, export, signing round) counts only for its epoch. -/
  epoch : Nat := 0
  /-- `AppModel.exclusively(.spending)`: one payment is signed and broadcast at a time. -/
  spendingInFlight : Bool := false
  active : Bool := true
  deriving Repr, Inhabited

/-! ## Messages -/

/-- What changed in people/vaults, and what the screen does next. -/
inductive Done where
  | none
  | personSaved
  | senderLabeled
  | vaultSaved
  | vaultRemoved (id : String)
  | savingsCreated (id : String)
  | savingsAdded
  | labelSaved
  deriving Repr, Inhabited, BEq

/-- What the backend (Lean wallet + network, and iOS capabilities) reports. -/
inductive Host where
  /-- Test mode at launch (E2EMode): the forced network and the first tab; sent before `settingsLoaded`. -/
  | launched (forcedNetwork : Option Network) (tab : Nat)
  | settingsLoaded (s : Settings)
  | booted (gen : Nat) (r : BootResult)
  | created (gen : Nat) (words : List String)
  | imported (gen : Nat) (report : String)
  | snapshot (gen : Nat) (s : Status) (p : SyncPhase)
  | records (gen : Nat) (r : Records)
  | updated (gen : Nat) (d : Done) (r : Records)
  | receiveAddress (gen : Nat) (address : String)
  | unconfirmed (gen : Nat) (address txid : String) (amount : Int)
  | failed (gen : Nat) (context : String) (message : String)
  | deleted (gen : Nat)
  | resolvedRate (gen : Nat) (forInputs : SendInputs) (milli : Nat)
  | previewed (gen : Nat) (forInputs : SendInputs) (p : Preview)
  | sent (gen : Nat) (txid : String)
  | rawTransaction (gen : Nat) (txid : String) (hex : Option String)
  | relay (gen : Nat) (txid : String) (e : RelayEvent)
  | approvalPrepared (gen : Nat) (forInputs : SendInputs)
  | paymentLoaded (gen : Nat) (txid : String)
  | pendingRate (gen : Nat) (txid : String) (milli : Nat) (suggested : String)
  | bumpPreviewed (gen : Nat) (txid rateText : String) (p : FeeBumpPreview)
  | bumped (gen : Nat) (txid replacement : String)
  | catalogProgress (gen : Nat) (bytes : Nat)
  | catalogRefreshed (gen : Nat) (notice : String)
  | catalogStored (gen : Nat) (stored : String)
  | peers (gen : Nat) (ps : List PeerInfo)
  | peersReset (gen : Nat)
  | exported (gen epoch : Nat) (file : String)
  | revealed (gen epoch : Nat) (words : List String)
  | card (gen : Nat) (name : String) (card : String)
  | pasteParsed (gen : Nat) (text : String) (r : Except String PastePreview)
  | senderLookup (gen : Nat) (txid source : String) (addresses : List String)
  | ownKey (gen : Nat) (expression : String)
  | cosignerChecked (gen : Nat) (expression : String)
  | vaultBuilt (gen : Nat) (forCosigners : List String) (b : VaultBuild)
  | savingsCard (gen : Nat) (vaultID card : String)
  | approvalReviewed (gen : Nat) (vaultID : String) (r : ApprovalReview) (clearPasted : Bool)
  | approvalSent (gen : Nat) (vaultID txid : String)
  | musigReviewed (gen : Nat) (vaultID : String) (r : MusigReview) (clearPasted : Bool)
  | musigNonces (gen epoch : Nat) (vaultID : String) (r : MusigReview)
  | musigSigned (gen epoch : Nat) (vaultID : String) (r : MusigReview)
  | musigSent (gen epoch : Nat) (vaultID txid : String)
  | pasted (target : PasteTarget) (text : String)
  | copiedExpired (key : String)
  | scene (active : Bool)
  /-- The scene went inactive (still foreground: a system prompt, the app switcher): nothing changes. -/
  | sceneInactive
  /-- The screen is being recorded or mirrored (UIScreen.isCaptured): phrase grids are hidden. -/
  | captured (on : Bool)
  deriving Inhabited

inductive SendMsg where
  | setDestination (s : String)
  | setAmount (s : String)
  | setPriority (i : Nat)
  | setOverride (s : String)
  | setAccount (i : Nat)
  | pasteDestination
  | openRecipients
  | choosePerson (id : String)
  | clearPerson
  | review
  | sendPayment
  | editPayment
  | newPayment
  deriving Inhabited

inductive ReceiveMsg where
  | freshAddress
  | editLabel
  | setLabelDraft (s : String)
  | saveLabel
  | removeLabel
  | finishLabel
  | openCard
  | setOwnName (s : String)
  deriving Inhabited

inductive HomeMsg where
  | openPayment (txid : String)
  | openAccount (vaultID : String)
  | openBackup
  | pop
  | loadPayment
  | editRecipient (address : String) (personID : Option String)
  | removeRecipient (personID : String)
  | editPaymentLabel (address : String)
  | labelSender
  | attachSenderDestination (personID : String)
  | removeSenderLabel
  | sendToPerson (personID : String)
  | openFeeBump
  | setBumpRate (s : String)
  | reviewBump
  | bump
  deriving Inhabited

inductive SettingsMsg where
  | setManualPeer (s : String)
  | addManualPeer
  | removeManualPeer (i : Nat)
  | reconnect
  | setVerifyFromGenesis (b : Bool)
  | setExplorer (i : Nat)
  | setEsploraURL (s : String)
  | openReadSide
  | openPapers
  | openPaper (i : Nat)
  | closePaper
  | refreshCatalog
  | refreshPeers
  | askResetPeers
  | resetPeers
  | askDelete
  | deleteWallet
  | dismissTor
  deriving Inhabited

inductive BackupMsg where
  | openExport
  | setIncludeMnemonic (b : Bool)
  | createExport
  | confirmExport
  | reveal
  | copyPhrase
  deriving Inhabited

inductive PeopleMsg where
  | openAdd (mode : PersonMode) (address : String)
  | setName (s : String)
  | setPasted (s : String)
  | paste
  | chooseSaved (personID : String)
  | chooseFunding (address : String) (p : Provenance)
  | askInfer
  | infer
  | save
  | choose (personID : String)
  | rename (personID : String)
  | remove (personID : String)
  deriving Inhabited

inductive VaultMsg where
  | openCreate (role : VaultRole)
  | setName (s : String)
  | setRole (i : Nat)
  | setThreshold (n : Nat)
  | setPasted (s : String)
  | addPasted
  | addOwn
  | removeCosigner (i : Nat)
  | build
  | save
  | newAddress (vaultID : String)
  | send (vaultID : String)
  | openSigning (vaultID : String)
  | openBackup
  | openShare (vaultID : String)
  | askRemove (vaultID : String)
  | remove (vaultID : String)
  | openChooser
  | openSavingsCreate
  | openSavingsAdd
  | toggleCoOwner (personID : String)
  | setSavingsThreshold (n : Nat)
  | setSavingsName (s : String)
  | addCoOwner
  | createSavings
  | setSavingsCard (s : String)
  | pasteSavingsCard
  | addSavings
  deriving Inhabited

inductive ApprovalMsg where
  | setPasted (s : String)
  | paste
  | review
  | approve
  | finish
  deriving Inhabited

inductive MusigMsg where
  | setPasted (s : String)
  | paste
  | addReply
  | prepare
  | sign
  | broadcast
  | restart
  deriving Inhabited

inductive Msg where
  | createWallet
  | resumeBackup
  | openImport
  | setImportText (s : String)
  | pasteImport
  | importWallet
  | setWrittenDown (b : Bool)
  | copyBackupPhrase
  | finishOnboarding
  | closeSheet
  | setNetwork (i : Nat)
  | switchNetwork (net : Network)
  | askAdvanced
  | setAdvanced (b : Bool)
  | dismissConfirm
  | selectTab (i : Nat)
  | openReceive
  | openSend
  | copy (key text : String)
  | openExplorer (url exposedItem : String)
  | openURL (url : String)
  | setExpanded (key : String) (b : Bool)
  | syncNow
  | retryPeers
  | retryOpen
  | send (m : SendMsg)
  | receive (m : ReceiveMsg)
  | home (m : HomeMsg)
  | settings (m : SettingsMsg)
  | backup (m : BackupMsg)
  | people (m : PeopleMsg)
  | vault (m : VaultMsg)
  | approval (m : ApprovalMsg)
  | musig (m : MusigMsg)
  | host (h : Host)
  deriving Inhabited

/-! ## Commands -/

/-- What the app asks of the backend. Wallet and network commands carry the generation they belong to;
sensitive ones also carry the presentation epoch. -/
inductive Cmd where
  | boot
  | saveSettings (s : Settings)
  /-- `boot()` when `isBoot` (launch, Retry), `switchNetwork` otherwise: only a boot journals `app.booted`. -/
  | openWallet (gen : Nat) (network : Network) (isBoot : Bool)
  | createWallet (gen : Nat) (network : Network)
  | resumeBackup (gen : Nat)
  | importWallet (gen : Nat) (network : Network) (json : String)
  | finishOnboarding (gen : Nat)
  | refresh (gen : Nat)
  | syncNow (gen : Nat)
  | retryPeers (gen : Nat)
  | reconnect (gen : Nat) (settings : Settings)
  | receiveAddress (gen : Nat) (fresh : Bool)
  | watchAddress (gen : Nat) (address : String)
  | stopWatchingAddress
  | setReceiveLabel (gen : Nat) (address label : String)
  | copy (text : String) (policy : ClipPolicy)
  | timer (ms : Nat) (h : Host)
  | openURL (url : String)
  | deleteWallet (gen : Nat)
  | startNetworking (gen : Nat) (settings : Settings)
  | stopNetworking
  | resolveRate (gen : Nat) (inputs : SendInputs) (floor : Option Nat)
  | previewSend (gen : Nat) (inputs : SendInputs)
  | sendPayment (gen : Nat) (inputs : SendInputs) (p : Preview)
  | prepareVaultApproval (gen : Nat) (inputs : SendInputs) (p : Preview)
  | rawTransaction (gen : Nat) (txid : String)
  | watchRelay (gen : Nat) (txid : String)
  | loadPaymentDetails (gen : Nat) (txid : String)
  | pendingFeeRate (gen : Nat) (txid : String)
  | previewFeeBump (gen : Nat) (txid rateText : String) (milli : Nat)
  | bumpFee (gen : Nat) (txid : String) (p : FeeBumpPreview)
  | refreshCatalog (gen : Nat)
  | catalogStatus (gen : Nat)
  | connectedPeers (gen : Nat)
  | resetPeers (gen : Nat)
  /-- Export and stage the bundle as `fileName` in a fresh `winnow-export-*` directory of tmp. -/
  | exportBundle (gen epoch : Nat) (includeMnemonic : Bool) (fileName : String)
  /-- `ExportStagingFile.remove` for that file: its staging directory goes. -/
  | removeExport (file : String)
  | revealPhrase (gen epoch : Nat)
  | ownCard (gen : Nat) (name : String)
  | parsePaste (gen : Nat) (text : String) (forSigning : Bool)
  | addPerson (gen : Nat) (name : String) (paste : Option String) (forSigning : Bool)
      (provenance : Option Provenance) (source : Option String) (labelTxid : Option String)
  /-- Rename a person and keep them saved, first attaching a destination when they had none. -/
  | editPerson (gen : Nat) (personID name : String) (attach : Option (String × Provenance × Option String))
  | updateRecipient (gen : Nat) (personID : String) (name : Option String) (saved : Bool) (ctx : String)
  | labelSender (gen : Nat) (txid personID : String)
  | removeSenderLabel (gen : Nat) (txid : String)
  | lookupSender (gen : Nat) (txid baseURL : String)
  | ownKeyExpression (gen : Nat) (multipath : Bool)
  | checkCosigner (gen : Nat) (role : VaultRole) (existing : List String) (expression : String)
  | buildVault (gen : Nat) (role : VaultRole) (threshold : Nat) (cosigners : List String)
  | addVault (gen : Nat) (name descriptor : String)
  | removeVault (gen : Nat) (vaultID : String)
  | advanceVaultReceive (gen : Nat) (vaultID : String)
  | createSharedSavings (gen : Nat) (name : String) (personIDs : List String) (threshold : Nat)
  | addSharedSavings (gen : Nat) (card : String)
  | savingsCard (gen : Nat) (vaultID : String)
  | approvalAdd (gen : Nat) (vaultID : String) (working : Option String) (text : String)
  | approvalRecheck (gen : Nat) (vaultID working : String)
  | approvalApprove (gen : Nat) (vaultID working : String)
  | approvalFinish (gen : Nat) (vaultID working : String)
  | musigAdd (gen : Nat) (vaultID : String) (working : Option String) (text : String)
  | musigNonces (gen epoch : Nat) (vaultID working : String)
  | musigSign (gen epoch : Nat) (vaultID working : String)
  | musigBroadcast (gen epoch : Nat) (vaultID working : String)
  | musigRestart (gen : Nat) (vaultID working : String)
  /-- Re-review the working proposal against trusted local state (the coins or frontier moved). -/
  | musigRecheck (gen : Nat) (vaultID working : String)
  /-- Drop (scrub) the backend's MuSig2 secret nonces. -/
  | musigClear
  | paste (target : PasteTarget)
  /-- `e2e?.journal(name, fields:)` for what happens in the Model (test mode only; nothing otherwise). -/
  | journal (name : String) (fields : List (String × String))
  deriving Inhabited

instance : Lean.ToJson Cmd := ⟨fun _ => Lean.Json.null⟩

/-- `Review payment` is enabled when the amount is a positive number of sats and there is a destination
or a saved person. -/
def canReview (i : SendInputs) : Bool :=
  (i.personID.isSome || !i.destination.trimAscii.isEmpty) &&
  (match i.amount.trimAscii.copy.toNat? with | some n => n > 0 | none => false)

def networks : List Network := [.mainnet, .signet]

def appVersionText : String := "0.1.0 (1)"

/-! ## Small helpers every area uses -/

def Model.topSheet (m : Model) : Option Sheet := m.sheets.getLast?
def Model.hasSheet (m : Model) (s : Sheet) : Bool := m.sheets.contains s
def Model.present (m : Model) (s : Sheet) : Model := { m with sheets := m.sheets ++ [s], confirm := none }
def Model.isExpanded (m : Model) (key : String) : Bool := m.expanded.contains key
def Model.person? (m : Model) (id : String) : Option Person := m.records.people.find? (·.id == id)
def Model.vault? (m : Model) (id : String) : Option VaultSummary := m.records.vaults.find? (·.id == id)
def Model.historyItem? (m : Model) (txid : String) : Option HistoryItem := m.status.history.find? (·.txid == txid)

/-- Leave the current wallet/network generation: every answer still in flight is dropped. -/
def Model.nextGeneration (m : Model) : Model :=
  { m with generation := m.generation + 1, epoch := m.epoch + 1, spendingInFlight := false }

end WinnowApp
