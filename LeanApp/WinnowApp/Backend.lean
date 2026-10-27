import Lean.Data.Json
import WinnowApp.Model

/-! What the app needs from the wallet and the network: AppModel's async methods as IO actions. The
real implementation is the Lean WalletCore port (wired in as its areas land); until then `pending`
answers each operation with a plain "still being ported" failure, so the app runs end to end.

Every type here is an app-level summary (strings, numbers, small structures from `Types.lean`); the
backend keeps the WalletCore objects (wallet, stack, transactions being signed) to itself. Mutations of
people and labels answer with the fresh `Records`. -/

namespace WinnowApp

structure Backend where
  /-- Open the wallet of `network` stored under `dir` (wallet.json + the keychain secret). -/
  openWallet : Network → (dir : String) → IO BootResult
  /-- Create a wallet; the recovery words. -/
  createWallet : Network → (dir : String) → IO (List String)
  /-- Import a backup bundle (JSON); the verification report. -/
  importBundle : Network → (dir : String) → (json : String) → IO String
  finishOnboarding : IO Unit
  /-- `pendingBackupMnemonic`, after authentication: the words of a wallet whose backup is pending. -/
  pendingBackupWords : IO (List String)
  snapshot : IO (Status × SyncPhase)
  /-- People, sender and receive labels. -/
  records : IO Records
  receiveAddress : (fresh : Bool) → IO String
  /-- `setReceiveAddressLabel` (an empty label removes it). -/
  setReceiveLabel : (address label : String) → IO Records
  /-- Open the bounded mempool window on `address` (ReceiveView); `seen txid amount` per payment. -/
  watchAddress : (address : String) → (seen : String → Int → IO Unit) → IO Unit
  stopWatchingAddress : IO Unit
  deleteWallet : IO Unit
  startNetworking : Settings → IO Unit
  stopNetworking : IO Unit
  syncNow : IO Unit
  retryPeers : IO Unit
  /-- Tear the stack down and build it again with these settings (`reconnect`). -/
  reconnect : Settings → IO Unit
  /-- `resolvedFeeRate` (thousandths of sat/vB). -/
  resolveFeeRate : (priority : Nat) → (overrideMilli : Option Nat) → IO Nat
  /-- Winnow's `previewSend` (an address or a saved person). -/
  previewSend : SendInputs → IO Preview
  /-- Winnow's `send(preview:)` after authentication: rebuild, sign, check `authorizes`, broadcast,
  commit. The txid (display hex). -/
  sendPayment : SendInputs → Preview → IO String
  rawTransactionHex : (txid : String) → IO (Option String)
  /-- Follow a broadcast: broadcaster events plus mempool-window echoes, until it confirms. -/
  watchRelay : (txid : String) → (RelayEvent → IO Unit) → IO Unit
  loadPaymentDetails : (txid : String) → IO Unit
  /-- The pending rate in thousandths (shown) and the suggested replacement rate (`suggestedBumpText`, from the
  exact rate). -/
  pendingFeeRate : (txid : String) → IO (Nat × String)
  previewFeeBump : (txid : String) → (milli : Nat) → IO FeeBumpPreview
  /-- After authentication: sign and broadcast the reviewed replacement; its txid. -/
  bumpFee : (txid : String) → FeeBumpPreview → IO String
  /-- SettingsView's census line: "Observed …: N candidates." for the list this build ships, or the
  sentence for a build without one. -/
  catalogStatus : IO String
  connectedPeers : IO (List PeerInfo)
  resetPeers : IO Unit
  /-- The ImportBundle JSON (watch-only unless asked). -/
  exportBundle : (includeMnemonic : Bool) → IO String
  /-- After authentication: the recovery words. -/
  revealMnemonic : IO (List String)
  /-- `ownPersonCard(name:).serialized()`. -/
  ownCard : (name : String) → IO String
  /-- `PersonPaste.parse`. -/
  parsePaste : (text : String) → IO PastePreview
  /-- `addPerson` (+ `labelReceivedSender` when labelling a payment). -/
  addPerson : (name : String) → (paste : Option String) → Option Provenance →
    (source : Option String) → (labelTxid : Option String) → IO Records
  attachDestination : (personID paste : String) → Provenance → (source : Option String) → IO Records
  updateRecipient : (personID : String) → (name : Option String) → (saved : Bool) → IO Records
  labelSender : (txid personID : String) → IO Records
  removeSenderLabel : (txid : String) → IO Records
  /-- The consented explorer lookup of funding addresses. -/
  lookupSender : (txid baseURL : String) → IO (List String)

def notPorted (what : String) : IO α := throw (IO.userError s!"{what}: this part of Winnow is still being ported to Lean.")

def Backend.pending : Backend where
  openWallet := fun _ dir => do
    if ← System.FilePath.pathExists (System.FilePath.mk dir / "wallet.json") then
      pure (.damaged "A wallet file exists, but opening wallets is still being ported to Lean.")
    else pure .missing
  createWallet := fun _ _ => notPorted "Creating a wallet"
  importBundle := fun _ _ _ => notPorted "Importing a backup"
  finishOnboarding := pure ()
  pendingBackupWords := notPorted "Resuming a backup"
  snapshot := pure ({}, .idle)
  records := pure {}
  receiveAddress := fun _ => notPorted "Receiving"
  setReceiveLabel := fun _ _ => notPorted "Receive address labels"
  watchAddress := fun _ _ => pure ()
  stopWatchingAddress := pure ()
  deleteWallet := notPorted "Deleting the wallet"
  startNetworking := fun _ => pure ()
  stopNetworking := pure ()
  syncNow := notPorted "Syncing"
  retryPeers := pure ()
  reconnect := fun _ => pure ()
  resolveFeeRate := fun _ _ => notPorted "Fee rates"
  previewSend := fun _ => notPorted "Previewing a payment"
  sendPayment := fun _ _ => notPorted "Sending"
  rawTransactionHex := fun _ => pure none
  watchRelay := fun _ _ => pure ()
  loadPaymentDetails := fun _ => notPorted "Loading payment details"
  pendingFeeRate := fun _ => notPorted "Fee bumping"
  previewFeeBump := fun _ _ => notPorted "Fee bumping"
  bumpFee := fun _ _ => notPorted "Fee bumping"
  catalogStatus := pure "This build carries no peer list. Winnow uses saved peers and, when clearnet is allowed, DNS seeds."
  connectedPeers := pure []
  resetPeers := notPorted "Resetting peers"
  exportBundle := fun _ => notPorted "Backing up the wallet"
  revealMnemonic := notPorted "Showing the recovery phrase"
  ownCard := fun _ => notPorted "Your card"
  parsePaste := fun _ => notPorted "Reading addresses and cards"
  addPerson := fun _ _ _ _ _ => notPorted "Saving people"
  attachDestination := fun _ _ _ _ => notPorted "Saving people"
  updateRecipient := fun _ _ _ => notPorted "Saving people"
  labelSender := fun _ _ => notPorted "Sender labels"
  removeSenderLabel := fun _ => notPorted "Sender labels"
  lookupSender := fun _ _ => notPorted "Explorer lookups"

instance : Nonempty Backend := ⟨Backend.pending⟩

end WinnowApp
