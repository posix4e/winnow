import Lean.Data.Json
import WinnowApp.Model

/-! What the app needs from the wallet and the network: AppModel's async methods as IO actions. The
real implementation is the Lean WalletCore port (wired in as its areas land); until then `pending`
answers each operation with a plain "still being ported" failure, so the app runs end to end.

Every type here is an app-level summary (strings, numbers, small structures from `Types.lean`); the
backend keeps the WalletCore objects (wallet, stack, PSBTs being signed, MuSig2 secret nonces) to
itself. Mutations of people, vaults and labels answer with the fresh `Records`. -/

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
  /-- People, vaults (with their shared-savings reading), sender and receive labels. -/
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
  /-- Winnow's `previewSend` (address or person, wallet or vault). -/
  previewSend : SendInputs → IO Preview
  /-- Winnow's `send(preview:)` after authentication: rebuild, sign, check `authorizes`, broadcast,
  commit. The txid (display hex). -/
  sendPayment : SendInputs → Preview → IO String
  /-- `prepareVaultApproval`: the vault spend is still the reviewed one. -/
  prepareVaultApproval : SendInputs → Preview → IO Unit
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
  /-- Download the census catalog (`progress bytes`); the notice. -/
  refreshCatalog : (progress : Nat → IO Unit) → IO String
  /-- "Observed …: N candidates." or the bundled-candidates sentence. -/
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
  addPerson : (name : String) → (paste : Option String) → (forSigning : Bool) → Option Provenance →
    (source : Option String) → (labelTxid : Option String) → IO Records
  attachDestination : (personID paste : String) → Provenance → (source : Option String) → IO Records
  updateRecipient : (personID : String) → (name : Option String) → (saved : Bool) → IO Records
  labelSender : (txid personID : String) → IO Records
  removeSenderLabel : (txid : String) → IO Records
  /-- The consented explorer lookup of funding addresses. -/
  lookupSender : (txid baseURL : String) → IO (List String)
  ownKeyExpression : (multipath : Bool) → IO String
  /-- `VaultDraft.add`'s validation (shape, network, duplicate). -/
  checkCosigner : VaultRole → (existing : List String) → (expression : String) → IO Unit
  buildVault : VaultRole → (threshold : Nat) → (cosigners : List String) → IO VaultBuild
  addVault : (name descriptor : String) → IO Records
  removeVault : (vaultID : String) → IO Records
  advanceVaultReceive : (vaultID : String) → IO Records
  /-- The new vault's id with the records. -/
  createSharedSavings : (name : String) → (personIDs : List String) → (threshold : Nat) → IO (String × Records)
  addSharedSavings : (card : String) → IO Records
  sharedSavingsCard : (vaultID : String) → IO String
  /-- Decode a request (envelope or PSBT), combine with the working copy, review. -/
  approvalAdd : (vaultID : String) → (working : Option String) → (text : String) → IO ApprovalReview
  approvalRecheck : (vaultID working : String) → IO ApprovalReview
  /-- After authentication: add this phone's approval. -/
  approvalApprove : (vaultID working : String) → IO ApprovalReview
  approvalFinish : (vaultID working : String) → IO String
  musigAdd : (vaultID : String) → (working : Option String) → (text : String) → IO MusigReview
  /-- After authentication: round 1. The secret nonces stay in the backend's session. -/
  musigNonces : (vaultID working : String) → IO MusigReview
  /-- After authentication: round 2 with the session's nonces, which it then scrubs. -/
  musigSign : (vaultID working : String) → IO MusigReview
  musigBroadcast : (vaultID working : String) → IO String
  /-- Strip nonces, partial signatures and final fields; scrub the session. -/
  musigRestart : (vaultID working : String) → IO MusigReview
  /-- Re-review against trusted local state (`refreshSpendReview`). -/
  musigRecheck : (vaultID working : String) → IO MusigReview
  /-- Scrub the session's secret nonces. -/
  musigClear : IO Unit

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
  prepareVaultApproval := fun _ _ => notPorted "Vault payments"
  rawTransactionHex := fun _ => pure none
  watchRelay := fun _ _ => pure ()
  loadPaymentDetails := fun _ => notPorted "Loading payment details"
  pendingFeeRate := fun _ => notPorted "Fee bumping"
  previewFeeBump := fun _ _ => notPorted "Fee bumping"
  bumpFee := fun _ _ => notPorted "Fee bumping"
  refreshCatalog := fun _ => notPorted "Refreshing the peer list"
  catalogStatus := pure "Using bundled candidates. Downloaded catalogs expire after seven days."
  connectedPeers := pure []
  resetPeers := notPorted "Resetting peers"
  exportBundle := fun _ => notPorted "Backing up the wallet"
  revealMnemonic := notPorted "Showing the recovery phrase"
  ownCard := fun _ => notPorted "Your card"
  parsePaste := fun _ => notPorted "Reading addresses and cards"
  addPerson := fun _ _ _ _ _ _ => notPorted "Saving people"
  attachDestination := fun _ _ _ _ => notPorted "Saving people"
  updateRecipient := fun _ _ _ => notPorted "Saving people"
  labelSender := fun _ _ => notPorted "Sender labels"
  removeSenderLabel := fun _ => notPorted "Sender labels"
  lookupSender := fun _ _ => notPorted "Explorer lookups"
  ownKeyExpression := fun _ => notPorted "This device's key"
  checkCosigner := fun _ _ _ => notPorted "Vault keys"
  buildVault := fun _ _ _ => notPorted "Vault descriptors"
  addVault := fun _ _ => notPorted "Saving vaults"
  removeVault := fun _ => notPorted "Removing vaults"
  advanceVaultReceive := fun _ => notPorted "Vault addresses"
  createSharedSavings := fun _ _ _ => notPorted "Shared savings"
  addSharedSavings := fun _ => notPorted "Shared savings"
  sharedSavingsCard := fun _ => notPorted "Savings cards"
  approvalAdd := fun _ _ _ => notPorted "Approving requests"
  approvalRecheck := fun _ _ => notPorted "Approving requests"
  approvalApprove := fun _ _ => notPorted "Approving requests"
  approvalFinish := fun _ _ => notPorted "Approving requests"
  musigAdd := fun _ _ _ => notPorted "MuSig2 signing"
  musigNonces := fun _ _ => notPorted "MuSig2 signing"
  musigSign := fun _ _ => notPorted "MuSig2 signing"
  musigBroadcast := fun _ _ => notPorted "MuSig2 signing"
  musigRestart := fun _ _ => notPorted "MuSig2 signing"
  musigRecheck := fun _ _ => notPorted "MuSig2 signing"
  musigClear := pure ()

instance : Nonempty Backend := ⟨Backend.pending⟩

end WinnowApp
