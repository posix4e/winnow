import Lean.Data.Json

/-! The app-facing view of the wallet: what the screens show, already derived (the Model never holds
WalletCore objects, only these summaries). Mirrors AppModel's `Status`, `SyncPhase`, settings, stage,
and the records (people, vaults, labels) the screens read. The `Backend` fills them. -/

namespace WinnowApp
open Lean

inductive Network where
  | mainnet
  | signet
  | regtest
  deriving Repr, BEq, Inhabited, ToJson, FromJson

def Network.name : Network → String
  | .mainnet => "mainnet"
  | .signet => "signet"
  | .regtest => "regtest"

inductive Explorer where
  | blockstream
  | mempool
  | custom
  deriving Repr, BEq, Inhabited, ToJson, FromJson

/-- The settings Winnow keeps per network (#81: a signet peer or explorer must never be used on mainnet). -/
structure NetworkSettings where
  manualPeers : List String := []
  esploraURL : String := ""
  explorer : Explorer := .blockstream
  deriving Repr, Inhabited, BEq, ToJson

/-- AppModel's settings (UserDefaults in the original; `settings.json` here). -/
structure Settings where
  network : Network := .mainnet
  advancedMode : Bool := false
  verifyFromGenesis : Bool := false
  ownDisplayName : String := ""
  /-- The removed Tor option was on (shown once, then cleared). -/
  torRemovedNotice : Bool := false
  mainnet : NetworkSettings := {}
  signet : NetworkSettings := {}
  regtest : NetworkSettings := {}
  deriving Repr, Inhabited, ToJson

/-- Reads every field with its default when absent, so a settings file from an older build still loads. -/
instance : FromJson NetworkSettings where
  fromJson? j := pure
    { manualPeers := (j.getObjValAs? (List String) "manualPeers").toOption.getD []
      esploraURL := (j.getObjValAs? String "esploraURL").toOption.getD ""
      explorer := (j.getObjValAs? Explorer "explorer").toOption.getD
        (if ((j.getObjValAs? String "esploraURL").toOption.getD "").isEmpty then .blockstream else .custom) }

instance : FromJson Settings where
  fromJson? j := pure
    { network := (j.getObjValAs? Network "network").toOption.getD .mainnet
      advancedMode := (j.getObjValAs? Bool "advancedMode").toOption.getD false
      verifyFromGenesis := (j.getObjValAs? Bool "verifyFromGenesis").toOption.getD false
      ownDisplayName := (j.getObjValAs? String "ownDisplayName").toOption.getD ""
      torRemovedNotice := (j.getObjValAs? Bool "torRemovedNotice").toOption.getD false
      mainnet := (j.getObjValAs? NetworkSettings "mainnet").toOption.getD {}
      signet := (j.getObjValAs? NetworkSettings "signet").toOption.getD {}
      regtest := (j.getObjValAs? NetworkSettings "regtest").toOption.getD {} }

/-- `networkScopedSettings`: the peers and explorer of the selected network. -/
def Settings.scoped (s : Settings) : NetworkSettings :=
  match s.network with
  | .mainnet => s.mainnet
  | .signet => s.signet
  | .regtest => s.regtest

def Settings.withScoped (s : Settings) (f : NetworkSettings → NetworkSettings) : Settings :=
  match s.network with
  | .mainnet => { s with mainnet := f s.mainnet }
  | .signet => { s with signet := f s.signet }
  | .regtest => { s with regtest := f s.regtest }

def Settings.manualPeers (s : Settings) : List String := s.scoped.manualPeers

/-- One output of a wallet transaction, as the payment screens need it (the backend decodes the
transaction and renders each script; `address` is none for a non-standard script). -/
structure TxOut where
  index : Nat
  address : Option String
  /-- scriptPubKey, hex -/
  script : String
  amount : Nat
  /-- One of the wallet's own watch scripts (receive or change). -/
  ownedByWallet : Bool
  /-- A script of one of this phone's vaults. -/
  ownedByVault : Bool := false
  deriving Repr, Inhabited, BEq

/-- One row of the activity list (Winnow's `HistoryEntry`, with the transaction already decoded). -/
structure HistoryItem where
  /-- display hex -/
  txid : String
  height : Nat
  received : Int
  spent : Int
  fee : Option Int
  replacedBy : Option String := none
  /-- The decoded outputs; none while the raw transaction is not stored on this phone. -/
  outputs : Option (List TxOut) := none
  /-- Addresses this payment's inputs reveal (`FundingSources`), already rendered. -/
  fundingAddresses : List String := []
  deriving Repr, Inhabited, BEq

def HistoryItem.net (h : HistoryItem) : Int := h.received - h.spent

/-- AppModel's `Status`. -/
structure Status where
  balance : Int := 0
  utxoCount : Nat := 0
  history : List HistoryItem := []
  feeBumpable : List String := []
  peerCount : Nat := 0
  tipHeight : Nat := 0
  nextScanHeight : Nat := 0
  syncing : Bool := false
  lastSyncError : Option String := none
  relayStoreQuarantined : Option String := none
  feeFloorMilli : Option Nat := none
  deriving Repr, Inhabited

/-- AppModel's `SyncPhase`. -/
inductive SyncPhase where
  | idle
  | connecting (connected target : Nat)
  | headers (synced estimate : Nat)
  | filters (scanned tip : Nat)
  | synced
  | peerDiscoveryFailed
  deriving Repr, BEq, Inhabited

inductive SyncSummary where
  | syncing
  | synced
  | peersUnavailable
  deriving Repr, BEq

/-- `SyncPhase.summary`: the one line a beginner reads. -/
def SyncPhase.summary (p : SyncPhase) (syncing : Bool) : SyncSummary :=
  match p with
  | .peerDiscoveryFailed => .peersUnavailable
  | .synced => if syncing then .syncing else .synced
  | _ => .syncing

def SyncPhase.headerTipMayLagNetwork : SyncPhase → Bool
  | .filters .. | .synced => false
  | _ => true

inductive Stage where
  | loading
  | onboarding
  | ready
  | storageDamaged (message : String)
  deriving Repr, BEq, Inhabited

/-! ## People, vaults, labels -/

inductive Provenance where
  | supplied
  | localFunding
  | explorerFunding
  deriving Repr, BEq, Inhabited

/-- `PersonRecord`, as the screens read it. -/
structure Person where
  id : String
  name : String
  /-- Whether the person can be paid, and whether each payment derives a fresh address. -/
  payTo : Option Bool := none
  signerKey : Option String := none
  signerFingerprint : Option String := none
  nextPaymentIndex : Nat := 0
  savedRecipient : Option Bool := none
  provenance : Option Provenance := none
  deriving Repr, Inhabited, BEq

def Person.isSavedRecipient (p : Person) : Bool := p.payTo.isSome && p.savedRecipient != some false
def Person.canCoOwnSavings (p : Person) : Bool := p.signerKey.isSome
def Person.derivesFreshAddresses (p : Person) : Bool := p.payTo == some true
def Person.hasUnverifiedFundingDestination (p : Person) : Bool :=
  p.provenance == some .localFunding || p.provenance == some .explorerFunding

/-- One approving key of shared savings (`SharedSavings.Signer`). -/
structure Signer where
  fingerprint : String
  name : Option String
  isYou : Bool
  deriving Repr, Inhabited, BEq

structure VaultUtxo where
  txid : String
  vout : Nat
  amount : Nat
  height : Nat
  isCoinbase : Bool := false
  deriving Repr, Inhabited, BEq

/-- A `VaultRecord` with what its descriptor says (read from the descriptor, never from a label),
and, for script-path vaults, the shared-savings reading (`SharedSavings`). -/
structure VaultSummary where
  id : String
  name : String
  descriptor : String
  balance : Nat
  threshold : Nat
  signerCount : Nat
  isScriptPath : Bool
  /-- The address at `nextReceiveIndex`. -/
  receiveAddress : Option String
  utxos : List VaultUtxo := []
  coOwners : List String := []
  includesYou : Bool := false
  signers : List Signer := []
  deriving Repr, Inhabited, BEq

/-- People, vaults and local labels, as one snapshot (each mutation answers with a fresh one). -/
structure Records where
  people : List Person := []
  vaults : List VaultSummary := []
  /-- txid (display hex) → person id -/
  senderByTxid : List (String × String) := []
  /-- scriptPubKey hex → person id (`recipientByScript`) -/
  recipientByScript : List (String × String) := []
  /-- address → the owner's note (`ReceiveAddressLabelStore`) -/
  receiveLabels : List (String × String) := []
  peopleStorageNotice : Option String := none
  receiveLabelStorageNotice : Option String := none
  ownSignerFingerprint : Option String := none
  deriving Repr, Inhabited

/-! ## Results of individual operations -/

/-- What `PersonPaste.parse` read from a pasted address or card. -/
structure PastePreview where
  name : Option String := none
  /-- `some fresh` when it can be paid. -/
  payTo : Option Bool := none
  hasSignerKey : Bool := false
  deriving Repr, Inhabited, BEq

/-- A connected peer (SettingsView.PeerInfo). -/
structure PeerInfo where
  endpoint : String
  userAgent : String
  startHeight : Int
  /-- BIP133 feefilter, sat/kvB -/
  feeFilter : Option Nat
  deriving Repr, Inhabited

/-- `FeeBumpPreview`. -/
structure FeeBumpPreview where
  feeRateMilli : Nat
  fee : Nat
  change : Option Nat
  deriving Repr, Inhabited, BEq

/-- A descriptor built in VaultCreateView, with what its policy says. -/
structure VaultBuild where
  descriptor : String
  firstAddress : Option String
  threshold : Nat
  signerCount : Nat
  isScriptPath : Bool
  deriving Repr, Inhabited

/-- One broadcaster or mempool-window event about a sent transaction. -/
inductive RelayEvent where
  | announced (peerCount : Nat)
  | requested (peer : String)
  | echoed (peer : String)
  | feeFloorExceeded
  | confirmed
  deriving Repr, Inhabited

/-- `PaymentLabel` of a spend output. -/
inductive PayLabel where
  | savings (name : String)
  | person (name : String)
  | you
  | unknown
  deriving Repr, Inhabited, BEq

structure SpendLine where
  label : PayLabel
  address : String
  amount : Nat
  isVaultOwned : Bool
  deriving Repr, Inhabited

/-- A shared-savings request after review (VaultSpendSession's state, without the PSBT object). -/
structure ApprovalReview where
  /-- The working PSBT, base64 (public data; dropped with the sheet). -/
  working : String
  /-- The envelope to share back. -/
  output : String
  rawPSBT : Option String := none
  /-- none when the request cannot be reviewed against local state (the message says why). -/
  lines : Option (List SpendLine)
  reviewError : Option String := none
  fee : Option Nat := none
  threshold : Nat
  /-- Signer positions that signed every input. -/
  approvals : List Nat := []
  signerNames : List (Nat × String) := []
  ownPosition : Option Nat := none
  deriving Repr, Inhabited

/-- A MuSig2 proposal after review. The secret nonces never appear here: the backend keeps them. -/
structure MusigReview where
  working : String
  output : String
  lines : Option (List SpendLine)
  reviewError : Option String := none
  fee : Option Nat := none
  sighashTypes : List Nat := []
  version : Nat := 2
  locktime : Option Nat := none
  sequences : List Nat := []
  participantCount : Option Nat := none
  minNonces : Nat := 0
  minPartialSigs : Nat := 0
  deriving Repr, Inhabited

end WinnowApp
