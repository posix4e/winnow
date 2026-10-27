import Std.Sync.Mutex
import Winnow.IO
import Winnow.Wallet.Wallet
import Winnow.Wallet.FeePolicy
import WinnowApp.Backend
import WinnowApp.Pure

/-! # `Backend.real`: shared state, injected capabilities, error texts

The Swift `AppModel` is a `@MainActor` class whose async methods interleave at every `await`. Here the
backend's own state (wallet, stack, generation, in-flight flags, the reviewed previews) is one `Core`
value behind one `Std.Mutex`; every operation takes the lock only for short reads and claims (copy out,
unlock, do the I/O, lock again and re-check the generation before writing back), which is the actor's
reentrancy. The lock is never held across wallet, pool or file I/O, and never taken twice on a thread.

The `Wallet` actor's own isolation is a second lock (`walletLock`) around each wallet mutation (apply,
commit, record scan height, roll back, remember, receive index); wallet reads are atomic `IO.Ref` reads.

Platform dependencies come in as `Deps`: the secret store (`KeyStore IO`, the Keychain capability on
iOS), the HTTPS fetch (`http.get`), randomness, the wall clock, and the loop intervals. `Hooks` is the
seam for the records half (vaults, people, labels), which another module fills in; its defaults are
"nothing stored" or `notPorted`. -/

namespace WinnowApp.Real
open Winnow Winnow.IO Winnow.Net

/-- Network-name bridges between the app's `Network` and WalletCore's. -/
def Network.tx : WinnowApp.Network → Tx.BitcoinNetwork
  | .mainnet => .mainnet | .signet => .signet | .regtest => .regtest

def Network.net : WinnowApp.Network → Net.BitcoinNetwork
  | .mainnet => .mainnet | .signet => .signet | .regtest => .regtest

/-! ## The seam for the records half -/

/-- What the core needs from vaults, people and labels (the records half plugs these in). -/
structure Hooks where
  /-- `vaultStore.configure` for the network's directory: `some message` when the store is damaged. -/
  configure : WinnowApp.Network → (dir : String) → IO (Option String) := fun _ _ => pure none
  /-- `vaultStore.watchScripts(network:)`. -/
  vaultWatchScripts : IO (Array ByteArray) := pure #[]
  /-- `vaultStore.apply(match:network:)`. -/
  vaultApply : BlockMatch → IO Unit := fun _ => pure ()
  /-- `vaultStore.rollBack(to:)`. -/
  vaultRollBack : UInt32 → IO Unit := fun _ => pure ()
  /-- `VaultStore.validate(bundle.vaults, network:)`. -/
  validateBundleVaults : Array VaultRecord → WinnowApp.Network → IO Unit := fun _ _ => pure ()
  /-- `vaultStore.restore(bundle.vaults)`. -/
  restoreVaults : Array VaultRecord → IO Unit := fun _ => pure ()
  /-- `vaultStore.backupRecords()` for an exported bundle (`none`: no vault section). -/
  backupVaults : IO (Option (Array VaultRecord)) := pure none
  /-- `nextPaymentAddress(for:)` of a saved person: address, index, the review's recipient. -/
  personPayment : (personID : String) → IO (String × UInt32 × PreviewRecipient) :=
    fun _ => notPorted "Paying a saved person"
  /-- `advancePersonPaymentIndex(id:past:)` after a send to a person commits. -/
  advancePersonIndex : (personID : String) → UInt32 → IO Unit := fun _ _ => pure ()
  /-- `ownedVaultScripts`: outputs paying a vault are not shown as payments to someone else. -/
  ownedVaultScripts : IO (Array ByteArray) := pure #[]
  /-- The vaults as `journalSnapshotIfChanged` summarizes them: id, balance, coins, confirmed coins. -/
  vaultSummaries : IO (Array (String × Int64 × Nat × Nat)) := pure #[]

instance : Inhabited Hooks := ⟨{}⟩

/-- Platform capabilities and tunables, injected (`Backend.real` builds nothing platform-specific). -/
structure Deps where
  keyStore : Keys.KeyStore IO
  fetch : HttpFetch
  random : Randomness := .system
  /-- Wall clock, seconds since 1970 (census freshness). -/
  wallSeconds : IO Int := Winnow.IO.wallSeconds
  /-- `PeerPool(peerCount:)` (3 in the app). -/
  peerCount : Nat := 3
  /-- The sync loop's interval (45 s in the app). -/
  syncIntervalMs : Nat := 45_000
  /-- The phase ticker's interval (1 s). -/
  phaseIntervalMs : Nat := 1_000
  /-- The census publisher keys. -/
  censusKeys : List ByteArray := Keys.CensusPublisher.trustedKeys
  /-- `CensusCatalogStore(minimumEntries:)`: 0 in test mode. -/
  censusMinimumEntries : Nat := CensusCatalog.minimumClearnetEntries
  /-- Where the census is downloaded from (test mode reads its control file each time). -/
  censusURL : IO String := pure CensusCatalog.endpointURL
  /-- The sync stack's parameters in place of the network's (test mode's custom signet). -/
  networkParams : Option NetworkParams := none
  /-- Pinned wallet entropy (test mode); none draws it from `random`. -/
  entropy : Option ByteArray := none
  /-- `e2e?.journal(_:fields:)`: test mode's event journal; a no-op otherwise. -/
  journal : String → List (String × String) → IO Unit := fun _ _ => pure ()
  hooks : Hooks := {}

/-! ## AppModel's errors and the texts the app shows -/

/-- `AppModel.AppError` (AppModel.swift:52–96), the cases the core throws. -/
inductive AppError where
  | noWallet | noStack | noPeers | mnemonicUnavailable
  | invalidPeer (text : String)
  | wrongNetwork (network : String)
  | sendReviewChanged
  | storageDamaged (message : String)
  | spendAlreadyInFlight
  | noStorage
  | paymentDetailsUnavailable

def AppError.text : AppError → String
  | .noWallet => "No wallet is open."
  | .paymentDetailsUnavailable => "Payment details aren’t available on this phone."
  | .noStack => "The sync stack is not running."
  | .noPeers => "No peers reachable. Check the network connection or add a manual peer in Settings."
  | .mnemonicUnavailable => "The new wallet's mnemonic could not be read back from the Keychain."
  | .invalidPeer t => s!"Invalid peer “{t}” — use host:port."
  | .wrongNetwork n => s!"This bundle is for {n}; switch the network in Settings first."
  | .sendReviewChanged => "The available coins, fee, or change changed. Review the payment again before signing."
  | .storageDamaged m => m
  | .spendAlreadyInFlight => "Another payment is already being signed and broadcast. Wait for it to finish."
  | .noStorage => "Winnow could not reach its storage, so a chain reorganisation could not be recorded. Syncing has stopped rather than continue on stale data."

def failWith {α} (e : AppError) : IO α := throw (IO.userError e.text)
def failText {α} (t : String) : IO α := throw (IO.userError t)

/-- `AddressError.errorDescription` (AddressDecoder.swift). -/
def addressErrorText : AddressError → String
  | .invalidAddress _ => "That address is invalid or unsupported by Winnow."
  | .wrongNetwork _ => "That address belongs to a different Bitcoin network."
  | .unsupportedWitnessVersion v =>
    s!"That address uses future Bitcoin witness version {v}. Winnow cannot safely send to it before the output type is activated."
  | .unsupportedWitnessProgram v l => s!"That address uses an unsupported witness-v{v} program length ({l} bytes)."

/-- `KeyStoreError.errorDescription`. -/
def keyStoreErrorText (e : Keys.KeyStoreError) : String :=
  match e.errorDescription with
  | some t => t
  | none => match e with
    | .keychain s => s!"The device could not reach the protected wallet key (keychain status {s})."
    | _ => "The protected wallet key could not be read."

/-- Text for a failure another module reports only by its case name (its payload was dropped where
it was lifted into `WalletFailure.named`). -/
def namedText (n : String) : String :=
  match n with
  | "noUTXOs" => "There are no spendable coins."
  | "insufficientFunds" => "Insufficient funds for this payment and its fee."
  | "notFound" => "The protected key for this wallet is missing from this device."
  | "alreadyExists" => "This device already contains a protected key for this wallet."
  | "malformedSecret" => "The protected wallet key is damaged or has an unsupported format."
  | "dataCorrupted" => "The data couldn’t be read because it isn’t in the correct format."
  | n => s!"The operation couldn’t be completed. (WalletCore.{n})"

/-- `localizedDescription` of a wallet failure. -/
def _root_.Winnow.WalletFailure.text : WalletFailure → String
  | .wallet e => e.description
  | .feeBump e => e.description
  | .named n => namedText n
  | .io e => toString e

/-- Runs a wallet operation in `IO`, failing with the text the app shows. -/
def runWM {α} (x : WM α) : IO α := do
  match ← x.run with
  | .ok a => pure a
  | .error e => throw (IO.userError e.text)

/-- Runs an I/O-area operation in `IO`, failing with its `localizedDescription`. -/
def runNet {α} (x : NetM α) : IO α := do
  match ← x.attempt with
  | .ok a => pure a
  | .error e => throw (IO.userError e.description)

/-- A wallet failure inside a network callback (`onMatch`): the text rides along as `other`. -/
def WM.toNet {α} (x : WM α) : NetM α := do
  match ← (x.run : IO _) with
  | .ok a => pure a
  | .error e => throw (.other e.text)

/-- A network failure inside a wallet operation (`ScanSource.sync`). -/
def NetM.toWM {α} (x : NetM α) : WM α := ExceptT.mk do
  match ← x.attempt with
  | .ok a => return .ok a
  | .error e => return .error (.io (IO.userError e.description))

/-- `ImportBundle.decode` failures as Swift shows them. -/
def importFailureText : ImportBundle.Failure → String
  | .wallet e => e.description
  | .decoding _ => "The data couldn’t be read because it isn’t in the correct format."

/-- `CensusCatalogStore.replace` failures. -/
def censusErrorText : CensusError → String
  | .invalid e => s!"Invalid census peer list: {e.name}."
  | .signature e => e.errorDescription
  | .decoding _ => "The data couldn’t be read because it isn’t in the correct format."
  | .io r => r

/-! ## Rates and amounts -/

/-- A sat/vB rate in thousandths (the app's unit), rounded. -/
def milliOf (rate : Float) : Nat :=
  if rate.isNaN || rate ≤ 0 then 0 else (rate * 1000).round.toUInt64.toNat

def rateOfMilli (milli : Nat) : Float := milli.toFloat / 1000

def i64 (n : Nat) : Int64 := Int64.ofInt n
def natOf (v : Int64) : Nat := v.toInt.toNat

/-! ## The state -/

/-- What a stack was built for: changing any of it rebuilds the stack. -/
structure StackKey where
  network : WinnowApp.Network
  manualPeers : List String
  verifyFromGenesis : Bool
  deriving BEq

/-- `AppModel.SyncStack`: peer pool, header chain, filter sync (once a wallet exists), broadcaster. -/
structure Stack where
  pool : PeerPool
  chain : HeaderStore
  filters : Option FilterSyncIO
  broadcaster : TxBroadcaster
  key : StackKey

/-- An open mempool window and the event stream its consumer reads. -/
structure Window where
  window : MempoolWindowIO
  events : EventStream MempoolEvent Unit

/-- `AppModel.SendPreview` as WalletCore built it: the app's `Preview` is only its summary, so the
authorization-relevant parts (payments, exact rate, outpoints, change) stay here. -/
structure SendReview where
  inputs : SendInputs
  summary : Preview
  payments : Array Payment
  feeRate : Float
  fee : Int64
  changeAmount : Option Int64
  selected : Array Transaction.Outpoint
  change : Option Payment
  recipient : Option (String × Option UInt32) := none

/-- The backend's state (AppModel's stored properties that are not UI). -/
structure Core where
  network : Option WinnowApp.Network := none
  /-- `storageDirectory()`: `<Application Support>/BTCSwift/<network>`. -/
  dir : Option String := none
  settings : Option Settings := none
  wallet : Option Wallet := none
  stack : Option Stack := none
  /-- `networkGeneration`: bumps on every suspend, network switch and rebuild. -/
  generation : Nat := 0
  /-- `isActive`: networking was asked for and not stopped. -/
  active : Bool := false
  buildingStack : Bool := false
  /-- `status.syncing` -/
  syncing : Bool := false
  /-- `operationsInFlight.contains(.spending)` -/
  spending : Bool := false
  /-- Identity of the current sync loop (`syncTask`); bumping it cancels the loop. -/
  loopToken : Nat := 0
  syncLoop : Option Nat := none
  /-- The generation the phase ticker (`phaseTask`) runs for. -/
  phaseLoop : Option Nat := none
  lastSyncError : Option String := none
  relayStoreQuarantined : Option String := none
  phase : SyncPhase := .idle
  receiveWindow : Option Window := none
  relayWindows : Array (Nat × Window) := #[]
  nextWatchId : Nat := 0
  reviews : Array SendReview := #[]
  bumps : Array (String × Winnow.FeeBumpPreview) := #[]
  refreshingCatalog : Bool := false
  peersToAvoid : Array PeerEndpoint := #[]
  http : RoutedHTTPClient
  /-- `lastE2EPeerFingerprint` / `lastE2ESnapshotFingerprint`: the last `peers.status` and
  `wallet.snapshot` journaled, so an unchanged one is not journaled again. -/
  lastPeerFingerprint : Option String := none
  lastSnapshotFingerprint : Option String := none
  /-- Diagnostics: sync passes started, phase ticks, loop threads alive. -/
  syncPasses : Nat := 0
  phaseTicks : Nat := 0
  liveLoops : Nat := 0

structure Env where
  deps : Deps
  core : Std.Mutex Core
  walletLock : Std.Mutex Unit

namespace Env

def get (env : Env) : IO Core := env.core.atomically (m := IO) MonadStateOf.get
def modify (env : Env) (f : Core → Core) : IO Unit := env.core.atomically (m := IO) (_root_.modify f)
def modifyGet {α} (env : Env) (f : Core → α × Core) : IO α := env.core.atomically (m := IO) (MonadStateOf.modifyGet f)

/-- One `Wallet` actor call: wallet mutations never interleave. -/
def walletOp {α} (env : Env) (x : WM α) : IO α :=
  env.walletLock.atomically (m := IO) (liftM (runWM x) : Std.AtomicT Unit IO α)

/-- The same inside a network callback. -/
def walletOpNet {α} (env : Env) (x : WM α) : NetM α := do
  let r : Except WalletFailure α ← (env.walletLock.atomically (m := IO) (liftM x.run : Std.AtomicT Unit IO _) : IO _)
  match r with
  | .ok a => pure a
  | .error e => throw (.other e.text)

def hooks (env : Env) : Hooks := env.deps.hooks

/-- `e2e?.journal(name, fields:)`. -/
def journal (env : Env) (name : String) (fields : List (String × String)) : IO Unit := env.deps.journal name fields

/-- The journal's dedup key (`fields.keys.sorted().map { "k=v" }.joined("|")`). -/
def _root_.WinnowApp.Real.journalFingerprint (fields : List (String × String)) : String :=
  "|".intercalate ((fields.toArray.qsort (fun a b => a.1 < b.1)).toList.map fun (k, v) => s!"{k}={v}")

/-- Journals `name` unless the last one journaled through `slot` had the same fields. The check and the
claim happen under the lock, so two concurrent callers cannot both journal one state. -/
def journalIfChanged (env : Env) (name : String) (fields : List (String × String))
    (slot : Core → Option String) (setSlot : Core → Option String → Core) : IO Unit := do
  let fp := journalFingerprint fields
  let changed ← env.modifyGet fun c => if slot c == some fp then (false, c) else (true, setSlot c (some fp))
  if changed then env.journal name fields

/-- A loop thread of this backend: counted while it runs. -/
def spawnLoop (env : Env) (body : IO Unit) : IO Unit := do
  env.modify fun c => { c with liveLoops := c.liveLoops + 1 }
  spawn do
    try body finally env.modify fun c => { c with liveLoops := c.liveLoops - 1 }

/-- Sleeps `ms` in short slices, returning early (false) once `alive` stops holding. -/
def sleepWhile (env : Env) (ms : Nat) (alive : Core → Bool) : IO Bool := do
  let deadline := (← IO.monoMsNow) + ms
  repeat
    if !alive (← env.get) then return false
    let now ← IO.monoMsNow
    if now ≥ deadline then return true
    IO.sleep (min 200 (deadline - now)).toUInt32
  return true

end Env

def walletPath (dir : String) : System.FilePath := System.FilePath.mk dir / "wallet.json"
def dirFile (dir name : String) : System.FilePath := System.FilePath.mk dir / name

def removeQuietly (p : System.FilePath) : IO Unit := do
  try IO.FS.removeFile p catch _ => pure ()

/-- `AppModel.parsePeer`: `host:port`, a non-empty host and a positive port. -/
def parsePeerEndpoint (text : String) : Option PeerEndpoint :=
  let parts := ((text.trimAscii.copy.splitOn ":").filter (!·.isEmpty))
  match parts with
  | [host, port] =>
    match port.toNat? with
    | some p => if p > 0 && p ≤ 65535 then some { host, port := p.toUInt16 } else none
    | none => none
  | _ => none

/-- The peers and settings scoped to `n` (`networkScopedSettings`). -/
def scopedFor (s : Settings) (n : WinnowApp.Network) : NetworkSettings :=
  match n with
  | .mainnet => s.mainnet | .signet => s.signet | .regtest => s.regtest

def keyFor (s : Option Settings) (n : WinnowApp.Network) : StackKey :=
  match s with
  | some s => { network := n, manualPeers := (scopedFor s n).manualPeers, verifyFromGenesis := s.verifyFromGenesis }
  | none => { network := n, manualPeers := [], verifyFromGenesis := false }

end WinnowApp.Real
