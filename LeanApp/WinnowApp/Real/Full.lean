import WinnowApp.Real.Assemble
import WinnowApp.Real.RecordsBackend

/-! # `Backend.real`: the core half with the records half plugged in

The records (`vaults.json`, `people.json`, `receive-labels.json` of the network directory) open where
AppModel's `vaultStore.configure` and `configurePeople` run: on every `Hooks.configure` (boot, adopting a
wallet, deleting one). The core reaches them through the other `Hooks`; the records fields of `Backend`
reach the core through `RecordsCtx`. The vault path of `previewSend` and `prepareVaultApproval` lives
here, because it needs both halves. -/

namespace WinnowApp
open Winnow Winnow.IO

namespace Real
open RecordsReal

/-- The records of the open network directory, and what the vault send path keeps between calls. -/
structure RecordsHost where
  keys : StoreKeyVault
  current : IO.Ref (Option RecordsStore)
  sessions : MusigSessions
  /-- Reviewed vault sends (`SendPreview.source == .vault`): the inputs, the summary shown, the review. -/
  vaultReviews : IO.Ref (Array (SendInputs × Preview × VaultSendPreview))
  /-- `ownedVaultScripts`, recomputed only when a vault's watch range changes (AppModel's `didSet`). -/
  ownedCache : IO.Ref (Option (Array (String × UInt32 × UInt32) × Array ByteArray))
  /-- `e2e?.journal(_:fields:)`, handed to every store opened here. -/
  journal : String → List (String × String) → IO Unit := fun _ _ => pure ()

namespace RecordsHost

def new (keyStore : Keys.KeyStore IO) (journal : String → List (String × String) → IO Unit := fun _ _ => pure ()) :
    IO RecordsHost := do
  return { keys := StoreKeyVault.ofKeyStore keyStore, current := ← IO.mkRef none,
           sessions := ← MusigSessions.new, vaultReviews := ← IO.mkRef #[], ownedCache := ← IO.mkRef none, journal }

/-- The open records; before the first `configure` there are none (`noWallet`). -/
def store (h : RecordsHost) : IO RecordsStore := do
  match ← h.current.get with
  | some s => return s
  | none => failWith .noWallet

/-- `vaultStore.configure` + `configurePeople` for `dir`: re-read when the directory is the open one. -/
def configure (h : RecordsHost) (n : WinnowApp.Network) (dir : String) : IO (Option String) := do
  let result ← match ← h.current.get with
    | some s =>
      if s.network == Network.tx n && s.dir == some (System.FilePath.mk dir) then s.configure
      else openAt
    | none => openAt
  h.vaultReviews.set #[]
  h.ownedCache.set none
  return match result with | .damaged m => some m | _ => none
where
  openAt : IO OpenResult := do
    let (s, r) ← RecordsStore.open (Network.tx n) (some (System.FilePath.mk dir)) h.keys
    h.current.set (some { s with journal := h.journal })
    return r

def withStore {α} (h : RecordsHost) (none' : α) (f : RecordsStore → IO α) : IO α := do
  match ← h.current.get with
  | some s => f s
  | none => return none'

def ownedVaultScripts (h : RecordsHost) : IO (Array ByteArray) := h.withStore #[] fun s => do
  let vaults := (← s.read).vaults.records
  let key := vaults.map fun r => (r.id, r.nextReceiveIndex, r.nextChangeIndex)
  if let some (k, scripts) ← h.ownedCache.get then
    if k == key then return scripts
  let scripts := RecordsReal.ownedVaultScripts vaults s.network
  h.ownedCache.set (some (key, scripts))
  return scripts

/-- `nextPaymentAddress(for:)` of a saved person, with the review's recipient. -/
def personPayment (h : RecordsHost) (personID : String) : IO (String × UInt32 × PreviewRecipient) := do
  let s ← h.store
  let some p := (← s.read).people.record? personID | RM.toIO (throw (.people .unknownPerson))
  let (address, index) ← RM.toIO (nextPaymentAddress s personID)
  return (address, index, { personID := p.id, name := p.name, derivesFreshAddresses := p.derivesFreshAddresses,
                            hasUnverifiedFundingDestination := p.hasUnverifiedFundingDestination })

def hooks (h : RecordsHost) : Hooks where
  configure := h.configure
  vaultWatchScripts := h.withStore #[] fun s => RM.toIO (vaultWatchScripts s)
  vaultApply := fun m => h.withStore () fun s => RM.toIO (applyVaultMatch s m)
  vaultRollBack := fun fork => h.withStore () fun s => RM.toIO (rollBackVaults s fork)
  validateBundleVaults := fun records n => RM.toIO (VaultStore.validate records (Network.tx n))
  restoreVaults := fun records => do RM.toIO (restoreVaults (← h.store) records)
  backupVaults := h.withStore (some #[]) fun s => do return some (← RM.toIO (backupVaultRecords s))
  personPayment := h.personPayment
  advancePersonIndex := fun id index => h.withStore () fun s => discard <| advancePersonPaymentIndex s none id index
  ownedVaultScripts := h.ownedVaultScripts
  vaultSummaries := h.withStore #[] fun s => do
    return (← s.read).vaults.records.map fun r => (r.id, r.balance, r.utxos.size, (r.utxos.filter (·.height > 0)).size)

end RecordsHost

/-- `previewSend` for a vault (`accountID`): AppModel's fee rate, the vault's spend PSBT, kept for
`prepareVaultApproval`. -/
def previewVaultSend (env : Env) (h : RecordsHost) (vaultID : String) (inputs : SendInputs) : IO Preview := do
  let s ← h.store
  let feeRate ← resolveRate env inputs.priority (parseRateMilli inputs.override)
  let amount := inputs.amount.trimAscii.copy.toNat?.getD 0
  let tip ← env.tipHeight
  let phase ← updateSyncPhase env
  let (vp, summary) ← RM.toIO (RecordsReal.previewVaultSend s vaultID inputs.destination (i64 amount) (milliOf feeRate)
    tip phase.headerTipMayLagNetwork inputs.personID env.deps.random (exactRate := some feeRate))
  h.vaultReviews.modify fun a => ((a.filter (·.1 != inputs)).push (inputs, summary, vp)).extract 0 16
  return summary

/-- `prepareVaultApproval(_:)`: only a summary the review produced, still authorized by the vault now. -/
def prepareVaultApproval (env : Env) (h : RecordsHost) (inputs : SendInputs) (p : Preview) : IO Unit :=
  exclusively env do
    let s ← h.store
    let some (_, _, vp) := (← h.vaultReviews.get).find? (fun (i, q, _) => i == inputs && sameSummary q p)
      | failWith .sendReviewChanged
    discard <| RM.toIO (RecordsReal.prepareVaultApproval s (← env.currentWallet) vp (← env.tipHeight))
    -- `journalApproval("approval.requested", vaultID:fields:)`
    env.journal "approval.requested" [("base64", vp.psbt.base64), ("vaultID", vp.vaultID)]

def RecordsHost.ctx (h : RecordsHost) (env : Env) : RecordsCtx :=
  { store := h.store, wallet := env.currentWallet, tip := env.tipHeight, creationHeight := env.scanHeight,
    http := env.httpGet, broadcast := env.broadcast, sessions := h.sessions, journal := env.deps.journal,
    journalSnapshot := discard (snapshot env) }

end Real

/-- The real backend over the injected capabilities, with its diagnostics handle: the core half
(`Real/Assemble.lean`) and the records half (`Real/Records*.lean`) joined through `Hooks`. -/
def Backend.realWithEnv (deps : Real.Deps) : IO (Backend × Real.Env) := do
  let host ← Real.RecordsHost.new deps.keyStore deps.journal
  let env ← Real.Env.new { deps with hooks := host.hooks }
  let ctx := host.ctx env
  let base := ctx.install env.backend
  return ({ base with
    records := host.withStore {} fun _ => ctx.records
    previewSend := fun inputs => match inputs.accountID with
      | some id => Real.previewVaultSend env host id inputs
      | none => base.previewSend inputs
    prepareVaultApproval := fun inputs p => Real.prepareVaultApproval env host inputs p }, env)

/-- The real backend: the Lean WalletCore, the network stack and the records behind every field. -/
def Backend.real (deps : Real.Deps) : IO Backend := do
  return (← Backend.realWithEnv deps).1

end WinnowApp
