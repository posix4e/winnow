import WinnowApp.Real.Assemble
import WinnowApp.Real.RecordsBackend

/-! # `Backend.real`: the core half with the records half plugged in

The records (`people.json`, `receive-labels.json` of the network directory) open where AppModel's
`configurePeople` runs: on every `Hooks.configure` (boot, adopting a wallet, deleting one). The core
reaches them through the other `Hooks`; the records fields of `Backend` reach the core through
`RecordsCtx`. (The vault store and the vault send path went with vaults, upstream 1cf93fb.) -/

namespace WinnowApp
open Winnow Winnow.IO

namespace Real
open RecordsReal

/-- The records of the open network directory. -/
structure RecordsHost where
  keys : StoreKeyVault
  current : IO.Ref (Option RecordsStore)
  /-- `e2e?.journal(_:fields:)`, handed to every store opened here. -/
  journal : String → List (String × String) → IO Unit := fun _ _ => pure ()

namespace RecordsHost

def new (keyStore : Keys.KeyStore IO) (journal : String → List (String × String) → IO Unit := fun _ _ => pure ()) :
    IO RecordsHost := do
  return { keys := StoreKeyVault.ofKeyStore keyStore, current := ← IO.mkRef none, journal }

/-- The open records; before the first `configure` there are none (`noWallet`). -/
def store (h : RecordsHost) : IO RecordsStore := do
  match ← h.current.get with
  | some s => return s
  | none => failWith .noWallet

/-- `configurePeople` for `dir`: re-read when the directory is the open one. Damage to people is a
notice, never `storageDamaged`, so this answers `none`. -/
def configure (h : RecordsHost) (n : WinnowApp.Network) (dir : String) : IO (Option String) := do
  match ← h.current.get with
  | some s =>
    if s.network == Network.tx n && s.dir == some (System.FilePath.mk dir) then s.configure
    else openAt
  | none => openAt
  return none
where
  openAt : IO Unit := do
    let s ← RecordsStore.open (Network.tx n) (some (System.FilePath.mk dir)) h.keys
    h.current.set (some { s with journal := h.journal })

def withStore {α} (h : RecordsHost) (none' : α) (f : RecordsStore → IO α) : IO α := do
  match ← h.current.get with
  | some s => f s
  | none => return none'

/-- `nextPaymentAddress(for:)` of a saved person, with the review's recipient. -/
def personPayment (h : RecordsHost) (personID : String) : IO (String × UInt32 × PreviewRecipient) := do
  let s ← h.store
  let some p := (← s.read).people.record? personID | RM.toIO (throw (.people .unknownPerson))
  let (address, index) ← RM.toIO (nextPaymentAddress s personID)
  return (address, index, { personID := p.id, name := p.name, derivesFreshAddresses := p.derivesFreshAddresses,
                            hasUnverifiedFundingDestination := p.hasUnverifiedFundingDestination })

def hooks (h : RecordsHost) : Hooks where
  configure := h.configure
  personPayment := h.personPayment
  advancePersonIndex := fun id index => h.withStore () fun s => discard <| advancePersonPaymentIndex s none id index

end RecordsHost

def RecordsHost.ctx (h : RecordsHost) (env : Env) : RecordsCtx :=
  { store := h.store, wallet := env.currentWallet, http := env.httpGet, journal := env.deps.journal }

end Real

/-- The real backend over the injected capabilities, with its diagnostics handle: the core half
(`Real/Assemble.lean`) and the records half (`Real/Records*.lean`) joined through `Hooks`. -/
def Backend.realWithEnv (deps : Real.Deps) : IO (Backend × Real.Env) := do
  let host ← Real.RecordsHost.new deps.keyStore deps.journal
  let env ← Real.Env.new { deps with hooks := host.hooks }
  let ctx := host.ctx env
  let base := ctx.install env.backend
  return ({ base with records := host.withStore {} fun _ => ctx.records }, env)

/-- The real backend: the Lean WalletCore, the network stack and the records behind every field. -/
def Backend.real (deps : Real.Deps) : IO Backend := do
  return (← Backend.realWithEnv deps).1

end WinnowApp
