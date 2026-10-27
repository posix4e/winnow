import WinnowApp.Real.Send

/-! # Networking controls: start/stop, reconnect, retry, the census catalog, peers

AppModel.swift: `scenePhaseChanged` (:553: active → `activate`, background → suspend + stop),
`retryPeerDiscovery` (:593), `reconnect` (:2586), `refreshPeerCatalog` (:2612), `candidateCount`
(:2636), `resetPeers` (:2642); SettingsView's catalog line and peer rows. -/

namespace WinnowApp.Real
open Winnow Winnow.IO Winnow.Net

/-- The scene became active (`activate`), with these settings. A stack built for other settings
(manual peers, verify-from-genesis) is torn down first so the change takes effect. -/
def startNetworking (env : Env) (s : Settings) : IO Unit := do
  let restart ← env.modifyGet fun c =>
    let c := { c with settings := some s, active := true }
    match c.stack, c.network with
    | some st, some n => (st.key != keyFor (some s) n, c)
    | _, _ => (false, c)
  if restart then suspendAndStop env true
  activate env

/-- The scene went to the background: suspend, then stop (nothing of this generation keeps running). -/
def stopNetworking (env : Env) : IO Unit := suspendAndStop env false

/-- `reconnect()`: rebuild the stack so changed peer settings take effect. -/
def reconnect (env : Env) (s : Settings) : IO Unit := do
  env.modify fun c => { c with settings := some s }
  suspendAndStop env true
  env.modify fun c => { c with active := true }
  activate env

/-- `retryPeerDiscovery()`. -/
def retryPeers (env : Env) : IO Unit := do
  match (← env.get).stack with
  | some s => s.pool.retry
  | none => activate env

/-- `syncNow()`. -/
def syncNow (env : Env) : IO Unit := syncOnce env

/-- "977 candidates". -/
def candidateCount (c : CensusCatalog) : String :=
  let n := (c.clearnet.map (·.size)).getD 0
  s!"{n} {if n == 1 then "candidate" else "candidates"}"

def catalogStore (env : Env) (dir : String) : CensusCatalogStore :=
  let root := (System.FilePath.mk dir).parent.getD (System.FilePath.mk dir)
  { path := root / "mainnet" / "downloaded-census.json", minimumEntries := env.deps.censusMinimumEntries }

def cancelledRefreshText : String := "Refresh cancelled; previous peer list retained."

/-- `refreshPeerCatalog()`: the signed list through the routed client; the notice. -/
def refreshCatalog (env : Env) (progress : Nat → IO Unit) : IO String := do
  let claim ← env.modifyGet fun c =>
    if c.refreshingCatalog || !c.active then (none, c)
    else (some (c.generation, c.http, c.dir, c.network), { c with refreshingCatalog := true })
  let some (epoch, http, dir, network) := claim | failText cancelledRefreshText
  try
    let url ← env.deps.censusURL
    let data ← runNet (http.get url CensusCatalog.maximumBytes (progress := some progress))
    let signature ← runNet (http.get (url ++ ".sig") Keys.CensusSignature.maximumBytes)
    let c ← env.get
    let some dir := dir | failText cancelledRefreshText
    if c.generation != epoch || !c.active then failText cancelledRefreshText
    let download ← match ← (catalogStore env dir).replace data (some signature) (← env.deps.wallSeconds) env.deps.censusKeys with
      | .ok d => pure d
      | .error e => failText (censusErrorText e)
    if network == some .mainnet then
      if let some s := c.stack then
        match ← s.pool.updateCensusCatalog download.catalog with
        | .ok () => pure ()
        | .error e => failText s!"Invalid census peer list: {e.name}."
    env.journal "peers.catalogRefreshed" [("date", download.catalog.date), ("sha256", download.sha256)]
    return s!"Observed {download.catalog.date}: {candidateCount download.catalog}. Active peers unchanged."
  finally
    env.modify fun c => { c with refreshingCatalog := false }

/-- SettingsView's catalog line when no refresh notice is showing. -/
def catalogStatus (env : Env) : IO String := do
  let fallback := "Using bundled candidates. Downloaded catalogs expire after seven days."
  let some dir := (← env.get).dir | return fallback
  match ← (catalogStore env dir).load (← env.deps.wallSeconds) env.deps.censusKeys with
  | some d => return s!"Observed {d.catalog.date}: {candidateCount d.catalog}."
  | none => return fallback

/-- SettingsView's connected-peer rows. -/
def connectedPeers (env : Env) : IO (List PeerInfo) := do
  let some s := (← env.get).stack | return []
  let mut out := #[]
  for p in ← s.pool.connectedPeers do
    out := out.push { endpoint := p.endpoint.description, userAgent := ← p.peerUserAgent,
                      startHeight := (← p.peerStartHeight).toInt, feeFilter := (← p.feeFilter).map natOf }
  return out.toList

/-- `resetPeers()`: forget learned peers (manual peers and the catalog stay), avoid the current ones
first next time, and come back up. -/
def resetPeers (env : Env) : IO Unit := do
  let c ← env.get
  let avoid ← match c.stack with
    | some s => (·.map (·.endpoint)) <$> s.pool.connectedPeers
    | none => pure #[]
  env.modify fun c => { c with peersToAvoid := avoid }
  suspendAndStop env true
  try
    match c.stack, c.dir with
    | some s, _ => s.pool.forgetKnownGood
    | none, some d =>
      let f := dirFile d "peers.json"
      if ← f.pathExists then IO.FS.removeFile f
    | none, none => pure ()
  catch e =>
    env.modify fun c => { c with lastSyncError := some (toString e) }
    return
  env.journal "peers.reset" []
  activate env

end WinnowApp.Real
