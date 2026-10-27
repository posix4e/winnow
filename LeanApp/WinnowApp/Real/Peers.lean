import WinnowApp.Real.Send

/-! # Networking controls: start/stop, reconnect, retry, the census line, peers

AppModel.swift: `scenePhaseChanged` (:553: active → `activate`, background → suspend + stop),
`retryPeerDiscovery` (:593), `reconnect` (:2586), `candidateCount` (:2636), `resetPeers` (:2642);
SettingsView's census line (the list each build ships; upstream e5ce950 removed the download and its
Refresh button) and peer rows. -/

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

/-- SettingsView's census line: the list this build ships (`CensusCatalog.bundled`), or the sentence for
a build without one. -/
def catalogStatus (env : Env) : IO String := do
  match ← env.deps.census with
  | some c => return s!"Observed {c.date}: {candidateCount c}."
  | none => return "This build carries no peer list. Winnow uses saved peers and, when clearnet is allowed, DNS seeds."

/-- SettingsView's connected-peer rows. -/
def connectedPeers (env : Env) : IO (List PeerInfo) := do
  let some s := (← env.get).stack | return []
  let mut out := #[]
  for p in ← s.pool.connectedPeers do
    out := out.push { endpoint := p.endpoint.description, userAgent := ← p.peerUserAgent,
                      startHeight := (← p.peerStartHeight).toInt, feeFilter := (← p.feeFilter).map natOf }
  return out.toList

/-- `resetPeers()`: forget learned peers (manual peers and the shipped list stay), avoid the current ones
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
