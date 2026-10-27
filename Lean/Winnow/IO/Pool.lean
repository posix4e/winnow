import Std.Data.HashMap
import Std.Data.HashSet
import Winnow.IO.Headers
import Winnow.IO.Seeds
import Winnow.IO.Census

/-! # The peer pool (`Network/Peers/PeerPool.swift`)

A small pool of outbound peers (default 3). Candidates: manual endpoints, the persisted good peers
(`peers.json`, version 2 with source classes), the census catalog's clearnet list when it is at most
7 days old (else the network's fallback peers), shuffled, with `avoidOnReset` endpoints last — and
DNS seeds only when those cannot fill the pool. A round dials up to `maxParallelDials` (5) at once,
each with `dialTimeout` (5 s), at most `maxDialAttempts` (50) per round, skipping candidates the
diversity policy refuses (re-checked on arrival); stragglers are awaited and disconnected; a round
that ends below target is `exhausted`. A monitor prunes dead connections and replenishes every 30 s.

Judgement, as in Swift (#82): `misbehaving` (a data fault) disconnects, removes from the persisted
good list and refuses for the session; `transportFailure` (slow, dropped) cools the endpoint off for
30 s doubling to 600 s per consecutive failure, cleared on the next success. After every header sync
and dial round, seats whose handshake height is more than 100 blocks below the validated header tip
are unseated (judged once per seat; manual peers exempt), dropped from the good list and cooled for
600 s. `syncHeaders` fails over across peers (6 burned at most, 12 transport retries), asks other
peers claiming a much taller tip to catch up, and condemns a primary that claimed a taller tip and
delivered nothing.

State is one `IO.Ref` updated atomically; dials run on dedicated threads and report to the round
through an `EventStream`. The clock is injectable (`now`, monotonic milliseconds). -/

namespace Winnow.IO
open Winnow.Net

structure PoolState where
  peers : Array PeerConnection := #[]
  /-- Insertion-ordered set (Swift's `Set`, whose order is unspecified). -/
  knownGood : Array PeerEndpoint := #[]
  knownSource : Std.HashMap PeerEndpoint PeerSource := {}
  seatedSources : Std.HashMap PeerEndpoint PeerSource := {}
  inFlight : Array (PeerEndpoint × PeerConnection) := #[]
  started : Bool := false
  replenishing : Bool := false
  attemptsThisRound : Nat := 0
  exhausted : Bool := false
  rejectedForSession : Std.HashSet PeerEndpoint := {}
  cooldownUntil : Std.HashMap PeerEndpoint Nat := {}
  consecutiveTransportFailures : Std.HashMap PeerEndpoint Nat := {}
  lastRejection : Std.HashMap PeerEndpoint String := {}
  validatedTip : Option UInt32 := none
  staleTipJudged : Std.HashSet PeerEndpoint := {}
  censusCatalog : Option CensusCatalog := none
  monitorGeneration : Nat := 0

/-- The UI snapshot (`ConnectionStatus`). -/
structure ConnectionStatus where
  connected : Nat
  target : Nat
  dialing : Bool
  attempts : Nat
  exhausted : Bool
  deriving Repr, BEq

structure PeerPool where
  params : NetworkParams
  peerCount : Nat
  manualPeers : Array PeerEndpoint
  peersFile : Option System.FilePath
  relayPreference : Bool
  dialTimeoutMs : Nat
  maxParallelDials : Nat
  maxDialAttempts : Nat
  seedResolver : SeedResolver
  /-- Wall clock in seconds for the census freshness rule (`catalogNow`). -/
  catalogNow : IO Int
  avoidOnReset : Array PeerEndpoint
  /-- Monotonic milliseconds for cooldowns (`now`). -/
  now : IO Nat
  monitorIntervalMs : Nat
  state : IO.Ref PoolState

namespace PeerPool

def transportCooldownBaseMs : Nat := 30_000
def transportCooldownCapMs : Nat := 600_000
def staleTipTolerance : Int := 100

/-- `base × 2^(failures - 1)`, capped. -/
def cooldown (failures : Nat) (base : Nat := transportCooldownBaseMs) (cap : Nat := transportCooldownCapMs) : Nat := Id.run do
  let mut interval := base
  for _ in [1:max 1 failures] do
    let doubled := interval + interval
    if !(doubled < cap) then return cap
    interval := doubled
  return min interval cap

/-- The pool. On iOS the app must pass `seedResolver` (or `httpFetch` from the shell's `http.get`
capability): the default `curlFetch` runs a `curl` subprocess and exists for tests on macOS only. -/
def new (params : NetworkParams) (peerCount : Nat := 3) (manualPeers : Array PeerEndpoint := #[])
    (peersFile : Option System.FilePath := none) (relayPreference : Bool := false) (dialTimeoutMs : Nat := 5_000)
    (maxParallelDials : Nat := 5) (maxDialAttempts : Nat := 50) (seedResolver : Option SeedResolver := none)
    (censusCatalog : Option CensusCatalog := none) (catalogNow : IO Int := wallSeconds)
    (avoidOnReset : Array PeerEndpoint := #[]) (now : IO Nat := monoMs) (monitorIntervalMs : Nat := 30_000)
    (httpFetch : HttpFetch := curlFetch) : IO PeerPool := do
  let resolver : SeedResolver ← match seedResolver with
    | some r => pure r
    | none => pure (SeedResolver.routed (← RoutedHTTPClient.new httpFetch))
  let nowS ← catalogNow
  let catalog := censusCatalog.bind fun c => (c.validated nowS).toOption
  let mut st : PoolState := { censusCatalog := catalog }
  if let some p := peersFile then
    if let some data ← PersistedPeers.boundedRead p then
      if let some stored := PersistedPeers.decode data then
        for c in stored do
          if !st.knownGood.contains c.endpoint then
            st := { st with knownGood := st.knownGood.push c.endpoint,
                            knownSource := st.knownSource.insert c.endpoint c.source }
  return { params, peerCount, manualPeers, peersFile, relayPreference, dialTimeoutMs, maxParallelDials,
           maxDialAttempts, seedResolver := resolver, catalogNow, avoidOnReset, now, monitorIntervalMs,
           state := ← IO.mkRef st }

def connectionStatus (p : PeerPool) : BaseIO ConnectionStatus := do
  let s ← p.state.get
  return { connected := s.peers.size, target := p.peerCount, dialing := s.replenishing,
           attempts := s.attemptsThisRound, exhausted := s.exhausted }

/-- Currently connected peers (snapshot). -/
def connectedPeers (p : PeerPool) : BaseIO (Array PeerConnection) := do return (← p.state.get).peers

def randomPeer (p : PeerPool) : IO (Option PeerConnection) := do
  let ps ← p.connectedPeers
  if ps.isEmpty then return none
  return ps[(← randomU64).toNat % ps.size]?

def source (p : PeerPool) (e : PeerEndpoint) : BaseIO (Option PeerSource) := do return (← p.state.get).knownSource[e]?
def rejectionReason (p : PeerPool) (e : PeerEndpoint) : BaseIO (Option String) := do return (← p.state.get).lastRejection[e]?
def rejectionReasons (p : PeerPool) : BaseIO (Std.HashMap PeerEndpoint String) := do return (← p.state.get).lastRejection
def knownGood (p : PeerPool) : BaseIO (Array PeerEndpoint) := do return (← p.state.get).knownGood

def isCoolingDown (p : PeerPool) (e : PeerEndpoint) : IO Bool := do
  match (← p.state.get).cooldownUntil[e]? with
  | some deadline => return (← p.now) < deadline
  | none => return false

/-- Endpoints only unavailable because they are cooling off. -/
def coolingEndpoints (p : PeerPool) : IO (Array PeerEndpoint) := do
  let now ← p.now
  return (← p.state.get).cooldownUntil.fold (fun acc e deadline => if now < deadline then acc.push e else acc) #[]

def transportSucceeded (p : PeerPool) (e : PeerEndpoint) : BaseIO Unit :=
  p.state.modify fun s => { s with consecutiveTransportFailures := s.consecutiveTransportFailures.erase e,
                                   cooldownUntil := s.cooldownUntil.erase e }

private def persistKnownGood (p : PeerPool) : IO Unit := do
  let some path := p.peersFile | return
  let s ← p.state.get
  let stored := (s.knownGood.extract 0 100).map fun e => { endpoint := e, source := s.knownSource[e]?.getD .persisted : PeerCandidate }
  try writeAtomic path (PersistedPeers.encode stored) catch _ => pure ()

private def rememberedSource (p : PeerPool) (s : PoolState) (e : PeerEndpoint) : PeerSource :=
  let remembered := s.knownSource[e]?.getD .persisted
  if remembered == .manual && !p.manualPeers.contains e then .persisted else remembered

private def seatedCandidates (s : PoolState) : Array PeerCandidate :=
  s.peers.map fun c => { endpoint := c.endpoint, source := s.seatedSources[c.endpoint]?.getD .persisted }

private def policy (p : PeerPool) : DiversityPolicy := { peerCount := p.peerCount }

/-- Manual peers, then persisted good peers, then the census list or the hardcoded fallbacks. -/
def localCandidates (p : PeerPool) (excluded : Std.HashSet PeerEndpoint) : IO (Array PeerCandidate) := do
  let s ← p.state.get
  let mut ordered : Array PeerCandidate := p.manualPeers.map ({ endpoint := ·, source := .manual })
  for e in s.knownGood do
    if !p.manualPeers.contains e then ordered := ordered.push { endpoint := e, source := p.rememberedSource s e }
  let nowS ← p.catalogNow
  let fresh := s.censusCatalog.filter (·.isFresh nowS)
  let automatic ← shuffle (match fresh.bind (·.clearnet) with
    | some entries => entries.map (·.endpoint)
    | none => p.params.fallbackPeers)
  let preferred := automatic.filter (!p.avoidOnReset.contains ·)
  let previous := automatic.filter (p.avoidOnReset.contains ·)
  ordered := ordered ++ (preferred ++ previous).map ({ endpoint := ·, source := .fallback })
  let mut seen := excluded
  let mut out := #[]
  for c in ordered do
    if !seen.contains c.endpoint then
      seen := seen.insert c.endpoint
      out := out.push c
  return out

private def seedCandidates (p : PeerPool) (excluded : Std.HashSet PeerEndpoint) : IO (Array PeerCandidate) := do
  let seeds ← p.seedResolver.resolveSeeds p.params.dnsSeeds p.params.defaultPort p.params.allowsPrivateSeedAddresses
  let mut seen := excluded
  let mut out := #[]
  for e in seeds do
    if !seen.contains e then
      seen := seen.insert e
      out := out.push { endpoint := e, source := .dnsSeed }
  return out

/-- Refresh only changes future discovery. -/
def updateCensusCatalog (p : PeerPool) (c : CensusCatalog) : IO (Except CensusInvalid Unit) := do
  match c.validated (← p.catalogNow) with
  | .ok v => p.state.modify (fun s => { s with censusCatalog := some v }); return .ok ()
  | .error e => return .error e

/-! ## Unseating -/

/-- Unseats every seat (judged once) whose handshake height is more than 100 below the validated tip. -/
def evictStaleTips (p : PeerPool) : IO (Array PeerEndpoint) := do
  let s ← p.state.get
  let some tip := s.validatedTip | return #[]
  let reference : Int := tip.toNat
  let seated : Std.HashSet PeerEndpoint := s.peers.foldl (fun acc c => acc.insert c.endpoint) {}
  let judged := s.staleTipJudged.filter seated.contains
  let mut judged := judged
  let mut heights := #[]
  for peer in s.peers do
    if judged.contains peer.endpoint then continue
    judged := judged.insert peer.endpoint
    heights := heights.push (peer, (← peer.peerStartHeight).toInt)
  p.state.modify fun st => { st with staleTipJudged := judged }
  let mut evicted := #[]
  for (peer, height) in heights do
    if !(reference - height > staleTipTolerance) then continue
    if (← p.state.get).seatedSources[peer.endpoint]? == some .manual then continue
    peer.disconnect
    let deadline := (← p.now) + transportCooldownCapMs
    p.state.modify fun st => { st with
      peers := st.peers.filter (·.endpoint != peer.endpoint)
      knownGood := st.knownGood.filter (· != peer.endpoint)
      cooldownUntil := st.cooldownUntil.insert peer.endpoint deadline
      lastRejection := st.lastRejection.insert peer.endpoint
        s!"stale tip: reports height {height}, {reference - height} blocks behind our validated tip {tip}" }
    evicted := evicted.push peer.endpoint
  if !evicted.isEmpty then p.persistKnownGood
  return evicted

/-! ## Dialling -/

private def seatArrival (p : PeerPool) (peer : PeerConnection) (endpoint : PeerEndpoint) (source : PeerSource) : IO Unit := do
  let candidate : PeerCandidate := { endpoint, source }
  let r ← p.state.modifyGet fun s =>
    if !(s.started && s.peers.size < p.peerCount && !s.peers.any (·.endpoint == endpoint) &&
        p.policy.admits candidate (seatedCandidates s)) then (none, s)
    else
      let isNew := !s.knownGood.contains endpoint
      let s := { s with peers := s.peers.push peer, staleTipJudged := s.staleTipJudged.erase endpoint,
                        seatedSources := s.seatedSources.insert endpoint source }
      let s := if isNew then { s with knownGood := s.knownGood.push endpoint, knownSource := s.knownSource.insert endpoint source } else s
      (some isNew, s)
  match r with
  | none => peer.disconnect
  | some true => p.persistKnownGood
  | some false => pure ()

mutual

/-- Dials until the pool is full or the round's candidates are used up. -/
partial def replenish (p : PeerPool) : IO Unit := do
  let go ← p.state.modifyGet fun s =>
    if s.started && !s.replenishing && s.peers.size < p.peerCount then
      (true, { s with replenishing := true, attemptsThisRound := 0, exhausted := false })
    else (false, s)
  if !go then return
  let s ← p.state.get
  let cooling ← p.coolingEndpoints
  let excluded : Std.HashSet PeerEndpoint :=
    (s.peers.map (·.endpoint) ++ cooling).foldl (·.insert ·) s.rejectedForSession
  let mut queue ← p.localCandidates excluded
  let mut resolvedSeeds := false
  let mut next := 0
  let mut running := 0
  let done : EventStream (PeerEndpoint × Option PeerConnection) Unit ← EventStream.new 0 1_000_000
  while (← p.state.get).peers.size < p.peerCount && (← p.state.get).started do
    if next ≥ queue.size && !resolvedSeeds then
      resolvedSeeds := true
      let seen := queue.foldl (fun acc c => acc.insert c.endpoint) excluded
      queue := queue ++ (← p.seedCandidates seen)
    -- launchEligibleDials
    while next < queue.size && running < p.maxParallelDials && (← p.state.get).attemptsThisRound < p.maxDialAttempts do
      let candidate := queue[next]!
      next := next + 1
      if !p.policy.admits candidate (seatedCandidates (← p.state.get)) then continue
      running := running + 1
      let endpoint := candidate.endpoint
      let peer ← PeerConnection.new endpoint p.params (relayPreference := p.relayPreference)
      p.state.modify fun st => { st with attemptsThisRound := st.attemptsThisRound + 1,
                                         inFlight := st.inFlight.push (endpoint, peer) }
      spawn do
        match ← (peer.connect p.dialTimeoutMs).attempt with
        | .ok () => done.yield (endpoint, some peer)
        | .error _ => done.yield (endpoint, none)
    if running == 0 then break
    let .value (endpoint, dialed) ← done.next | break
    running := running - 1
    p.state.modify fun st => { st with inFlight := st.inFlight.filter (·.1 != endpoint) }
    let some peer := dialed | continue
    let src := (queue.find? (·.endpoint == endpoint)).map (·.source) |>.getD .persisted
    p.seatArrival peer endpoint src
  -- The pool filled or stopped while other dials were in flight.
  while running > 0 do
    let .value (endpoint, peer) ← done.next | break
    running := running - 1
    p.state.modify fun st => { st with inFlight := st.inFlight.filter (·.1 != endpoint) }
    if let some c := peer then c.disconnect
  let evicted ← p.evictStaleTips
  let st ← p.state.modifyGet fun st =>
    let st := { st with exhausted := st.peers.size < p.peerCount, replenishing := false }
    (st, st)
  if !evicted.isEmpty && st.started then spawn p.pruneAndReplenish

partial def pruneAndReplenish (p : PeerPool) : IO Unit := do
  let peers := (← p.state.get).peers
  let mut alive := #[]
  for c in peers do
    if ← c.isConnected then alive := alive.push c
  let aliveIds := alive.map (·.uid)
  p.state.modify fun st => { st with peers := st.peers.filter fun c => aliveIds.contains c.uid || !peers.any (·.uid == c.uid) }
  p.replenish

end

/-- Dials again immediately (the UI retry after exhaustion). -/
def retry (p : PeerPool) : IO Unit := p.replenish

/-- Connects to `peerCount` peers and starts the replacement monitor. -/
def start (p : PeerPool) : IO Unit := do
  let (go, gen) ← p.state.modifyGet fun s =>
    if s.started then ((false, 0), s) else ((true, s.monitorGeneration), { s with started := true })
  if !go then return
  p.replenish
  spawn do
    repeat
      sleepMs p.monitorIntervalMs
      let s ← p.state.get
      if !s.started || s.monitorGeneration != gen then break
      p.pruneAndReplenish

/-- Disconnects everything and persists the good-peers list. -/
def stop (p : PeerPool) : IO Unit := do
  let (inFlight, peers) ← p.state.modifyGet fun s =>
    ((s.inFlight, s.peers), { s with started := false, monitorGeneration := s.monitorGeneration + 1, inFlight := #[] })
  for (_, c) in inFlight do c.disconnect
  for c in peers do c.disconnect
  p.state.modify fun s => { s with peers := #[], rejectedForSession := {} }
  p.persistKnownGood

/-- Forgets every remembered good peer (manual peers survive). Call after `stop`. -/
def forgetKnownGood (p : PeerPool) : IO Unit := do
  if let some f := p.peersFile then
    if ← fileExists f then IO.FS.removeFile f
  p.state.modify fun s => { s with knownSource := {}, seatedSources := {}, staleTipJudged := {}, knownGood := #[],
                                   cooldownUntil := {}, rejectedForSession := {}, lastRejection := {} }

/-- Disconnects a peer that sent something wrong and refuses it for the session (a data fault). -/
def misbehaving (p : PeerPool) (peer : PeerConnection) (reason : String) : IO Unit := do
  peer.disconnect
  p.state.modify fun s => { s with
    peers := s.peers.filter (·.endpoint != peer.endpoint)
    knownGood := s.knownGood.filter (· != peer.endpoint)
    rejectedForSession := s.rejectedForSession.insert peer.endpoint
    lastRejection := s.lastRejection.insert peer.endpoint reason }
  p.replenish

/-- Disconnects a peer that failed to answer in time and cools it off instead of condemning it. -/
def transportFailure (p : PeerPool) (peer : PeerConnection) (reason : String) : IO Unit := do
  peer.disconnect
  let now ← p.now
  p.state.modify fun s =>
    let failures := (s.consecutiveTransportFailures[peer.endpoint]?.getD 0) + 1
    { s with peers := s.peers.filter (·.endpoint != peer.endpoint)
             consecutiveTransportFailures := s.consecutiveTransportFailures.insert peer.endpoint failures
             cooldownUntil := s.cooldownUntil.insert peer.endpoint (now + cooldown failures)
             lastRejection := s.lastRejection.insert peer.endpoint reason }
  p.replenish

/-! ## Header sync with failover -/

/-- A primary that claimed a much taller tip and delivered nothing has withheld what it advertised. -/
private def requireDelivery (o : SyncOutcome) (peer : PeerConnection) (tip : UInt32) : NetM Unit := do
  if o.connected != 0 then return
  let claimed := (← peer.peerStartHeight).toInt
  if claimed - tip.toNat > staleTipTolerance then
    throw (.headers (.badPeerResponse s!"claimed height {claimed} at handshake but delivered no headers past {tip}"))

private def catchUp (p : PeerPool) (chain : HeaderStore) (outcome : SyncOutcome) (primary : PeerEndpoint)
    (timeoutMs : Nat) : IO SyncOutcome := do
  let mut merged := outcome
  let others := (← p.connectedPeers).filter (·.endpoint != primary)
  for other in others do
    let claimed := (← other.peerStartHeight).toInt
    if !(claimed - (← chain.height).toNat > staleTipTolerance) then continue
    match ← (chain.sync other timeoutMs).attempt with
    | .ok more =>
      p.transportSucceeded other.endpoint
      merged := { merged with connected := merged.connected + more.connected,
                              disconnectedHeaders := merged.disconnectedHeaders + more.disconnectedHeaders }
      if let some fork := more.minForkHeight then
        merged := { merged with minForkHeight := some (min (merged.minForkHeight.getD fork) fork) }
    | .error e =>
      match e with
      | .headers (.storageCorrupt _) | .headers (.storageUnavailable _) => return merged
      | .headers _ => p.misbehaving other e.description
      | .cancelled => return merged
      | .peer pe => if pe.isTransport then p.transportFailure other e.description else p.misbehaving other e.description
      | _ => p.misbehaving other e.description
  return merged

private def settledSync (p : PeerPool) (chain : HeaderStore) (peer : PeerConnection) (timeoutMs : Nat) : NetM SyncOutcome := do
  let outcome ← chain.sync peer timeoutMs
  requireDelivery outcome peer (← chain.height)
  p.transportSucceeded peer.endpoint
  let outcome ← p.catchUp chain outcome peer.endpoint timeoutMs
  let tip ← chain.height
  p.state.modify fun s => { s with validatedTip := some tip }
  if !(← p.evictStaleTips).isEmpty && (← p.state.get).started then spawn p.pruneAndReplenish
  return outcome

/-- Syncs headers against connected peers with bounded failover. -/
def syncHeaders (p : PeerPool) (chain : HeaderStore) (timeoutPerPeerMs : Nat := 30_000) (maxAttempts : Nat := 6)
    (maxTransportRetries : Nat := 12) : NetM SyncOutcome := do
  let mut attempts := 0
  let mut transportRetries := 0
  let mut lastError : Option NetError := none
  while attempts < maxAttempts && transportRetries < maxTransportRetries do
    let some peer := (← p.connectedPeers)[0]? | do
      let cooling ← p.coolingEndpoints
      if !cooling.isEmpty || transportRetries > 0 then
        throw (.pool (.allPeersCoolingDown cooling.size
          ((lastError.map (·.description)).getD "the connected peers stopped answering")))
      if attempts == 0 then throw (.pool .noPeers)
      break
    let mut burnedAPeer := true
    match ← (p.settledSync chain peer timeoutPerPeerMs).attempt with
    | .ok o => return o
    | .error e =>
      match e with
      | .headers (.storageCorrupt _) | .headers (.storageUnavailable _) => throw e
      | .cancelled => throw e
      | .peer pe =>
        lastError := some e
        if pe.isTransport then
          burnedAPeer := false
          transportRetries := transportRetries + 1
          p.transportFailure peer e.description
        else p.misbehaving peer e.description
      | _ =>
        lastError := some e
        p.misbehaving peer e.description
    if burnedAPeer then attempts := attempts + 1
  let cooling ← p.coolingEndpoints
  if attempts == 0 && (!cooling.isEmpty || transportRetries > 0) then
    throw (.pool (.allPeersCoolingDown (max cooling.size 1)
      ((lastError.map (·.description)).getD "the connected peers stopped answering")))
  throw (.pool (.exhausted attempts ((lastError.map (·.description)).getD "no additional peers were available")))

end PeerPool
end Winnow.IO
