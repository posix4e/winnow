import Foundation

public enum PeerPoolHeaderSyncError: LocalizedError, Equatable {
    case noPeers
    case exhausted(attempts: Int, lastError: String)
    /// Every peer is briefly cooling off after a slow reply. Distinct from
    /// `noPeers`, which means there is nothing to dial at all (#82).
    case allPeersCoolingDown(cooling: Int, lastError: String)
    /// The pool is holding seats for transaction relay only
    /// (`PeerPool.enterRelayOnly(seats:)`), which does not read the chain.
    case relayOnly

    public var errorDescription: String? {
        switch self {
        case .noPeers:
            "No Bitcoin peers are available for block-header sync."
        case .relayOnly:
            "Winnow is keeping Bitcoin peers connected only to finish relaying a payment. Resume syncing to download block headers."
        case let .exhausted(attempts, lastError):
            "Winnow tried \(attempts) Bitcoin peer\(attempts == 1 ? "" : "s"), but none supplied a usable block-header chain. Last error: \(lastError)"
        case let .allPeersCoolingDown(cooling, lastError):
            "\(cooling) Bitcoin peer\(cooling == 1 ? " was" : "s were") slow to answer and \(cooling == 1 ? "is" : "are") being rested briefly. Syncing will resume on its own. Last error: \(lastError)"
        }
    }
}

/// A small pool of outbound peers (default 3). Candidates come from manually
/// supplied endpoints, a persisted good-peers JSON file, the census list
/// the release ships, and DNS seeds resolved over DoH (dns-json)
/// with getaddrinfo as fallback. Dials race a batch of candidates at once
/// (short per-attempt timeout);
/// a round that runs out of candidates below target is reported as
/// `exhausted` in `connectionStatus`. A monitor task prunes dead connections
/// and connects replacements. Deliberately simple: no scoring buckets, no
/// addr gossip — misbehaving peers are dropped and replaced.
///
/// Two modes, and `stop()` is neither: full service, and a relay-only session
/// (`enterRelayOnly(seats:)`) that keeps a seat or two so a payment already
/// signed can go on being announced while the pool dials nothing and reads
/// nothing. See `Mode`.
public actor PeerPool {
    public let params: NetworkParams
    public let peerCount: Int
    public let manualPeers: [PeerEndpoint]
    /// BIP37 relay flag for connections this pool creates: true asks peers to
    /// inv every relayed transaction (bounded mempool windows, §2.8, fetch
    /// them with getdata; without a window open the invs are simply dropped).
    public let relayPreference: Bool
    /// Per-attempt TCP+handshake timeout for pool-created connections.
    public let dialTimeout: Duration
    /// How many candidates are dialed concurrently per round.
    public let maxParallelDials: Int
    /// Total dial attempts per round — bounds the effort before the round
    /// gives up and reports exhaustion.
    public let maxDialAttempts: Int
    /// JSON file where known-good peers are persisted.
    private let peersFileURL: URL?
    /// DNS-seed resolver (DoH, then getaddrinfo). Injectable for tests.
    private let seedResolver: SeedResolver
    public let gateways: PeerGatewayConfiguration
    private let censusCatalog: CensusCatalog?
    private var inFlight: [PeerEndpoint: PeerConnection] = [:]
    private var avoidOnReset: Set<PeerEndpoint> = []
    /// Clock for cooldown expiry. Injectable so a test can advance time
    /// instead of sleeping through a 30-second cooldown.
    private let now: @Sendable () -> ContinuousClock.Instant

    private var peers: [PeerConnection] = []
    private var knownGood: Set<PeerEndpoint> = []
    /// Where each known-good peer was originally found. A successful dial
    /// promotes an endpoint into `knownGood` whatever its origin, so without
    /// this the pool forgets it ever had diverse sources (#3).
    private var knownSource: [PeerEndpoint: PeerSource] = [:]
    /// The source class of every currently connected peer, parallel to `peers`.
    private var seatedSources: [PeerEndpoint: PeerSource] = [:]
    private var monitorTask: Task<Void, Never>?
    /// The prune-only pass a relay-only session runs where full service runs
    /// its replacement monitor. Its own handle, because the two are not the
    /// same job: this one drops seats that have gone and never dials, and
    /// `start()` has to be able to cancel it and install the real monitor
    /// without either standing in for the other.
    private var relayPruneTask: Task<Void, Never>?
    private var started = false
    private var replenishing = false
    private var attemptsThisRound = 0
    private var exhausted = false
    /// Set for a round that follows one which could not fill the pool, so a
    /// dry Tor or I2P side cannot keep the pool short under the mix rule.
    private var relaxOverlayMix = false
    /// Endpoints rejected for a protocol/chain failure during this pool run.
    /// Without this set a manual or persisted bad peer is immediately dialed
    /// again after `misbehaving`, starving healthy fallback candidates.
    private var rejectedForSession: Set<PeerEndpoint> = []
    /// Endpoints cooling off after a transport failure, and how many they have
    /// had in a row. Neither survives the process: a cooldown is a judgement
    /// about right now, not a reputation (#82).
    private var cooldownUntil: [PeerEndpoint: ContinuousClock.Instant] = [:]
    private var consecutiveTransportFailures: [PeerEndpoint: Int] = [:]
    /// Why each endpoint was last dropped, so a diagnosis does not have to
    /// guess between "slow" and "lying".
    private var lastRejection: [PeerEndpoint: String] = [:]

    /// First cooldown after a transport failure; doubles per consecutive
    /// failure up to the cap.
    static let transportCooldownBase: Duration = .seconds(30)
    static let transportCooldownCap: Duration = .seconds(600)
    /// How often either monitor runs: the replacement monitor full service
    /// installs, and the prune pass a relay-only session runs in its place.
    /// One number for both, because "the same cadence" is the whole claim.
    /// Fixed at init; a test that wants to watch a dead seat dropped passes a
    /// short one instead of sleeping through half a minute.
    private let monitorInterval: Duration
    /// How far behind our own validated header tip a peer's reported height
    /// may be before it is unseated. A hundred blocks is about sixteen hours,
    /// the wallet's own reorg horizon, and far inside what a node still in
    /// initial download or stuck on a dead fork reports.
    public static let staleTipTolerance: Int64 = 100
    /// The height of the header chain this pool last synced — proof-of-work
    /// validated, so no peer can inflate it. nil until the first header sync.
    private var validatedTip: UInt32?
    /// Seats `evictStaleTips` has already judged. The height a peer reports
    /// is fixed at its handshake and never refreshed, while `validatedTip`
    /// advances with every header sync, so judging the same seat again later
    /// would read an honest peer's age as staleness and burn it.
    private var staleTipJudged: Set<PeerEndpoint> = []
    /// What the pool is currently willing to do. Set by `start()` and
    /// `enterRelayOnly(seats:)`, and reset by `stop()`.
    public private(set) var mode: Mode = .full
    /// Seats a relay-only session was asked to keep. Meaningless — and zero —
    /// in `.full`, where `peerCount` is the target.
    private var relaySeats = 0
    /// Test-visible (@testable): awaited by `enterRelayOnly(seats:)` once the
    /// narrowing is committed and before it reports the seats kept. A test
    /// that parks it holds every caller at its `await pool.enterRelayOnly`,
    /// which is how what `TxBroadcaster` does on the far side of that
    /// suspension is checked as an ordering rather than raced for. Nil
    /// outside the tests, and read nowhere else.
    private var narrowingHold: (@Sendable () async -> Void)?

    /// What a pool is doing for its owner right now.
    public enum Mode: String, Sendable, Equatable {
        /// Everything: dial up to `peerCount`, replace seats the monitor finds
        /// dead, sync headers and filters, relay transactions.
        case full
        /// Relay only. The pool keeps a few of the peers it already had so a
        /// pending payment can go on being announced, dials nothing, resolves
        /// no addresses, runs no replacement monitor, and refuses header (and
        /// so filter) sync. See `enterRelayOnly(seats:)`.
        case relayOnly
    }

    /// Seats `enterRelayOnly(seats:)` keeps unless the caller says otherwise.
    /// One, because the point of the mode is to cost less than a sync pool;
    /// a caller that would rather pay for redundancy passes more.
    public static let defaultRelaySeats = 1

    /// UI-facing snapshot of the pool's connection progress.
    public struct ConnectionStatus: Sendable, Equatable {
        /// Currently connected peers.
        public var connected: Int
        /// The pool's target size.
        public var target: Int
        /// A dial round is in flight.
        public var dialing: Bool
        /// Dials launched in the current/last round.
        public var attempts: Int
        /// The last round ran out of candidates below target — no peers at
        /// all when `connected == 0` (the UI's error + retry state).
        public var exhausted: Bool
    }

    public var connectionStatus: ConnectionStatus {
        ConnectionStatus(connected: peers.count, target: seatTarget,
                         dialing: replenishing, attempts: attemptsThisRound,
                         exhausted: exhausted)
    }

    /// How many seats the pool holds in its current mode: the full target, or
    /// what a relay-only session was asked to keep. Reported as the target so
    /// a paused pool does not read as permanently short of peers.
    private var seatTarget: Int { mode == .full ? peerCount : relaySeats }

    /// Whether the pool is running: `start()` has been called and `stop()` has
    /// not. A relay-only pool is running — it holds live connections — so this
    /// is not the same question as `mode`.
    public var isRunning: Bool { started }

    public init(params: NetworkParams, peerCount: Int = 3,
                manualPeers: [PeerEndpoint] = [], peersFileURL: URL? = nil,
                relayPreference: Bool = false,
                dialTimeout: Duration = .seconds(5),
                maxParallelDials: Int = 5, maxDialAttempts: Int = 50,
                seedResolver: SeedResolver? = nil,
                censusCatalog: CensusCatalog? = nil,
                gateways: PeerGatewayConfiguration = .init(),
                avoidOnReset: Set<PeerEndpoint> = [],
                monitorInterval: Duration = .seconds(30),
                now: @Sendable @escaping () -> ContinuousClock.Instant = { ContinuousClock.now }) {
        self.gateways = gateways
        self.params = params
        self.peerCount = peerCount
        self.manualPeers = manualPeers
        self.peersFileURL = peersFileURL
        self.relayPreference = relayPreference
        self.dialTimeout = dialTimeout
        self.maxParallelDials = maxParallelDials
        self.maxDialAttempts = maxDialAttempts
        self.censusCatalog = try? censusCatalog?.validated()
        self.avoidOnReset = avoidOnReset
        self.seedResolver = seedResolver ?? .routed(client: RoutedHTTPClient())
        self.monitorInterval = monitorInterval
        self.now = now
        if let peersFileURL,
           let data = Self.boundedRead(peersFileURL),
           let stored = PersistedPeers.decode(data) {
            knownGood = Set(stored.map(\.endpoint))
            knownSource = Dictionary(stored.map { ($0.endpoint, $0.source) },
                                     uniquingKeysWith: { first, _ in first })
        }
    }

    /// Connects to `peerCount` peers and starts the replacement monitor.
    ///
    /// Also the way back from `.relayOnly`: a narrowed pool is still running,
    /// so this restores full service, refills the seats the session dropped
    /// and starts the monitor again. An app that already calls `start()` when
    /// it comes back to the foreground needs no second call.
    public func start() async {
        let resuming = started && mode == .relayOnly
        guard !started || resuming else { return }
        mode = .full
        relaySeats = 0
        // The relay-only prune runs where the replacement monitor would, so
        // full service must not inherit it: it drops dead seats and dials
        // nothing, and what full service needs is the monitor installed below,
        // which replaces what it drops.
        relayPruneTask?.cancel()
        relayPruneTask = nil
        // A fresh run owes nothing to the last one's session rejections. They
        // are cleared here as well as in `stop()`, because a data fault from
        // a scan still unwinding can land between that clear and the last
        // disconnect, and would otherwise bar the peer for a run it never
        // misbehaved in.
        if !resuming { rejectedForSession = [] }
        started = true
        await replenish()
        // `mode` as well as `monitorTask`, because `replenish` above is a long
        // suspension and `enterRelayOnly` may land inside it: it sets the mode
        // and clears the monitor, so a check on the monitor alone passes and
        // this installs a 30-second timer for a session documented as having
        // neither a monitor nor a pruning pass.
        guard mode == .full, monitorTask == nil else { return }
        let interval = monitorInterval
        monitorTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: interval)
                guard !Task.isCancelled, let self else { return }
                await self.pruneAndReplenish()
            }
        }
    }

    /// Narrows the pool to transaction relay: keeps at most `seats` of the
    /// peers it already has, disconnects the rest, and stops dialling.
    ///
    /// This is the state a wallet needs when it is otherwise idle but has a
    /// payment in flight. `stop()` is all or nothing — it disconnects every
    /// peer, and `TxBroadcaster` announces over exactly those connections, so
    /// stopping a pool with a pending transaction leaves relay dead until the
    /// app is opened again. A relay-only pool keeps announcing and
    /// rebroadcasting while costing one connection instead of `peerCount`.
    ///
    /// What it stops doing: `replenish` refuses, so no candidate is dialled,
    /// no DNS seed is resolved and no new address is taken; the replacement
    /// monitor is cancelled; `syncHeaders` (and so `FilterSync`) is refused.
    /// What it keeps doing: `connectedPeers()` still answers, and everything
    /// `TxBroadcaster` does over those peers is unchanged.
    ///
    /// Deliberately not a self-healing mode. A seat lost while relaying is not
    /// replaced, because replacing it means dialling, which is the cost and
    /// the exposure this session exists to avoid; the session holds what it
    /// was given until the caller resumes full service with `start()`.
    ///
    /// It does not go on reporting a seat that has gone, though. In the
    /// replacement monitor's place, and on its cadence, the session runs
    /// `pruneRelaySeats`: seats whose connection is closed are dropped, and
    /// nothing is dialled to take their place. Without it a remote that went
    /// away left its seat in `peers` for the whole session — `connectedPeers()`
    /// kept reporting it, every announcement over it failed silently, and the
    /// session had no way to end. A session can therefore reach zero seats,
    /// which is the honest end of it: `TxBroadcaster.enterRelayOnly(seats:)`
    /// reads the pool on its next backoff attempt and closes the session
    /// there. Callers that need the pool to stop itself once relay is
    /// finished should drive this through that call, which owns the pending
    /// set and stops the pool when it drains.
    ///
    /// A stopped pool is not narrowed: there is nothing to keep, and dialling
    /// here would be the very thing the mode refuses.
    ///
    /// The gate is on entry only, here as in `FilterSync.sync`: a header or
    /// filter sync that is already running keeps reading over the seats this
    /// leaves behind, and can still reach `misbehaving` and burn one. A caller
    /// narrowing a pool that may be being read must cancel its scan and await
    /// it before calling this.
    ///
    /// - Returns: the seats the session actually holds once the narrowing is
    ///   done: what is still seated after the dropped peers have been
    ///   disconnected, not what the split set out to keep. Zero when the pool
    ///   is stopped, had no peers to keep, or lost its kept seat to a removal
    ///   that landed while the rest were being disconnected. A zero-seat
    ///   session announces to nobody and cannot dial one, so the count is the
    ///   caller's cue to stop rather than to wait — `TxBroadcaster.enterRelayOnly(seats:)`
    ///   reads it for exactly that.
    @discardableResult
    public func enterRelayOnly(seats: Int = PeerPool.defaultRelaySeats) async -> Int {
        guard started else { return 0 }
        mode = .relayOnly
        relaySeats = max(0, seats)
        monitorTask?.cancel()
        monitorTask = nil
        // No round has been dialled in this session, and none will be: the
        // counters describe dialling, so they start the session empty rather
        // than reporting the sync pool's last round for as long as it lasts.
        attemptsThisRound = 0
        exhausted = false
        // The split is committed before anything is awaited, and this is the
        // whole of why the two lines are in this order. `await
        // peer.disconnect()` suspends the pool, so any interleaved removal —
        // a `transportFailure` or `misbehaving` from a scan still unwinding,
        // which is exactly what is in flight when an app narrows on going
        // idle — shifts `peers` underneath a prefix taken afterwards, and the
        // session ends up seated on a connection this loop already tore down.
        // Announcements then reach nobody, the monitor that would have pruned
        // the dead seat is cancelled by the mode, and nothing drains the
        // pending set, so the pool is held open with the payment silently
        // unrelayed. Reading `peers` once and writing it once, with no
        // suspension in between, is what makes the seats the session keeps
        // the seats it was looking at.
        let dropped = Array(peers.dropFirst(relaySeats))
        peers = Array(peers.prefix(relaySeats))
        for peer in dropped { await peer.disconnect() }
        if let narrowingHold { await narrowingHold() }
        persistKnownGood()
        // The mode is asked again because a `start()` can land in the
        // disconnects above and take the pool back. It cancelled the prune
        // and installed the replacement monitor as it went, and a session
        // that is no longer a session must not put its own pass back on a
        // pool in full service.
        if mode == .relayOnly { startRelayPruneMonitor() }
        // Counted after the loop, for the same reason the split is committed
        // before it. The seat the split kept can be removed during these
        // awaits by the same `transportFailure` or `misbehaving` that shifts
        // the array, and a count taken before them reported that seat as
        // held. `TxBroadcaster.enterRelayOnly(seats:)` opens a session on any
        // count above zero, so the pool sat in a mode that dials nothing and
        // runs no monitor, over no connection at all, and the payment was
        // never announced again. What is returned is what is seated now.
        return peers.count
    }

    /// Test-visible (@testable). See `narrowingHold`.
    func holdNarrowing(_ hold: (@Sendable () async -> Void)?) { narrowingHold = hold }

    /// Stops the pool, but only while it is still the relay-only session that
    /// asked to — one actor job, so nothing can land between the question and
    /// the answer.
    ///
    /// `TxBroadcaster` ends a relay-only session from a detached task, and the
    /// mode has to be re-read there: a caller that resumed full service has
    /// taken the pool back, and a payment confirming a moment later must not
    /// tear down the peers it is now syncing over. Reading `mode` and calling
    /// `stop()` as two hops made that re-read a lie — a `start()` enqueued in
    /// the gap runs first, and the queued `stop()` then undoes it, leaving a
    /// foregrounded app at zero peers with `retry()` refusing (it needs
    /// `started`) until the next full stop/start cycle.
    public func stopIfRelayOnly() async {
        guard mode == .relayOnly else { return }
        await stop()
    }

    /// Disconnects everything and persists the good-peers list.
    ///
    /// The seat list is emptied before the first disconnect is awaited, for
    /// the reason `enterRelayOnly` gives: everything this writes must be
    /// written in one uninterrupted piece, because `await peer.disconnect()`
    /// hands the pool to whatever is queued behind it. `start()` is what is
    /// queued behind it now that a relay-only session stops the pool from a
    /// task of its own — an app resuming at the same instant the drain lands
    /// — and a `start()` that ran between `started = false` and `peers = []`
    /// used to see the old seats, decline to dial because the pool looked
    /// full, and then have those seats cleared out from under it: a running
    /// pool with no peers, no monitor and nothing that would dial one.
    /// Everything still disconnects, and still before this returns.
    public func stop() async {
        monitorTask?.cancel()
        monitorTask = nil
        relayPruneTask?.cancel()
        relayPruneTask = nil
        started = false
        mode = .full
        relaySeats = 0
        let dropped = peers + Array(inFlight.values)
        inFlight = [:]
        peers = []
        rejectedForSession = []
        persistKnownGood()
        for peer in dropped { await peer.disconnect() }
    }

    /// Forgets every remembered good peer: the in-memory list, the persisted
    /// file, cooldowns and session rejections. Manual peers are the owner's
    /// instruction, not a memory — they survive. The next start dials from
    /// scratch: manual peers, then fallbacks, then DNS seeds. Call after
    /// `stop()` (which persists); a pool rebuilt afterwards starts clean.
    public func forgetKnownGood() throws {
        if let peersFileURL, FileManager.default.fileExists(atPath: peersFileURL.path) {
            try FileManager.default.removeItem(at: peersFileURL)
        }
        knownSource = [:]
        seatedSources = [:]
        staleTipJudged = []
        knownGood = []
        cooldownUntil = [:]
        rejectedForSession = []
        lastRejection = [:]

    }

    /// Currently connected peers (snapshot).
    public func connectedPeers() -> [PeerConnection] { peers }

    public func randomPeer() -> PeerConnection? { peers.randomElement() }

    /// Disconnects a peer that sent something wrong and refuses it for the
    /// rest of the session.
    ///
    /// This is the response to a *data* fault — a protocol violation, a filter
    /// commitment that disagrees with its peers, a header that does not link.
    /// It is deliberately harsh: it drops the endpoint from `knownGood`, which
    /// is the persisted peers file, so the judgement outlives this launch.
    ///
    /// A peer that was merely slow must not come here. See
    /// `transportFailure(_:reason:)` (#82).
    public func misbehaving(_ peer: PeerConnection, reason: String) async {
        await peer.disconnect()
        peers.removeAll { $0.endpoint == peer.endpoint }
        knownGood.remove(peer.endpoint)
        rejectedForSession.insert(peer.endpoint)
        lastRejection[peer.endpoint] = reason
        await replenish()
    }

    /// Disconnects a peer that failed to answer in time, and cools it off
    /// instead of condemning it.
    ///
    /// A mid-request timeout makes the connection suspect, so it is dropped —
    /// but being slow once is not misconduct. Routing that through
    /// `misbehaving` meant a single lagging reply removed the endpoint from
    /// `knownGood` *and* barred it for the session, so on a mainnet header sync
    /// — around 460 round trips, all inside one call against one peer — a
    /// user's best peers were burned one hiccup at a time, and the persisted
    /// peers file was degraded for every future launch too. That is the
    /// "peers are lagging me out" report (#82).
    ///
    /// Instead the endpoint enters an exponential, capped cooldown, escalating
    /// while failures stay consecutive and clearing on the first success. It
    /// stays in `knownGood` and never reaches `rejectedForSession` on its own,
    /// so a peer that is briefly slow is skipped for a while and then tried
    /// again. Only a data fault is permanent.
    public func transportFailure(_ peer: PeerConnection, reason: String) async {
        await peer.disconnect()
        peers.removeAll { $0.endpoint == peer.endpoint }
        let failures = (consecutiveTransportFailures[peer.endpoint] ?? 0) + 1
        consecutiveTransportFailures[peer.endpoint] = failures
        cooldownUntil[peer.endpoint] = now().advanced(by: Self.cooldown(afterFailures: failures))
        lastRejection[peer.endpoint] = reason
        await replenish()
    }

    /// Unseats every peer whose handshake height is more than
    /// `staleTipTolerance` below our own validated header tip.
    ///
    /// A peer that far behind cannot serve filters or blocks near the tip,
    /// and asking it about a tip it has never seen makes Bitcoin Core drop the
    /// connection — which is how one such peer stalled a mainnet filter sync
    /// five hundred blocks short for good. The case that found this was a
    /// node stuck on the dead BIP-110 minority chain of August 2026, four
    /// thousand blocks behind with a fee filter no transaction could clear;
    /// the rule judges what the peer reports, never what software it runs.
    ///
    /// The reference is deliberately not the best height any peer claims. A
    /// `version.startHeight` is an unvalidated claim, and judging peers
    /// against the maximum would let one peer claiming `Int32.max` evict
    /// every honest peer and their replacements until it held the pool
    /// alone. Our own header chain is proof-of-work checked, so a liar can
    /// only make itself look ahead of it, which the header sync then
    /// punishes as a data fault. Before the first header sync there is no
    /// reference and nothing is judged.
    ///
    /// Not `misbehaving`: being behind is a state, not a lie. The endpoint
    /// leaves the persisted good list, since a node that far back is not a
    /// good peer to dial first next launch, and cools off for the full cap so
    /// this session stops re-seating it.
    @discardableResult
    func evictStaleTips() async -> [PeerEndpoint] {
        guard let validatedTip else { return [] }
        let reference = Int64(validatedTip)
        // Judged once per seat, against the first tip the pool trusted after
        // the seat was taken; a peer that is unseated and dials back in is a
        // new seat with a new handshake, and is judged afresh.
        staleTipJudged.formIntersection(peers.map(\.endpoint))
        var heights: [(peer: PeerConnection, height: Int64)] = []
        for peer in peers where !staleTipJudged.contains(peer.endpoint) {
            staleTipJudged.insert(peer.endpoint)
            // Widened before any arithmetic: the wire accepts the full signed
            // field, and `Int32.min` from a hostile peer must not trap here.
            heights.append((peer, Int64(await peer.peerStartHeight)))
        }
        var evicted: [PeerEndpoint] = []
        for (peer, height) in heights where reference - height > Self.staleTipTolerance {
            // A peer the user typed in is their explicit choice, and the
            // diversity policy already declines to overrule that. Someone
            // pointing at their own node mid-sync gets to keep it.
            if seatedSources[peer.endpoint] == .manual { continue }
            await peer.disconnect()
            peers.removeAll { $0.endpoint == peer.endpoint }
            knownGood.remove(peer.endpoint)
            cooldownUntil[peer.endpoint] = now().advanced(by: Self.transportCooldownCap)
            lastRejection[peer.endpoint] =
                "stale tip: reports height \(height), \(reference - height) blocks behind our validated tip \(validatedTip)"
            evicted.append(peer.endpoint)
        }
        if !evicted.isEmpty { persistKnownGood() }
        return evicted
    }

    /// A completed exchange clears the endpoint's cooldown escalation. Without
    /// this, failures accumulate across a long session and a peer that had one
    /// bad minute an hour ago starts its next hiccup already halfway to the
    /// cap.
    func transportSucceeded(_ endpoint: PeerEndpoint) {
        consecutiveTransportFailures[endpoint] = nil
        cooldownUntil[endpoint] = nil
    }

    /// `base × 2^(failures - 1)`, capped — the shape `TxBroadcaster` already
    /// uses for rebroadcast backoff, applied to peer endpoints rather than
    /// transactions.
    static func cooldown(afterFailures failures: Int,
                         base: Duration = transportCooldownBase,
                         cap: Duration = transportCooldownCap) -> Duration {
        var interval = base
        for _ in 1 ..< max(1, failures) {
            let doubled = interval + interval
            guard doubled < cap else { return cap }
            interval = doubled
        }
        return min(interval, cap)
    }

    /// Whether this endpoint is currently cooling off after a transport
    /// failure, and so should not be dialled yet.
    func isCoolingDown(_ endpoint: PeerEndpoint) -> Bool {
        guard let until = cooldownUntil[endpoint] else { return false }
        return now() < until
    }

    /// Endpoints that are only unavailable because they are cooling off —
    /// the pool would take them again once the timer expires.
    var coolingEndpoints: Set<PeerEndpoint> {
        Set(cooldownUntil.keys.filter { isCoolingDown($0) })
    }

    /// Why an endpoint was last dropped, for diagnosis. `misbehaving` accepted
    /// a reason and discarded it, which is why the original report could say
    /// only that peers were "lagging me out".
    public func rejectionReason(_ endpoint: PeerEndpoint) -> String? {
        lastRejection[endpoint]
    }

    /// Every endpoint dropped this session with the reason it was dropped,
    /// for diagnostics that want the whole picture (the E2E journal).
    public var rejectionReasons: [PeerEndpoint: String] { lastRejection }

    /// Syncs headers against connected peers with bounded failover. Header
    /// batches already accepted by `HeaderChain` remain persisted, so the next
    /// peer resumes from that progress rather than restarting at genesis.
    /// Local storage failures are never blamed on (or retried against) peers.
    /// - Parameters:
    ///   - maxAttempts: how many peers may be *burned* — dropped for a data
    ///     fault — before the sync gives up.
    ///   - maxTransportRetries: how many slow or dropped peers may be skipped
    ///     without counting against that budget. Separate because the two
    ///     failures mean different things, but still bounded, or a pool that
    ///     keeps producing timing-out candidates would spin.
    @discardableResult
    public func syncHeaders(_ chain: HeaderChain, timeoutPerPeer: Duration = .seconds(30),
                            maxAttempts: Int = 6,
                            maxTransportRetries: Int = 12) async throws -> HeaderChain.SyncOutcome {
        precondition(maxAttempts > 0)
        // A relay-only session holds a seat so a pending payment can still be
        // announced, and reading the chain over it is the work it exists not
        // to do. Refused rather than served quietly: a caller that asked for
        // headers here has lost track of the mode, and a header sync that runs
        // anyway would burn the relay seat on a peer fault or a stale tip.
        guard mode == .full else { throw PeerPoolHeaderSyncError.relayOnly }
        var attempts = 0
        var transportRetries = 0
        var lastError: (any Error)?

        while Self.budgetRemains(attempts: attempts, of: maxAttempts,
                                 transportRetries: transportRetries, of: maxTransportRetries) {
            guard let peer = peers.first else {
                try throwIfPoolOnlyCooling(attempts: attempts,
                                           transportRetries: transportRetries,
                                           lastError: lastError)
                break
            }
            // `maxAttempts` is a budget of peers *burned*, so a peer that was
            // only slow must not spend it. Otherwise a run of hiccups declares
            // exhaustion while healthy endpoints sit in the pool cooling off,
            // and the report the user gets moves up a layer without the cause
            // changing (#82).
            switch try await attemptSync(chain, primary: peer, timeoutPerPeer: timeoutPerPeer) {
            case let .synced(outcome):
                return outcome
            case let .burned(error):
                lastError = error
                await misbehaving(peer, reason: error.localizedDescription)
                attempts += 1
            case let .transient(error):
                lastError = error
                transportRetries += 1
                await transportFailure(peer, reason: error.localizedDescription)
            }
        }

        throw loopExitError(attempts: attempts, transportRetries: transportRetries,
                            lastError: lastError)
    }

    /// Two ways out of the sync loop: peers burned, or transport retries
    /// spent. Only the first is exhaustion — reporting the second as "tried
    /// 0 peers" is both wrong and unhelpful, because the peers exist and are
    /// resting.
    private func loopExitError(attempts: Int, transportRetries: Int,
                               lastError: (any Error)?) -> PeerPoolHeaderSyncError {
        if attempts == 0, !coolingEndpoints.isEmpty || transportRetries > 0 {
            return .allPeersCoolingDown(
                cooling: max(coolingEndpoints.count, 1),
                lastError: lastError?.localizedDescription
                    ?? "the connected peers stopped answering")
        }
        return .exhausted(
            attempts: attempts,
            lastError: lastError?.localizedDescription ?? "no additional peers were available")
    }

    /// The empty-pool verdict. An empty pool used to mean there were no
    /// candidates; since transport failures cool endpoints off rather than
    /// banning them, it can now mean "everyone is briefly unavailable" — a
    /// normal transient state, not a peerless one. Reporting it as `noPeers`
    /// would tell the user no Bitcoin peers exist while a peer sits thirty
    /// seconds from eligibility — the same overreaction #82 exists to
    /// remove. Throws the truthful error, or returns to let the caller
    /// leave the loop with what it has.
    private func throwIfPoolOnlyCooling(attempts: Int, transportRetries: Int,
                                        lastError: (any Error)?) throws {
        if !coolingEndpoints.isEmpty || transportRetries > 0 {
            throw PeerPoolHeaderSyncError.allPeersCoolingDown(
                cooling: coolingEndpoints.count,
                lastError: lastError?.localizedDescription
                    ?? "the connected peers stopped answering")
        }
        if attempts == 0 { throw PeerPoolHeaderSyncError.noPeers }
    }

    /// The success path of one attempt: the primary's headers, then whatever
    /// the other peers claiming a taller tip can add, then the judgement on
    /// who still deserves a seat.
    private func settledSync(_ chain: HeaderChain, primary peer: PeerConnection,
                             timeoutPerPeer: Duration) async throws -> HeaderChain.SyncOutcome {
        var outcome = try await chain.sync(using: peer, timeout: timeoutPerPeer)
        try await Self.requireDelivery(outcome, from: peer, tip: chain.height)
        transportSucceeded(peer.endpoint)
        // The first peer answered, but it may be the one that is behind: a
        // stale peer seated first would otherwise freeze the tip here every
        // pass while honest peers sat idle. Any other peer claiming a tip
        // well above ours gets asked too; the claim costs one round trip to
        // check and is settled by proof of work, so a liar gains nothing by
        // it.
        outcome = await catchUp(chain, after: outcome, except: peer.endpoint,
                                timeoutPerPeer: timeoutPerPeer)
        // The one place the pool learns a height it can trust. Judged here
        // as well as after each dial round, so a peer seated before the
        // first sync is caught once there is a tip to compare against.
        validatedTip = await chain.height
        if !(await evictStaleTips()).isEmpty, started {
            Task { await self.pruneAndReplenish() }
        }
        return outcome
    }

    /// A primary that claimed a tip well above ours at handshake and then
    /// delivered nothing has withheld what it advertised: an honest peer
    /// with a taller chain answers getheaders with headers. Left alone, such
    /// a peer froze the chain — and every scan behind it — silently, for as
    /// long as it kept its seat, and was persisted as known-good besides.
    /// Thrown as a data fault, so the pool condemns it and moves on.
    private static func requireDelivery(_ outcome: HeaderChain.SyncOutcome, from peer: PeerConnection,
                                        tip: UInt32) async throws {
        guard outcome.connected == 0 else { return }
        let claimed = Int64(await peer.peerStartHeight)
        guard claimed - Int64(tip) <= staleTipTolerance else {
            throw HeaderChainError.badPeerResponse(
                "claimed height \(claimed) at handshake but delivered no headers past \(tip)")
        }
    }

    /// Syncs headers from every other connected peer whose reported height
    /// is more than `staleTipTolerance` above the chain's, folding what they
    /// deliver into `outcome`. Peers that fail are cooled off or condemned
    /// exactly as the primary sync would treat them.
    private func catchUp(_ chain: HeaderChain, after outcome: HeaderChain.SyncOutcome,
                         except primary: PeerEndpoint,
                         timeoutPerPeer: Duration) async -> HeaderChain.SyncOutcome {
        var merged = outcome
        let others = peers.filter { $0.endpoint != primary }
        for other in others {
            let claimed = Int64(await other.peerStartHeight)
            guard claimed - Int64(await chain.height) > Self.staleTipTolerance else { continue }
            do {
                let more = try await chain.sync(using: other, timeout: timeoutPerPeer)
                transportSucceeded(other.endpoint)
                merged.connected += more.connected
                merged.disconnectedHeaders += more.disconnectedHeaders
                if let fork = more.minForkHeight {
                    merged.minForkHeight = min(merged.minForkHeight ?? fork, fork)
                }
            } catch let error as HeaderChainError {
                switch error {
                case .storageCorrupt, .storageUnavailable: return merged
                default: await misbehaving(other, reason: error.localizedDescription)
                }
            } catch is CancellationError {
                return merged
            } catch let error as PeerError where error.isTransport {
                await transportFailure(other, reason: error.localizedDescription)
            } catch {
                await misbehaving(other, reason: error.localizedDescription)
            }
        }
        return merged
    }

    // MARK: - Internals

    private enum DiscoveryResult: Sendable {
        case dial(PeerEndpoint, PeerConnection?)
        case seeds([PeerEndpoint])
    }

    /// Starts dials for the next eligible candidates, up to the parallel
    /// and per-round caps. Candidates the diversity policy would refuse are
    /// skipped before the dial, not after: they would cost a connection
    /// attempt and a slot in the race for nothing.
    private func launchEligibleDials(from queue: [PeerCandidate], next: inout Int,
                                     running: inout Int,
                                     into group: inout TaskGroup<DiscoveryResult>) {
        while next < queue.count, running < maxParallelDials,
              attemptsThisRound < maxDialAttempts, mode == .full {
            let candidate = queue[next]
            next += 1
            guard gateways.permits(candidate.endpoint), policy.admits(candidate, given: seatedCandidates()) else { continue }
            let endpoint = candidate.endpoint
            running += 1
            attemptsThisRound += 1
            let peer = PeerConnection(endpoint: endpoint, params: params,
                                      relayPreference: relayPreference, socksProxy: gateways.proxy(for: endpoint))
            inFlight[endpoint] = peer
            group.addTask { [dialTimeout] in
                do {
                    try await peer.connect(timeout: dialTimeout)
                    return .dial(endpoint, peer)
                } catch {
                    return .dial(endpoint, nil) // unreachable or bad handshake
                }
            }
        }
    }

    /// Admits (or disconnects) a completed dial. Re-checked on arrival as
    /// well as before the dial: dials race, so two candidates from one
    /// netblock or one source class can be in flight together and the second
    /// must still be refused.
    private func seatArrival(_ peer: PeerConnection, endpoint: PeerEndpoint,
                             source: PeerSource) async {
        let candidate = PeerCandidate(endpoint: endpoint, source: source)
        guard started, mode == .full, peers.count < peerCount, !peers.contains(where: { $0.endpoint == endpoint }),
              policy.admits(candidate, given: seatedCandidates()) else {
            await peer.disconnect() // slot filled, or diversity refused it
            return
        }
        peers.append(peer)
        staleTipJudged.remove(endpoint)
        seatedSources[endpoint] = source
        if knownGood.insert(endpoint).inserted {
            knownSource[endpoint] = source
            persistKnownGood()
        }
    }

    /// Drops seats whose connection has gone and refills them. The removal
    /// is by endpoint, as `pruneRelaySeats` does it: writing the survivors
    /// back reinstated any seat a `transportFailure`, `misbehaving` or
    /// `enterRelayOnly` removed while the `isConnected` reads were suspended,
    /// and a narrowing that landed inside this pass was undone by it.
    private func pruneAndReplenish() async {
        var dead: Set<PeerEndpoint> = []
        for peer in peers where await peer.isConnected == false {
            dead.insert(peer.endpoint)
        }
        guard started, mode == .full else { return }
        peers.removeAll { dead.contains($0.endpoint) }
        await replenish()
    }

    /// The relay-only session's own monitor: prune, on the replacement
    /// monitor's cadence, and never dial.
    ///
    /// `enterRelayOnly` cancels the replacement monitor, and that monitor is
    /// the only thing in the pool that drops a seat nobody reported. So a
    /// remote that simply went away — the ordinary end of a mobile
    /// connection — left its seat in `peers` for as long as the session
    /// lasted: `connectedPeers()` kept reporting it, `TxBroadcaster.announce`
    /// skipped it on a failed send without saying so, and the session had
    /// nothing left that could end it. This is the half of that monitor a
    /// relay-only session can have, with the dialling half left out.
    private func startRelayPruneMonitor() {
        relayPruneTask?.cancel()
        let interval = monitorInterval
        relayPruneTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: interval)
                guard !Task.isCancelled, let self else { return }
                await self.pruneRelaySeats()
            }
        }
    }

    /// Drops the seats whose connection has gone. Dials nothing: the session
    /// holds what it was given, and this only stops it claiming more.
    ///
    /// The removal is by endpoint rather than by writing back the survivors.
    /// `pruneAndReplenish` reads `peers`, awaits every `isConnected` and then
    /// assigns `alive`, which reinstates any seat a `transportFailure` or
    /// `misbehaving` removed while those awaits ran; it gets away with it
    /// because it replenishes straight afterwards, and this cannot dial, so a
    /// seat put back here would be put back for good.
    private func pruneRelaySeats() async {
        guard mode == .relayOnly else { return }
        var dead: Set<PeerEndpoint> = []
        for peer in peers where await peer.isConnected == false {
            dead.insert(peer.endpoint)
        }
        guard !dead.isEmpty else { return }
        peers.removeAll { dead.contains($0.endpoint) }
    }

    /// Dials again immediately (UI retry after exhaustion). No-op while a
    /// round is in flight, the pool is full, or the pool is stopped or
    /// relaying only — `start()` is what leaves a relay-only session.
    public func retry() async {
        await replenish()
    }

    /// Races up to `maxParallelDials` candidates at a time (each with the
    /// short `dialTimeout`) until the pool is full or the round's candidates
    /// — capped at `maxDialAttempts` — are used up. Once full, close surplus
    /// connections before draining the race: their timeouts must not delay
    /// callers that are waiting to begin sync.
    /// Whether a header sync may try another peer: `maxAttempts` is a budget
    /// of peers burned for a data fault, `maxTransportRetries` a separate one
    /// for peers that were merely slow, and the run stops when either is spent.
    private static func budgetRemains(attempts: Int, of maxAttempts: Int,
                                      transportRetries: Int, of maxTransportRetries: Int) -> Bool {
        attempts < maxAttempts && transportRetries < maxTransportRetries
    }

    /// What one header sync attempt against one peer came to.
    private enum SyncAttempt {
        case synced(HeaderChain.SyncOutcome)
        /// The peer's fault, and permanent: headers that do not link, claimed
        /// work it does not have, a framing violation, an unexpected message.
        case burned(any Error)
        /// Slow or dropped, not dishonest: the endpoint is cooled off and the
        /// attempt does not count against the peers the budget may burn.
        case transient(any Error)
    }

    /// One attempt, classified. Storage faults are this device's and are
    /// rethrown as they are; a cancellation is local control flow, kept out
    /// of the classification so the connection stays eligible for the next
    /// foreground sync instead of poisoning the session pool.
    private func attemptSync(_ chain: HeaderChain, primary peer: PeerConnection,
                             timeoutPerPeer: Duration) async throws -> SyncAttempt {
        do {
            return .synced(try await settledSync(chain, primary: peer, timeoutPerPeer: timeoutPerPeer))
        } catch let error as HeaderChainError {
            try Self.rethrowIfOurs(error)
            return .burned(error)
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as PeerError where error.isTransport {
            return .transient(error)
        } catch {
            return .burned(error)
        }
    }

    /// A header-chain error that is this device's, not the peer's: corrupt or
    /// unavailable storage is rethrown as is, because burning a peer for it
    /// would blame the wrong side and keep going over the same broken store.
    private static func rethrowIfOurs(_ error: HeaderChainError) throws {
        switch error {
        case .storageCorrupt, .storageUnavailable: throw error
        default: break
        }
    }

    private var hasRoomForFullService: Bool {
        started && mode == .full && peers.count < peerCount
    }

    private var canReplenish: Bool { hasRoomForFullService && !replenishing }

    private func replenish() async {
        // `mode` is checked here rather than at each caller: every path back
        // into dialling — the monitor, a peer dropped for misconduct or a
        // timeout, the UI's retry — runs through this one function, and a
        // relay-only session must not dial from any of them.
        guard canReplenish else { return }
        replenishing = true
        attemptsThisRound = 0
        relaxOverlayMix = exhausted
        exhausted = false
        defer { finishReplenish() }

        // Give manual / persisted / census candidates the first dial slots.
        // DNS completions then join the same race as connections; explicitly
        // configured peers get a chance to fill the pool without DNS.
        // Cooling endpoints are skipped, not rejected: they come back into the
        // queue on a later round once their timer expires (#82).
        let excluded = Set(peers.map(\.endpoint)).union(rejectedForSession).union(coolingEndpoints)
        var queue = localCandidates(excluding: excluded)
        var resolvedSeeds = false
        var seen = excluded.union(queue.map(\.endpoint))
        var next = 0
        await withTaskGroup(of: DiscoveryResult.self) { group in
            var running = 0
            var seedLookups = 0
            while hasRoomForFullService {
                launchEligibleDials(from: queue, next: &next, running: &running,
                                    into: &group)
                // Lookups share the completion queue with handshakes, so a
                // slow seed cannot hide a ready connection or another seed's
                // results. Local peers still get the first dial slots.
                if shouldResolveSeeds(next: next, queued: queue.count,
                                      resolved: resolvedSeeds, running: running) {
                    resolvedSeeds = true
                    seedLookups = launchSeedLookups(into: &group)
                }
                guard running > 0 || seedLookups > 0,
                      let result = await group.next() else { break }
                switch result {
                case let .seeds(endpoints):
                    seedLookups -= 1
                    queue += endpoints.filter { gateways.permits($0) && seen.insert($0).inserted }
                        .map { PeerCandidate(endpoint: $0, source: .dnsSeed) }
                case let .dial(endpoint, dialed):
                    running -= 1
                    inFlight.removeValue(forKey: endpoint)
                    guard let peer = dialed else { continue }
                    let source = queue.first { $0.endpoint == endpoint }?.source ?? .persisted
                    await seatArrival(peer, endpoint: endpoint, source: source)
                }
            }
            await cancelSurplusDiscovery(in: &group)
        }
        await settleDiscoveryRound()
    }

    private func shouldResolveSeeds(next: Int, queued: Int, resolved: Bool, running: Int) -> Bool {
        next >= queued && !resolved && (running == 0 || manualPeers.isEmpty)
    }

    /// DNS lookups join the same completion queue as dials. An invalid or
    /// overlay-only route starts none, so a relay-only transition cannot
    /// acquire new connections through an outstanding lookup.
    private func launchSeedLookups(into group: inout TaskGroup<DiscoveryResult>) -> Int {
        guard gateways.isValid, gateways.networks.contains(.clearnet) else { return 0 }
        let seeds = params.dnsSeeds.shuffled()
        for seed in seeds {
            group.addTask { [seedResolver, params] in
                .seeds(await seedResolver.resolve(host: seed,
                    port: params.defaultPort,
                    allowPrivate: params.allowsPrivateSeedAddresses))
            }
        }
        return seeds.count
    }

    private func settleDiscoveryRound() async {
        // A round that ended because the pool narrowed is not a round that came
        // up short of peers, and a relay-only session neither evicts nor
        // refills: it holds what it was given.
        guard mode == .full else { return }
        // Judged after the round against the last validated tip, so a stale
        // peer that raced in ahead of honest ones does not keep its seat.
        let evicted = await evictStaleTips()
        exhausted = peers.count < peerCount
        if !evicted.isEmpty, started {
            // Refill the slots just freed. `replenishing` is still set here,
            // so the follow-up runs after this round has fully returned.
            Task { await self.pruneAndReplenish() }
        }
    }

    /// Disconnect resumes pending handshake continuations immediately;
    /// drain afterward so no surplus receive task keeps a socket alive.
    private func cancelSurplusDiscovery(in group: inout TaskGroup<DiscoveryResult>) async {
        group.cancelAll()
        for peer in inFlight.values { await peer.disconnect() }
        for await result in group {
            if case let .dial(endpoint, peer) = result {
                inFlight.removeValue(forKey: endpoint)
                await peer?.disconnect()
            }
        }
    }

    private func finishReplenish() {
        replenishing = false
    }

    /// The diversity rules this pool enforces, sized to its slot count.
    private var policy: DiversityPolicy {
        let networks = gateways.networks
        return DiversityPolicy(peerCount: peerCount, clearnetSelected: networks.contains(.clearnet),
                               overlayMix: !networks.contains(.clearnet) && networks.contains(.tor)
                                   && networks.contains(.i2p) && !relaxOverlayMix)
    }

    /// The class a known-good peer counts as today.
    ///
    /// `manual` is exempt from the source ceiling because a peer the user typed
    /// in is instruction rather than selection — but only while it *is* still
    /// configured. A peer that was manual once and has since been removed from
    /// settings is no longer an instruction, and letting it keep a permanent
    /// ceiling exemption would mean a transient entry buys standing that
    /// outlives it. It reverts to `persisted`, which is what it now is: a peer
    /// this device happened to connect to before.
    private func rememberedSource(_ endpoint: PeerEndpoint) -> PeerSource {
        let remembered = knownSource[endpoint] ?? .persisted
        if remembered == .manual, !manualPeers.contains(endpoint) { return .persisted }
        return remembered
    }

    /// Test seam: the class each known-good peer would be dialled under now.
    func candidateSourcesForTest() -> [PeerEndpoint: PeerSource] {
        Dictionary(localCandidates(excluding: []).map { ($0.endpoint, $0.source) },
                   uniquingKeysWith: { first, _ in first })
    }

    func candidateEndpointsForTest() -> [PeerEndpoint] {
        localCandidates(excluding: []).map(\.endpoint)
    }

    /// What is connected right now, with each peer's origin.
    /// The provenance class this pool reached `endpoint` through, when it
    /// knows one. Consumers use it to make comparisons span acquisition
    /// channels (#3): two peers from one class agreeing is one channel
    /// agreeing with itself.
    public func source(of endpoint: PeerEndpoint) -> PeerSource? {
        knownSource[endpoint]
    }

    private func seatedCandidates() -> [PeerCandidate] {
        peers.map {
            PeerCandidate(endpoint: $0.endpoint, source: seatedSources[$0.endpoint] ?? .persisted)
        }
    }

    /// Manual peers, then persisted good peers, then the shipped census.
    ///
    /// A persisted peer keeps the class it was first found under, so a peer
    /// originally discovered through a DNS seed still counts as one for
    /// diversity rather than collapsing into `persisted` after its first
    /// connection.
    private func localCandidates(excluding connected: Set<PeerEndpoint>) -> [PeerCandidate] {
        var ordered: [PeerCandidate] = []
        for endpoint in manualPeers {
            ordered.append(PeerCandidate(endpoint: endpoint, source: .manual))
        }
        for endpoint in knownGood.subtracting(manualPeers) {
            ordered.append(PeerCandidate(endpoint: endpoint, source: rememberedSource(endpoint)))
        }
        let automatic = interleavedCatalogEndpoints(censusCatalog)
        let preferred = automatic.filter { !avoidOnReset.contains($0) }
        let previous = automatic.filter { avoidOnReset.contains($0) }
        ordered += (preferred + previous).map { PeerCandidate(endpoint: $0, source: .census) }
        var seen = connected
        return ordered.filter { gateways.permits($0.endpoint) && seen.insert($0.endpoint).inserted }
    }

    /// A large Tor list must not occupy every initial dial while a usable
    /// clearnet candidate waits behind it. Shuffle within each network, then
    /// interleave the networks; provenance checks still govern actual seats.
    private func interleavedCatalogEndpoints(_ catalog: CensusCatalog?) -> [PeerEndpoint] {
        let lists = PeerNetwork.allCases.filter { gateways.networks.contains($0) }.map {
            (catalog?.networks[$0.rawValue]?.map(\.endpoint) ?? []).shuffled()
        }
        return (0..<(lists.map(\.count).max() ?? 0)).flatMap { index in
            lists.compactMap { index < $0.count ? $0[index] : nil }
        }
    }

    /// The most a peers file may weigh: the writer keeps 100 entries, so a
    /// larger file was not written by this code and is not read.
    static let maximumPeersFileBytes = 256 * 1_024

    /// Reads the peers file only after measuring it, so a planted file is
    /// refused before it is held rather than after.
    static func boundedRead(_ url: URL) -> Data? {
        // `attributesOfItem`, not `resourceValues`: the latter caches on the
        // URL value, so a file rewritten under the same URL keeps its old size.
        guard let size = try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int,
              size <= maximumPeersFileBytes,
              let data = try? Data(contentsOf: url), data.count <= maximumPeersFileBytes
        else { return nil }
        return data
    }

    private func persistKnownGood() {
        guard let peersFileURL else { return }
        let stored = knownGood.prefix(100).map {
            PeerCandidate(endpoint: $0, source: knownSource[$0] ?? .persisted)
        }
        if let data = try? JSONEncoder().encode(PersistedPeers(Array(stored))) {
            try? data.write(to: peersFileURL,
                            options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        }
    }
}
