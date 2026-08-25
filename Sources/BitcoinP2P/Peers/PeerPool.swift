import Foundation

public enum PeerPoolHeaderSyncError: LocalizedError, Equatable {
    case noPeers
    case exhausted(attempts: Int, lastError: String)
    /// Every peer is briefly cooling off after a slow reply. Distinct from
    /// `noPeers`, which means there is nothing to dial at all (#82).
    case allPeersCoolingDown(cooling: Int, lastError: String)

    public var errorDescription: String? {
        switch self {
        case .noPeers:
            "No Bitcoin peers are available for block-header sync."
        case let .exhausted(attempts, lastError):
            "Winnow tried \(attempts) Bitcoin peer\(attempts == 1 ? "" : "s"), but none supplied a usable block-header chain. Last error: \(lastError)"
        case let .allPeersCoolingDown(cooling, lastError):
            "\(cooling) Bitcoin peer\(cooling == 1 ? " was" : "s were") slow to answer and \(cooling == 1 ? "is" : "are") being rested briefly. Syncing will resume on its own. Last error: \(lastError)"
        }
    }
}

/// A small pool of outbound peers (default 3). Candidates come from manually
/// supplied endpoints, a persisted good-peers JSON file, the network's
/// hardcoded fallback peers, and DNS seeds resolved over DoH (dns-json)
/// with getaddrinfo as fallback. Dials race a batch of candidates at once
/// (short per-attempt timeout) so a fresh launch fills the pool in seconds;
/// a round that runs out of candidates below target is reported as
/// `exhausted` in `connectionStatus`. A monitor task prunes dead connections
/// and connects replacements. Deliberately simple: no scoring buckets, no
/// addr gossip — misbehaving peers are dropped and replaced.
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
    private var started = false
    private var replenishing = false
    private var attemptsThisRound = 0
    private var exhausted = false
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
        ConnectionStatus(connected: peers.count, target: peerCount,
                         dialing: replenishing, attempts: attemptsThisRound,
                         exhausted: exhausted)
    }

    public init(params: NetworkParams, peerCount: Int = 3,
                manualPeers: [PeerEndpoint] = [], peersFileURL: URL? = nil,
                relayPreference: Bool = false,
                dialTimeout: Duration = .seconds(5),
                maxParallelDials: Int = 5, maxDialAttempts: Int = 50,
                seedResolver: SeedResolver = .live(),
                now: @Sendable @escaping () -> ContinuousClock.Instant = { ContinuousClock.now }) {
        self.params = params
        self.peerCount = peerCount
        self.manualPeers = manualPeers
        self.peersFileURL = peersFileURL
        self.relayPreference = relayPreference
        self.dialTimeout = dialTimeout
        self.maxParallelDials = maxParallelDials
        self.maxDialAttempts = maxDialAttempts
        self.seedResolver = seedResolver
        self.now = now
        if let peersFileURL,
           let data = try? Data(contentsOf: peersFileURL),
           let stored = PersistedPeers.decode(data) {
            knownGood = Set(stored.map(\.endpoint))
            knownSource = Dictionary(stored.map { ($0.endpoint, $0.source) },
                                     uniquingKeysWith: { first, _ in first })
        }
    }

    /// Connects to `peerCount` peers and starts the replacement monitor.
    public func start() async {
        guard !started else { return }
        started = true
        await replenish()
        monitorTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(30))
                guard !Task.isCancelled, let self else { return }
                await self.pruneAndReplenish()
            }
        }
    }

    /// Disconnects everything and persists the good-peers list.
    public func stop() async {
        monitorTask?.cancel()
        monitorTask = nil
        started = false
        for peer in peers { await peer.disconnect() }
        peers = []
        rejectedForSession = []
        persistKnownGood()
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
        var attempts = 0
        var transportRetries = 0
        var lastError: (any Error)?

        while attempts < maxAttempts, transportRetries < maxTransportRetries {
            guard let peer = peers.first else {
                // An empty pool used to mean there were no candidates. Since
                // transport failures cool endpoints off rather than banning
                // them, it can now mean "everyone is briefly unavailable" —
                // which is a normal transient state, not a peerless one.
                //
                // Reporting it as `noPeers` would tell the user no Bitcoin
                // peers are available at all while a peer sits thirty seconds
                // from eligibility. That is the same overreaction #82 exists
                // to remove, moved up a layer and made less truthful than
                // before the change.
                if !coolingEndpoints.isEmpty || transportRetries > 0 {
                    throw PeerPoolHeaderSyncError.allPeersCoolingDown(
                        cooling: coolingEndpoints.count,
                        lastError: lastError?.localizedDescription
                            ?? "the connected peers stopped answering")
                }
                if attempts == 0 { throw PeerPoolHeaderSyncError.noPeers }
                break
            }
            // `maxAttempts` is a budget of peers *burned*, so a peer that was
            // only slow must not spend it. Otherwise a run of hiccups declares
            // exhaustion while healthy endpoints sit in the pool cooling off,
            // and the report the user gets moves up a layer without the cause
            // changing (#82).
            var burnedAPeer = true
            do {
                let outcome = try await chain.sync(using: peer, timeout: timeoutPerPeer)
                transportSucceeded(peer.endpoint)
                return outcome
            } catch let error as HeaderChainError {
                switch error {
                case .storageCorrupt, .storageUnavailable:
                    throw error
                default:
                    break
                }
                // The peer sent headers that do not link, or claim work they
                // do not have. That is a data fault, and permanent.
                lastError = error
                await misbehaving(peer, reason: error.localizedDescription)
            } catch is CancellationError {
                // App lifecycle cancellation is local control flow, not peer
                // misconduct. Keep the connection eligible for the next
                // foreground sync instead of poisoning the session pool.
                throw CancellationError()
            } catch let error as PeerError where error.isTransport {
                // Slow or dropped, not dishonest. Cool the endpoint off and
                // try the next peer; this attempt does not count as one of the
                // peers the budget allows us to burn.
                lastError = error
                burnedAPeer = false
                transportRetries += 1
                await transportFailure(peer, reason: error.localizedDescription)
            } catch {
                // Anything else — framing violations, unexpected messages —
                // is the peer's fault and stays permanent.
                lastError = error
                await misbehaving(peer, reason: error.localizedDescription)
            }
            if burnedAPeer { attempts += 1 }
        }

        // Two ways out of that loop: peers burned, or transport retries spent.
        // Only the first is exhaustion. Reporting the second as "tried 0 peers"
        // is both wrong and unhelpful — the peers exist and are resting.
        if attempts == 0, !coolingEndpoints.isEmpty || transportRetries > 0 {
            throw PeerPoolHeaderSyncError.allPeersCoolingDown(
                cooling: max(coolingEndpoints.count, 1),
                lastError: lastError?.localizedDescription
                    ?? "the connected peers stopped answering")
        }
        throw PeerPoolHeaderSyncError.exhausted(
            attempts: attempts,
            lastError: lastError?.localizedDescription ?? "no additional peers were available")
    }

    // MARK: - Internals

    private func pruneAndReplenish() async {
        var alive: [PeerConnection] = []
        for peer in peers where await peer.isConnected {
            alive.append(peer)
        }
        peers = alive
        await replenish()
    }

    /// Dials again immediately (UI retry after exhaustion). No-op while a
    /// round is in flight, the pool is full, or the pool is stopped.
    public func retry() async {
        await replenish()
    }

    /// Races up to `maxParallelDials` candidates at a time (each with the
    /// short `dialTimeout`) until the pool is full or the round's candidates
    /// — capped at `maxDialAttempts` — are used up. In-flight stragglers are
    /// never cancelled (PeerConnection's checked continuations do not respond
    /// to cancellation); they resolve on their own timeout and a late success
    /// with no slot left is disconnected again.
    private func replenish() async {
        guard started, !replenishing, peers.count < peerCount else { return }
        replenishing = true
        attemptsThisRound = 0
        exhausted = false
        defer { replenishing = false }

        // Dial manual / persisted / fallback first. Resolve DNS seeds only
        // if those sources cannot fill the pool — a working manual peer
        // must not wait on DoH.
        // Cooling endpoints are skipped, not rejected: they come back into the
        // queue on a later round once their timer expires (#82).
        let excluded = Set(peers.map(\.endpoint)).union(rejectedForSession).union(coolingEndpoints)
        var queue = localCandidates(excluding: excluded)
        var resolvedSeeds = false
        var needed = peerCount - peers.count
        var next = 0
        await withTaskGroup(of: (PeerEndpoint, PeerConnection?).self) { group in
            var running = 0
            while needed > 0, started {
                if next >= queue.count && !resolvedSeeds {
                    resolvedSeeds = true
                    var seen = excluded
                    seen.formUnion(queue.map(\.endpoint))
                    queue.append(contentsOf: await seedCandidates(excluding: seen))
                }
                while next < queue.count, running < maxParallelDials,
                      attemptsThisRound < maxDialAttempts {
                    let candidate = queue[next]
                    next += 1
                    // Skipped before the dial, not after: a candidate the
                    // policy would refuse costs a connection attempt and a
                    // slot in the race for nothing.
                    guard policy.admits(candidate, given: seatedCandidates()) else { continue }
                    let endpoint = candidate.endpoint
                    running += 1
                    attemptsThisRound += 1
                    group.addTask { [params, relayPreference, dialTimeout] in
                        let peer = PeerConnection(endpoint: endpoint, params: params,
                                                  relayPreference: relayPreference)
                        do {
                            try await peer.connect(timeout: dialTimeout)
                            return (endpoint, peer)
                        } catch {
                            return (endpoint, nil) // unreachable or bad handshake
                        }
                    }
                }
                guard running > 0, let (endpoint, dialed) = await group.next() else { break }
                running -= 1
                guard let peer = dialed else { continue }
                let source = queue.first { $0.endpoint == endpoint }?.source ?? .persisted
                let candidate = PeerCandidate(endpoint: endpoint, source: source)
                // Re-checked on arrival as well as before the dial. Dials race,
                // so two candidates from one block or one class can be in
                // flight together and the second must still be refused.
                if started, needed > 0, !peers.contains(where: { $0.endpoint == endpoint }),
                   policy.admits(candidate, given: seatedCandidates()) {
                    peers.append(peer)
                    seatedSources[endpoint] = source
                    needed -= 1
                    if knownGood.insert(endpoint).inserted {
                        knownSource[endpoint] = source
                        persistKnownGood()
                    }
                } else {
                    await peer.disconnect() // slot filled, or diversity refused it
                }
            }
        }
        exhausted = peers.count < peerCount
    }

    /// The diversity rules this pool enforces, sized to its slot count.
    private var policy: DiversityPolicy { DiversityPolicy(peerCount: peerCount) }

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

    /// Manual peers, then persisted good peers, then hardcoded fallbacks.
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
        for endpoint in params.fallbackPeers {
            ordered.append(PeerCandidate(endpoint: endpoint, source: .fallback))
        }
        var seen = connected
        return ordered.filter { seen.insert($0.endpoint).inserted }
    }

    /// DNS-seed results (DoH, then getaddrinfo). Called only when local
    /// candidates did not fill the pool.
    private func seedCandidates(excluding connected: Set<PeerEndpoint>) async -> [PeerCandidate] {
        let seeds = await seedResolver.resolveSeeds(
            params.dnsSeeds, port: params.defaultPort,
            allowPrivate: params.allowsPrivateSeedAddresses
        )
        var seen = connected
        return seeds.filter { seen.insert($0).inserted }
            .map { PeerCandidate(endpoint: $0, source: .dnsSeed) }
    }

    private func persistKnownGood() {
        guard let peersFileURL else { return }
        let stored = knownGood.prefix(100).map {
            PeerCandidate(endpoint: $0, source: knownSource[$0] ?? .persisted)
        }
        if let data = try? JSONEncoder().encode(PersistedPeers(Array(stored))) {
            try? data.write(to: peersFileURL, options: .atomic)
        }
    }
}
