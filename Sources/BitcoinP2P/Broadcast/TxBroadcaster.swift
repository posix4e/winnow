import Foundation

/// P2P transaction relay (docs/write-side.md §7): announce via
/// `inv(MSG_WITNESS_TX)` to connected peers (pool default: 3), answer
/// `getdata` with the raw transaction, and re-announce on an exponential
/// backoff until the caller reports confirmation (observed via FilterSync
/// block matches) or cancels. Pending transactions persist as JSON — raw tx,
/// feerate and next backoff attempt — so relay survives restarts.
///
/// Relay hardening on top of the basic flood:
/// - **Per-peer state machine** (`announced → requested → served`, plus
///   `failed` on timeout/disconnect and `deprioritized` for a peer that never
///   answers `maxAnnouncementsPerPeer` invs with getdata — deprioritized peers
///   are skipped by future announcements of that tx).
/// - **BIP133 feefilter reaction**: when the minimum feefilter across
///   connected peers rises above a pending tx's feerate (no remaining peer
///   will relay it), `.feeFloorExceeded` is emitted once per crossing; the
///   caller decides whether to bump the fee.
public actor TxBroadcaster {
    public enum Event: Equatable, Sendable {
        /// The tx was inv-announced to this many peers.
        case announced(txid: Data, peerCount: Int)
        /// A peer answered our inv with getdata.
        case requested(txid: Data, peer: PeerEndpoint)
        /// The tx was sent to a peer that asked for it.
        case served(txid: Data, peer: PeerEndpoint)
        /// Relay to a peer failed: announcement timed out, the peer
        /// disconnected, or serving the tx failed.
        case failed(txid: Data, peer: PeerEndpoint, reason: String)
        /// A peer never sent getdata after `maxAnnouncementsPerPeer`
        /// announcements; future announcements of this tx skip it.
        case deprioritized(txid: Data, peer: PeerEndpoint)
        case confirmed(txid: Data)
        case cancelled(txid: Data)
        /// The minimum BIP133 feefilter across connected peers (sat/kvB)
        /// rose above this tx's feerate — no peer will relay it as-is.
        case feeFloorExceeded(txid: Data, floor: Int64)
    }

    /// Per-peer relay progress for one pending transaction.
    public enum PeerAnnouncementState: String, Equatable, Sendable {
        case announced, requested, served, failed, deprioritized
    }

    private struct PeerRelay {
        var state: PeerAnnouncementState
        var announcements: Int
        var lastAnnouncedAt: Date
    }

    private struct Pending {
        let rawTx: Data
        let transaction: Transaction
        /// Feerate (sat/vB) the caller paid, for the feefilter comparison.
        /// nil = unknown (no fee-floor events for this tx).
        let feeRateSatPerVByte: Double?
        /// Per-peer relay state, keyed by endpoint description.
        var peers: [String: PeerRelay] = [:]
        /// Backoff attempts fired so far (0 = only the initial announcement).
        var attempt: Int
        var nextAttemptAt: Date
        var feeFloorExceededEmitted = false
    }

    /// JSON persistence shape: txid hex → relay record.
    private struct StoredPending: Codable {
        struct StoredTx: Codable {
            var rawTx: String
            var feeRateSatPerVByte: Double?
            var attempt: Int
            /// Next backoff attempt, seconds since 1970.
            var nextAttemptAt: TimeInterval
        }
        var transactions: [String: StoredTx]
    }

    /// Pre-backoff store shape (txid hex → raw tx hex), still accepted on load.
    private struct LegacyStoredPending: Codable {
        var transactions: [String: String]
    }

    private let pool: PeerPool
    private let storageURL: URL?
    private let rebroadcastBaseInterval: Duration
    private let maxRebroadcastInterval: Duration
    private let maxAnnouncementsPerPeer: Int
    /// How long an `announced` entry may sit without getdata before it is
    /// marked `failed` (and retried on the next backoff attempt).
    private let announcementTimeout: Duration
    private let now: @Sendable () -> Date
    private var pending: [Data: Pending] = [:]
    private var rebroadcastTask: Task<Void, Never>?
    private var listenedPeers: Set<String> = []
    private var subscribers: [UUID: AsyncStream<Event>.Continuation] = [:]

    public init(pool: PeerPool, storageURL: URL? = nil,
                rebroadcastBaseInterval: Duration = .seconds(60),
                maxRebroadcastInterval: Duration = .seconds(3_600),
                maxAnnouncementsPerPeer: Int = 3,
                announcementTimeout: Duration = .seconds(120),
                now: @Sendable @escaping () -> Date = { Date() }) {
        self.pool = pool
        self.storageURL = storageURL
        self.rebroadcastBaseInterval = rebroadcastBaseInterval
        self.maxRebroadcastInterval = maxRebroadcastInterval
        self.maxAnnouncementsPerPeer = maxAnnouncementsPerPeer
        self.announcementTimeout = announcementTimeout
        self.now = now
        if let storageURL,
           let data = try? Data(contentsOf: storageURL) {
            if let stored = try? JSONDecoder().decode(StoredPending.self, from: data) {
                for (txidHex, record) in stored.transactions {
                    guard let txid = Data(hex: txidHex), let rawTx = Data(hex: record.rawTx),
                          let transaction = try? Transaction.decode(rawTx), transaction.txid == txid
                    else { continue }
                    pending[txid] = Pending(rawTx: rawTx, transaction: transaction,
                                            feeRateSatPerVByte: record.feeRateSatPerVByte,
                                            attempt: record.attempt,
                                            nextAttemptAt: Date(timeIntervalSince1970: record.nextAttemptAt))
                }
            } else if let legacy = try? JSONDecoder().decode(LegacyStoredPending.self, from: data) {
                for (txidHex, rawHex) in legacy.transactions {
                    guard let txid = Data(hex: txidHex), let rawTx = Data(hex: rawHex),
                          let transaction = try? Transaction.decode(rawTx), transaction.txid == txid
                    else { continue }
                    // Due immediately: the restored loop re-announces at once.
                    pending[txid] = Pending(rawTx: rawTx, transaction: transaction,
                                            feeRateSatPerVByte: nil, attempt: 0,
                                            nextAttemptAt: now())
                }
            }
        }
        // Restored transactions resume their backoff schedule; an overdue
        // attempt fires as soon as the loop runs.
        if !pending.isEmpty {
            Task { await self.scheduleRebroadcast() }
        }
    }

    /// txids (internal byte order) awaiting confirmation.
    public var pendingTxids: [Data] { Array(pending.keys) }

    public func events() -> AsyncStream<Event> {
        let id = UUID()
        return AsyncStream { continuation in
            subscribers[id] = continuation
            continuation.onTermination = { _ in
                Task { await self.removeSubscriber(id) }
            }
        }
    }

    /// Validates, stores and announces a raw signed transaction.
    /// `feeRateSatPerVByte` enables the BIP133 fee-floor events.
    /// Returns its txid (internal byte order).
    @discardableResult
    public func broadcast(_ rawTx: Data, feeRateSatPerVByte: Double? = nil) async throws -> Data {
        let transaction = try Transaction.decode(rawTx)
        let txid = transaction.txid
        pending[txid] = Pending(rawTx: rawTx, transaction: transaction,
                                feeRateSatPerVByte: feeRateSatPerVByte,
                                attempt: 0,
                                nextAttemptAt: now() + Self.timeInterval(backoffInterval(attempt: 0)))
        try persist()
        await ensurePeerListeners()
        await announce(txid: txid)
        await checkFeeFloors()
        scheduleRebroadcast()
        return txid
    }

    /// Called when the tx is seen in a matched block (or otherwise confirmed).
    public func markConfirmed(_ txid: Data) {
        if pending.removeValue(forKey: txid) != nil {
            try? persist()
            emit(.confirmed(txid: txid))
            scheduleRebroadcast()
        }
    }

    /// Stops relaying a pending tx without a confirmation (e.g. the user
    /// replaced it with a fee-bumped transaction).
    public func cancel(_ txid: Data) {
        if pending.removeValue(forKey: txid) != nil {
            try? persist()
            emit(.cancelled(txid: txid))
            scheduleRebroadcast()
        }
    }

    /// Per-peer relay state for a pending tx, keyed by endpoint description.
    public func relayStatus(_ txid: Data) -> [String: PeerAnnouncementState] {
        pending[txid]?.peers.mapValues(\.state) ?? [:]
    }

    // MARK: - Internals

    /// Test-visible backoff accessors (@testable).
    func attemptCount(_ txid: Data) -> Int? { pending[txid]?.attempt }
    func nextAttemptDate(_ txid: Data) -> Date? { pending[txid]?.nextAttemptAt }

    private func removeSubscriber(_ id: UUID) {
        subscribers.removeValue(forKey: id)
    }

    private func emit(_ event: Event) {
        for subscriber in subscribers.values { subscriber.yield(event) }
    }

    /// base × 2^attempt, capped at `cap`.
    ///
    /// A pure function of the attempt count and the configured intervals: it
    /// never reads the clock, so the schedule can be checked exhaustively
    /// without timing anything. Asserting the step sizes against wall-clock
    /// observations instead measures poll latency on a loaded runner, which is
    /// how this became a flaky release gate (#138).
    static func backoffInterval(attempt: Int, base: Duration, cap: Duration) -> Duration {
        var interval = base
        for _ in 0 ..< attempt {
            let doubled = interval + interval
            guard doubled < cap else { return cap }
            interval = doubled
        }
        return min(interval, cap)
    }

    private func backoffInterval(attempt: Int) -> Duration {
        Self.backoffInterval(attempt: attempt,
                             base: rebroadcastBaseInterval,
                             cap: maxRebroadcastInterval)
    }

    private static func timeInterval(_ duration: Duration) -> TimeInterval {
        let components = duration.components
        return TimeInterval(components.seconds) + TimeInterval(components.attoseconds) / 1e18
    }

    /// inv-announces one pending tx to every eligible peer. State reads and
    /// writes go through `pending` afresh each step — the getdata listener
    /// may mutate the same entry while a send is suspended.
    private func announce(txid: Data) async {
        guard pending[txid] != nil else { return }
        let peers = await pool.connectedPeers()
        let announcement = PeerMessage.inv(InventoryPayload([InventoryVector(type: .witnessTx, hash: txid)]))
        var announced = 0
        for peer in peers {
            let key = peer.endpoint.description
            if let relay = pending[txid]?.peers[key] {
                if relay.state == .deprioritized { continue }
                if relay.state != .requested, relay.state != .served,
                   relay.announcements >= maxAnnouncementsPerPeer {
                    pending[txid]?.peers[key]?.state = .deprioritized
                    emit(.deprioritized(txid: txid, peer: peer.endpoint))
                    continue
                }
            }
            guard (try? await peer.send(announcement)) != nil else { continue }
            announced += 1
            if var relay = pending[txid]?.peers[key] {
                relay.announcements += 1
                relay.lastAnnouncedAt = now()
                if relay.state == .failed { relay.state = .announced } // retry after timeout/disconnect
                pending[txid]?.peers[key] = relay
            } else {
                pending[txid]?.peers[key] = PeerRelay(state: .announced, announcements: 1,
                                                      lastAnnouncedAt: now())
            }
        }
        emit(.announced(txid: txid, peerCount: announced))
    }

    /// Marks `announced` entries whose getdata never came within
    /// `announcementTimeout` as `failed`; the next attempt re-announces.
    private func expireStaleAnnouncements(txid: Data) {
        guard let entry = pending[txid] else { return }
        let deadline = now() - Self.timeInterval(announcementTimeout)
        for (key, relay) in entry.peers
        where relay.state == .announced && relay.lastAnnouncedAt < deadline {
            pending[txid]?.peers[key]?.state = .failed
            if let endpoint = endpoint(forKey: key) {
                emit(.failed(txid: txid, peer: endpoint, reason: "announcement timeout"))
            }
        }
    }

    /// Reconstructs an endpoint from its dictionary key ("host:port").
    private func endpoint(forKey key: String) -> PeerEndpoint? {
        guard let separator = key.lastIndex(of: ":"),
              let port = UInt16(key[key.index(after: separator)...]) else { return nil }
        return PeerEndpoint(host: String(key[key.startIndex ..< separator]), port: port)
    }

    /// Marks everything relayed to this peer `failed` (disconnect/serve
    /// failure); deprioritized entries stay untouched.
    private func markPeerFailed(_ peer: PeerConnection, reason: String) {
        let key = peer.endpoint.description
        for (txid, entry) in pending {
            guard let relay = entry.peers[key],
                  relay.state != .failed, relay.state != .deprioritized else { continue }
            pending[txid]?.peers[key]?.state = .failed
            emit(.failed(txid: txid, peer: peer.endpoint, reason: reason))
        }
    }

    /// Emits `.feeFloorExceeded` when even the most lenient peer's BIP133
    /// feefilter exceeds a pending tx's feerate (once per crossing; the flag
    /// resets when the floor drops back below). A peer that never sent a
    /// feefilter relays anything, so it counts as floor 0.
    private func checkFeeFloors() async {
        var floors: [Int64] = []
        for peer in await pool.connectedPeers() {
            floors.append(await peer.feeFilter ?? 0)
        }
        guard let minimum = floors.min() else { return }
        for (txid, entry) in pending {
            guard let rate = entry.feeRateSatPerVByte else { continue }
            let exceeded = Double(minimum) > rate * 1_000
            if exceeded, !entry.feeFloorExceededEmitted {
                pending[txid]?.feeFloorExceededEmitted = true
                emit(.feeFloorExceeded(txid: txid, floor: minimum))
            } else if !exceeded, entry.feeFloorExceededEmitted {
                pending[txid]?.feeFloorExceededEmitted = false
            }
        }
    }

    /// (Re)schedules the backoff loop: sleeps until the earliest pending
    /// `nextAttemptAt`, fires due attempts, repeats. Called whenever the
    /// pending set or its schedule changes; stops when nothing is pending.
    private func scheduleRebroadcast() {
        rebroadcastTask?.cancel()
        guard !pending.isEmpty else {
            rebroadcastTask = nil
            return
        }
        rebroadcastTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                guard let next = await self.pending.values.map(\.nextAttemptAt).min() else { return }
                let wait = next.timeIntervalSince(self.now())
                if wait > 0 {
                    try? await Task.sleep(for: .seconds(wait))
                    guard !Task.isCancelled else { return }
                }
                await self.fireDueAttempts()
            }
        }
    }

    /// Announces every tx whose backoff attempt is due, then advances its
    /// schedule and persists.
    private func fireDueAttempts() async {
        await ensurePeerListeners()
        let firedAt = now()
        var fired = false
        for txid in pending.keys.sorted(by: { $0.hex < $1.hex }) {
            guard let entry = pending[txid], entry.nextAttemptAt <= firedAt else { continue }
            expireStaleAnnouncements(txid: txid)
            await announce(txid: txid)
            guard var updated = pending[txid] else { continue } // confirmed/cancelled mid-announce
            updated.attempt += 1
            updated.nextAttemptAt = firedAt + Self.timeInterval(backoffInterval(attempt: updated.attempt))
            pending[txid] = updated
            fired = true
        }
        if fired { try? persist() }
        await checkFeeFloors()
    }

    /// Subscribes to getdata/feefilter traffic on every connected peer
    /// (once per peer).
    private func ensurePeerListeners() async {
        for peer in await pool.connectedPeers() {
            let key = peer.endpoint.description
            guard !listenedPeers.contains(key) else { continue }
            listenedPeers.insert(key)
            Task { await self.listen(to: peer) }
        }
    }

    private func listen(to peer: PeerConnection) async {
        let stream = await peer.events()
        do {
            for try await event in stream {
                switch event {
                case let .message(message):
                    switch message {
                    case let .getdata(payload):
                        await serve(payload, to: peer)
                    case .feefilter:
                        await checkFeeFloors()
                    default:
                        continue
                    }
                case .disconnected:
                    markPeerFailed(peer, reason: "disconnected")
                }
            }
        } catch {
            // Peer stream failed; the pool replaces the peer and the next
            // announce cycle attaches a listener to the replacement.
            markPeerFailed(peer, reason: "disconnected")
        }
        listenedPeers.remove(peer.endpoint.description)
    }

    private func serve(_ payload: InventoryPayload, to peer: PeerConnection) async {
        let key = peer.endpoint.description
        for vector in payload.vectors where vector.type.baseType == .tx {
            guard pending[vector.hash] != nil else { continue }
            var relay = pending[vector.hash]?.peers[key] ?? PeerRelay(state: .announced,
                                                                      announcements: 0,
                                                                      lastAnnouncedAt: now())
            relay.state = .requested
            pending[vector.hash]?.peers[key] = relay
            emit(.requested(txid: vector.hash, peer: peer.endpoint))
            guard let transaction = pending[vector.hash]?.transaction else { continue }
            do {
                try await peer.send(.tx(transaction))
                relay.state = .served
                pending[vector.hash]?.peers[key] = relay
                emit(.served(txid: vector.hash, peer: peer.endpoint))
            } catch {
                relay.state = .failed
                pending[vector.hash]?.peers[key] = relay
                emit(.failed(txid: vector.hash, peer: peer.endpoint, reason: "serve failed"))
            }
        }
    }

    private func persist() throws {
        guard let storageURL else { return }
        let stored = StoredPending(transactions: Dictionary(uniqueKeysWithValues:
            pending.map { txid, entry in
                (txid.hex, StoredPending.StoredTx(rawTx: entry.rawTx.hex,
                                                  feeRateSatPerVByte: entry.feeRateSatPerVByte,
                                                  attempt: entry.attempt,
                                                  nextAttemptAt: entry.nextAttemptAt.timeIntervalSince1970))
            }))
        let data = try JSONEncoder().encode(stored)
        try data.write(to: storageURL, options: .atomic)
    }
}
