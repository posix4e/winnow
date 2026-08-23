import Foundation

public enum TxBroadcasterError: LocalizedError, Equatable, Sendable {
    case invalidFeeRate
    case stopped

    public var errorDescription: String? {
        switch self {
        case .invalidFeeRate:
            "The transaction fee rate must be a positive, finite number within Bitcoin's monetary range."
        case .stopped:
            "This transaction relay session has stopped. Reconnect before changing relay state."
        }
    }
}

public enum TxBroadcasterStorageError: LocalizedError, Equatable, Sendable {
    case unreadable
    case tooLarge(maxBytes: Int)
    case damaged(String)
    case unsupportedVersion(Int)
    case writeFailed

    public var errorDescription: String? {
        switch self {
        case .unreadable:
            "Winnow could not read its pending-transaction file. Relay is stopped until local storage is available."
        case let .tooLarge(maxBytes):
            "The pending-transaction file is unexpectedly large (limit: \(maxBytes) bytes). Relay is stopped to protect the wallet."
        case let .damaged(reason):
            "The pending-transaction file is damaged (\(reason)). Relay is stopped; Winnow will not discard or replay its entries."
        case let .unsupportedVersion(version):
            "The pending-transaction file uses unsupported version \(version). Update Winnow before relaying transactions."
        case .writeFailed:
            "Winnow could not safely save pending transaction state. The relay change was not accepted."
        }
    }
}

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
    public enum PersistenceState: Equatable, Sendable {
        case disabled
        case missing
        case loaded(transactionCount: Int)
    }

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
        /// A scheduled retry could not be durably recorded, so automatic
        /// relay stopped instead of looping with an in-memory-only state.
        case persistenceFailed(reason: String)
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
        var version: Int
        struct StoredTx: Codable {
            var rawTx: String
            var feeRateSatPerVByte: Double?
            var attempt: Int
            /// Next backoff attempt, seconds since 1970.
            var nextAttemptAt: TimeInterval
        }
        var transactions: [String: StoredTx]
    }

    /// Store shape written before the explicit format version was added.
    private struct UnversionedStoredPending: Codable {
        var transactions: [String: StoredPending.StoredTx]
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
    public nonisolated let persistenceState: PersistenceState
    private var pending: [Data: Pending] = [:]
    private var rebroadcastTask: Task<Void, Never>?
    private var persistenceBlocked = false
    private var listenedPeers: Set<String> = []
    private var subscribers: [UUID: AsyncStream<Event>.Continuation] = [:]
    private var stopped = false

    private static let storageVersion = 1
    private static let maximumStoredTransactions = 4_096
    private static let maximumStorageBytes = 64 * 1_024 * 1_024
    private static let maximumRawTransactionBytes = 4_000_000
    private static let maximumAttempt = 63
    private static let maximumFeeRate = 2_100_000_000_000_000.0
    private static let maximumFutureSchedule: TimeInterval = 366 * 24 * 60 * 60

    public init(pool: PeerPool, storageURL: URL? = nil,
                rebroadcastBaseInterval: Duration = .seconds(60),
                maxRebroadcastInterval: Duration = .seconds(3_600),
                maxAnnouncementsPerPeer: Int = 3,
                announcementTimeout: Duration = .seconds(120),
                now: @Sendable @escaping () -> Date = { Date() }) throws {
        self.pool = pool
        self.storageURL = storageURL
        self.rebroadcastBaseInterval = rebroadcastBaseInterval
        self.maxRebroadcastInterval = maxRebroadcastInterval
        self.maxAnnouncementsPerPeer = maxAnnouncementsPerPeer
        self.announcementTimeout = announcementTimeout
        self.now = now
        if let storageURL {
            let result = try Self.load(storageURL: storageURL, now: now())
            persistenceState = result.state
            pending = result.pending
        } else {
            persistenceState = .disabled
        }
        // Restored transactions resume their backoff schedule; an overdue
        // attempt fires as soon as the loop runs.
        if !pending.isEmpty {
            Task { await self.scheduleRebroadcast() }
        }
    }

    /// txids (internal byte order) awaiting confirmation.
    public var pendingTxids: [Data] { Array(pending.keys) }

    /// The signed bytes of a transaction still awaiting confirmation.
    ///
    /// Winnow relays over its own peer connections and has no fallback
    /// submission path, so when relay is not working the only way out of the
    /// device is the transaction itself. Handing the user the raw bytes lets
    /// them paste it into any node or explorer that accepts one, which is a
    /// real escape hatch rather than a debugging convenience.
    ///
    /// nil once the transaction confirms and leaves the pending set.
    public func rawTransaction(_ txid: Data) -> Data? { pending[txid]?.rawTx }

    public func events() -> AsyncStream<Event> {
        let id = UUID()
        return AsyncStream { continuation in
            subscribers[id] = continuation
            continuation.onTermination = { _ in
                Task { await self.removeSubscriber(id) }
            }
        }
    }

    /// Ends this relay session without changing its durable pending set. A
    /// replacement broadcaster may reload the same store (reconnect), or the
    /// caller may deliberately remove the store while changing wallets.
    public func shutdown() {
        guard !stopped else { return }
        stopped = true
        rebroadcastTask?.cancel()
        rebroadcastTask = nil
        pending.removeAll()
        for subscriber in subscribers.values { subscriber.finish() }
        subscribers.removeAll()
    }

    /// Validates, stores and announces a raw signed transaction.
    /// `feeRateSatPerVByte` enables the BIP133 fee-floor events.
    /// Returns its txid (internal byte order).
    @discardableResult
    public func broadcast(_ rawTx: Data, feeRateSatPerVByte: Double? = nil) async throws -> Data {
        guard !stopped else { throw TxBroadcasterError.stopped }
        let transaction = try Self.validatedTransaction(rawTx)
        try Self.validateFeeRate(feeRateSatPerVByte)
        let txid = transaction.txid
        var candidate = pending
        candidate[txid] = Pending(rawTx: rawTx, transaction: transaction,
                                  feeRateSatPerVByte: feeRateSatPerVByte,
                                  attempt: 0,
                                  nextAttemptAt: now() + Self.timeInterval(backoffInterval(attempt: 0)))
        try persist(candidate)
        pending = candidate
        persistenceBlocked = false
        await ensurePeerListeners()
        await announce(txid: txid)
        await checkFeeFloors()
        scheduleRebroadcast()
        return txid
    }

    /// Called when the tx is seen in a matched block (or otherwise confirmed).
    public func markConfirmed(_ txid: Data) throws {
        guard !stopped else { throw TxBroadcasterError.stopped }
        guard pending[txid] != nil else { return }
        var candidate = pending
        candidate.removeValue(forKey: txid)
        try persist(candidate)
        pending = candidate
        persistenceBlocked = false
        emit(.confirmed(txid: txid))
        scheduleRebroadcast()
    }

    /// Stops relaying a pending tx without a confirmation (e.g. the user
    /// replaced it with a fee-bumped transaction).
    public func cancel(_ txid: Data) throws {
        guard !stopped else { throw TxBroadcasterError.stopped }
        guard pending[txid] != nil else { return }
        var candidate = pending
        candidate.removeValue(forKey: txid)
        try persist(candidate)
        pending = candidate
        persistenceBlocked = false
        emit(.cancelled(txid: txid))
        scheduleRebroadcast()
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

    private static func load(storageURL: URL, now: Date) throws
        -> (state: PersistenceState, pending: [Data: Pending])
    {
        guard FileManager.default.fileExists(atPath: storageURL.path) else {
            return (.missing, [:])
        }
        let attributes: [FileAttributeKey: Any]
        do {
            attributes = try FileManager.default.attributesOfItem(atPath: storageURL.path)
        } catch {
            throw TxBroadcasterStorageError.unreadable
        }
        if let size = attributes[.size] as? NSNumber,
           size.int64Value > Int64(maximumStorageBytes) {
            throw TxBroadcasterStorageError.tooLarge(maxBytes: maximumStorageBytes)
        }
        let data: Data
        do {
            data = try Data(contentsOf: storageURL, options: .mappedIfSafe)
        } catch {
            throw TxBroadcasterStorageError.unreadable
        }
        guard data.count <= maximumStorageBytes else {
            throw TxBroadcasterStorageError.tooLarge(maxBytes: maximumStorageBytes)
        }
        guard !data.isEmpty else {
            throw TxBroadcasterStorageError.damaged("the file is empty")
        }

        let topLevel: [String: Any]
        do {
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw TxBroadcasterStorageError.damaged("the top level is not an object")
            }
            topLevel = object
        } catch let error as TxBroadcasterStorageError {
            throw error
        } catch {
            throw TxBroadcasterStorageError.damaged("the JSON is invalid")
        }

        let decoder = JSONDecoder()
        if let rawVersion = topLevel["version"] {
            guard let number = rawVersion as? NSNumber,
                  number.doubleValue.isFinite,
                  number.doubleValue.rounded(.towardZero) == number.doubleValue else {
                throw TxBroadcasterStorageError.damaged("the format version is invalid")
            }
            let version = number.intValue
            guard version == storageVersion else {
                throw TxBroadcasterStorageError.unsupportedVersion(version)
            }
            let stored: StoredPending
            do {
                stored = try decoder.decode(StoredPending.self, from: data)
            } catch {
                throw TxBroadcasterStorageError.damaged("a versioned relay record is invalid")
            }
            let result = try validatedRecords(stored.transactions, now: now)
            return (.loaded(transactionCount: result.count), result)
        }

        if let unversioned = try? decoder.decode(UnversionedStoredPending.self, from: data) {
            let result = try validatedRecords(unversioned.transactions, now: now)
            return (.loaded(transactionCount: result.count), result)
        }
        if let legacy = try? decoder.decode(LegacyStoredPending.self, from: data) {
            guard legacy.transactions.count <= maximumStoredTransactions else {
                throw TxBroadcasterStorageError.damaged("there are too many pending transactions")
            }
            var result: [Data: Pending] = [:]
            result.reserveCapacity(legacy.transactions.count)
            for (txidHex, rawHex) in legacy.transactions {
                let (txid, rawTx, transaction) = try validatedRecordIdentity(
                    txidHex: txidHex, rawHex: rawHex)
                result[txid] = Pending(rawTx: rawTx, transaction: transaction,
                                       feeRateSatPerVByte: nil, attempt: 0,
                                       nextAttemptAt: now)
            }
            return (.loaded(transactionCount: result.count), result)
        }
        throw TxBroadcasterStorageError.damaged("the relay record format is not recognized")
    }

    private static func validatedRecords(_ records: [String: StoredPending.StoredTx], now: Date) throws
        -> [Data: Pending]
    {
        guard records.count <= maximumStoredTransactions else {
            throw TxBroadcasterStorageError.damaged("there are too many pending transactions")
        }
        var result: [Data: Pending] = [:]
        result.reserveCapacity(records.count)
        for (txidHex, record) in records {
            let (txid, rawTx, transaction) = try validatedRecordIdentity(
                txidHex: txidHex, rawHex: record.rawTx)
            do {
                try validateFeeRate(record.feeRateSatPerVByte)
            } catch {
                throw TxBroadcasterStorageError.damaged("transaction \(txid.displayHex) has an invalid fee rate")
            }
            guard (0 ... maximumAttempt).contains(record.attempt) else {
                throw TxBroadcasterStorageError.damaged("transaction \(txid.displayHex) has an invalid retry count")
            }
            guard record.nextAttemptAt.isFinite,
                  record.nextAttemptAt >= 0,
                  record.nextAttemptAt <= now.timeIntervalSince1970 + maximumFutureSchedule else {
                throw TxBroadcasterStorageError.damaged("transaction \(txid.displayHex) has an invalid retry time")
            }
            result[txid] = Pending(rawTx: rawTx, transaction: transaction,
                                   feeRateSatPerVByte: record.feeRateSatPerVByte,
                                   attempt: record.attempt,
                                   nextAttemptAt: Date(timeIntervalSince1970: record.nextAttemptAt))
        }
        return result
    }

    private static func validatedRecordIdentity(txidHex: String, rawHex: String) throws
        -> (Data, Data, Transaction)
    {
        guard txidHex.utf8.count == 64, let txid = Data(hex: txidHex), txid.count == 32 else {
            throw TxBroadcasterStorageError.damaged("a transaction ID is invalid")
        }
        guard rawHex.utf8.count <= maximumRawTransactionBytes * 2,
              let rawTx = Data(hex: rawHex) else {
            throw TxBroadcasterStorageError.damaged("transaction \(txid.displayHex) has invalid raw bytes")
        }
        let transaction: Transaction
        do {
            transaction = try validatedTransaction(rawTx)
        } catch {
            throw TxBroadcasterStorageError.damaged("transaction \(txid.displayHex) cannot be decoded")
        }
        guard transaction.txid == txid else {
            throw TxBroadcasterStorageError.damaged("a transaction ID does not match its raw bytes")
        }
        return (txid, rawTx, transaction)
    }

    private static func validatedTransaction(_ rawTx: Data) throws -> Transaction {
        guard !rawTx.isEmpty, rawTx.count <= maximumRawTransactionBytes else {
            throw WireError.malformed("raw transaction size \(rawTx.count)")
        }
        let transaction = try Transaction.decode(rawTx)
        guard transaction.serialized(includeWitness: true) == rawTx else {
            throw WireError.malformed("non-canonical transaction encoding")
        }
        return transaction
    }

    private static func validateFeeRate(_ feeRate: Double?) throws {
        guard let feeRate else { return }
        guard feeRate.isFinite, feeRate > 0, feeRate <= maximumFeeRate else {
            throw TxBroadcasterError.invalidFeeRate
        }
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
        guard !stopped, !pending.isEmpty, !persistenceBlocked else {
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
                guard await self.fireDueAttempts() else { return }
            }
        }
    }

    /// Announces every tx whose backoff attempt is due, then advances its
    /// schedule and persists.
    private func fireDueAttempts() async -> Bool {
        await ensurePeerListeners()
        let firedAt = now()
        let dueTxids = pending.keys.sorted(by: { $0.hex < $1.hex }).filter {
            pending[$0]?.nextAttemptAt ?? .distantFuture <= firedAt
        }
        guard !dueTxids.isEmpty else { return true }

        // Advance the retry schedule durably before any network side effect.
        // A failed write leaves both memory and disk untouched, and stops the
        // loop rather than repeatedly announcing from an uncommitted state.
        var candidate = pending
        for txid in dueTxids {
            guard var updated = candidate[txid] else { continue }
            updated.attempt = min(updated.attempt + 1, Self.maximumAttempt)
            updated.nextAttemptAt = firedAt + Self.timeInterval(backoffInterval(attempt: updated.attempt))
            candidate[txid] = updated
        }
        do {
            try persist(candidate)
            pending = candidate
            persistenceBlocked = false
        } catch {
            persistenceBlocked = true
            emit(.persistenceFailed(reason: error.localizedDescription))
            return false
        }

        for txid in dueTxids {
            expireStaleAnnouncements(txid: txid)
            await announce(txid: txid)
        }
        await checkFeeFloors()
        return true
    }

    /// Subscribes to getdata/feefilter traffic on every connected peer
    /// (once per peer).
    private func ensurePeerListeners() async {
        guard !stopped else { return }
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
                guard !stopped else { return }
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

    private func persist(_ state: [Data: Pending]) throws {
        guard let storageURL else { return }
        guard state.count <= Self.maximumStoredTransactions else {
            throw TxBroadcasterStorageError.writeFailed
        }
        let stored = StoredPending(version: Self.storageVersion,
                                   transactions: Dictionary(uniqueKeysWithValues:
            state.map { txid, entry in
                (txid.hex, StoredPending.StoredTx(rawTx: entry.rawTx.hex,
                                                  feeRateSatPerVByte: entry.feeRateSatPerVByte,
                                                  attempt: entry.attempt,
                                                  nextAttemptAt: entry.nextAttemptAt.timeIntervalSince1970))
            }))
        do {
            let data = try JSONEncoder().encode(stored)
            guard data.count <= Self.maximumStorageBytes else {
                throw TxBroadcasterStorageError.writeFailed
            }
            try data.write(to: storageURL,
                           options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        } catch let error as TxBroadcasterStorageError {
            throw error
        } catch {
            throw TxBroadcasterStorageError.writeFailed
        }
    }
}
