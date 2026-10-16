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
        /// The relay-only session this broadcaster opened has ended: it is no
        /// longer relaying while the app is idle. The pool it narrowed has
        /// been stopped, unless the caller had already resumed full service on
        /// it. Anything still pending stays saved and goes out on the next
        /// start.
        case relaySessionEnded(reason: RelaySessionEnd)
    }

    /// Why a relay-only session ended — which is why the wallet stopped
    /// relaying a payment with nothing else running.
    public enum RelaySessionEnd: String, Equatable, Sendable {
        /// There is nothing left to relay: the payment confirmed, was
        /// cancelled, or was replaced. The session did what it was for.
        case drained
        /// The seats it was holding are gone or can no longer hear about
        /// anything pending: a remote went away, a data fault unseated the
        /// last one, every kept seat was deprioritized for every pending
        /// payment, or the caller resumed full service and an attempt found
        /// the pool empty. A relay-only pool dials no replacement by design,
        /// so nothing could be announced again, and no confirmation can
        /// arrive over a pool that refuses filter sync — the session would
        /// have been peers held open for nothing.
        case seatsGone
        /// A retry could not be saved, so the backoff loop halted. Nothing
        /// will be announced again, and with no announcement and no
        /// confirmation the session had no way left to end.
        case persistenceBlocked
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
        /// Some peer was handed the bytes at least once. Sticky for the
        /// entry's life and persisted across relaunch. A later disconnect
        /// cannot undo that handoff. It does not prove the peer accepted,
        /// retained, or relayed the transaction.
        var served = false
        /// Confirmation tombstone (#157), mirroring `WalletUTXO.SpentMarker`:
        /// a confirmed entry is kept, silent, rather than deleted. Deleting it
        /// destroyed the raw transaction — the only thing that makes
        /// re-announcement possible when a reorg disconnects the confirming
        /// block and the transaction is suddenly in flight again.
        var confirmedAtHeight: UInt32?
    }

    /// JSON persistence shape: txid hex → relay record.
    private struct StoredPending: Codable {
        var version: Int
        struct StoredTx: Codable {
            var rawTx: String
            var feeRateSatPerVByte: Double?
            var attempt: Int
            /// Next backoff attempt, seconds since 1970. Confirmed-held
            /// entries store 0 — their in-memory schedule is `.distantFuture`,
            /// which the future-schedule bound below would rightly refuse.
            var nextAttemptAt: TimeInterval
            /// The confirmation tombstone; absent in stores written before
            /// #157, which load with every entry unconfirmed as they were.
            var confirmedAtHeight: UInt32?
            /// Whether some peer was ever served the bytes; absent in stores
            /// written before it, which load as not.
            var served: Bool?
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
    /// Whether this broadcaster narrowed the pool to a relay-only session and
    /// therefore owns stopping it when nothing is left to relay.
    private var relayOnlySession = false
    /// The drain's stop on its way to the pool, so a session re-entered
    /// behind it waits for it instead of being torn down by it.
    private var closingTask: Task<Void, Never>?

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
    /// Transactions still being relayed. Confirmed-held entries (#157) are
    /// excluded: they are retained only so a reorg can resurrect them, and
    /// every caller of this — the relay UI, the confirmation sweep — means
    /// "still in flight".
    public var pendingTxids: [Data] { pending.filter { $0.value.confirmedAtHeight == nil }.map(\.key) }

    /// The signed bytes of a transaction still awaiting confirmation.
    ///
    /// Winnow relays over its own peer connections and has no fallback
    /// submission path, so when relay is not working the only way out of the
    /// device is the transaction itself. Handing the user the raw bytes lets
    /// them paste it into any node or explorer that accepts one, which is a
    /// real escape hatch rather than a debugging convenience.
    ///
    /// nil once the transaction confirms and leaves the pending set.
    public func rawTransaction(_ txid: Data) -> Data? {
        // The #155 decision survives the #157 tombstone: once confirmed the
        // tx is public and offering its bytes only invites rebroadcasting
        // something already mined, so a held entry hands out nothing.
        guard let entry = pending[txid], entry.confirmedAtHeight == nil else { return nil }
        return entry.rawTx
    }

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
    ///
    /// A relay-only session ends here too, and this call leaves the pool
    /// alone: a caller shutting the broadcaster down is rebuilding the stack
    /// around it and owns what happens to the peers next. Stopping the pool
    /// from here would race a caller that shuts this broadcaster down and
    /// immediately starts the pool for its replacement. The one thing that
    /// still touches the pool afterwards is a narrowing already in flight:
    /// `enterRelayOnly(seats:)` finds this broadcaster stopped when it
    /// resumes and ends with `stopIfRelayOnly`, so a pool narrowed for a
    /// broadcaster that is gone goes quiet rather than being held open, and
    /// a caller that restarted the pool in the meantime keeps it, because
    /// that re-read sees full service and does nothing.
    public func shutdown() {
        guard !stopped else { return }
        stopped = true
        relayOnlySession = false
        rebroadcastTask?.cancel()
        rebroadcastTask = nil
        pending.removeAll()
        for subscriber in subscribers.values { subscriber.finish() }
        subscribers.removeAll()
    }

    /// Whether a relay-only session opened by this broadcaster is still open.
    /// It closes when the pending set drains — or quietly, without stopping
    /// anything, if the caller resumed full service on the pool first.
    ///
    /// This is "this broadcaster still owns a stop", not "the pool is
    /// narrowed", and the two part company the moment a caller calls
    /// `PeerPool.start()`: nothing tells the broadcaster, so this stays true
    /// over a pool back in full service until the payment drains or a backoff
    /// attempt finds no seat it can announce to. `pool.mode` is the truth
    /// about the pool. A UI or lifecycle branch that wants to say "paused"
    /// should read that, not this; this is a test seam.
    var isRelayOnly: Bool { relayOnlySession }

    /// Goes on relaying with the peer pool narrowed to a relay-only session,
    /// and stops that pool once nothing is left to relay.
    ///
    /// This is what a wallet needs when it goes idle with a payment in flight.
    /// `PeerPool.stop()` disconnects every peer, and announcements go over
    /// exactly those connections, so stopping a pool with a pending
    /// transaction leaves it unrelayed until the app is opened again. Holding
    /// the full pool instead pays for a sync pool nobody is reading. In
    /// between is this: `seats` connections, announcements and rebroadcasts
    /// unchanged, no filter sync, nothing dialled.
    ///
    /// Watching for the drain is not the caller's job. Every path that empties
    /// the pending set — a confirmation, a cancellation, a replacement —
    /// already reschedules the backoff loop, and the session ends there: the
    /// pool stops itself and persists its good-peers list.
    ///
    /// Which of those paths can actually happen is worth saying plainly. A
    /// confirmation is not one of them while the session runs: it is observed
    /// through the filter sync a narrowed pool refuses, so it arrives only
    /// once somebody resumes full service. What ends a session in practice is
    /// the payment being cancelled or replaced, its seats going (the pool
    /// prunes a seat whose connection closed, and the next backoff attempt
    /// finds none left), or the caller resuming full service and the sync
    /// that follows confirming the payment. Every one of them emits
    /// `.relaySessionEnded(reason:)`, and anything still pending stays saved
    /// for the caller's next `PeerPool.start()`. After the session ends the
    /// pool is stopped, so a caller that wants to relay again starts it first.
    ///
    /// - Parameter seats: peers to keep, defaulting to `PeerPool.defaultRelaySeats`.
    /// - Returns: whether a session was opened, which is whether anything is
    ///   actually being relayed. False means the pool was stopped instead,
    ///   for one of these reasons: nothing was pending; a retry could not be
    ///   saved, so the backoff loop is already halted; the pool kept no
    ///   seat, because it was already stopped, or its peers had all gone, or
    ///   the seat it kept was lost while it tore down the rest; or the
    ///   pending set drained, or the broadcaster was shut down, while the
    ///   pool was being narrowed. A zero-seat session announces to nobody
    ///   and can never drain itself, because a confirmation needs the filter
    ///   sync the mode refuses. It would be a pool held open forever with
    ///   the caller told "relaying in the background", so it is reported as
    ///   what it is and the pool goes quiet, which is what the caller asked
    ///   for. The last reason is the same pool held open for the same
    ///   nothing, reached the other way round: the narrowing is a
    ///   suspension, and the last pending payment can confirm inside it, or
    ///   `shutdown()` can run. Every reason found on the far side of that
    ///   suspension, the lost seat included, stops the pool only if it is
    ///   still the relay-only session this call narrowed it to; a caller
    ///   that resumed full service in the same gap has taken it back, and it
    ///   is left as they put it.
    @discardableResult
    public func enterRelayOnly(seats: Int = PeerPool.defaultRelaySeats) async throws -> Bool {
        // A drain's stop may still be on its way to the pool. A session
        // re-entered ahead of it would be torn down by that stale stop, so it
        // is waited for first; what it leaves is a stopped pool, and the
        // narrowing below then reports zero seats, as it should.
        await closingTask?.value
        closingTask = nil
        guard !stopped else { throw TxBroadcasterError.stopped }
        guard hasPendingRelay else {
            relayOnlySession = false
            await pool.stop()
            return false
        }
        // A halted backoff loop is a session that cannot announce and cannot
        // end: `fireDueAttempts` stopped after a failed write, so nothing is
        // re-announced, and a confirmation cannot arrive over a pool that
        // refuses filter sync. That is the zero-seat state reached before the
        // pool is even narrowed, and it is refused for the same reason. Still
        // before the first await, so the plain `stop()` the nothing-pending
        // branch uses is the right one here too.
        guard !persistenceBlocked else {
            relayOnlySession = false
            await pool.stop()
            return false
        }
        guard await pool.enterRelayOnly(seats: seats) > 0 else {
            relayOnlySession = false
            // Not a plain `stop()`. This branch is on the far side of the
            // narrowing, the same suspension the re-check below guards, and a
            // count of zero is what a `start()` landing inside it can leave
            // behind: the kept seat fails while the pool is tearing down the
            // rest, the app foregrounds and takes the pool back, and its
            // dialling has not seated anyone yet when the count is read. A
            // `stop()` here tore down the pool the caller had just resumed,
            // and left them at zero peers with `retry()` refusing until the
            // next full stop/start cycle. Re-reading the mode as one job on
            // the pool is what `closeRelayOnlySession` does for the same
            // race, and it is what is done here: a pool still narrowed for
            // nothing goes quiet, and a pool back in full service is left as
            // its caller put it.
            await pool.stopIfRelayOnly()
            return false
        }
        // All three checks again, because the narrowing above is a suspension
        // and this actor ran other work inside it. A confirmation landing
        // there is the drain: it empties the pending set and calls the close,
        // which has no session to close yet and does nothing. A session
        // recorded now would be one over nothing, with no drain left to end
        // it, so the pool is held open for a payment that already confirmed.
        // A `shutdown()` landing there has ended every session, and a session
        // recorded now would have a finished broadcaster claiming to relay. A
        // failed write landing there has halted the backoff loop, and the end
        // it called found no session yet, so a session recorded now would be
        // the one over a dead loop that the check before the narrowing refuses.
        //
        // The stop is the drain's stop arriving late, so it re-reads the mode
        // for the drain's reason: a caller that resumed full service in the
        // gap has taken the pool back, and this must not take it away. Awaited
        // rather than detached, as `closeRelayOnlySession` has to, because
        // this is already async and the caller is told false only once the
        // pool has actually gone quiet.
        guard !stopped, !persistenceBlocked, hasPendingRelay else {
            relayOnlySession = false
            await pool.stopIfRelayOnly()
            return false
        }
        relayOnlySession = true
        return true
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
    public func markConfirmed(_ txid: Data, atHeight height: UInt32) throws {
        guard !stopped else { throw TxBroadcasterError.stopped }
        guard let entry = pending[txid], entry.confirmedAtHeight == nil else { return }
        var candidate = pending
        candidate[txid]?.confirmedAtHeight = height
        // Held entries never come due; `.distantFuture` keeps them out of the
        // backoff loop without a second code path deciding what "due" means.
        candidate[txid]?.nextAttemptAt = .distantFuture
        try persist(candidate)
        pending = candidate
        persistenceBlocked = false
        emit(.confirmed(txid: txid))
        scheduleRebroadcast()
    }

    /// Reactivates entries whose confirming block was disconnected (#157).
    /// The transaction is back in mempools whether or not we speak, so the
    /// wallet re-reserves its inputs and this re-announces — the two halves of
    /// not building a conflicting send.
    public func rollBack(to forkHeight: UInt32) throws {
        guard !stopped else { throw TxBroadcasterError.stopped }
        var candidate = pending
        var reactivated = false
        for (txid, entry) in candidate {
            guard let height = entry.confirmedAtHeight, height > forkHeight else { continue }
            candidate[txid]?.confirmedAtHeight = nil
            candidate[txid]?.nextAttemptAt = now()
            // Every peer gets the inv again: relay state from before the
            // confirmation describes a conversation about a different chain.
            candidate[txid]?.peers = [:]
            reactivated = true
        }
        guard reactivated else { return }
        try persist(candidate)
        pending = candidate
        persistenceBlocked = false
        scheduleRebroadcast()
    }

    /// Drops held entries once their confirmation is deeper than any reorg
    /// this wallet reorganises over — the same 100-block horizon
    /// `Wallet.spentCoinHorizon` uses for spent-coin tombstones, for the same
    /// reason.
    public func pruneConfirmed(scannedTo tip: UInt32) throws {
        guard !stopped else { return }
        var candidate = pending
        candidate = candidate.filter { _, entry in
            guard let height = entry.confirmedAtHeight else { return true }
            return height + 100 > tip
        }
        guard candidate.count != pending.count else { return }
        try persist(candidate)
        pending = candidate
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

    /// Whether some peer was ever handed this transaction's bytes, across
    /// disconnections and relaunches. A transport handoff alone does not
    /// establish acceptance, propagation, or confirmation.
    public func wasServed(_ txid: Data) -> Bool {
        pending[txid]?.served ?? false
    }

    /// Per-peer relay state for a pending tx, keyed by endpoint description.
    public func relayStatus(_ txid: Data) -> [String: PeerAnnouncementState] {
        pending[txid]?.peers.mapValues(\.state) ?? [:]
    }

    // MARK: - Internals

    /// Test-visible backoff accessors (@testable).
    func attemptCount(_ txid: Data) -> Int? { pending[txid]?.attempt }
    func nextAttemptDate(_ txid: Data) -> Date? { pending[txid]?.nextAttemptAt }

    /// Whether anything is still being relayed. Confirmed-held entries (#157)
    /// are retained for a reorg, not announced, so they are not relay work —
    /// the same reading of "pending" `pendingTxids` publishes.
    private var hasPendingRelay: Bool {
        pending.contains { $0.value.confirmedAtHeight == nil }
    }

    /// Ends a relay-only session and stops the pool it narrowed.
    ///
    /// A detached stop rather than an awaited one because every caller is a
    /// synchronous state transition that must not suspend part-way through
    /// its own bookkeeping. `PeerPool.stop()` is idempotent, so a caller that
    /// stops the pool itself as well loses nothing.
    ///
    /// The mode is re-read there rather than assumed. A caller that resumed
    /// full service — the app coming back to the foreground — has taken the
    /// pool back, and a payment confirming a moment later must not tear down
    /// the peers it is now syncing over. The session simply expires.
    ///
    /// That re-read is `stopIfRelayOnly`, one job on the pool, and it has to
    /// be: reading `mode` and then calling `stop()` are two jobs with an
    /// arbitrary gap between them, and a `start()` landing in the gap runs
    /// first and is then silently undone by the queued stop. On iOS that gap
    /// is the unfreeze boundary — the suspended drain and the app's foreground
    /// `start()` become runnable in the same instant.
    private func closeRelayOnlySession() {
        guard relayOnlySession else { return }
        relayOnlySession = false
        closingTask = Task { [pool] in await pool.stopIfRelayOnly() }
        emit(.relaySessionEnded(reason: .drained))
    }

    /// Ends the session, stops the pool it narrowed, and says why.
    ///
    /// The awaited twin of `closeRelayOnlySession`, for the reasons a session
    /// ends that are not the drain. Every caller of this one is already
    /// suspended, so the stop is awaited and the event follows it: a
    /// subscriber that sees `.relaySessionEnded` here is looking at a pool
    /// that has already gone quiet. The re-read is the same re-read for the
    /// same reason — a caller that resumed full service has taken the pool
    /// back, and the session expires over it rather than taking its peers.
    private func endRelayOnlySession(reason: RelaySessionEnd) async {
        guard relayOnlySession else { return }
        relayOnlySession = false
        await pool.stopIfRelayOnly()
        emit(.relaySessionEnded(reason: reason))
    }

    /// Ends a session with no seat left to announce over.
    ///
    /// The mode is still not self-healing: a lost seat is not replaced, here
    /// or anywhere, because replacing it means dialling. What must not happen
    /// is the session outliving its seats. The remote goes away and the
    /// pool's relay-only prune drops the seat, or a data fault unseats the
    /// last one through `misbehaving`, and the pool is then empty in a mode
    /// that dials nothing: `announce` reaches nobody, no confirmation can
    /// arrive over a pool that refuses filter sync, and the session had
    /// nothing left that could end it — peers held open, and the caller told
    /// the payment is relaying in the background. It ends here instead, the
    /// caller is told which way it went, and everything still pending stays
    /// saved for the next `PeerPool.start()`.
    private func endRelayOnlySessionIfSeatsGone() async {
        guard relayOnlySession else { return }
        let peers = await pool.connectedPeers()
        guard peers.isEmpty || !canAnnounce(toAnyOf: peers) else { return }
        await endRelayOnlySession(reason: .seatsGone)
    }

    /// Whether any seat can still hear about any pending payment. A seat
    /// deprioritized for every payment still pending is held for nothing —
    /// the state the session must not sit in — so it counts as gone. A
    /// fee-filter refusal is transient and does not count; a seat with no
    /// record for a payment has yet to be asked, and does.
    private func canAnnounce(toAnyOf peers: [PeerConnection]) -> Bool {
        let unconfirmed = pending.values.filter { $0.confirmedAtHeight == nil }
        return peers.contains { peer in
            let key = peer.endpoint.description
            return unconfirmed.contains { entry in
                guard let relay = entry.peers[key] else { return true }
                if relay.state == .requested || relay.state == .served { return true }
                return relay.state != .deprioritized && relay.announcements < maxAnnouncementsPerPeer
            }
        }
    }

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
        let data = try readBoundedFile(at: storageURL)

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
            let result = try loadVersioned(rawVersion, data: data, decoder: decoder, now: now)
            return (.loaded(transactionCount: result.count), result)
        }
        let result = try loadUnversioned(data, decoder: decoder, now: now)
        return (.loaded(transactionCount: result.count), result)
    }

    /// The file, read under the storage byte cap — checked against the
    /// reported size before reading and against the bytes after, so a file
    /// that grows between the two is still refused.
    private static func readBoundedFile(at storageURL: URL) throws -> Data {
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
        return data
    }

    /// A record that declares its version must declare ours, exactly and as
    /// an integer — a float or unknown version is damage, not tolerance.
    private static func loadVersioned(_ rawVersion: Any, data: Data, decoder: JSONDecoder,
                                      now: Date) throws -> [Data: Pending] {
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
        return try validatedRecords(stored.transactions, now: now)
    }

    /// The two pre-version formats, tried in order; anything else is not a
    /// relay record.
    private static func loadUnversioned(_ data: Data, decoder: JSONDecoder,
                                        now: Date) throws -> [Data: Pending] {
        if let unversioned = try? decoder.decode(UnversionedStoredPending.self, from: data) {
            return try validatedRecords(unversioned.transactions, now: now)
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
            return result
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
                                   // A held entry's stored schedule is a
                                   // placeholder 0; in memory it must never
                                   // come due, so the sentinel is restored
                                   // rather than trusted from disk.
                                   nextAttemptAt: record.confirmedAtHeight == nil
                                       ? Date(timeIntervalSince1970: record.nextAttemptAt)
                                       : .distantFuture,
                                   served: record.served ?? false,
                                   confirmedAtHeight: record.confirmedAtHeight)
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
            // BIP133: a peer whose fee filter is above this transaction's
            // rate has said it will drop the bytes unread. Announcing anyway
            // spends an attempt on a peer that cannot help, and the
            // deprioritization it earns hides the real reason. Skipped, not
            // marked, so a filter that later drops lets it back in.
            if await feeFilterRefuses(txid: txid, at: peer) { continue }
            guard admitsAnnouncement(txid: txid, to: peer) else { continue }
            guard (try? await peer.send(announcement)) != nil else { continue }
            announced += 1
            recordAnnouncement(txid: txid, key: peer.endpoint.description)
        }
        emit(.announced(txid: txid, peerCount: announced))
    }

    /// BIP133: whether the peer's announced fee filter sits above this
    /// transaction's rate. No filter, or no rate on record, refuses nothing.
    private func feeFilterRefuses(txid: Data, at peer: PeerConnection) async -> Bool {
        guard let rate = pending[txid]?.feeRateSatPerVByte,
              let floor = await peer.feeFilter else { return false }
        return Double(floor) > rate * 1_000
    }

    /// Whether this peer should hear about the tx again — and the
    /// deprioritization write when the answer is "never again": a peer that
    /// was announced to `maxAnnouncementsPerPeer` times without ever
    /// requesting or serving it stops costing bandwidth.
    private func admitsAnnouncement(txid: Data, to peer: PeerConnection) -> Bool {
        let key = peer.endpoint.description
        guard let relay = pending[txid]?.peers[key] else { return true }
        if relay.state == .deprioritized { return false }
        if relay.state != .requested, relay.state != .served,
           relay.announcements >= maxAnnouncementsPerPeer {
            pending[txid]?.peers[key]?.state = .deprioritized
            emit(.deprioritized(txid: txid, peer: peer.endpoint))
            return false
        }
        return true
    }

    /// One successful announcement's bookkeeping; a failed relay returns to
    /// announced so a timeout or disconnect gets retried.
    private func recordAnnouncement(txid: Data, key: String) {
        if var relay = pending[txid]?.peers[key] {
            relay.announcements += 1
            relay.lastAnnouncedAt = now()
            if relay.state == .failed { relay.state = .announced }
            pending[txid]?.peers[key] = relay
        } else {
            pending[txid]?.peers[key] = PeerRelay(state: .announced, announcements: 1,
                                                  lastAnnouncedAt: now())
        }
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

    /// Marks unfinished handoffs to this peer failed. Completed handoffs
    /// and deprioritized entries stay untouched.
    private func markPeerFailed(_ peer: PeerConnection, reason: String) {
        let key = peer.endpoint.description
        for (txid, entry) in pending {
            // A disconnect cannot undo the recorded transport handoff.
            guard entry.confirmedAtHeight == nil, let relay = entry.peers[key],
                  relay.state != .failed, relay.state != .deprioritized,
                  relay.state != .served else { continue }
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
            guard entry.confirmedAtHeight == nil, let rate = entry.feeRateSatPerVByte else { continue }
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
        guard !stopped, !persistenceBlocked, hasPendingRelay else {
            rebroadcastTask = nil
            // The drain, wherever it came from: a confirmation, a
            // cancellation, a replacement. A relay-only session is peers held
            // open for work in flight, so with no work left it ends here and
            // the pool stops itself.
            if !hasPendingRelay { closeRelayOnlySession() }
            return
        }
        // `weak` on purpose, and re-bound every iteration: a broadcaster that
        // was dropped without `shutdown()` must let its loop end rather than
        // be kept alive by it.
        rebroadcastTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, await self.rebroadcastStep() else { return }
            }
        }
    }

    /// One turn of the backoff loop: wait for the earliest due attempt, then
    /// fire whatever is due. False ends the loop, which is nothing left
    /// pending, a cancellation that landed during the wait, or an attempt
    /// that halted the loop itself.
    private func rebroadcastStep() async -> Bool {
        guard let next = pending.values.map(\.nextAttemptAt).min() else { return false }
        let wait = next.timeIntervalSince(now())
        if wait > 0 {
            try? await Task.sleep(for: .seconds(wait))
            guard !Task.isCancelled else { return false }
        }
        return await fireDueAttempts()
    }

    /// Announces every tx whose backoff attempt is due, then advances its
    /// schedule and persists.
    private func fireDueAttempts() async -> Bool {
        // Where a session that has lost its seats is noticed: the pool prunes
        // a seat whose connection closed, and the attempt that follows has
        // nobody to announce to. The attempt itself then runs as it always
        // has over an empty pool — the schedule advances, the announcement
        // reaches nobody — so the payment is still pending, and still saved,
        // when the caller starts the pool again.
        await endRelayOnlySessionIfSeatsGone()
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
            // The loop stops here, and a relay-only session would outlive it:
            // nothing is announced again, and a confirmation cannot arrive
            // over a narrowed pool. Peers held open for relay that has
            // stopped is the one thing the session must not become.
            await endRelayOnlySession(reason: .persistenceBlocked)
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
        // One transaction per request, and one serving per peer: a getdata
        // that names a txid 50,000 times, or asks again for what it already
        // holds, must not multiply the bytes and events it costs us.
        var seen = Set<Data>()
        for vector in payload.vectors where vector.type.baseType == .tx {
            guard pending[vector.hash] != nil, seen.insert(vector.hash).inserted else { continue }
            var relay = pending[vector.hash]?.peers[key] ?? PeerRelay(state: .announced,
                                                                      announcements: 0,
                                                                      lastAnnouncedAt: now())
            guard relay.state != .served else { continue }
            relay.state = .requested
            pending[vector.hash]?.peers[key] = relay
            emit(.requested(txid: vector.hash, peer: peer.endpoint))
            guard let transaction = pending[vector.hash]?.transaction else { continue }
            do {
                try await peer.send(.tx(transaction))
                relay.state = .served
                if pending[vector.hash]?.served != true {
                    pending[vector.hash]?.served = true
                    // Best effort for this historical hint. If saving fails,
                    // a later successful handoff can record it again.
                    try? persist(pending)
                }
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
                                                  nextAttemptAt: entry.confirmedAtHeight == nil
                                                      ? entry.nextAttemptAt.timeIntervalSince1970
                                                      : 0,
                                                  confirmedAtHeight: entry.confirmedAtHeight,
                                                  served: entry.served))
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
