import BitcoinP2P
import BlockchainBackend
import Foundation

/// The P2P half of a route, as the coordinator sees it. `TxBroadcaster`
/// conforms; tests substitute a counting fake. The coordinator resolves this
/// per route and receives `nil` for `minerOnly` and `export`, which is what
/// makes "miner-only never touches peers" a property of the wiring rather
/// than of a branch nobody forgot.
public protocol PeerRelay: Sendable {
    func broadcast(_ rawTx: Data, feeRateSatPerVByte: Double?) async throws -> Data
    func cancel(_ txid: Data) async throws
    func events() async -> AsyncStream<TxBroadcaster.Event>
}

extension TxBroadcaster: PeerRelay {}

public enum SubmissionStoreError: LocalizedError, Equatable, Sendable {
    case unreadable
    case tooLarge(maxBytes: Int)
    case damaged(String)
    case unsupportedVersion(Int)
    case writeFailed

    public var errorDescription: String? {
        switch self {
        case .unreadable:
            "Winnow could not read its submission receipts. Submission tracking is stopped until local storage is available."
        case let .tooLarge(maxBytes):
            "The submission receipts file is unexpectedly large (limit: \(maxBytes) bytes). Tracking is stopped to protect the wallet."
        case let .damaged(reason):
            "The submission receipts file is damaged (\(reason)). Tracking is stopped; Winnow will not discard or replay its entries."
        case let .unsupportedVersion(version):
            "The submission receipts file uses unsupported version \(version). Update Winnow before submitting transactions."
        case .writeFailed:
            "Winnow could not safely save submission state. The change was not accepted."
        }
    }
}

/// Owns every submission receipt and executes routes (issue #51).
///
/// Sits between the wallet (which signs and commits) and the two ways bytes
/// leave the phone: `TxBroadcaster` for peers, a `DirectMinerClient` for a
/// miner. Persists receipts as JSON, strict on load and quarantined by the
/// app when damaged, exactly as `broadcast.json` is.
///
/// Three rules the tests pin:
/// - The relay is resolved per route and is `nil` for `minerOnly` and
///   `export`, so those paths cannot announce to a peer.
/// - `state` reaches `confirmed` only through `markConfirmed`, which the
///   app calls from its block-match loop. What a provider reports is kept
///   in `providerStatus` and displayed as the provider's opinion.
/// - No route ever changes without a `RouteApproval` written first.
public actor SubmissionCoordinator {
    public typealias RelayResolver = @Sendable (SubmissionRoute) -> (any PeerRelay)?
    public typealias MinerResolver = @Sendable (MinerProviderID) async throws -> any DirectMinerClient

    public enum PersistenceState: Equatable, Sendable {
        case disabled
        case missing
        case loaded(receiptCount: Int)
    }

    public enum Event: Equatable, Sendable {
        case submitted(txid: Data, provider: MinerProviderID)
        case accepted(txid: Data, provider: MinerProviderID)
        case rejected(txid: Data, reason: String, policy: Bool)
        /// Every submit attempt failed at the transport; the bytes may or
        /// may not have arrived. The receipt is held and can be re-routed.
        case deliveryUnconfirmed(txid: Data)
        case providerStatus(txid: Data, kind: ProviderStatusSnapshot.Kind)
        case relayed(txid: Data)
        case rerouted(txid: Data, to: SubmissionRoute)
        case replaced(txid: Data, by: Data)
        case confirmed(txid: Data)
        case abandoned(txid: Data)
        case persistenceFailed(reason: String)
    }

    private struct StoredReceipts: Codable {
        var version: Int
        var receipts: [SubmissionReceipt]
    }

    private let relay: RelayResolver
    private let miners: MinerResolver
    private let storageURL: URL?
    private let now: @Sendable () -> Date
    private let pollBaseInterval: Duration
    private let maxPollInterval: Duration
    private let submitBaseInterval: Duration
    private let maxSubmitInterval: Duration
    private let maxSubmitAttempts: Int
    public nonisolated let persistenceState: PersistenceState

    private var receiptsByTxid: [Data: SubmissionReceipt] = [:]
    private var subscribers: [UUID: AsyncStream<Event>.Continuation] = [:]
    private var workTask: Task<Void, Never>?
    private var relayEventTask: Task<Void, Never>?
    private var stopped = false

    static let storageVersion = 1
    static let maximumStoredReceipts = 4_096
    static let maximumStorageBytes = 64 * 1_024 * 1_024
    static let maximumRawTransactionBytes = 4_000_000
    static let maximumAttempt = 63
    static let maximumFutureSchedule: TimeInterval = 366 * 24 * 60 * 60
    /// Replaced and abandoned receipts have no height to prune on; they age
    /// out on wall-clock time instead.
    static let terminalRetention: TimeInterval = 30 * 24 * 60 * 60

    public init(relay: @escaping RelayResolver,
                miners: @escaping MinerResolver,
                storageURL: URL? = nil,
                now: @Sendable @escaping () -> Date = { Date() },
                pollBaseInterval: Duration = .seconds(30),
                maxPollInterval: Duration = .seconds(600),
                submitBaseInterval: Duration = .seconds(15),
                maxSubmitInterval: Duration = .seconds(300),
                maxSubmitAttempts: Int = 5) throws
    {
        self.relay = relay
        self.miners = miners
        self.storageURL = storageURL
        self.now = now
        self.pollBaseInterval = pollBaseInterval
        self.maxPollInterval = maxPollInterval
        self.submitBaseInterval = submitBaseInterval
        self.maxSubmitInterval = maxSubmitInterval
        self.maxSubmitAttempts = max(1, maxSubmitAttempts)
        if let storageURL {
            let loaded = try Self.load(storageURL: storageURL, now: now())
            persistenceState = .loaded(receiptCount: loaded.count)
            receiptsByTxid = loaded
        } else {
            persistenceState = .disabled
        }
    }

    // MARK: - Reading

    /// Newest first.
    public var receipts: [SubmissionReceipt] {
        receiptsByTxid.values.sorted { $0.createdAt > $1.createdAt }
    }

    public func receipt(_ txid: Data) -> SubmissionReceipt? {
        receiptsByTxid[txid]
    }

    /// Receipts still awaiting a block: the confirmation sweep's input.
    public var pendingTxids: [Data] {
        receiptsByTxid.filter { $0.value.confirmedAtHeight == nil && !$0.value.state.isTerminal }.map(\.key)
    }

    /// A bug-report export: every receipt without its raw bytes. Nothing in
    /// a receipt is a secret, but the bytes of an unconfirmed transaction
    /// are not something to paste into an issue tracker.
    public func exportReceipts() throws -> Data {
        struct Exported: Encodable {
            let txid: String
            let origin: SubmissionOrigin
            let requestID: UUID
            let route: SubmissionRoute
            let routeHistory: [RouteApproval]
            let state: SubmissionState
            let timeline: [SubmissionReceipt.TimelineEntry]
            let providerStatus: ProviderStatusSnapshot?
            let rejection: SubmissionRejection?
            let lastError: String?
            let submitAttempt: Int
            let pollAttempt: Int
            let confirmedAtHeight: UInt32?
        }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(receipts.map { receipt in
            Exported(txid: receipt.txid.displayHex, origin: receipt.origin,
                     requestID: receipt.requestID, route: receipt.route,
                     routeHistory: receipt.routeHistory, state: receipt.state,
                     timeline: receipt.timeline, providerStatus: receipt.providerStatus,
                     rejection: receipt.rejection, lastError: receipt.lastError,
                     submitAttempt: receipt.submitAttempt, pollAttempt: receipt.pollAttempt,
                     confirmedAtHeight: receipt.confirmedAtHeight)
        })
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

    // MARK: - Lifecycle

    /// Starts the retry/poll loop and the relay-event bridge. Separate from
    /// `init` so a coordinator can be built, inspected and torn down in a
    /// test without ever spawning a task.
    public func start() async {
        guard !stopped else { return }
        await observeRelay()
        scheduleWork()
    }

    /// Ends this session without touching the durable receipts.
    public func shutdown() {
        guard !stopped else { return }
        stopped = true
        workTask?.cancel()
        workTask = nil
        relayEventTask?.cancel()
        relayEventTask = nil
        receiptsByTxid.removeAll()
        for subscriber in subscribers.values { subscriber.finish() }
        subscribers.removeAll()
    }

    // MARK: - Submitting

    /// Records a receipt and executes `route`.
    ///
    /// Throws only when nothing left the device: a malformed transaction, a
    /// provider that could not be built, a relay that is not running, or a
    /// store that refused the write. A provider's rejection or a transport
    /// failure after the request went out returns normally with the receipt
    /// saying so, because by then the signed bytes may be anywhere and the
    /// wallet must reserve the inputs.
    @discardableResult
    public func submit(rawTx: Data, feeRateSatPerVByte: Double?, route: SubmissionRoute,
                       origin: SubmissionOrigin) async throws -> SubmissionReceipt
    {
        guard !stopped else { throw SubmissionError.stopped }
        let transaction = try Self.validatedTransaction(rawTx)
        let txid = transaction.txid
        if let existing = receiptsByTxid[txid] {
            // The same bytes twice is a caller that lost the first answer,
            // not a second submission. Return what already happened.
            guard existing.route == route else {
                throw SubmissionError.duplicateSubmission(route: existing.route)
            }
            return existing
        }
        // Resolve what the route needs before anything is written: a
        // misconfigured provider or a missing relay means nothing leaves the
        // device, and then nothing should be recorded either.
        let client = try await resolveClient(for: route)
        let peerRelay = try resolveRelay(for: route)

        let receipt = SubmissionReceipt(txid: txid, origin: origin, route: route,
                                        feeRateSatPerVByte: feeRateSatPerVByte,
                                        rawTransaction: rawTx, at: now())
        try store(receipt)

        var transmitted = false
        if let client {
            await submitToMiner(txid, client: client)
            transmitted = true
        }
        if let peerRelay {
            do {
                _ = try await peerRelay.broadcast(rawTx, feeRateSatPerVByte: feeRateSatPerVByte)
                transmitted = true
            } catch {
                guard transmitted else {
                    // Nothing reached anyone. Undo the record so the caller
                    // can keep its "broadcast threw, nothing spent" rule.
                    receiptsByTxid.removeValue(forKey: txid)
                    try? persistAll()
                    throw error
                }
                update(txid) { $0.lastError = error.localizedDescription }
            }
        }
        scheduleWork()
        return receiptsByTxid[txid] ?? receipt
    }

    /// Sends a receipt through another route, after recording that the user
    /// approved the change. The approval is written before the new route
    /// runs, so a crash in between leaves the decision on disk.
    @discardableResult
    public func reroute(_ txid: Data, to route: SubmissionRoute) async throws -> SubmissionReceipt {
        guard !stopped else { throw SubmissionError.stopped }
        guard let receipt = receiptsByTxid[txid] else { throw SubmissionError.unknownTransaction }
        guard receipt.canReroute else { throw SubmissionError.notReroutable(receipt.state) }
        let client = try await resolveClient(for: route)
        let peerRelay = try resolveRelay(for: route)

        let approval = RouteApproval(approvedAt: now(), from: receipt.route, to: route)
        try update(txid) {
            $0.recordRoute(approval)
            $0.nextSubmitAt = nil
            $0.nextPollAt = nil
            $0.submitAttempt = 0
            $0.pollAttempt = 0
            $0.lastError = nil
        }
        emit(.rerouted(txid: txid, to: route))

        if let client {
            await submitToMiner(txid, client: client)
        }
        if let peerRelay {
            do {
                _ = try await peerRelay.broadcast(receipt.rawTransaction,
                                                  feeRateSatPerVByte: receipt.feeRateSatPerVByte)
            } catch {
                update(txid) { $0.lastError = error.localizedDescription }
            }
        }
        scheduleWork()
        return receiptsByTxid[txid] ?? receipt
    }

    // MARK: - Lifecycle of a receipt

    /// A replacement was committed for the same inputs.
    public func markReplaced(_ original: Data, by replacement: Data) throws {
        guard !stopped else { throw SubmissionError.stopped }
        guard let receipt = receiptsByTxid[original],
              SubmissionState.allows(receipt.state, to: .replaced) else { return }
        try update(original) {
            try $0.transition(to: .replaced, at: now())
            $0.replacedBy = replacement
            $0.nextSubmitAt = nil
            $0.nextPollAt = nil
        }
        if receiptsByTxid[replacement] != nil {
            try update(replacement) { $0.replaces = original }
        }
        emit(.replaced(txid: original, by: replacement))
        scheduleWork()
    }

    /// Called from the block-match loop. The only way to `confirmed`.
    public func markConfirmed(_ txid: Data, atHeight height: UInt32) throws {
        guard !stopped else { throw SubmissionError.stopped }
        guard let receipt = receiptsByTxid[txid], receipt.confirmedAtHeight == nil else { return }
        try update(txid) {
            try $0.transition(to: .confirmed, at: now())
            $0.confirmedAtHeight = height
            $0.nextSubmitAt = nil
            $0.nextPollAt = nil
        }
        emit(.confirmed(txid: txid))
        scheduleWork()
    }

    /// The confirming block was disconnected (#157). The receipt returns to
    /// flight; a miner route resubmits idempotently and polls again. Nothing
    /// here announces to peers — a `.peers` receipt's relay is the
    /// broadcaster's own rollback, and a `minerOnly` one stays that way.
    public func rollBack(to forkHeight: UInt32) throws {
        guard !stopped else { throw SubmissionError.stopped }
        var reactivated = false
        for (txid, receipt) in receiptsByTxid {
            guard let height = receipt.confirmedAtHeight, height > forkHeight else { continue }
            try update(txid) {
                $0.revertConfirmation(at: now())
                $0.providerStatus = nil
                if $0.route.miner != nil, $0.state == .submitted || $0.state == .accepted {
                    $0.submitAttempt = 0
                    $0.nextSubmitAt = now()
                    $0.pollAttempt = 0
                }
            }
            reactivated = true
        }
        if reactivated { scheduleWork() }
    }

    /// Drops confirmed receipts past the wallet's reorg horizon and terminal
    /// ones past their wall-clock retention.
    public func pruneConfirmed(scannedTo tip: UInt32) throws {
        guard !stopped else { return }
        let cutoff = now() - Self.terminalRetention
        let kept = receiptsByTxid.filter { _, receipt in
            if let height = receipt.confirmedAtHeight { return height + 100 > tip }
            if receipt.state == .replaced || receipt.state == .abandoned {
                return (receipt.timeline.last?.at ?? .distantPast) > cutoff
            }
            return true
        }
        guard kept.count != receiptsByTxid.count else { return }
        try persist(kept)
        receiptsByTxid = kept
    }

    /// Stops tracking. Wallet state is untouched: the transaction may still
    /// confirm, and if it does the block path records that here too.
    public func abandon(_ txid: Data) async throws {
        guard !stopped else { throw SubmissionError.stopped }
        guard let receipt = receiptsByTxid[txid] else { throw SubmissionError.unknownTransaction }
        try update(txid) {
            try $0.transition(to: .abandoned, at: now())
            $0.nextSubmitAt = nil
            $0.nextPollAt = nil
        }
        if receipt.route.touchesPeers, let peerRelay = relay(receipt.route) {
            try? await peerRelay.cancel(txid)
        }
        emit(.abandoned(txid: txid))
        scheduleWork()
    }

    // MARK: - Miner side

    private func resolveClient(for route: SubmissionRoute) async throws -> (any DirectMinerClient)? {
        guard let provider = route.miner else { return nil }
        do {
            return try await miners(provider)
        } catch let error as SubmissionError {
            throw error
        } catch {
            throw SubmissionError.providerUnavailable(provider, reason: error.localizedDescription)
        }
    }

    private func resolveRelay(for route: SubmissionRoute) throws -> (any PeerRelay)? {
        guard route.touchesPeers else { return nil }
        guard let peerRelay = relay(route) else { throw SubmissionError.relayUnavailable }
        return peerRelay
    }

    private func submitToMiner(_ txid: Data, client: any DirectMinerClient) async {
        guard let provider = receiptsByTxid[txid]?.route.miner,
              let package = receiptsByTxid[txid].map({ SubmissionPackage($0.rawTransaction) })
        else { return }
        update(txid) {
            if $0.state != .submitted { try? $0.transition(to: .submitted, at: now()) }
            if $0.submittedAt == nil { $0.submittedAt = now() }
            $0.submitAttempt += 1
            $0.nextSubmitAt = nil
        }
        emit(.submitted(txid: txid, provider: provider))

        let outcome: MinerSubmitOutcome
        do {
            outcome = try await client.submit(package)
        } catch {
            // Reentrancy: the block path may have confirmed it meanwhile.
            guard let current = receiptsByTxid[txid], current.state == .submitted else { return }
            let attempt = current.submitAttempt
            var retryAfter: Date?
            if attempt < maxSubmitAttempts {
                var wait = Self.backoffInterval(attempt: attempt - 1, base: submitBaseInterval,
                                                cap: maxSubmitInterval)
                if case let .rateLimited(seconds?) = error as? MinerClientError {
                    wait = max(wait, .seconds(seconds))
                }
                retryAfter = now() + Self.timeInterval(wait)
            }
            update(txid) {
                $0.lastError = error.localizedDescription
                $0.nextSubmitAt = retryAfter
            }
            if retryAfter == nil { emit(.deliveryUnconfirmed(txid: txid)) }
            return
        }
        guard let current = receiptsByTxid[txid], current.state == .submitted else { return }
        switch outcome {
        case let .accepted(_, message):
            update(txid) {
                try? $0.transition(to: .accepted, at: now())
                $0.lastError = nil
                $0.providerStatus = ProviderStatusSnapshot(
                    kind: .pending, message: message, position: nil, inclusionOdds: nil,
                    reportedHeight: nil, observedAt: now())
                $0.pollAttempt = 0
                $0.nextPollAt = client.capabilities.contains(.statusByTxid)
                    ? now() + Self.timeInterval(pollBaseInterval) : nil
            }
            emit(.accepted(txid: txid, provider: provider))
        case .alreadyKnown:
            update(txid) {
                try? $0.transition(to: .accepted, at: now())
                $0.lastError = nil
                $0.pollAttempt = 0
                $0.nextPollAt = client.capabilities.contains(.statusByTxid)
                    ? now() + Self.timeInterval(pollBaseInterval) : nil
            }
            emit(.accepted(txid: txid, provider: provider))
        case let .rejected(reason, policy):
            update(txid) {
                try? $0.transition(to: .rejected, at: now())
                $0.rejection = SubmissionRejection(reason: reason, policy: policy, observedAt: now())
                $0.nextPollAt = nil
            }
            emit(.rejected(txid: txid, reason: reason, policy: policy))
        }
    }

    private func pollOnce(_ txid: Data) async {
        guard let receipt = receiptsByTxid[txid], let provider = receipt.route.miner,
              receipt.state == .submitted || receipt.state == .accepted else { return }
        guard let client = try? await miners(provider),
              client.capabilities.contains(.statusByTxid) else {
            update(txid) { $0.nextPollAt = nil }
            return
        }
        let status: MinerReportedStatus
        do {
            status = try await client.status(txid: txid)
        } catch {
            guard let current = receiptsByTxid[txid],
                  current.state == .submitted || current.state == .accepted else { return }
            let attempt = current.pollAttempt + 1
            update(txid) {
                $0.lastPolledAt = now()
                $0.pollAttempt = attempt
                $0.lastError = error.localizedDescription
                $0.nextPollAt = now() + Self.timeInterval(
                    Self.backoffInterval(attempt: attempt, base: pollBaseInterval, cap: maxPollInterval))
            }
            return
        }
        guard let current = receiptsByTxid[txid],
              current.state == .submitted || current.state == .accepted else { return }
        let attempt = current.pollAttempt + 1
        let snapshot = ProviderStatusSnapshot(status, observedAt: now())
        update(txid) {
            $0.lastPolledAt = now()
            $0.pollAttempt = attempt
            $0.providerStatus = snapshot
            switch status {
            case let .rejected(reason):
                try? $0.transition(to: .rejected, at: now())
                $0.rejection = SubmissionRejection(reason: reason, policy: false, observedAt: now())
                $0.nextPollAt = nil
            case .confirmed:
                // The provider's opinion; Winnow's block path finishes it.
                $0.nextPollAt = nil
            case .pending:
                if $0.state == .submitted, $0.nextSubmitAt == nil {
                    try? $0.transition(to: .accepted, at: now())
                }
                $0.nextPollAt = now() + Self.timeInterval(
                    Self.backoffInterval(attempt: attempt, base: pollBaseInterval, cap: maxPollInterval))
            case .notFound:
                $0.nextPollAt = now() + Self.timeInterval(
                    Self.backoffInterval(attempt: attempt, base: pollBaseInterval, cap: maxPollInterval))
            }
        }
        if case let .rejected(reason) = status {
            emit(.rejected(txid: txid, reason: reason, policy: false))
        }
        emit(.providerStatus(txid: txid, kind: snapshot.kind))
    }

    // MARK: - Peer side

    /// Subscribes before returning, so an event emitted right after `start`
    /// is seen rather than lost to a task that had not yet asked for the
    /// stream.
    private func observeRelay() async {
        guard relayEventTask == nil, let peerRelay = relay(.peers) else { return }
        let stream = await peerRelay.events()
        relayEventTask = Task { [weak self] in
            for await event in stream {
                guard let self else { return }
                switch event {
                case let .requested(txid, _), let .served(txid, _):
                    await self.noteRelayed(txid)
                default:
                    continue
                }
            }
        }
    }

    private func noteRelayed(_ txid: Data) {
        guard let receipt = receiptsByTxid[txid], receipt.route.touchesPeers,
              SubmissionState.allows(receipt.state, to: .relayed) else { return }
        update(txid) {
            try? $0.transition(to: .relayed, at: now())
            $0.nextSubmitAt = nil
            $0.nextPollAt = nil
        }
        emit(.relayed(txid: txid))
        scheduleWork()
    }

    // MARK: - Scheduling

    /// Sleeps until the earliest due retry or poll, runs everything due,
    /// repeats. Stops when nothing is scheduled.
    private func scheduleWork() {
        workTask?.cancel()
        workTask = nil
        guard !stopped else { return }
        let due = receiptsByTxid.values
            .flatMap { [$0.nextSubmitAt, $0.nextPollAt] }
            .compactMap { $0 }
            .min()
        guard let due else { return }
        let delay = due.timeIntervalSince(now())
        workTask = Task { [weak self] in
            if delay > 0 { try? await Task.sleep(for: .seconds(delay)) }
            guard !Task.isCancelled else { return }
            await self?.runDue()
        }
    }

    private func runDue() async {
        guard !stopped else { return }
        let deadline = now()
        let resubmits = receiptsByTxid.filter { $0.value.nextSubmitAt.map { $0 <= deadline } ?? false }.map(\.key)
        for txid in resubmits {
            guard let provider = receiptsByTxid[txid]?.route.miner,
                  let client = try? await miners(provider) else {
                update(txid) { $0.nextSubmitAt = nil }
                emit(.deliveryUnconfirmed(txid: txid))
                continue
            }
            await submitToMiner(txid, client: client)
        }
        let polls = receiptsByTxid.filter { $0.value.nextPollAt.map { $0 <= deadline } ?? false }.map(\.key)
        for txid in polls {
            await pollOnce(txid)
        }
        scheduleWork()
    }

    /// Test-visible hook: run everything that is due right now.
    func runDueNow() async { await runDue() }

    // MARK: - Internals

    private func removeSubscriber(_ id: UUID) {
        subscribers.removeValue(forKey: id)
    }

    private func emit(_ event: Event) {
        for subscriber in subscribers.values { subscriber.yield(event) }
    }

    /// Persists a mutation, keeping memory and disk in step: the candidate
    /// is written first and adopted only if the write succeeded.
    private func update(_ txid: Data, _ body: (inout SubmissionReceipt) throws -> Void) rethrows {
        guard var candidate = receiptsByTxid[txid] else { return }
        try body(&candidate)
        var all = receiptsByTxid
        all[txid] = candidate
        do {
            try persist(all)
            receiptsByTxid = all
        } catch {
            // Keep the in-memory truth: the state did change, and hiding
            // that would be worse than a stale file. Say so.
            receiptsByTxid = all
            emit(.persistenceFailed(reason: error.localizedDescription))
        }
    }

    private func store(_ receipt: SubmissionReceipt) throws {
        var all = receiptsByTxid
        all[receipt.txid] = receipt
        try persist(all)
        receiptsByTxid = all
    }

    private func persistAll() throws {
        try persist(receiptsByTxid)
    }

    private func persist(_ state: [Data: SubmissionReceipt]) throws {
        guard let storageURL else { return }
        guard state.count <= Self.maximumStoredReceipts else {
            throw SubmissionStoreError.writeFailed
        }
        let stored = StoredReceipts(version: Self.storageVersion,
                                    receipts: state.values.sorted { $0.createdAt < $1.createdAt })
        do {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .secondsSince1970
            encoder.outputFormatting = [.sortedKeys]
            let data = try encoder.encode(stored)
            guard data.count <= Self.maximumStorageBytes else {
                throw SubmissionStoreError.writeFailed
            }
            try data.write(to: storageURL,
                           options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        } catch let error as SubmissionStoreError {
            throw error
        } catch {
            throw SubmissionStoreError.writeFailed
        }
    }

    private static func load(storageURL: URL, now: Date) throws -> [Data: SubmissionReceipt] {
        guard FileManager.default.fileExists(atPath: storageURL.path) else { return [:] }
        let attributes: [FileAttributeKey: Any]
        do {
            attributes = try FileManager.default.attributesOfItem(atPath: storageURL.path)
        } catch {
            throw SubmissionStoreError.unreadable
        }
        if let size = attributes[.size] as? NSNumber, size.int64Value > Int64(maximumStorageBytes) {
            throw SubmissionStoreError.tooLarge(maxBytes: maximumStorageBytes)
        }
        let data: Data
        do {
            data = try Data(contentsOf: storageURL, options: .mappedIfSafe)
        } catch {
            throw SubmissionStoreError.unreadable
        }
        guard data.count <= maximumStorageBytes else {
            throw SubmissionStoreError.tooLarge(maxBytes: maximumStorageBytes)
        }
        guard !data.isEmpty else { throw SubmissionStoreError.damaged("the file is empty") }

        let topLevel: [String: Any]
        do {
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw SubmissionStoreError.damaged("the top level is not an object")
            }
            topLevel = object
        } catch let error as SubmissionStoreError {
            throw error
        } catch {
            throw SubmissionStoreError.damaged("the JSON is invalid")
        }
        guard let rawVersion = topLevel["version"] as? NSNumber,
              rawVersion.doubleValue.isFinite,
              rawVersion.doubleValue.rounded(.towardZero) == rawVersion.doubleValue
        else { throw SubmissionStoreError.damaged("the format version is missing or invalid") }
        let version = rawVersion.intValue
        guard version == storageVersion else { throw SubmissionStoreError.unsupportedVersion(version) }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        let stored: StoredReceipts
        do {
            stored = try decoder.decode(StoredReceipts.self, from: data)
        } catch {
            throw SubmissionStoreError.damaged("a receipt record is invalid")
        }
        guard stored.receipts.count <= maximumStoredReceipts else {
            throw SubmissionStoreError.damaged("there are too many receipts")
        }
        var result: [Data: SubmissionReceipt] = [:]
        result.reserveCapacity(stored.receipts.count)
        for receipt in stored.receipts {
            try validate(receipt, now: now)
            guard result[receipt.txid] == nil else {
                throw SubmissionStoreError.damaged("a transaction has two receipts")
            }
            result[receipt.txid] = receipt
        }
        return result
    }

    private static func validate(_ receipt: SubmissionReceipt, now: Date) throws {
        guard receipt.txid.count == 32 else { throw SubmissionStoreError.damaged("a txid is not 32 bytes") }
        let transaction: Transaction
        do {
            transaction = try validatedTransaction(receipt.rawTransaction)
        } catch {
            throw SubmissionStoreError.damaged("a raw transaction is invalid")
        }
        guard transaction.txid == receipt.txid else {
            throw SubmissionStoreError.damaged("a receipt's txid does not match its transaction")
        }
        guard !receipt.timeline.isEmpty, receipt.timeline.last?.state == receipt.state else {
            throw SubmissionStoreError.damaged("a receipt's timeline disagrees with its state")
        }
        guard (0 ... maximumAttempt).contains(receipt.submitAttempt),
              (0 ... maximumAttempt).contains(receipt.pollAttempt) else {
            throw SubmissionStoreError.damaged("a retry counter is out of range")
        }
        let horizon = now + maximumFutureSchedule
        for date in [receipt.nextSubmitAt, receipt.nextPollAt].compactMap({ $0 }) {
            guard date.timeIntervalSince1970.isFinite, date <= horizon else {
                throw SubmissionStoreError.damaged("a schedule is too far in the future")
            }
        }
        if let rate = receipt.feeRateSatPerVByte {
            guard rate.isFinite, rate > 0 else { throw SubmissionStoreError.damaged("a fee rate is invalid") }
        }
        if let replacedBy = receipt.replacedBy, replacedBy.count != 32 {
            throw SubmissionStoreError.damaged("a replacement txid is not 32 bytes")
        }
    }

    static func validatedTransaction(_ rawTx: Data) throws -> Transaction {
        guard !rawTx.isEmpty, rawTx.count <= maximumRawTransactionBytes else {
            throw SubmissionError.malformedTransaction("size \(rawTx.count)")
        }
        let transaction: Transaction
        do {
            transaction = try Transaction.decode(rawTx)
        } catch {
            throw SubmissionError.malformedTransaction("undecodable")
        }
        guard transaction.serialized(includeWitness: true) == rawTx else {
            throw SubmissionError.malformedTransaction("non-canonical encoding")
        }
        return transaction
    }

    /// base × 2^attempt, capped. Pure, so the schedule is testable without
    /// a clock (the lesson of #138).
    static func backoffInterval(attempt: Int, base: Duration, cap: Duration) -> Duration {
        var interval = base
        for _ in 0 ..< max(0, attempt) {
            let doubled = interval + interval
            guard doubled < cap else { return cap }
            interval = doubled
        }
        return min(interval, cap)
    }

    static func timeInterval(_ duration: Duration) -> TimeInterval {
        let components = duration.components
        return TimeInterval(components.seconds) + TimeInterval(components.attoseconds) / 1e18
    }
}
