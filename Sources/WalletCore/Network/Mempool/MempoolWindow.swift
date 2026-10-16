import Foundation

/// A bounded mempool window (docs/read-side.md §2.8): a time- and
/// screen-bounded subscription to *full transaction relay*. While the window
/// is open, every transaction `inv` from the pool's connected peers is
/// answered with `getdata(MSG_WITNESS_TX)`, and the fetched transactions are
/// matched locally against a watch set of scriptPubKeys (typically the one
/// address currently displayed).
///
/// Privacy: nothing is queried and nothing is revealed — the client receives
/// public gossip, and a node that fetches every relayed transaction is
/// indistinguishable from an ordinary full node. The relay bit
/// (`relayPreference`) is a connect-time parameter of the pool's connections
/// (PeerPool/PeerConnection); this actor bounds the expensive part: with no
/// window open, invs are dropped by PeerConnection's bounded backlog — bounded
/// in messages and in bytes, so a peer that floods them costs a fixed amount
/// of memory and nothing else — and no getdata is ever sent.
///
/// Lifecycle: `start(duration:)` opens the window (default 20 minutes),
/// `extend(by:)` pushes the deadline out, `stop()` closes it — cancelling the
/// peer listeners and the expiry sweep. Peers that disconnect mid-window are
/// forgotten; the sweep task re-attaches to replacement peers the pool
/// connects.
///
/// Bounds by construction: announced txids dedupe through a capped
/// FIFO set (`maxSeenTxids`), in-flight getdata requests are capped
/// (`maxInFlight`) and time out (`requestTimeout`), and a fetched tx is
/// matched at most once.
public actor MempoolWindow {
    public enum Event: Equatable, Sendable {
        /// A relayed transaction pays a watched script. `amount` is the sum
        /// (sats) of all outputs paying watched scripts; `scriptPubKey` is
        /// the first watched script matched. Unconfirmed is never final
        /// (RBF/double-spend) — the UI says "unconfirmed", never "received".
        case paymentSeen(txid: Data, amount: Int64, scriptPubKey: Data)
        /// A peer inv'd back a txid registered via `watchEcho(of:)` — the
        /// network has our broadcast (emitted once per txid per peer).
        case txidEchoed(txid: Data, peer: PeerEndpoint)
    }

    public static let defaultDuration: Duration = .seconds(1_200) // 20 minutes

    private let pool: PeerPool
    private let watchScripts: Set<Data>
    /// Max txids remembered for inv dedupe; oldest evicted past the cap.
    private let maxSeenTxids: Int
    /// Max unanswered getdata requests; new invs are dropped past the cap.
    private let maxInFlight: Int
    /// How long a getdata may go unanswered before the txid can be
    /// re-requested from another peer.
    private let requestTimeout: Duration
    /// How often the sweep attaches to new peers and expires stale requests.
    private let sweepInterval: Duration

    private var running = false
    /// Bumped on every start/stop so a dying listener's cleanup cannot
    /// unregister the replacement listener of a restarted window.
    private var generation = 0
    private var stopTask: Task<Void, Never>?
    private var sweepTask: Task<Void, Never>?
    private var listenerTasks: [String: Task<Void, Never>] = [:] // keyed by endpoint description

    /// txids already announced to us (requested or matched), FIFO-evicted.
    private var seenTxids: Set<Data> = []
    private var seenOrder: [Data] = []
    /// txid → when we sent the getdata.
    private var inFlight: [Data: Date] = [:]
    /// txids registered for echo detection.
    private var echoTxids: Set<Data> = []
    /// "txidHex|host:port" pairs already echoed.
    private var echoed: Set<String> = []
    private var subscribers: [UUID: AsyncStream<Event>.Continuation] = [:]

    public init(pool: PeerPool, watchScripts: Set<Data>,
                maxSeenTxids: Int = 10_000, maxInFlight: Int = 512,
                requestTimeout: Duration = .seconds(30),
                sweepInterval: Duration = .seconds(5)) {
        self.pool = pool
        self.watchScripts = watchScripts
        self.maxSeenTxids = maxSeenTxids
        self.maxInFlight = maxInFlight
        self.requestTimeout = requestTimeout
        self.sweepInterval = sweepInterval
    }

    /// Whether the window is currently open.
    public var isRunning: Bool { running }

    /// The window's events; each caller gets its own stream (same multicast
    /// pattern as TxBroadcaster).
    public func events() -> AsyncStream<Event> {
        let id = UUID()
        return AsyncStream { continuation in
            subscribers[id] = continuation
            continuation.onTermination = { _ in
                Task { await self.removeSubscriber(id) }
            }
        }
    }

    /// Opens the window for `duration`, then closes it automatically.
    /// Calling start again re-arms the deadline. Awaits the initial listener
    /// attach, so invs arriving right after `start` returns are seen.
    public func start(duration: Duration = MempoolWindow.defaultDuration) async {
        armStop(after: duration)
        guard !running else { return }
        running = true
        generation += 1
        await attachToConnectedPeers()
        sweepTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                try? await Task.sleep(for: self.sweepInterval)
                guard !Task.isCancelled else { return }
                await self.sweep()
            }
        }
    }

    /// Pushes the automatic close `extra` into the future (from now).
    public func extend(by extra: Duration) {
        guard running else { return }
        armStop(after: extra)
    }

    /// Closes the window: listeners and timers are cancelled, in-flight
    /// state is dropped. Subscribers' streams stay open (they simply go
    /// quiet); the window can be started again.
    public func stop() {
        running = false
        generation += 1
        stopTask?.cancel()
        stopTask = nil
        sweepTask?.cancel()
        sweepTask = nil
        for (_, task) in listenerTasks { task.cancel() }
        listenerTasks.removeAll()
        seenTxids.removeAll()
        seenOrder.removeAll()
        inFlight.removeAll()
        echoed.removeAll()
    }

    /// Registers a broadcast txid for echo detection: a peer inv'ing it back
    /// proves network propagation. Not cleared by `stop()` — echo watches
    /// belong to the caller, not the window session.
    public func watchEcho(of txid: Data) {
        echoTxids.insert(txid)
    }

    /// Drops an echo watch (e.g. the tx confirmed).
    public func unwatchEcho(of txid: Data) {
        echoTxids.remove(txid)
        echoed = echoed.filter { !$0.hasPrefix(txid.hex + "|") }
    }

    // MARK: - Internals

    private func removeSubscriber(_ id: UUID) {
        subscribers.removeValue(forKey: id)
    }

    private func emit(_ event: Event) {
        for subscriber in subscribers.values { subscriber.yield(event) }
    }

    private func armStop(after duration: Duration) {
        stopTask?.cancel()
        stopTask = Task { [weak self] in
            try? await Task.sleep(for: duration)
            guard !Task.isCancelled, let self else { return }
            await self.stop()
        }
    }

    /// Attaches listeners to connected peers that lack one and expires
    /// getdata requests whose peer never answered (a re-announcement from
    /// another peer then re-requests the tx).
    private func sweep() async {
        guard running else { return }
        await attachToConnectedPeers()
        let deadline = Date().addingTimeInterval(-Self.timeInterval(requestTimeout))
        for (txid, requestedAt) in inFlight where requestedAt < deadline {
            inFlight.removeValue(forKey: txid)
            forget(txid)
        }
    }

    private func attachToConnectedPeers() async {
        // A relay-only pool holds its seats for a payment going out, not for
        // reading what the network relays; nothing attaches to them.
        guard running, await pool.mode == .full else { return }
        for peer in await pool.connectedPeers() {
            let key = peer.endpoint.description
            guard listenerTasks[key] == nil else { continue }
            // Subscribe here rather than inside the listener task.
            // PeerConnection.events() registers the subscriber at call time and
            // replays nothing, so a listener that only subscribes once its task
            // is scheduled drops every message announced in that gap — and an
            // inv is never re-sent. Awaiting the subscription makes start()
            // returning mean "attached", which is what callers already assume.
            let gen = generation
            let stream = await peer.events()
            // That await is a suspension point on this actor, so a stop (or a
            // stop-then-start, which is why `gen` is checked and not just
            // `running`) may have landed meanwhile, making this stream stale:
            // its buffer holds gossip from the closed window. Dropping it
            // unconsumed terminates it and unregisters the subscriber.
            guard running, generation == gen, listenerTasks[key] == nil else { continue }
            listenerTasks[key] = Task { await self.listen(to: peer, stream: stream, generation: gen) }
        }
    }

    private func listen(to peer: PeerConnection,
                        stream: AsyncThrowingStream<PeerEvent, Error>,
                        generation: Int) async {
        do {
            for try await event in stream {
                guard running else { break }
                if case let .message(message) = event {
                    await handle(message, from: peer)
                }
            }
        } catch {
            // Peer stream failed; the pool replaces the peer and the sweep
            // attaches a listener to the replacement.
        }
        // A restarted window has already replaced this registration.
        if self.generation == generation {
            listenerTasks.removeValue(forKey: peer.endpoint.description)
        }
    }

    private func handle(_ message: PeerMessage, from peer: PeerConnection) async {
        switch message {
        case let .inv(payload):
            await handleInv(payload, from: peer)
        case let .tx(transaction):
            handleTx(transaction)
        case let .notfound(payload):
            for vector in payload.vectors where vector.type.baseType == .tx {
                // This peer doesn't have it; free the txid so a duplicate
                // announcement from another peer re-requests it there.
                inFlight.removeValue(forKey: vector.hash)
                forget(vector.hash)
            }
        default:
            break
        }
    }

    /// Dedupes announced txids across peers and fetches each unknown one
    /// (witness serialization) from the first peer that announced it. Txids
    /// are marked seen before the suspending send (so a second peer's inv of
    /// the same tx, processed while the send is in flight, is deduped) and
    /// rolled back if the send fails.
    private func handleInv(_ payload: InventoryPayload, from peer: PeerConnection) async {
        let request = admitAnnouncements(payload, from: peer)
        guard !request.isEmpty else { return }
        do {
            try await peer.send(.getdata(InventoryPayload(request)))
        } catch {
            // Peer died mid-request; roll back so another peer's announcement
            // re-requests the txs.
            for vector in request { forget(vector.hash) }
            return
        }
        let requestedAt = Date()
        for vector in request { inFlight[vector.hash] = requestedAt }
    }

    /// Filters an inv down to the tx announcements worth fetching — echo
    /// tracking, dedup against the bounded seen set, and the in-flight cap —
    /// and records them as seen before the request goes out.
    private func admitAnnouncements(_ payload: InventoryPayload,
                                    from peer: PeerConnection) -> [InventoryVector] {
        var request: [InventoryVector] = []
        for vector in payload.vectors where vector.type.baseType == .tx {
            let txid = vector.hash
            if echoTxids.contains(txid) {
                let key = txid.hex + "|" + peer.endpoint.description
                if echoed.insert(key).inserted {
                    emit(.txidEchoed(txid: txid, peer: peer.endpoint))
                }
            }
            guard !seenTxids.contains(txid), inFlight.count + request.count < maxInFlight else { continue }
            seenTxids.insert(txid)
            seenOrder.append(txid)
            request.append(InventoryVector(type: .witnessTx, hash: txid))
        }
        while seenOrder.count > maxSeenTxids {
            let evicted = seenOrder.removeFirst()
            seenTxids.remove(evicted)
        }
        return request
    }

    /// Drops a txid from the seen set. The ordered list is searched only for
    /// a txid that was actually seen: a `notfound` naming 50,000 strangers
    /// must not cost 50,000 scans of it.
    private func forget(_ txid: Data) {
        guard seenTxids.remove(txid) != nil,
              let index = seenOrder.firstIndex(of: txid) else { return }
        seenOrder.remove(at: index)
    }

    /// Matches a fetched transaction against the watch set (once — the
    /// in-flight entry is consumed, so duplicate deliveries are ignored).
    private func handleTx(_ transaction: Transaction) {
        let txid = transaction.txid
        guard inFlight.removeValue(forKey: txid) != nil else { return }
        var amount: Int64 = 0
        var matchedScript: Data?
        for output in transaction.outputs where watchScripts.contains(output.scriptPubKey) {
            amount += output.value
            if matchedScript == nil { matchedScript = output.scriptPubKey }
        }
        if let matchedScript, amount > 0 {
            emit(.paymentSeen(txid: txid, amount: amount, scriptPubKey: matchedScript))
        }
    }

    private static func timeInterval(_ duration: Duration) -> TimeInterval {
        let components = duration.components
        return TimeInterval(components.seconds) + TimeInterval(components.attoseconds) / 1e18
    }
}
