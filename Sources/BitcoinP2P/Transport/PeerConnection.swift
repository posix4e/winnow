import Foundation
import Network

public enum PeerError: LocalizedError, Equatable {
    case timeout
    case notConnected
    case disconnected(String)
    case handshakeFailed(String)
    /// Peer did not signal NODE_COMPACT_FILTERS (BIP157 service bit 6).
    case missingCompactFilters(services: UInt64)
    case protocolViolation(String)

    /// Without this every reason recorded through `localizedDescription` read
    /// as "BitcoinP2P.PeerError error 4", which is the same discarded-diagnosis
    /// problem #82 is about — one layer down.
    public var errorDescription: String? {
        switch self {
        case .timeout: "The peer did not answer in time."
        case .notConnected: "The connection to the peer was not open."
        case let .disconnected(reason): "The peer disconnected (\(reason))."
        case let .handshakeFailed(reason): "The peer handshake failed (\(reason))."
        case let .missingCompactFilters(services):
            "The peer does not serve compact block filters (services \(services))."
        case let .protocolViolation(reason): "The peer violated the protocol (\(reason))."
        }
    }

    /// Whether this is the connection failing rather than the peer being
    /// dishonest — the distinction that decides between a cooldown and a
    /// session-long ban (#82).
    ///
    /// Timeouts and disconnections say nothing about whether a peer is
    /// truthful; they say the link was slow or dropped, which a good peer on a
    /// bad network does routinely. A protocol violation or a missing service
    /// bit is the peer itself being unusable, and stays permanent.
    ///
    /// `handshakeFailed` is counted as transport on purpose: it is the most
    /// common shape of "unreachable right now", and treating a failed dial as
    /// misconduct is what removes a perfectly good endpoint from the persisted
    /// peers file.
    public var isTransport: Bool {
        switch self {
        case .timeout, .notConnected, .disconnected, .handshakeFailed:
            true
        case .missingCompactFilters, .protocolViolation:
            false
        }
    }
}

/// A peer's host/port.
public struct PeerEndpoint: Equatable, Sendable, Codable, Hashable, CustomStringConvertible {
    public var host: String
    public var port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    public var description: String { "\(host):\(port)" }
}

/// Unsolicited things a peer tells us outside request/response exchanges.
public enum PeerEvent: Sendable {
    case message(PeerMessage)
    case disconnected
}

/// One Bitcoin P2P peer over `Network.framework` (plain TCP, BIP324 is out of
/// scope for this phase).
///
/// Lifecycle: `connect()` performs the version/verack handshake (protocol
/// 70016, services 0, UA "/winnow:0.1/") and rejects peers that do not
/// signal NODE_COMPACT_FILTERS. The BIP37 relay flag defaults to false (no
/// unsolicited tx relay); a client that wants full relay for a bounded
/// mempool window (docs/read-side.md §2.8) passes `relayPreference: true` at
/// connect time. Inbound `ping`/`feefilter` are handled internally; everything
/// else goes to a waiting request or to the multicast `events()` stream.
public actor PeerConnection {
    public static let protocolVersion: Int32 = 70_016
    public static let userAgent = "/winnow:0.1/"
    /// BIP157/158 service bit 6.
    public static let nodeCompactFilters: UInt64 = 1 << 6

    public let endpoint: PeerEndpoint
    public let params: NetworkParams
    public let localServices: UInt64
    public let localStartHeight: Int32
    /// Value of the BIP37 relay flag sent in our version handshake
    /// (fRelayTransactions): true asks the peer to inv every relayed tx.
    public let relayPreference: Bool

    public private(set) var peerServices: UInt64 = 0
    public private(set) var peerUserAgent = ""
    public private(set) var peerStartHeight: Int32 = 0
    /// Latest BIP133 feefilter (sat/kvB) the peer sent us.
    public private(set) var feeFilter: Int64?
    public private(set) var isConnected = false

    private var connection: NWConnection?
    private var framer: MessageFramer
    private var receiveTask: Task<Void, Never>?
    private var pingTask: Task<Void, Never>?
    private var didTeardown = false

    private struct PendingRequest {
        let commands: Set<String>
        let continuation: CheckedContinuation<PeerMessage, Error>
    }

    private struct PendingCollector {
        let command: String
        let expected: Int
        var received: [PeerMessage]
        let continuation: CheckedContinuation<[PeerMessage], Error>
    }

    private var pending: [UUID: PendingRequest] = [:]
    private var collectors: [UUID: PendingCollector] = [:]
    private var timeoutTasks: [UUID: Task<Void, Never>] = [:]
    private var subscribers: [UUID: AsyncThrowingStream<PeerEvent, Error>.Continuation] = [:]
    /// Messages that arrived with no waiter/collector registered (e.g. a
    /// verack sent before we started waiting for it). Bounded; oldest dropped.
    private var backlog: [PeerMessage] = []
    private static let backlogLimit = 256

    public init(endpoint: PeerEndpoint, params: NetworkParams,
                localServices: UInt64 = 0, localStartHeight: Int32 = 0,
                relayPreference: Bool = false) {
        self.endpoint = endpoint
        self.params = params
        self.localServices = localServices
        self.localStartHeight = localStartHeight
        self.relayPreference = relayPreference
        framer = MessageFramer(magic: params.magic)
    }

    // MARK: - Connect / handshake

    /// TCP connect + version handshake. Throws `missingCompactFilters` when
    /// the peer cannot serve BIP157 filters.
    public func connect(timeout: Duration = .seconds(20)) async throws {
        guard connection == nil else { return }
        guard let port = NWEndpoint.Port(rawValue: endpoint.port) else {
            throw PeerError.handshakeFailed("invalid port \(endpoint.port)")
        }
        let connection = NWConnection(host: NWEndpoint.Host(endpoint.host),
                                      port: port,
                                      using: .tcp)
        self.connection = connection
        connection.stateUpdateHandler = { state in
            Task { await self.handleStateUpdate(state) }
        }
        connection.start(queue: DispatchQueue(label: "org.winnow.peer.\(endpoint.description)"))
        do {
            try await waitForReady(timeout: timeout)
        } catch {
            teardown(error: error)
            throw error
        }

        receiveTask = Task { await self.receiveLoop(connection) }

        // version → version + verack → verack (BIP handshake order).
        let version = VersionMessage(
            version: Self.protocolVersion,
            services: localServices,
            timestamp: Int64(Date().timeIntervalSince1970),
            receiver: .unspecified,
            sender: .unspecified,
            nonce: UInt64.random(in: UInt64.min ... UInt64.max),
            userAgent: Self.userAgent,
            startHeight: localStartHeight,
            relay: relayPreference
        )
        try await send(.version(version))
        do {
            let theirVersionMessage = try await waitFor(matching: ["version"], timeout: timeout)
            guard case let .version(theirVersion) = theirVersionMessage else {
                throw PeerError.handshakeFailed("expected version")
            }
            guard theirVersion.services & Self.nodeCompactFilters != 0 else {
                throw PeerError.missingCompactFilters(services: theirVersion.services)
            }
            peerServices = theirVersion.services
            peerUserAgent = theirVersion.userAgent
            peerStartHeight = theirVersion.startHeight
            // The peer's verack may already be in our receive buffer (it is
            // sent on receipt of our version), so the waiter consults the
            // backlog first — no ordering assumption here.
            try await send(.verack)
            _ = try await waitFor(matching: ["verack"], timeout: timeout)
        } catch {
            teardown(error: error)
            throw error
        }
        // BIP130: we prefer `headers` over `inv` for block announcements.
        try? await send(.sendheaders)

        isConnected = true
        startKeepalive()
    }

    /// Cleanly closes the connection and finishes all event streams.
    public func disconnect() {
        teardown(error: nil)
    }

    // MARK: - Sending / requests

    public func send(_ message: PeerMessage) async throws {
        guard let connection, !didTeardown else { throw PeerError.notConnected }
        let framed = MessageFramer.frame(command: message.command, payload: message.payload, magic: params.magic)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: framed, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: PeerError.disconnected(error.localizedDescription))
                } else {
                    continuation.resume()
                }
            })
        }
    }

    /// Sends a request and awaits the first response matching `commands`.
    public func request(_ message: PeerMessage, expecting commands: Set<String>,
                        timeout: Duration = .seconds(30)) async throws -> PeerMessage {
        async let response = waitFor(matching: commands, timeout: timeout)
        try await send(message)
        return try await response
    }

    /// Sends a request and collects `count` responses of one command
    /// (e.g. the `cfilter` burst answering `getcfilters`).
    public func requestMany(_ message: PeerMessage, expecting command: String, count: Int,
                            timeout: Duration = .seconds(60)) async throws -> [PeerMessage] {
        precondition(count > 0)
        let id = UUID()
        scheduleTimeout(for: id, timeout: timeout)
        do {
            async let collected = collect(id: id, command: command, count: count)
            try await send(message)
            let result = try await collected
            timeoutTasks.removeValue(forKey: id)?.cancel()
            return result
        } catch {
            collectors.removeValue(forKey: id)
            timeoutTasks.removeValue(forKey: id)?.cancel()
            throw error
        }
    }

    /// Registers a response collector; resolves once `count` messages of
    /// `command` have arrived (or the timeout from `requestMany` fires).
    /// Drains any matching backlog entries first.
    private func collect(id: UUID, command: String, count: Int) async throws -> [PeerMessage] {
        var received: [PeerMessage] = []
        while received.count < count, let index = backlog.firstIndex(where: { $0.command == command }) {
            received.append(backlog.remove(at: index))
        }
        guard received.count < count else { return received }
        return try await withCheckedThrowingContinuation { continuation in
            collectors[id] = PendingCollector(command: command, expected: count, received: received,
                                              continuation: continuation)
        }
    }

    /// Manual ping: sends a nonce and waits for any pong.
    public func ping(timeout: Duration = .seconds(10)) async throws {
        let nonce = UInt64.random(in: UInt64.min ... UInt64.max)
        _ = try await request(.ping(nonce), expecting: ["pong"], timeout: timeout)
    }

    /// Multicast stream of unsolicited messages (inv, headers, getdata, …).
    /// Each caller gets its own stream.
    public func events() -> AsyncThrowingStream<PeerEvent, Error> {
        let id = UUID()
        // Bounded buffer: a peer that floods unsolicited messages faster than a
        // subscriber drains must drop old gossip, not grow memory without limit.
        return AsyncThrowingStream(bufferingPolicy: .bufferingNewest(256)) { continuation in
            subscribers[id] = continuation
            continuation.onTermination = { _ in
                Task { await self.removeSubscriber(id) }
            }
        }
    }

    // MARK: - Internals

    private var readyContinuation: CheckedContinuation<Void, Error>?
    private var readyTimeoutTask: Task<Void, Never>?
    /// Set when the connection reached .ready before anyone waited on it.
    private var connectionReady = false

    /// Awaits NWConnection.State.ready; resolved/failed by handleStateUpdate,
    /// or throws PeerError.timeout after `timeout`. (A refused connection may
    /// sit in .waiting forever, so the timeout must live here rather than in
    /// a task-group race that would wait on the cancelled child.)
    private func waitForReady(timeout: Duration) async throws {
        if connectionReady {
            connectionReady = false
            return
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            readyContinuation = continuation
            readyTimeoutTask = Task { [weak self] in
                try? await Task.sleep(for: timeout)
                guard !Task.isCancelled, let self else { return }
                await self.expireReady()
            }
        }
    }

    private func expireReady() {
        readyTimeoutTask = nil
        guard let ready = readyContinuation else { return }
        readyContinuation = nil
        ready.resume(throwing: PeerError.timeout)
    }

    private func removeSubscriber(_ id: UUID) {
        subscribers.removeValue(forKey: id)
    }

    private func handleStateUpdate(_ state: NWConnection.State) {
        switch state {
        case .ready:
            connectionReady = true
            readyTimeoutTask?.cancel()
            readyTimeoutTask = nil
            if let ready = readyContinuation {
                connectionReady = false
                ready.resume()
                readyContinuation = nil
            }
        case let .failed(error):
            connectionReady = false
            readyTimeoutTask?.cancel()
            readyTimeoutTask = nil
            if let ready = readyContinuation {
                ready.resume(throwing: PeerError.disconnected(error.localizedDescription))
                readyContinuation = nil
            }
            teardown(error: PeerError.disconnected(error.localizedDescription))
        case .cancelled:
            connectionReady = false
            readyTimeoutTask?.cancel()
            readyTimeoutTask = nil
            if let ready = readyContinuation {
                ready.resume(throwing: PeerError.disconnected("cancelled"))
                readyContinuation = nil
            }
            teardown(error: nil)
        default:
            break
        }
    }

    private func receiveLoop(_ connection: NWConnection) async {
        while !Task.isCancelled {
            do {
                let chunk: Data? = try await withCheckedThrowingContinuation { continuation in
                    connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 22) { data, _, isComplete, error in
                        if let error {
                            continuation.resume(throwing: PeerError.disconnected(error.localizedDescription))
                        } else if let data, !data.isEmpty {
                            continuation.resume(returning: data)
                        } else if isComplete {
                            continuation.resume(returning: nil)
                        } else {
                            continuation.resume(throwing: PeerError.disconnected("empty read"))
                        }
                    }
                }
                guard let chunk else { throw PeerError.disconnected("connection closed") }
                framer.append(chunk)
                while let (command, payload) = try framer.nextMessage() {
                    await handleInbound(command: command, payload: payload)
                }
            } catch {
                teardown(error: error)
                return
            }
        }
    }

    private func handleInbound(command: String, payload: Data) async {
        let message: PeerMessage
        do {
            message = try PeerMessage.decode(command: command, payload: payload)
        } catch {
            teardown(error: PeerError.protocolViolation("\(command): \(error)"))
            return
        }
        switch message {
        case let .ping(nonce):
            try? await send(.pong(nonce))
            return
        case let .feefilter(feeRate):
            feeFilter = feeRate
            // Also notify subscribers (TxBroadcaster reacts to fee-floor
            // changes); feefilter is never a request response, so no
            // waiter/collector/backlog handling applies.
            for subscriber in subscribers.values {
                subscriber.yield(.message(message))
            }
            return
        case .pong where !pending.contains(where: { $0.value.commands.contains("pong") }):
            return // keepalive pong with no waiter — drop
        default:
            break
        }
        if let (id, request) = pending.first(where: { $0.value.commands.contains(command) }) {
            pending.removeValue(forKey: id)
            timeoutTasks.removeValue(forKey: id)?.cancel()
            request.continuation.resume(returning: message)
            return
        }
        if let (id, collector) = collectors.first(where: { $0.value.command == command }) {
            var collector = collector
            collector.received.append(message)
            if collector.received.count >= collector.expected {
                collectors.removeValue(forKey: id)
                timeoutTasks.removeValue(forKey: id)?.cancel()
                collector.continuation.resume(returning: collector.received)
            } else {
                collectors[id] = collector
            }
            return
        }
        // No waiter yet: keep it for future waitFor/collect calls (the peer
        // owes us nothing about send/receive ordering) and notify subscribers.
        backlog.append(message)
        if backlog.count > Self.backlogLimit { backlog.removeFirst() }
        for subscriber in subscribers.values {
            subscriber.yield(.message(message))
        }
    }

    private func waitFor(matching commands: Set<String>, timeout: Duration) async throws -> PeerMessage {
        if let index = backlog.firstIndex(where: { commands.contains($0.command) }) {
            return backlog.remove(at: index)
        }
        let id = UUID()
        return try await withCheckedThrowingContinuation { continuation in
            pending[id] = PendingRequest(commands: commands, continuation: continuation)
            scheduleTimeout(for: id, timeout: timeout)
        }
    }

    private func scheduleTimeout(for id: UUID, timeout: Duration) {
        timeoutTasks[id] = Task { [weak self] in
            try? await Task.sleep(for: timeout)
            guard !Task.isCancelled, let self else { return }
            await self.expire(id)
        }
    }

    private func expire(_ id: UUID) {
        if let request = pending.removeValue(forKey: id) {
            request.continuation.resume(throwing: PeerError.timeout)
        }
        if let collector = collectors.removeValue(forKey: id) {
            collector.continuation.resume(throwing: PeerError.timeout)
        }
        timeoutTasks.removeValue(forKey: id)
    }

    private func startKeepalive() {
        pingTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(60))
                guard !Task.isCancelled, let self else { return }
                do {
                    try await self.send(.ping(UInt64.random(in: UInt64.min ... UInt64.max)))
                } catch {
                    await self.teardown(error: error)
                    return
                }
            }
        }
    }

    private func teardown(error: (any Error)?) {
        guard !didTeardown else { return }
        didTeardown = true
        isConnected = false
        pingTask?.cancel()
        receiveTask?.cancel()
        connection?.stateUpdateHandler = nil
        connection?.cancel()
        connection = nil
        readyTimeoutTask?.cancel()
        readyTimeoutTask = nil
        if let ready = readyContinuation {
            ready.resume(throwing: error ?? PeerError.disconnected("closed"))
            readyContinuation = nil
        }
        let failure: any Error = error ?? PeerError.disconnected("closed")
        for (_, request) in pending { request.continuation.resume(throwing: failure) }
        pending.removeAll()
        for (_, collector) in collectors { collector.continuation.resume(throwing: failure) }
        collectors.removeAll()
        timeoutTasks.values.forEach { $0.cancel() }
        timeoutTasks.removeAll()
        for (_, subscriber) in subscribers {
            subscriber.yield(.disconnected)
            if let error { subscriber.finish(throwing: error) } else { subscriber.finish() }
        }
        subscribers.removeAll()
    }
}
