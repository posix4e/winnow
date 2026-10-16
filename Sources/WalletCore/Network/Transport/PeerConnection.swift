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
    /// Payload bytes of unsolicited gossip this connection buffers before it
    /// drops the oldest. A client with less memory to spend than the default
    /// assumes may lower it; below `MessageFramer.maxPayloadSize` it also
    /// starts refusing single messages the protocol allows.
    public let backlogByteLimit: Int

    public private(set) var peerServices: UInt64 = 0
    public private(set) var peerUserAgent = ""
    public private(set) var peerStartHeight: Int32 = 0
    /// Latest BIP133 feefilter (sat/kvB) the peer sent us.
    public private(set) var feeFilter: Int64?
    public private(set) var isConnected = false

    /// Optional external SOCKS5 gateway. The destination name is resolved by
    /// the proxy; nil preserves direct TCP. No router is started by WalletCore.
    public let socksProxy: PeerEndpoint?
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
        let maxTotalBytes: Int?
        var received: [PeerMessage]
        var receivedBytes: Int
        let continuation: CheckedContinuation<[PeerMessage], Error>
    }

    private var pending: [UUID: PendingRequest] = [:]
    private var collectors: [UUID: PendingCollector] = [:]
    private var timeoutTasks: [UUID: Task<Void, Never>] = [:]
    private var subscribers: [UUID: AsyncThrowingStream<PeerEvent, Error>.Continuation] = [:]

    /// One unsolicited message and the payload size it arrived with. The size
    /// travels with the message because `PeerMessage.payload` re-serializes
    /// every time it is read, and the bounds below are counted on every frame.
    private struct BacklogEntry {
        let message: PeerMessage
        let bytes: Int
    }

    /// Messages that arrived with no waiter/collector registered (e.g. a
    /// verack sent before we started waiting for it). Bounded in messages and
    /// in bytes; oldest dropped past either.
    private var backlog: [BacklogEntry] = []
    /// Payload bytes the backlog holds, kept in step by every path that adds
    /// or removes an entry.
    private var backlogBytes = 0
    static let backlogLimit = 256

    /// How many payload bytes of unsolicited gossip a connection buffers by
    /// default before it drops the oldest.
    ///
    /// The message cap bounds messages, not memory, and one message is
    /// whatever the framer accepts: 256 of `MessageFramer.maxPayloadSize` is
    /// a gigabyte held per peer, times the pool's seats, for gossip nobody
    /// asked for, on a connection that stays up. The ceiling is derived from
    /// the largest unsolicited messages a wallet legitimately keeps. An `inv`
    /// carries at most 50,000 vectors of 36 bytes (`InventoryPayload`'s own
    /// limit, Core's MAX_INV_SZ), so about 1.8 MB; a `headers` batch is 2,000
    /// headers of 81 bytes, so about 162 KB. Eight megabytes holds four
    /// maximal invs, which is every honest burst several times over, and
    /// leaves a hostile peer under one percent of what it could hold before.
    public static let defaultBacklogByteLimit = 8_000_000
    /// A relayed transaction past the standard 400,000 weight units cannot
    /// have come from an honest mempool; it is dropped before it is decoded.
    public static let maximumRelayedTransactionBytes = 400_000

    /// How often the keepalive pings, and how long the peer may stay silent
    /// before the connection is judged dead. A live peer answers every ping,
    /// so the deadline is a small multiple of the interval.
    public let pingInterval: Duration
    public let readIdleTimeout: Duration
    private var lastReceivedAt = ContinuousClock.now

    public init(endpoint: PeerEndpoint, params: NetworkParams,
                localServices: UInt64 = 0, localStartHeight: Int32 = 0,
                relayPreference: Bool = false,
                socksProxy: PeerEndpoint? = nil,
                backlogByteLimit: Int = PeerConnection.defaultBacklogByteLimit,
                pingInterval: Duration = .seconds(60), readIdleTimeout: Duration = .seconds(150)) {
        precondition(backlogByteLimit > 0, "the gossip buffer needs a positive ceiling")
        self.backlogByteLimit = backlogByteLimit
        self.endpoint = endpoint
        self.params = params
        self.localServices = localServices
        self.localStartHeight = localStartHeight
        self.relayPreference = relayPreference
        self.socksProxy = socksProxy
        self.pingInterval = pingInterval
        self.readIdleTimeout = readIdleTimeout
        framer = MessageFramer(magic: params.magic)
    }

    // MARK: - Connect / handshake

    /// TCP connect + version handshake. Throws `missingCompactFilters` when
    /// the peer cannot serve BIP157 filters.
    private var permanentlyClosed = false

    public func connect(timeout: Duration = .seconds(20)) async throws {
        try Task.checkCancellation()
        try await withTaskCancellationHandler {
            try await connectOnce(timeout: timeout)
        } onCancel: {
            Task { await self.disconnect() }
        }
    }

    private func connectOnce(timeout: Duration) async throws {
        try Task.checkCancellation()
        guard !permanentlyClosed else { throw PeerError.notConnected }
        guard connection == nil else { return }
        let dial = socksProxy ?? endpoint
        guard let port = NWEndpoint.Port(rawValue: dial.port) else {
            throw PeerError.handshakeFailed("invalid port \(dial.port)")
        }
        let connection = NWConnection(host: NWEndpoint.Host(dial.host),
                                      port: port,
                                      using: .tcp)
        self.connection = connection
        connection.stateUpdateHandler = { state in
            Task { await self.handleStateUpdate(state) }
        }
        connection.start(queue: DispatchQueue(label: "org.winnow.peer.\(endpoint.description)"))
        do {
            try await waitForReady(timeout: timeout)
            if socksProxy != nil {
                try await Self.negotiateSOCKS5(connection, to: endpoint, timeout: timeout)
            }
            try Task.checkCancellation()
        } catch {
            teardown(error: error)
            throw error
        }

        receiveTask = Task { await self.receiveLoop(connection) }

        try await exchangeVersion(timeout: timeout)
    }

    private func exchangeVersion(timeout: Duration) async throws {
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
            peerServices = theirVersion.services
            peerUserAgent = theirVersion.userAgent
            peerStartHeight = theirVersion.startHeight
            guard theirVersion.services & Self.nodeCompactFilters != 0 else {
                throw PeerError.missingCompactFilters(services: theirVersion.services)
            }
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
        permanentlyClosed = true
        teardown(error: nil)
    }

    // MARK: - SOCKS5 (RFC 1928)

    /// Asks the proxy for a TCP circuit to `destination` by name. Runs before
    /// the Bitcoin framer sees a byte: everything here is the proxy talking,
    /// and the peer's first `version` arrives only after the reply.
    ///
    /// The timeout cancels the connection rather than racing a task group:
    /// a proxy that never answers would otherwise pin a cancelled child, the
    /// same trap `waitForReady` documents.
    private static func negotiateSOCKS5(_ connection: NWConnection, to destination: PeerEndpoint,
                                        timeout: Duration) async throws {
        let timedOut = TimeoutFlag()
        let timer = Task {
            try? await Task.sleep(for: timeout)
            guard !Task.isCancelled else { return }
            timedOut.set()
            connection.cancel()
        }
        defer { timer.cancel() }
        do {
            // Greeting: version 5, one method, no authentication.
            try await rawSend(connection, Data([0x05, 0x01, 0x00]))
            let chosen = try await rawReceive(connection, exactly: 2)
            guard chosen == Data([0x05, 0x00]) else {
                throw PeerError.handshakeFailed("SOCKS5 proxy refused an unauthenticated connection")
            }
            // CONNECT, address type 3: the name goes through unresolved.
            let name = Data(destination.host.utf8)
            guard !name.isEmpty, name.count <= 255 else {
                throw PeerError.handshakeFailed("SOCKS5 destination name too long")
            }
            var request = Data([0x05, 0x01, 0x00, 0x03, UInt8(name.count)])
            request.append(name)
            request.append(UInt8(destination.port >> 8))
            request.append(UInt8(destination.port & 0xFF))
            try await rawSend(connection, request)
            // Reply: VER REP RSV ATYP BND.ADDR BND.PORT.
            let head = try await rawReceive(connection, exactly: 4)
            guard head[head.startIndex] == 0x05, head[head.startIndex + 2] == 0 else {
                throw PeerError.handshakeFailed("SOCKS5 proxy returned an invalid reply header")
            }
            let reply = head[head.startIndex + 1]
            guard reply == 0x00 else {
                // The proxy could not reach the peer. That is the peer being
                // unreachable, not a protocol fault, so it is a transport error.
                throw PeerError.disconnected("SOCKS5 proxy: \(socksReplyDescription(reply))")
            }
            switch head[head.startIndex + 3] {
            case 0x01: _ = try await rawReceive(connection, exactly: 4 + 2)
            case 0x04: _ = try await rawReceive(connection, exactly: 16 + 2)
            case 0x03:
                let length = try await rawReceive(connection, exactly: 1)
                _ = try await rawReceive(connection, exactly: Int(length[length.startIndex]) + 2)
            default:
                throw PeerError.handshakeFailed("SOCKS5 proxy answered with an unknown address type")
            }
        } catch {
            if timedOut.isSet { throw PeerError.timeout }
            throw error
        }
    }

    private static func socksReplyDescription(_ code: UInt8) -> String {
        switch code {
        case 0x01: "general failure"
        case 0x02: "connection not allowed by ruleset"
        case 0x03: "network unreachable"
        case 0x04: "host unreachable"
        case 0x05: "connection refused"
        case 0x06: "TTL expired"
        case 0x07: "command not supported"
        case 0x08: "address type not supported"
        default: "reply code \(code)"
        }
    }

    private static func rawSend(_ connection: NWConnection, _ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: PeerError.disconnected(error.localizedDescription))
                } else {
                    continuation.resume()
                }
            })
        }
    }

    /// Reads exactly `count` bytes, or throws if the stream ends first.
    private static func rawReceive(_ connection: NWConnection, exactly count: Int) async throws -> Data {
        var collected = Data()
        while collected.count < count {
            let remaining = count - collected.count
            let chunk: Data = try await withCheckedThrowingContinuation { continuation in
                connection.receive(minimumIncompleteLength: 1, maximumLength: remaining) { data, _, isComplete, error in
                    if let error {
                        continuation.resume(throwing: PeerError.disconnected(error.localizedDescription))
                    } else if let data, !data.isEmpty {
                        continuation.resume(returning: data)
                    } else if isComplete {
                        continuation.resume(throwing: PeerError.disconnected("proxy closed the connection"))
                    } else {
                        continuation.resume(throwing: PeerError.disconnected("empty read from proxy"))
                    }
                }
            }
            collected.append(chunk)
        }
        return collected
    }

    /// A flag the SOCKS timeout task sets so the caller can tell a timeout
    /// from the cancellation error it produces.
    private final class TimeoutFlag: @unchecked Sendable {
        private let lock = NSLock()
        private var value = false
        func set() { lock.withLock { value = true } }
        var isSet: Bool { lock.withLock { value } }
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
        // A reply can only follow its request. Whatever the backlog holds
        // under the expected command arrived before this request was sent —
        // an announcement, or a reply to an earlier request that was already
        // satisfied from the backlog — and must not be handed back as the
        // answer to this one. (An announcement dropped here is not lost: the
        // reply covers the same headers.)
        purgeBacklog { commands.contains($0.command) }
        async let response = waitFor(matching: commands, timeout: timeout)
        try await send(message)
        return try await response
    }

    /// Sends a request and collects `count` responses of one command
    /// (e.g. the `cfilter` burst answering `getcfilters`).
    public func requestMany(_ message: PeerMessage, expecting command: String, count: Int,
                            maxTotalBytes: Int? = nil, timeout: Duration = .seconds(60)) async throws -> [PeerMessage] {
        precondition(count > 0)
        // Same rule as `request`: a burst that timed out mid-delivery leaves
        // its trailing messages in the backlog, and they are not the answer
        // to the burst asked for now.
        purgeBacklog { $0.command == command }
        let id = UUID()
        scheduleTimeout(for: id, timeout: timeout)
        do {
            async let collected = collect(id: id, command: command, count: count, maxTotalBytes: maxTotalBytes)
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
    private func collect(id: UUID, command: String, count: Int,
                         maxTotalBytes: Int?) async throws -> [PeerMessage] {
        try Task.checkCancellation()
        guard connection != nil, !didTeardown else { throw PeerError.notConnected }
        var received: [PeerMessage] = []
        var receivedBytes = 0
        while received.count < count,
              let index = backlog.firstIndex(where: { $0.message.command == command }) {
            let entry = takeFromBacklog(at: index)
            receivedBytes += entry.bytes
            received.append(entry.message)
        }
        if let limit = maxTotalBytes, receivedBytes > limit {
            let error = Self.burstTooLarge(command: command, bytes: receivedBytes, limit: limit)
            teardown(error: error)
            throw error
        }
        guard received.count < count else { return received }
        return try await withCheckedThrowingContinuation { continuation in
            collectors[id] = PendingCollector(command: command, expected: count,
                                              maxTotalBytes: maxTotalBytes, received: received,
                                              receivedBytes: receivedBytes, continuation: continuation)
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
        // The stream has a count-based API. Budget each slot at the largest
        // accepted payload so a stalled subscriber cannot bypass the backlog's
        // byte ceiling. This bounds wire payload retention, not decoded RSS.
        let largestPayload = min(backlogByteLimit, MessageFramer.maxPayloadSize)
        let slots = min(Self.backlogLimit, max(1, backlogByteLimit / largestPayload))
        return AsyncThrowingStream(bufferingPolicy: .bufferingNewest(slots)) { continuation in
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
                lastReceivedAt = .now
                framer.append(chunk)
                // A handler may tear the connection down (an oversized
                // unsolicited message does); the rest of the chunk is then
                // not read.
                while !didTeardown, let (command, payload) = try framer.nextMessage() {
                    await handleInbound(command: command, payload: payload)
                }
                // Once per chunk, not per message: release what the drain
                // loop consumed, or the buffer keeps every byte ever received.
                framer.compact()
            } catch {
                teardown(error: error)
                return
            }
        }
    }

    /// Decodes one frame, or returns nil when the frame was dropped or the
    /// connection torn down for a protocol violation.
    private func decodeInbound(command: String, payload: Data) -> PeerMessage? {
        // Nothing this client does can solicit a transaction this large,
        // and decoding it would hand a hostile peer the allocation for free.
        if command == "tx", payload.count > Self.maximumRelayedTransactionBytes { return nil }
        do {
            return try PeerMessage.decode(command: command, payload: payload)
        } catch {
            teardown(error: PeerError.protocolViolation("\(command): \(error)"))
            return nil
        }
    }

    private func handleInbound(command: String, payload: Data) async {
        guard let message = decodeInbound(command: command, payload: payload) else { return }
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
        if deliverToCollector(message, bytes: payload.count) { return }
        // No waiter yet: keep it for future waitFor/collect calls (the peer
        // owes us nothing about send/receive ordering) and notify subscribers.
        buffer(message, bytes: payload.count)
    }

    private static func burstTooLarge(command: String, bytes: Int, limit: Int) -> PeerError {
        .protocolViolation("\(command) burst of \(bytes) bytes exceeds the \(limit)-byte bound")
    }

    private func deliverToCollector(_ message: PeerMessage, bytes: Int) -> Bool {
        guard let (id, value) = collectors.first(where: { $0.value.command == message.command }) else { return false }
        var collector = value
        collector.receivedBytes += bytes
        if let limit = collector.maxTotalBytes, collector.receivedBytes > limit {
            collectors.removeValue(forKey: id)
            timeoutTasks.removeValue(forKey: id)?.cancel()
            let error = Self.burstTooLarge(command: message.command, bytes: collector.receivedBytes, limit: limit)
            collector.continuation.resume(throwing: error)
            teardown(error: error)
            return true
        }
        collector.received.append(message)
        if collector.received.count >= collector.expected {
            collectors.removeValue(forKey: id)
            timeoutTasks.removeValue(forKey: id)?.cancel()
            collector.continuation.resume(returning: collector.received)
        } else {
            collectors[id] = collector
        }
        return true
    }

    /// Buffers an unsolicited message for a later `waitFor`/`collect` and
    /// hands it to the event subscribers — unless nothing this client sends
    /// could have solicited it and nothing consumes it (a block, an addr), in
    /// which case holding it only serves the peer that sent it. An unknown
    /// command is kept as ordinary gossip, inside the byte limit like the
    /// rest.
    ///
    /// Past either bound the oldest gossip goes. That is the recorded choice
    /// for a flood: a peer that announces faster than a subscriber drains
    /// loses its stale announcements, not its connection, because an honest
    /// peer on a busy network does exactly that. The one thing it may not do
    /// is arrive with a single message larger than the whole buffer. Keeping
    /// that one would evict every other entry to make room for something
    /// nobody asked for, so a peer could empty the buffer at will, and no
    /// honest gossip is that large — that is the peer being unusable, and it
    /// is torn down as a protocol violation.
    private func buffer(_ message: PeerMessage, bytes: Int) {
        guard bytes <= backlogByteLimit else {
            teardown(error: Self.unsolicitedTooLarge(command: message.command, bytes: bytes,
                                                     limit: backlogByteLimit))
            return
        }
        switch message {
        case .block, .addr: return
        default: break
        }
        backlog.append(BacklogEntry(message: message, bytes: bytes))
        backlogBytes += bytes
        while backlog.count > Self.backlogLimit || backlogBytes > backlogByteLimit {
            backlogBytes -= backlog.removeFirst().bytes
        }
        for subscriber in subscribers.values {
            subscriber.yield(.message(message))
        }
    }

    /// The refusal one oversized unsolicited message produces. A protocol
    /// violation rather than a transport failure: what the peer sent is not
    /// something an honest one has to say, so the fault is the peer's and
    /// not the link's — the distinction `isTransport` draws.
    private static func unsolicitedTooLarge(command: String, bytes: Int, limit: Int) -> PeerError {
        .protocolViolation("unsolicited \(command) of \(bytes) bytes exceeds the \(limit)-byte buffer")
    }

    /// Removes one backlog entry and keeps the byte total in step.
    private func takeFromBacklog(at index: Int) -> BacklogEntry {
        let entry = backlog.remove(at: index)
        backlogBytes -= entry.bytes
        return entry
    }

    /// Drops every backlog entry the predicate matches, keeping the byte
    /// total in step. Nothing removes an entry except this and
    /// `takeFromBacklog`: a total that drifts above the truth shrinks the
    /// buffer for no reason, and one that drifts below it bounds nothing.
    private func purgeBacklog(where predicate: (PeerMessage) -> Bool) {
        backlog.removeAll { entry in
            guard predicate(entry.message) else { return false }
            backlogBytes -= entry.bytes
            return true
        }
    }

    /// What the gossip buffer holds right now: messages, and the payload
    /// bytes they arrived with. For tests and diagnostics, like
    /// `MessageFramer.bufferedCount`.
    var backlogSize: (messages: Int, bytes: Int) { (backlog.count, backlogBytes) }

    private func waitFor(matching commands: Set<String>, timeout: Duration) async throws -> PeerMessage {
        // Sending can fail and tear down the connection before an async-let
        // waiter gets its actor turn. Teardown has already drained waiters;
        // registering another here would sleep until the response deadline.
        try Task.checkCancellation()
        guard connection != nil, !didTeardown else { throw PeerError.notConnected }
        if let index = backlog.firstIndex(where: { commands.contains($0.message.command) }) {
            return takeFromBacklog(at: index).message
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
                guard let interval = self?.pingInterval else { return }
                try? await Task.sleep(for: interval)
                guard !Task.isCancelled, let self else { return }
                do {
                    try await self.requireRecentBytes()
                    try await self.send(.ping(UInt64.random(in: UInt64.min ... UInt64.max)))
                } catch {
                    await self.teardown(error: error)
                    return
                }
            }
        }
    }

    /// A peer that has sent nothing — not even the pong to our last ping —
    /// for longer than `readIdleTimeout` is gone, whatever the socket says.
    /// Without this a silent or trickling peer kept its seat until the next
    /// request against it timed out.
    private func requireRecentBytes() throws {
        let silence = ContinuousClock.now - lastReceivedAt
        guard silence <= readIdleTimeout else {
            throw PeerError.disconnected("no bytes received for \(silence)")
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
        backlog.removeAll()
        backlogBytes = 0
        timeoutTasks.values.forEach { $0.cancel() }
        timeoutTasks.removeAll()
        for (_, subscriber) in subscribers {
            subscriber.yield(.disconnected)
            if let error { subscriber.finish(throwing: error) } else { subscriber.finish() }
        }
        subscribers.removeAll()
    }
}
