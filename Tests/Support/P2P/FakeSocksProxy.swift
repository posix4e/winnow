import WalletCore
import Foundation
import Network

/// A loopback SOCKS5 proxy: accepts one CONNECT by name, records the name,
/// and either bridges bytes to a real loopback node or refuses with a reply
/// code. Enough of RFC 1928 to prove the client half.
public actor FakeSocksProxy {
    private var listener: NWListener?
    public private(set) var port: UInt16 = 0
    public private(set) var requestedHost: String?
    public private(set) var requestedPort: UInt16?
    public private(set) var requestedHosts: [String] = []
    private let upstreamPort: UInt16?
    private let refuseWith: UInt8?
    private var connections: [NWConnection] = []

    /// `upstreamPort` nil with `refuseWith` set answers every CONNECT with
    /// that reply code and closes. `listenPort` 0 takes any free port; the
    /// tailnet simulation fixes it so its gateway nodes can forward to it.
    public init(upstreamPort: UInt16?, refuseWith: UInt8? = nil, stall: Bool = false, reserved: UInt8 = 0,
                listenPort: UInt16 = 0) {
        self.upstreamPort = upstreamPort
        self.refuseWith = refuseWith
        self.stall = stall
        self.reserved = reserved
        self.listenPort = listenPort
    }
    private let stall: Bool
    private let reserved: UInt8
    private let listenPort: UInt16

    public var endpoint: PeerEndpoint { PeerEndpoint(host: "127.0.0.1", port: port) }

    public func start() async throws {
        let listener = try NWListener(using: .tcp, on: NWEndpoint.Port(rawValue: listenPort) ?? .any)
        self.listener = listener
        listener.newConnectionHandler = { connection in
            Task { await self.serve(connection) }
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let once = ResumeOnce(continuation)
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    Task { await self.capturePort(); once.resume() }
                case let .failed(error): once.resume(throwing: error)
                default: break
                }
            }
            listener.start(queue: DispatchQueue(label: "fake-socks"))
        }
    }

    private func capturePort() { port = listener?.port?.rawValue ?? 0 }

    public func stop() {
        listener?.cancel()
        for connection in connections { connection.cancel() }
    }

    private func serve(_ client: NWConnection) async {
        connections.append(client)
        client.start(queue: DispatchQueue(label: "fake-socks-client"))
        do {
            if stall { return }
            let greeting = try await Self.read(client, exactly: 2)
            let methods = try await Self.read(client, exactly: Int(greeting[1]))
            _ = methods
            try await Self.write(client, Data([0x05, 0x00]))
            let head = try await Self.read(client, exactly: 4)
            guard head[0] == 0x05, head[1] == 0x01 else { client.cancel(); return }
            let name = try await Self.readHost(client, type: head[3])
            let portBytes = try await Self.read(client, exactly: 2)
            requestedHost = name
            requestedHosts.append(name)
            requestedPort = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])
            if let refuseWith {
                try await Self.write(client, Data([0x05, refuseWith, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
                client.cancel()
                return
            }
            guard let upstreamPort, let port = NWEndpoint.Port(rawValue: upstreamPort) else { client.cancel(); return }
            let upstream = NWConnection(host: "127.0.0.1", port: port, using: .tcp)
            connections.append(upstream)
            upstream.start(queue: DispatchQueue(label: "fake-socks-upstream"))
            try await Self.write(client, Data([0x05, 0x00, reserved, 0x01, 0, 0, 0, 0, 0, 0]))
            Self.pump(from: client, to: upstream)
            Self.pump(from: upstream, to: client)
        } catch {
            client.cancel()
        }
    }

    private static func readHost(_ client: NWConnection, type: UInt8) async throws -> String {
        switch type {
        case 1:
            return try await read(client, exactly: 4).map(String.init).joined(separator: ".")
        case 3:
            let length = try await read(client, exactly: 1)
            return String(decoding: try await read(client, exactly: Int(length[0])), as: UTF8.self)
        case 4:
            let bytes = try await read(client, exactly: 16)
            guard let address = IPv6Address(bytes) else { throw NWError.posix(.EINVAL) }
            return address.debugDescription
        default: throw NWError.posix(.EINVAL)
        }
    }

    private static func pump(from source: NWConnection, to sink: NWConnection) {
        source.receive(minimumIncompleteLength: 1, maximumLength: 1 << 16) { data, _, isComplete, error in
            if let data, !data.isEmpty {
                sink.send(content: data, completion: .contentProcessed { _ in })
            }
            if error != nil || isComplete {
                sink.cancel()
                return
            }
            pump(from: source, to: sink)
        }
    }

    private static func read(_ connection: NWConnection, exactly count: Int) async throws -> Data {
        var collected = Data()
        while collected.count < count {
            let chunk: Data = try await withCheckedThrowingContinuation { continuation in
                connection.receive(minimumIncompleteLength: 1, maximumLength: count - collected.count) { data, _, isComplete, error in
                    if let error { continuation.resume(throwing: error) }
                    else if let data, !data.isEmpty { continuation.resume(returning: data) }
                    else { continuation.resume(throwing: NWError.posix(.ECONNRESET)) }
                    _ = isComplete
                }
            }
            collected.append(chunk)
        }
        return collected
    }

    private static func write(_ connection: NWConnection, _ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            })
        }
    }
}
