import BitcoinCore
import Foundation
import Network
import Testing
@testable import BitcoinP2P

/// A loopback SOCKS5 proxy: accepts one CONNECT by name, records the name,
/// and either bridges bytes to a real loopback node or refuses with a reply
/// code. Enough of RFC 1928 to prove the client half.
actor FakeSocksProxy {
    private var listener: NWListener?
    private(set) var port: UInt16 = 0
    private(set) var requestedHost: String?
    private(set) var requestedPort: UInt16?
    private let upstreamPort: UInt16?
    private let refuseWith: UInt8?
    private var connections: [NWConnection] = []

    /// `upstreamPort` nil with `refuseWith` set answers every CONNECT with
    /// that reply code and closes.
    init(upstreamPort: UInt16?, refuseWith: UInt8? = nil) {
        self.upstreamPort = upstreamPort
        self.refuseWith = refuseWith
    }

    var endpoint: PeerEndpoint { PeerEndpoint(host: "127.0.0.1", port: port) }

    func start() async throws {
        let listener = try NWListener(using: .tcp, on: .any)
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

    func stop() {
        listener?.cancel()
        for connection in connections { connection.cancel() }
    }

    private func serve(_ client: NWConnection) async {
        connections.append(client)
        client.start(queue: DispatchQueue(label: "fake-socks-client"))
        do {
            let greeting = try await Self.read(client, exactly: 2)
            let methods = try await Self.read(client, exactly: Int(greeting[1]))
            _ = methods
            try await Self.write(client, Data([0x05, 0x00]))
            let head = try await Self.read(client, exactly: 4)
            guard head[0] == 0x05, head[1] == 0x01, head[3] == 0x03 else { client.cancel(); return }
            let length = try await Self.read(client, exactly: 1)
            let name = try await Self.read(client, exactly: Int(length[0]))
            let portBytes = try await Self.read(client, exactly: 2)
            requestedHost = String(decoding: name, as: UTF8.self)
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
            try await Self.write(client, Data([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
            Self.pump(from: client, to: upstream)
            Self.pump(from: upstream, to: client)
        } catch {
            client.cancel()
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

@Suite("SOCKS5 proxying", .timeLimit(.minutes(1)))
struct SocksProxyTests {
    @Test("a peer is dialled by name through the proxy and the handshake runs over the circuit")
    func connectsByName() async throws {
        let params = NetworkParams.signet
        let node = LoopbackNode(params: params)
        try await node.start()
        defer { Task { await node.stop() } }
        let proxy = FakeSocksProxy(upstreamPort: await node.endpoint.port)
        try await proxy.start()
        defer { Task { await proxy.stop() } }

        // A name no resolver could answer: only the proxy can take it.
        let peer = PeerConnection(endpoint: PeerEndpoint(host: "winnowtestpeer.onion", port: 8333),
                                  params: params, socksProxy: await proxy.endpoint)
        try await peer.connect(timeout: .seconds(10))
        #expect(await peer.isConnected)
        #expect(await peer.peerUserAgent.isEmpty == false, "the version exchange ran over the circuit")
        #expect(await proxy.requestedHost == "winnowtestpeer.onion", "the name went to the proxy unresolved")
        #expect(await proxy.requestedPort == 8333)
        #expect(await node.nextMessage(command: "verack", timeout: .seconds(5)) != nil)
        await peer.disconnect()
    }

    @Test("a proxy that cannot reach the peer reports a transport failure, not a protocol fault")
    func proxyRefusal() async throws {
        let params = NetworkParams.signet
        let proxy = FakeSocksProxy(upstreamPort: nil, refuseWith: 0x04) // host unreachable
        try await proxy.start()
        defer { Task { await proxy.stop() } }
        let peer = PeerConnection(endpoint: PeerEndpoint(host: "nowhere.onion", port: 8333),
                                  params: params, socksProxy: await proxy.endpoint)
        do {
            try await peer.connect(timeout: .seconds(10))
            Issue.record("the connection should have failed")
        } catch let error as PeerError {
            #expect(error.isTransport, "\(error)")
            #expect(error.localizedDescription.contains("host unreachable"))
        }
        #expect(await peer.isConnected == false)
    }

    @Test("without a proxy the dial is direct and unchanged")
    func directDialUnchanged() async throws {
        let params = NetworkParams.signet
        let node = LoopbackNode(params: params)
        try await node.start()
        defer { Task { await node.stop() } }
        let peer = PeerConnection(endpoint: await node.endpoint, params: params)
        try await peer.connect(timeout: .seconds(10))
        #expect(await peer.socksProxy == nil)
        #expect(await peer.isConnected)
        await peer.disconnect()
    }
}
