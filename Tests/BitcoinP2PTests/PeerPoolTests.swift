import Foundation
import Network
import Testing
@testable import BitcoinP2P

/// PeerPool dial rounds: candidates are raced in parallel with a short
/// per-attempt timeout, the pool fills across mixed accept/reject/timeout
/// candidates, and a round that runs out of candidates reports exhaustion
/// (with `retry()` recovering once a candidate becomes viable). All loopback
/// — no external network.
@Suite("Peer pool dialing")
struct PeerPoolTests {
    /// No DNS seeds, no fallback peers: the pool dials exactly the manual
    /// peers the test gives it.
    private let params = NetworkParams.customSignet(challenge: Data([0x51]))

    /// A shorter branch that shares only `best`'s genesis. It has valid
    /// trivial PoW but cannot replace the longer branch's accumulated work.
    private func weakerFork(of best: SyntheticChain, length: Int = 4) -> [Block] {
        var result = [best.blocks[0]]
        var previous = best.blocks[0].hash
        for height in 1 ... length {
            let transaction = best.blocks[height].transactions[0]
            let header = minedHeader(
                previousHash: previous,
                merkleRoot: Data(repeating: UInt8(0xA0 + height), count: 32),
                time: best.blocks[0].header.time + UInt32(height * 601))
            result.append(Block(header: header, transactions: [transaction]))
            previous = header.hash
        }
        return result
    }

    @Test("pool fills from mixed accept / reject / silent / refused candidates")
    func mixedCandidates() async throws {
        let goodA = LoopbackNode(params: params)
        let goodB = LoopbackNode(params: params)
        let nonFilter = LoopbackNode(params: params, services: 1) // handshake rejects
        let silent = SilentNode()
        try await goodA.start()
        try await goodB.start()
        try await nonFilter.start()
        try await silent.start()
        defer {
            Task { await goodA.stop() }
            Task { await goodB.stop() }
            Task { await nonFilter.stop() }
            Task { await silent.stop() }
        }
        let refused = PeerEndpoint(host: "127.0.0.1", port: 1) // nothing listens there

        let pool = PeerPool(params: params, peerCount: 2,
                            manualPeers: [refused, await silent.endpoint, await nonFilter.endpoint,
                                          await goodA.endpoint, await goodB.endpoint],
                            dialTimeout: .milliseconds(500))
        await pool.start()
        var endpoints: [PeerEndpoint] = []
        for peer in await pool.connectedPeers() { endpoints.append(await peer.endpoint) }
        #expect(endpoints.count == 2)
        #expect(endpoints.contains(await goodA.endpoint))
        #expect(endpoints.contains(await goodB.endpoint))
        let status = await pool.connectionStatus
        #expect(status.connected == 2)
        #expect(status.target == 2)
        #expect(status.attempts == 5)
        #expect(!status.exhausted)
        await pool.stop()
    }

    @Test("dialing past the target leaves exactly peerCount peers connected")
    func targetIsRespected() async throws {
        var nodes: [LoopbackNode] = []
        for _ in 0 ..< 4 {
            let node = LoopbackNode(params: params)
            try await node.start()
            nodes.append(node)
        }
        defer { for node in nodes { Task { await node.stop() } } }
        var endpoints: [PeerEndpoint] = []
        for node in nodes { endpoints.append(await node.endpoint) }

        let pool = PeerPool(params: params, peerCount: 2, manualPeers: endpoints,
                            dialTimeout: .milliseconds(500))
        await pool.start()
        #expect(await pool.connectedPeers().count == 2)
        await pool.stop()
        #expect(await pool.connectedPeers().isEmpty)
    }

    @Test("a round of silent candidates exhausts in ~one dial timeout, not five")
    func exhaustionIsParallel() async throws {
        var nodes: [SilentNode] = []
        var endpoints: [PeerEndpoint] = []
        for _ in 0 ..< 5 {
            let node = SilentNode()
            try await node.start()
            nodes.append(node)
            endpoints.append(await node.endpoint)
        }
        defer { for node in nodes { Task { await node.stop() } } }

        // Measure one silent candidate first, so the claim can be stated as a
        // ratio. An absolute bound is a claim about the machine as much as the
        // code: on a contended runner `elapsed < 2s` fails while the racing it
        // is meant to prove works perfectly (#144).
        let single = SilentNode()
        try await single.start()
        defer { Task { await single.stop() } }
        let onePool = PeerPool(params: params, peerCount: 1,
                               manualPeers: [await single.endpoint],
                               dialTimeout: .milliseconds(400))
        let oneStart = ContinuousClock.now
        await onePool.start()
        let oneRound = ContinuousClock.now - oneStart
        await onePool.stop()

        let pool = PeerPool(params: params, peerCount: 3, manualPeers: endpoints,
                            dialTimeout: .milliseconds(400))
        let start = ContinuousClock.now
        await pool.start()
        let elapsed = ContinuousClock.now - start
        // Serial dialing would cost five timeouts; racing costs about one. The
        // margin is generous because what is being refused is 5×, not 2×.
        #expect(elapsed < oneRound * 3,
                "five candidates took \(elapsed) against \(oneRound) for one — that looks serial, not raced")
        let status = await pool.connectionStatus
        #expect(status.connected == 0)
        #expect(status.exhausted)
        #expect(status.attempts == 5)
        await pool.stop()
    }

    @Test("total dial effort is capped per round")
    func dialAttemptsCapped() async throws {
        var nodes: [SilentNode] = []
        var endpoints: [PeerEndpoint] = []
        for _ in 0 ..< 5 {
            let node = SilentNode()
            try await node.start()
            nodes.append(node)
            endpoints.append(await node.endpoint)
        }
        defer { for node in nodes { Task { await node.stop() } } }

        let pool = PeerPool(params: params, peerCount: 3, manualPeers: endpoints,
                            dialTimeout: .milliseconds(300), maxDialAttempts: 3)
        await pool.start()
        let status = await pool.connectionStatus
        #expect(status.attempts == 3)
        #expect(status.exhausted)
        await pool.stop()
    }

    @Test("exhaustion then retry once a candidate is viable fills the pool")
    func retryAfterExhaustion() async throws {
        // Grab a free port, then close it: the pool's first round is refused.
        let reserved = LoopbackNode(params: params)
        try await reserved.start()
        let port = await reserved.port
        await reserved.stop()

        let endpoint = PeerEndpoint(host: "127.0.0.1", port: port)
        let pool = PeerPool(params: params, peerCount: 1, manualPeers: [endpoint],
                            dialTimeout: .milliseconds(400))
        await pool.start()
        var status = await pool.connectionStatus
        #expect(status.connected == 0)
        #expect(status.exhausted)

        // The same endpoint now serves: retry connects without a restart.
        let node = LoopbackNode(params: params, listenPort: port)
        try await node.start()
        defer { Task { await node.stop() } }
        await pool.retry()
        status = await pool.connectionStatus
        #expect(status.connected == 1)
        #expect(!status.exhausted)
        await pool.stop()
    }

    @Test("header sync rejects a stale peer and continues with a healthy fallback")
    func headerSyncFailover() async throws {
        let best = makeSyntheticChain(length: 8, watchHeight: 3)
        let stale = weakerFork(of: best)
        let staleNode = LoopbackNode(params: best.params, chain: stale)
        let goodNode = LoopbackNode(params: best.params, chain: best.blocks,
                                    versionDelay: .milliseconds(200))
        try await staleNode.start()
        try await goodNode.start()
        defer {
            Task { await staleNode.stop() }
            Task { await goodNode.stop() }
        }

        let chain = try HeaderChain(params: best.params)
        try await chain.connect(Array(best.blocks.dropFirst().map(\.header)))
        let pool = PeerPool(params: best.params, peerCount: 1,
                            manualPeers: [await staleNode.endpoint, await goodNode.endpoint],
                            dialTimeout: .seconds(1))
        await pool.start()
        try await pool.syncHeaders(chain, timeoutPerPeer: .seconds(1), maxAttempts: 2)

        #expect(await chain.height == 8)
        var endpoints: [PeerEndpoint] = []
        for peer in await pool.connectedPeers() { endpoints.append(await peer.endpoint) }
        #expect(endpoints == [await goodNode.endpoint])
        await pool.stop()
    }

    @Test("header sync reports exhaustion after every candidate fails")
    func headerSyncExhaustion() async throws {
        let best = makeSyntheticChain(length: 8, watchHeight: 3)
        let staleNode = LoopbackNode(params: best.params, chain: weakerFork(of: best))
        try await staleNode.start()
        defer { Task { await staleNode.stop() } }

        let chain = try HeaderChain(params: best.params)
        try await chain.connect(Array(best.blocks.dropFirst().map(\.header)))
        let pool = PeerPool(params: best.params, peerCount: 1,
                            manualPeers: [await staleNode.endpoint],
                            dialTimeout: .seconds(1))
        await pool.start()
        var caught: PeerPoolHeaderSyncError?
        do {
            try await pool.syncHeaders(chain, timeoutPerPeer: .seconds(1), maxAttempts: 1)
        } catch let error as PeerPoolHeaderSyncError {
            caught = error
        }
        #expect(caught?.localizedDescription.contains(
            "Winnow tried 1 Bitcoin peer, but none supplied a usable block-header chain") == true)
        #expect(caught?.localizedDescription.contains("older or weaker Bitcoin chain") == true)
        await pool.stop()
    }

    @Test("local header storage damage is not retried against another peer")
    func localStorageFailureIsNotRetried() async throws {
        let best = makeSyntheticChain(length: 4, watchHeight: 2)
        let first = LoopbackNode(params: best.params, chain: best.blocks)
        let second = LoopbackNode(params: best.params, chain: best.blocks,
                                  versionDelay: .milliseconds(200))
        try await first.start()
        try await second.start()
        defer {
            Task { await first.stop() }
            Task { await second.stop() }
        }

        let directory = FileManager.default.temporaryDirectory
            .appending(path: "header-storage-failure-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let storage = directory.appending(path: "headers.bin")
        let chain = try HeaderChain(params: best.params, storageURL: storage)
        // Replacing the not-yet-created file with a directory makes the
        // first atomic persistence fail after valid headers arrive.
        try FileManager.default.createDirectory(at: storage, withIntermediateDirectories: false)

        let pool = PeerPool(params: best.params, peerCount: 1,
                            manualPeers: [await first.endpoint, await second.endpoint],
                            dialTimeout: .seconds(1))
        await pool.start()
        var caught: HeaderChainError?
        do {
            try await pool.syncHeaders(chain, timeoutPerPeer: .seconds(1), maxAttempts: 2)
        } catch let error as HeaderChainError {
            caught = error
        }
        #expect({
            if case .storageUnavailable? = caught { return true }
            return false
        }())
        #expect(await pool.connectedPeers().count == 1)
        await pool.stop()
    }
}

/// A listener that accepts connections and never speaks — exercises the
/// pool's per-attempt dial timeout.
private actor SilentNode {
    private var listener: NWListener?
    private var held: [NWConnection] = []
    private(set) var port: UInt16 = 0

    var endpoint: PeerEndpoint { PeerEndpoint(host: "127.0.0.1", port: port) }

    func start() async throws {
        let listener = try NWListener(using: .tcp, on: .any)
        self.listener = listener
        listener.newConnectionHandler = { connection in
            connection.start(queue: DispatchQueue(label: "org.winnow.tests.silent.conn"))
            Task { await self.hold(connection) }
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let resumeOnce = ResumeOnce(continuation)
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    listener.stateUpdateHandler = nil
                    Task { await self.capturePortAndResume(resumeOnce) }
                case let .failed(error):
                    listener.stateUpdateHandler = nil
                    resumeOnce.resume(throwing: error)
                default:
                    break
                }
            }
            listener.start(queue: DispatchQueue(label: "org.winnow.tests.silent"))
        }
    }

    func stop() {
        for connection in held { connection.cancel() }
        listener?.cancel()
    }

    private func hold(_ connection: NWConnection) {
        held.append(connection)
    }

    private func capturePortAndResume(_ resumeOnce: ResumeOnce) {
        port = listener?.port?.rawValue ?? 0
        resumeOnce.resume()
    }
}
