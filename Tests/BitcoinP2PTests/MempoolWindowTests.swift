import Foundation
import Testing
@testable import BitcoinP2P

/// MempoolWindow against loopback nodes (docs/read-side.md §2.8): the relay
/// bit at connect time, inv dedupe across peers, watched-script matching,
/// broadcast echo detection, bounded buffers and teardown.
@Suite("MempoolWindow")
struct MempoolWindowTests {
    /// P2TR-shaped watched script (also the output of makeFakeSegwitTx()).
    static let watchedScript = Data([0x51, 0x20] + repeatElement(0x77, count: 32))
    static let otherScript = Data([0x51, 0x20] + repeatElement(0x99, count: 32))

    /// A segwit fixture tx with unique txid (seed feeds the input outpoint).
    private func makeTx(seed: UInt8, outputs: [(Int64, Data)]) -> Transaction {
        var input = Transaction.Input(
            previousOutput: Transaction.Outpoint(txid: Data(repeating: seed, count: 32), vout: 0),
            scriptSig: Data(), sequence: 0xFFFF_FFFD)
        input.witness = [Data([0x30, 0x44, 0x02, 0x20]), Data(repeating: 0x02, count: 33)]
        return Transaction(version: 2, inputs: [input],
                           outputs: outputs.map { Transaction.Output(value: $0.0, scriptPubKey: $0.1) },
                           locktime: 0)
    }

    /// Two tx-paying variants used across tests.
    private func watchedTx(seed: UInt8) -> Transaction {
        makeTx(seed: seed, outputs: [(50_000, Self.watchedScript)])
    }

    private func unrelatedTx(seed: UInt8) -> Transaction {
        makeTx(seed: seed, outputs: [(75_000, Self.otherScript)])
    }

    @Test("the relay bit is a connect-time parameter")
    func relayBitIsAConnectTimeParameter() async throws {
        let params = NetworkParams.signet
        let plainNode = LoopbackNode(params: params)
        let relayNode = LoopbackNode(params: params)
        try await plainNode.start()
        try await relayNode.start()
        defer {
            Task { await plainNode.stop() }
            Task { await relayNode.stop() }
        }

        let plainPool = PeerPool(params: params, peerCount: 1,
                                 manualPeers: [await plainNode.endpoint])
        await plainPool.start()
        #expect(await plainNode.clientRelay == false)
        await plainPool.stop()

        let relayPool = PeerPool(params: params, peerCount: 1,
                                 manualPeers: [await relayNode.endpoint],
                                 relayPreference: true)
        await relayPool.start()
        #expect(await relayNode.clientRelay == true)
        await relayPool.stop()
    }

    @Test("fetches announced txs once, sums watched outputs, ignores the rest")
    func paymentMatchingAndDedupe() async throws {
        let params = NetworkParams.signet
        let watched1 = watchedTx(seed: 0x21)
        // Two outputs pay the watched script (sum), one pays elsewhere.
        let watched2 = makeTx(seed: 0x22, outputs: [(12_000, Self.watchedScript),
                                                    (8_000, Self.watchedScript),
                                                    (5_000, Self.otherScript)])
        let unrelated = unrelatedTx(seed: 0x23)
        let mempool = [watched1, watched2, unrelated]

        let nodeA = LoopbackNode(params: params, transactions: mempool)
        let nodeB = LoopbackNode(params: params, transactions: mempool)
        try await nodeA.start()
        try await nodeB.start()
        defer {
            Task { await nodeA.stop() }
            Task { await nodeB.stop() }
        }
        let pool = PeerPool(params: params, peerCount: 2,
                            manualPeers: [await nodeA.endpoint, await nodeB.endpoint],
                            relayPreference: true)
        await pool.start()
        #expect(await pool.connectedPeers().count == 2)

        let window = MempoolWindow(pool: pool, watchScripts: [Self.watchedScript])
        let seen = WindowEventCollector()
        let events = await window.events()
        let consumer = Task { for await event in events { seen.add(event) } }
        defer { consumer.cancel() }
        await window.start()
        #expect(await window.isRunning)

        // Node A announces watched1 + unrelated; node B re-announces watched1
        // (duplicate across peers) plus watched2.
        try await nodeA.send(.inv(InventoryPayload([
            InventoryVector(type: .tx, hash: watched1.txid),
            InventoryVector(type: .tx, hash: unrelated.txid),
        ])))

        // Node A gets one getdata carrying both txids as MSG_WITNESS_TX.
        guard case let .getdata(payloadA) = await nodeA.nextMessage(command: "getdata") else {
            Issue.record("node A never received a getdata")
            return
        }
        #expect(payloadA.vectors.count == 2)
        #expect(payloadA.vectors.contains(InventoryVector(type: .witnessTx, hash: watched1.txid)))
        #expect(payloadA.vectors.contains(InventoryVector(type: .witnessTx, hash: unrelated.txid)))

        try await nodeB.send(.inv(InventoryPayload([
            InventoryVector(type: .tx, hash: watched1.txid), // duplicate of A's announcement
            InventoryVector(type: .tx, hash: watched2.txid),
        ])))

        // Node B is asked only for watched2 — the duplicate was deduped.
        guard case let .getdata(payloadB) = await nodeB.nextMessage(command: "getdata") else {
            Issue.record("node B never received a getdata")
            return
        }
        #expect(payloadB.vectors == [InventoryVector(type: .witnessTx, hash: watched2.txid)])
        #expect(await nodeB.nextMessage(command: "getdata", timeout: .milliseconds(500)) == nil)

        // Matches: watched1 (50k, single output) and watched2 (20k, two
        // outputs summed); the unrelated tx matched nothing.
        let matched = await pollUntil {
            seen.events.filter { if case .paymentSeen = $0 { return true }; return false }.count == 2
        }
        #expect(matched)
        #expect(seen.events.contains {
            $0 == .paymentSeen(txid: watched1.txid, amount: 50_000, scriptPubKey: Self.watchedScript)
        })
        #expect(seen.events.contains {
            $0 == .paymentSeen(txid: watched2.txid, amount: 20_000, scriptPubKey: Self.watchedScript)
        })

        // The window fetched every announced tx exactly once in total.
        #expect(await nodeA.nextMessage(command: "getdata", timeout: .milliseconds(500)) == nil)

        await window.stop()
        await pool.stop()
    }

    @Test("a peer inv'ing back a watched broadcast emits txidEchoed once per peer")
    func txidEchoedPerPeer() async throws {
        let params = NetworkParams.signet
        let ours = unrelatedTx(seed: 0x31)
        let nodeA = LoopbackNode(params: params, transactions: [ours])
        let nodeB = LoopbackNode(params: params, transactions: [ours])
        try await nodeA.start()
        try await nodeB.start()
        defer {
            Task { await nodeA.stop() }
            Task { await nodeB.stop() }
        }
        let pool = PeerPool(params: params, peerCount: 2,
                            manualPeers: [await nodeA.endpoint, await nodeB.endpoint],
                            relayPreference: true)
        await pool.start()

        let window = MempoolWindow(pool: pool, watchScripts: [])
        await window.watchEcho(of: ours.txid)
        let seen = WindowEventCollector()
        let events = await window.events()
        let consumer = Task { for await event in events { seen.add(event) } }
        defer { consumer.cancel() }
        await window.start()

        let announcement = PeerMessage.inv(InventoryPayload([InventoryVector(type: .tx, hash: ours.txid)]))
        try await nodeA.send(announcement)
        try await nodeB.send(announcement)
        try await nodeA.send(announcement) // same peer again — no second event

        let endpointA = await nodeA.endpoint
        let endpointB = await nodeB.endpoint
        let echoed = await pollUntil {
            seen.events.filter { if case .txidEchoed = $0 { return true }; return false }.count == 2
        }
        #expect(echoed)
        #expect(seen.events.contains { $0 == .txidEchoed(txid: ours.txid, peer: endpointA) })
        #expect(seen.events.contains { $0 == .txidEchoed(txid: ours.txid, peer: endpointB) })
        // No watched scripts → no payment events.
        #expect(!seen.events.contains { if case .paymentSeen = $0 { return true }; return false })

        await window.stop()
        await pool.stop()
    }

    @Test("notfound frees the txid so another peer can serve it")
    func notfoundReRequest() async throws {
        let params = NetworkParams.signet
        let watched = watchedTx(seed: 0x41)
        let emptyNode = LoopbackNode(params: params) // announces but cannot serve
        let fullNode = LoopbackNode(params: params, transactions: [watched])
        try await emptyNode.start()
        try await fullNode.start()
        defer {
            Task { await emptyNode.stop() }
            Task { await fullNode.stop() }
        }
        let pool = PeerPool(params: params, peerCount: 2,
                            manualPeers: [await emptyNode.endpoint, await fullNode.endpoint],
                            relayPreference: true)
        await pool.start()
        // Both dials must have handshaked before anything is announced: a peer
        // the pool never adopted gets no listener, and the inv below would then
        // fail as an opaque getdata timeout instead of naming the real cause.
        #expect(await pool.connectedPeers().count == 2)

        let window = MempoolWindow(pool: pool, watchScripts: [Self.watchedScript])
        let seen = WindowEventCollector()
        let events = await window.events()
        let consumer = Task { for await event in events { seen.add(event) } }
        defer { consumer.cancel() }
        await window.start()
        #expect(await window.isRunning)

        let announcement = PeerMessage.inv(InventoryPayload([InventoryVector(type: .tx, hash: watched.txid)]))
        try await emptyNode.send(announcement)
        // The empty node is asked, answers notfound.
        #expect(await emptyNode.nextMessage(command: "getdata") != nil)
        try await fullNode.send(announcement)
        // …so the full node's duplicate announcement is NOT deduped away.
        guard case let .getdata(payload) = await fullNode.nextMessage(command: "getdata") else {
            Issue.record("full node never received a getdata")
            return
        }
        #expect(payload.vectors == [InventoryVector(type: .witnessTx, hash: watched.txid)])

        let matched = await pollUntil {
            seen.events.contains {
                $0 == .paymentSeen(txid: watched.txid, amount: 50_000, scriptPubKey: Self.watchedScript)
            }
        }
        #expect(matched)

        await window.stop()
        await pool.stop()
    }

    @Test("the seen buffer evicts the oldest txid past its cap")
    func seenBufferIsBounded() async throws {
        let params = NetworkParams.signet
        let txs = [unrelatedTx(seed: 0x51), unrelatedTx(seed: 0x52), unrelatedTx(seed: 0x53)]
        let node = LoopbackNode(params: params, transactions: txs)
        try await node.start()
        defer { Task { await node.stop() } }
        let pool = PeerPool(params: params, peerCount: 1,
                            manualPeers: [await node.endpoint], relayPreference: true)
        await pool.start()

        let window = MempoolWindow(pool: pool, watchScripts: [], maxSeenTxids: 2)
        await window.start()

        // Three announcements with a cap of two: the first txid is evicted,
        // so re-announcing it triggers a fresh getdata.
        for tx in txs {
            try await node.send(.inv(InventoryPayload([InventoryVector(type: .tx, hash: tx.txid)])))
            #expect(await node.nextMessage(command: "getdata") != nil)
        }
        try await node.send(.inv(InventoryPayload([InventoryVector(type: .tx, hash: txs[0].txid)])))
        guard case let .getdata(payload) = await node.nextMessage(command: "getdata") else {
            Issue.record("evicted txid was not re-requested")
            return
        }
        #expect(payload.vectors == [InventoryVector(type: .witnessTx, hash: txs[0].txid)])

        await window.stop()
        await pool.stop()
    }

    @Test("stop ends the subscription; the duration auto-closes the window")
    func stopAndAutoClose() async throws {
        let params = NetworkParams.signet
        let tx = watchedTx(seed: 0x61)
        let node = LoopbackNode(params: params, transactions: [tx])
        try await node.start()
        defer { Task { await node.stop() } }
        let pool = PeerPool(params: params, peerCount: 1,
                            manualPeers: [await node.endpoint], relayPreference: true)
        await pool.start()

        let window = MempoolWindow(pool: pool, watchScripts: [Self.watchedScript])
        let seen = WindowEventCollector()
        let events = await window.events()
        let consumer = Task { for await event in events { seen.add(event) } }
        defer { consumer.cancel() }

        await window.start(duration: .seconds(60))
        #expect(await window.isRunning)
        await window.stop()
        #expect(await !window.isRunning)

        // After stop, announcements are ignored: no getdata, no events.
        try await node.send(.inv(InventoryPayload([InventoryVector(type: .tx, hash: tx.txid)])))
        #expect(await node.nextMessage(command: "getdata", timeout: .milliseconds(500)) == nil)
        #expect(seen.events.isEmpty)

        // A short-duration window closes itself.
        await window.start(duration: .milliseconds(250))
        #expect(await window.isRunning)
        #expect(await pollUntil { await !window.isRunning })
        #expect(await node.nextMessage(command: "getdata", timeout: .milliseconds(500)) == nil)

        await pool.stop()
    }
}

/// Polls `condition` every 10ms until it holds or `timeout` elapses.
/// Waits for `condition`, and gives up eventually so a hung test fails instead
/// of hanging forever.
///
/// The timeout is a HANG-GUARD, not a performance claim. Nothing here asserts
/// that the condition is met within it — on a contended CI runner a short
/// deadline turns into an assertion nobody wrote, which is how these became
/// intermittent (#144). Keep it generous: a real hang fails either way.
private func pollUntil(_ timeout: Duration = .seconds(60),
                       _ condition: () async -> Bool) async -> Bool {
    let deadline = ContinuousClock.now + timeout
    while ContinuousClock.now < deadline {
        if await condition() { return true }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return false
}

/// Collects MempoolWindow events from the AsyncStream consumer task.
private final class WindowEventCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [MempoolWindow.Event] = []

    var events: [MempoolWindow.Event] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    func add(_ event: MempoolWindow.Event) {
        lock.lock()
        storage.append(event)
        lock.unlock()
    }
}
