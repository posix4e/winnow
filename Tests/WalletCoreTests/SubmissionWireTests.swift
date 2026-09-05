import BitcoinCore
import BitcoinP2P
import BlockchainBackend
import Foundation
import Testing
@testable import WalletCore

/// The miner-only guarantee, observed on a wire rather than on a fake: a real
/// `TxBroadcaster` on a loopback peer, resolved per route exactly as the app
/// resolves it, and the loopback node reporting whether an `inv` ever came.
@Suite("Submission wire silence", .timeLimit(.minutes(1)))
struct SubmissionWireTests {
    @Test("a miner-only submission puts nothing on the wire, and a peers one does")
    func minerOnlyIsSilentOnTheWire() async throws {
        let params = NetworkParams.signet
        let node = LoopbackNode(params: params)
        try await node.start()
        defer { Task { await node.stop() } }
        let pool = PeerPool(params: params, peerCount: 1, manualPeers: [await node.endpoint])
        await pool.start()
        defer { Task { await pool.stop() } }
        let broadcaster = try TxBroadcaster(pool: pool, rebroadcastBaseInterval: .seconds(60),
                                            announcementTimeout: .seconds(30))
        let miner = ScriptedMiner(submit: [.success(.accepted(txids: [], providerMessage: nil))])
        let coordinator = try SubmissionCoordinator(
            relay: { route in route.touchesPeers ? broadcaster : nil },
            miners: { _ in miner })
        await coordinator.start()
        defer { Task { await coordinator.shutdown(); await broadcaster.shutdown() } }

        // Handshake first, so silence afterwards is silence on a live peer.
        _ = await node.nextMessage(command: "verack", timeout: .seconds(10))

        let private_ = try await coordinator.submit(rawTx: fakeSignedTx(seed: 1), feeRateSatPerVByte: 4,
                                                    route: .minerOnly(.slipstream), origin: .walletSend)
        #expect(private_.state == .accepted)
        // A TCP ordering barrier (#164): by the time the pong arrives, anything
        // the client sent before answering has arrived too.
        try await node.send(.ping(0xB412_B412_B412_B412))
        #expect(await node.nextMessage(command: "pong", timeout: .seconds(10)) != nil)
        #expect(await node.nextMessage(command: "inv", timeout: .milliseconds(500)) == nil,
                "miner-only must never announce to a peer")
        #expect(await broadcaster.pendingTxids.isEmpty, "the broadcaster never heard of it")

        let public_ = try await coordinator.submit(rawTx: fakeSignedTx(seed: 2), feeRateSatPerVByte: 2,
                                                   route: .peers, origin: .walletSend)
        #expect(await node.nextMessage(command: "inv", timeout: .seconds(10)) != nil,
                "the peers route announces as before")
        #expect(await broadcaster.pendingTxids == [public_.txid])
    }
}
