import BitcoinCore
import Foundation
import Testing
@testable import BitcoinP2P

/// BIP133: a peer whose fee filter is above a transaction's rate has said it
/// will drop the bytes unread. Announcing to it is noise, and the
/// deprioritization it would earn hides the real reason.
@Suite("Fee filter announcements", .timeLimit(.minutes(2)))
struct FeeFilterAnnouncementTests {
    @Test("a peer whose fee filter refuses the transaction is not announced to until the filter drops")
    func feeFilterSkipsPeer() async throws {
        let params = NetworkParams.signet
        let node = LoopbackNode(params: params)
        try await node.start()
        defer { Task { await node.stop() } }
        let pool = PeerPool(params: params, peerCount: 1, manualPeers: [await node.endpoint])
        await pool.start()
        defer { Task { await pool.stop() } }
        _ = await node.nextMessage(command: "verack", timeout: .seconds(10))

        // 100 sat/vB: nothing this test sends clears it.
        try await node.send(.feefilter(100_000))
        let peer = try #require(await pool.connectedPeers().first)
        for _ in 0 ..< 100 where await peer.feeFilter != 100_000 {
            try await Task.sleep(for: .milliseconds(50))
        }
        #expect(await peer.feeFilter == 100_000)

        let broadcaster = try TxBroadcaster(pool: pool,
                                            rebroadcastBaseInterval: .milliseconds(300),
                                            maxRebroadcastInterval: .milliseconds(600),
                                            announcementTimeout: .seconds(30))
        defer { Task { await broadcaster.shutdown() } }
        let txid = try await broadcaster.broadcast(
            makeFakeSegwitTx().serialized(includeWitness: true), feeRateSatPerVByte: 2)
        #expect(await node.nextMessage(command: "inv", timeout: .seconds(1)) == nil,
                "the peer said it would drop it; no announcement")
        #expect(await broadcaster.relayStatus(txid).isEmpty,
                "skipped, not marked: no relay state was recorded against the peer")

        // The filter drops to 1 sat/vB; the next scheduled attempt announces.
        try await node.send(.feefilter(1_000))
        #expect(await node.nextMessage(command: "inv", timeout: .seconds(10)) != nil,
                "a filter that later allows the transaction lets the peer back in")
    }
}
