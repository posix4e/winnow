import BitcoinCore
import Foundation
import Testing
@testable import BitcoinP2P

/// The mainnet failure of 2026-09-04, reproduced: a peer a little behind the
/// tip (inside the eviction tolerance) is asked for filter checkpoints at a
/// stop hash it has never seen, hangs up the way Bitcoin Core does, and the
/// sync must carry on with the peers that answered instead of failing the
/// whole pass on the same batch forever.
@Suite("Checkpoint hang-up failover", .timeLimit(.minutes(3)))
struct CheckpointHangupTests {
    @Test("a peer that hangs up on the checkpoint request is cooled off and the sync completes with the others")
    func hangupFailsOver() async throws {
        let synthetic = makeSyntheticChain(length: 1_001, watchHeight: 3)
        let honestA = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        let honestB = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        // 51 blocks behind: kept by the pool, unable to answer for the tip.
        // Answers its handshake late so the honest peers lead the header sync.
        let short = LoopbackNode(params: synthetic.params,
                                 chain: Array(synthetic.blocks.prefix(950)),
                                 disconnectOnUnknownStopHash: true,
                                 versionDelay: .milliseconds(300))
        let nodes = [honestA, honestB, short]
        for node in nodes { try await node.start() }
        defer { for node in nodes { Task { await node.stop() } } }
        var endpoints: [PeerEndpoint] = []
        for node in nodes { endpoints.append(await node.endpoint) }
        let shortEndpoint = endpoints[2]

        let pool = PeerPool(params: synthetic.params, peerCount: 3, manualPeers: endpoints,
                            peersFileURL: tempFileURL("peers.json"))
        await pool.start()
        #expect(await pool.connectedPeers().count == 3,
                "51 behind is inside the tolerance; the pool keeps the short peer")

        let chain = try HeaderChain(params: synthetic.params)
        let sync = try FilterSync(pool: pool, chain: chain, startHeight: 1,
                                  storageURL: tempFileURL("progress.json"),
                                  requiredCheckpointPeers: 3)
        let collector = MatchCollector()
        try await sync.sync(watchScripts: [synthetic.watchScript]) { collector.add($0) }

        #expect(collector.matches.count == 1, "the scan finished on the honest peers' answers")
        #expect(await sync.lastScannedHeight == 1_001)

        var connected: Set<String> = []
        for peer in await pool.connectedPeers() { connected.insert(await peer.endpoint.description) }
        #expect(!connected.contains(shortEndpoint.description), "the peer that hung up is gone")
        #expect(await pool.coolingEndpoints.contains(shortEndpoint),
                "hanging up is a transport fault: cooled off, not condemned")
        await pool.stop()
    }
}
