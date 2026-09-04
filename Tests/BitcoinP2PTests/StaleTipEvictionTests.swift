import BitcoinCore
import Foundation
import Testing
@testable import BitcoinP2P

/// A peer far behind the tip cannot serve filters or blocks near it, and
/// asking it about a tip it has never seen makes Bitcoin Core hang up. The
/// pool unseats such a peer on what it reports, never on what it runs.
@Suite("Stale tip eviction", .timeLimit(.minutes(2)))
struct StaleTipEvictionTests {
    /// Polls the pool until `predicate` holds for its seated endpoints, or
    /// ten seconds pass. Eviction refills asynchronously, so `start()` alone
    /// does not settle the pool.
    private static func settle(_ pool: PeerPool,
                               until predicate: @escaping ([PeerEndpoint]) -> Bool) async -> [PeerEndpoint] {
        var seen: [PeerEndpoint] = []
        for _ in 0 ..< 100 {
            seen = []
            for peer in await pool.connectedPeers() { seen.append(await peer.endpoint) }
            if predicate(seen) { return seen }
            try? await Task.sleep(for: .milliseconds(100))
        }
        return seen
    }

    @Test("a peer far behind the best connected tip is unseated and cooled off, even when it was seated first")
    func staleIsUnseated() async throws {
        let synthetic = makeSyntheticChain(length: 120, watchHeight: 3)
        // The current node answers its handshake late, so the stale one is
        // seated first and the eviction has to reach back to it.
        let current = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                   versionDelay: .milliseconds(300))
        let stale = LoopbackNode(params: synthetic.params) // reports height 0
        try await current.start()
        try await stale.start()
        defer { Task { await current.stop() }; Task { await stale.stop() } }
        let currentEndpoint = await current.endpoint
        let staleEndpoint = await stale.endpoint

        let pool = PeerPool(params: synthetic.params, peerCount: 2,
                            manualPeers: [staleEndpoint, currentEndpoint])
        await pool.start()
        let seated = await Self.settle(pool) { $0 == [currentEndpoint] }
        #expect(seated == [currentEndpoint], "only the peer near the tip keeps its seat")
        #expect(await pool.rejectionReason(staleEndpoint)?.hasPrefix("stale tip:") == true)
        #expect(await pool.coolingEndpoints.contains(staleEndpoint), "cooled off, not banned")
        await pool.stop()
    }

    @Test("peers inside the tolerance keep their seats")
    func nearPeersStay() async throws {
        let synthetic = makeSyntheticChain(length: 120, watchHeight: 3)
        let current = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        let slightlyBehind = LoopbackNode(params: synthetic.params,
                                          chain: Array(synthetic.blocks.prefix(60)))
        try await current.start()
        try await slightlyBehind.start()
        defer { Task { await current.stop() }; Task { await slightlyBehind.stop() } }
        let endpoints = [await current.endpoint, await slightlyBehind.endpoint]

        let pool = PeerPool(params: synthetic.params, peerCount: 2, manualPeers: endpoints)
        await pool.start()
        let seated = await Self.settle(pool) { $0.count == 2 }
        #expect(Set(seated) == Set(endpoints), "59 blocks apart is inside the tolerance")
        for endpoint in endpoints {
            #expect(await pool.rejectionReason(endpoint) == nil)
        }
        #expect(await pool.coolingEndpoints.isEmpty)
        await pool.stop()
    }

    @Test("the tolerance is the wallet's reorg horizon")
    func toleranceMatchesHorizon() {
        #expect(PeerPool.staleTipTolerance == 100)
    }
}
