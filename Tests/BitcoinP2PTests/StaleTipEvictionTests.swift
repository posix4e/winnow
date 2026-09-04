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

    /// The remembered-peers file the pool reads at start, version 2.
    private static func persistedPeersFile(_ endpoints: [PeerEndpoint]) -> Data {
        let entries = endpoints.map {
            "{\"source\":\"persisted\",\"port\":\($0.port),\"host\":\"\($0.host)\"}"
        }.joined(separator: ",")
        return Data("{\"version\":2,\"peers\":[\(entries)]}".utf8)
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

        // The stale node arrives as a remembered peer, the way the mainnet
        // stall's dead node did; a manual peer is exempt (see below), so it
        // cannot carry this test. The tip node is manual so the diversity
        // ceiling, which refuses one source class the whole pool, lets both
        // seat.
        let store = tempFileURL("peers.json")
        try Self.persistedPeersFile([staleEndpoint]).write(to: store)
        let pool = PeerPool(params: synthetic.params, peerCount: 2,
                            manualPeers: [currentEndpoint], peersFileURL: store)
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

    @Test("a peer the user typed in keeps its seat however far behind it is")
    func manualPeerIsKept() async throws {
        let synthetic = makeSyntheticChain(length: 120, watchHeight: 3)
        let current = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        let ownNode = LoopbackNode(params: synthetic.params) // the user's own node, still syncing
        try await current.start()
        try await ownNode.start()
        defer { Task { await current.stop() }; Task { await ownNode.stop() } }
        let ownEndpoint = await ownNode.endpoint
        let store = tempFileURL("peers.json")
        // The current node arrives as a remembered peer, not a manual one.
        try Self.persistedPeersFile([await current.endpoint]).write(to: store)

        let pool = PeerPool(params: synthetic.params, peerCount: 2, manualPeers: [ownEndpoint],
                            peersFileURL: store)
        await pool.start()
        let seated = await Self.settle(pool) { $0.count == 2 }
        #expect(seated.contains(ownEndpoint), "the user's explicit choice is not overruled")
        #expect(await pool.rejectionReason(ownEndpoint) == nil)
        await pool.stop()
    }

    @Test("the tolerance is the wallet's reorg horizon")
    func toleranceMatchesHorizon() {
        #expect(PeerPool.staleTipTolerance == 100)
    }
}
