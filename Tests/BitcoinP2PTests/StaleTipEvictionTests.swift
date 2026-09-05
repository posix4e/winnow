import BitcoinCore
import Foundation
import Testing
@testable import BitcoinP2P

/// A peer far behind the tip cannot serve filters or blocks near it, and
/// asking it about a tip it has never seen makes Bitcoin Core hang up. The
/// pool unseats such a peer on what it reports, judged against the header
/// chain the pool itself validated — never against another peer's claim,
/// and never on what software it runs.
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

    @Test("a peer far behind the validated tip is unseated and cooled off once headers have synced")
    func staleIsUnseated() async throws {
        let synthetic = makeSyntheticChain(length: 120, watchHeight: 3)
        let current = LoopbackNode(params: synthetic.params, chain: synthetic.blocks) // reports 120
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
        let both = await Self.settle(pool) { $0.count == 2 }
        #expect(both.count == 2, "before any header sync there is no validated tip, so nothing is judged")

        // Headers sync against the current node gives the pool a tip it can
        // trust; the stale peer's claim is now 119 behind it.
        let chain = try HeaderChain(params: synthetic.params)
        _ = try await pool.syncHeaders(chain)
        #expect(await chain.height == 120)
        let seated = await Self.settle(pool) { $0 == [currentEndpoint] }
        #expect(seated == [currentEndpoint], "only the peer near the tip keeps its seat")
        #expect(await pool.rejectionReason(staleEndpoint)?.hasPrefix("stale tip:") == true)
        #expect(await pool.coolingEndpoints.contains(staleEndpoint), "cooled off, not banned")
        await pool.stop()
    }

    @Test("a peer claiming an absurd height cannot get honest peers evicted")
    func liarCannotEvictHonestPeers() async throws {
        let synthetic = makeSyntheticChain(length: 120, watchHeight: 3)
        let honest = LoopbackNode(params: synthetic.params, chain: synthetic.blocks) // reports 120
        let liar = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                claimedStartHeight: Int32.max)
        let negative = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                    claimedStartHeight: Int32.min)
        let nodes = [honest, liar, negative]
        for node in nodes { try await node.start() }
        defer { for node in nodes { Task { await node.stop() } } }
        var endpoints: [PeerEndpoint] = []
        for node in nodes { endpoints.append(await node.endpoint) }

        let pool = PeerPool(params: synthetic.params, peerCount: 3, manualPeers: [endpoints[0]],
                            peersFileURL: {
                                let store = tempFileURL("peers.json")
                                try! Self.persistedPeersFile([endpoints[1], endpoints[2]]).write(to: store)
                                return store
                            }())
        await pool.start()
        _ = await Self.settle(pool) { $0.count == 3 }
        let chain = try HeaderChain(params: synthetic.params)
        _ = try await pool.syncHeaders(chain)
        // Int32.min widened, not trapped; Int32.max is ahead of the tip, which
        // this rule does not judge (the header sync does).
        let seated = await Self.settle(pool) { !$0.contains(endpoints[2]) }
        #expect(seated.contains(endpoints[0]), "the honest peer keeps its seat whatever a liar claims")
        #expect(seated.contains(endpoints[1]), "claiming ahead of the tip is not staleness")
        #expect(!seated.contains(endpoints[2]), "a negative height is far behind any tip")
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
        let chain = try HeaderChain(params: synthetic.params)
        _ = try await pool.syncHeaders(chain)
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
        let chain = try HeaderChain(params: synthetic.params)
        _ = try await pool.syncHeaders(chain)
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
