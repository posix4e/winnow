import Foundation
import Testing
import TestSupport
@testable import WalletCore

struct PeerCatalogIntegrationTests {
    @Test func resetPreservesTheShippedListAndManualPeers() async throws {
        let chain = makeSyntheticChain(length: 4, watchHeight: 2)
        let node = LoopbackNode(params: chain.params, chain: chain.blocks)
        try await node.start()
        let manual = await node.endpoint
        let pool = PeerPool(params: chain.params, peerCount: 1, manualPeers: [manual],
                            censusCatalog: CensusCatalogTests().catalog())
        await pool.start()
        #expect(await pool.candidateSourcesForTest()[.init(host: "8.8.8.8", port: 8333)] == .census)
        await pool.stop()
        try await pool.forgetKnownGood()
        let candidates = await pool.candidateSourcesForTest()
        #expect(candidates[manual] == .manual)
        #expect(candidates[.init(host: "8.8.8.8", port: 8333)] == .census)
        await node.stop()
    }

    /// A shipped list is used at any age; one that fails validation is not
    /// used at all, and the pool still has its other sources.
    @Test func anOldListIsUsedAndAnInvalidOneIsIgnored() async {
        let old = CensusCatalogTests().catalog("2026-01-01")
        #expect(await PeerPool(params: .mainnet, censusCatalog: old).candidateEndpointsForTest()
                == [PeerEndpoint(host: "8.8.8.8", port: 8333)])
        var invalid = old; invalid.schemaVersion = 2
        #expect(await PeerPool(params: .mainnet, censusCatalog: invalid).candidateEndpointsForTest().isEmpty)
    }

    @Test func reshuffleAvoidsPreviousPeersAndCensusPeersAreOneSource() async {
        var catalog = CensusCatalogTests().catalog()
        catalog.networks["clearnet"]!.append(.init(host: "9.9.9.9", port: 8333, userAgent: "", startHeight: 900_000))
        let previous = PeerEndpoint(host: "8.8.8.8", port: 8333)
        let pool = PeerPool(params: .mainnet, censusCatalog: catalog, avoidOnReset: [previous])
        #expect(await pool.candidateEndpointsForTest().first == .init(host: "9.9.9.9", port: 8333))
        let sources = await pool.candidateSourcesForTest()
        #expect(Set(sources.values) == [.census], "census peers are one trust source")
    }
}
