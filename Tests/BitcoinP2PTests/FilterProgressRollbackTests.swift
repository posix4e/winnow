import Foundation
import Testing
@testable import BitcoinP2P

/// Filter progress rewinds with everything else (#127).
///
/// The frontier is the thing that makes a reorg silent: scanning forward from
/// a height the wallet has already passed means the orphaned branch is never
/// re-examined. Rewinding it is what turns the rollback into a rescan.
@Suite("Filter progress rollback")
struct FilterProgressRollbackTests {
    private func sync(startHeight: UInt32) throws -> FilterSync {
        let pool = PeerPool(params: .signet, peerCount: 0, manualPeers: [])
        let chain = try HeaderChain(params: .signet)
        return try FilterSync(pool: pool, chain: chain, startHeight: startHeight)
    }

    @Test("the frontier rewinds to the block after the fork")
    func frontierRewinds() async throws {
        let filters = try sync(startHeight: 100)
        try await filters.recordProgressForTest(nextScanHeight: 500)
        try await filters.rollBack(to: 300)
        #expect(await filters.nextScanHeight == 301)
    }

    /// Pinned filter headers above the fork commit to filters for blocks that
    /// are no longer on the chain. Keeping them would make a later cross-check
    /// compare the surviving branch against the orphaned one and reject honest
    /// peers.
    @Test("pinned filter headers above the fork are dropped")
    func pinnedHeadersAboveForkAreDropped() async throws {
        let filters = try sync(startHeight: 100)
        try await filters.recordProgressForTest(
            nextScanHeight: 500,
            filterHeaders: ["200": "aa", "300": "bb", "400": "cc"])

        try await filters.rollBack(to: 300)

        let remaining = await filters.pinnedFilterHeadersForTest
        #expect(remaining.keys.sorted() == ["200", "300"])
        #expect(remaining["400"] == nil, "that block is not on this chain any more")
    }

    /// Same property the wallet has, and for the same reason: the crash marker
    /// names a height, so recovery is a redo.
    @Test("rolling back twice is the same as once")
    func idempotent() async throws {
        let filters = try sync(startHeight: 100)
        try await filters.recordProgressForTest(nextScanHeight: 500,
                                                filterHeaders: ["400": "cc"])
        try await filters.rollBack(to: 300)
        let once = await filters.nextScanHeight
        try await filters.rollBack(to: 300)
        #expect(await filters.nextScanHeight == once)
    }

    /// A fork above the frontier leaves nothing scanned in doubt, and moving
    /// forward here would skip blocks that were never read.
    @Test("the frontier never advances")
    func frontierNeverAdvances() async throws {
        let filters = try sync(startHeight: 100)
        try await filters.recordProgressForTest(nextScanHeight: 200)
        try await filters.rollBack(to: 900)
        #expect(await filters.nextScanHeight == 200)
    }
}
