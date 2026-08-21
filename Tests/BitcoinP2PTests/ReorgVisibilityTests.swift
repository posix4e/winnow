import Foundation
import Testing
@testable import BitcoinP2P

/// A reorg must not be silent (epic #100, invariant S5).
///
/// `connect` returns how many headers it appended and nothing else, so an
/// ordinary extension and a branch swap that disconnected blocks look
/// identical to the caller. That matters because the wallet scans forward
/// only: once its frontier has passed a height it never revisits it. If a
/// reorg removes a block the wallet already credited, and nothing says so,
/// the wallet keeps describing a branch that no longer exists — a payment
/// stays "confirmed" and a coin stays spendable when neither is true on
/// chain.
///
/// These tests cover the reporting. Acting on it is `SEC-016`, still open.
@Suite("Reorg visibility")
struct ReorgVisibilityTests {
    /// Builds a branch of `count` headers descending from `parent`. The tag
    /// makes each branch's hashes distinct.
    static func branch(from parent: Data, count: Int, tag: UInt8, fromTime time: UInt32) -> [BlockHeader] {
        var headers: [BlockHeader] = []
        var previous = parent
        for index in 0 ..< count {
            let header = minedHeader(previousHash: previous,
                                     merkleRoot: Data(repeating: tag, count: 32),
                                     time: time + UInt32(index) * 600)
            headers.append(header)
            previous = header.hash
        }
        return headers
    }

    /// An ordinary sync is not a reorg and must not look like one.
    @Test("extending the tip records no reorg")
    func plainExtensionRecordsNothing() async throws {
        let chain = makeSyntheticChain(length: 1, watchHeight: 6)
        let headerChain = try HeaderChain(params: chain.params)
        let extension_ = Self.branch(from: chain.blocks[0].hash, count: 4,
                                     tag: 0xAA, fromTime: 1_600_010_000)
        _ = try await headerChain.connect(extension_)
        #expect(await headerChain.height == 4)
        #expect(await headerChain.lastReorg == nil)
    }

    /// A branch swap reports where the branches diverged and how much was
    /// thrown away — the two facts a consumer needs in order to rewind.
    @Test("a branch swap reports its fork height and how much it disconnected")
    func branchSwapIsReported() async throws {
        let chain = makeSyntheticChain(length: 1, watchHeight: 6)
        let headerChain = try HeaderChain(params: chain.params)
        let original = Self.branch(from: chain.blocks[0].hash, count: 3,
                                   tag: 0xAA, fromTime: 1_600_010_000)
        _ = try await headerChain.connect(original)
        #expect(await headerChain.height == 3)
        #expect(await headerChain.lastReorg == nil)

        // A competing branch from genesis that ends up longer.
        let longer = Self.branch(from: chain.blocks[0].hash, count: 5,
                                 tag: 0xCC, fromTime: 1_600_030_000)
        _ = try await headerChain.connect(longer)

        let reorg = try #require(await headerChain.lastReorg)
        #expect(reorg.forkHeight == 0, "both branches descend from genesis")
        #expect(reorg.disconnectedHeaders == 3, "all three original headers were disconnected")
        #expect(await headerChain.height == 5)
        #expect(await headerChain.tipHash == longer[4].hash)
    }

    /// A refused reorg changes nothing, so it must not be reported either —
    /// otherwise a consumer would rewind for a branch that was rejected.
    @Test("a refused reorg is not reported")
    func refusedReorgIsNotReported() async throws {
        let chain = makeSyntheticChain(length: 1, watchHeight: 6)
        let headerChain = try HeaderChain(params: chain.params)
        _ = try await headerChain.connect(Self.branch(from: chain.blocks[0].hash, count: 3,
                                                      tag: 0xAA, fromTime: 1_600_010_000))

        let shorter = Self.branch(from: chain.blocks[0].hash, count: 2,
                                  tag: 0xBB, fromTime: 1_600_020_000)
        await #expect(throws: HeaderChainError.reorgWithoutMoreWork) {
            _ = try await headerChain.connect(shorter)
        }
        #expect(await headerChain.lastReorg == nil,
                "a branch that was refused must not look like one that was applied")
        #expect(await headerChain.height == 3)
    }

    /// The record describes the latest reorg, so a consumer that acts on one
    /// and is then reorged again sees the newer fork rather than a stale one.
    @Test("a second reorg replaces the record")
    func secondReorgReplacesTheRecord() async throws {
        let chain = makeSyntheticChain(length: 1, watchHeight: 6)
        let headerChain = try HeaderChain(params: chain.params)
        _ = try await headerChain.connect(Self.branch(from: chain.blocks[0].hash, count: 2,
                                                      tag: 0xAA, fromTime: 1_600_010_000))

        let second = Self.branch(from: chain.blocks[0].hash, count: 4,
                                 tag: 0xCC, fromTime: 1_600_030_000)
        _ = try await headerChain.connect(second)
        let first = try #require(await headerChain.lastReorg)
        #expect(first.disconnectedHeaders == 2)

        // Fork above the new branch's first header, so the fork height moves up.
        let third = Self.branch(from: second[0].hash, count: 6,
                                tag: 0xDD, fromTime: 1_600_050_000)
        _ = try await headerChain.connect(third)
        let latest = try #require(await headerChain.lastReorg)
        #expect(latest.forkHeight == 1, "the record must describe the most recent swap")
        #expect(latest.disconnectedHeaders == 3)
    }
}
