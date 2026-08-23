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
/// The reporting used to be a sticky `lastReorg` property, which was the wrong
/// shape twice over: a consumer could read the same value again after later
/// ordinary syncs and roll back a second time, and two swaps inside one sync
/// collapsed into whichever happened last, losing the deeper one. A batch now
/// reports its own fork height, and a sync reports the lowest it saw.
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
        let outcome = try await headerChain.connect(extension_)
        #expect(await headerChain.height == 4)
        #expect(outcome.forkHeight == nil)
        #expect(outcome.appended == 4)
    }

    /// A branch swap reports where the branches diverged and how much was
    /// thrown away — the two facts a consumer needs in order to rewind.
    @Test("a branch swap reports its fork height and how much it disconnected")
    func branchSwapIsReported() async throws {
        let chain = makeSyntheticChain(length: 1, watchHeight: 6)
        let headerChain = try HeaderChain(params: chain.params)
        let original = Self.branch(from: chain.blocks[0].hash, count: 3,
                                   tag: 0xAA, fromTime: 1_600_010_000)
        let extended = try await headerChain.connect(original)
        #expect(await headerChain.height == 3)
        #expect(extended.forkHeight == nil)

        // A competing branch from genesis that ends up longer.
        let longer = Self.branch(from: chain.blocks[0].hash, count: 5,
                                 tag: 0xCC, fromTime: 1_600_030_000)
        let swap = try await headerChain.connect(longer)

        #expect(swap.forkHeight == 0, "both branches descend from genesis")
        #expect(swap.disconnectedHeaders == 3, "all three original headers were disconnected")
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
        #expect(await headerChain.height == 3, "the refused branch changed nothing")

        // Nothing was reported because nothing was returned: a throw carries no
        // outcome, so there is no value a consumer could rewind on. The next
        // ordinary batch confirms the refusal left no residue behind it.
        let afterwards = try await headerChain.connect(
            Self.branch(from: (await headerChain.tipHash), count: 1,
                        tag: 0xEE, fromTime: 1_600_040_000))
        #expect(afterwards.forkHeight == nil,
                "a branch that was refused must not look like one that was applied")
        #expect(await headerChain.height == 4)
    }

    /// Two swaps in one sync must not collapse into the shallower one.
    ///
    /// This is the case the sticky property got wrong: it kept whichever
    /// happened last, so a sync that first forked at height 0 and then at
    /// height 1 reported 1, and a rollback to 1 would leave everything above
    /// height 0 from the discarded branch in place. Taking the minimum is what
    /// makes collapsing harmless.
    @Test("a sync reports the lowest fork of several")
    func syncReportsTheLowestFork() async throws {
        let chain = makeSyntheticChain(length: 1, watchHeight: 6)
        let headerChain = try HeaderChain(params: chain.params)
        _ = try await headerChain.connect(Self.branch(from: chain.blocks[0].hash, count: 2,
                                                      tag: 0xAA, fromTime: 1_600_010_000))

        var outcome = HeaderChain.SyncOutcome()

        // Deeper swap first: forks at the genesis block, height 0.
        let second = Self.branch(from: chain.blocks[0].hash, count: 4,
                                 tag: 0xCC, fromTime: 1_600_030_000)
        outcome.absorb(try await headerChain.connect(second))
        #expect(outcome.minForkHeight == 0)

        // Then a shallower one, forking at height 1.
        let third = Self.branch(from: second[0].hash, count: 6,
                                tag: 0xDD, fromTime: 1_600_050_000)
        outcome.absorb(try await headerChain.connect(third))
        #expect(outcome.minForkHeight == 0,
                "the shallower swap must not hide the deeper one")
        #expect(outcome.disconnectedHeaders == 5)
    }
}
