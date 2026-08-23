import Foundation
import Testing
@testable import BitcoinP2P

/// The BIP157 cfcheckpt majority rule, actually exercised (epic #100, S5).
///
/// `FilterSync` adopts the *majority* cfcheckpt answer rather than the first
/// reply, and the reasoning is written out in the source: a first reply adopted
/// by fiat would let one lying peer evict the honest ones and become the sole
/// reference. Until now nothing ran that code. Checkpoints are served every
/// 1,000 blocks, so every existing loopback chain — six blocks — had all peers
/// return an *empty* checkpoint list. Identical lists agree, the tally is
/// unanimous, and the majority branch was never entered. A mutation removing
/// the rule outright killed no test (#129).
///
/// These use a real 1,001-block chain and the real interval rather than making
/// `checkpointInterval` injectable. Configuring the constant would prove the
/// decision function works on a number of our choosing; it would not prove the
/// wire-to-policy path a real peer travels.
@Suite("cfcheckpt majority")
struct CheckpointMajorityTests {

    /// One checkpoint entry (height 1,000) and a tip above it, so the rule is
    /// reachable. `watchHeight: 3` gives exactly one match to prove the sync
    /// really ran rather than exiting early.
    static func chain() -> SyntheticChain {
        makeSyntheticChain(length: 1_001, watchHeight: 3)
    }

    static func endpoints(_ nodes: [LoopbackNode]) async -> [PeerEndpoint] {
        var result: [PeerEndpoint] = []
        for node in nodes { result.append(await node.endpoint) }
        return result
    }

    static func connectedEndpoints(_ pool: PeerPool) async -> Set<String> {
        var result: Set<String> = []
        for peer in await pool.connectedPeers() { result.insert(await peer.endpoint.description) }
        return result
    }

    // MARK: - The rule adopts the majority and evicts the liar

    @Test("two honest peers outvote one liar, which is evicted while the sync completes")
    func majorityOfThreeAdoptsHonestCheckpoints() async throws {
        let synthetic = Self.chain()
        let honestA = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        let honestB = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        let liar = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                lieAboutFilterCommitments: true)
        let nodes = [honestA, honestB, liar]
        for node in nodes { try await node.start() }
        defer { for node in nodes { Task { await node.stop() } } }

        let liarEndpoint = await liar.endpoint
        let pool = PeerPool(params: synthetic.params, peerCount: 3,
                            manualPeers: await Self.endpoints(nodes),
                            peersFileURL: tempFileURL("peers.json"))
        await pool.start()
        #expect(await pool.connectedPeers().count == 3)

        let chain = try HeaderChain(params: synthetic.params)
        let sync = try FilterSync(pool: pool, chain: chain, startHeight: 1,
                                  storageURL: tempFileURL("progress.json"),
                                  requiredCheckpointPeers: 3)
        let collector = MatchCollector()
        try await sync.sync(watchScripts: [synthetic.watchScript]) { collector.add($0) }

        // The honest answer was adopted: the scan finished and the checkpoint
        // height carries a pinned header.
        #expect(collector.matches.count == 1)
        #expect(await sync.lastScannedHeight == 1_001)
        #expect(await sync.filterHeader(at: 1_000) != nil)

        // And the minority peer is gone. This is the half that matters: a rule
        // that adopted the majority but kept the liar connected would leave it
        // free to serve filters for the rest of the session.
        #expect(await Self.connectedEndpoints(pool).contains(liarEndpoint.description) == false)

        await pool.stop()
    }

    // MARK: - No majority is a refusal, not a tie-break

    @Test("three peers that all disagree fail closed without advancing the scan")
    func threeWaySplitFailsClosed() async throws {
        let synthetic = Self.chain()
        // Three mutually inconsistent answers: one honest, two liars whose
        // fabrications differ. With a single fixed lie the two liars would
        // agree and form a majority *for the lie* — the opposite of this test.
        let honest = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        let liarA = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                 lieAboutFilterCommitments: true, lieSalt: 0xFF)
        let liarB = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                 lieAboutFilterCommitments: true, lieSalt: 0x0F)
        let nodes = [honest, liarA, liarB]
        for node in nodes { try await node.start() }
        defer { for node in nodes { Task { await node.stop() } } }

        let pool = PeerPool(params: synthetic.params, peerCount: 3,
                            manualPeers: await Self.endpoints(nodes),
                            peersFileURL: tempFileURL("peers.json"))
        await pool.start()
        #expect(await pool.connectedPeers().count == 3)

        let chain = try HeaderChain(params: synthetic.params)
        let sync = try FilterSync(pool: pool, chain: chain, startHeight: 1,
                                  storageURL: tempFileURL("progress.json"),
                                  requiredCheckpointPeers: 3)

        var thrown: (any Error)?
        do {
            try await sync.sync(watchScripts: [synthetic.watchScript]) { _ in }
        } catch {
            thrown = error
        }
        guard case let .checkpointMismatch(reason)? = thrown as? FilterSyncError else {
            Issue.record("expected checkpointMismatch, got \(String(describing: thrown))")
            return
        }
        #expect(reason.contains("no cfcheckpt majority"))

        // With no majority the lie is unattributable, so every checkpoint peer
        // is dropped rather than guessing which two to trust.
        #expect(await pool.connectedPeers().isEmpty)
        // And nothing was scanned: the refusal happens before any batch.
        #expect(await sync.nextScanHeight == 1)

        await pool.stop()
    }

    /// Two peers cannot produce a strict majority, so a disagreement between
    /// them is the no-majority case rather than an eviction. Above height 1,000
    /// this is caught by the checkpoint rule; the six-block test in
    /// `PeerDisagreementTests` catches the same lie one layer down, at the
    /// per-batch cfheaders cross-check, because there the checkpoint lists are
    /// both empty.
    @Test("two disagreeing peers are a no-majority refusal above the checkpoint interval")
    func twoPeersCannotFormAMajority() async throws {
        let synthetic = Self.chain()
        let honest = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        let liar = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                lieAboutFilterCommitments: true)
        let nodes = [honest, liar]
        for node in nodes { try await node.start() }
        defer { for node in nodes { Task { await node.stop() } } }

        let pool = PeerPool(params: synthetic.params, peerCount: 2,
                            manualPeers: await Self.endpoints(nodes),
                            peersFileURL: tempFileURL("peers.json"))
        await pool.start()
        #expect(await pool.connectedPeers().count == 2)

        let chain = try HeaderChain(params: synthetic.params)
        let sync = try FilterSync(pool: pool, chain: chain, startHeight: 1,
                                  storageURL: tempFileURL("progress.json"),
                                  requiredCheckpointPeers: 2)

        var thrown: (any Error)?
        do {
            try await sync.sync(watchScripts: [synthetic.watchScript]) { _ in }
        } catch {
            thrown = error
        }
        guard case let .checkpointMismatch(reason)? = thrown as? FilterSyncError else {
            Issue.record("expected checkpointMismatch, got \(String(describing: thrown))")
            return
        }
        #expect(reason.contains("no cfcheckpt majority across 2 peers"))
        #expect(await sync.nextScanHeight == 1)

        await pool.stop()
    }

    /// Adopting the majority is only half the job — the sync then has to keep
    /// going without the peer it just dropped.
    ///
    /// The peer list is captured before the checkpoint comparison, and the
    /// batch loop sends to `peers[0]`. Evicting a liar that sits at the front
    /// of that captured list tears down the very connection the next request
    /// uses, so a sync that correctly identified the liar would still die with
    /// a transport error. Peer order is dial-completion order, so the liar is
    /// pinned to the front here by delaying the honest nodes' handshakes.
    @Test("the sync continues after evicting a liar that was first in the peer list")
    func continuesAfterEvictingTheFirstPeer() async throws {
        let synthetic = Self.chain()
        let liar = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                lieAboutFilterCommitments: true)
        let honestA = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                   versionDelay: .milliseconds(150))
        let honestB = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                   versionDelay: .milliseconds(250))
        let nodes = [liar, honestA, honestB]
        for node in nodes { try await node.start() }
        defer { for node in nodes { Task { await node.stop() } } }

        let liarEndpoint = await liar.endpoint
        let pool = PeerPool(params: synthetic.params, peerCount: 3,
                            manualPeers: await Self.endpoints(nodes),
                            peersFileURL: tempFileURL("peers.json"))
        await pool.start()
        #expect(await pool.connectedPeers().count == 3)
        // Precondition for what this test is actually about.
        let first = await pool.connectedPeers().first
        #expect(await first?.endpoint.description == liarEndpoint.description,
                "fixture precondition: the liar must be first in the peer list")

        let chain = try HeaderChain(params: synthetic.params)
        let sync = try FilterSync(pool: pool, chain: chain, startHeight: 1,
                                  storageURL: tempFileURL("progress.json"),
                                  requiredCheckpointPeers: 3)
        let collector = MatchCollector()
        try await sync.sync(watchScripts: [synthetic.watchScript]) { collector.add($0) }

        #expect(collector.matches.count == 1)
        #expect(await sync.lastScannedHeight == 1_001)
        #expect(await Self.connectedEndpoints(pool).contains(liarEndpoint.description) == false)

        await pool.stop()
    }

    // MARK: - The reply must answer the question that was asked

    /// A peer that echoes a different stop hash is answering about some other
    /// chain. The tally cannot catch this on its own: with one peer there is
    /// nothing to compare against, and peers that agree on a wrong stop hash
    /// agree unanimously. `pinFilterHeaders` has always validated its own stop
    /// hash; the checkpoint path had not.
    @Test("a cfcheckpt answering about a different chain is refused, even from a lone peer")
    func stopHashMismatchRefused() async throws {
        let synthetic = Self.chain()
        let node = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                cfcheckptStopHashOverride: Data(repeating: 0xAB, count: 32))
        try await node.start()
        defer { Task { await node.stop() } }

        let pool = PeerPool(params: synthetic.params, peerCount: 1,
                            manualPeers: [await node.endpoint],
                            peersFileURL: tempFileURL("peers.json"))
        await pool.start()

        let chain = try HeaderChain(params: synthetic.params)
        let sync = try FilterSync(pool: pool, chain: chain, startHeight: 1,
                                  storageURL: tempFileURL("progress.json"),
                                  requiredCheckpointPeers: 1)

        var thrown: (any Error)?
        do {
            try await sync.sync(watchScripts: [synthetic.watchScript]) { _ in }
        } catch {
            thrown = error
        }
        guard case let .badPeerResponse(reason)? = thrown as? FilterSyncError else {
            Issue.record("expected badPeerResponse, got \(String(describing: thrown))")
            return
        }
        // The peer is evicted rather than the sync being aborted on the spot,
        // so what remains is an empty checkpoint set — no peer answered about
        // the chain we asked about.
        #expect(reason.contains("no peer answered"))
        #expect(await sync.nextScanHeight == 1)
        // The peer is dropped, not merely disbelieved for this request.
        #expect(await pool.connectedPeers().isEmpty)

        await pool.stop()
    }

    /// The case that proves eviction is the right response rather than
    /// throwing: one peer answers about a different chain while two answer
    /// honestly. Aborting on the first bad reply would fail a sync that two
    /// honest peers could have completed — handing any single hostile peer a
    /// denial of service.
    @Test("one peer lying about the stop hash does not stop two honest peers syncing")
    func mixedStopHashLieStillSyncs() async throws {
        let synthetic = Self.chain()
        let honestA = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        let honestB = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        let liar = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                cfcheckptStopHashOverride: Data(repeating: 0xAB, count: 32))
        let nodes = [honestA, honestB, liar]
        for node in nodes { try await node.start() }
        defer { for node in nodes { Task { await node.stop() } } }

        let liarEndpoint = await liar.endpoint
        let pool = PeerPool(params: synthetic.params, peerCount: 3,
                            manualPeers: await Self.endpoints(nodes),
                            peersFileURL: tempFileURL("peers.json"))
        await pool.start()
        #expect(await pool.connectedPeers().count == 3)

        let chain = try HeaderChain(params: synthetic.params)
        let sync = try FilterSync(pool: pool, chain: chain, startHeight: 1,
                                  storageURL: tempFileURL("progress.json"),
                                  requiredCheckpointPeers: 3)
        let collector = MatchCollector()
        try await sync.sync(watchScripts: [synthetic.watchScript]) { collector.add($0) }

        #expect(collector.matches.count == 1)
        #expect(await sync.lastScannedHeight == 1_001)
        #expect(await Self.connectedEndpoints(pool).contains(liarEndpoint.description) == false)

        await pool.stop()
    }

    /// The same lie with three peers agreeing on it. Unanimity is exactly the
    /// case a majority tally cannot see, which is why the guard is per-reply.
    @Test("three peers unanimously answering about a different chain are still refused")
    func unanimousStopHashMismatchRefused() async throws {
        let synthetic = Self.chain()
        let wrong = Data(repeating: 0xAB, count: 32)
        let nodes = (0 ..< 3).map { _ in
            LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                         cfcheckptStopHashOverride: wrong)
        }
        for node in nodes { try await node.start() }
        defer { for node in nodes { Task { await node.stop() } } }

        let pool = PeerPool(params: synthetic.params, peerCount: 3,
                            manualPeers: await Self.endpoints(nodes),
                            peersFileURL: tempFileURL("peers.json"))
        await pool.start()

        let chain = try HeaderChain(params: synthetic.params)
        let sync = try FilterSync(pool: pool, chain: chain, startHeight: 1,
                                  storageURL: tempFileURL("progress.json"),
                                  requiredCheckpointPeers: 3)

        var thrown: (any Error)?
        do {
            try await sync.sync(watchScripts: [synthetic.watchScript]) { _ in }
        } catch {
            thrown = error
        }
        // Assert the specific reason, not merely that something threw: with a
        // bare `is FilterSyncError` check this test would still pass if the
        // sync failed for an unrelated reason and the guard had been removed.
        guard case let .badPeerResponse(reason)? = thrown as? FilterSyncError else {
            Issue.record("expected badPeerResponse, got \(String(describing: thrown))")
            return
        }
        #expect(reason.contains("no peer answered"))
        #expect(await sync.nextScanHeight == 1)

        await pool.stop()
    }

    // Not covered: the `noPeers` throw inside `approved(peers:)`, which fires
    // only when every approved peer disconnects *between* batches. Killing a
    // node mid-scan does not reach it — the in-flight request fails on the
    // transport first, 30 seconds later — and there is no hook between a batch
    // persisting and the next one starting. Left untested rather than covered
    // by a test that would pass for the wrong reason.

    // MARK: - Positive control

    /// Without this, every refusal above could be explained by the sync simply
    /// never working on a chain this long.
    @Test("three honest peers agree and the scan completes")
    func threeHonestPeersSync() async throws {
        let synthetic = Self.chain()
        let nodes = (0 ..< 3).map { _ in
            LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        }
        for node in nodes { try await node.start() }
        defer { for node in nodes { Task { await node.stop() } } }

        let pool = PeerPool(params: synthetic.params, peerCount: 3,
                            manualPeers: await Self.endpoints(nodes),
                            peersFileURL: tempFileURL("peers.json"))
        await pool.start()

        let chain = try HeaderChain(params: synthetic.params)
        let sync = try FilterSync(pool: pool, chain: chain, startHeight: 1,
                                  storageURL: tempFileURL("progress.json"),
                                  requiredCheckpointPeers: 3)
        let collector = MatchCollector()
        try await sync.sync(watchScripts: [synthetic.watchScript]) { collector.add($0) }

        #expect(collector.matches.count == 1)
        #expect(await sync.lastScannedHeight == 1_001)
        #expect(await sync.filterHeader(at: 1_000) != nil)
        #expect(await pool.connectedPeers().count == 3)

        await pool.stop()
    }
}
