import Foundation
import Testing
import TestSupport
@testable import WalletCore

/// What FilterSync does when a peer is not telling the truth (epic #100,
/// invariant S5).
///
/// BIP157 filters are not committed to by consensus, so a peer can serve a
/// self-consistent but wrong filter-commitment chain and nothing in the block
/// headers contradicts it. The only defence is comparing peers, and every
/// section below is one layer of that: the cfcheckpt majority rule on a chain
/// long enough to reach a checkpoint, the per-batch cfheaders cross-check on a
/// six-block chain where the checkpoint lists are empty for everyone, the
/// selection that decides *which* peers are compared, and a peer that hangs up
/// rather than answering at all.
///
/// Merged from `CheckpointMajorityTests`, `PeerDisagreementTests`,
/// `CrossSourceCheckTests` and `CheckpointHangupTests`, in that order. Of the
/// four, only `CheckpointHangupTests` carried a trait; the merged suite keeps
/// its `.timeLimit(.minutes(3))`, which is the strictest of the four.
///
/// These use a real 1,001-block chain and the real interval rather than making
/// `checkpointInterval` injectable. Configuring the constant would prove the
/// decision function works on a number of our choosing; it would not prove the
/// wire-to-policy path a real peer travels.
@Suite("FilterSync adversaries", .timeLimit(.minutes(3)))
struct FilterSyncAdversaryTests {

    // MARK: - The pool every socket-backed case here builds

    /// The stop hash a lying node answers about instead of the one it was
    /// asked about.
    private static let wrongStopHash = Data(repeating: 0xAB, count: 32)

    /// How one node in a fixture misbehaves. `nil` in a fixture's `liars`
    /// array is an honest node serving the whole chain.
    private enum CheckpointLie {
        /// A complete, internally consistent, and wrong filter-commitment
        /// chain, so the client's own arithmetic cannot catch it. The salt
        /// distinguishes one liar's fabrication from another's: with a single
        /// fixed lie two liars agree and form a majority *for the lie* rather
        /// than making a three-way split (#129).
        case filterCommitments(salt: UInt8)
        /// Answers every getcfcheckpt with `wrongStopHash` — a peer replying
        /// about a different chain.
        case stopHash
        case checkpointCount(delta: Int)
        /// Serves only the first `blocks` blocks and hangs up when asked about
        /// a block it does not have, which is what Bitcoin Core does with a
        /// getcfcheckpt for an unknown stop hash.
        case behindAndHangsUp(blocks: Int)
        /// An honest cfheaders/cfilters chain announced with a fabricated
        /// cfcheckpt header at this height: the peer's checkpoint answer
        /// contradicts the commitments it serves. Every filter still
        /// reproduces the header chain the peer sent, so only the comparison
        /// against cfcheckpt can catch it.
        case checkpointHeader(wrongAt: Int)
    }

    /// Everything one case needs: the started nodes, the pool seated on them,
    /// and a FilterSync wired to both.
    private struct CheckpointFixture {
        let synthetic: SyntheticChain
        let nodes: [LoopbackNode]
        /// Node order, which is also `manualPeers` order.
        let endpoints: [PeerEndpoint]
        let liarEndpoints: [PeerEndpoint]
        let honestEndpoints: [PeerEndpoint]
        let peersFile: URL
        let progressFile: URL
        let pool: PeerPool
        let chain: HeaderChain
        let sync: FilterSync

        /// The fire-and-forget teardown each case used to write inline.
        func stopNodes() { for node in nodes { Task { await node.stop() } } }
    }

    private static func makeNode(params: NetworkParams, blocks: [Block],
                                 lie: CheckpointLie?, versionDelay: Duration) -> LoopbackNode {
        switch lie {
        case .none:
            return LoopbackNode(params: params, chain: blocks, versionDelay: versionDelay)
        case let .filterCommitments(salt):
            return LoopbackNode(params: params, chain: blocks,
                                lieAboutFilterCommitments: true, lieSalt: salt,
                                versionDelay: versionDelay)
        case let .checkpointCount(delta):
            return LoopbackNode(params: params, chain: blocks,
                                cfcheckptCountDelta: delta, versionDelay: versionDelay)
        case .stopHash:
            return LoopbackNode(params: params, chain: blocks,
                                cfcheckptStopHashOverride: wrongStopHash,
                                versionDelay: versionDelay)
        case let .behindAndHangsUp(count):
            return LoopbackNode(params: params, chain: Array(blocks.prefix(count)),
                                disconnectOnUnknownStopHash: true,
                                versionDelay: versionDelay)
        case let .checkpointHeader(height):
            return LoopbackNode(params: params, chain: blocks,
                                cfcheckptLieAtHeight: height,
                                versionDelay: versionDelay)
        }
    }

    /// The three-node pool these cases were each building by hand.
    ///
    /// Every socket-backed case below wired the same thing: N loopback nodes
    /// on one synthetic chain, started; a pool with `peerCount` and
    /// `requiredCheckpointPeers` both N, seated on them in node order, with a
    /// temp peers file; a fresh HeaderChain; and a FilterSync from height 1
    /// with its progress in a temp file. `liars` carries one entry per node —
    /// `nil` for honest — so the node count follows it: three for most cases,
    /// two or one where the case is about a pool that small.
    ///
    /// `delays` pins dial-completion order, which is peer order, for the cases
    /// that depend on which peer is seated first. `chainLength` is 1,001 —
    /// past the checkpoint interval — except where a case wants the six-block
    /// chain on which every peer's cfcheckpt list is empty.
    ///
    /// The default `watchHeight: 3` gives exactly one match, which is how
    /// these cases prove the sync really ran rather than exiting early.
    private static func threePeerFixture(liars: [CheckpointLie?],
                                         delays: [Duration] = [],
                                         chainLength: Int = 1_001,
                                         watchHeight: UInt32 = 3,
                                         policy: FilterSync.CrossCheckPolicy = .acceptSingleSource)
        async throws -> CheckpointFixture {
        let synthetic = makeSyntheticChain(length: chainLength, watchHeight: watchHeight)
        let padded = delays + Array(repeating: Duration.zero,
                                    count: max(0, liars.count - delays.count))
        var nodes: [LoopbackNode] = []
        for (lie, delay) in zip(liars, padded) {
            nodes.append(makeNode(params: synthetic.params, blocks: synthetic.blocks,
                                  lie: lie, versionDelay: delay))
        }
        for node in nodes { try await node.start() }
        var endpoints: [PeerEndpoint] = []
        for node in nodes { endpoints.append(await node.endpoint) }

        let peersFile = tempFileURL("peers.json")
        let pool = PeerPool(params: synthetic.params, peerCount: liars.count,
                            manualPeers: endpoints, peersFileURL: peersFile)
        await pool.start()
        let chain = try HeaderChain(params: synthetic.params)
        let progressFile = tempFileURL("progress.json")
        let sync = try FilterSync(pool: pool, chain: chain, startHeight: 1,
                                  storageURL: progressFile,
                                  requiredCheckpointPeers: liars.count,
                                  crossCheckPolicy: policy)
        return CheckpointFixture(
            synthetic: synthetic,
            nodes: nodes,
            endpoints: endpoints,
            liarEndpoints: zip(liars, endpoints).filter { $0.0 != nil }.map { $0.1 },
            honestEndpoints: zip(liars, endpoints).filter { $0.0 == nil }.map { $0.1 },
            peersFile: peersFile,
            progressFile: progressFile,
            pool: pool,
            chain: chain,
            sync: sync)
    }

    /// `threePeerFixture` with the pool deliberately split across acquisition
    /// channels: `sources` names the class each node is reached through, so a
    /// case can say "two channels" and mean it rather than infer it from a
    /// pool that happens to be diverse. Every peer in the fixture above is
    /// manual, which is one channel however many nodes it has.
    ///
    /// Only `.manual` and `.persisted` are buildable without a network, and
    /// they are built the way `secondClassIsQueried` already builds them:
    /// manual nodes go in `manualPeers`, persisted ones are written to the
    /// peers file before the pool starts. A persisted node answers its
    /// handshake late so it is seated last, which is what makes a case about
    /// selection order fail every run rather than one in three.
    private static func mixedSourceFixture(sources: [PeerSource],
                                           liars: [CheckpointLie?]? = nil,
                                           chainLength: Int = 1_001,
                                           watchHeight: UInt32 = 3,
                                           checkpointPeers: Int? = nil,
                                           policy: FilterSync.CrossCheckPolicy)
        async throws -> CheckpointFixture {
        let lies = liars ?? Array(repeating: nil, count: sources.count)
        let synthetic = makeSyntheticChain(length: chainLength, watchHeight: watchHeight)
        var nodes: [LoopbackNode] = []
        for (lie, source) in zip(lies, sources) {
            nodes.append(makeNode(params: synthetic.params, blocks: synthetic.blocks, lie: lie,
                                  versionDelay: source == .manual ? .zero : .milliseconds(300)))
        }
        for node in nodes { try await node.start() }
        var endpoints: [PeerEndpoint] = []
        for node in nodes { endpoints.append(await node.endpoint) }

        let peersFile = tempFileURL("mixed-source-peers.json")
        let remembered = zip(sources, endpoints)
            .filter { $0.0 != .manual }
            .map { PeerCandidate(endpoint: $0.1, source: $0.0) }
        try JSONEncoder().encode(PersistedPeers(remembered)).write(to: peersFile)

        let pool = PeerPool(params: synthetic.params, peerCount: sources.count,
                            manualPeers: zip(sources, endpoints).filter { $0.0 == .manual }.map(\.1),
                            peersFileURL: peersFile)
        await pool.start()
        let chain = try HeaderChain(params: synthetic.params)
        let progressFile = tempFileURL("mixed-source-progress.json")
        let sync = try FilterSync(pool: pool, chain: chain, startHeight: 1,
                                  storageURL: progressFile,
                                  requiredCheckpointPeers: checkpointPeers ?? sources.count,
                                  crossCheckPolicy: policy)
        return CheckpointFixture(
            synthetic: synthetic,
            nodes: nodes,
            endpoints: endpoints,
            liarEndpoints: zip(lies, endpoints).filter { $0.0 != nil }.map(\.1),
            honestEndpoints: zip(lies, endpoints).filter { $0.0 == nil }.map(\.1),
            peersFile: peersFile,
            progressFile: progressFile,
            pool: pool,
            chain: chain,
            sync: sync)
    }

    /// The progress on disk, which is what survives a crash — read straight
    /// from the file rather than from the actor, so a test can say the two
    /// agree instead of asking the same source twice.
    private static func storedProgress(_ url: URL) throws -> FilterSync.Progress {
        try JSONDecoder().decode(FilterSync.Progress.self, from: Data(contentsOf: url))
    }

    private static func connectedEndpoints(_ pool: PeerPool) async -> Set<String> {
        var result: Set<String> = []
        for peer in await pool.connectedPeers() { result.insert(await peer.endpoint.description) }
        return result
    }

    @Test("short and extra checkpoint lists fail before callbacks or publication", arguments: [-1, 1])
    func invalidCheckpointCount(delta: Int) async throws {
        let fixture = try await Self.threePeerFixture(liars: [.checkpointCount(delta: delta)])
        let pool = fixture.pool
        defer { fixture.stopNodes(); Task { await pool.stop() } }
        let matches = MatchCollector()
        await #expect(throws: FilterSyncError.self) {
            try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) { matches.add($0) }
        }
        #expect(matches.matches.isEmpty)
        #expect(await fixture.sync.nextScanHeight == 1)
        #expect(!FileManager.default.fileExists(atPath: fixture.progressFile.path))
        #expect(await fixture.nodes[0].receivedMessages.allSatisfy { $0.command != "getcfilters" })
    }

    @Test("a malformed checkpoint list cannot block honest peers", arguments: [-1, 1])
    func invalidCheckpointCountWithHonestPeers(delta: Int) async throws {
        let fixture = try await Self.threePeerFixture(liars: [.checkpointCount(delta: delta), nil, nil])
        let pool = fixture.pool
        defer { fixture.stopNodes(); Task { await pool.stop() } }
        let matches = MatchCollector()
        try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) { matches.add($0) }
        #expect(matches.matches.count == 1)
        #expect(await fixture.sync.nextScanHeight == 1_002)
        #expect(await fixture.pool.rejectionReason(fixture.liarEndpoints[0]) == "cfcheckpt count mismatch")
    }

    @Test("a deep rollback reconstructs from a surviving pin before scanning", arguments: [false, true])
    func deepRollbackReconstruction(liar: Bool) async throws {
        let fixture = try await Self.threePeerFixture(
            liars: [liar ? .filterCommitments(salt: 0xFF) : nil], watchHeight: 750)
        let pool = fixture.pool
        defer { fixture.stopNodes(); Task { await pool.stop() } }
        // A pruned store whose original anchor is honest, but whose fork
        // height (500) no longer has a pin. Everything after 500 is orphaned.
        let genesis = fixture.synthetic.blocks[0]
        let items = genesis.transactions.flatMap { $0.outputs.map(\.scriptPubKey) }
        let filter = try GCSFilter(items: items, key: genesis.hash.prefix(16)).serialized
        let anchor = SHA256d.hash(GCSFilter.filterHash(filter) + Data(repeating: 0, count: 32))
        try await fixture.sync.recordProgressForTest(nextScanHeight: 1_002,
            filterHeaders: ["0": anchor.hex, "1000": Data(repeating: 1, count: 32).hex])
        try await fixture.sync.rollBack(to: 500)
        // Reopen at the wallet's actual frontier, proving reconstruction
        // doesn't require lying about or lowering the persisted wallet height.
        let resumed = try FilterSync(pool: pool, chain: fixture.chain, startHeight: 501,
                                      storageURL: fixture.progressFile)
        let before = try Data(contentsOf: fixture.progressFile)
        let matches = MatchCollector()
        if liar {
            await #expect(throws: FilterSyncError.filterHeaderMismatch(height: 1)) {
                try await resumed.sync(watchScripts: [fixture.synthetic.watchScript]) { matches.add($0) }
            }
            #expect(matches.matches.isEmpty)
            #expect(await resumed.nextScanHeight == 501)
            #expect(try Data(contentsOf: fixture.progressFile) == before)
            #expect(await fixture.nodes[0].receivedMessages.allSatisfy { $0.command != "getcfilters" })
        } else {
            try await resumed.sync(watchScripts: [fixture.synthetic.watchScript]) { matches.add($0) }
            #expect(matches.matches.map(\.height) == [750])
            #expect(await resumed.nextScanHeight == 1_002)
            let requests = await fixture.nodes[0].receivedMessages.compactMap { message -> UInt32? in
                if case let .getcfilters(request) = message { return request.startHeight }
                return nil
            }
            #expect(requests.first == 501, "reconstruct headers without replaying old payment callbacks")
        }
    }

    // MARK: - cfcheckpt majority

    // The BIP157 cfcheckpt majority rule, actually exercised (epic #100, S5).
    //
    // `FilterSync` adopts the *majority* cfcheckpt answer rather than the
    // first reply, and the reasoning is written out in the source: a first
    // reply adopted by fiat would let one lying peer evict the honest ones and
    // become the sole reference. Until now nothing ran that code. Checkpoints
    // are served every 1,000 blocks, so every existing loopback chain — six
    // blocks — had all peers return an *empty* checkpoint list. Identical
    // lists agree, the tally is unanimous, and the majority branch was never
    // entered. A mutation removing the rule outright killed no test (#129).

    // MARK: The rule adopts the majority and evicts the liar

    @Test("two honest peers outvote one liar, which is evicted while the sync completes")
    func majorityOfThreeAdoptsHonestCheckpoints() async throws {
        let fixture = try await Self.threePeerFixture(liars: [nil, nil, .filterCommitments(salt: 0xFF)])
        defer { fixture.stopNodes() }
        let liarEndpoint = fixture.liarEndpoints[0]
        #expect(await fixture.pool.connectedPeers().count == 3)

        let collector = MatchCollector()
        try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) { collector.add($0) }

        // The honest answer was adopted: the scan finished and the checkpoint
        // height carries a pinned header.
        #expect(collector.matches.count == 1)
        #expect(await fixture.sync.lastScannedHeight == 1_001)
        #expect(await fixture.sync.filterHeader(at: 1_000) != nil)

        // And the minority peer is gone. This is the half that matters: a rule
        // that adopted the majority but kept the liar connected would leave it
        // free to serve filters for the rest of the session.
        #expect(await Self.connectedEndpoints(fixture.pool).contains(liarEndpoint.description) == false)

        await fixture.pool.stop()
    }

    // MARK: No majority is a refusal, not a tie-break

    @Test("three peers that all disagree fail closed without advancing the scan")
    func threeWaySplitFailsClosed() async throws {
        // Three mutually inconsistent answers: one honest, two liars whose
        // fabrications differ. With a single fixed lie the two liars would
        // agree and form a majority *for the lie* — the opposite of this test.
        let fixture = try await Self.threePeerFixture(
            liars: [nil, .filterCommitments(salt: 0xFF), .filterCommitments(salt: 0x0F)])
        defer { fixture.stopNodes() }
        #expect(await fixture.pool.connectedPeers().count == 3)

        var thrown: (any Error)?
        do {
            try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) { _ in }
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
        #expect(await fixture.pool.connectedPeers().isEmpty)
        // And nothing was scanned: the refusal happens before any batch.
        #expect(await fixture.sync.nextScanHeight == 1)

        await fixture.pool.stop()
    }

    /// Two peers cannot produce a strict majority, so a disagreement between
    /// them is the no-majority case rather than an eviction. Above height 1,000
    /// this is caught by the checkpoint rule; the six-block case in the peer
    /// disagreement section below catches the same lie one layer down, at the
    /// per-batch cfheaders cross-check, because there the checkpoint lists are
    /// both empty.
    @Test("two disagreeing peers are a no-majority refusal above the checkpoint interval")
    func twoPeersCannotFormAMajority() async throws {
        let fixture = try await Self.threePeerFixture(liars: [nil, .filterCommitments(salt: 0xFF)])
        defer { fixture.stopNodes() }
        #expect(await fixture.pool.connectedPeers().count == 2)

        var thrown: (any Error)?
        do {
            try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) { _ in }
        } catch {
            thrown = error
        }
        guard case let .checkpointMismatch(reason)? = thrown as? FilterSyncError else {
            Issue.record("expected checkpointMismatch, got \(String(describing: thrown))")
            return
        }
        #expect(reason.contains("no cfcheckpt majority across 2 peers"))
        #expect(await fixture.sync.nextScanHeight == 1)

        await fixture.pool.stop()
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
        let fixture = try await Self.threePeerFixture(
            liars: [.filterCommitments(salt: 0xFF), nil, nil],
            delays: [.zero, .milliseconds(150), .milliseconds(250)])
        defer { fixture.stopNodes() }
        let liarEndpoint = fixture.liarEndpoints[0]
        #expect(await fixture.pool.connectedPeers().count == 3)
        // Precondition for what this test is actually about.
        let first = await fixture.pool.connectedPeers().first
        #expect(await first?.endpoint.description == liarEndpoint.description,
                "fixture precondition: the liar must be first in the peer list")

        let collector = MatchCollector()
        try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) { collector.add($0) }

        #expect(collector.matches.count == 1)
        #expect(await fixture.sync.lastScannedHeight == 1_001)
        #expect(await Self.connectedEndpoints(fixture.pool).contains(liarEndpoint.description) == false)

        await fixture.pool.stop()
    }

    // MARK: The reply must answer the question that was asked

    /// A peer that echoes a different stop hash is answering about some other
    /// chain. The tally cannot catch this on its own: with one peer there is
    /// nothing to compare against, and peers that agree on a wrong stop hash
    /// agree unanimously. `pinFilterHeaders` has always validated its own stop
    /// hash; the checkpoint path had not.
    @Test("a cfcheckpt answering about a different chain is refused, even from a lone peer")
    func stopHashMismatchRefused() async throws {
        let fixture = try await Self.threePeerFixture(liars: [.stopHash])
        defer { fixture.stopNodes() }

        var thrown: (any Error)?
        do {
            try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) { _ in }
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
        #expect(await fixture.sync.nextScanHeight == 1)
        // The peer is dropped, not merely disbelieved for this request.
        #expect(await fixture.pool.connectedPeers().isEmpty)

        await fixture.pool.stop()
    }

    /// The case that proves eviction is the right response rather than
    /// throwing: one peer answers about a different chain while two answer
    /// honestly. Aborting on the first bad reply would fail a sync that two
    /// honest peers could have completed — handing any single hostile peer a
    /// denial of service.
    @Test("one peer lying about the stop hash does not stop two honest peers syncing")
    func mixedStopHashLieStillSyncs() async throws {
        let fixture = try await Self.threePeerFixture(liars: [nil, nil, .stopHash])
        defer { fixture.stopNodes() }
        let liarEndpoint = fixture.liarEndpoints[0]
        #expect(await fixture.pool.connectedPeers().count == 3)

        let collector = MatchCollector()
        try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) { collector.add($0) }

        #expect(collector.matches.count == 1)
        #expect(await fixture.sync.lastScannedHeight == 1_001)
        #expect(await Self.connectedEndpoints(fixture.pool).contains(liarEndpoint.description) == false)

        await fixture.pool.stop()
    }

    /// The same lie with three peers agreeing on it. Unanimity is exactly the
    /// case a majority tally cannot see, which is why the guard is per-reply.
    @Test("three peers unanimously answering about a different chain are still refused")
    func unanimousStopHashMismatchRefused() async throws {
        let fixture = try await Self.threePeerFixture(liars: [.stopHash, .stopHash, .stopHash])
        defer { fixture.stopNodes() }

        var thrown: (any Error)?
        do {
            try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) { _ in }
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
        #expect(await fixture.sync.nextScanHeight == 1)

        await fixture.pool.stop()
    }

    // Not covered: the `noPeers` throw inside `approved(peers:)`, which fires
    // only when every approved peer disconnects *between* batches. Killing a
    // node mid-scan does not reach it — the in-flight request fails on the
    // transport first, 30 seconds later — and there is no hook between a batch
    // persisting and the next one starting. Left untested rather than covered
    // by a test that would pass for the wrong reason.

    // MARK: Positive control

    /// Without this, every refusal above could be explained by the sync simply
    /// never working on a chain this long.
    ///
    /// It is also the regression test for a bug the differential harness
    /// caught: Core's ProcessGetCFCheckPt returns headers at heights 1000,
    /// 2000, … ascending — never the stop block itself. FilterSync used to map
    /// the first header onto the tip and reject every sync past height 1000,
    /// so cfcheckpt headers mapping to checkpoint multiples rather than the
    /// tip (Core semantics) is what the pinned header at 1,000 proves.
    @Test("three honest peers agree and the scan completes")
    func threeHonestPeersSync() async throws {
        let fixture = try await Self.threePeerFixture(liars: [nil, nil, nil])
        defer { fixture.stopNodes() }

        let collector = MatchCollector()
        try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) { collector.add($0) }

        #expect(collector.matches.count == 1)
        #expect(await fixture.sync.lastScannedHeight == 1_001)
        // The single checkpoint (height 1000) was pinned and cross-checked.
        #expect(await fixture.sync.filterHeader(at: 1_000) != nil)
        #expect(await fixture.pool.connectedPeers().count == 3)

        await fixture.pool.stop()
    }

    // MARK: A batch commits only after its own checkpoint comparison

    /// A peer whose cfcheckpt answer contradicts the commitments it serves,
    /// on a chain long enough for two batches: the boundary at 1,000 is
    /// announced honestly and the one at 2,000 is not.
    ///
    /// The first batch passes its comparison and commits; the second is
    /// refused. What the refusal leaves behind is the point. The comparison
    /// used to run once, at the end of the sync, by which time every batch had
    /// already handed its matches to the caller and persisted its progress —
    /// so a chain that failed its checkpoint had nonetheless altered the
    /// wallet. The watched output sits at height 1,500, inside the batch that
    /// fails, so effects applied ahead of the comparison show up as a match
    /// the caller should never have seen.
    @Test("a batch whose checkpoint comparison fails delivers no match and persists nothing")
    func refusedBatchLeavesEverythingAsItWas() async throws {
        let fixture = try await Self.threePeerFixture(liars: [.checkpointHeader(wrongAt: 2_000)],
                                                      chainLength: 2_001,
                                                      watchHeight: 1_500)
        defer { fixture.stopNodes() }

        let collector = MatchCollector()
        var thrown: (any Error)?
        do {
            try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) {
                collector.add($0)
            }
        } catch {
            thrown = error
        }
        // The specific reason, not merely that something threw: the sync ends
        // in an error either way, and only the reason says which comparison
        // stopped it.
        guard case let .checkpointMismatch(reason)? = thrown as? FilterSyncError else {
            Issue.record("expected checkpointMismatch, got \(String(describing: thrown))")
            return
        }
        #expect(reason.contains("pinned header at 2000"))

        // Nothing from the refused batch was applied, and everything from the
        // batch that passed still was.
        #expect(collector.matches.isEmpty, "a refused batch must not deliver its matches")
        #expect(await fixture.sync.nextScanHeight == 1_001,
                "the frontier stands where the batch that passed left it")
        #expect(await fixture.sync.filterHeader(at: 1_000) != nil,
                "the batch that passed its comparison still committed")
        #expect(await fixture.sync.filterHeader(at: 1_001) == nil,
                "no header from the refused batch was pinned")

        // The file says the same thing the actor does. This is the state a
        // relaunch would resume from, so it is the one that has to be clean.
        let before = try Self.storedProgress(fixture.progressFile)
        #expect(before.nextScanHeight == 1_001)
        #expect(before.filterHeaders == (await fixture.sync.pinnedFilterHeadersForTest))

        // And retrying the same batch is the same refusal: state before the
        // second attempt equals state after it, with nothing accumulated in
        // between. The peer keeps its seat through a checkpoint refusal, so
        // this really is the same batch being attempted again.
        var again: (any Error)?
        do {
            try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) {
                collector.add($0)
            }
        } catch {
            again = error
        }
        guard case let .checkpointMismatch(secondReason)? = again as? FilterSyncError,
              secondReason.contains("pinned header at 2000")
        else {
            Issue.record("expected the same refusal, got \(String(describing: again))")
            return
        }
        #expect(collector.matches.isEmpty)
        #expect(await fixture.sync.nextScanHeight == 1_001)
        #expect(try Self.storedProgress(fixture.progressFile) == before,
                "a second refusal of the same batch must leave the file untouched too")

        await fixture.pool.stop()
    }

    /// The other half: a comparison that passes commits exactly what its
    /// batch staged. Without this, the case above would also be satisfied by
    /// a guard that refused everything.
    @Test("a batch whose checkpoint comparison passes commits exactly its own effects")
    func passingBatchCommitsWhatItStaged() async throws {
        let fixture = try await Self.threePeerFixture(liars: [nil])
        defer { fixture.stopNodes() }

        let collector = MatchCollector()
        try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) {
            collector.add($0)
        }

        #expect(collector.matches.map(\.height) == [3])
        #expect(await fixture.sync.nextScanHeight == 1_002)
        let stored = try Self.storedProgress(fixture.progressFile)
        #expect(stored.nextScanHeight == 1_002)
        #expect(stored.filterHeaders == (await fixture.sync.pinnedFilterHeadersForTest),
                "the persisted progress is the frontier the sync reports, not a lagging copy")
        #expect(stored.filterHeaders["1000"] != nil,
                "the boundary the comparison covered is pinned")

        await fixture.pool.stop()
    }

    // MARK: - Peer disagreement

    // What happens when peers disagree, and what happens when there is nobody
    // to disagree with. The lying node keeps its block headers honest and
    // rebuilds a complete, internally consistent filter-commitment chain, so
    // it cannot be caught by the client's own arithmetic. Only another peer
    // catches it.

    /// Two peers that disagree give no majority. The lie is unattributable —
    /// either one could be the liar — so the sync must fail closed rather than
    /// pick a side, and must blame nobody.
    @Test("two peers disagreeing about filter commitments fails closed")
    func twoWayDisagreementFailsClosed() async throws {
        let fixture = try await Self.threePeerFixture(liars: [nil, .filterCommitments(salt: 0xFF)],
                                                      chainLength: 6)
        defer { fixture.stopNodes() }
        let endpoints = fixture.endpoints
        let peersFile = fixture.peersFile
        #expect(await fixture.pool.connectedPeers().count == 2)

        // The specific error matters: a bare "some FilterSyncError" would also
        // pass if the cross-check were gone and the lie were caught by
        // something weaker downstream.
        //
        // Note which defence fires here. Checkpoints are served every 1000
        // blocks, so on a six-block chain both peers return an *empty*
        // cfcheckpt list — identical, no disagreement — and the cfcheckpt
        // majority rule never engages. The defence that catches this lie is
        // the per-batch cfheaders cross-check, which is exactly why this test
        // stays at six blocks: it is the control for that layer.
        //
        // The majority rule itself is exercised in the section above, on a
        // 1,001-block chain that actually crosses the interval (#129).
        do {
            try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) { _ in }
            Issue.record("a two-way disagreement was accepted")
        } catch let error as FilterSyncError {
            guard case let .checkpointMismatch(reason) = error,
                  reason.contains("cfheaders disagree")
            else {
                Issue.record("caught \(error) rather than a cfheaders disagreement")
                return
            }
        }
        // Nothing was pinned from a disputed answer.
        #expect(await fixture.sync.nextScanHeight == 1,
                "a disputed filter view must not advance the scan frontier")
        // And nobody was banned for it. A 1–1 split cannot say which peer
        // lied, so both are cooled off — the rest a slow peer gets — rather
        // than one of them condemned for having connected second (#26).
        for endpoint in endpoints {
            #expect(await fixture.pool.coolingEndpoints.contains(endpoint),
                    "an unattributable disagreement cools \(endpoint) off, not bans it")
            #expect(await fixture.pool.rejectionReason(endpoint)?.contains("cfheaders disagree") == true)
        }
        await fixture.pool.stop()
        // Cooled, not condemned: both survive in the persisted good-peers
        // file, which `misbehaving` would have struck them from.
        #expect(try PeerPoolTests.storedPeers(peersFile) == Set(endpoints),
                "a tie must not strike either peer from the peers file")
    }

    /// The fix for #26: a liar seated *first*. The cfheaders cross-check kept
    /// the first reply as its reference and evicted whoever contradicted it
    /// later, so seating order decided blame — the liar became the reference
    /// and an honest peer was banned, struck from the persisted good-peers
    /// file, for telling the truth. Judged by majority, the liar is the one
    /// that goes and the sync completes on the honest answer.
    ///
    /// Six blocks, so cfcheckpt is empty for everyone and only the cfheaders
    /// layer can catch the lie (see above). Peer order is dial-completion
    /// order, so the liar is pinned to the front by delaying the honest
    /// nodes' handshakes, as the checkpoint majority section does.
    @Test("a liar seated first is the one evicted, not the honest peer that contradicts it")
    func liarFirstIsTheOneEvicted() async throws {
        let fixture = try await Self.threePeerFixture(
            liars: [.filterCommitments(salt: 0xFF), nil, nil],
            delays: [.zero, .milliseconds(150), .milliseconds(250)],
            chainLength: 6)
        defer { fixture.stopNodes() }
        let liarEndpoint = fixture.liarEndpoints[0]
        let honestEndpoints = fixture.honestEndpoints
        let peersFile = fixture.peersFile
        #expect(await fixture.pool.connectedPeers().count == 3)
        // Precondition for what this test is actually about.
        let first = await fixture.pool.connectedPeers().first
        #expect(await first?.endpoint.description == liarEndpoint.description,
                "fixture precondition: the liar must be first in the peer list")

        let collector = MatchCollector()
        try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) { collector.add($0) }

        // The honest answer was adopted and the scan ran to the tip.
        #expect(collector.matches.count == 1)
        #expect(await fixture.sync.nextScanHeight == 7)

        // The liar is the one gone — banned, not rested, because two peers
        // outvoting it makes the lie attributable — and both honest peers
        // keep their seats.
        let connected = await Self.connectedEndpoints(fixture.pool)
        #expect(connected.contains(liarEndpoint.description) == false)
        for endpoint in honestEndpoints {
            #expect(connected.contains(endpoint.description),
                    "an honest peer was evicted for contradicting the liar")
        }
        #expect(await fixture.pool.rejectionReason(liarEndpoint)?.contains("cfheaders mismatch") == true)
        #expect(await fixture.pool.coolingEndpoints.contains(liarEndpoint) == false,
                "a ban is not a cooldown — it must not expire")
        await fixture.pool.stop()
        #expect(try PeerPoolTests.storedPeers(peersFile) == Set(honestEndpoints),
                "the liar is struck from the peers file; the honest peers stay")
    }

    // Positive control: the same two-peer setup with both peers honest syncs
    // normally, so the failure above is the disagreement being caught rather
    // than the two-peer path being broken. That is `FilterSyncTests.filterSync`,
    // which runs the full BIP157 flow with one peer and with two.

    /// The eclipse case, pinned as current behaviour rather than asserted as
    /// desirable.
    ///
    /// With one peer there is nobody to compare against, so `FilterSync`
    /// accepts that peer's filter view and advances. A wallet in this state
    /// has no corroboration and no indication of it. That is a deliberate
    /// degradation — failing closed would strand a user whose network reaches
    /// only one peer — but it is the sharpest boundary in a wallet whose whole
    /// claim is that it trusts no server, so it is recorded here rather than
    /// left implicit.
    @Test("a single peer is trusted without corroboration")
    func singlePeerIsTrustedUncorroborated() async throws {
        let fixture = try await Self.threePeerFixture(liars: [.filterCommitments(salt: 0xFF)],
                                                      chainLength: 6)
        defer { fixture.stopNodes() }

        // The lying commitment chain is self-consistent, so the only thing that
        // catches it is a second peer — and there is not one. The sync either
        // completes on the liar's view or fails on the filter bodies; what it
        // cannot do is detect the lie as a disagreement.
        let collector = MatchCollector()
        _ = try? await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) { collector.add($0) }
        #expect(await fixture.pool.connectedPeers().count <= 1)
        await fixture.pool.stop()
    }

    // MARK: - Cross-source cfheaders check

    // The cross-source half of #3: comparisons must span acquisition
    // channels.
    //
    // The diversity ceiling (#159) stops one source class owning the pool, but
    // the per-batch cfheaders cross-check took `prefix(2)` — whichever two
    // peers connected first — and the ceiling permits two seats from one
    // class. A DNS seed's answer compared against the same seed's other answer
    // is one channel agreeing with itself: the comparison the defence rests
    // on, hollowed out exactly when an attacker controls that channel.

    private func connection(_ index: UInt8) -> PeerConnection {
        PeerConnection(endpoint: PeerEndpoint(host: "10.0.\(index).1", port: 1),
                       params: .signet)
    }

    // MARK: The pure selection policy

    @Test("two classes present: the set spans them before it repeats one")
    func setSpansClasses() {
        let a = connection(1), b = connection(2), c = connection(3)
        let picked = FilterSync.crossSourceSet([(a, .dnsSeed), (b, .dnsSeed), (c, .persisted)])
        #expect(picked.count == 3)
        #expect(picked[0] === a)
        #expect(picked[1] === c, "the second same-class peer must be passed over for the other channel")
        #expect(picked[2] === b, "and then taken: a third answer is what lets a tally name a liar")
    }

    @Test("three classes present: one seat each, the same-class repeat left out")
    func threeClassesEachGetASeat() {
        let a = connection(1), b = connection(2), c = connection(3), d = connection(4)
        let picked = FilterSync.crossSourceSet(
            [(a, .dnsSeed), (b, .dnsSeed), (c, .persisted), (d, .census)])
        #expect(picked.count == 3)
        #expect(picked[0] === a && picked[1] === c && picked[2] === d,
                "a third class outranks a second seat for the anchor's class")
    }

    @Test("one class present: what there is, the degraded mode")
    func singleClassDegrades() {
        let a = connection(1), b = connection(2)
        let picked = FilterSync.crossSourceSet([(a, .dnsSeed), (b, .dnsSeed)])
        #expect(picked.count == 2, "same-class is degraded, not refused — like a single-peer pool")
        #expect(picked[0] === a && picked[1] === b)
    }

    @Test("an unknown source counts as its own channel")
    func unknownIsItsOwnClass() {
        let a = connection(1), b = connection(2), c = connection(3)
        let picked = FilterSync.crossSourceSet([(a, nil), (b, nil), (c, .census)])
        #expect(picked[1] === c, "known-vs-unknown is more diverse than unknown-vs-unknown")
    }

    @Test("one peer or none: what there is")
    func degenerateCounts() {
        let a = connection(1)
        #expect(FilterSync.crossSourceSet([]).isEmpty)
        #expect(FilterSync.crossSourceSet([(a, .manual)]).count == 1)
    }

    @Test("the limit is a ceiling, and no peer is seated twice")
    func limitIsACeiling() {
        let a = connection(1), b = connection(2), c = connection(3)
        let sourced: [(peer: PeerConnection, source: PeerSource?)] =
            [(a, .manual), (b, .manual), (c, .dnsSeed)]
        let two = FilterSync.crossSourceSet(sourced, limit: 2)
        #expect(two.count == 2)
        #expect(two[0] === a && two[1] === c, "the other channel still comes before the repeat")
        #expect(FilterSync.crossSourceSet(sourced, limit: 5).count == 3,
                "a ceiling, not a quota: three peers make a set of three")
    }

    // MARK: The wiring, on the wire

    /// Three honest peers: two manual, one persisted, with the persisted one
    /// deliberately last to connect. `prefix(2)` would query the two manuals
    /// and never the other channel; the selection must reach it.
    ///
    /// The one socket-backed case here that `threePeerFixture` does not build:
    /// its point is a pool split across two source classes, so the peers file
    /// is seeded before the pool starts and only two of the three nodes are
    /// manual.
    @Test("the cross-check reaches the second source class")
    func secondClassIsQueried() async throws {
        let synthetic = makeSyntheticChain(length: 6, watchHeight: 3)
        let manualA = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        let manualB = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        // The version delay makes the persisted peer the *last* to be seated,
        // so the pre-#3 prefix(2) deterministically never reaches it — which
        // is what makes the mutation of this test fail every run rather than
        // one run in three.
        let persisted = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                     versionDelay: .milliseconds(300))
        try await manualA.start()
        try await manualB.start()
        try await persisted.start()
        defer { Task { await manualA.stop(); await manualB.stop(); await persisted.stop() } }

        let peersFile = tempFileURL("cross-source-peers.json")
        let stored = PersistedPeers([PeerCandidate(endpoint: await persisted.endpoint,
                                                   source: .persisted)])
        try JSONEncoder().encode(stored).write(to: peersFile)

        let pool = PeerPool(params: synthetic.params, peerCount: 3,
                            manualPeers: [await manualA.endpoint, await manualB.endpoint],
                            peersFileURL: peersFile)
        await pool.start()
        #expect(await pool.connectedPeers().count == 3)
        #expect(await pool.source(of: persisted.endpoint) == .persisted)

        let chain = try HeaderChain(params: synthetic.params)
        let sync = try FilterSync(pool: pool, chain: chain, startHeight: 1,
                                  storageURL: tempFileURL("cross-source-progress.json"),
                                  requiredCheckpointPeers: 3)
        try await sync.sync(watchScripts: [synthetic.watchScript]) { _ in }

        #expect(await persisted.nextMessage(command: "getcfheaders", timeout: .seconds(2)) != nil,
                "the persisted channel was never asked — the cross-check compared one class with itself")
        await pool.stop()
    }

    // MARK: - The cross-check policy and its receipt

    // The half of #3 the selection above cannot reach.
    //
    // `crossSourceSet` prefers a set that spans classes, but it is a ceiling
    // and not a quota, and the three tests above pin that on purpose: one
    // class is used, not refused. Two ordinary pool states make the whole
    // comparison run inside a single channel — `DiversityPolicy` exempts
    // manual peers from the source rule, so an all-manual pool is one class in
    // every seat; and its ceiling counts against `peerCount` rather than
    // against how many peers are connected, so a pool at two of three seats
    // admits two peers of one class. Neither is an attack. A wallet that would
    // rather refuse than advance uncorroborated sets
    // `CrossCheckPolicy.requireDistinctSources`, and these are what that buys.
    //
    // The receipt is the other half: what agreed, recorded, so the claim can
    // be read afterwards instead of inferred from configuration that does not
    // imply it.

    // MARK: The rule, without a network

    private func receipt(_ sources: [PeerSource?],
                         tipHeight: UInt32 = 1_001) -> FilterSync.CrossCheckReceipt {
        FilterSync.CrossCheckReceipt(
            tipHeight: tipHeight,
            answerDigest: Data(repeating: 0x07, count: 32).hex,
            agreed: sources.enumerated().map {
                .init(endpoint: "10.0.\($0.offset).1:8333", source: $0.element)
            })
    }

    @Test("every network defaults to single-source verification; strict verification is an explicit choice")
    func networkDefaults() async throws {
        #expect(FilterSync.CrossCheckPolicy.default(for: .mainnet) == .acceptSingleSource)
        #expect(FilterSync.CrossCheckPolicy.default(for: .signet) == .acceptSingleSource)
        let pool = PeerPool(params: .mainnet, peerCount: 0)
        let chain = try HeaderChain(params: .mainnet, start: .checkpoint)
        let strict = try FilterSync(pool: pool, chain: chain, startHeight: await chain.startHeight,
                                    crossCheckPolicy: .requireDistinctSources)
        let degraded = try FilterSync(pool: pool, chain: chain, startHeight: await chain.startHeight)
        #expect(await strict.crossCheckPolicy == .requireDistinctSources)
        #expect(await degraded.crossCheckPolicy == .acceptSingleSource)
    }

    @Test("two known classes span; one class, or an unknown one, does not")
    func receiptSpansOnlyKnownClasses() {
        #expect(receipt([.manual, .persisted]).spansDistinctSources)
        #expect(!receipt([.manual, .manual, .manual]).spansDistinctSources,
                "three seats of one class is one channel agreeing with itself")
        #expect(!receipt([.dnsSeed, nil]).spansDistinctSources,
                "not knowing where a peer came from is not evidence it came from elsewhere")
        #expect(!receipt([nil, nil]).spansDistinctSources)
        #expect(!receipt([]).spansDistinctSources)
        #expect(receipt([.manual, nil, .census]).sourceClasses == [.manual, .census])
    }

    @Test("explicit degraded verification admits a lone source while strict verification refuses it")
    func policiesDisagreeOnlyOnTheDegradedCase() {
        let lone = receipt([.manual])
        #expect(FilterSync.CrossCheckPolicy.acceptSingleSource.admits(lone),
                "degraded verification is an explicit single-source choice")
        #expect(!FilterSync.CrossCheckPolicy.requireDistinctSources.admits(lone))
        let spanning = receipt([.manual, .persisted])
        #expect(FilterSync.CrossCheckPolicy.acceptSingleSource.admits(spanning))
        #expect(FilterSync.CrossCheckPolicy.requireDistinctSources.admits(spanning))
    }

    // MARK: The rule, on the wire

    /// The cfcheckpt lane took `prefix` over seating order until this patch,
    /// while the cfheaders lane beside it went through `crossSourceSet` — so
    /// the comparison every later check is anchored to was the one settled by
    /// which peer connected first. Three peers, two channels, two asked:
    /// seating order asks the two manuals, which is one channel corroborating
    /// itself, and the class-spanning selection reaches the other.
    ///
    /// Nothing about the policy here: this is who gets asked, which matters
    /// under either one.
    @Test("the checkpoint comparison reaches the second source class")
    func checkpointComparisonSpansClasses() async throws {
        let fixture = try await Self.mixedSourceFixture(
            sources: [.manual, .manual, .persisted], chainLength: 6,
            checkpointPeers: 2, policy: .acceptSingleSource)
        defer { fixture.stopNodes() }
        #expect(await fixture.pool.connectedPeers().count == 3)

        try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) { _ in }

        #expect(await fixture.nodes[2].nextMessage(command: "getcfcheckpt",
                                                  timeout: .seconds(2)) != nil,
                "the persisted channel was never asked for checkpoints — the comparison ran inside one class")
        await fixture.pool.stop()
    }

    /// The case the pool ceiling is supposed to make impossible and does not.
    /// Three manual peers, one lying about filter commitments: two answers
    /// outvote one, and the two that agreed are the same channel, because
    /// manual peers are exempt from the source rule. A majority of one channel
    /// is what `requireDistinctSources` refuses — and a majority it refuses to
    /// stand on condemns nobody: the dissenter is cooled off its seat, not
    /// struck from the persisted good-peers list on that channel's word.
    @Test("a 2-of-3 majority inside one source class advances nothing")
    func singleClassMajorityIsRefused() async throws {
        let fixture = try await Self.threePeerFixture(
            liars: [nil, nil, .filterCommitments(salt: 0xFF)],
            policy: .requireDistinctSources)
        defer { fixture.stopNodes() }
        let liarEndpoint = fixture.liarEndpoints[0]

        let collector = MatchCollector()
        var thrown: (any Error)?
        do {
            try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) {
                collector.add($0)
            }
        } catch { thrown = error }

        guard case let .crossCheckUnavailable(reason)? = thrown as? FilterSyncError else {
            Issue.record("expected a cross-check refusal, got \(String(describing: thrown))")
            return
        }
        #expect(reason.contains("2 peers agreed, from 1 known source class"))
        #expect(collector.matches.isEmpty, "no block was handed to the caller")
        #expect(await fixture.sync.nextScanHeight == 1, "the frontier did not move")
        #expect(await fixture.sync.lastCrossCheck == nil)
        #expect(!FileManager.default.fileExists(atPath: fixture.progressFile.path),
                "a refused run persists nothing at all")
        // The comparison still ran and the dissenter is off its seat, but on
        // the strength of a vote the policy declined: cooled off, so the pool
        // seats other candidates before the next attempt, and not banned.
        #expect(!(await Self.connectedEndpoints(fixture.pool)).contains(liarEndpoint.description))
        #expect(await fixture.pool.rejectionReasons[liarEndpoint] == "cfcheckpt mismatch in a single-class vote",
                "a single-class majority is not evidence against the peer it outvoted")
        #expect(await fixture.pool.coolingEndpoints.contains(liarEndpoint))
        await fixture.pool.stop()
    }

    /// The same three peers, two channels: the scan runs, and the receipt on
    /// disk names the classes that agreed rather than the classes that were
    /// dialled.
    @Test("two source classes agreeing advances the scan and records who agreed")
    func twoClassesAdvanceAndAreRecorded() async throws {
        let fixture = try await Self.mixedSourceFixture(
            sources: [.manual, .manual, .persisted], policy: .requireDistinctSources)
        defer { fixture.stopNodes() }
        #expect(await fixture.pool.connectedPeers().count == 3)

        let collector = MatchCollector()
        let reported = try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) {
            collector.add($0)
        }

        #expect(collector.matches.count == 1)
        #expect(await fixture.sync.lastScannedHeight == 1_001, "the frontier advanced")
        guard let receipt = reported else {
            Issue.record("a run that scanned to the tip reported no receipt")
            return
        }
        #expect(receipt.spansDistinctSources)
        #expect(receipt.sourceClasses == [.manual, .persisted],
                "the classes that answered, read from the pool rather than assumed")
        #expect(receipt.agreed.count == 3)
        #expect(receipt.tipHeight == 1_001)
        #expect(Set(receipt.agreed.map(\.endpoint))
            == Set(fixture.endpoints.map(\.description)))
        // The returned receipt and the saved one are the same claim, so a
        // caller that restarts reads what the run reported.
        #expect(try Self.storedProgress(fixture.progressFile).crossCheck == receipt)
        #expect(await fixture.sync.lastCrossCheck == receipt)
        await fixture.pool.stop()
    }

    /// A lone survivor, which `majorityReference` accepts on purpose. The pool
    /// spans two channels and only one of them answers: the other is evicted
    /// for replying about a different chain, which is the eviction working.
    /// Upstream advances on what is left; here nothing does, and there is no
    /// receipt to read afterwards because there was no run to write one.
    @Test("a lone surviving checkpoint peer commits nothing and leaves no receipt")
    func loneSurvivorCommitsNothing() async throws {
        let fixture = try await Self.mixedSourceFixture(
            sources: [.manual, .persisted], liars: [nil, .stopHash],
            policy: .requireDistinctSources)
        defer { fixture.stopNodes() }
        #expect(await fixture.pool.connectedPeers().count == 2, "two channels were dialled")

        let collector = MatchCollector()
        var thrown: (any Error)?
        do {
            try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) {
                collector.add($0)
            }
        } catch { thrown = error }

        guard case let .crossCheckUnavailable(reason)? = thrown as? FilterSyncError else {
            Issue.record("expected a cross-check refusal, got \(String(describing: thrown))")
            return
        }
        #expect(reason.contains("1 peer agreed, from 1 known source class"))
        #expect(collector.matches.isEmpty)
        #expect(await fixture.sync.nextScanHeight == 1)
        #expect(await fixture.sync.lastCrossCheck == nil, "no receipt: nothing was corroborated")
        #expect(!FileManager.default.fileExists(atPath: fixture.progressFile.path))
        await fixture.pool.stop()
    }

    /// The same pool under the explicit degraded policy, so the refusal above is read as
    /// the policy choosing and not as a two-peer pool being broken.
    @Test("the same lone survivor advances only with explicit degraded policy, with a one-class receipt")
    func loneSurvivorAdvancesUnderTheDefault() async throws {
        let fixture = try await Self.mixedSourceFixture(
            sources: [.manual, .persisted], liars: [nil, .stopHash],
            policy: .acceptSingleSource)
        defer { fixture.stopNodes() }

        let collector = MatchCollector()
        let reported = try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) {
            collector.add($0)
        }

        #expect(collector.matches.count == 1)
        #expect(await fixture.sync.lastScannedHeight == 1_001)
        guard let receipt = reported else {
            Issue.record("a run that scanned to the tip reported no receipt")
            return
        }
        #expect(!receipt.spansDistinctSources, "recorded as uncorroborated, not hidden")
        #expect(receipt.agreed.count == 1)
        #expect(try Self.storedProgress(fixture.progressFile).crossCheck == receipt)
        await fixture.pool.stop()
    }

    // MARK: - Checkpoint hang-up failover

    /// The mainnet failure of 2026-09-04, reproduced: a peer a little behind
    /// the tip (inside the eviction tolerance) is asked for filter checkpoints
    /// at a stop hash it has never seen, hangs up the way Bitcoin Core does,
    /// and the sync must carry on with the peers that answered instead of
    /// failing the whole pass on the same batch forever.
    @Test("a peer that hangs up on the checkpoint request is cooled off and the sync completes with the others")
    func hangupFailsOver() async throws {
        // 51 blocks behind: kept by the pool, unable to answer for the tip.
        // Answers its handshake late so the honest peers lead the header sync.
        let fixture = try await Self.threePeerFixture(
            liars: [nil, nil, .behindAndHangsUp(blocks: 950)],
            delays: [.zero, .zero, .milliseconds(300)])
        defer { fixture.stopNodes() }
        let shortEndpoint = fixture.endpoints[2]
        #expect(await fixture.pool.connectedPeers().count == 3,
                "51 behind is inside the tolerance; the pool keeps the short peer")

        let collector = MatchCollector()
        try await fixture.sync.sync(watchScripts: [fixture.synthetic.watchScript]) { collector.add($0) }

        #expect(collector.matches.count == 1, "the scan finished on the honest peers' answers")
        #expect(await fixture.sync.lastScannedHeight == 1_001)

        var connected: Set<String> = []
        for peer in await fixture.pool.connectedPeers() { connected.insert(await peer.endpoint.description) }
        #expect(!connected.contains(shortEndpoint.description), "the peer that hung up is gone")
        #expect(await fixture.pool.coolingEndpoints.contains(shortEndpoint),
                "hanging up is a transport fault: cooled off, not condemned")
        await fixture.pool.stop()
    }
}
