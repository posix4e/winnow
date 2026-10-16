import Foundation
import Testing
import TestSupport
@testable import WalletCore

/// The restore-only range scan: what it finds, what it refuses, and what it
/// leaves behind.
///
/// The filter scan is forward-only from a frontier by design — the module
/// README says so and `docs/mobile.html` §4.1 says why — and `scanRange` is
/// the one exception, for a customer who has restored a mnemonic and holds no
/// wallet file. Every case below is about the two properties that let the
/// exception exist: the forward frontier is never touched, and every dimension
/// of the scan is capped by a number a caller cannot raise.
///
/// The offline cases run against a mainnet header chain rooted at the shipped
/// checkpoint over a pool holding no peers. That reaches every refusal decided
/// before a peer is asked anything — including the one only mainnet can show,
/// a range reaching below the checkpoint — and a request that gets past all of
/// them fails with `noPeers`, which is how a case says "this one was let
/// through". The rest open real 127.0.0.1 listeners, exactly as
/// `FilterSyncTests` does.
@Suite("RangeScan")
struct RangeScanTests {

    // MARK: - Caps decided before any peer is asked

    /// A mainnet chain holding only the shipped checkpoint header, over a pool
    /// with nothing seated in it. `base` is that checkpoint height, which is
    /// both the chain's floor and its tip here.
    private static func offline() throws -> (sync: FilterSync, base: UInt32) {
        let checkpoint = try #require(NetworkParams.mainnet.checkpoint)
        let pool = PeerPool(params: .mainnet, peerCount: 0, manualPeers: [])
        let chain = try HeaderChain(params: .mainnet, start: .checkpoint)
        let sync = try FilterSync(pool: pool, chain: chain, startHeight: checkpoint.height)
        return (sync, checkpoint.height)
    }

    /// With a non-boundary checkpoint, shape validation succeeds before the
    /// independent anchor check refuses. A boundary checkpoint reaches noPeers.
    private static func expectPostShapeRefusal(at base: UInt32,
                                               _ operation: () async throws -> Void) async {
        do {
            try await operation()
            Issue.record("an offline scan unexpectedly succeeded")
        } catch FilterSyncError.noPeers {
            #expect(base < FilterSync.checkpointInterval || base.isMultiple(of: FilterSync.checkpointInterval))
        } catch let RangeScanError.rangeSpansNoCheckpoint(from, to) {
            #expect(from == base && to == base)
            #expect(base >= FilterSync.checkpointInterval && !base.isMultiple(of: FilterSync.checkpointInterval))
        } catch {
            Issue.record("shape validation did not reach the anchor/peer check: \(error)")
        }
    }

    private static let script = Data([0x51, 0x20] + repeatElement(0x42, count: 32))
    private static let otherScript = Data([0x51, 0x20] + repeatElement(0x43, count: 32))

    @Test("a range that is not a range, or has nothing to look for, is refused by name")
    func refusesAnUnscannableRequest() async throws {
        let (sync, base) = try Self.offline()

        await #expect(throws: RangeScanError.invalidRange(from: base + 1, to: base)) {
            try await sync.scanRange(from: base + 1, to: base,
                                     watchScripts: [Self.script]) { _ in }
        }
        // `to` at the top of the range has no "height after the last one
        // scanned", so a completed record could not name its own frontier.
        await #expect(throws: RangeScanError.invalidRange(from: base, to: .max)) {
            try await sync.scanRange(from: base, to: .max,
                                     watchScripts: [Self.script]) { _ in }
        }
        await #expect(throws: RangeScanError.noWatchScripts) {
            try await sync.scanRange(from: base, to: base, watchScripts: []) { _ in }
        }
    }

    @Test("the width cap refuses at its boundary and lets the block below it through")
    func widthCapBoundary() async throws {
        let (sync, base) = try Self.offline()
        let oneBlock = RangeScanLimits(maxBlocks: 1)

        // At the cap: through the shape check, and stopped by the empty pool.
        await Self.expectPostShapeRefusal(at: base) {
            try await sync.scanRange(from: base, to: base, watchScripts: [Self.script],
                                     limits: oneBlock) { _ in }
        }
        // One block past it, and the width refusal comes first — before the
        // chain check, which would otherwise have called the same request a
        // range above the tip.
        await #expect(throws: RangeScanError.rangeTooWide(blocks: 2, limit: 1)) {
            try await sync.scanRange(from: base, to: base + 1, watchScripts: [Self.script],
                                     limits: oneBlock) { _ in }
        }
    }

    @Test("the script cap refuses at its boundary and lets the set below it through")
    func scriptCapBoundary() async throws {
        let (sync, base) = try Self.offline()
        let twoScripts = RangeScanLimits(maxScripts: 2)
        let three = [Self.script, Self.otherScript,
                     Data([0x51, 0x20] + repeatElement(0x44, count: 32))]

        await Self.expectPostShapeRefusal(at: base) {
            try await sync.scanRange(from: base, to: base,
                                     watchScripts: Array(three.prefix(2)),
                                     limits: twoScripts) { _ in }
        }
        await #expect(throws: RangeScanError.tooManyScripts(count: 3, limit: 2)) {
            try await sync.scanRange(from: base, to: base, watchScripts: three,
                                     limits: twoScripts) { _ in }
        }
    }

    /// Filters are fetched by block hash, so a checkpoint-rooted chain has no
    /// way to name a block below its base: the range is refused by name rather
    /// than left to fail mid-batch as a missing header. Mainnet is the only
    /// network that ships a checkpoint, which is why this case is here and not
    /// on the synthetic signet chain the rest of the suite mines.
    @Test("a range outside the headers the chain holds is refused at both ends")
    func rangeOutsideTheChain() async throws {
        let (sync, base) = try Self.offline()

        await #expect(throws: RangeScanError.rangeBelowChain(from: base - 1, start: base)) {
            try await sync.scanRange(from: base - 1, to: base,
                                     watchScripts: [Self.script]) { _ in }
        }
        await #expect(throws: RangeScanError.rangeAboveChain(to: base + 1, tip: base)) {
            try await sync.scanRange(from: base, to: base + 1,
                                     watchScripts: [Self.script]) { _ in }
        }
        // The block at the floor itself is inside the chain, so it gets past
        // both ends and stops at the empty pool.
        await Self.expectPostShapeRefusal(at: base) {
            try await sync.scanRange(from: base, to: base, watchScripts: [Self.script]) { _ in }
        }
    }

    /// The fixed-point loop is the caller's, so the pass counter is what
    /// bounds the whole restore rather than one run. A stored record plus a
    /// changed script set is the next pass, and the cap is read before any
    /// peer is asked.
    @Test("the pass cap refuses at its boundary and lets the pass below it through")
    func iterationCapBoundary() async throws {
        let (sync, base) = try Self.offline()
        let recordURL = tempFileURL("range-iterations.json")
        defer { try? FileManager.default.removeItem(at: recordURL.deletingLastPathComponent()) }
        let stored = RangeScanProgress(
            from: base, to: base, nextScanHeight: base,
            watchFingerprint: RangeScanProgress.fingerprint(of: [Self.script]),
            iteration: 1)
        try stored.persist(to: recordURL)

        // A different script set over the same range is pass two.
        await #expect(throws: RangeScanError.tooManyIterations(count: 2, limit: 1)) {
            try await sync.scanRange(from: base, to: base, watchScripts: [Self.otherScript],
                                     limits: RangeScanLimits(maxIterations: 1),
                                     storageURL: recordURL) { _ in }
        }
        // Room for two, and the same request gets through to the pool. Nothing
        // was written on the way past: a record is persisted only after a
        // batch commits, and this run never reaches one.
        await Self.expectPostShapeRefusal(at: base) {
            try await sync.scanRange(from: base, to: base, watchScripts: [Self.otherScript],
                                     limits: RangeScanLimits(maxIterations: 2),
                                     storageURL: recordURL) { _ in }
        }
        #expect(try RangeScanProgress.load(storageURL: recordURL) == stored)
    }

    /// A record's pass number comes off disk, so it is bounded on the way in:
    /// a number past the ceiling is damage to report, not a trap on `+ 1`
    /// when a changed script set makes it the next pass. And the identity a
    /// pass is told apart by ignores repeats as well as order, so a caller
    /// that rebuilds its watch list with an overlap resumes rather than
    /// starting the range again as a new pass.
    @Test("a pass number past the ceiling is damage, and a repeated script is the same set")
    func iterationPastTheCeilingIsDamage() async throws {
        let (sync, base) = try Self.offline()
        let recordURL = tempFileURL("range-iterations-overflow.json")
        defer { try? FileManager.default.removeItem(at: recordURL.deletingLastPathComponent()) }
        let fingerprint = RangeScanProgress.fingerprint(of: [Self.script])
        try RangeScanProgress(from: base, to: base, nextScanHeight: base,
                              watchFingerprint: fingerprint, iteration: Int.max)
            .persist(to: recordURL)
        await #expect(throws: RangeScanError.recordDamaged("the pass number is out of range")) {
            try await sync.scanRange(from: base, to: base, watchScripts: [Self.otherScript],
                                     storageURL: recordURL) { _ in }
        }
        try RangeScanProgress(from: base, to: base, nextScanHeight: base,
                              watchFingerprint: fingerprint,
                              iteration: RangeScanLimits.iterationsCeiling)
            .persist(to: recordURL)
        // The pass after the last permitted one is refused by name, not by trap.
        await #expect(throws: RangeScanError.tooManyIterations(
            count: RangeScanLimits.iterationsCeiling + 1, limit: RangeScanLimits().maxIterations)) {
            try await sync.scanRange(from: base, to: base, watchScripts: [Self.otherScript],
                                     storageURL: recordURL) { _ in }
        }
        #expect(RangeScanProgress.fingerprint(of: [Self.script, Self.otherScript, Self.otherScript])
            == RangeScanProgress.fingerprint(of: [Self.otherScript, Self.script]))
        #expect(fingerprint != RangeScanProgress.fingerprint(of: [Self.script, Self.otherScript]))
    }

    /// Each cap is clamped to its ceiling on the way in rather than validated,
    /// so a caller cannot loosen one by asking for more — which is the whole
    /// reason a back-scan is allowed to exist in a forward-only library.
    @Test("no caller can raise a cap past its hard maximum, or below zero")
    func capsClampToTheirCeilings() {
        let greedy = RangeScanLimits(maxBlocks: .max, maxScripts: .max,
                                     maxFilterBytes: .max, maxDuration: .seconds(86_400),
                                     maxIterations: .max)
        #expect(greedy.maxBlocks == RangeScanLimits.blocksCeiling)
        #expect(greedy.maxScripts == RangeScanLimits.scriptsCeiling)
        #expect(greedy.maxFilterBytes == RangeScanLimits.filterBytesCeiling)
        #expect(greedy.maxDuration == RangeScanLimits.durationCeiling)
        #expect(greedy.maxIterations == RangeScanLimits.iterationsCeiling)

        // Asking for less always works.
        let modest = RangeScanLimits(maxBlocks: 10, maxScripts: 3, maxFilterBytes: 4_096,
                                     maxDuration: .seconds(5), maxIterations: 2)
        #expect(modest.maxBlocks == 10)
        #expect(modest.maxScripts == 3)
        #expect(modest.maxFilterBytes == 4_096)
        #expect(modest.maxDuration == .seconds(5))
        #expect(modest.maxIterations == 2)

        // A negative budget is no budget, not a wrapped enormous one.
        let negative = RangeScanLimits(maxScripts: -1, maxFilterBytes: -1,
                                       maxDuration: .seconds(-1), maxIterations: -1)
        #expect(negative.maxScripts == 0)
        #expect(negative.maxFilterBytes == 0)
        #expect(negative.maxDuration == .zero)
        #expect(negative.maxIterations == 0)
    }

    // MARK: - Loopback peers

    /// The fixture every socket-backed case here wants: one honest loopback
    /// node on a synthetic chain, a pool seated on it, a header chain, and a
    /// FilterSync with its forward progress in a temp file. Nothing is synced
    /// yet — a range scan reads the header chain and never advances it, so
    /// each case says for itself how the chain got its headers.
    private struct Fixture {
        let synthetic: SyntheticChain
        let node: LoopbackNode
        let pool: PeerPool
        let chain: HeaderChain
        let sync: FilterSync
        let forwardFile: URL
        let rangeFile: URL

        /// The node and the pool are bound to locals first: the closures a
        /// `Task` takes are `sending`, and capturing them through `self` would
        /// send this whole struct.
        func stop() {
            let node = node
            let pool = pool
            Task { await node.stop() }
            Task { await pool.stop() }
        }

        func removeFiles() {
            try? FileManager.default.removeItem(at: forwardFile.deletingLastPathComponent())
            try? FileManager.default.removeItem(at: rangeFile.deletingLastPathComponent())
        }
    }

    private static func fixture(chainLength: Int = 2_100, watchHeight: UInt32 = 1_500,
                                cfcheckptLieAtHeight: Int? = nil,
                                crossCheckPolicy: FilterSync.CrossCheckPolicy = .acceptSingleSource)
        async throws -> Fixture {
        let synthetic = makeSyntheticChain(length: chainLength, watchHeight: watchHeight, noRetargeting: true)
        let node = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                cfcheckptLieAtHeight: cfcheckptLieAtHeight)
        try await node.start()
        let pool = PeerPool(params: synthetic.params, peerCount: 1,
                            manualPeers: [await node.endpoint],
                            peersFileURL: tempFileURL("peers.json"))
        await pool.start()
        let chain = try HeaderChain(params: synthetic.params)
        let forwardFile = tempFileURL("forward-progress.json")
        let rangeFile = tempFileURL("range-progress.json")
        let sync = try FilterSync(pool: pool, chain: chain, startHeight: 1,
                                  storageURL: forwardFile, requiredCheckpointPeers: 1,
                                  crossCheckPolicy: crossCheckPolicy)
        return Fixture(synthetic: synthetic, node: node, pool: pool, chain: chain,
                       sync: sync, forwardFile: forwardFile, rangeFile: rangeFile)
    }

    /// The situation the whole patch exists for, in one case: a wallet has
    /// scanned forward to the tip without knowing the script it was paid to,
    /// so the payment sits below its frontier and no forward run can ever
    /// reach it again. The range scan finds it, and the frontier — the thing a
    /// restore must not disturb, because everything above it really has been
    /// scanned — is exactly where it was, in the actor and in the file.
    @Test("a range scan finds a payment below the forward frontier and leaves the frontier alone")
    func findsAPaymentBelowTheForwardFrontier() async throws {
        let fixture = try await Self.fixture()
        defer { fixture.stop(); fixture.removeFiles() }

        try await fixture.sync.sync(watchScripts: []) { _ in
            Issue.record("the forward pass is looking for nothing")
        }
        #expect(await fixture.sync.nextScanHeight == 2_101)

        let collector = MatchCollector()
        let outcome = try await fixture.sync.scanRange(
            from: 1_000, to: 1_600,
            watchScripts: [fixture.synthetic.watchScript],
            storageURL: fixture.rangeFile) { collector.add($0) }

        #expect(collector.matches.map(\.height) == [1_500])
        #expect(collector.matches.first?.block.transactions[0].outputs.contains {
            $0.scriptPubKey == fixture.synthetic.watchScript
        } == true)
        #expect(outcome.matchedHeights == [1_500])
        #expect(outcome.isComplete)
        #expect(outcome.scannedThrough == 1_600)
        #expect(outcome.iteration == 1)
        #expect(outcome.filterBytesRead > 0)

        #expect(await fixture.sync.nextScanHeight == 2_101, "the forward frontier did not move")
        let forward = try JSONDecoder().decode(
            FilterSync.Progress.self, from: Data(contentsOf: fixture.forwardFile))
        #expect(forward.nextScanHeight == 2_101, "and the file a relaunch reads agrees")

        // The range's own record, in its own file, describing its own range.
        let stored = try RangeScanProgress.load(storageURL: fixture.rangeFile)
        let record = try #require(stored)
        #expect(record.from == 1_000)
        #expect(record.to == 1_600)
        #expect(record.nextScanHeight == 1_601)
        #expect(record.iteration == 1)
        #expect(record.isComplete)
    }

    /// The byte cap and the resumable record are one mechanism seen from two
    /// ends, so they are tested together: a run stops on its budget, and what
    /// makes that survivable is that the next run starts where it stopped
    /// rather than at `from`.
    ///
    /// The budget is measured, not guessed — one batch of this range costs
    /// what a scan of exactly that batch reports — so "the batch that fits
    /// commits and the next one does not" is arithmetic rather than a hope
    /// about filter sizes.
    @Test("a run that spends its byte budget resumes from its own record and re-delivers nothing")
    func interruptedRangeScanResumes() async throws {
        let fixture = try await Self.fixture(chainLength: 1_200, watchHeight: 500)
        defer { fixture.stop(); fixture.removeFiles() }
        try await fixture.pool.syncHeaders(fixture.chain)
        #expect(await fixture.chain.height == 1_200)
        let watch = [fixture.synthetic.watchScript]

        // [100, 1200] is two batches: [100, 1099] and [1100, 1200]. This is
        // what the first one costs, both halves of it: the filters of the
        // batch, and the block the payment at 500 pulled down.
        let firstBatch = try await fixture.sync.scanRange(from: 100, to: 1_099,
                                                          watchScripts: watch) { _ in }
        #expect(firstBatch.filterBytesRead > 0)
        #expect(firstBatch.blockBytesRead > 0)
        let budget = firstBatch.filterBytesRead + firstBatch.blockBytesRead

        let collector = MatchCollector()
        var thrown: (any Error)?
        do {
            _ = try await fixture.sync.scanRange(
                from: 100, to: 1_200, watchScripts: watch,
                limits: RangeScanLimits(maxFilterBytes: budget),
                storageURL: fixture.rangeFile) { collector.add($0) }
        } catch {
            thrown = error
        }
        guard case let .filterBytesExhausted(read, limit)? = thrown as? RangeScanError else {
            Issue.record("expected filterBytesExhausted, got \(String(describing: thrown))")
            return
        }
        #expect(limit == budget)
        #expect(read > budget, "the run stopped on the chunk that took it past the cap")
        #expect(collector.matches.map(\.height) == [500])

        let halfway = try RangeScanProgress.load(storageURL: fixture.rangeFile)
        let interrupted = try #require(halfway)
        #expect(interrupted.nextScanHeight == 1_100,
                "the batch that fitted committed; the one that did not left nothing")
        #expect(interrupted.iteration == 1, "a resumption is not a new pass")

        // Resumed with room. It starts at its own record, so the payment at
        // 500 is below the resumed frontier: not read again, not delivered
        // again.
        let resumed = try await fixture.sync.scanRange(
            from: 100, to: 1_200, watchScripts: watch,
            storageURL: fixture.rangeFile) { collector.add($0) }
        #expect(resumed.isComplete)
        #expect(resumed.scannedThrough == 1_200)
        #expect(resumed.iteration == 1)
        #expect(resumed.matchedHeights.isEmpty, "this run scanned only [1100, 1200]")
        #expect(collector.matches.map(\.height) == [500],
                "and the match was delivered once across both runs")
        let complete = try RangeScanProgress.load(storageURL: fixture.rangeFile)
        let finished = try #require(complete)
        #expect(finished.nextScanHeight == 1_201)

        // One byte short of a batch, and the cap fires inside the batch
        // instead of after it: a batch is the unit that commits, so a run
        // refused inside one persists nothing at all and has nothing to
        // resume from.
        let tightFile = tempFileURL("range-tight.json")
        defer { try? FileManager.default.removeItem(at: tightFile.deletingLastPathComponent()) }
        var tightThrow: (any Error)?
        do {
            _ = try await fixture.sync.scanRange(
                from: 100, to: 1_200, watchScripts: watch,
                limits: RangeScanLimits(maxFilterBytes: budget - 1),
                storageURL: tightFile) { _ in }
        } catch {
            tightThrow = error
        }
        guard case let .filterBytesExhausted(tightRead, tightLimit)? = tightThrow as? RangeScanError
        else {
            Issue.record("expected filterBytesExhausted, got \(String(describing: tightThrow))")
            return
        }
        #expect(tightLimit == budget - 1)
        #expect(tightRead > tightLimit && tightRead <= budget,
                "the overshoot is one chunk, and the chunk was inside the first batch")
        #expect(!FileManager.default.fileExists(atPath: tightFile.path),
                "a cap that fires inside a batch persists nothing")
    }

    /// The time cap at the boundary that needs no clock: a run given no time
    /// is refused before it reads a filter, and the same request with a budget
    /// completes.
    @Test("a run with no time budget is refused before it reads a filter")
    func timeCapRefusesAtZero() async throws {
        let fixture = try await Self.fixture(chainLength: 6, watchHeight: 3)
        defer { fixture.stop(); fixture.removeFiles() }
        try await fixture.pool.syncHeaders(fixture.chain)
        let watch = [fixture.synthetic.watchScript]

        await #expect(throws: RangeScanError.runTimedOut(limit: .zero)) {
            try await fixture.sync.scanRange(
                from: 1, to: 6, watchScripts: watch,
                limits: RangeScanLimits(maxDuration: .zero),
                storageURL: fixture.rangeFile) { _ in
                    Issue.record("a run out of time must not read a filter")
                }
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.rangeFile.path))

        let outcome = try await fixture.sync.scanRange(
            from: 1, to: 6, watchScripts: watch,
            storageURL: fixture.rangeFile) { _ in }
        #expect(outcome.matchedHeights == [3])
        #expect(outcome.isComplete)
    }

    /// The deadline is read between batches and again inside the chunk loop,
    /// and this is the case that separates the two. A batch is up to a
    /// thousand blocks, so a deadline consulted only between batches is a cap
    /// on batches: a run that overruns inside one would finish it, commit it,
    /// and record a frontier reached after its time was up.
    ///
    /// The budget is spent from inside `onMatch`, which the scan awaits in the
    /// middle of a batch. What separates the two readings is not the error —
    /// both give `runTimedOut` — but what is left behind: with the chunk
    /// reading, the batch never finishes and nothing is persisted at all.
    @Test("a budget spent inside a batch stops the batch, so the batch commits nothing")
    func timeCapStopsARunInsideABatch() async throws {
        let fixture = try await Self.fixture(chainLength: 1_200, watchHeight: 500)
        defer { fixture.stop(); fixture.removeFiles() }
        try await fixture.pool.syncHeaders(fixture.chain)
        let watch = [fixture.synthetic.watchScript]

        // [100, 1099] is one batch of ten chunks and the payment at 500 is in
        // the fifth, so holding `onMatch` there for longer than the whole
        // budget puts every later chunk of that batch past the deadline. A
        // loaded machine that runs out of budget before the fifth chunk gets
        // the same refusal from the batch reading and asserts the same thing,
        // one notch less sharply — the deadline is never the reason this goes
        // green.
        await #expect(throws: RangeScanError.runTimedOut(limit: .milliseconds(500))) {
            try await fixture.sync.scanRange(
                from: 100, to: 1_099, watchScripts: watch,
                limits: RangeScanLimits(maxDuration: .milliseconds(500)),
                storageURL: fixture.rangeFile) { _ in
                    try await Task.sleep(for: .seconds(1))
                }
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.rangeFile.path),
                "the batch the run died inside committed nothing")
    }

    /// The forward path's per-batch checkpoint comparison, on the range path:
    /// a peer whose `cfcheckpt` answer contradicts the commitments it serves
    /// is caught before the batch has any effect. The watched payment sits
    /// inside the refused batch, so a comparison that ran after the batch —
    /// or not at all — shows up here as a match a restore should never have
    /// been shown, and as a record naming blocks nothing verified.
    @Test("a lying checkpoint peer during a range scan delivers no match and persists nothing")
    func lyingCheckpointPeerCommitsNothing() async throws {
        let fixture = try await Self.fixture(chainLength: 1_100, watchHeight: 500,
                                             cfcheckptLieAtHeight: 1_000)
        defer { fixture.stop(); fixture.removeFiles() }
        try await fixture.pool.syncHeaders(fixture.chain)
        #expect(await fixture.chain.height == 1_100)

        let collector = MatchCollector()
        var thrown: (any Error)?
        do {
            // One batch, 601 blocks: it pins the disputed boundary at 1,000
            // and the payment at 500 in the same commitment set.
            _ = try await fixture.sync.scanRange(
                from: 500, to: 1_100,
                watchScripts: [fixture.synthetic.watchScript],
                storageURL: fixture.rangeFile) { collector.add($0) }
        } catch {
            thrown = error
        }
        guard case let .checkpointMismatch(reason)? = thrown as? FilterSyncError else {
            Issue.record("expected checkpointMismatch, got \(String(describing: thrown))")
            return
        }
        #expect(reason.contains("pinned header at 1000"))
        #expect(collector.matches.isEmpty, "a refused batch must not deliver its matches")
        #expect(!FileManager.default.fileExists(atPath: fixture.rangeFile.path),
                "and must not write a record")
        #expect(await fixture.sync.nextScanHeight == 1, "the forward frontier was never involved")
    }

    /// The narrow mirror of the case above, and the one a lying peer wins if
    /// nothing refuses it. `[1010, 1100]` pins no multiple of 1,000, so the
    /// boundary comparison has nothing to compare: the batch's anchor is
    /// whatever the peer announced as the previous filter header, every header
    /// above it is derived from that by hash chain, and one peer's cfheaders
    /// answer is accepted by design. The same node that is caught over a range
    /// reaching 1,000 would otherwise serve a fabricated chain here, hide the
    /// payment at 1,050, and have the run write a record saying those blocks
    /// were scanned.
    @Test("a range that reaches no checkpoint is refused before a peer is asked")
    func boundaryFreeRangeIsRefused() async throws {
        let fixture = try await Self.fixture(chainLength: 1_100, watchHeight: 1_050,
                                             cfcheckptLieAtHeight: 1_000)
        defer { fixture.stop(); fixture.removeFiles() }
        try await fixture.pool.syncHeaders(fixture.chain)
        #expect(await fixture.chain.height == 1_100)

        let collector = MatchCollector()
        await #expect(throws: RangeScanError.rangeSpansNoCheckpoint(from: 1_010, to: 1_100)) {
            try await fixture.sync.scanRange(
                from: 1_010, to: 1_100,
                watchScripts: [fixture.synthetic.watchScript],
                storageURL: fixture.rangeFile) { collector.add($0) }
        }
        #expect(collector.matches.isEmpty, "a range nothing could check delivers no match")
        #expect(!FileManager.default.fileExists(atPath: fixture.rangeFile.path),
                "and writes no record saying it scanned them")

        // Widened by ten blocks it reaches the boundary at 1,000, and that is
        // the check the narrow range had none of: the same node is caught.
        var thrown: (any Error)?
        do {
            _ = try await fixture.sync.scanRange(
                from: 1_000, to: 1_100,
                watchScripts: [fixture.synthetic.watchScript],
                storageURL: fixture.rangeFile) { collector.add($0) }
        } catch {
            thrown = error
        }
        guard case let .checkpointMismatch(reason)? = thrown as? FilterSyncError else {
            Issue.record("expected checkpointMismatch, got \(String(describing: thrown))")
            return
        }
        #expect(reason.contains("pinned header at 1000"))
        #expect(collector.matches.isEmpty)

        // One block above the boundary is not boundary-free: the first batch
        // pins the header at 1,000 as its anchor and compares it, so the same
        // node is caught at the same height rather than the range refused.
        var aboveBoundary: (any Error)?
        do {
            _ = try await fixture.sync.scanRange(
                from: 1_001, to: 1_100,
                watchScripts: [fixture.synthetic.watchScript],
                storageURL: fixture.rangeFile) { collector.add($0) }
        } catch {
            aboveBoundary = error
        }
        guard case let .checkpointMismatch(anchorReason)? = aboveBoundary as? FilterSyncError else {
            Issue.record("expected the anchor at 1000 to be compared, got \(String(describing: aboveBoundary))")
            return
        }
        #expect(anchorReason.contains("pinned header at 1000"))
        #expect(collector.matches.isEmpty)
    }

    /// The other half of the same rule: the refusal is about having no anchor,
    /// not about the arithmetic of the range, so a pass that starts from a
    /// header an earlier pass pinned runs over exactly the blocks the case
    /// above refuses. This is what a resumption and the next fixed-point pass
    /// both look like.
    ///
    /// The anchor here is taken from a forward pass rather than written by
    /// hand, so it is a header this library verified rather than a plausible
    /// 32 bytes.
    @Test("a boundary-free range whose record holds the anchor below it runs")
    func boundaryFreeRangeRunsFromAVerifiedAnchor() async throws {
        let fixture = try await Self.fixture(chainLength: 1_100, watchHeight: 1_050)
        defer { fixture.stop(); fixture.removeFiles() }
        try await fixture.pool.syncHeaders(fixture.chain)

        try await fixture.sync.sync(watchScripts: [], maxBlocks: 1_010) { _ in
            Issue.record("the forward pass is looking for nothing")
        }
        let anchor = try #require(await fixture.sync.filterHeader(at: 1_009))
        let watch = [fixture.synthetic.watchScript]
        let record = RangeScanProgress(
            from: 1_010, to: 1_100, nextScanHeight: 1_010,
            watchFingerprint: RangeScanProgress.fingerprint(of: watch),
            iteration: 1, filterHeaders: ["1009": anchor.hex])
        try record.persist(to: fixture.rangeFile)

        let collector = MatchCollector()
        let outcome = try await fixture.sync.scanRange(
            from: 1_010, to: 1_100, watchScripts: watch,
            storageURL: fixture.rangeFile) { collector.add($0) }
        #expect(outcome.isComplete)
        #expect(outcome.iteration == 1, "a record with the same scripts is a resumption")
        #expect(collector.matches.map(\.height) == [1_050])
    }

    /// A range record keeps one header the forward scan's pruning does not:
    /// the one below the range's own first block. Pruning keeps what the next
    /// batch can be asked for, so by the end of a range wider than about two
    /// checkpoint intervals that anchor is gone, and the next fixed-point pass
    /// would restart at `from` with nothing to refuse a peer's announced chain
    /// with. `[100, 2000]` is the smallest range over this fixture whose last
    /// prune reaches past 99.
    @Test("a pass wide enough to prune keeps the anchor below its own range")
    func rangeRecordKeepsItsOwnAnchor() async throws {
        let fixture = try await Self.fixture()
        defer { fixture.stop(); fixture.removeFiles() }
        try await fixture.pool.syncHeaders(fixture.chain)
        #expect(await fixture.chain.height == 2_100)

        let outcome = try await fixture.sync.scanRange(
            from: 100, to: 2_000, watchScripts: [fixture.synthetic.watchScript],
            storageURL: fixture.rangeFile) { _ in }
        #expect(outcome.isComplete)

        let stored = try #require(try RangeScanProgress.load(storageURL: fixture.rangeFile))
        let anchor = try #require(stored.filterHeaders["99"],
                                  "the header below the range survived pruning")
        // And the next pass carries it, which is the only reason to keep it.
        let next = stored.restarted(fingerprint: RangeScanProgress.fingerprint(of: [Self.otherScript]))
        #expect(next.nextScanHeight == 100)
        #expect(next.iteration == 2)
        #expect(next.filterHeaders["99"] == anchor)
    }

    /// The same policy as arithmetic over a record, at the width a restore
    /// actually asks for and with no peers involved: the forward scan's
    /// pruning drops the anchor below `from`, and the range's own pruning
    /// keeps it.
    @Test("pruning a range record keeps the anchor the forward pruning drops")
    func prunedRangeHeadersKeepsTheAnchor() throws {
        let from: UInt32 = 900_000
        let to: UInt32 = 950_000
        let header = String(repeating: "ab", count: 32)
        var proposed: [String: String] = [:]
        for height in [UInt32(0), from - 1, from, 949_000, to] { proposed[String(height)] = header }

        #expect(FilterSync.prunedFilterHeaders(proposed, frontier: to + 1)[String(from - 1)] == nil,
                "the forward scan keeps what a forward frontier can be asked for, and this is not it")
        let pruned = FilterSync.prunedRangeHeaders(proposed, frontier: to + 1, rangeStart: from)
        #expect(pruned[String(from - 1)] == header)
        #expect(pruned[String(from)] == header, "and the boundaries are still kept")

        let record = RangeScanProgress(
            from: from, to: to, nextScanHeight: to + 1,
            watchFingerprint: RangeScanProgress.fingerprint(of: [Self.script]),
            iteration: 1, filterHeaders: pruned)
        try record.validate()
        #expect(record.restarted(fingerprint: RangeScanProgress.fingerprint(of: [Self.otherScript]))
            .filterHeaders[String(from - 1)] == header)
    }

    /// The run deadline is read between batches, before every chunk request,
    /// and once per filter inside the chunk. The last reading is this case:
    /// every block in this chain pays its coinbase to `everyBlock`, so all six
    /// filters of the one chunk match and each match fetches a whole block on
    /// a 120-second timeout and then awaits the caller. A deadline read only
    /// around the chunk bounds the wait for filters and nothing else, so a run
    /// given a second would spend as long as the matches take, which on a
    /// restore against a full watch set is minutes to hours.
    ///
    /// The budget is twenty seconds, and the first match holds until a second
    /// after that budget has elapsed since the run began, whatever the setup
    /// cost; both are margin rather than taste. The suite runs its cases
    /// concurrently, and the peer round trips before the first filter is
    /// judged share the loopback with every other socket-backed case: alone
    /// they take a fifth of a second, beside the filter-sync suites over
    /// three, and on a contended hosted runner they have taken more than
    /// eight. A budget spent on that setup times the run out with nothing
    /// delivered, and the case then fails for a reason that is not the one
    /// it tests, so the budget is sized to the slowest runner observed and
    /// the hold is measured from the run's own start rather than fixed.
    @Test("the run deadline stops a chunk between its matches")
    func deadlineStopsAChunkBetweenItsMatches() async throws {
        let fixture = try await Self.fixture(chainLength: 6, watchHeight: 3)
        defer { fixture.stop(); fixture.removeFiles() }
        try await fixture.pool.syncHeaders(fixture.chain)

        let everyBlock = [Data([0x51])]
        let collector = MatchCollector()
        let budget: Duration = .seconds(20)
        let started = ContinuousClock.now
        await #expect(throws: RangeScanError.runTimedOut(limit: budget)) {
            try await fixture.sync.scanRange(
                from: 1, to: 6, watchScripts: everyBlock,
                limits: RangeScanLimits(maxDuration: budget),
                storageURL: fixture.rangeFile) { match in
                    collector.add(match)
                    // Hold until the deadline has certainly passed, measured
                    // from the run's start, so the next filter's check fires.
                    try await Task.sleep(until: started + budget + .seconds(1), clock: .continuous)
                }
        }
        #expect(collector.matches.count == 1,
                "the deadline was spent inside the first match, so there was no second")
        #expect(!FileManager.default.fileExists(atPath: fixture.rangeFile.path))
    }

    /// Two records, two files, and each loader refuses the other's. A range
    /// record decodes cleanly as forward progress — same key names, and the
    /// decoder ignores the rest — so without the marker a `scanRange` pointed
    /// at the wallet's own progress file would rewrite the forward frontier,
    /// which is the one thing the whole file exists not to do.
    @Test("a range record and forward progress are refused by each other's loader")
    func recordKindsDoNotCross() async throws {
        let (_, base) = try Self.offline()
        let file = tempFileURL("crossed-progress.json")
        defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
        let pool = PeerPool(params: .mainnet, peerCount: 0, manualPeers: [])
        let chain = try HeaderChain(params: .mainnet, start: .checkpoint)

        let range = RangeScanProgress(
            from: base, to: base + 500, nextScanHeight: base + 200,
            watchFingerprint: RangeScanProgress.fingerprint(of: [Self.script]), iteration: 1)
        try range.persist(to: file)
        #expect(throws: FilterSyncStorageError.damaged(
            "the file is a \"range\" record, not compact-filter progress")) {
            _ = try FilterSync(pool: pool, chain: chain, startHeight: base, storageURL: file)
        }

        // A forward progress file names nothing, and loads exactly as it did
        // before the marker existed.
        try JSONEncoder().encode(FilterSync.Progress(nextScanHeight: base + 200)).write(to: file)
        let sync = try FilterSync(pool: pool, chain: chain, startHeight: base, storageURL: file)
        #expect(sync.persistenceState == .loaded)
        #expect(await sync.nextScanHeight == base + 200)

        #expect(throws: RangeScanError.recordDamaged(
            "the file is not a range-scan record (it is marked nothing)")) {
            _ = try RangeScanProgress.load(storageURL: file)
        }
    }

    @Test("a damaged resume record cannot smuggle noncanonical or future commitments")
    func damagedPinnedHeadersAreRefusedWithoutReplacingTheRecord() throws {
        let file = tempFileURL("damaged-range-pins.json")
        defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
        let header = String(repeating: "ab", count: 32)
        let invalid: [[String: String]] = [
            ["01": header], ["-1": header], ["4294967296": header],
            ["10": header], ["11": header], ["9": "not-hex"],
            ["9": String(repeating: "zz", count: 32)], ["9": String(repeating: "ab", count: 31)]
        ]
        for pins in invalid {
            let record = RangeScanProgress(from: 1, to: 20, nextScanHeight: 10,
                watchFingerprint: RangeScanProgress.fingerprint(of: [Self.script]),
                iteration: 1, filterHeaders: pins)
            let original = try JSONEncoder().encode(record)
            try original.write(to: file)
            do {
                _ = try RangeScanProgress.load(storageURL: file)
                Issue.record("unsafe pinned headers were accepted: \(pins)")
            } catch RangeScanError.recordDamaged {
                #expect(try Data(contentsOf: file) == original,
                        "a refusal must preserve evidence and must not reset the frontier")
            }
        }
        let valid = RangeScanProgress(from: 1, to: 20, nextScanHeight: 10,
            watchFingerprint: RangeScanProgress.fingerprint(of: [Self.script]), iteration: 1,
            filterHeaders: ["0": header, "9": header])
        try valid.persist(to: file)
        #expect(try RangeScanProgress.load(storageURL: file) == valid)
    }

    /// The byte cap counts what the run reads, and on a restore most of that
    /// is blocks: every BIP158 match pulls a whole block down, false positives
    /// included, and a block is up to 4 MB where a filter is tens of
    /// kilobytes. A cap that counted only filters was not a cap on the
    /// download at all.
    @Test("a matched block's bytes are charged to the byte budget and can exhaust it")
    func matchedBlockBytesCountAgainstTheBudget() async throws {
        let fixture = try await Self.fixture(chainLength: 6, watchHeight: 3)
        defer { fixture.stop(); fixture.removeFiles() }
        try await fixture.pool.syncHeaders(fixture.chain)
        let watch = [fixture.synthetic.watchScript]

        let measured = try await fixture.sync.scanRange(from: 1, to: 6,
                                                        watchScripts: watch) { _ in }
        #expect(measured.matchedHeights == [3])
        #expect(measured.filterBytesRead > 0)
        #expect(measured.blockBytesRead > 0, "the match pulled a whole block down")
        let spent = measured.filterBytesRead + measured.blockBytesRead

        // A budget of exactly the filters is spent by the block, and only by
        // the block: every filter of the range fits inside it.
        let collector = MatchCollector()
        var thrown: (any Error)?
        do {
            _ = try await fixture.sync.scanRange(
                from: 1, to: 6, watchScripts: watch,
                limits: RangeScanLimits(maxFilterBytes: measured.filterBytesRead),
                storageURL: fixture.rangeFile) { collector.add($0) }
        } catch {
            thrown = error
        }
        guard case let .filterBytesExhausted(read, limit)? = thrown as? RangeScanError else {
            Issue.record("expected filterBytesExhausted, got \(String(describing: thrown))")
            return
        }
        #expect(limit == measured.filterBytesRead)
        #expect(read == spent, "the run stopped on the two halves together")
        #expect(collector.matches.map(\.height) == [3])
        #expect(!FileManager.default.fileExists(atPath: fixture.rangeFile.path))

        // The same run with room for the block finishes.
        let complete = try await fixture.sync.scanRange(
            from: 1, to: 6, watchScripts: watch,
            limits: RangeScanLimits(maxFilterBytes: spent),
            storageURL: fixture.rangeFile) { _ in }
        #expect(complete.isComplete)
        #expect(complete.blockBytesRead == measured.blockBytesRead)
    }

    /// The forward path's cross-check policy, on the range path: a restore's
    /// coins are spend-relevant state, so a caller that refuses to advance on
    /// answers from one acquisition channel is refusing here too. The pool
    /// holds one manual peer, which is one class, and the refusal comes before
    /// a filter is fetched: nothing delivered, nothing written, the forward
    /// frontier never involved.
    @Test("a range scan under the strict cross-check policy is refused before a filter is fetched")
    func strictPolicyRefusesAOneClassRangeScan() async throws {
        let fixture = try await Self.fixture(chainLength: 6, watchHeight: 3,
                                             crossCheckPolicy: .requireDistinctSources)
        defer { fixture.stop(); fixture.removeFiles() }
        try await fixture.pool.syncHeaders(fixture.chain)

        let collector = MatchCollector()
        var thrown: (any Error)?
        do {
            _ = try await fixture.sync.scanRange(
                from: 1, to: 6, watchScripts: [fixture.synthetic.watchScript],
                storageURL: fixture.rangeFile) { collector.add($0) }
        } catch {
            thrown = error
        }
        guard case let .crossCheckUnavailable(reason)? = thrown as? FilterSyncError else {
            Issue.record("expected crossCheckUnavailable, got \(String(describing: thrown))")
            return
        }
        #expect(reason.contains("1 known source class"))
        #expect(collector.matches.isEmpty, "a refused run delivers nothing")
        #expect(!FileManager.default.fileExists(atPath: fixture.rangeFile.path),
                "and writes no record")
        #expect(await fixture.sync.nextScanHeight == 1, "the forward frontier was never involved")
    }

    /// Under the default the same run advances, and says who it advanced on:
    /// the receipt names the one manual peer and its class, sits on the
    /// outcome, is persisted with the record, and is dropped by a restart,
    /// since the next pass earns its own.
    @Test("a range scan records which peers corroborated it, and a restart clears the receipt")
    func rangeScanRecordsItsCorroboration() async throws {
        let fixture = try await Self.fixture(chainLength: 6, watchHeight: 3)
        defer { fixture.stop(); fixture.removeFiles() }
        try await fixture.pool.syncHeaders(fixture.chain)
        let watch = [fixture.synthetic.watchScript]

        let outcome = try await fixture.sync.scanRange(
            from: 1, to: 6, watchScripts: watch, storageURL: fixture.rangeFile) { _ in }
        let receipt = try #require(outcome.crossCheck)
        #expect(receipt.tipHeight == 6)
        #expect(receipt.sourceClasses == [.manual])
        #expect(receipt.agreed.count == 1)
        #expect(receipt.agreed.first?.endpoint == (await fixture.node.endpoint).description)

        let stored = try #require(try RangeScanProgress.load(storageURL: fixture.rangeFile))
        #expect(stored.crossCheck == receipt, "the record stands on the receipt it was committed with")
        let next = stored.restarted(fingerprint: RangeScanProgress.fingerprint(of: [Self.otherScript]))
        #expect(next.crossCheck == nil, "and the next pass starts without one")
    }

    /// Both runs read the chain over one pool, and a peer's reply goes to
    /// whichever collector expects the command first, so the two have to
    /// exclude each other rather than interleave. They share the flag `sync`
    /// already had; this pins that they still do, and that a relay-only pool
    /// refuses the range scan for the same reason it refuses a forward one —
    /// the seats are held so a signed payment can go out, not so a restore can
    /// read history over them.
    @Test("a forward sync during a range scan is refused, and a relay-only pool refuses both")
    func rangeScanAndForwardSyncExcludeEachOther() async throws {
        let fixture = try await Self.fixture(chainLength: 6, watchHeight: 3)
        defer { fixture.stop(); fixture.removeFiles() }
        try await fixture.pool.syncHeaders(fixture.chain)
        let watch = [fixture.synthetic.watchScript]

        let gate = ParkGate()
        let collector = MatchCollector()
        // Bound out of the fixture so the task's closure captures only what
        // it needs.
        let sync = fixture.sync
        let rangeFile = fixture.rangeFile
        // A run that never matched opens the gate too, so a broken scan fails
        // this case on an assertion rather than parking it forever.
        let scan = gate.settling {
            try await sync.scanRange(
                from: 1, to: 6, watchScripts: watch,
                storageURL: rangeFile) { match in
                    collector.add(match)
                    await gate.reach()
                    await gate.waitForRelease()
                }
        }
        await gate.waitForReach()

        await #expect(throws: FilterSyncError.busy) {
            try await fixture.sync.sync(watchScripts: watch) { _ in
                Issue.record("the refused sync must not scan anything")
            }
        }
        #expect(await fixture.sync.nextScanHeight == 1, "the forward frontier never moved")

        await gate.release()
        let outcome = try await scan.value.get()
        #expect(outcome.matchedHeights == [3])
        #expect(collector.matches.map(\.height) == [3])

        // And the flag is cleared on the way out, so the pool is free again —
        // until it is narrowed to relay seats, which refuses both directions.
        _ = await fixture.pool.enterRelayOnly(seats: 1)
        await #expect(throws: FilterSyncError.relayOnly) {
            try await fixture.sync.scanRange(from: 1, to: 6, watchScripts: watch) { _ in }
        }
        await #expect(throws: FilterSyncError.relayOnly) {
            try await fixture.sync.sync(watchScripts: watch) { _ in }
        }
    }
}
