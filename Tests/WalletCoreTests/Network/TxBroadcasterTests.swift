import Foundation
import Testing
import TestSupport
@testable import WalletCore

/// TxBroadcaster's relay behaviour, against loopback nodes: inv announcement
/// and the getdata answer, the BIP133 fee filter, the backoff table, and the
/// deprioritisation of a peer that never asks.
///
/// Combined from `TxBroadcaster` (minus its store-persistence tests, which are
/// now in `TxBroadcasterStoreTests.swift`), `TxBroadcaster backoff schedule`
/// and `Fee filter announcements`. The relay-only sessions at the end came
/// from none of them: they are this fork's mode for a payment still going out
/// while nothing is being read. Only the last of the three carried a suite
/// trait, `.timeLimit(.minutes(2))`; it is the stricter of the three and so it
/// is the trait this suite keeps.
@Suite("TxBroadcaster", .timeLimit(.minutes(2)))
struct TxBroadcasterTests {

    // MARK: - TxBroadcaster
    //
    // Announcement, the getdata answer, confirmation and cancellation, the
    // fee floor. The store-persistence cases these used to sit beside are in
    // `TxBroadcasterStoreTests`.

    @Test("announces witness-tx inv to all peers and answers getdata")
    func announceAndServe() async throws {
        let params = NetworkParams.signet
        let nodeA = LoopbackNode(params: params)
        let nodeB = LoopbackNode(params: params)
        let nodeC = LoopbackNode(params: params)
        for node in [nodeA, nodeB, nodeC] { try await node.start() }
        defer { for node in [nodeA, nodeB, nodeC] { Task { await node.stop() } } }

        var endpoints: [PeerEndpoint] = []
        for node in [nodeA, nodeB, nodeC] { endpoints.append(await node.endpoint) }

        let store = tempFileURL("pending-txs.json")
        let pool = PeerPool(params: params, peerCount: 3, manualPeers: endpoints)
        await pool.start()
        #expect(await pool.connectedPeers().count == 3)

        let broadcaster = try TxBroadcaster(pool: pool, storageURL: store,
                                        rebroadcastBaseInterval: .seconds(3_600))
        let events = await broadcaster.events()
        let tx = makeFakeSegwitTx()
        let rawTx = tx.serialized(includeWitness: true)
        let txid = try await broadcaster.broadcast(rawTx)
        #expect(txid == tx.txid)

        // Every node must receive inv(MSG_WITNESS_TX, txid), then get the tx
        // when it asks via getdata.
        for node in [nodeA, nodeB, nodeC] {
            let invMessage = await node.nextMessage(command: "inv")
            guard case let .inv(payload) = invMessage else {
                Issue.record("no inv received")
                continue
            }
            #expect(payload.vectors == [InventoryVector(type: .witnessTx, hash: txid)])
            try await node.send(.getdata(InventoryPayload(payload.vectors)))
            let txMessage = await node.nextMessage(command: "tx")
            guard case let .tx(served) = txMessage else {
                Issue.record("no tx received")
                continue
            }
            #expect(served == tx)
        }

        // Events: announced to 3 peers, then requested by each.
        let seen = EventCollector<TxBroadcaster.Event>()
        let consumer = Task {
            for await event in events { seen.add(event) }
        }
        let deadline = ContinuousClock.now + .seconds(5)
        while ContinuousClock.now < deadline {
            let events = seen.events
            if events.contains(where: {
                if case .announced(_, peerCount: 3) = $0 { return true }
                return false
            }), events.filter({ if case .requested = $0 { return true }; return false }).count == 3 {
                break
            }
            try await Task.sleep(for: .milliseconds(20))
        }
        consumer.cancel()
        #expect(seen.events.contains {
            if case .announced(_, peerCount: 3) = $0 { return true }
            return false
        })
        #expect(seen.events.filter {
            if case .requested = $0 { return true }
            return false
        }.count == 3)

        // Pending tx survives a restart (JSON persistence).
        let reloaded = try TxBroadcaster(pool: pool, storageURL: store)
        #expect(await reloaded.pendingTxids == [txid])

        try await broadcaster.markConfirmed(txid, atHeight: 1)
        #expect(await broadcaster.pendingTxids.isEmpty)

        await pool.stop()
        try? FileManager.default.removeItem(at: store.deletingLastPathComponent())
    }

    @Test("broadcasting malformed raw tx data throws")
    func malformedTx() async throws {
        let pool = PeerPool(params: .signet, peerCount: 0, manualPeers: [])
        let broadcaster = try TxBroadcaster(pool: pool)
        await #expect(throws: (any Error).self) {
            try await broadcaster.broadcast(Data([0x01, 0x02, 0x03]))
        }
    }

    @Test("a served peer that goes away stays served, and served survives a reload")
    func servedIsSticky() async throws {
        let store = FileManager.default.temporaryDirectory
            .appending(path: "broadcaster-served-\(UUID().uuidString)/broadcast.json")
        try FileManager.default.createDirectory(at: store.deletingLastPathComponent(), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: store.deletingLastPathComponent()) }
        let fixture = try await BroadcasterFixture.make(autoRequestDelay: .milliseconds(50), storageURL: store)
        defer { fixture.stop() }
        let (node, pool, broadcaster, seen) = (fixture.node, fixture.pool, fixture.broadcaster, fixture.seen)

        let tx = makeFakeSegwitTx()
        let txid = try await broadcaster.broadcast(tx.serialized(includeWitness: true))
        let endpoint = fixture.endpoint
        #expect(await pollUntil { seen.events.contains { $0 == .served(txid: txid, peer: endpoint) } })
        #expect(await broadcaster.wasServed(txid))

        // The peer goes away. Its relay entry does not become a failure: it
        // was handed the bytes; that fact alone does not prove acceptance.
        await node.stop()
        _ = await pollUntil { await pool.connectedPeers().isEmpty }
        #expect(await broadcaster.relayStatus(txid)[endpoint.description] == .served)
        #expect(!seen.events.contains { if case .failed(let id, let peer, _) = $0 { return id == txid && peer == endpoint }; return false })
        #expect(await broadcaster.wasServed(txid))

        // A reload remembers.
        await pool.stop()
        let reloaded = try TxBroadcaster(pool: pool, storageURL: store, rebroadcastBaseInterval: .seconds(3_600))
        #expect(await reloaded.wasServed(txid))
        #expect(await reloaded.pendingTxids == [txid])
    }

    @Test("a legacy relay record never invents a successful handoff")
    func legacyServedDefaultsFalse() async throws {
        let url = tempFileURL("legacy-served.json")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let pool = PeerPool(params: .signet, peerCount: 0, manualPeers: [])
        let broadcaster = try TxBroadcaster(pool: pool, storageURL: url)
        let txid = try await broadcaster.broadcast(makeFakeSegwitTx().serialized(includeWitness: true))
        #expect(await !broadcaster.wasServed(txid), "no peer was connected")
        await broadcaster.shutdown()
        var root = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        var entries = try #require(root["transactions"] as? [String: [String: Any]])
        for key in entries.keys { entries[key]?.removeValue(forKey: "served") }
        root["transactions"] = entries
        try JSONSerialization.data(withJSONObject: root).write(to: url)
        let reopened = try TxBroadcaster(pool: pool, storageURL: url)
        #expect(await !reopened.wasServed(txid))
        #expect(await reopened.pendingTxids == [txid])
        await reopened.shutdown()
    }

    @Test("serves a delayed getdata and tracks per-peer state")
    func delayedGetdata() async throws {
        let fixture = try await BroadcasterFixture.make(autoRequestDelay: .milliseconds(100))
        defer { fixture.stop() }
        let (node, broadcaster, seen) = (fixture.node, fixture.broadcaster, fixture.seen)

        let tx = makeFakeSegwitTx()
        let txid = try await broadcaster.broadcast(tx.serialized(includeWitness: true))
        let endpoint = fixture.endpoint

        // The node requests after its delay and is then served the tx.
        let served = await pollUntil {
            seen.events.contains { $0 == .served(txid: txid, peer: endpoint) }
        }
        #expect(served)
        #expect(seen.events.contains { $0 == .requested(txid: txid, peer: endpoint) })
        #expect(await broadcaster.relayStatus(txid)[endpoint.description] == .served)

        guard case let .tx(servedTx) = await node.nextMessage(command: "tx") else {
            Issue.record("node never received the tx")
            return
        }
        #expect(servedTx == tx)
    }

    @Test("deprioritizes a peer that never answers invs with getdata")
    func deprioritizesSilentPeer() async throws {
        let params = NetworkParams.signet
        let nodeA = LoopbackNode(params: params, autoRequestDelay: .milliseconds(20))
        let nodeB = LoopbackNode(params: params, autoRequestDelay: .milliseconds(20))
        let silent = LoopbackNode(params: params) // never requests
        for node in [nodeA, nodeB, silent] { try await node.start() }
        defer { for node in [nodeA, nodeB, silent] { Task { await node.stop() } } }

        var endpoints: [PeerEndpoint] = []
        for node in [nodeA, nodeB, silent] { endpoints.append(await node.endpoint) }
        let silentEndpoint = await silent.endpoint

        let pool = PeerPool(params: params, peerCount: 3, manualPeers: endpoints)
        await pool.start()
        #expect(await pool.connectedPeers().count == 3)

        let broadcaster = try TxBroadcaster(pool: pool,
                                        rebroadcastBaseInterval: .milliseconds(150),
                                        maxRebroadcastInterval: .milliseconds(600),
                                        maxAnnouncementsPerPeer: 2,
                                        announcementTimeout: .milliseconds(100))
        let seen = EventCollector<TxBroadcaster.Event>()
        let events = await broadcaster.events()
        let consumer = Task { for await event in events { seen.add(event) } }
        defer { consumer.cancel() }

        let txid = try await broadcaster.broadcast(makeFakeSegwitTx().serialized(includeWitness: true))

        // After exactly 2 unanswered announcements the silent peer is skipped.
        let dropped = await pollUntil {
            seen.events.contains { $0 == .deprioritized(txid: txid, peer: silentEndpoint) }
        }
        #expect(dropped)
        #expect(await broadcaster.relayStatus(txid)[silentEndpoint.description] == .deprioritized)

        // It saw exactly the initial inv plus one retry, and nothing after.
        #expect(await silent.nextMessage(command: "inv") != nil)
        #expect(await silent.nextMessage(command: "inv") != nil)
        #expect(await silent.nextMessage(command: "inv", timeout: .milliseconds(800)) == nil)

        // The responsive peers keep being served on every announcement.
        #expect(seen.events.contains { $0 == .served(txid: txid, peer: endpoints[0]) })
        #expect(seen.events.contains { $0 == .served(txid: txid, peer: endpoints[1]) })

        await pool.stop()
    }

    @Test("rebroadcast backs off exponentially, capped, with injected intervals")
    func exponentialBackoff() async throws {
        // 100ms base, doubling, capped at 250ms → gaps 100, 200, 250, 250.
        let fixture = try await BroadcasterFixture.make(
            autoRequestDelay: .milliseconds(20),
            rebroadcastBase: .milliseconds(100), maxRebroadcast: .milliseconds(250),
            announcementTimeout: .seconds(30))
        defer { fixture.stop() }
        let broadcaster = fixture.broadcaster
        let txid = try await broadcaster.broadcast(makeFakeSegwitTx().serialized(includeWitness: true))

        var schedule: [Date] = []
        if let first = await broadcaster.nextAttemptDate(txid) { schedule.append(first) }
        for attempt in 1 ... 3 {
            // `>=`, not `==`. The counter advances every 100-250ms for as long
            // as the broadcaster runs, so equality asks the poll to observe it
            // inside one interval. A contended runner that misses that window
            // can never satisfy the check again -- the counter is already past
            // it -- so the test burned the full hang-guard three times and
            // failed with the schedule assertions below still passing (#144).
            let reached = await pollUntil {
                await broadcaster.attemptCount(txid) ?? 0 >= attempt
            }
            #expect(reached)
            if let date = await broadcaster.nextAttemptDate(txid) { schedule.append(date) }
        }
        #expect(schedule.count == 4)
        guard schedule.count == 4 else { return }
        let gaps = zip(schedule, schedule.dropFirst()).map { $1.timeIntervalSince($0) }
        // What this test can honestly prove is that attempts fire and that the
        // schedule only ever moves forward. It cannot prove the *size* of a
        // step, nor that any single sample caught its own step: the schedule is
        // sampled by polling, so a loaded runner can advance the counter twice
        // between two samples (leaving a zero gap) or read an already-advanced
        // entry (inflating one). Asserting per-step movement is therefore an
        // assertion about scheduling luck, which is what made this a flaky
        // release gate (#138, #144).
        //
        // So: never backwards, forward overall, and the attempts really fired.
        // The doubling-then-cap shape is checked exhaustively and without a
        // clock in "TxBroadcaster backoff schedule".
        #expect(gaps.allSatisfy { $0 >= 0 }, "the schedule must never move backwards")
        #expect(schedule.last! > schedule.first!, "three attempts must push the schedule forward")
        #expect(await broadcaster.attemptCount(txid) ?? 0 >= 3, "three attempts must have fired")
    }

    @Test("stops rebroadcasting on confirmation and on explicit cancel")
    func stopOnConfirmationAndCancel() async throws {
        let fixture = try await BroadcasterFixture.make(
            rebroadcastBase: .milliseconds(150), maxRebroadcast: .milliseconds(600),
            announcementTimeout: .seconds(30))
        defer { fixture.stop() }
        let (node, broadcaster, seen) = (fixture.node, fixture.broadcaster, fixture.seen)

        // Confirmed tx: no further invs.
        let txid1 = try await broadcaster.broadcast(makeFakeSegwitTx().serialized(includeWitness: true))
        #expect(await node.nextMessage(command: "inv") != nil)
        try await broadcaster.markConfirmed(txid1, atHeight: 1)
        // The pending entry is gone, so no further attempt can be scheduled.
        // That is the claim, and it is deterministic.
        #expect(await broadcaster.pendingTxids.isEmpty)
        // The wire check is about what happens *after* that. Rebroadcasts
        // already sent when the confirmation landed are not counter-examples,
        // and the old drain-then-stay-quiet shape could not tell them apart
        // from real ones: a straggler landing inside the 700ms quiet window
        // failed the test on a loaded runner (#164, twice on main). The
        // barrier consumes everything already in flight, so the quiet window
        // now only ever sees newly scheduled attempts — which the empty
        // pending set above proves cannot exist.
        await drainQueuedInvs(from: node)
        try await stragglersFlushed(node)
        #expect(await node.nextMessage(command: "inv", timeout: .milliseconds(700)) == nil)
        #expect(seen.events.contains { $0 == .confirmed(txid: txid1) })

        // Cancelled tx: no further invs either.
        let txid2 = try await broadcaster.broadcast(makeFakeSegwitTx().serialized(includeWitness: true))
        #expect(await node.nextMessage(command: "inv") != nil)
        try await broadcaster.cancel(txid2)
        #expect(await broadcaster.pendingTxids.isEmpty)
        // Same shape as the confirmation branch, for the same reason.
        await drainQueuedInvs(from: node)
        try await stragglersFlushed(node)
        #expect(await node.nextMessage(command: "inv", timeout: .milliseconds(700)) == nil)
        #expect(seen.events.contains { $0 == .cancelled(txid: txid2) })
    }

    @Test("emits feeFloorExceeded when every peer's feefilter exceeds the tx feerate")
    func feeFloorExceeded() async throws {
        let params = NetworkParams.signet
        let nodeA = LoopbackNode(params: params, autoRequestDelay: .milliseconds(20))
        let nodeB = LoopbackNode(params: params, autoRequestDelay: .milliseconds(20))
        for node in [nodeA, nodeB] { try await node.start() }
        defer { for node in [nodeA, nodeB] { Task { await node.stop() } } }

        var endpoints: [PeerEndpoint] = []
        for node in [nodeA, nodeB] { endpoints.append(await node.endpoint) }
        let pool = PeerPool(params: params, peerCount: 2, manualPeers: endpoints)
        await pool.start()

        let broadcaster = try TxBroadcaster(pool: pool,
                                        rebroadcastBaseInterval: .milliseconds(150),
                                        maxRebroadcastInterval: .milliseconds(600),
                                        announcementTimeout: .seconds(30))
        let seen = EventCollector<TxBroadcaster.Event>()
        let events = await broadcaster.events()
        let consumer = Task { for await event in events { seen.add(event) } }
        defer { consumer.cancel() }

        // 1 sat/vB = 1000 sat/kvB.
        let txid = try await broadcaster.broadcast(makeFakeSegwitTx().serialized(includeWitness: true),
                                                   feeRateSatPerVByte: 1)
        // Drain the initial announcement so later inv checks only match
        // rebroadcasts.
        #expect(await nodeA.nextMessage(command: "inv") != nil)

        // One peer raises its floor to 5 sat/vB, but the other still relays.
        try await nodeA.send(.feefilter(5_000))
        try? await Task.sleep(for: .milliseconds(100))
        #expect(!seen.events.contains { if case .feeFloorExceeded = $0 { return true }; return false })

        // Now the second peer raises too: the minimum (5 sat/vB) exceeds the
        // tx's 1 sat/vB — no remaining peer will relay it.
        try await nodeB.send(.feefilter(9_000))
        let emitted = await pollUntil {
            seen.events.contains { $0 == .feeFloorExceeded(txid: txid, floor: 5_000) }
        }
        #expect(emitted)

        // Nothing is announced to a peer that has said it will drop the
        // bytes (BIP133): retries keep running, but node A hears none of them
        // while its floor refuses the transaction. A rebroadcast that fired
        // before node A's floor reached the broadcaster was legitimate and can
        // still sit in A's inbox on a slow runner; drain it, so the window
        // below only sees announcements made after the floor took effect.
        while await nodeA.nextMessage(command: "inv", timeout: .milliseconds(50)) != nil {}
        #expect(await nodeA.nextMessage(command: "inv", timeout: .milliseconds(600)) == nil)

        // Floor dropping back below the feerate rearms the event, and the
        // next attempt announces to node A again…
        try await nodeA.send(.feefilter(500))
        #expect(await nodeA.nextMessage(command: "inv", timeout: .seconds(10)) != nil)
        // …so a later rise emits it again.
        try await nodeA.send(.feefilter(2_000))
        let reemitted = await pollUntil {
            seen.events.filter { if case .feeFloorExceeded = $0 { return true }; return false }.count == 2
        }
        #expect(reemitted)
        #expect(seen.events.contains { $0 == .feeFloorExceeded(txid: txid, floor: 2_000) })

        await pool.stop()
    }

    // MARK: - TxBroadcaster backoff schedule
    //
    // The rebroadcast backoff policy, checked without a clock.
    //
    // The integration test above proves attempts fire and the schedule
    // advances; it deliberately does not measure step sizes, because it
    // samples the schedule by polling and a late poll inflates the
    // measurement. The step sizes live here instead, where they are a pure
    // function of the attempt count and the configured intervals (#138).

    /// Every (base, cap, attempt) the schedule is pinned at, with the interval
    /// it must produce. The cap is inclusive — the guard is `<`, so the moment
    /// doubling would *reach* the cap the cap is taken — and no attempt past
    /// that point, however large, ever schedules beyond it.
    static let steps: [(base: Duration, cap: Duration, attempt: Int, expected: Duration)] = [
        // Doubles from the base on every attempt until the cap, then holds:
        // 200 doubled is 400, past the cap, so the cap is taken instead.
        (.milliseconds(100), .milliseconds(250), 0, .milliseconds(100)),
        (.milliseconds(100), .milliseconds(250), 1, .milliseconds(200)),
        (.milliseconds(100), .milliseconds(250), 2, .milliseconds(250)),
        (.milliseconds(100), .milliseconds(250), 3, .milliseconds(250)),
        (.milliseconds(100), .milliseconds(250), 50, .milliseconds(250)),
        // Doubling 100ms lands exactly on the 200ms cap: the cap wins, and the
        // boundary case does not produce a longer interval than the cap.
        (.milliseconds(100), .milliseconds(200), 1, .milliseconds(200)),
        // An uncapped schedule is exactly base × 2^attempt.
        (.seconds(1), .seconds(3_600), 0, .seconds(1)),
        (.seconds(1), .seconds(3_600), 1, .seconds(2)),
        (.seconds(1), .seconds(3_600), 2, .seconds(4)),
        (.seconds(1), .seconds(3_600), 3, .seconds(8)),
        (.seconds(1), .seconds(3_600), 4, .seconds(16)),
        (.seconds(1), .seconds(3_600), 5, .seconds(32)),
        (.seconds(1), .seconds(3_600), 6, .seconds(64)),
        (.seconds(1), .seconds(3_600), 7, .seconds(128)),
        (.seconds(1), .seconds(3_600), 8, .seconds(256)),
        (.seconds(1), .seconds(3_600), 9, .seconds(512)),
        (.seconds(1), .seconds(3_600), 10, .seconds(1_024)),
        // The shipped defaults double six times before capping at an hour:
        // 1,920 doubled is 3,840 — past the hour cap, so the cap is taken.
        (.seconds(60), .seconds(3_600), 0, .seconds(60)),
        (.seconds(60), .seconds(3_600), 1, .seconds(120)),
        (.seconds(60), .seconds(3_600), 2, .seconds(240)),
        (.seconds(60), .seconds(3_600), 3, .seconds(480)),
        (.seconds(60), .seconds(3_600), 4, .seconds(960)),
        (.seconds(60), .seconds(3_600), 5, .seconds(1_920)),
        (.seconds(60), .seconds(3_600), 6, .seconds(3_600)),
        // ...and no later attempt schedules beyond the cap, out to the
        // counter's saturation point (`retryCounterSaturates` below).
        (.seconds(60), .seconds(3_600), 7, .seconds(3_600)),
        (.seconds(60), .seconds(3_600), 32, .seconds(3_600)),
        (.seconds(60), .seconds(3_600), 63, .seconds(3_600)),
        (.seconds(60), .seconds(3_600), 64, .seconds(3_600)),
        // A cap below the base is a degenerate configuration, but it must not
        // return an interval longer than the cap the caller asked for.
        (.seconds(60), .seconds(10), 0, .seconds(10)),
    ]

    @Test("the interval is base × 2^attempt, capped inclusively and held there",
          arguments: Self.steps)
    func stepIsPinned(_ row: (base: Duration, cap: Duration, attempt: Int, expected: Duration)) {
        let interval = TxBroadcaster.backoffInterval(attempt: row.attempt, base: row.base, cap: row.cap)
        #expect(interval == row.expected,
                "attempt \(row.attempt) from \(row.base) capped at \(row.cap)")
        #expect(interval <= row.cap, "attempt \(row.attempt) exceeded the cap")
    }

    /// The retry counter saturates instead of growing without bound, and the
    /// reason is not tidiness: `load` refuses any record whose attempt is
    /// outside `0...maximumAttempt`, and it refuses by throwing for the whole
    /// file. So an unclamped counter does not cost one transaction -- it makes
    /// the entire pending store unloadable, and every transaction waiting in it
    /// is forgotten at the next launch.
    ///
    /// That state is reachable in practice. At the shipped defaults the
    /// interval caps at an hour, so a transaction still unconfirmed after
    /// roughly two and a half days has fired 64 attempts. Driven here with a
    /// 1ms interval and no peers, so it is arithmetic rather than a wait.
    @Test("the retry counter saturates, leaving the store loadable")
    func retryCounterSaturates() async throws {
        let pool = PeerPool(params: .signet, peerCount: 0, manualPeers: [])
        let store = tempFileURL("pending-saturate.json")
        defer { try? FileManager.default.removeItem(at: store.deletingLastPathComponent()) }
        let broadcaster = try TxBroadcaster(pool: pool, storageURL: store,
                                            rebroadcastBaseInterval: .milliseconds(1),
                                            maxRebroadcastInterval: .milliseconds(1))
        let txid = try await broadcaster.broadcast(
            makeFakeSegwitTx().serialized(includeWitness: true))

        // Run past the ceiling, then let it keep firing: the point is that it
        // stops climbing, not merely that it arrives.
        var saturated = false
        let deadline = ContinuousClock.now + .seconds(60) // hang-guard, not a deadline
        while ContinuousClock.now < deadline {
            if await broadcaster.attemptCount(txid) ?? 0 >= 63 { saturated = true; break }
            try? await Task.sleep(for: .milliseconds(5))
        }
        #expect(saturated)
        try? await Task.sleep(for: .milliseconds(50))
        #expect(await broadcaster.attemptCount(txid) == 63,
                "the counter must hold at the ceiling rather than climb past it")
        await broadcaster.shutdown()

        // The consequence that actually matters: the store still loads, so the
        // transaction is still being rebroadcast after a restart.
        let reloaded = try TxBroadcaster(pool: pool, storageURL: store,
                                         rebroadcastBaseInterval: .milliseconds(1),
                                         maxRebroadcastInterval: .milliseconds(1))
        #expect(await reloaded.pendingTxids == [txid],
                "a saturated counter must not make the pending store unloadable")
        await reloaded.shutdown()
    }

    /// The signed bytes stay reachable while a transaction is pending.
    ///
    /// Winnow relays over its own peers with no fallback submission path, so
    /// when relay is not working the transaction itself is the only thing that
    /// can leave the device. Handing the user a txid for something no one has
    /// seen is not much use; handing them the bytes is an escape hatch.
    @Test("a pending transaction's raw bytes can be read back")
    func rawTransactionIsRecoverable() async throws {
        let pool = PeerPool(params: .signet, peerCount: 0, manualPeers: [])
        let broadcaster = try TxBroadcaster(pool: pool,
                                            rebroadcastBaseInterval: .seconds(60))
        let raw = makeFakeSegwitTx().serialized(includeWitness: true)
        let txid = try await broadcaster.broadcast(raw)

        #expect(await broadcaster.rawTransaction(txid) == raw,
                "the bytes handed back must be the bytes that were signed")

        // Unknown txids are simply absent rather than an error.
        #expect(await broadcaster.rawTransaction(Data(repeating: 0xFF, count: 32)) == nil)

        // Once it confirms it is on the chain, and the txid is the handle.
        try await broadcaster.markConfirmed(txid, atHeight: 1)
        #expect(await broadcaster.rawTransaction(txid) == nil)
        await broadcaster.shutdown()
    }

    // MARK: - Fee filter announcements
    //
    // BIP133: a peer whose fee filter is above a transaction's rate has said
    // it will drop the bytes unread. Announcing to it is noise, and the
    // deprioritization it would earn hides the real reason.

    @Test("a peer whose fee filter refuses the transaction is not announced to until the filter drops")
    func feeFilterSkipsPeer() async throws {
        let fixture = try await BroadcasterFixture.make(
            rebroadcastBase: .milliseconds(300), maxRebroadcast: .milliseconds(600),
            announcementTimeout: .seconds(30))
        defer { fixture.stop() }
        let (node, pool, broadcaster) = (fixture.node, fixture.pool, fixture.broadcaster)
        _ = await node.nextMessage(command: "verack", timeout: .seconds(10))

        // 100 sat/vB: nothing this test sends clears it.
        try await node.send(.feefilter(100_000))
        let peer = try #require(await pool.connectedPeers().first)
        for _ in 0 ..< 100 where await peer.feeFilter != 100_000 {
            try await Task.sleep(for: .milliseconds(50))
        }
        #expect(await peer.feeFilter == 100_000)

        let txid = try await broadcaster.broadcast(
            makeFakeSegwitTx().serialized(includeWitness: true), feeRateSatPerVByte: 2)
        #expect(await node.nextMessage(command: "inv", timeout: .seconds(1)) == nil,
                "the peer said it would drop it; no announcement")
        #expect(await broadcaster.relayStatus(txid).isEmpty,
                "skipped, not marked: no relay state was recorded against the peer")

        // The filter drops to 1 sat/vB; the next scheduled attempt announces.
        try await node.send(.feefilter(1_000))
        #expect(await node.nextMessage(command: "inv", timeout: .seconds(10)) != nil,
                "a filter that later allows the transaction lets the peer back in")
    }

    // MARK: - Relay-only sessions
    //
    // A wallet that goes idle with a payment in flight has two bad options and
    // one good one. Stopping the pool disconnects the peers announcements go
    // over, so the transaction stops being relayed until the app is opened
    // again; keeping the full pool up pays for a sync pool nobody is reading.
    // `enterRelayOnly` is the third: a seat held for the announcements, and a
    // pool that stops itself when there is nothing left to announce.

    @Test("a relay-only session keeps a pending payment announcing and being served")
    func relayOnlyKeepsRelaying() async throws {
        let params = NetworkParams.signet
        var nodes: [LoopbackNode] = []
        var endpoints: [PeerEndpoint] = []
        var byEndpoint: [PeerEndpoint: LoopbackNode] = [:]
        for _ in 0 ..< 3 {
            let node = LoopbackNode(params: params)
            try await node.start()
            nodes.append(node)
            endpoints.append(await node.endpoint)
            byEndpoint[await node.endpoint] = node
        }
        defer { for node in nodes { Task { await node.stop() } } }

        let pool = PeerPool(params: params, peerCount: 3, manualPeers: endpoints)
        await pool.start()
        #expect(await pool.connectedPeers().count == 3)

        // A high per-peer announcement ceiling: this is about relay surviving
        // the narrowing, not about the peer that never answers.
        let broadcaster = try TxBroadcaster(pool: pool,
                                            rebroadcastBaseInterval: .milliseconds(500),
                                            maxRebroadcastInterval: .seconds(1),
                                            maxAnnouncementsPerPeer: 20,
                                            announcementTimeout: .seconds(30))
        defer { Task { await broadcaster.shutdown() } }
        let tx = makeFakeSegwitTx()
        let txid = try await broadcaster.broadcast(tx.serialized(includeWitness: true))
        for node in nodes {
            #expect(await node.nextMessage(command: "inv") != nil, "every peer hears the first inv")
        }

        let opened = try await broadcaster.enterRelayOnly(seats: 1)
        #expect(opened, "a pending payment is what a session is opened for")
        #expect(await broadcaster.isRelayOnly)
        #expect(await pool.mode == .relayOnly)
        let seat = try #require(await pool.connectedPeers().first)
        let kept = try #require(byEndpoint[await seat.endpoint])

        // The seat that stayed goes on hearing rebroadcasts. Drained first, so
        // this is an announcement scheduled after the narrowing rather than
        // one that was already in flight when it happened.
        await drainQueuedInvs(from: kept)
        #expect(await kept.nextMessage(command: "inv", timeout: .seconds(10)) != nil,
                "the backoff loop must keep announcing over the seat that stayed")

        // And the bytes still go out when that peer asks for them, which is
        // the half of relay that actually puts the transaction on the network.
        try await kept.send(.getdata(InventoryPayload([
            InventoryVector(type: .witnessTx, hash: txid)])))
        guard case let .tx(served) = await kept.nextMessage(command: "tx") else {
            Issue.record("a relay-only session did not answer getdata")
            return
        }
        #expect(served == tx)
        #expect(await pool.isRunning, "the session holds the pool open while the payment is pending")
        await pool.stop()
    }

    @Test("the pool stops itself once the relay-only session has nothing pending")
    func relayOnlyStopsWhenDrained() async throws {
        let fixture = try await BroadcasterFixture.make()
        defer { fixture.stop() }
        let (pool, broadcaster) = (fixture.pool, fixture.broadcaster)

        let confirmed = try await broadcaster.broadcast(
            makeFakeSegwitTx().serialized(includeWitness: true))
        var opened = try await broadcaster.enterRelayOnly()
        #expect(opened)
        #expect(await pool.connectedPeers().count == 1)

        // The confirmation is the drain, and nothing external watches for it:
        // the broadcaster owns the pending set, so it is the thing that can
        // say the pool has no work left.
        try await broadcaster.markConfirmed(confirmed, atHeight: 1)
        #expect(await pollUntil(.seconds(10)) { await poolIsStopped(pool) },
                "a drained session must stop its pool without being asked")
        #expect(await broadcaster.isRelayOnly == false)

        // The same for a cancellation, which is what a fee bump does to the
        // transaction it replaces — and `start()` is all it takes to come back
        // from a stopped pool.
        await pool.start()
        #expect(await pool.connectedPeers().count == 1)
        let cancelled = try await broadcaster.broadcast(
            makeFakeSegwitTx(value: 40_000).serialized(includeWitness: true))
        opened = try await broadcaster.enterRelayOnly()
        #expect(opened)
        try await broadcaster.cancel(cancelled)
        #expect(await pollUntil(.seconds(10)) { await poolIsStopped(pool) })
    }

    @Test("a session whose pool went back to full service does not stop it on the drain")
    func relayOnlyYieldsToAResumedPool() async throws {
        let fixture = try await BroadcasterFixture.make()
        defer { fixture.stop() }
        let (pool, broadcaster) = (fixture.pool, fixture.broadcaster)
        let txid = try await broadcaster.broadcast(
            makeFakeSegwitTx().serialized(includeWitness: true))
        _ = try await broadcaster.enterRelayOnly()

        // The app comes back and resumes full service, so the pool is being
        // synced over again. The payment confirming a moment later must end
        // the session without taking those peers away.
        await pool.start()
        try await broadcaster.markConfirmed(txid, atHeight: 1)
        #expect(await pollUntil(.seconds(10)) { await broadcaster.isRelayOnly == false })
        try await Task.sleep(for: .milliseconds(200))
        #expect(await pool.isRunning, "a resumed pool belongs to its caller again")
        #expect(await pool.connectedPeers().count == 1)
    }

    @Test("a relay-only session with nothing pending stops the pool instead of holding it")
    func relayOnlyWithNothingPending() async throws {
        let fixture = try await BroadcasterFixture.make()
        defer { fixture.stop() }
        let (pool, broadcaster) = (fixture.pool, fixture.broadcaster)

        // Nothing is in flight, so there is nothing to stay up for: the caller
        // asked to go quiet and quiet is available immediately.
        let opened = try await broadcaster.enterRelayOnly()
        #expect(opened == false)
        #expect(await broadcaster.isRelayOnly == false)
        #expect(await pool.isRunning == false)
        #expect(await pool.connectedPeers().isEmpty)

        // A finished relay session cannot open one, exactly as it cannot
        // broadcast, confirm or cancel.
        await broadcaster.shutdown()
        await #expect(throws: TxBroadcasterError.stopped) {
            _ = try await broadcaster.enterRelayOnly()
        }
    }

    /// A session with no seat is no session, and is reported as none.
    ///
    /// The pool refuses to narrow a pool it cannot narrow — one already
    /// stopped, or one whose peers have all gone — and a broadcaster that
    /// recorded a session anyway would tell the caller "relaying in the
    /// background" over zero connections. Nothing would ever announce, and
    /// nothing could ever end it either: the drain that closes a session
    /// arrives with a confirmation, and a confirmation needs the filter sync
    /// the mode refuses.
    @Test("a session that could keep no seat reports none and stops the pool")
    func relayOnlyWithNoSeats() async throws {
        // A pool with a peer, so the transaction can be broadcast, and then no
        // pool at all: the peer is gone by the time the session is asked for.
        let fixture = try await BroadcasterFixture.make()
        defer { fixture.stop() }
        let (pool, broadcaster) = (fixture.pool, fixture.broadcaster)
        _ = try await broadcaster.broadcast(makeFakeSegwitTx().serialized(includeWitness: true))
        #expect(await broadcaster.pendingTxids.count == 1, "there is something to relay")
        await pool.stop()

        let opened = try await broadcaster.enterRelayOnly()
        #expect(opened == false, "a payment is pending, but nothing is connected to relay it over")
        #expect(await broadcaster.isRelayOnly == false)
        #expect(await pool.isRunning == false)
        #expect(await pool.mode == .full, "no session was left open on a pool holding nothing")
    }

    /// The drain's stop and a caller resuming the pool are the same instant on
    /// iOS — the suspended task and the app's foreground `start()` become
    /// runnable together at the unfreeze boundary — so the end state must not
    /// depend on which of them the scheduler runs first.
    ///
    /// It did. `closeRelayOnlySession` re-read `pool.mode` and then called
    /// `pool.stop()` as two jobs on the pool, so a `start()` landing in the
    /// gap ran first and was silently undone: zero peers, `started == false`,
    /// and `retry()` a no-op (it is gated on `started`), until the user
    /// backgrounded and foregrounded the app again. `stopIfRelayOnly` makes
    /// the question and the answer one job, and then the order stops
    /// mattering: run first, it stops a pool the caller had not yet taken
    /// back and the `start()` that follows brings it up; run second, it finds
    /// full service and expires.
    ///
    /// Which is the invariant asserted every round: after a drain and a
    /// resume, the pool is running and seated, whatever the interleaving.
    @Test("a drain that races the caller resuming the pool never leaves it stopped")
    func relayOnlyDrainDoesNotUndoAResume() async throws {
        let fixture = try await BroadcasterFixture.make()
        defer { fixture.stop() }
        let (pool, broadcaster) = (fixture.pool, fixture.broadcaster)

        for round in 0 ..< 30 {
            // A distinct txid per round, so each is a real pending payment
            // that drains on its own confirmation.
            let txid = try await broadcaster.broadcast(
                makeFakeSegwitTx(value: 50_000 - Int64(round)).serialized(includeWitness: true))
            #expect(try await broadcaster.enterRelayOnly(seats: 1), "round \(round)")

            // The confirmation spawns the session's stop; the resume is the
            // app coming back. Varying how much of the stop's first hop gets
            // to run before the resume is enqueued walks the window rather
            // than sampling one point in it.
            try await broadcaster.markConfirmed(txid, atHeight: UInt32(round + 1))
            for _ in 0 ..< (round % 3) { await Task.yield() }
            await pool.start()

            #expect(await pollUntil(.seconds(10)) { await broadcaster.isRelayOnly == false },
                    "round \(round): the session must close on the drain")
            // Give a stop that is still queued time to land, then read the
            // pool: a resumed pool is running and seated.
            try await Task.sleep(for: .milliseconds(50))
            #expect(await pool.isRunning,
                    "round \(round): a resumed pool must not be stopped by the drain it raced")
            #expect(await pool.connectedPeers().count == 1, "round \(round)")
            try await broadcaster.cancel(txid)
        }
    }

    /// `enterRelayOnly` checks that something is pending, narrows the pool,
    /// and records the session. The narrowing is a suspension, and the
    /// broadcaster runs other work inside it. A confirmation landing there is
    /// the drain: it empties the pending set and calls the close, which finds
    /// no session to close and does nothing. The session recorded on the far
    /// side is then a session over nothing, and nothing is left to end it: the
    /// pool is held open for a payment that already confirmed, with the
    /// caller told "relaying in the background".
    ///
    /// The pool is parked inside its narrowing so the confirmation lands
    /// while the broadcaster is genuinely suspended on that call, not
    /// sometime near it.
    @Test("a drain that lands while the pool is being narrowed opens no session")
    func relayOnlyDrainDuringNarrowingOpensNoSession() async throws {
        let fixture = try await BroadcasterFixture.make()
        defer { fixture.stop() }
        let (pool, broadcaster) = (fixture.pool, fixture.broadcaster)
        let txid = try await broadcaster.broadcast(
            makeFakeSegwitTx().serialized(includeWitness: true))

        let gate = ParkGate()
        await pool.holdNarrowing { await gate.reach(); await gate.waitForRelease() }
        // A call that returns without ever narrowing the pool opens the gate
        // too, so a broken path fails on an assertion instead of parking the
        // test on a wait that will never be resumed.
        let opening = gate.settling { try await broadcaster.enterRelayOnly(seats: 1) }
        await gate.waitForReach()
        #expect(await pool.mode == .relayOnly, "the pool is mid-narrowing")
        #expect(await broadcaster.isRelayOnly == false, "and no session is recorded yet")

        // The confirmation is the drain, landing inside the suspension.
        try await broadcaster.markConfirmed(txid, atHeight: 1)
        #expect(await broadcaster.pendingTxids.isEmpty)
        await gate.release()

        let opened = try await opening.value.get()
        #expect(opened == false, "nothing is pending, so there is nothing to hold a session for")
        #expect(await broadcaster.isRelayOnly == false,
                "a session recorded over a drained set has no drain left to end it")
        #expect(await poolIsStopped(pool),
                "the pool must go quiet, which is what the caller asked for")
    }

    /// The other thing that can land inside the narrowing is `shutdown()`.
    /// It ends every session and, by its own contract, leaves the pool to the
    /// caller. A session recorded after it would have a finished broadcaster
    /// reporting "relaying in the background" over a pool it had narrowed and
    /// can never drain.
    @Test("a shutdown that lands while the pool is being narrowed opens no session")
    func relayOnlyShutdownDuringNarrowingOpensNoSession() async throws {
        let fixture = try await BroadcasterFixture.make()
        defer { fixture.stop() }
        let (pool, broadcaster) = (fixture.pool, fixture.broadcaster)
        _ = try await broadcaster.broadcast(makeFakeSegwitTx().serialized(includeWitness: true))

        let gate = ParkGate()
        await pool.holdNarrowing { await gate.reach(); await gate.waitForRelease() }
        // A call that returns without ever narrowing the pool opens the gate
        // too, so a broken path fails on an assertion instead of parking the
        // test on a wait that will never be resumed.
        let opening = gate.settling { try await broadcaster.enterRelayOnly(seats: 1) }
        await gate.waitForReach()
        #expect(await pool.mode == .relayOnly, "the pool is mid-narrowing")

        await broadcaster.shutdown()
        await gate.release()

        let opened = try await opening.value.get()
        #expect(opened == false, "a finished broadcaster owns no session")
        #expect(await broadcaster.isRelayOnly == false)
        #expect(await poolIsStopped(pool),
                "a pool narrowed for a broadcaster that is gone would be held open forever")
        #expect(await pool.mode == .full, "no session was left open on it")
    }

    /// The zero-seat branch sits on the far side of the same suspension, and
    /// a `start()` can land inside it: the kept seat fails while the pool is
    /// tearing down the rest, the app comes back to the foreground and takes
    /// the pool back, and its dialling has seated nobody by the time the
    /// narrowing reports its count. A plain `stop()` on that count tore down
    /// the pool the caller had just resumed, which is the race
    /// `stopIfRelayOnly` was made for, reached through a different branch.
    ///
    /// The seeds are stubbed to nothing and the one manual peer is cooling
    /// after its failure, so the resume finds nothing to dial and the count
    /// is genuinely zero when the narrowing returns. The pool is parked
    /// inside the narrowing, as above, so the failure and the resume land
    /// while the broadcaster is suspended on that call rather than near it.
    @Test("a resume that lands while the pool is being narrowed is not undone by a zero seat count")
    func relayOnlyZeroSeatsDoesNotUndoAResume() async throws {
        let fixture = try await BroadcasterFixture.make(
            dialTimeout: .milliseconds(500), seedResolver: SeedResolver { _, _, _ in [] })
        defer { fixture.stop() }
        let (pool, broadcaster) = (fixture.pool, fixture.broadcaster)
        _ = try await broadcaster.broadcast(makeFakeSegwitTx().serialized(includeWitness: true))
        let kept = try #require(await pool.connectedPeers().first)

        let gate = ParkGate()
        await pool.holdNarrowing { await gate.reach(); await gate.waitForRelease() }
        // A call that returns without ever narrowing the pool opens the gate
        // too, so a broken path fails on an assertion instead of parking the
        // test on a wait that will never be resumed.
        let opening = gate.settling { try await broadcaster.enterRelayOnly(seats: 1) }
        await gate.waitForReach()
        #expect(await pool.mode == .relayOnly, "the pool is mid-narrowing")

        // The kept seat goes, and the app comes back, both inside the narrowing.
        await pool.transportFailure(kept, reason: "test: the kept seat fails while the pool narrows")
        await pool.start()
        #expect(await pool.isRunning, "the resume has taken the pool back")
        #expect(await pool.mode == .full)
        #expect(await pool.connectedPeers().isEmpty,
                "nothing to dial yet, so the narrowing will report zero seats")
        await gate.release()

        let opened = try await opening.value.get()
        #expect(opened == false, "no seat was held, so there is no session")
        #expect(await broadcaster.isRelayOnly == false)
        #expect(await pool.isRunning,
                "a pool the caller resumed must be left as they put it, not stopped for the seat it lost")
        #expect(await pool.mode == .full)
    }

    /// A session ends when its seats are gone, and says so.
    ///
    /// The mode dials no replacement, which is the point of it, and the pool
    /// now drops a seat whose connection has closed rather than reporting one
    /// that is not there. What was left was a session over an empty pool:
    /// `announce` reached nobody on every attempt, and no confirmation could
    /// arrive either, because a confirmation comes through the filter sync
    /// the mode refuses. The peers were held open and the caller was told the
    /// payment was relaying in the background, for as long as the app stayed
    /// closed. The backoff attempt is where it is noticed, and the session
    /// ends there: the pool stops, the caller is told which way it went, and
    /// the payment stays saved for the next start.
    @Test("a relay-only session whose seat is gone ends, and stops the pool")
    func relayOnlyEndsWhenItsSeatIsGone() async throws {
        // The prune and the backoff attempt are what notice, in that order, so
        // both run on the test's timescale instead of the wallet's.
        let fixture = try await BroadcasterFixture.make(
            monitorInterval: .milliseconds(50),
            rebroadcastBase: .milliseconds(200), maxRebroadcast: .milliseconds(200))
        defer { fixture.stop() }
        let (node, pool, broadcaster, seen) = (fixture.node, fixture.pool, fixture.broadcaster, fixture.seen)

        let txid = try await broadcaster.broadcast(
            makeFakeSegwitTx().serialized(includeWitness: true))
        #expect(try await broadcaster.enterRelayOnly(seats: 1))
        #expect(await pool.connectedPeers().count == 1)

        // The remote goes away, which is how a mobile connection usually ends.
        await node.stop()

        #expect(await pollUntil(.seconds(15)) {
            seen.events.contains(.relaySessionEnded(reason: .seatsGone))
        }, "a session with nothing left to announce over must end, not wait forever")
        #expect(await broadcaster.isRelayOnly == false)
        #expect(await poolIsStopped(pool), "the peers it was holding go with it")
        #expect(await broadcaster.pendingTxids == [txid],
                "the payment is still pending and still saved: it goes out on the next start")
    }

    /// The other way the last seat goes: a data fault unseats it. `misbehaving`
    /// removes the peer and calls `replenish`, which a relay-only session
    /// refuses, so the pool is simply empty — and that is the state a scan
    /// still unwinding leaves behind when an app narrows the pool on going
    /// idle, which is exactly when this session is opened.
    @Test("a fault that takes the last seat ends the session on the next attempt")
    func relayOnlyEndsWhenAFaultTakesTheLastSeat() async throws {
        let fixture = try await BroadcasterFixture.make(
            rebroadcastBase: .milliseconds(200), maxRebroadcast: .milliseconds(200))
        defer { fixture.stop() }
        let (pool, broadcaster, seen) = (fixture.pool, fixture.broadcaster, fixture.seen)

        _ = try await broadcaster.broadcast(makeFakeSegwitTx().serialized(includeWitness: true))
        #expect(try await broadcaster.enterRelayOnly(seats: 1))
        let seat = try #require(await pool.connectedPeers().first)

        await pool.misbehaving(seat, reason: "test: a filter commitment from a scan still unwinding")
        #expect(await pool.connectedPeers().isEmpty)
        #expect(await pool.mode == .relayOnly, "nothing dials a replacement, which is the mode")

        #expect(await pollUntil(.seconds(15)) {
            seen.events.contains(.relaySessionEnded(reason: .seatsGone))
        })
        #expect(await broadcaster.isRelayOnly == false)
        #expect(await poolIsStopped(pool))
    }

    /// Ending a session must not take a pool the caller has resumed. The
    /// session's seats can be gone and the pool be in full service at the same
    /// instant — the app comes back while its last seat is being unseated —
    /// and the end is then only the session's: `stopIfRelayOnly` re-reads the
    /// mode as one job on the pool, finds full service, and declines.
    @Test("seats gone on a pool the caller resumed ends the session and keeps the pool")
    func relayOnlySeatsGoneLeavesAResumedPoolAlone() async throws {
        // The seeds resolve to nothing and the one manual peer is refused for
        // the rest of the run by the fault below, so the resume finds nothing
        // to dial and the attempt lands on a pool that is empty and in full
        // service, which is the case being pinned.
        let fixture = try await BroadcasterFixture.make(
            dialTimeout: .milliseconds(500), seedResolver: SeedResolver { _, _, _ in [] },
            rebroadcastBase: .milliseconds(200), maxRebroadcast: .milliseconds(200))
        defer { fixture.stop() }
        let (pool, broadcaster, seen) = (fixture.pool, fixture.broadcaster, fixture.seen)

        _ = try await broadcaster.broadcast(makeFakeSegwitTx().serialized(includeWitness: true))
        #expect(try await broadcaster.enterRelayOnly(seats: 1))
        let seat = try #require(await pool.connectedPeers().first)
        await pool.misbehaving(seat, reason: "test: a data fault takes the last seat")
        await pool.start()
        #expect(await pool.isRunning, "the app is back, and the pool is its caller's again")
        #expect(await pool.connectedPeers().isEmpty, "with nothing left to dial")

        #expect(await pollUntil(.seconds(15)) {
            seen.events.contains(.relaySessionEnded(reason: .seatsGone))
        })
        #expect(await broadcaster.isRelayOnly == false)
        // Give a stop that was queued anyway time to land before reading.
        try await Task.sleep(for: .milliseconds(100))
        #expect(await pool.isRunning, "a resumed pool is not stopped by a session ending over it")
        #expect(await pool.mode == .full)
    }

    /// A halted retry loop is the zero-seat state reached before the pool is
    /// even narrowed. `fireDueAttempts` stops after a failed write, so nothing
    /// is announced again; a confirmation cannot arrive over a narrowed pool;
    /// and the session would have been peers held open with the caller told
    /// the payment was relaying. It is refused instead, and the pool goes
    /// quiet, which is what the caller asked for.
    @Test("a session is refused while retries cannot be saved")
    func relayOnlyRefusedWhileRetriesCannotBeSaved() async throws {
        let store = tempFileURL("pending-relay-blocked.json")
        defer { try? FileManager.default.removeItem(at: store.deletingLastPathComponent()) }
        let fixture = try await BroadcasterFixture.make(storageURL: store,
                                                        rebroadcastBase: .milliseconds(100))
        defer { fixture.stop() }
        let (pool, broadcaster, seen) = (fixture.pool, fixture.broadcaster, fixture.seen)

        let txid = try await broadcaster.broadcast(
            makeFakeSegwitTx().serialized(includeWitness: true))
        try FileManager.default.removeItem(at: store.deletingLastPathComponent())
        #expect(await pollUntil(.seconds(15)) {
            seen.events.contains { if case .persistenceFailed = $0 { return true }; return false }
        }, "the retry loop has to halt before there is anything to refuse")

        let opened = try await broadcaster.enterRelayOnly(seats: 1)
        #expect(opened == false, "a session that can never announce is not a session")
        #expect(await broadcaster.isRelayOnly == false)
        #expect(await poolIsStopped(pool))
        #expect(await pool.mode == .full, "no session was left open on it")
        #expect(await broadcaster.pendingTxids == [txid])
    }

    /// The same halt reached from inside a session. The write fails on a
    /// backoff attempt this time, so the loop stops with the pool already
    /// narrowed: nothing is announced again, and nothing could end the session
    /// either. It ends here, and names the reason it did.
    @Test("a session whose retries stop being saved ends instead of holding the pool")
    func relayOnlyEndsWhenARetryCannotBeSaved() async throws {
        let store = tempFileURL("pending-relay-halted.json")
        defer { try? FileManager.default.removeItem(at: store.deletingLastPathComponent()) }
        let fixture = try await BroadcasterFixture.make(
            storageURL: store, rebroadcastBase: .milliseconds(200), maxRebroadcast: .milliseconds(200))
        defer { fixture.stop() }
        let (pool, broadcaster, seen) = (fixture.pool, fixture.broadcaster, fixture.seen)

        let txid = try await broadcaster.broadcast(
            makeFakeSegwitTx().serialized(includeWitness: true))
        #expect(try await broadcaster.enterRelayOnly(seats: 1))

        // The store goes out from under the retry loop, which is what a device
        // that has run out of room does to it.
        try FileManager.default.removeItem(at: store.deletingLastPathComponent())
        #expect(await pollUntil(.seconds(15)) {
            seen.events.contains(.relaySessionEnded(reason: .persistenceBlocked))
        }, "a session that will never announce again must not hold the peers")
        #expect(await broadcaster.isRelayOnly == false)
        #expect(await poolIsStopped(pool))
        #expect(await broadcaster.pendingTxids == [txid])
    }

    /// The halt can also land inside the narrowing: the write fails on an
    /// attempt that fires while the pool is being narrowed, so the end it
    /// calls finds no session yet, and the loop is dead by the time the
    /// narrowing reports its seats. The re-check on the far side has to see
    /// that, or the session the check before the narrowing refuses is
    /// recorded anyway, over a loop that will never announce.
    @Test("a write that fails while the pool is being narrowed opens no session")
    func relayOnlyPersistenceFailureDuringNarrowingOpensNoSession() async throws {
        let store = tempFileURL("pending-relay-narrowing.json")
        defer { try? FileManager.default.removeItem(at: store.deletingLastPathComponent()) }
        let fixture = try await BroadcasterFixture.make(
            storageURL: store, rebroadcastBase: .milliseconds(100), maxRebroadcast: .milliseconds(100))
        defer { fixture.stop() }
        let (pool, broadcaster, seen) = (fixture.pool, fixture.broadcaster, fixture.seen)
        let txid = try await broadcaster.broadcast(
            makeFakeSegwitTx().serialized(includeWitness: true))

        let gate = ParkGate()
        await pool.holdNarrowing { await gate.reach(); await gate.waitForRelease() }
        // A call that returns without ever narrowing the pool opens the gate
        // too, so a broken path fails on an assertion instead of parking the
        // test on a wait that will never be resumed.
        let opening = gate.settling { try await broadcaster.enterRelayOnly(seats: 1) }
        await gate.waitForReach()
        #expect(await pool.mode == .relayOnly, "the pool is mid-narrowing")

        // The store goes out from under the retry loop while the broadcaster
        // is suspended on the narrowing; the next attempt halts the loop.
        try FileManager.default.removeItem(at: store.deletingLastPathComponent())
        #expect(await pollUntil(.seconds(15)) {
            seen.events.contains { if case .persistenceFailed = $0 { return true }; return false }
        }, "the loop has to halt inside the narrowing for the case to exist")
        await gate.release()

        let opened = try await opening.value.get()
        #expect(opened == false, "a session over a halted loop is refused on the far side too")
        #expect(await broadcaster.isRelayOnly == false)
        #expect(await poolIsStopped(pool), "the pool goes quiet, which is what the caller asked for")
        #expect(await broadcaster.pendingTxids == [txid])
    }

    /// A seat can be present and useless: a peer announced to the maximum
    /// number of times without ever asking for the payment is skipped for
    /// good, and a relay-only session kept over nothing but such seats is
    /// peers held open for a relay that has already stopped. The attempt
    /// that finds no seat it can announce to ends the session, as a lost
    /// seat would.
    @Test("a session whose only seat will never hear about the payment ends")
    func relayOnlyEndsWhenItsSeatIsDeprioritized() async throws {
        // The node never requests: it is silent about every inv.
        let fixture = try await BroadcasterFixture.make(
            rebroadcastBase: .milliseconds(150), maxRebroadcast: .milliseconds(200),
            maxAnnouncementsPerPeer: 2, announcementTimeout: .milliseconds(100))
        defer { fixture.stop() }
        let (pool, broadcaster, seen) = (fixture.pool, fixture.broadcaster, fixture.seen)
        let silentEndpoint = fixture.endpoint

        let txid = try await broadcaster.broadcast(makeFakeSegwitTx().serialized(includeWitness: true))
        #expect(await pollUntil {
            seen.events.contains { $0 == .deprioritized(txid: txid, peer: silentEndpoint) }
        }, "the only seat has stopped being worth announcing to")

        // The session opens over the seat it has, and the next attempt finds
        // that seat cannot be announced to for anything still pending.
        #expect(try await broadcaster.enterRelayOnly(seats: 1))
        #expect(await pollUntil(.seconds(15)) {
            seen.events.contains(.relaySessionEnded(reason: .seatsGone))
        }, "a seat that will never hear about the payment is a seat that is gone")
        #expect(await broadcaster.isRelayOnly == false)
        #expect(await poolIsStopped(pool))
        #expect(await broadcaster.pendingTxids == [txid], "the payment stays saved for the next start()")
    }
}

/// The scaffold most cases here open with: one loopback node, a started pool
/// of one seated on it, a broadcaster over that pool, and a collector draining
/// the broadcaster's events. `stop()` is for the `defer`: it ends the
/// broadcaster, the pool and the node, in that order, off the test's thread.
private struct BroadcasterFixture {
    let node: LoopbackNode
    let endpoint: PeerEndpoint
    let pool: PeerPool
    let broadcaster: TxBroadcaster
    let seen: EventCollector<TxBroadcaster.Event>
    private let consumer: Task<Void, Never>

    static func make(autoRequestDelay: Duration? = nil, storageURL: URL? = nil,
                     dialTimeout: Duration = .seconds(5),
                     seedResolver: SeedResolver? = nil,
                     monitorInterval: Duration = .seconds(30),
                     rebroadcastBase: Duration = .seconds(3_600),
                     maxRebroadcast: Duration = .seconds(3_600),
                     maxAnnouncementsPerPeer: Int = 3,
                     announcementTimeout: Duration = .seconds(120)) async throws -> BroadcasterFixture {
        let params = NetworkParams.signet
        let node = LoopbackNode(params: params, autoRequestDelay: autoRequestDelay)
        try await node.start()
        let endpoint = await node.endpoint
        let pool = PeerPool(params: params, peerCount: 1, manualPeers: [endpoint],
                            dialTimeout: dialTimeout, seedResolver: seedResolver,
                            monitorInterval: monitorInterval)
        await pool.start()
        let broadcaster = try TxBroadcaster(pool: pool, storageURL: storageURL,
                                            rebroadcastBaseInterval: rebroadcastBase,
                                            maxRebroadcastInterval: maxRebroadcast,
                                            maxAnnouncementsPerPeer: maxAnnouncementsPerPeer,
                                            announcementTimeout: announcementTimeout)
        let seen = EventCollector<TxBroadcaster.Event>()
        let events = await broadcaster.events()
        let consumer = Task { for await event in events { seen.add(event) } }
        return BroadcasterFixture(node: node, endpoint: endpoint, pool: pool,
                                  broadcaster: broadcaster, seen: seen, consumer: consumer)
    }

    func stop() {
        consumer.cancel()
        let (broadcaster, pool, node) = (broadcaster, pool, node)
        Task {
            await broadcaster.shutdown()
            await pool.stop()
            await node.stop()
        }
    }
}

/// Whether the pool has finished stopping: not running *and* with no peer
/// left. Both halves, because `stop()` clears the running flag before it
/// awaits each disconnect, so a pool can be observed stopped with its last
/// peer still on the way down.
private func poolIsStopped(_ pool: PeerPool) async -> Bool {
    guard await pool.isRunning == false else { return false }
    return await pool.connectedPeers().isEmpty
}

/// Consumes every inv already queued on `node`, so a following assertion is
/// about what arrives *next* rather than what was already in flight.
///
/// Bounded so a broadcaster that never stops fails the test instead of hanging
/// it — the drain is meant to remove a finite backlog, not to wait out an
/// unbounded stream.
private func drainQueuedInvs(from node: LoopbackNode, limit: Int = 20) async {
    for _ in 0 ..< limit {
        if await node.nextMessage(command: "inv", timeout: .milliseconds(250)) == nil { return }
    }
}

/// A TCP ordering barrier (#164). The connection is one ordered stream, so by
/// the time the client's `pong` arrives, every message it dispatched before
/// answering has arrived too. Draining after the barrier therefore consumes
/// any rebroadcast that was already in flight when the confirmation landed —
/// the stragglers that used to land inside the quiet window and fail the
/// negative assertion on a loaded runner. An inv after barrier-plus-drain can
/// only be a *newly scheduled* attempt, which is exactly what the assertion
/// is supposed to catch.
private func stragglersFlushed(_ node: LoopbackNode) async throws {
    try await node.send(.ping(0xB412_B412_B412_B412))
    let pong = await node.nextMessage(command: "pong", timeout: .seconds(10))
    #expect(pong != nil, "the client stopped answering pings — the barrier proves nothing")
    await drainQueuedInvs(from: node)
}
