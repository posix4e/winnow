import Foundation
import Testing
@testable import BitcoinP2P

/// TxBroadcaster against loopback nodes: inv announcement, getdata answer,
/// pending persistence, confirmation.
@Suite("TxBroadcaster")
struct TxBroadcasterTests {
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
        let seen = EventCollector()
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

        try await broadcaster.markConfirmed(txid)
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

    @Test("serves a delayed getdata and tracks per-peer state")
    func delayedGetdata() async throws {
        let params = NetworkParams.signet
        let node = LoopbackNode(params: params, autoRequestDelay: .milliseconds(100))
        try await node.start()
        defer { Task { await node.stop() } }

        let pool = PeerPool(params: params, peerCount: 1, manualPeers: [await node.endpoint])
        await pool.start()

        let broadcaster = try TxBroadcaster(pool: pool, rebroadcastBaseInterval: .seconds(3_600))
        let seen = EventCollector()
        let events = await broadcaster.events()
        let consumer = Task { for await event in events { seen.add(event) } }
        defer { consumer.cancel() }

        let tx = makeFakeSegwitTx()
        let txid = try await broadcaster.broadcast(tx.serialized(includeWitness: true))
        let endpoint = await node.endpoint

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

        await pool.stop()
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
        let seen = EventCollector()
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
        let params = NetworkParams.signet
        let node = LoopbackNode(params: params, autoRequestDelay: .milliseconds(20))
        try await node.start()
        defer { Task { await node.stop() } }

        let pool = PeerPool(params: params, peerCount: 1, manualPeers: [await node.endpoint])
        await pool.start()

        // 100ms base, doubling, capped at 250ms → gaps 100, 200, 250, 250.
        let broadcaster = try TxBroadcaster(pool: pool,
                                        rebroadcastBaseInterval: .milliseconds(100),
                                        maxRebroadcastInterval: .milliseconds(250),
                                        announcementTimeout: .seconds(30))
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

        await pool.stop()
    }

    @Test("pending store round-trips backoff state and still loads the legacy format")
    func persistenceRoundTrip() async throws {
        let pool = PeerPool(params: .signet, peerCount: 0, manualPeers: [])
        let store = tempFileURL("pending-txs.json")
        defer { try? FileManager.default.removeItem(at: store.deletingLastPathComponent()) }

        let broadcaster = try TxBroadcaster(pool: pool, storageURL: store,
                                        rebroadcastBaseInterval: .milliseconds(100))
        let tx = makeFakeSegwitTx()
        let rawTx = tx.serialized(includeWitness: true)
        let txid = try await broadcaster.broadcast(rawTx, feeRateSatPerVByte: 2.5)

        // Let at least one backoff attempt fire so `attempt` advances past 0.
        #expect(await pollUntil { await broadcaster.attemptCount(txid) ?? 0 >= 1 })

        // Then stop the loop before sampling anything. While the broadcaster
        // runs, `attempt` advances every 100ms, so reading the file and the
        // live counter are two different moments and pinning either to a
        // literal 1 is a race, not an invariant (#144).
        await broadcaster.shutdown()

        // The store carries the raw tx, feerate and next-attempt time.
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: store)) as? [String: Any]
        let record = (json?["transactions"] as? [String: Any])?[txid.hex] as? [String: Any]
        let persistedAttempt = record?["attempt"] as? Int
        #expect(record?["rawTx"] as? String == rawTx.hex)
        #expect(record?["feeRateSatPerVByte"] as? Double == 2.5)
        #expect(persistedAttempt ?? 0 >= 1, "the fired attempt must reach the store")
        #expect(record?["nextAttemptAt"] as? Double != nil)
        #expect(json?["version"] as? Int == 1)

        // A fresh broadcaster restores tx, feerate and schedule. The claim is
        // that what comes back equals what went to disk -- comparing against
        // the persisted value rather than a literal is what makes this a
        // round-trip assertion instead of a timing one.
        let restored = try TxBroadcaster(pool: pool, storageURL: store,
                                     rebroadcastBaseInterval: .milliseconds(100))
        #expect(await restored.pendingTxids == [txid])
        #expect(await restored.attemptCount(txid) == persistedAttempt)
        #expect(await restored.nextAttemptDate(txid) != nil)

        try await restored.cancel(txid)

        // The pre-backoff format (txid → rawTx) still loads, due immediately.
        let legacyStore = tempFileURL("pending-legacy.json")
        defer { try? FileManager.default.removeItem(at: legacyStore.deletingLastPathComponent()) }
        let legacy = #"{"transactions": {"\#(txid.hex)": "\#(rawTx.hex)"}}"#
        try Data(legacy.utf8).write(to: legacyStore)
        let legacyLoaded = try TxBroadcaster(pool: pool, storageURL: legacyStore)
        #expect(await legacyLoaded.pendingTxids == [txid])
        try await legacyLoaded.cancel(txid)
    }

    @Test("stops rebroadcasting on confirmation and on explicit cancel")
    func stopOnConfirmationAndCancel() async throws {
        let params = NetworkParams.signet
        let node = LoopbackNode(params: params)
        try await node.start()
        defer { Task { await node.stop() } }

        let pool = PeerPool(params: params, peerCount: 1, manualPeers: [await node.endpoint])
        await pool.start()

        let broadcaster = try TxBroadcaster(pool: pool,
                                        rebroadcastBaseInterval: .milliseconds(150),
                                        maxRebroadcastInterval: .milliseconds(600),
                                        announcementTimeout: .seconds(30))
        let seen = EventCollector()
        let events = await broadcaster.events()
        let consumer = Task { for await event in events { seen.add(event) } }
        defer { consumer.cancel() }

        // Confirmed tx: no further invs.
        let txid1 = try await broadcaster.broadcast(makeFakeSegwitTx().serialized(includeWitness: true))
        #expect(await node.nextMessage(command: "inv") != nil)
        try await broadcaster.markConfirmed(txid1)
        // The pending entry is gone, so no further attempt can be scheduled.
        // That is the claim, and it is deterministic.
        #expect(await broadcaster.pendingTxids.isEmpty)
        // The wire check is about what happens *after* that. Rebroadcasts
        // already sent when the confirmation landed are still sitting in the
        // node's inbox — the interval here is 150ms and the node buffers, so
        // there can be several — and none of them is a counter-example. Drain
        // whatever is queued, then require quiet for longer than the maximum
        // rebroadcast interval, which is the window in which a *new* one would
        // have to appear (#144).
        await drainQueuedInvs(from: node)
        #expect(await node.nextMessage(command: "inv", timeout: .milliseconds(700)) == nil)
        #expect(seen.events.contains { $0 == .confirmed(txid: txid1) })

        // Cancelled tx: no further invs either.
        let txid2 = try await broadcaster.broadcast(makeFakeSegwitTx().serialized(includeWitness: true))
        #expect(await node.nextMessage(command: "inv") != nil)
        try await broadcaster.cancel(txid2)
        #expect(await broadcaster.pendingTxids.isEmpty)
        // Same as the confirmation branch above, for the same reason.
        await drainQueuedInvs(from: node)
        #expect(await node.nextMessage(command: "inv", timeout: .milliseconds(700)) == nil)
        #expect(seen.events.contains { $0 == .cancelled(txid: txid2) })

        await pool.stop()
    }

    @Test("missing, disabled, and loaded persistence are distinguished")
    func persistenceState() async throws {
        let pool = PeerPool(params: .signet, peerCount: 0, manualPeers: [])
        let store = tempFileURL("pending-state.json")
        defer { try? FileManager.default.removeItem(at: store.deletingLastPathComponent()) }

        let disabled = try TxBroadcaster(pool: pool)
        #expect(disabled.persistenceState == .disabled)
        let missing = try TxBroadcaster(pool: pool, storageURL: store)
        #expect(missing.persistenceState == .missing)

        let tx = makeFakeSegwitTx()
        _ = try await missing.broadcast(tx.serialized(includeWitness: true))
        let loaded = try TxBroadcaster(pool: pool, storageURL: store)
        #expect(loaded.persistenceState == .loaded(transactionCount: 1))
    }

    @Test("damaged persistence is rejected as a whole and never rewritten")
    func damagedPersistenceFailsClosed() throws {
        let pool = PeerPool(params: .signet, peerCount: 0, manualPeers: [])
        let store = tempFileURL("pending-damaged.json")
        defer { try? FileManager.default.removeItem(at: store.deletingLastPathComponent()) }
        let tx = makeFakeSegwitTx()
        let raw = tx.serialized(includeWitness: true)
        let otherTxid = Data(repeating: 0x42, count: 32).hex
        let bytes = Data(#"{"version":1,"transactions":{"\#(tx.txid.hex)":{"rawTx":"\#(raw.hex)","attempt":0,"nextAttemptAt":1},"\#(otherTxid)":{"rawTx":"00","attempt":0,"nextAttemptAt":1}}}"#.utf8)
        try bytes.write(to: store)

        #expect(throws: TxBroadcasterStorageError.self) {
            _ = try TxBroadcaster(pool: pool, storageURL: store)
        }
        #expect(try Data(contentsOf: store) == bytes)
    }

    @Test("txid mismatch, unsupported versions, and hostile retry metadata are rejected")
    func invalidStoredMetadata() throws {
        let pool = PeerPool(params: .signet, peerCount: 0, manualPeers: [])
        let store = tempFileURL("pending-hostile.json")
        defer { try? FileManager.default.removeItem(at: store.deletingLastPathComponent()) }
        let tx = makeFakeSegwitTx()
        let raw = tx.serialized(includeWitness: true).hex
        let wrongTxid = Data(repeating: 0x24, count: 32).hex

        try Data(#"{"version":2,"transactions":{}}"#.utf8).write(to: store)
        #expect(throws: TxBroadcasterStorageError.unsupportedVersion(2)) {
            _ = try TxBroadcaster(pool: pool, storageURL: store)
        }

        try Data(#"{"version":1,"transactions":{"\#(wrongTxid)":{"rawTx":"\#(raw)","attempt":0,"nextAttemptAt":1}}}"#.utf8).write(to: store)
        #expect(throws: TxBroadcasterStorageError.self) {
            _ = try TxBroadcaster(pool: pool, storageURL: store)
        }

        try Data(#"{"version":1,"transactions":{"\#(tx.txid.hex)":{"rawTx":"\#(raw)","feeRateSatPerVByte":0,"attempt":0,"nextAttemptAt":1}}}"#.utf8).write(to: store)
        #expect(throws: TxBroadcasterStorageError.self) {
            _ = try TxBroadcaster(pool: pool, storageURL: store)
        }

        try Data(#"{"version":1,"transactions":{"\#(tx.txid.hex)":{"rawTx":"\#(raw)","attempt":64,"nextAttemptAt":1}}}"#.utf8).write(to: store)
        #expect(throws: TxBroadcasterStorageError.self) {
            _ = try TxBroadcaster(pool: pool, storageURL: store)
        }

        try Data(#"{"version":1,"transactions":{"\#(tx.txid.hex)":{"rawTx":"\#(raw)","attempt":0,"nextAttemptAt":999999999999}}}"#.utf8).write(to: store)
        #expect(throws: TxBroadcasterStorageError.self) {
            _ = try TxBroadcaster(pool: pool, storageURL: store)
        }
    }

    @Test("invalid fee rates and failed initial writes never create pending relay state")
    func broadcastPersistenceIsTransactional() async throws {
        let pool = PeerPool(params: .signet, peerCount: 0, manualPeers: [])
        let store = tempFileURL("missing-parent/pending.json")
        try FileManager.default.removeItem(at: store.deletingLastPathComponent())
        let broadcaster = try TxBroadcaster(pool: pool, storageURL: store)
        let raw = makeFakeSegwitTx().serialized(includeWitness: true)

        await #expect(throws: TxBroadcasterError.invalidFeeRate) {
            try await broadcaster.broadcast(raw, feeRateSatPerVByte: .nan)
        }
        await #expect(throws: TxBroadcasterStorageError.writeFailed) {
            try await broadcaster.broadcast(raw, feeRateSatPerVByte: 1)
        }
        #expect(await broadcaster.pendingTxids.isEmpty)
    }

    @Test("failed confirmation and cancellation writes retain pending state and emit no success")
    func removalPersistenceIsTransactional() async throws {
        let pool = PeerPool(params: .signet, peerCount: 0, manualPeers: [])
        let store = tempFileURL("pending-removal.json")
        defer { try? FileManager.default.removeItem(at: store.deletingLastPathComponent()) }
        let broadcaster = try TxBroadcaster(pool: pool, storageURL: store,
                                            rebroadcastBaseInterval: .seconds(3_600))
        let events = await broadcaster.events()
        let seen = EventCollector()
        let consumer = Task { for await event in events { seen.add(event) } }
        defer { consumer.cancel() }
        let txid = try await broadcaster.broadcast(makeFakeSegwitTx().serialized(includeWitness: true))
        try FileManager.default.removeItem(at: store.deletingLastPathComponent())

        await #expect(throws: TxBroadcasterStorageError.writeFailed) {
            try await broadcaster.markConfirmed(txid)
        }
        await #expect(throws: TxBroadcasterStorageError.writeFailed) {
            try await broadcaster.cancel(txid)
        }
        #expect(await broadcaster.pendingTxids == [txid])
        #expect(!seen.events.contains { $0 == .confirmed(txid: txid) })
        #expect(!seen.events.contains { $0 == .cancelled(txid: txid) })
    }

    @Test("failed retry persistence halts automatic announcements and reports the error")
    func retryPersistenceFailureStopsLoop() async throws {
        let pool = PeerPool(params: .signet, peerCount: 0, manualPeers: [])
        let store = tempFileURL("pending-retry.json")
        defer { try? FileManager.default.removeItem(at: store.deletingLastPathComponent()) }
        let broadcaster = try TxBroadcaster(pool: pool, storageURL: store,
                                            rebroadcastBaseInterval: .milliseconds(100))
        let events = await broadcaster.events()
        let seen = EventCollector()
        let consumer = Task { for await event in events { seen.add(event) } }
        defer { consumer.cancel() }
        let txid = try await broadcaster.broadcast(makeFakeSegwitTx().serialized(includeWitness: true))
        try FileManager.default.removeItem(at: store.deletingLastPathComponent())

        #expect(await pollUntil {
            seen.events.contains { if case .persistenceFailed = $0 { return true }; return false }
        })
        #expect(await broadcaster.attemptCount(txid) == 0)
        let announcementCount = seen.events.filter {
            if case let .announced(id, _) = $0 { return id == txid }
            return false
        }.count
        try await Task.sleep(for: .milliseconds(350))
        #expect(seen.events.filter {
            if case let .announced(id, _) = $0 { return id == txid }
            return false
        }.count == announcementCount)
    }

    @Test("shutdown clears only the live session and leaves durable relay state for reconnect")
    func shutdownPreservesStore() async throws {
        let pool = PeerPool(params: .signet, peerCount: 0, manualPeers: [])
        let store = tempFileURL("pending-shutdown.json")
        defer { try? FileManager.default.removeItem(at: store.deletingLastPathComponent()) }
        let broadcaster = try TxBroadcaster(pool: pool, storageURL: store,
                                            rebroadcastBaseInterval: .seconds(3_600))
        let raw = makeFakeSegwitTx().serialized(includeWitness: true)
        let txid = try await broadcaster.broadcast(raw)

        await broadcaster.shutdown()
        #expect(await broadcaster.pendingTxids.isEmpty)
        await #expect(throws: TxBroadcasterError.stopped) {
            try await broadcaster.broadcast(raw)
        }
        await #expect(throws: TxBroadcasterError.stopped) {
            try await broadcaster.cancel(txid)
        }

        let reconnected = try TxBroadcaster(pool: pool, storageURL: store)
        #expect(await reconnected.pendingTxids == [txid])
        try await reconnected.cancel(txid)
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
        let seen = EventCollector()
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

        // Relay attempts continue meanwhile (another inv reaches node A).
        #expect(await nodeA.nextMessage(command: "inv") != nil)

        // Floor dropping back below the feerate rearms the event…
        try await nodeA.send(.feefilter(500))
        try? await Task.sleep(for: .milliseconds(100))
        // …so a later rise emits it again.
        try await nodeA.send(.feefilter(2_000))
        let reemitted = await pollUntil {
            seen.events.filter { if case .feeFloorExceeded = $0 { return true }; return false }.count == 2
        }
        #expect(reemitted)
        #expect(seen.events.contains { $0 == .feeFloorExceeded(txid: txid, floor: 2_000) })

        await pool.stop()
    }
}

/// Polls `condition` every 10ms until it holds or `timeout` elapses.
/// Waits for `condition`, and gives up eventually so a hung test fails instead
/// of hanging forever.
///
/// The timeout is a HANG-GUARD, not a performance claim. Nothing here asserts
/// that the condition is met within it — on a contended CI runner a short
/// deadline turns into an assertion nobody wrote, which is how these became
/// intermittent (#144). Keep it generous: a real hang fails either way.
private func pollUntil(_ timeout: Duration = .seconds(60),
                       _ condition: () async -> Bool) async -> Bool {
    let deadline = ContinuousClock.now + timeout
    while ContinuousClock.now < deadline {
        if await condition() { return true }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return false
}

/// Collects broadcaster events from the AsyncStream consumer task.
private final class EventCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [TxBroadcaster.Event] = []

    var events: [TxBroadcaster.Event] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    func add(_ event: TxBroadcaster.Event) {
        lock.lock()
        storage.append(event)
        lock.unlock()
    }
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
