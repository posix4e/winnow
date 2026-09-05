import BitcoinCore
import BitcoinP2P
import BlockchainBackend
import Foundation
import Testing
@testable import WalletCore

// MARK: - Fakes

/// Counts what the coordinator asks of the peer relay.
final class CountingRelay: PeerRelay, @unchecked Sendable {
    private let lock = NSLock()
    private var _broadcasts: [Data] = []
    private var _cancels: [Data] = []
    private var continuations: [AsyncStream<TxBroadcaster.Event>.Continuation] = []
    var failBroadcast = false

    var broadcasts: [Data] { lock.withLock { _broadcasts } }
    var cancels: [Data] { lock.withLock { _cancels } }

    func broadcast(_ rawTx: Data, feeRateSatPerVByte: Double?) async throws -> Data {
        if failBroadcast { throw TxBroadcasterError.stopped }
        lock.withLock { _broadcasts.append(rawTx) }
        return try Transaction.decode(rawTx).txid
    }

    func cancel(_ txid: Data) async throws {
        lock.withLock { _cancels.append(txid) }
    }

    func events() async -> AsyncStream<TxBroadcaster.Event> {
        AsyncStream { continuation in
            lock.withLock { continuations.append(continuation) }
        }
    }

    func emit(_ event: TxBroadcaster.Event) {
        let all = lock.withLock { continuations }
        for continuation in all { continuation.yield(event) }
    }
}

/// A scripted miner: answers in order, then repeats its last answer.
final class ScriptedMiner: DirectMinerClient, @unchecked Sendable {
    let providerID: MinerProviderID
    let capabilities: MinerCapabilities
    let endpointHost = "miner.example"
    private let lock = NSLock()
    private var submitScript: [Result<MinerSubmitOutcome, MinerClientError>]
    private var statusScript: [Result<MinerReportedStatus, MinerClientError>]
    private var _submits: [SubmissionPackage] = []
    private var _statusCalls: [Data] = []

    init(providerID: MinerProviderID = .slipstream,
         capabilities: MinerCapabilities = [.statusByTxid, .rates],
         submit: [Result<MinerSubmitOutcome, MinerClientError>],
         status: [Result<MinerReportedStatus, MinerClientError>] = [.success(.pending(position: 1, inclusionOdds: "80", message: nil))])
    {
        self.providerID = providerID
        self.capabilities = capabilities
        submitScript = submit
        statusScript = status
    }

    var submits: [SubmissionPackage] { lock.withLock { _submits } }
    var statusCalls: [Data] { lock.withLock { _statusCalls } }

    func submit(_ package: SubmissionPackage) async throws -> MinerSubmitOutcome {
        let next = lock.withLock {
            _submits.append(package)
            return submitScript.count > 1 ? submitScript.removeFirst() : submitScript[0]
        }
        return try next.get()
    }

    func status(txid: Data) async throws -> MinerReportedStatus {
        let next = lock.withLock {
            _statusCalls.append(txid)
            return statusScript.count > 1 ? statusScript.removeFirst() : statusScript[0]
        }
        return try next.get()
    }

    func rates() async throws -> MinerRateQuote? { nil }
    func health() async throws -> MinerHealth { MinerHealth(reachable: true, height: nil, floorSatPerVByte: nil, version: nil) }
}

/// A clock the test moves by hand.
final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var _now = Date(timeIntervalSince1970: 1_700_000_000)
    var now: Date { lock.withLock { _now } }
    func advance(_ seconds: TimeInterval) { lock.withLock { _now += seconds } }
}

/// A signed-looking segwit transaction; `seed` varies the txid.
func fakeSignedTx(seed: UInt8 = 0x77) -> Data {
    var input = Transaction.Input(
        previousOutput: Transaction.Outpoint(txid: Data(repeating: 0x11, count: 32), vout: 0),
        scriptSig: Data(), sequence: 0xFFFF_FFFD)
    input.witness = [Data([0x30, 0x44, 0x02, 0x20]), Data(repeating: 0x02, count: 33)]
    let output = Transaction.Output(value: 50_000 + Int64(seed),
                                    scriptPubKey: Data([0x51, 0x20] + repeatElement(seed, count: 32)))
    return Transaction(version: 2, inputs: [input], outputs: [output], locktime: 0)
        .serialized(includeWitness: true)
}

struct Harness {
    let relay = CountingRelay()
    let clock = TestClock()
    let coordinator: SubmissionCoordinator
    /// How often the coordinator asked for a relay, by route.
    let relayRequests: RequestLog
    let minerRequests: RequestLog

    final class RequestLog: @unchecked Sendable {
        private let lock = NSLock()
        private var _entries: [String] = []
        var entries: [String] { lock.withLock { _entries } }
        func note(_ entry: String) { lock.withLock { _entries.append(entry) } }
    }

    init(miner: (any DirectMinerClient)? = nil, storageURL: URL? = nil,
         maxSubmitAttempts: Int = 5, relayFails: Bool = false) throws
    {
        let relay = self.relay
        relay.failBroadcast = relayFails
        let clock = self.clock
        let relayLog = RequestLog()
        let minerLog = RequestLog()
        relayRequests = relayLog
        minerRequests = minerLog
        coordinator = try SubmissionCoordinator(
            relay: { route in
                relayLog.note(route.label)
                return route.touchesPeers ? relay : nil
            },
            miners: { provider in
                minerLog.note(provider.rawValue)
                guard let miner else {
                    throw MinerClientError.unreachable(host: "unconfigured")
                }
                return miner
            },
            storageURL: storageURL,
            now: { clock.now },
            pollBaseInterval: .seconds(30), maxPollInterval: .seconds(600),
            submitBaseInterval: .seconds(15), maxSubmitInterval: .seconds(300),
            maxSubmitAttempts: maxSubmitAttempts)
    }
}

// MARK: - Tests

@Suite("Submission coordinator", .timeLimit(.minutes(1)))
struct SubmissionCoordinatorTests {
    @Test("miner-only never touches the relay, or even asks for one")
    func minerOnlyNeverTouchesRelay() async throws {
        let miner = ScriptedMiner(submit: [.success(.accepted(txids: [], providerMessage: "ok"))])
        let h = try Harness(miner: miner)
        let raw = fakeSignedTx()
        let receipt = try await h.coordinator.submit(rawTx: raw, feeRateSatPerVByte: 4,
                                                     route: .minerOnly(.slipstream), origin: .walletSend)
        #expect(receipt.state == .accepted)
        #expect(receipt.route.isPrivateToMiner)
        #expect(miner.submits == [SubmissionPackage(raw)])
        #expect(h.relay.broadcasts.isEmpty, "no bytes reached the peer relay")
        #expect(h.relayRequests.entries.isEmpty, "the relay was never even resolved")
        #expect(receipt.nextPollAt != nil, "an accepted miner submission is polled")
    }

    @Test("the peers route relays and becomes relayed when a peer asks for the bytes")
    func peersRouteRelays() async throws {
        let h = try Harness()
        await h.coordinator.start()
        let raw = fakeSignedTx()
        let events = await h.coordinator.events()
        let receipt = try await h.coordinator.submit(rawTx: raw, feeRateSatPerVByte: 2,
                                                     route: .peers, origin: .walletSend)
        #expect(receipt.state == .constructed, "announced, but no peer has asked yet")
        #expect(h.relay.broadcasts == [raw])
        #expect(h.minerRequests.entries.isEmpty, "no miner was resolved for a peers send")

        h.relay.emit(.requested(txid: receipt.txid, peer: PeerEndpoint(host: "1.2.3.4", port: 38333)))
        var sawRelayed = false
        for await event in events {
            if case let .relayed(txid) = event, txid == receipt.txid { sawRelayed = true; break }
        }
        #expect(sawRelayed)
        #expect(await h.coordinator.receipt(receipt.txid)?.state == .relayed)
        await h.coordinator.shutdown()
    }

    @Test("export performs no network call and stays constructed, ready to be routed later")
    func exportIsInert() async throws {
        let h = try Harness()
        let raw = fakeSignedTx()
        let receipt = try await h.coordinator.submit(rawTx: raw, feeRateSatPerVByte: 2,
                                                     route: .export, origin: .walletSend)
        #expect(receipt.state == .constructed)
        #expect(receipt.canReroute)
        #expect(h.relay.broadcasts.isEmpty)
        #expect(h.relayRequests.entries.isEmpty)
        #expect(h.minerRequests.entries.isEmpty)
        #expect(receipt.rawTransaction == raw, "the bytes are what the user takes elsewhere")
    }

    @Test("a miner rejection returns normally with a rejected, reroutable receipt")
    func rejectionReturnsNormally() async throws {
        let miner = ScriptedMiner(submit: [.success(.rejected(reason: "fee below 4 sat/vB", policy: false))])
        let h = try Harness(miner: miner)
        let receipt = try await h.coordinator.submit(rawTx: fakeSignedTx(), feeRateSatPerVByte: 1,
                                                     route: .minerOnly(.slipstream), origin: .walletSend)
        #expect(receipt.state == .rejected)
        #expect(receipt.rejection?.reason == "fee below 4 sat/vB")
        #expect(receipt.rejection?.policy == false)
        #expect(receipt.canReroute)
        #expect(receipt.nextPollAt == nil)
        #expect(await h.coordinator.pendingTxids == [receipt.txid],
                "rejected is not terminal — the bytes exist and may still be mined")
    }

    @Test("a transport failure keeps submitted and the retry resolves alreadyKnown to accepted")
    func transportFailureRetries() async throws {
        let miner = ScriptedMiner(submit: [
            .failure(.unreachable(host: "miner.example")),
            .success(.alreadyKnown(txids: [])),
        ])
        let h = try Harness(miner: miner)
        let receipt = try await h.coordinator.submit(rawTx: fakeSignedTx(), feeRateSatPerVByte: 4,
                                                     route: .minerOnly(.slipstream), origin: .walletSend)
        #expect(receipt.state == .submitted, "the bytes may have arrived; nothing is assumed")
        #expect(receipt.submitAttempt == 1)
        #expect(receipt.nextSubmitAt == h.clock.now + 15, "base backoff, no clock read")
        #expect(receipt.lastError?.contains("miner.example") == true)
        #expect(!receipt.isDeliveryUnconfirmed)

        h.clock.advance(20)
        await h.coordinator.runDueNow()
        let retried = try #require(await h.coordinator.receipt(receipt.txid))
        #expect(retried.state == .accepted)
        #expect(retried.submitAttempt == 2)
        #expect(retried.lastError == nil)
        #expect(miner.submits.count == 2)
    }

    @Test("an unrecognised API answer is a transport failure, never an acceptance")
    func unrecognisedAnswerStaysSubmitted() async throws {
        let miner = ScriptedMiner(submit: [.failure(.unexpectedResponse(shape: "text/html"))])
        let h = try Harness(miner: miner, maxSubmitAttempts: 2)
        let receipt = try await h.coordinator.submit(rawTx: fakeSignedTx(), feeRateSatPerVByte: 4,
                                                     route: .minerOnly(.slipstream), origin: .walletSend)
        #expect(receipt.state == .submitted)
        h.clock.advance(100)
        await h.coordinator.runDueNow()
        let final = try #require(await h.coordinator.receipt(receipt.txid))
        #expect(final.state == .submitted)
        #expect(final.isDeliveryUnconfirmed, "cap reached: held, not accepted, not rejected")
        #expect(final.canReroute)
        #expect(miner.submits.count == 2)
    }

    @Test("the same bytes submitted twice yield one receipt; a different route is refused")
    func duplicateSubmission() async throws {
        let miner = ScriptedMiner(submit: [.success(.accepted(txids: [], providerMessage: nil))])
        let h = try Harness(miner: miner)
        let raw = fakeSignedTx()
        let first = try await h.coordinator.submit(rawTx: raw, feeRateSatPerVByte: 4,
                                                   route: .minerOnly(.slipstream), origin: .walletSend)
        let second = try await h.coordinator.submit(rawTx: raw, feeRateSatPerVByte: 4,
                                                    route: .minerOnly(.slipstream), origin: .walletSend)
        #expect(first == second)
        #expect(miner.submits.count == 1)
        await #expect(throws: SubmissionError.duplicateSubmission(route: .minerOnly(.slipstream))) {
            try await h.coordinator.submit(rawTx: raw, feeRateSatPerVByte: 4, route: .peers,
                                           origin: .walletSend)
        }
        #expect(await h.coordinator.receipts.count == 1)
    }

    @Test("reroute records the approval first, then runs the new route exactly once")
    func rerouteRecordsApproval() async throws {
        let h = try Harness()
        await h.coordinator.start()
        let raw = fakeSignedTx()
        let events = await h.coordinator.events()
        let exported = try await h.coordinator.submit(rawTx: raw, feeRateSatPerVByte: 2,
                                                      route: .export, origin: .walletSend)
        let rerouted = try await h.coordinator.reroute(exported.txid, to: .peers)
        #expect(rerouted.route == .peers)
        #expect(rerouted.routeHistory.count == 1)
        #expect(rerouted.routeHistory.first?.from == .export)
        #expect(rerouted.routeHistory.first?.to == .peers)
        #expect(rerouted.routeHistory.first?.approvedAt == h.clock.now)
        #expect(h.relay.broadcasts == [raw], "relayed exactly once")

        // Once a peer has the bytes the transaction is public; there is no
        // second route to take.
        h.relay.emit(.served(txid: exported.txid, peer: PeerEndpoint(host: "1.2.3.4", port: 38333)))
        for await event in events {
            if case let .relayed(txid) = event, txid == exported.txid { break }
        }
        await #expect(throws: SubmissionError.notReroutable(.relayed)) {
            _ = try await h.coordinator.reroute(exported.txid, to: .minerOnly(.slipstream))
        }
        await #expect(throws: SubmissionError.unknownTransaction) {
            _ = try await h.coordinator.reroute(Data(repeating: 9, count: 32), to: .peers)
        }
        await h.coordinator.shutdown()
    }

    @Test("a rejected miner-only send can be re-routed to peers, and the receipt says the disclosure changed")
    func rejectedToPeers() async throws {
        let miner = ScriptedMiner(submit: [.success(.rejected(reason: "policy", policy: true))])
        let h = try Harness(miner: miner)
        let raw = fakeSignedTx()
        let rejected = try await h.coordinator.submit(rawTx: raw, feeRateSatPerVByte: 4,
                                                      route: .minerOnly(.slipstream), origin: .walletSend)
        #expect(rejected.rejection?.policy == true)
        let rerouted = try await h.coordinator.reroute(rejected.txid, to: .peers)
        #expect(!rerouted.route.isPrivateToMiner)
        #expect(rerouted.routeHistory.map(\.to) == [.peers])
        #expect(rerouted.rejection != nil, "history is kept")
        #expect(h.relay.broadcasts == [raw])
        #expect(rerouted.state == .rejected, "until a peer asks for it")
    }

    @Test("a miner that cannot be built means nothing is recorded and nothing leaves")
    func unconfiguredMinerRecordsNothing() async throws {
        let h = try Harness(miner: nil)
        await #expect(throws: SubmissionError.self) {
            try await h.coordinator.submit(rawTx: fakeSignedTx(), feeRateSatPerVByte: 4,
                                           route: .minerOnly(.slipstream), origin: .walletSend)
        }
        #expect(await h.coordinator.receipts.isEmpty)
        #expect(h.relay.broadcasts.isEmpty)
    }

    @Test("a relay that throws before anything left the device undoes the record")
    func relayFailureUndoesRecord() async throws {
        let h = try Harness(relayFails: true)
        await #expect(throws: TxBroadcasterError.self) {
            try await h.coordinator.submit(rawTx: fakeSignedTx(), feeRateSatPerVByte: 2,
                                           route: .peers, origin: .walletSend)
        }
        #expect(await h.coordinator.receipts.isEmpty, "the caller keeps its nothing-was-spent rule")
    }

    @Test("miner-and-peers keeps the peer half when the miner rejects, and the receipt is not private")
    func minerAndPeers() async throws {
        let miner = ScriptedMiner(submit: [.success(.rejected(reason: "no", policy: false))])
        let h = try Harness(miner: miner)
        let raw = fakeSignedTx()
        let receipt = try await h.coordinator.submit(rawTx: raw, feeRateSatPerVByte: 4,
                                                     route: .minerAndPeers(.slipstream), origin: .walletSend)
        #expect(receipt.state == .rejected)
        #expect(h.relay.broadcasts == [raw], "the peer relay still happened")
        #expect(!receipt.route.isPrivateToMiner)
    }

    @Test("a provider-reported confirmation never sets state confirmed")
    func providerConfirmationIsAdvisory() async throws {
        let miner = ScriptedMiner(
            submit: [.success(.accepted(txids: [], providerMessage: nil))],
            status: [.success(.confirmed(height: 900_001, blockHash: nil))])
        let h = try Harness(miner: miner)
        let receipt = try await h.coordinator.submit(rawTx: fakeSignedTx(), feeRateSatPerVByte: 4,
                                                     route: .minerOnly(.slipstream), origin: .walletSend)
        h.clock.advance(31)
        await h.coordinator.runDueNow()
        let polled = try #require(await h.coordinator.receipt(receipt.txid))
        #expect(polled.state == .accepted, "the block path finishes it, not the miner")
        #expect(polled.providerStatus?.kind == .confirmed)
        #expect(polled.providerStatus?.reportedHeight == 900_001)
        #expect(polled.nextPollAt == nil, "nothing more to ask the provider")
        #expect(miner.statusCalls == [receipt.txid])
        #expect(await h.coordinator.pendingTxids == [receipt.txid], "still awaiting Winnow's own block")
    }

    @Test("a status poll that reports rejection moves the receipt to rejected")
    func polledRejection() async throws {
        let miner = ScriptedMiner(
            submit: [.success(.accepted(txids: [], providerMessage: nil))],
            status: [.success(.rejected(reason: "evicted"))])
        let h = try Harness(miner: miner)
        let receipt = try await h.coordinator.submit(rawTx: fakeSignedTx(), feeRateSatPerVByte: 4,
                                                     route: .minerOnly(.slipstream), origin: .walletSend)
        h.clock.advance(31)
        await h.coordinator.runDueNow()
        let polled = try #require(await h.coordinator.receipt(receipt.txid))
        #expect(polled.state == .rejected)
        #expect(polled.rejection?.reason == "evicted")
    }

    @Test("polling backs off and survives a status failure")
    func pollingBacksOff() async throws {
        let miner = ScriptedMiner(
            submit: [.success(.accepted(txids: [], providerMessage: nil))],
            status: [.failure(.unreachable(host: "miner.example")),
                     .success(.pending(position: 2, inclusionOdds: "50", message: "queued"))])
        let h = try Harness(miner: miner)
        let receipt = try await h.coordinator.submit(rawTx: fakeSignedTx(), feeRateSatPerVByte: 4,
                                                     route: .minerOnly(.slipstream), origin: .walletSend)
        #expect(receipt.nextPollAt == h.clock.now + 30)
        h.clock.advance(31)
        await h.coordinator.runDueNow()
        let afterFailure = try #require(await h.coordinator.receipt(receipt.txid))
        #expect(afterFailure.pollAttempt == 1)
        #expect(afterFailure.nextPollAt == h.clock.now + 60, "second interval")
        #expect(afterFailure.state == .accepted)
        h.clock.advance(61)
        await h.coordinator.runDueNow()
        let afterSuccess = try #require(await h.coordinator.receipt(receipt.txid))
        #expect(afterSuccess.providerStatus?.position == 2)
        #expect(afterSuccess.providerStatus?.inclusionOdds == "50")
        #expect(afterSuccess.nextPollAt == h.clock.now + 120)
    }

    @Test("markConfirmed, rollBack and prune mirror the broadcaster's tombstones")
    func confirmRollBackPrune() async throws {
        let miner = ScriptedMiner(submit: [.success(.accepted(txids: [], providerMessage: nil))])
        let h = try Harness(miner: miner)
        let receipt = try await h.coordinator.submit(rawTx: fakeSignedTx(), feeRateSatPerVByte: 4,
                                                     route: .minerOnly(.slipstream), origin: .walletSend)
        try await h.coordinator.markConfirmed(receipt.txid, atHeight: 500)
        let confirmed = try #require(await h.coordinator.receipt(receipt.txid))
        #expect(confirmed.state == .confirmed)
        #expect(confirmed.confirmedAtHeight == 500)
        #expect(confirmed.nextPollAt == nil)
        #expect(await h.coordinator.pendingTxids.isEmpty, "held is not in flight")

        try await h.coordinator.rollBack(to: 450)
        let revived = try #require(await h.coordinator.receipt(receipt.txid))
        #expect(revived.state == .accepted, "back to the state before the block")
        #expect(revived.confirmedAtHeight == nil)
        #expect(revived.nextSubmitAt == h.clock.now, "resubmitted idempotently to the miner")
        #expect(h.relay.broadcasts.isEmpty, "a reorg never turns miner-only into a peer announcement")
        await h.coordinator.runDueNow()
        #expect(miner.submits.count == 2)

        try await h.coordinator.rollBack(to: 600)
        try await h.coordinator.markConfirmed(receipt.txid, atHeight: 510)
        try await h.coordinator.pruneConfirmed(scannedTo: 609)
        #expect(await h.coordinator.receipt(receipt.txid) != nil, "inside the horizon")
        try await h.coordinator.pruneConfirmed(scannedTo: 610)
        #expect(await h.coordinator.receipt(receipt.txid) == nil, "past the 100-block horizon")
    }

    @Test("a replacement marks the original replaced and links both receipts")
    func replacement() async throws {
        let miner = ScriptedMiner(submit: [.success(.accepted(txids: [], providerMessage: nil))])
        let h = try Harness(miner: miner)
        let original = try await h.coordinator.submit(rawTx: fakeSignedTx(seed: 1), feeRateSatPerVByte: 2,
                                                      route: .minerOnly(.slipstream), origin: .walletSend)
        let replacement = try await h.coordinator.submit(rawTx: fakeSignedTx(seed: 2), feeRateSatPerVByte: 5,
                                                         route: .minerOnly(.slipstream),
                                                         origin: .feeBump(original: original.txid))
        try await h.coordinator.markReplaced(original.txid, by: replacement.txid)
        let old = try #require(await h.coordinator.receipt(original.txid))
        #expect(old.state == .replaced)
        #expect(old.replacedBy == replacement.txid)
        #expect(old.nextPollAt == nil, "nothing to poll for a replaced transaction")
        #expect(!old.canReroute)
        let new = try #require(await h.coordinator.receipt(replacement.txid))
        #expect(new.replaces == original.txid)
        #expect(await h.coordinator.pendingTxids == [replacement.txid])
        // The block path can still confirm a replaced transaction.
        try await h.coordinator.markConfirmed(original.txid, atHeight: 700)
        #expect(await h.coordinator.receipt(original.txid)?.state == .confirmed)
    }

    @Test("abandon is bookkeeping, and cancels the relay only for routes that used it")
    func abandon() async throws {
        let miner = ScriptedMiner(submit: [.success(.accepted(txids: [], providerMessage: nil))])
        let h = try Harness(miner: miner)
        let mined = try await h.coordinator.submit(rawTx: fakeSignedTx(seed: 1), feeRateSatPerVByte: 4,
                                                   route: .minerOnly(.slipstream), origin: .walletSend)
        let peered = try await h.coordinator.submit(rawTx: fakeSignedTx(seed: 2), feeRateSatPerVByte: 2,
                                                    route: .peers, origin: .walletSend)
        try await h.coordinator.abandon(mined.txid)
        try await h.coordinator.abandon(peered.txid)
        #expect(await h.coordinator.receipt(mined.txid)?.state == .abandoned)
        #expect(h.relay.cancels == [peered.txid])
        #expect(await h.coordinator.pendingTxids.isEmpty)
        await #expect(throws: SubmissionError.self) {
            try await h.coordinator.abandon(mined.txid)
        }
    }

    @Test("the store round-trips, and restart resumes the schedule")
    func storeRoundTrip() async throws {
        let store = tempFileURL("submissions.json")
        defer { try? FileManager.default.removeItem(at: store.deletingLastPathComponent()) }
        let miner = ScriptedMiner(submit: [.failure(.unreachable(host: "miner.example")),
                                           .success(.accepted(txids: [], providerMessage: nil))])
        let first = try Harness(miner: miner, storageURL: store)
        let receipt = try await first.coordinator.submit(rawTx: fakeSignedTx(), feeRateSatPerVByte: 4,
                                                         route: .minerOnly(.slipstream), origin: .walletSend)
        #expect(first.coordinator.persistenceState == .loaded(receiptCount: 0))
        await first.coordinator.shutdown()

        let second = try Harness(miner: miner, storageURL: store)
        #expect(second.coordinator.persistenceState == .loaded(receiptCount: 1))
        let loaded = try #require(await second.coordinator.receipt(receipt.txid))
        #expect(loaded == receipt, "every field survives the file")
        second.clock.advance(20)
        await second.coordinator.runDueNow()
        #expect(await second.coordinator.receipt(receipt.txid)?.state == .accepted,
                "the persisted retry fired after the restart")
        #expect(miner.submits.count == 2)
    }

    @Test("a damaged store is rejected as a whole and never rewritten")
    func damagedStore() async throws {
        let store = tempFileURL("submissions.json")
        defer { try? FileManager.default.removeItem(at: store.deletingLastPathComponent()) }
        let miner = ScriptedMiner(submit: [.success(.accepted(txids: [], providerMessage: nil))])
        let h = try Harness(miner: miner, storageURL: store)
        _ = try await h.coordinator.submit(rawTx: fakeSignedTx(), feeRateSatPerVByte: 4,
                                           route: .minerOnly(.slipstream), origin: .walletSend)
        await h.coordinator.shutdown()

        let good = try Data(contentsOf: store)
        func expectRejected(_ bytes: Data, _ label: String) {
            try? bytes.write(to: store)
            #expect(throws: SubmissionStoreError.self, "\(label)") {
                _ = try Harness(miner: miner, storageURL: store)
            }
            #expect((try? Data(contentsOf: store)) == bytes, "\(label): the file was left alone")
        }
        expectRejected(Data("not json".utf8), "garbage")
        expectRejected(Data("{}".utf8), "no version")
        expectRejected(Data("[]".utf8), "wrong top level")
        expectRejected(Data(), "empty")
        var text = String(decoding: good, as: UTF8.self)
        text = text.replacingOccurrences(of: "\"version\":1", with: "\"version\":2")
        expectRejected(Data(text.utf8), "future version")
        // Swap the txid for another 32 bytes: the raw transaction no longer matches.
        let receiptTxidBase64 = try #require(Transaction.decode(fakeSignedTx()).txid.base64EncodedString() as String?)
        let tampered = String(decoding: good, as: UTF8.self)
            .replacingOccurrences(of: receiptTxidBase64, with: Data(repeating: 7, count: 32).base64EncodedString())
        expectRejected(Data(tampered.utf8), "txid mismatch")
    }

    @Test("exported receipts carry no raw bytes")
    func exportCarriesNoBytes() async throws {
        let miner = ScriptedMiner(submit: [.success(.accepted(txids: [], providerMessage: "queued"))])
        let h = try Harness(miner: miner)
        let raw = fakeSignedTx()
        let receipt = try await h.coordinator.submit(rawTx: raw, feeRateSatPerVByte: 4,
                                                     route: .minerOnly(.slipstream), origin: .walletSend)
        let exported = String(decoding: try await h.coordinator.exportReceipts(), as: UTF8.self)
        #expect(exported.contains(receipt.txid.displayHex))
        #expect(exported.contains("queued"))
        #expect(!exported.contains(raw.base64EncodedString()))
        #expect(!exported.contains(raw.hex))
        #expect(!exported.contains("rawTransaction"))
    }

    @Test("a malformed transaction is refused before anything is recorded")
    func malformedRefused() async throws {
        let h = try Harness()
        await #expect(throws: SubmissionError.self) {
            try await h.coordinator.submit(rawTx: Data([1, 2, 3]), feeRateSatPerVByte: 2,
                                           route: .peers, origin: .walletSend)
        }
        #expect(await h.coordinator.receipts.isEmpty)
        #expect(h.relay.broadcasts.isEmpty)
    }
}
