import Foundation
import Testing
@testable import BitcoinP2P

/// The rebroadcast backoff policy, checked without a clock.
///
/// The integration test in `TxBroadcasterTests` proves attempts fire and the
/// schedule advances; it deliberately does not measure step sizes, because it
/// samples the schedule by polling and a late poll inflates the measurement.
/// The step sizes live here instead, where they are a pure function of the
/// attempt count and the configured intervals (#138).
@Suite("TxBroadcaster backoff schedule")
struct TxBroadcasterBackoffTests {

    @Test("doubles from the base on every attempt until the cap, then holds")
    func doublesThenHolds() {
        let base = Duration.milliseconds(100)
        let cap = Duration.milliseconds(250)
        func interval(_ attempt: Int) -> Duration {
            TxBroadcaster.backoffInterval(attempt: attempt, base: base, cap: cap)
        }

        #expect(interval(0) == .milliseconds(100))
        #expect(interval(1) == .milliseconds(200))
        // 200 doubled is 400, past the cap, so the cap is taken instead.
        #expect(interval(2) == cap)
        #expect(interval(3) == cap)
        #expect(interval(50) == cap)
    }

    @Test("an uncapped schedule is exactly base × 2^attempt")
    func uncappedIsExactlyExponential() {
        let base = Duration.seconds(1)
        let cap = Duration.seconds(3_600)
        for attempt in 0 ... 10 {
            let expected = Duration.seconds(1 << attempt)
            #expect(TxBroadcaster.backoffInterval(attempt: attempt, base: base, cap: cap) == expected,
                    "attempt \(attempt) should be \(expected)")
        }
    }

    @Test("the cap is taken the moment doubling would reach it, not exceed it")
    func capBoundaryIsInclusive() {
        // Doubling 100ms lands exactly on the 200ms cap. The guard is `<`, so
        // the cap wins — the schedule never returns a value above it, and the
        // boundary case does not produce a longer interval than the cap.
        let interval = TxBroadcaster.backoffInterval(attempt: 1,
                                                     base: .milliseconds(100),
                                                     cap: .milliseconds(200))
        #expect(interval == .milliseconds(200))
    }

    @Test("no attempt ever schedules beyond the cap")
    func neverExceedsTheCap() {
        let base = Duration.seconds(60)
        let cap = Duration.seconds(3_600)
        for attempt in 0 ... 64 {
            let interval = TxBroadcaster.backoffInterval(attempt: attempt, base: base, cap: cap)
            #expect(interval <= cap, "attempt \(attempt) exceeded the cap")
        }
    }

    @Test("the shipped defaults double six times before capping at an hour")
    func shippedDefaults() {
        let base = Duration.seconds(60)
        let cap = Duration.seconds(3_600)
        func interval(_ attempt: Int) -> Duration {
            TxBroadcaster.backoffInterval(attempt: attempt, base: base, cap: cap)
        }

        #expect(interval(0) == .seconds(60))
        #expect(interval(1) == .seconds(120))
        #expect(interval(2) == .seconds(240))
        #expect(interval(3) == .seconds(480))
        #expect(interval(4) == .seconds(960))
        #expect(interval(5) == .seconds(1_920))
        // 1,920 doubled is 3,840 — past the hour cap, so the cap is taken.
        #expect(interval(6) == cap)
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
        try await broadcaster.markConfirmed(txid)
        #expect(await broadcaster.rawTransaction(txid) == nil)
        await broadcaster.shutdown()
    }

    @Test("a cap below the base clamps every attempt to the cap")
    func capBelowBaseClamps() {
        // Degenerate configuration, but it must not return an interval longer
        // than the cap the caller asked for.
        let interval = TxBroadcaster.backoffInterval(attempt: 0,
                                                     base: .seconds(60),
                                                     cap: .seconds(10))
        #expect(interval == .seconds(10))
    }
}
