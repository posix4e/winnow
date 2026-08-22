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
