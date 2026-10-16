import Foundation

/// Parks code at a chosen suspension point until the test lets it go, so a
/// second call can be made while the first is genuinely suspended there.
/// Polling for that window would make the test a race; this makes it an
/// ordering.
///
/// Two latches, each one-shot. The parked side calls `reach()` and then
/// `waitForRelease()`; the test calls `waitForReach()`, does what it came to
/// do, then `release()`. Either side may arrive first.
public actor ParkGate {
    private var reached = false
    private var reachWaiter: CheckedContinuation<Void, Never>?
    private var released = false
    private var releaseWaiter: CheckedContinuation<Void, Never>?

    public init() {}

    /// Called from the parking spot: the code under test has arrived.
    public func reach() {
        reached = true
        reachWaiter?.resume()
        reachWaiter = nil
    }

    public func waitForReach() async {
        guard !reached else { return }
        await withCheckedContinuation { reachWaiter = $0 }
    }

    public func release() {
        released = true
        releaseWaiter?.resume()
        releaseWaiter = nil
    }

    public func waitForRelease() async {
        guard !released else { return }
        await withCheckedContinuation { releaseWaiter = $0 }
    }

    /// Runs `body` in a task and hands back its outcome as a `Result`, then
    /// opens the reach latch whether or not `body` ever parked. A run that
    /// ended without reaching the gate would otherwise leave the test waiting
    /// on a latch nobody will open; this way a broken path fails the test on an
    /// assertion instead.
    public nonisolated func settling<Value: Sendable>(
        _ body: @escaping @Sendable () async throws -> Value
    ) -> Task<Result<Value, any Error>, Never> {
        Task {
            let outcome: Result<Value, any Error>
            do {
                outcome = .success(try await body())
            } catch {
                outcome = .failure(error)
            }
            await self.reach()
            return outcome
        }
    }
}
