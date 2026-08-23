@testable import WinnowApp
import BitcoinP2P
import Foundation
import WalletCore
import XCTest

/// A damaged relay store must not stop the wallet from syncing (#150).
///
/// The three stores the app keeps are not equally important. Rebroadcast state
/// is best-effort — it exists so a pending transaction keeps being announced,
/// and the wallet's own history is the source of truth for balance and
/// confirmations. Headers and filters are what make the wallet work at all.
///
/// Constructing the broadcaster inside the sync-stack build inverted that: one
/// damaged record in the least important store threw out of the whole build,
/// `stack` was never assigned, and neither header nor filter sync started.
/// Because nothing repaired the file, every relaunch failed identically — and
/// it surfaced as a sync error, so the user had no way of knowing that
/// deleting a file they cannot see was the remedy.
@MainActor
final class RelayStoreQuarantineTests: XCTestCase {
    private final class SilentAuthenticator: DeviceAuthenticating {
        func authenticate(reason: String) async throws {}
    }

    private func makeModel() -> AppModel {
        AppModel(deviceAuthenticator: SilentAuthenticator())
    }

    private func makeDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appending(path: "winnow-relay-quarantine-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func pool() -> PeerPool {
        PeerPool(params: .signet, peerCount: 0, manualPeers: [])
    }

    /// Every shape `load` refuses. Each is a distinct rejection path, so one
    /// broad case would pass even if the others stopped being handled.
    private var damagedStores: [(label: String, bytes: Data)] {
        [
            ("not json at all", Data("this is not json".utf8)),
            ("json of the wrong shape", Data(#"{"version":1,"transactions":"nope"}"#.utf8)),
            ("unsupported version", Data(#"{"version":9999,"transactions":{}}"#.utf8)),
            ("truncated mid-object", Data(#"{"version":1,"transactions":{"ab"#.utf8)),
            ("empty file", Data()),
        ]
    }

    // MARK: - The defect

    /// The property that keeps the stack build alive: this must not throw.
    func testDamagedStoreDoesNotThrowOutOfTheBuild() throws {
        for store in damagedStores {
            let dir = try makeDirectory()
            defer { try? FileManager.default.removeItem(at: dir) }
            let url = dir.appending(path: "broadcast.json")
            try store.bytes.write(to: url)

            let model = makeModel()
            XCTAssertNoThrow(try model.makeBroadcaster(pool: pool(), storageURL: url),
                             "a \(store.label) store must not take the sync stack down with it")
        }
    }

    /// The damaged file is kept, not deleted: it is the only evidence of what
    /// went wrong and may hold transactions worth recovering by hand.
    func testDamagedStoreIsQuarantinedRatherThanDeleted() throws {
        let dir = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appending(path: "broadcast.json")
        let original = Data("this is not json".utf8)
        try original.write(to: url)

        let model = makeModel()
        _ = try model.makeBroadcaster(pool: pool(), storageURL: url)

        let quarantine = dir.appending(path: AppModel.quarantinedRelayStoreName)
        XCTAssertEqual(try Data(contentsOf: quarantine), original,
                       "the damaged bytes must survive for diagnosis")
    }

    /// …and the original path is usable again, so relay starts fresh rather
    /// than failing identically on every relaunch.
    func testOriginalPathIsUsableAgain() async throws {
        let dir = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appending(path: "broadcast.json")
        try Data("this is not json".utf8).write(to: url)

        let model = makeModel()
        let broadcaster = try model.makeBroadcaster(pool: pool(), storageURL: url)
        let pending = await broadcaster.pendingTxids
        XCTAssertTrue(pending.isEmpty, "a fresh broadcaster starts with an empty queue")

        // A second construction on the same path now succeeds cleanly, which
        // is what "recovers on its own" means.
        XCTAssertNoThrow(try model.makeBroadcaster(pool: pool(), storageURL: url))
    }

    /// Reported as a relay problem, not as a sync failure — sync is fine.
    func testSurfacedAsARelayProblemNotASyncFailure() throws {
        let dir = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appending(path: "broadcast.json")
        try Data("this is not json".utf8).write(to: url)

        let model = makeModel()
        _ = try model.makeBroadcaster(pool: pool(), storageURL: url)

        let message = try XCTUnwrap(model.status.relayStoreQuarantined)
        XCTAssertTrue(message.contains(AppModel.quarantinedRelayStoreName),
                      "the message must name the file it set aside")
        XCTAssertNil(model.status.lastSyncError,
                     "sync did not fail; saying so would send the user after the wrong problem")
    }

    /// The control. A healthy store must load normally and quarantine nothing,
    /// or the tests above would pass against a build that always quarantines.
    func testHealthyStoreIsLeftAlone() throws {
        let dir = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appending(path: "broadcast.json")

        // Written by the broadcaster itself, so this is a real store.
        let seed = makeModel()
        _ = try seed.makeBroadcaster(pool: pool(), storageURL: url)

        let model = makeModel()
        XCTAssertNoThrow(try model.makeBroadcaster(pool: pool(), storageURL: url))
        XCTAssertNil(model.status.relayStoreQuarantined,
                     "an undamaged store must not be set aside")
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: dir.appending(path: AppModel.quarantinedRelayStoreName).path()))
    }

    /// A second failure keeps the most recent evidence rather than refusing to
    /// move because the destination exists.
    func testASecondQuarantineReplacesTheFirst() throws {
        let dir = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appending(path: "broadcast.json")
        let model = makeModel()

        try Data("first damage".utf8).write(to: url)
        _ = try model.makeBroadcaster(pool: pool(), storageURL: url)
        try Data("second damage".utf8).write(to: url)
        _ = try model.makeBroadcaster(pool: pool(), storageURL: url)

        let quarantine = dir.appending(path: AppModel.quarantinedRelayStoreName)
        XCTAssertEqual(try Data(contentsOf: quarantine), Data("second damage".utf8))
    }
}
