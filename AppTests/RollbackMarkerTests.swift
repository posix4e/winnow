@testable import WinnowApp
import BitcoinP2P
import Foundation
import WalletCore
import XCTest

/// The crash marker has to fail closed (#127).
///
/// The rollback spans four stores that persist independently, so a crash
/// part-way through leaves them disagreeing. The marker is what makes that
/// recoverable: because a rollback is a pure function of the fork height it is
/// idempotent, so recovery is a redo rather than a repair.
///
/// That only holds if the target is genuinely recorded before anything moves.
/// Both of these pin a `try?` that had quietly defeated the mechanism it was
/// written to protect — the failure mode being a silent one, where the code
/// reads as if the guarantee holds.
@MainActor
final class RollbackMarkerTests: XCTestCase {
    private final class SilentAuthenticator: DeviceAuthenticating {
        func authenticate(reason: String) async throws {}
    }

    private func makeModel() -> AppModel {
        AppModel(deviceAuthenticator: SilentAuthenticator())
    }

    /// If the target cannot be written, nothing may change. Proceeding into
    /// the rollbacks unprotected is exactly the state the marker prevents: a
    /// crash then leaves the stores disagreeing with nothing to trigger a redo.
    func testAFailedMarkerWriteStopsTheRollback() async throws {
        let model = makeModel()
        let directory = try XCTUnwrap(model.storageDirectory())
        let marker = directory.appending(path: AppModel.rollbackMarkerName)
        defer {
            try? FileManager.default.setAttributes([.immutable: false], ofItemAtPath: marker.path(percentEncoded: false))
            try? FileManager.default.removeItem(at: marker)
        }

        // A directory where the marker's name should be: the write cannot
        // succeed, and must not be shrugged off.
        try? FileManager.default.removeItem(at: marker)
        try FileManager.default.createDirectory(at: marker, withIntermediateDirectories: true)

        var thrown: (any Error)?
        do {
            try await model.rollBackStores(to: 200)
        } catch {
            thrown = error
        }
        XCTAssertNotNil(thrown, "an unrecordable rollback must not proceed silently")

        try? FileManager.default.removeItem(at: marker)
    }

    /// The happy path, so the test above is not passing because the marker is
    /// broken in general.
    func testTheTargetIsRecordedBeforeTheStoresMove() async throws {
        let model = makeModel()
        let directory = try XCTUnwrap(model.storageDirectory())
        let marker = directory.appending(path: AppModel.rollbackMarkerName)
        defer { try? FileManager.default.removeItem(at: marker) }
        try? FileManager.default.removeItem(at: marker)

        try await model.rollBackStores(to: 4_242)

        let recorded = try String(contentsOf: marker, encoding: .utf8)
        XCTAssertEqual(recorded.trimmingCharacters(in: .whitespacesAndNewlines), "4242")
    }

    /// …and it is cleared once the sync that followed has finished, or every
    /// later launch would redo a rollback that already completed.
    func testFinishClearsTheTarget() async throws {
        let model = makeModel()
        let directory = try XCTUnwrap(model.storageDirectory())
        let marker = directory.appending(path: AppModel.rollbackMarkerName)
        defer { try? FileManager.default.removeItem(at: marker) }
        // The simulator keeps its container between runs, so clear whatever a
        // previous test left at this path -- including a directory.
        try? FileManager.default.removeItem(at: marker)

        try await model.rollBackStores(to: 200)
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker.path(percentEncoded: false)))
        model.finishRollback()
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path(percentEncoded: false)))
    }

    /// A marker holding something that is not a height is inert cruft, not a
    /// reason to refuse to launch: there is no height to roll back to, so
    /// there is nothing to redo.
    func testAGarbageMarkerIsInert() async throws {
        let model = makeModel()
        let directory = try XCTUnwrap(model.storageDirectory())
        let marker = directory.appending(path: AppModel.rollbackMarkerName)
        defer { try? FileManager.default.removeItem(at: marker) }
        try Data("not a height".utf8).write(to: marker, options: .atomic)

        try await model.resumeInterruptedRollback()
    }

    /// No marker means no interrupted rollback, which must be silent.
    func testNoMarkerIsSilent() async throws {
        let model = makeModel()
        if let directory = model.storageDirectory() {
            try? FileManager.default.removeItem(
                at: directory.appending(path: AppModel.rollbackMarkerName))
        }
        try await model.resumeInterruptedRollback()
    }
}
