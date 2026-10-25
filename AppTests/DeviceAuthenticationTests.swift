@testable import WinnowApp
import LocalAuthentication
import WalletCore
import TestSupport
import XCTest

@MainActor
final class DeviceAuthenticationTests: XCTestCase {
    private final class RecordingAuthenticator: DeviceAuthenticating {
        enum Failure: Error { case denied }

        var reasons: [String] = []
        var shouldFail = false

        func authenticate(reason: String) async throws {
            reasons.append(reason)
            if shouldFail { throw Failure.denied }
        }
    }

    /// Passes, and leaves a check behind the way the real authenticator
    /// does, so the model's handling of that check can be observed.
    private final class GrantingAuthenticator: DeviceAuthenticating {
        var keychain: KeychainAuthentication?

        func authenticate(reason: String) async throws {
            keychain?.grant(LAContext())
        }
    }

    func testSensitiveActionUsesInjectedDeviceAuthenticator() async throws {
        let authenticator = RecordingAuthenticator()
        let model = makeModel(deviceAuthenticator: authenticator)

        try await model.authenticateSensitiveAction(reason: "Authorize test operation")

        XCTAssertEqual(authenticator.reasons, ["Authorize test operation"])
    }

    func testSensitiveActionFailsClosedWhenAuthenticationFails() async {
        let authenticator = RecordingAuthenticator()
        authenticator.shouldFail = true
        let model = makeModel(deviceAuthenticator: authenticator)

        do {
            try await model.authenticateSensitiveAction(reason: "Authorize test operation")
            XCTFail("authentication failure was ignored")
        } catch RecordingAuthenticator.Failure.denied {
            XCTAssertEqual(authenticator.reasons, ["Authorize test operation"])
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testCloudRestoreAuthenticatesBeforeReadingCloudData() async {
        let authenticator = RecordingAuthenticator()
        authenticator.shouldFail = true
        let model = makeModel(deviceAuthenticator: authenticator)
        do {
            _ = try await model.restoreCloudBackup(UUID())
            XCTFail("cloud restore ignored denied device authentication")
        } catch RecordingAuthenticator.Failure.denied {
            XCTAssertEqual(authenticator.reasons, ["Restore your wallet and signing key from iCloud"])
            XCTAssertNil(model.walletID)
        } catch {
            XCTFail("cloud access ran before authentication: \(error)")
        }
    }

    /// The check the app passes is held for the Keychain read of that one
    /// operation and no longer. Deleting the wallet reads no secret, so
    /// when it returns nothing must be left for other code to read with.
    func testAPassedCheckDoesNotOutliveTheOperation() async throws {
        let environment = ["WINNOW_E2E": "1", "WINNOW_E2E_RUN": "auth-scope-\(UUID().uuidString)",
                           "WINNOW_E2E_ENTROPY": String(repeating: "a1", count: 16),
                           "WINNOW_E2E_DEVICE_AUTH": "1"]
        guard case let .active(mode) = E2EMode.resolve(environment: environment),
              case let .active(cleanup) = E2EMode.resolve(
                environment: environment.merging(["WINNOW_E2E_RESET": "1"]) { _, reset in reset })
        else { return XCTFail("could not create an isolated fixture") }
        defer { cleanup.wipeIfRequested() }
        let authenticator = GrantingAuthenticator()
        let model = AppModel(deviceAuthenticator: authenticator, e2e: mode, defaults: makeDefaults())
        authenticator.keychain = model.keychainAuthentication
        let directory = try XCTUnwrap(model.storageDirectory())
        _ = try Wallet.create(network: .signet, keyStore: model.keyStore,
                              storageURL: directory.appending(path: "wallet.json"), entropy: mode.entropy)
        await model.boot()
        XCTAssertEqual(model.stage, .ready)

        try await model.authenticateSensitiveAction(reason: "control")
        XCTAssertTrue(model.keychainAuthentication.isGranted, "the fixture authenticator left no check")

        let cachedCloudCopy = directory.appending(path: "cloud-backup.json")
        try Data("encrypted-test-backup".utf8).write(to: cachedCloudCopy)

        try await model.destroyWallet()
        XCTAssertFalse(FileManager.default.fileExists(atPath: cachedCloudCopy.path),
                       "deleting the local wallet retained its encrypted local cloud copy")
        XCTAssertFalse(model.keychainAuthentication.isGranted,
                       "the wallet is gone and the check that let it go is still there for a read")
    }

    /// Leaving the screen drops a check whatever operation held it.
    func testLeavingTheScreenDropsAPassedCheck() async {
        let model = makeModel()
        model.keychainAuthentication.grant(LAContext())
        await model.scenePhaseChanged(.background)
        XCTAssertFalse(model.keychainAuthentication.isGranted)
    }
}
