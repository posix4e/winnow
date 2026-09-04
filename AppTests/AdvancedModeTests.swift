@testable import WinnowApp
import BitcoinP2P
import XCTest

/// Advanced mode gates everything a beginner should never have to read,
/// starting with the network picker. Off by default, global rather than per
/// network, and turning it off hides rather than deletes.
@MainActor
final class AdvancedModeTests: XCTestCase {
    private final class SilentAuthenticator: DeviceAuthenticating {
        func authenticate(reason: String) async throws {}
    }

    private var savedNetwork: String?

    override func setUp() {
        super.setUp()
        savedNetwork = UserDefaults.standard.string(forKey: AppModel.DefaultsKey.network)
        UserDefaults.standard.removeObject(forKey: AppModel.DefaultsKey.advancedMode)
        UserDefaults.standard.removeObject(forKey: AppModel.DefaultsKey.network)
    }

    override func tearDown() {
        UserDefaults.standard.removeObject(forKey: AppModel.DefaultsKey.advancedMode)
        if let savedNetwork {
            UserDefaults.standard.set(savedNetwork, forKey: AppModel.DefaultsKey.network)
        } else {
            UserDefaults.standard.removeObject(forKey: AppModel.DefaultsKey.network)
        }
        super.tearDown()
    }

    func testAFreshInstallIsOnMainnetAndHidesTheNetworkPicker() {
        let model = AppModel(deviceAuthenticator: SilentAuthenticator())
        XCTAssertEqual(model.network, .mainnet, "#9: mainnet is the default")
        XCTAssertEqual(AppModel.defaultNetwork, .mainnet)
        XCTAssertFalse(model.showsNetworkPicker, "signet is an Advanced-mode concern")
        model.setAdvancedMode(true)
        XCTAssertTrue(model.showsNetworkPicker)
    }

    func testASignetWalletAlwaysKeepsTheNetworkPicker() {
        // Advanced mode off, but the stored network is signet: the row must
        // stay, or turning the flag off would strand the wallet there.
        UserDefaults.standard.set(BitcoinNetwork.signet.rawValue, forKey: AppModel.DefaultsKey.network)
        let model = AppModel(deviceAuthenticator: SilentAuthenticator())
        XCTAssertEqual(model.network, .signet)
        XCTAssertFalse(model.advancedMode)
        XCTAssertTrue(model.showsNetworkPicker)
    }

    func testOffByDefaultAndPersistedWhenTurnedOn() {
        let model = AppModel(deviceAuthenticator: SilentAuthenticator())
        XCTAssertFalse(model.advancedMode, "a fresh install is a beginner")
        model.setAdvancedMode(true)
        XCTAssertTrue(model.advancedMode)
        XCTAssertTrue(UserDefaults.standard.bool(forKey: AppModel.DefaultsKey.advancedMode))
        XCTAssertEqual(AppModel.DefaultsKey.advancedMode, "advancedMode",
                       "global, not network-scoped: a statement about the user, not the chain")
    }

    func testTheE2EFlagTurnsItOnForAUITestLaunch() throws {
        let base = [
            "WINNOW_E2E": "1",
            "WINNOW_E2E_ENTROPY": String(repeating: "00", count: 16),
        ]
        guard case let .active(plain) = E2EMode.resolve(environment: base) else {
            return XCTFail("E2E mode should resolve")
        }
        XCTAssertFalse(plain.advancedMode)
        guard case let .active(advanced) = E2EMode.resolve(
            environment: base.merging(["WINNOW_E2E_ADVANCED": "1"]) { $1 })
        else {
            return XCTFail("E2E mode should resolve")
        }
        XCTAssertTrue(advanced.advancedMode)
    }
}
