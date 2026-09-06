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

    private var saved: [String: Any?] = [:]
    private var trackedKeys: [String] {
        [AppModel.DefaultsKey.network, AppModel.DefaultsKey.advancedMode,
         AppModel.DefaultsKey.verifyFromGenesis,
         AppModel.DefaultsKey.manualPeers(.mainnet), AppModel.DefaultsKey.esploraURL(.mainnet)]
    }

    override func setUp() {
        super.setUp()
        for key in trackedKeys {
            saved[key] = UserDefaults.standard.object(forKey: key)
            UserDefaults.standard.removeObject(forKey: key)
        }
    }

    override func tearDown() {
        for key in trackedKeys {
            if let value = saved[key] ?? nil {
                UserDefaults.standard.set(value, forKey: key)
            } else {
                UserDefaults.standard.removeObject(forKey: key)
            }
        }
        super.tearDown()
    }

    func testBeginnerKeepsManualPeersWhileAnyAreSet() throws {
        let model = AppModel(deviceAuthenticator: SilentAuthenticator())
        XCTAssertFalse(model.showsManualPeers)
        try model.addManualPeer("127.0.0.1:38401")
        XCTAssertTrue(model.showsManualPeers, "a configured peer keeps its section")
        model.setAdvancedMode(true)
        model.setAdvancedMode(false)
        XCTAssertEqual(model.manualPeers, ["127.0.0.1:38401"], "hide, never delete")
        model.removeManualPeers(at: IndexSet(integer: 0))
        XCTAssertFalse(model.showsManualPeers)
        model.setAdvancedMode(true)
        XCTAssertTrue(model.showsManualPeers)
    }

    func testBeginnerKeepsChainVerificationWhileOn() {
        UserDefaults.standard.set(true, forKey: AppModel.DefaultsKey.verifyFromGenesis)
        let model = AppModel(deviceAuthenticator: SilentAuthenticator())
        XCTAssertFalse(model.advancedMode)
        XCTAssertTrue(model.showsChainVerification)
        XCTAssertFalse(AppModel(deviceAuthenticator: SilentAuthenticator()).showsExplorerSettings)
    }

    func testBeginnerKeepsExplorerSettingsWhileCustomised() {
        let model = AppModel(deviceAuthenticator: SilentAuthenticator())
        XCTAssertFalse(model.showsExplorerSettings)
        model.setEsploraURL("https://example.org")
        XCTAssertTrue(model.showsExplorerSettings)
        model.setEsploraURL("")
        XCTAssertFalse(model.showsExplorerSettings)
        XCTAssertTrue(model.esploraTransactionURL(Data(repeating: 0xAB, count: 32)).absoluteString
            .hasPrefix("https://mempool.space/tx/"), "the history link works with the section hidden")
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
