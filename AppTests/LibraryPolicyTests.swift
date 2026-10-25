@testable import WinnowApp
import WalletCore
import TestSupport
import XCTest

@MainActor
final class LibraryPolicyTests: XCTestCase {
    func testCappedPeerFloorRequiresANewFeeDecision() throws {
        let quote = FeePolicy.resolution(floorSatPerVByte: 200)
        XCTAssertEqual(quote.rate, 120)
        do {
            try AppModel.requireRelayFee(rate: quote.rate, floor: quote.clampedFloor)
            XCTFail("a capped rate was accepted below the reported floor")
        } catch let AppModel.AppError.feeDecisionRequired(rate, floor) {
            XCTAssertEqual(rate, 120)
            XCTAssertEqual(floor, 200)
        }
        let explicit = FeePolicy.resolution(override: 200, floorSatPerVByte: 200)
        XCTAssertNoThrow(try AppModel.requireRelayFee(rate: explicit.rate, floor: explicit.clampedFloor))
        // The live broadcast gate also rejects a floor that rose since review.
        XCTAssertThrowsError(try AppModel.requireRelayFee(rate: 200, floor: 201))
    }

    func testNetworkSwitchKeepsPreferencesIsolated() async throws {
        let environment = ["WINNOW_E2E": "1", "WINNOW_E2E_RUN": "policy-switch-\(UUID().uuidString)",
                           "WINNOW_E2E_ENTROPY": String(repeating: "a1", count: 16),
                           "WINNOW_E2E_RESET": "1"]
        guard case let .active(mode) = E2EMode.resolve(environment: environment) else {
            return XCTFail("could not create an isolated fixture")
        }
        defer { mode.wipeIfRequested() }
        let model = AppModel(e2e: mode, storeKeys: InMemoryStoreKeyVault(),
                             keyStore: InMemoryKeyStore())
        // The isolated E2E namespace, initialized and wiped by the model.
        let defaults = mode.defaults
        defaults.set(["mainnet.example:8333"], forKey: AppModel.DefaultsKey.manualPeers(.mainnet))
        defaults.set(["signet.example:38333"], forKey: AppModel.DefaultsKey.manualPeers(.signet))
        await model.switchNetwork(to: .mainnet)
        await model.switchNetwork(to: .signet)
        XCTAssertEqual(model.manualPeers, ["signet.example:38333"])
        XCTAssertEqual(model.stage, .onboarding)
        await model.switchNetwork(to: .mainnet)
        XCTAssertEqual(model.manualPeers, ["mainnet.example:8333"])
        XCTAssertNil(model.walletID)
        XCTAssertEqual(model.stage, .onboarding)
    }

    func testNetworkSwitchReopensOnlyItsOwnWalletAndRefusesDamagedState() async throws {
        let environment = ["WINNOW_E2E": "1", "WINNOW_E2E_RUN": "policy-wallet-\(UUID().uuidString)",
                           "WINNOW_E2E_ENTROPY": String(repeating: "a1", count: 16),
                           "WINNOW_E2E_RESET": "1"]
        guard case let .active(mode) = E2EMode.resolve(environment: environment) else {
            return XCTFail("could not create an isolated fixture")
        }
        defer { mode.wipeIfRequested() }
        let keys = InMemoryKeyStore()
        let model = AppModel(e2e: mode, storeKeys: InMemoryStoreKeyVault(), keyStore: keys)
        await model.switchNetwork(to: .mainnet)
        let mainnetFile = try XCTUnwrap(model.storageDirectory()).appending(path: "wallet.json")
        let wallet = try Wallet.create(network: .mainnet, keyStore: keys,
                                       storageURL: mainnetFile, entropy: mode.entropy)
        let id = await wallet.id
        let original = try Data(contentsOf: mainnetFile)
        await model.switchNetwork(to: .signet)
        XCTAssertNil(model.walletID)
        XCTAssertEqual(model.stage, .onboarding)
        let signetFile = try XCTUnwrap(model.storageDirectory()).appending(path: "wallet.json")
        // A wallet on the other network must not hide this one, and reopening
        // must preserve its exact bytes and the key already held for its ID.
        await model.switchNetwork(to: .mainnet)
        XCTAssertEqual(model.walletID, id)
        XCTAssertEqual(model.stage, .ready)
        XCTAssertEqual(try Data(contentsOf: mainnetFile), original)
        XCTAssertNoThrow(try keys.load(walletID: id))
        let damaged = Data("unreadable wallet fixture".utf8)
        try damaged.write(to: signetFile)
        await model.switchNetwork(to: .signet)
        XCTAssertNil(model.walletID)
        guard case .storageDamaged = model.stage else {
            return XCTFail("a damaged network wallet was treated as empty")
        }
        XCTAssertEqual(try Data(contentsOf: signetFile), damaged)
        XCTAssertEqual(try Data(contentsOf: mainnetFile), original)
        XCTAssertNoThrow(try keys.load(walletID: id))
    }

    func testAppRefusalsExplainAuthorizationAndRecovery() throws {
        let cases: [(AppModel.AppError, String)] = [
            (.noWallet, "No wallet"), (.noStack, "not running"), (.noPeers, "Settings"),
            (.mnemonicUnavailable, "Keychain"),
            (.feeDecisionRequired(rate: 120, floor: 200), "explicit rate"),
            (.invalidPeer("bad-peer"), "host:port"), (.wrongNetwork("signet"), "signet"),
            (.sendReviewChanged, "Review the payment again"),
            (.storageDamaged("fixture damage"), "fixture damage"),
            (.deviceAuthUnavailable, "passcode"), (.deviceAuthFailed, "failed"),
            (.spendAlreadyInFlight, "Wait for it to finish"),
            (.noStorage, "Syncing has stopped"), (.paymentDetailsUnavailable, "on this phone"),
            (.personCannotBePaid, "pay-to key")
        ]
        for (error, guidance) in cases {
            XCTAssertTrue(try XCTUnwrap(error.errorDescription).contains(guidance))
        }
        let fee = try XCTUnwrap(AppModel.AppError.feeDecisionRequired(rate: 120, floor: 200).errorDescription)
        XCTAssertTrue(fee.contains("200.0"))
        XCTAssertTrue(fee.contains("120"))
    }

}
