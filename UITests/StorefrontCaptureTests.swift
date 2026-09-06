import BitcoinCore
import BitcoinP2P
import CryptoKit
import Foundation
import WalletCore
import XCTest

/// App Store screenshots from the real app against the signet fixture (#39):
/// believable amounts, the beginner shell, no doctoring. Its own class so the
/// functional capture (WinnowAppUITests) stays byte-identical.
///
/// Runs only with WINNOW_E2E_STOREFRONT=1, read through BitcoinCLI's
/// environment lookup (process environment, then ~/.winnow-node.env), so an
/// ordinary `-only-testing:WinnowAppUITests` run skips it. Invocation:
/// scripts/storefront-capture, or
///   TEST_RUNNER_WINNOW_E2E_STOREFRONT=1 xcodebuild test … \
///     -only-testing:WinnowAppUITests/StorefrontCaptureTests
///
/// One test method, because the sequence is one story: the wallet the
/// receive shots fund is the wallet the send and savings shots spend from.
@MainActor
final class StorefrontCaptureTests: XCTestCase {
    private static let runID = "store"
    private static let payerWallet = "storefront-payer"

    /// Entropy pinned per run from the chain height: a different wallet from
    /// the functional suite's, so it never rediscovers those coinbases, and a
    /// different one on every rerun, so a balance is never doubled.
    private static var entropyHex: String = {
        let count = (try? BitcoinCLI.blockCount()) ?? 0
        let digest = SHA256.hash(data: Data("winnow-storefront-\(count)".utf8))
        return Data(digest).prefix(16).map { String(format: "%02x", $0) }.joined()
    }()

    private static var mnemonic: String {
        try! BIP39.mnemonic(entropy: Data(hex: entropyHex)!)
    }

    override func setUp() async throws {
        try await super.setUp()
        guard BitcoinCLI.environmentValue("WINNOW_E2E_STOREFRONT") == "1" else {
            throw XCTSkip("set WINNOW_E2E_STOREFRONT=1 to capture the storefront set")
        }
        // The -only-testing selection bypasses HostProcessProbeTests.
        XCTAssertGreaterThan(try BitcoinCLI.blockCount(), 0, "local signet node unreachable")
        executionTimeAllowance = 1800
    }

    // MARK: - Launch

    @discardableResult
    private func launch(run: String = StorefrontCaptureTests.runID, reset: Bool = false,
                        clipboard: String? = nil, network: BitcoinNetwork? = nil,
                        localNode: Bool = true, expectOnboarding: Bool = false) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchEnvironment = [
            "WINNOW_E2E": "1",
            "WINNOW_E2E_RUN": run,
            "WINNOW_E2E_ENTROPY": Self.entropyHex,
        ]
        if localNode {
            app.launchEnvironment["WINNOW_E2E_PEER"] = "\(BitcoinCLI.nodeHost):\(BitcoinCLI.p2pPort)"
            app.launchEnvironment["WINNOW_E2E_CHALLENGE"] = BitcoinCLI.challengeHex
        }
        if let network { app.launchEnvironment["WINNOW_E2E_NETWORK"] = network.rawValue }
        if reset { app.launchEnvironment["WINNOW_E2E_RESET"] = "1" }
        if let clipboard { app.launchEnvironment["WINNOW_E2E_CLIPBOARD"] = clipboard }
        app.launch()
        if expectOnboarding {
            XCTAssertTrue(app.buttons["createWalletButton"].waitForExistence(timeout: 120),
                          "onboarding did not appear")
        } else {
            XCTAssertTrue(app.staticTexts["balanceText"].waitForExistence(timeout: 120),
                          "wallet home did not appear")
        }
        return app
    }

    private func createWallet(_ app: XCUIApplication) {
        app.buttons["createWalletButton"].tap()
        let toggle = app.switches["writtenDownToggle"]
        XCTAssertTrue(toggle.waitForExistence(timeout: 60), "backup sheet did not appear")
        app.flipSwitch(toggle)
        let done = app.buttons["backupDoneButton"]
        XCTAssertTrue(scrollUntilExists(app, done, maxSwipes: 4), "backup Done button was not reachable")
        XCTAssertTrue(poll(timeout: 10, interval: 1, "backup Done enabled") { done.isEnabled })
        done.tap()
        XCTAssertTrue(app.staticTexts["balanceText"].waitForExistence(timeout: 60), "home did not appear")
    }

    /// The balance label parsed to sats (-1 when absent).
    private func balanceSats(_ app: XCUIApplication) -> Int64 {
        Int64(balanceText(app).filter(\.isNumber)) ?? -1
    }

    private func waitForBalance(_ app: XCUIApplication, atLeast target: Int64, _ what: String) {
        XCTAssertTrue(poll(timeout: 300, interval: 5, what) {
            if self.balanceSats(app) >= target { return true }
            self.nudgeSync(app)
            return false
        }, "balance never reached \(target) sats: \(what)")
    }

    /// Waits until the beginner sync line reads "Synced", so a send review
    /// carries no mid-sync locktime warning. Not fatal: the story goes on
    /// with the warning if the phase never settles.
    private func waitForSynced(_ app: XCUIApplication) {
        let summary = app.descendants(matching: .any).matching(identifier: "syncSummaryText").firstMatch
        let deadline = Date().addingTimeInterval(120)
        while Date() < deadline {
            if summary.exists, summary.label.contains("Synced") { return }
            nudgeSync(app)
            Thread.sleep(forTimeInterval: 3)
        }
        print("storefront: sync did not read Synced within two minutes; the review may carry the locktime note")
    }

    // MARK: - The node as a payer

    /// A keyed wallet on the node with at least `minimum` spendable sats,
    /// funded by mining coinbases to it (101 blocks matures the first).
    private func ensurePayer(minimum: Int64) async throws {
        try BitcoinCLI.ensureWallet(Self.payerWallet)
        if try BitcoinCLI.trustedBalanceSats(wallet: Self.payerWallet) >= minimum { return }
        let address = try BitcoinCLI.newAddress(wallet: Self.payerWallet)
        let script = try AddressDecoder.scriptPubKey(for: address, network: .signet)
        for _ in 0 ..< 101 {
            try await SignetMiner.mineOntoTip(payingTo: script)
        }
        XCTAssertGreaterThanOrEqual(try BitcoinCLI.trustedBalanceSats(wallet: Self.payerWallet), minimum,
                                    "the payer wallet did not mature a coinbase")
    }

    /// Pays the app from the node, waits for the transaction to reach the
    /// mempool (it is created there, so this is immediate), and mines it.
    private func payAndConfirm(_ address: String, sats: Int64) async throws {
        try BitcoinCLI.sendToAddress(wallet: Self.payerWallet, address: address, sats: sats, feeRate: 2)
        try await SignetMiner.mineOntoTip(payingTo: Self.payoutScript())
    }

    private static func payoutScript() throws -> Data {
        try AddressDecoder.scriptPubKey(for: WinnowAppUITests.fixtureAddress(0xD4), network: .signet)
    }

    private func mempoolHasNewTransaction(since before: Set<String>) -> Bool {
        ((try? Set(BitcoinCLI.mempoolTxids()).isSubset(of: before)) ?? true) == false
    }

    /// This run's wallet key expression, as "Add this device's key" and the
    /// shared-savings builder derive it.
    private static func deviceKeyExpression() throws -> String {
        let master = try HDKey(seed: BIP39.seed(mnemonic: mnemonic))
        let account = try BIP86.accountKey(from: master, coinType: 1, account: 0)
        let fingerprint = String(format: "%08x", master.fingerprint)
        return "[\(fingerprint)/86'/1'/0']\(account.neutered.serialized(network: .testnet))/<0;1>/*"
    }

    // MARK: - The sequence

    func test01StorefrontSequence() async throws {
        // 1. Onboarding as a mainnet user sees it: no wallet, no network row.
        let onboarding = launch(run: "store-onboarding", reset: true, network: .mainnet,
                                localNode: false, expectOnboarding: true)
        XCTAssertFalse(onboarding.staticTexts["Network"].exists, "the network row is an Advanced-mode row")
        Screenshots.capture(onboarding, "store-01-onboarding", testCase: self)
        onboarding.terminate()

        // 2. A fresh wallet on the fixture. The mnemonic is on screen here,
        // so nothing is captured until home.
        try await ensurePayer(minimum: 1_000_000)
        var app = launch(reset: true, expectOnboarding: true)
        createWallet(app)

        // 3. Two payments received, one address each, then a third caught
        // while Receive is open.
        var address = try receiveAddress(app)
        try await payAndConfirm(address, sats: 120_000)
        waitForBalance(app, atLeast: 120_000, "first payment")
        address = try receiveAddress(app)
        try await payAndConfirm(address, sats: 80_000)
        waitForBalance(app, atLeast: 200_000, "second payment")

        app.buttons["receiveButton"].tap()
        let addressElement = app.staticTexts["receiveAddress"]
        XCTAssertTrue(addressElement.waitForExistence(timeout: 30), "no receive address")
        address = addressElement.value as? String ?? ""
        XCTAssertTrue(address.hasPrefix("tb1p"), address)
        Screenshots.capture(app, "store-02-receive", testCase: self)
        try BitcoinCLI.sendToAddress(wallet: Self.payerWallet, address: address, sats: 50_000, feeRate: 2)
        let unconfirmed = app.staticTexts["unconfirmedPayment"]
        if unconfirmed.waitForExistence(timeout: 120) {
            Screenshots.capture(app, "store-03-receive-unconfirmed", testCase: self)
        } else {
            XCTFail("the open Receive screen never showed the unconfirmed payment")
        }
        try await SignetMiner.mineOntoTip(payingTo: Self.payoutScript())
        app.buttons["Done"].tap()
        waitForBalance(app, atLeast: 250_000, "third payment")
        XCTAssertGreaterThanOrEqual(app.staticTexts.matching(identifier: "Received").count, 1)
        Screenshots.capture(app, "store-04-home", testCase: self)

        // 4. A send: the form before any address is typed, then the review.
        waitForSynced(app)
        let payee = try BitcoinCLI.newAddress(wallet: Self.payerWallet)
        app.tabBars.buttons["Send"].tap()
        app.typeInto("amountField", "25000")
        Screenshots.capture(app, "store-05-send-form", testCase: self)
        app.typeInto("destinationField", payee)
        app.buttons["reviewButton"].tap()
        let sendButton = app.buttons["sendButton"]
        XCTAssertTrue(scrollUntilExists(app, sendButton, maxSwipes: 5), "no send review")
        if app.staticTexts["locktimeLagWarning"].exists {
            print("storefront: the review carries the mid-sync locktime warning")
        }
        Screenshots.capture(app, "store-06-send-review", testCase: self)
        let mempoolBefore = Set(try BitcoinCLI.mempoolTxids())
        sendButton.tap()
        XCTAssertTrue(poll(timeout: 60, "broadcast status") {
            app.staticTexts["broadcastPending"].exists || app.staticTexts["broadcastConfirmed"].exists
        })
        XCTAssertTrue(poll(timeout: 60, interval: 1, "send relayed into the node's mempool") {
            self.mempoolHasNewTransaction(since: mempoolBefore)
        })
        try await SignetMiner.mineOntoTip(payingTo: Self.payoutScript())
        app.tabBars.buttons["Wallet"].tap()
        XCTAssertTrue(poll(timeout: 300, interval: 5, "the send confirms") {
            if app.staticTexts["Sent"].firstMatch.exists, self.balanceSats(app) < 250_000 { return true }
            self.nudgeSync(app)
            return false
        })
        Screenshots.capture(app, "store-07-home-after-send", testCase: self)

        // 5. People and shared savings. Alice and Bob arrive as cards.
        let aliceKey = try WinnowAppUITests.fixtureCosigner(0xA1)
        let bobKey = try WinnowAppUITests.fixtureCosigner(0xB2)
        for (name, key) in [("Alice", aliceKey), ("Bob", bobKey)] {
            let card = try PersonCard(network: .signet, name: name, payTo: "tr(\(key))", signerKey: key).serialized()
            app.terminate()
            app = launch(clipboard: card)
            app.tabBars.buttons["People"].tap()
            app.buttons["addPersonButton"].tap()
            XCTAssertTrue(app.buttons["personPasteButton"].waitForExistence(timeout: 20))
            app.buttons["personPasteButton"].tap()
            XCTAssertTrue(app.staticTexts["personSignerSummary"].waitForExistence(timeout: 10))
            app.buttons["savePersonButton"].tap()
            XCTAssertTrue(app.buttons["personRow-\(name)"].waitForExistence(timeout: 30), "\(name) was not saved")
        }
        let savingsName = "Savings with Alice, Bob"
        app.buttons["newSharedSavingsButton"].tap()
        XCTAssertTrue(app.buttons["coOwnerToggle-Alice"].waitForExistence(timeout: 20), "no co-owner picker")
        app.buttons["coOwnerToggle-Alice"].tap()
        app.buttons["coOwnerToggle-Bob"].tap()
        XCTAssertTrue(scrollUntilExists(app, app.buttons["createSharedSavingsButton"]))
        app.buttons["createSharedSavingsButton"].tap()
        XCTAssertTrue(app.staticTexts["savingsShareNotice"].waitForExistence(timeout: 60),
                      "creating did not lead to the share step")
        app.buttons["savingsShareDoneButton"].tap()
        XCTAssertTrue(app.staticTexts[savingsName].waitForExistence(timeout: 30), "the savings were not listed")
        Screenshots.capture(app, "store-08-people", testCase: self)

        // Fund the savings from the node and show them holding money.
        app.staticTexts[savingsName].firstMatch.tap()
        let savingsAddressElement = app.staticTexts.matching(
            NSPredicate(format: "label BEGINSWITH 'tb1p'")).firstMatch
        XCTAssertTrue(savingsAddressElement.waitForExistence(timeout: 20), "no receive address on the savings")
        let savingsAddress = savingsAddressElement.label
        let savingsScript = try AddressDecoder.scriptPubKey(for: savingsAddress, network: .signet)
        let fundingHeight = UInt32(try BitcoinCLI.blockCount())
        try await payAndConfirm(savingsAddress, sats: 60_000)
        let savingsBalance = app.staticTexts["savingsBalance"]
        XCTAssertTrue(poll(timeout: 300, interval: 5, "the savings see their coin") {
            if savingsBalance.exists, (Int64(savingsBalance.label.filter(\.isNumber)) ?? 0) >= 60_000 { return true }
            app.tabBars.buttons["Wallet"].tap()
            self.nudgeSync(app)
            app.tabBars.buttons["People"].tap()
            if !savingsBalance.exists { app.staticTexts[savingsName].firstMatch.tap() }
            return false
        })
        Screenshots.capture(app, "store-09-shared-savings", testCase: self)

        // 6. A request from Alice, reviewed but not approved.
        guard let coin = try BitcoinCLI.unspents(scriptHex: savingsScript.hex)
            .filter({ $0.height > fundingHeight }).max(by: { $0.height < $1.height }) else {
            return XCTFail("the savings were not funded")
        }
        let descriptor = try Vault.multiADescriptor(
            threshold: 2, cosigners: [try Self.deviceKeyExpression(), aliceKey, bobKey])
        let vault = try Vault(descriptor: descriptor, network: .signet)
        XCTAssertEqual(try vault.address(index: 0), savingsAddress, "the rebuilt descriptor is not the app's")
        let recordID = String(descriptor.serialized().split(separator: "#").last!)
        let utxo = WalletUTXO(txid: Data(Data(hex: coin.txid)!.reversed()), vout: coin.vout,
                              amount: coin.amount, scriptPubKey: savingsScript,
                              chain: .receive, index: 0, height: coin.height)
        var psbt = try vault.createSpend(
            utxos: [utxo],
            payments: [Payment(amount: 25_000, address: WinnowAppUITests.fixtureReceiveAddress(0xA1, index: 0),
                               network: .signet)],
            changeIndex: 0, feeRateSatPerVByte: 2, chainTip: UInt32(try BitcoinCLI.blockCount()),
            randomness: { 0.5 })
        let alice = try HDKey(seed: Data(repeating: 0xA1, count: 64))
        try vault.partialSign(&psbt, master: alice, knownUTXOs: [utxo],
                              ownedOutputCoordinates: [.init(choice: 1, index: 0)])
        let request = try ApprovalRequest(network: .signet, vault: recordID, name: savingsName,
                                          psbt: psbt).serialized()
        app.terminate()
        app = launch(clipboard: request)
        app.tabBars.buttons["People"].tap()
        XCTAssertTrue(app.staticTexts[savingsName].firstMatch.waitForExistence(timeout: 30))
        app.staticTexts[savingsName].firstMatch.tap()
        let approve = app.buttons["approveRequestButton"]
        XCTAssertTrue(scrollUntilExists(app, approve), "savings detail did not load")
        approve.tap()
        XCTAssertTrue(app.buttons["approvalPasteButton"].waitForExistence(timeout: 20), "no approval sheet")
        app.buttons["approvalPasteButton"].tap()
        let review = app.buttons["reviewApprovalButton"]
        XCTAssertTrue(scrollUntilExists(app, review, maxSwipes: 4), "no Review request button")
        XCTAssertTrue(poll(timeout: 10, interval: 1, "Review request enabled") { review.isEnabled })
        review.tap()
        let progress = app.staticTexts["approvalProgress"]
        XCTAssertTrue(scrollUntilExists(app, progress), "the request was not reviewed")
        XCTAssertTrue(app.staticTexts["Pays Alice"].exists || app.staticTexts.matching(
            NSPredicate(format: "label BEGINSWITH 'Pays Alice'")).firstMatch.exists, "the review does not name Alice")
        _ = scrollUntilExists(app, app.staticTexts["approvalRequestField"], maxSwipes: 3, up: true)
        Screenshots.capture(app, "store-10-approve-request", testCase: self)
    }

    /// Opens Receive, reads the address, closes the sheet.
    private func receiveAddress(_ app: XCUIApplication) throws -> String {
        app.buttons["receiveButton"].tap()
        let element = app.staticTexts["receiveAddress"]
        XCTAssertTrue(element.waitForExistence(timeout: 30), "no receive address")
        let address = element.value as? String ?? ""
        XCTAssertTrue(address.hasPrefix("tb1p"), "unexpected receive address \(address)")
        app.buttons["Done"].tap()
        return address
    }
}
