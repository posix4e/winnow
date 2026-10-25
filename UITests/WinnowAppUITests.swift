import Foundation
import TestSupport
import WalletCore
import XCTest

/// One real wallet round trip on a disposable signet: the app creates its
/// wallet, discovers a node-funded payment, signs and relays a payment, and
/// notices its confirmation; then a 2-of-3 script-path multisig account with
/// two Bitcoin Core wallets as the other signers receives and spends, and
/// spends its change again on the recovery path (`MultisigJourney`).
/// Screenshots come from that same successful flow.
/// Detailed wallet rules live in AppTests and WalletCore tests.
@MainActor
final class WinnowAppUITests: XCTestCase {
    nonisolated private static let bank = SignetFixture.bank
    nonisolated private static let fundingAmount: Int64 = 5_000_000
    nonisolated private static let paymentAmount: Int64 = 1_000_000

    func test01CreateReceiveSendConfirm() async throws {
        continueAfterFailure = false
        executionTimeAllowance = 600 // the host prepares the fixture before this UI journey
        let setupStarted = Date()
        try SignetFixture.requirePreparedBank()
        print("SIGNET_SETUP_SECONDS=\(Date().timeIntervalSince(setupStarted))")

        let destination = try BitcoinCLI.newAddress(wallet: Self.bank)
        let destinationScript = try AddressDecoder.scriptPubKey(for: destination, network: .signet)
        let control = FileManager.default.temporaryDirectory.appending(path: "winnow-smoke-\(UUID().uuidString).json")
        try JSONEncoder().encode(["clipboard": destination]).write(to: control, options: .atomic)
        defer { try? FileManager.default.removeItem(at: control) }

        let journeyStarted = Date()
        defer { print("SIGNET_JOURNEY_SECONDS=\(Date().timeIntervalSince(journeyStarted))") }
        let app = XCUIApplication()
        app.launchEnvironment = [
            "WINNOW_E2E": "1",
            "WINNOW_E2E_RUN": "smoke",
            "WINNOW_E2E_RESET": "1",
            // A fresh pinned seed avoids rediscovering an earlier run's coins
            // when the same prepared node is reused.
            "WINNOW_E2E_ENTROPY": UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(),
            "WINNOW_E2E_CONTROL_FILE": control.path,
            "WINNOW_E2E_PEER": "\(BitcoinCLI.nodeHost):\(BitcoinCLI.p2pPort)",
            "WINNOW_E2E_CHALLENGE": BitcoinCLI.challengeHex,
            "WINNOW_E2E_PEER_COUNT": "1",
            "WINNOW_E2E_SYNC_INTERVAL": "3",
        ]
        app.launch()
        defer { app.terminate() }
        XCTAssertTrue(app.buttons["createWalletButton"].appears(within: 60))
        Screenshots.capture(app, "01-onboarding", testCase: self)
        let create = app.buttons["createWalletButton"]
        XCTAssertTrue(create.isEnabled)
        XCTAssertTrue(tapVisibleCenter(app, create), "create wallet has no finite onscreen tap target")
        XCTAssertTrue(app.buttons["receiveButton"].appears(within: 60), "creation should open the wallet without a backup checklist")
        XCTAssertTrue(app.staticTexts["balanceText"].appears(within: 60))

        app.buttons["receiveButton"].tap()
        XCTAssertTrue(app.buttons["skipReceiveAddressLabelButton"].appears(within: 20))
        app.buttons["skipReceiveAddressLabelButton"].tap()
        let addressElement = app.staticTexts["receiveAddress"]
        XCTAssertTrue(addressElement.appears(within: 20))
        let address = try XCTUnwrap(addressElement.value as? String, "no address displayed by Receive")
        _ = try AddressDecoder.scriptPubKey(for: address, network: .signet)
        Screenshots.capture(app, "03-receive", testCase: self)
        app.buttons["Done"].tap()

        let funding = try await Self.fundAndConfirm(address)
        guard poll(timeout: 90, interval: 1, "wallet discovers the confirmed payment", condition: {
            Int64(self.balanceText(app).filter(\.isNumber)) == Self.fundingAmount
        }) else { return }
        let received = app.buttons["historyPayment-\(funding)"]
        XCTAssertTrue(received.appears(within: 20), "the funded transaction is missing from history")
        XCTAssertTrue(received.label.contains("Received"))
        XCTAssertTrue(poll(timeout: 30, interval: 0.2, "funded wallet is up to date") {
            app.staticTexts["syncSummaryText"].label == "Up to date"
        })
        Screenshots.capture(app, "56-home-beginner", testCase: self)

        app.buttons["openSendButton"].tap()
        XCTAssertTrue(app.buttons["pasteDestinationButton"].appears(within: 20))
        app.buttons["pasteDestinationButton"].tap()
        app.typeInto("amountField", String(Self.paymentAmount))
        app.buttons["reviewButton"].tap()
        let send = app.buttons["sendButton"]
        XCTAssertTrue(send.appears(within: 30), "the payment review did not open")
        XCTAssertEqual(app.staticTexts["reviewDestination"].label, destination)
        let amount = try XCTUnwrap(app.staticTexts["reviewAmount"].value as? String)
        XCTAssertEqual(Int64(amount.filter(\.isNumber)), Self.paymentAmount)
        let feeText = try XCTUnwrap(app.staticTexts["reviewFee"].value as? String)
        let fee = try XCTUnwrap(Int64(feeText.filter(\.isNumber)))
        Screenshots.capture(app, "06-send-review", testCase: self)

        let before = Set(try BitcoinCLI.mempoolTxids())
        send.tap()
        var payment: String?
        XCTAssertTrue(poll(timeout: 60, interval: 1, "the node receives the signed payment") {
            payment = (try? Set(BitcoinCLI.mempoolTxids()))?.subtracting(before).first
            return payment != nil
        })
        let txid = try XCTUnwrap(payment)
        let transaction = try BitcoinCLI.runObject(["getrawtransaction", txid, "true"])
        let outputs = try XCTUnwrap(transaction["vout"] as? [[String: Any]])
        let paid = try XCTUnwrap(outputs.first {
            ($0["scriptPubKey"] as? [String: Any])?["hex"] as? String == destinationScript.hex
        }, "the transaction accepted by Core does not pay the reviewed destination")
        XCTAssertEqual(try BitcoinCLI.sats(try XCTUnwrap(paid["value"])), Self.paymentAmount)
        try await Self.mineBlock()

        // The receipt remains open: the app's own scan must update it.
        XCTAssertTrue(app.staticTexts["broadcastConfirmed"].appears(within: 90),
                      "the open receipt did not notice the confirmation")
        let confirmed = try BitcoinCLI.runObject(["getrawtransaction", txid, "true"])
        XCTAssertGreaterThan(try BitcoinCLI.int(confirmed, "confirmations"), 0)
        Screenshots.capture(app, "08-send-confirmed", testCase: self)
        app.buttons["closeSendButton"].tap()
        XCTAssertTrue(poll(timeout: 30, interval: 1, "confirmed wallet balance") {
            Int64(self.balanceText(app).filter(\.isNumber)) == Self.fundingAmount - Self.paymentAmount - fee
        })
        let sent = app.buttons["historyPayment-\(txid)"]
        XCTAssertTrue(sent.appears(within: 20), "the confirmed payment is missing from history")
        XCTAssertTrue(sent.label.contains("Sent"))
        Screenshots.capture(app, "09-home-after-send", testCase: self)
        print("SIGNET_ORDINARY_SECONDS=\(Date().timeIntervalSince(journeyStarted))")
        try await silentPaymentJourney(in: app, control: control)
        print("SIGNET_SILENT_SECONDS=\(Date().timeIntervalSince(journeyStarted))")
        try await multisigJourney(in: app, control: control)
    }

    /// Pays a BIP352 silent payment code from the everyday wallet's change.
    /// Core on the fixture has no BIP352 support, so the test owns the
    /// receiver: it derives the one address the code's holder would scan for
    /// from the mined transaction, requires that to be what the app paid, then
    /// has Core watch that address and confirm the coin.
    private func silentPaymentJourney(in app: XCUIApplication, control: URL) async throws {
        let receiver = try SilentPaymentTestReceiver(network: .signet)
        try JSONEncoder().encode(["clipboard": receiver.code]).write(to: control, options: .atomic)

        app.buttons["openSendButton"].tap()
        XCTAssertTrue(app.buttons["pasteDestinationButton"].appears(within: 20))
        app.buttons["pasteDestinationButton"].tap()
        app.typeInto("amountField", String(Self.silentPaymentAmount))
        app.buttons["reviewButton"].tap()
        let send = app.buttons["sendButton"]
        XCTAssertTrue(send.appears(within: 30), "the silent payment review did not open")
        XCTAssertEqual(app.staticTexts["reviewDestination"].label, receiver.code)
        XCTAssertTrue(app.staticTexts["silentPaymentNote"].exists, "the review does not say the address is derived")
        let amount = try XCTUnwrap(app.staticTexts["reviewAmount"].value as? String)
        XCTAssertEqual(Int64(amount.filter(\.isNumber)), Self.silentPaymentAmount)

        let before = Set(try BitcoinCLI.mempoolTxids())
        send.tap()
        var payment: String?
        XCTAssertTrue(poll(timeout: 60, interval: 1, "the node receives the silent payment") {
            payment = (try? Set(BitcoinCLI.mempoolTxids()))?.subtracting(before).first
            return payment != nil
        })
        let txid = try XCTUnwrap(payment)
        let transaction = try BitcoinCLI.runObject(["getrawtransaction", txid, "true"])
        let decoded = try Transaction.decode(XCTUnwrap(Data(hex: BitcoinCLI.string(transaction, "hex"))))
        let prevoutScripts = try decoded.inputs.map { input -> Data in
            let funding = try BitcoinCLI.runObject(["getrawtransaction", input.previousOutput.txid.displayHex, "true"])
            let outputs = try XCTUnwrap(funding["vout"] as? [[String: Any]])
            let script = try XCTUnwrap(outputs[Int(input.previousOutput.vout)]["scriptPubKey"] as? [String: Any])
            return try XCTUnwrap(Data(hex: BitcoinCLI.string(script, "hex")))
        }
        let expected = try receiver.expectedOutputScripts(in: decoded, prevoutScripts: prevoutScripts, count: 1)[0]
        let paid = try XCTUnwrap(decoded.outputs.first { $0.scriptPubKey == expected },
                                 "the transaction Core accepted pays no output the code's holder would find")
        XCTAssertEqual(paid.value, Self.silentPaymentAmount)
        let derivedAddress = try XCTUnwrap(AddressDecoder.address(for: expected, network: .signet))

        // The receipt shows the derived address under the code.
        XCTAssertTrue(app.staticTexts["derivedOutputAddress"].appears(within: 20),
                      "the receipt does not show where the code was paid on chain")
        XCTAssertEqual(app.staticTexts["derivedOutputAddress"].label, derivedAddress)

        // Core, told only the derived key, sees the coin once it is mined. A
        // watch-only wallet: a key-less descriptor cannot be imported into one
        // that holds private keys.
        if try !BitcoinCLI.run(["listwallets"]).contains("\"\(Self.silentWatchWallet)\""),
           (try? BitcoinCLI.run(["loadwallet", Self.silentWatchWallet])) == nil {
            _ = try BitcoinCLI.run(["-named", "createwallet", "wallet_name=\(Self.silentWatchWallet)",
                                    "disable_private_keys=true", "descriptors=true"])
        }
        let descriptor = try BitcoinCLI.runJSON(["getdescriptorinfo", "rawtr(\(expected.dropFirst(2).hex))"])
        let checksummed = try BitcoinCLI.string(XCTUnwrap(descriptor as? [String: Any]), "descriptor")
        let request = "[{\"desc\":\"\(checksummed)\",\"timestamp\":\"now\",\"label\":\"silent\"}]"
        _ = try BitcoinCLI.run(["importdescriptors", request], wallet: Self.silentWatchWallet)
        try await Self.mineBlock()
        XCTAssertTrue(app.staticTexts["broadcastConfirmed"].appears(within: 90),
                      "the open receipt did not notice the silent payment confirming")
        let coins = try XCTUnwrap(BitcoinCLI.runJSON(["listunspent", "1", "9999999"],
                                                     wallet: Self.silentWatchWallet) as? [[String: Any]])
        let found = coins.filter { $0["txid"] as? String == txid }
        XCTAssertEqual(found.count, 1, "Core's watch wallet did not find the silent payment output")
        XCTAssertEqual(try BitcoinCLI.string(XCTUnwrap(found.first), "address"), derivedAddress)
        XCTAssertEqual(try BitcoinCLI.sats(XCTUnwrap(found.first?["amount"])), Self.silentPaymentAmount)
        app.buttons["closeSendButton"].tap()
        let sent = app.buttons["historyPayment-\(txid)"]
        XCTAssertTrue(sent.appears(within: 20), "the silent payment is missing from history")
        XCTAssertTrue(sent.label.contains("Sent"))
    }

    static let silentPaymentAmount: Int64 = 150_000
    static let silentWatchWallet = "ui-silent-watch"

    nonisolated static func fundAndConfirm(_ address: String) async throws -> String {
        try await Task.detached(priority: .userInitiated) {
            let txid = try BitcoinCLI.sendToAddress(wallet: bank, address: address, sats: fundingAmount, feeRate: 2)
            try await mineBlock()
            return txid
        }.value
    }

    nonisolated static func mineBlock() async throws {
        try await Task.detached(priority: .userInitiated) {
            let payout = try AddressDecoder.scriptPubKey(for: BitcoinCLI.newAddress(wallet: bank), network: .signet)
            try await SignetMiner.mineOntoTip(payingTo: payout)
        }.value
    }
}
