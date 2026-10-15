import Foundation
import TestSupport
import VaultKit
import WalletCore
import XCTest

/// Two shared accounts in the same app session and recording. Core owns the
/// other keys; all phone approvals and broadcasts go through the visible UI.
extension WinnowAppUITests {
    func multisigJourney(in app: XCUIApplication, control: URL) async throws {
        let musigStarted = Date()
        let alice = try CoreSigner(wallet: "ui-alice-\(UUID().uuidString)")
        let bob = try CoreSigner(wallet: "ui-bob-\(UUID().uuidString)")
        app.buttons["advancedModeButton"].tap()
        XCTAssertTrue(app.alerts.buttons["Turn on"].appears(within: 10))
        app.alerts.buttons["Turn on"].tap()
        XCTAssertTrue(app.tabBars.buttons["Wallet"].appears(within: 15))

        let deviceName = "Two signing devices"
        tap(app, "walletExtraDeviceButton")
        app.typeInto("vaultNameField", deviceName)
        app.buttons["addDeviceKeyButton"].tap()
        app.typeInto("cosignerField", alice.publicExpression)
        tap(app, "addPastedKeyButton")
        tap(app, "buildDescriptorButton")
        XCTAssertTrue(scrollUntilExists(app, app.staticTexts["vaultRequiredKeys"]))
        XCTAssertEqual(app.staticTexts["vaultRequiredKeys"].label, "2 of 2 signing keys required")
        let descriptor = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'tr(musig('")).firstMatch
        XCTAssertTrue(scrollUntilExists(app, descriptor))
        let musig = try Vault(descriptor.label, network: .signet)
        tap(app, "saveVaultButton")
        let firstFunding = try await receiveIntoAccount(app, name: deviceName, vault: musig, signers: [alice])
        Screenshots.capture(app, "35-extra-device-policy", testCase: self)
        let firstPayment = try reviewAccountPayment(app, name: deviceName, vault: musig,
                                                   funding: firstFunding, control: control)
        Screenshots.capture(app, "36-extra-device-review", testCase: self)
        tap(app, "sendButton")
        try approveMuSigPayment(app, signer: alice, control: control)
        let firstTxid = try broadcast(app, button: "musigBroadcastButton", marker: "vaultPaymentSent")
        try firstPayment.verifyAccepted(txid: firstTxid)
        Screenshots.capture(app, "39-extra-device-sent", testCase: self)
        try await Self.mineBlock()
        try firstPayment.verifyConfirmed(txid: firstTxid)
        let firstChange = try firstPayment.verifyChange(txid: firstTxid, signers: [alice])
        app.buttons["Done"].tap()
        openAccount(app, name: deviceName)
        expectAccountConfirmation(app, txid: firstTxid, change: firstChange)
        expectAccountBalance(app, 5_000_000 - 1_000_000 - firstPayment.fee)
        Screenshots.capture(app, "40-extra-device-confirmed", testCase: self)
        goToWallet(app)
        print("SIGNET_MUSIG_SECONDS=\(Date().timeIntervalSince(musigStarted))")

        let savingsStarted = Date()
        let savingsName = "Savings with Alice and Bob"
        let savings = try createSavings(app, name: savingsName, signers: [("Alice", alice), ("Bob", bob)], control: control)
        let secondFunding = try await receiveIntoAccount(app, name: savingsName, vault: savings, signers: [alice, bob])
        Screenshots.capture(app, "27-savings-funded", testCase: self)
        let secondPayment = try reviewAccountPayment(app, name: savingsName, vault: savings,
                                                    funding: secondFunding, control: control)
        tap(app, "sendButton")
        try approveSavingsPayment(app, signer: alice, control: control)
        let secondTxid = try broadcast(app, button: "finishApprovalButton", marker: "approvalBroadcast")
        try secondPayment.verifyAccepted(txid: secondTxid)
        Screenshots.capture(app, "15-approval-sent", testCase: self)
        try await Self.mineBlock()
        try secondPayment.verifyConfirmed(txid: secondTxid)
        let secondChange = try secondPayment.verifyChange(txid: secondTxid, signers: [alice, bob])
        app.buttons["Done"].tap()
        openAccount(app, name: savingsName)
        expectAccountConfirmation(app, txid: secondTxid, change: secondChange)
        expectAccountBalance(app, 5_000_000 - 1_000_000 - secondPayment.fee)
        Screenshots.capture(app, "28-savings-confirmed", testCase: self)
        print("SIGNET_2OF3_SECONDS=\(Date().timeIntervalSince(savingsStarted))")
    }

    private func createSavings(_ app: XCUIApplication, name: String,
                               signers: [(String, CoreSigner)], control: URL) throws -> Vault {
        tap(app, "walletSharedSavingsButton")
        for (person, signer) in signers {
            tap(app, "addSavingsCoOwnerButton", up: true)
            let key = signer.publicExpression + "/<0;1>/*"
            try clipboard(PersonCard(network: .signet, name: person, payTo: "tr(\(key))",
                                     signerKey: key).serialized(), at: control)
            XCTAssertTrue(app.buttons["personPasteButton"].appears(within: 20))
            app.buttons["personPasteButton"].tap()
            tap(app, "savePersonButton")
            tap(app, "coOwnerToggle-\(person)")
        }
        app.typeInto("savingsNameField", name)
        tap(app, "createSharedSavingsButton")
        XCTAssertTrue(app.staticTexts["savingsShareNotice"].appears(within: 30))
        let cardText = app.staticTexts.matching(NSPredicate(format: "label CONTAINS 'shared-savings'")).firstMatch
        XCTAssertTrue(scrollUntilExists(app, cardText))
        let (_, vault) = try SharedSavingsCard.decode(cardText.label, network: .signet)
        XCTAssertTrue(vault.isScriptPath)
        XCTAssertEqual(vault.threshold, 2)
        XCTAssertEqual(vault.signerCount, 3)
        Screenshots.capture(app, "26-savings-share", testCase: self)
        app.buttons["savingsShareDoneButton"].tap()
        return vault
    }

    private func receiveIntoAccount(_ app: XCUIApplication, name: String, vault: Vault,
                                    signers: [CoreSigner]) async throws -> (txid: String, vout: UInt32) {
        for signer in signers { try signer.importVault(vault) }
        openAccount(app, name: name)
        let addressText = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'tb1p'")).firstMatch
        XCTAssertTrue(addressText.appears(within: 20))
        let address = addressText.label
        // Compare the actual address shown by the app, not a separate vector.
        let derived = try BitcoinCLI.runJSON(["deriveaddresses", vault.descriptor.serialized(), "[0,0]"])
        let coreReceive = ((derived as? [Any])?.first as? [String])?.first
        XCTAssertEqual(address, coreReceive)
        let txid = try await Self.fundAndConfirm(address)
        expectAccountBalance(app, 5_000_000)
        let output = try XCTUnwrap(BitcoinCLI.unspents(scriptHex: AddressDecoder.scriptPubKey(
            for: address, network: .signet).hex).first { $0.txid == txid })
        XCTAssertEqual(output.amount, 5_000_000)
        // Each independent Core co-owner must have discovered the same coin.
        for signer in signers {
            let coins = try BitcoinCLI.runJSON(["listunspent", "1", "9999999", "[\"\(address)\"]"], wallet: signer.wallet)
            let coin = try XCTUnwrap((coins as? [[String: Any]])?.first { $0["txid"] as? String == txid })
            XCTAssertEqual(try BitcoinCLI.sats(try XCTUnwrap(coin["amount"])), 5_000_000)
        }
        return (txid, output.vout)
    }

    private func reviewAccountPayment(_ app: XCUIApplication, name: String, vault: Vault,
                                      funding: (txid: String, vout: UInt32), control: URL) throws -> JourneyPayment {
        let destination = try BitcoinCLI.newAddress(wallet: "ui-bank")
        try clipboard(destination, at: control)
        tap(app, "sendFromAccountButton")
        XCTAssertTrue(app.buttons["pasteDestinationButton"].appears(within: 20))
        app.buttons["pasteDestinationButton"].tap()
        app.typeInto("amountField", "1000000")
        tap(app, "reviewButton")
        XCTAssertTrue(app.staticTexts["reviewAccount"].appears(within: 30))
        XCTAssertEqual(app.staticTexts["reviewAccount"].label, name)
        XCTAssertEqual(app.staticTexts["reviewDestination"].label, destination)
        let amount = try XCTUnwrap(app.staticTexts["reviewAmount"].value as? String)
        XCTAssertEqual(Int64(amount.filter(\.isNumber)), 1_000_000)
        let fee = try XCTUnwrap(Int64((app.staticTexts["reviewFee"].value as? String ?? "").filter(\.isNumber)))
        XCTAssertTrue(scrollUntilExists(app, app.buttons["sendButton"], fullyVisible: true))
        XCTAssertEqual(app.buttons["sendButton"].label, "Continue to approvals")
        return JourneyPayment(vault: vault, fundingTxid: funding.txid, fundingVout: funding.vout,
                              address: try vault.address(index: 0), destination: destination, fee: fee)
    }

    private func approveMuSigPayment(_ app: XCUIApplication, signer: CoreSigner, control: URL) throws {
        let output = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'cHNidP'")).firstMatch
        XCTAssertTrue(scrollUntilExists(app, output))
        let proposal = try PSBT(base64: output.label)
        let unsigned = try proposal.unsignedTransaction()
        let coreNonce = try signer.process(proposal)
        XCTAssertEqual(coreNonce.inputs[0].musig2PubNonces.count, 1)
        XCTAssertTrue(coreNonce.inputs[0].musig2PartialSigs.isEmpty)
        tap(app, "musigNonceButton", up: true)
        XCTAssertTrue(scrollUntilExists(app, output))
        XCTAssertTrue(poll(timeout: 20, interval: 0.2, "phone nonce") {
            (try? PSBT(base64: output.label).inputs[0].musig2PubNonces.count) == 1
        })
        let both = try PSBT(base64: output.label).combined(with: [coreNonce])
        XCTAssertEqual(both.inputs[0].musig2PubNonces.count, 2)
        try pasteReply(app, text: both.base64V0(), control: control, musig: true)
        tap(app, "musigSignButton")
        XCTAssertTrue(scrollUntilExists(app, output))
        XCTAssertTrue(poll(timeout: 20, interval: 0.2, "phone approval") {
            (try? PSBT(base64: output.label).inputs[0].musig2PartialSigs.count) == 1
        })
        let phoneSigned = try PSBT(base64: output.label)
        XCTAssertEqual(try phoneSigned.unsignedTransaction(), unsigned)
        XCTAssertTrue(scrollUntilExists(app, app.buttons["musigBroadcastButton"], up: true, fullyVisible: true))
        XCTAssertFalse(app.buttons["musigBroadcastButton"].isEnabled, "the phone alone cannot send")
        Screenshots.capture(app, "37-extra-device-waiting", testCase: self)
        let signed = try signer.process(phoneSigned)
        XCTAssertEqual(signed.inputs[0].musig2PartialSigs.count, 2)
        XCTAssertEqual(try signed.unsignedTransaction(), unsigned)
        try pasteReply(app, text: signed.base64V0(), control: control, musig: true)
    }

    private func approveSavingsPayment(_ app: XCUIApplication, signer: CoreSigner, control: URL) throws {
        let output = app.staticTexts.matching(NSPredicate(format: "label CONTAINS '\"winnow\":\"approval\"'")).firstMatch
        tap(app, "approveButton")
        XCTAssertTrue(scrollUntilExists(app, output))
        var phoneSigned: PSBT?
        XCTAssertTrue(poll(timeout: 20, interval: 0.2, "phone savings approval") {
            phoneSigned = try? ApprovalRequest.decode(output.label, network: .signet).decodedPSBT()
            return phoneSigned?.inputs[0].tapScriptSignatures.count == 1
        })
        let proposal = try XCTUnwrap(phoneSigned)
        XCTAssertTrue(scrollUntilExists(app, app.buttons["finishApprovalButton"], up: true, fullyVisible: true))
        XCTAssertFalse(app.buttons["finishApprovalButton"].isEnabled, "one approval is insufficient")
        Screenshots.capture(app, "14-approval-waiting", testCase: self)
        let signed = try signer.process(proposal)
        XCTAssertEqual(signed.inputs[0].tapScriptSignatures.count, 2)
        XCTAssertEqual(try signed.unsignedTransaction(), try proposal.unsignedTransaction())
        try pasteReply(app, text: signed.base64V0(), control: control, musig: false)
        XCTAssertTrue(scrollUntilExists(app, app.staticTexts["approvalProgress"]))
        XCTAssertTrue(app.staticTexts["approvalProgress"].label.contains("2 of 2"))
    }

    private func pasteReply(_ app: XCUIApplication, text: String, control: URL, musig: Bool) throws {
        try clipboard(text, at: control)
        tap(app, musig ? "psbtPasteButton" : "approvalPasteButton", up: true)
        tap(app, musig ? "addPSBTButton" : "reviewApprovalButton")
    }

    private func broadcast(_ app: XCUIApplication, button: String, marker: String) throws -> String {
        let before = Set(try BitcoinCLI.mempoolTxids())
        tap(app, button)
        XCTAssertTrue(app.staticTexts[marker].appears(within: 30))
        var txid: String?
        XCTAssertTrue(poll(timeout: 30, interval: 0.2, "Core accepts the joint payment") {
            txid = (try? Set(BitcoinCLI.mempoolTxids()))?.subtracting(before).first
            return txid != nil
        })
        return try XCTUnwrap(txid)
    }

    private func clipboard(_ text: String, at url: URL) throws {
        try JSONEncoder().encode(["clipboard": text]).write(to: url, options: .atomic)
    }

    private func expectAccountBalance(_ app: XCUIApplication, _ amount: Int64) {
        let balance = app.staticTexts["accountBalance"]
        XCTAssertTrue(scrollUntilExists(app, balance, up: true, fullyVisible: true))
        XCTAssertTrue(poll(timeout: 60, interval: 0.5, "shared account balance \(amount)") {
            Int64(balance.label.filter(\.isNumber)) == amount
        })
    }

    private func expectAccountConfirmation(_ app: XCUIApplication, txid: String,
                                           change: (vout: Int, height: Int)) {
        tap(app, "Technical details")
        // Account details abbreviate the txid; Core verified its full value and
        // output index. Balance alone includes pending change before any block.
        let outputPrefix = "\(txid.prefix(16))…:\(change.vout) · "
        let output = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", outputPrefix)).firstMatch
        XCTAssertTrue(scrollUntilExists(app, output))
        XCTAssertTrue(poll(timeout: 60, interval: 0.5, "app confirms shared change \(txid):\(change.vout)") {
            output.label == "\(outputPrefix)block \(change.height)"
        })
        tap(app, "Technical details", up: true)
    }

    private func goToWallet(_ app: XCUIApplication) {
        app.tabBars.buttons["Wallet"].tap()
        let back = app.navigationBars.buttons["Winnow"]
        if back.exists { back.tap() }
    }

    private func openAccount(_ app: XCUIApplication, name: String) {
        goToWallet(app)
        tap(app, "walletSavings-\(name)", up: true)
    }

    private func tap(_ app: XCUIApplication, _ identifier: String, up: Bool = false) {
        let button = app.buttons[identifier]
        XCTAssertTrue(scrollUntilExists(app, button, maxSwipes: 8, up: up, fullyVisible: true), identifier)
        // A lazy row can be replaced after scrolling while still reporting
        // enabled. Wait for usable geometry within the same readiness deadline;
        // tapVisibleCenter sends no event until it has a finite onscreen target.
        XCTAssertTrue(poll(timeout: 15, interval: 0.2, "\(identifier) enabled with an onscreen tap target") {
            button.exists && button.isEnabled && tapVisibleCenter(app, button)
        })
    }
}
