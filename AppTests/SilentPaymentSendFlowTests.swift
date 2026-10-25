@testable import WinnowApp
import VaultKit
import WalletCore
import TestSupport
import XCTest

/// Paying a BIP352 silent payment code from the everyday wallet, the way the
/// app does it: review, authentication, build, the SEC-018 gate, the
/// broadcaster hand-off and the receipt. The recipient's side is
/// `SilentPaymentTestReceiver`, written from the BIP without the wallet's
/// sender code, so the output the wallet derived is checked independently.
@MainActor
final class SilentPaymentSendFlowTests: XCTestCase {
    private enum FixtureError: Error { case unavailable }

    /// A booted model on signet whose wallet holds one mature coin per entry
    /// of `coins`, with a relay stack that queues (no peer answers).
    private func fundedModel(coins: [Int64], name: String) async throws -> (AppModel, fundings: [Transaction]) {
        let environment = [
            "WINNOW_E2E": "1",
            "WINNOW_E2E_RUN": "\(name)-\(UUID().uuidString)",
            "WINNOW_E2E_ENTROPY": String(repeating: "a1", count: 16),
            "WINNOW_E2E_PEER": "127.0.0.1:1",
            "WINNOW_E2E_CHALLENGE": "51",
        ]
        guard case let .active(mode) = E2EMode.resolve(environment: environment),
              case let .active(cleanup) = E2EMode.resolve(
                environment: environment.merging(["WINNOW_E2E_RESET": "1"]) { _, reset in reset })
        else {
            XCTFail("could not create isolated send fixture")
            throw FixtureError.unavailable
        }
        let model = AppModel(e2e: mode, storeKeys: InMemoryStoreKeyVault(), keyStore: InMemoryKeyStore())
        addTeardownBlock {
            await model.scenePhaseChanged(.background)
            cleanup.wipeIfRequested()
        }
        let directory = try XCTUnwrap(model.storageDirectory())
        let wallet = try Wallet.create(network: .signet, keyStore: model.keyStore,
                                       storageURL: directory.appending(path: "wallet.json"), entropy: mode.entropy)
        var fundings: [Transaction] = []
        for (index, amount) in coins.enumerated() {
            fundings.append(try await fund(wallet, amount: amount, height: 100, index: UInt32(index)))
        }
        try await matureCoinbase(wallet, height: 100)
        await model.boot()
        XCTAssertEqual(model.stage, .ready)
        await model.scenePhaseChanged(.active)
        XCTAssertNotNil(model.stack)
        return (model, fundings)
    }

    /// The prevout script of each input of `transaction`, looked up in the
    /// funding transactions the fixture made.
    private func prevoutScripts(of transaction: Transaction, fundings: [Transaction]) throws -> [Data] {
        try transaction.inputs.map { input in
            let funding = try XCTUnwrap(fundings.first { $0.txid == input.previousOutput.txid })
            return funding.outputs[Int(input.previousOutput.vout)].scriptPubKey
        }
    }

    private func sentEntry(_ model: AppModel, txid: Data) throws -> HistoryEntry {
        try XCTUnwrap(model.status.history.first { $0.txid == txid })
    }

    /// The whole path: an `sp1…`-shaped code is reviewed as a silent payment
    /// with no script, the send derives the script, the gate accepts it, and
    /// the receipt names both the code and the derived address. The derived
    /// script is what the receiver's own scan finds.
    func testPaysASilentPaymentCodeToAnOutputTheReceiverFinds() async throws {
        let (model, fundings) = try await fundedModel(coins: [80_000], name: "sp-send")
        let receiver = try SilentPaymentTestReceiver(network: .signet)

        let preview = try await model.previewSend(destination: " \(receiver.code.uppercased()) ", amount: 20_000,
                                                  priority: .medium, override: 2)
        XCTAssertTrue(preview.payments.isEmpty, "a code has no script at review time")
        XCTAssertEqual(preview.silentPayments.map(\.amount), [20_000])
        XCTAssertEqual(try preview.silentPayments[0].address.encoded, receiver.code)
        XCTAssertEqual(preview.amountSent, 20_000)
        XCTAssertNotNil(preview.changeAmount)

        let txid = try await model.send(preview: preview)
        let entry = try sentEntry(model, txid: txid)
        let transaction = try XCTUnwrap(entry.transaction())
        let expected = try receiver.expectedOutputScripts(
            in: transaction, prevoutScripts: try prevoutScripts(of: transaction, fundings: fundings), count: 1)
        let external = try XCTUnwrap(entry.outputs?.external)
        XCTAssertEqual(external.count, 1)
        XCTAssertEqual(external[0].amount, 20_000)
        XCTAssertEqual(external[0].scriptPubKey, expected[0], "the wallet's output is not the one the receiver derives")
        XCTAssertEqual(external[0].silentPaymentAddress, receiver.code)

        let recipients = model.paymentRecipients(entry)
        XCTAssertEqual(recipients.count, 1)
        XCTAssertEqual(recipients[0].silentPaymentAddress, receiver.code)
        XCTAssertEqual(recipients[0].address,
                       AddressDecoder.address(for: expected[0], network: .signet),
                       "the receipt shows the derived address beside the code")
        XCTAssertNil(recipients[0].person)
    }

    /// Reuse is the point of a code: two payments to it land on two different
    /// on-chain addresses, each found by the receiver from its own inputs.
    func testTheSameCodePaidTwiceLandsOnTwoAddresses() async throws {
        let (model, fundings) = try await fundedModel(coins: [80_000, 80_000], name: "sp-twice")
        let receiver = try SilentPaymentTestReceiver(network: .signet)
        var scripts: [Data] = []
        for _ in 0 ..< 2 {
            let preview = try await model.previewSend(destination: receiver.code, amount: 20_000,
                                                      priority: .medium, override: 2)
            let txid = try await model.send(preview: preview)
            let entry = try sentEntry(model, txid: txid)
            let transaction = try XCTUnwrap(entry.transaction())
            let expected = try receiver.expectedOutputScripts(
                in: transaction, prevoutScripts: try prevoutScripts(of: transaction, fundings: fundings), count: 1)
            let external = try XCTUnwrap(entry.outputs?.external)
            XCTAssertEqual(external.map(\.scriptPubKey), expected)
            scripts += expected
        }
        XCTAssertEqual(Set(scripts).count, 2, "the same code produced the same address twice")
    }

    /// A code for another network is refused where it was typed, naming the
    /// network, and never reaches coin selection.
    func testRefusesACodeForAnotherNetwork() async throws {
        let (model, _) = try await fundedModel(coins: [80_000], name: "sp-network")
        let mainnet = try SilentPaymentTestReceiver(network: .mainnet)
        do {
            _ = try await model.previewSend(destination: mainnet.code, amount: 20_000, priority: .medium, override: 2)
            XCTFail("a mainnet code was reviewed on signet")
        } catch let error as SilentPaymentAddressError {
            XCTAssertEqual(error, .wrongHRP(expected: "tsp", actual: "sp"))
        }
        // The old refusal still holds too: a code is not an address.
        XCTAssertThrowsError(try Payment(amount: 1, address: mainnet.code, network: .signet))
    }

    /// Shared accounts spend through script paths BIP352 excludes, so a code
    /// cannot be paid from one: the refusal says so before any vault lookup.
    func testRefusesASilentPaymentFromASharedAccount() async throws {
        let (model, _) = try await fundedModel(coins: [80_000], name: "sp-vault")
        let receiver = try SilentPaymentTestReceiver(network: .signet)
        do {
            _ = try await model.previewSend(destination: receiver.code, amount: 20_000, priority: .medium,
                                            override: 2, accountID: "any-account")
            XCTFail("a shared account reviewed a silent payment")
        } catch AppModel.AppError.silentPaymentNeedsEverydayWallet {}
    }

    /// A person saved from a pasted code is paid like anyone else, the code is
    /// the review's destination, the counter behind fresh addresses never
    /// moves, and the payment is labelled with their name by code rather than
    /// by a script no one could have watched for.
    func testAPersonSavedFromACodeIsPayableAndLabelled() async throws {
        let (model, fundings) = try await fundedModel(coins: [80_000], name: "sp-person")
        let receiver = try SilentPaymentTestReceiver(network: .signet)
        let imported = try PersonPaste.parse(receiver.code, network: .signet)
        let robin = try await model.addPerson(name: "Robin", payTo: imported.payTo, signerKey: nil)
        XCTAssertEqual(robin.payTo, .silentPayment(receiver.code))

        let preview = try await model.previewSend(to: robin, amount: 20_000, priority: .medium, override: 2)
        XCTAssertEqual(preview.destination, receiver.code)
        XCTAssertEqual(preview.recipient?.name, "Robin")
        XCTAssertNil(preview.recipient?.paymentIndex, "a code has no address index to advance")
        let txid = try await model.send(preview: preview)
        let paid = try XCTUnwrap(model.people.first { $0.id == robin.id })
        XCTAssertEqual(paid.nextPaymentIndex, 0)

        let entry = try sentEntry(model, txid: txid)
        let transaction = try XCTUnwrap(entry.transaction())
        let expected = try receiver.expectedOutputScripts(
            in: transaction, prevoutScripts: try prevoutScripts(of: transaction, fundings: fundings), count: 1)
        let recipients = model.paymentRecipients(entry)
        XCTAssertEqual(recipients.map(\.person?.id), [robin.id])
        XCTAssertEqual(recipients.map(\.address), [AddressDecoder.address(for: expected[0], network: .signet)])
    }
}
