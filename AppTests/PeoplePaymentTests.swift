@testable import WinnowApp
import WalletCore
import TestSupport
import XCTest

/// How people reach the send review: the address a payment to them derives,
/// when the counter behind it moves, and what unsaving a recipient keeps.
@MainActor
final class PeoplePaymentTests: XCTestCase {
    func testAReviewIsInvalidatedByTheRecipientOrTheirAddressIndex() {
        let base = SendReviewInputs(destination: "", amountText: "1000", priority: .medium,
                                    overrideText: "", network: .signet, personID: "alice", paymentIndex: 3)
        XCTAssertNotEqual(base, SendReviewInputs(destination: "", amountText: "1000", priority: .medium,
                                                 overrideText: "", network: .signet, personID: "bob", paymentIndex: 3))
        XCTAssertNotEqual(base, SendReviewInputs(destination: "", amountText: "1000", priority: .medium,
                                                 overrideText: "", network: .signet, personID: "alice", paymentIndex: 4))
        XCTAssertEqual(SendReviewInputs(destination: "tb1p", amountText: "1", priority: .low,
                                        overrideText: "", network: .signet).personID, nil)
    }

    /// Paying a person peeks their next address and never moves the counter
    /// on its own; the card's scripts are watched up to the gap limit.
    func testPayingAPersonPeeksTheNextAddressAndAdvancesOnlyWhenTold() async throws {
        let model = makeModel(network: .signet)
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("people-payment-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        await model.peopleStore.configure(storageURL: directory.appendingPathComponent("people.json"), network: .signet)

        let key = try TestKeys.keyExpression(master: TestKeys.master(entropyByte: 0xB2))
        let carol = try await model.addPerson(
            name: "Carol", payTo: try PersonPayTo.descriptor("tr(\(key))", network: .signet))
        let (address, index) = try model.nextPaymentAddress(for: carol)
        XCTAssertEqual(index, 0)
        XCTAssertTrue(address.hasPrefix("tb1p"))
        XCTAssertEqual(try model.nextPaymentAddress(for: carol).address, address)
        await model.advancePersonPaymentIndex(id: carol.id, past: 0)
        XCTAssertEqual(model.people.first { $0.id == carol.id }?.nextPaymentIndex, 1)
        XCTAssertNotEqual(try model.nextPaymentAddress(for: model.people.first { $0.id == carol.id }!).address, address)
        XCTAssertEqual(model.personScripts().values.filter { $0 == "Carol" }.count, Int(1 + Wallet.gapLimit))

        // A label-only person cannot be paid until a destination is attached.
        let nameOnly = try await model.addPerson(name: "Dan", payTo: nil)
        XCTAssertThrowsError(try model.nextPaymentAddress(for: nameOnly)) { error in
            guard case AppModel.AppError.personCannotBePaid = error else {
                return XCTFail("unexpected error \(error)")
            }
        }
    }

    /// The counter behind a person's fresh addresses moves when an ordinary
    /// wallet payment commits, not at review: the next payment to them then
    /// derives a different address.
    func testAnOrdinarySendAdvancesTheCardIndex() async throws {
        let environment = [
            "WINNOW_E2E": "1",
            "WINNOW_E2E_RUN": "card-index-\(UUID().uuidString)",
            "WINNOW_E2E_ENTROPY": String(repeating: "a1", count: 16),
            "WINNOW_E2E_PEER": "127.0.0.1:1",
            "WINNOW_E2E_CHALLENGE": "51",
        ]
        guard case let .active(mode) = E2EMode.resolve(environment: environment),
              case let .active(cleanup) = E2EMode.resolve(
                environment: environment.merging(["WINNOW_E2E_RESET": "1"]) { _, reset in reset })
        else { return XCTFail("could not create isolated send fixture") }
        let model = AppModel(e2e: mode, storeKeys: InMemoryStoreKeyVault(), keyStore: InMemoryKeyStore())
        addTeardownBlock {
            await model.scenePhaseChanged(.background)
            cleanup.wipeIfRequested()
        }
        let directory = try XCTUnwrap(model.storageDirectory())
        let wallet = try Wallet.create(network: .signet, keyStore: model.keyStore,
                                       storageURL: directory.appending(path: "wallet.json"), entropy: mode.entropy)
        try await fund(wallet, amount: 80_000, height: 100)
        try await matureCoinbase(wallet, height: 100)
        await model.boot()
        XCTAssertEqual(model.stage, .ready)
        // A send hands its transaction to the stack's broadcaster; no peer
        // answers here, which only queues the relay.
        await model.scenePhaseChanged(.active)
        XCTAssertNotNil(model.stack)

        let key = try TestKeys.keyExpression(master: TestKeys.master(entropyByte: 0xD4))
        let alex = try await model.addPerson(name: "Alex", payTo: PersonPayTo.descriptor("tr(\(key))", network: .signet))
        let first = try model.nextPaymentAddress(for: alex)
        XCTAssertEqual(first.index, 0)
        let preview = try await model.previewSend(to: alex, amount: 20_000, priority: .medium, override: 2)
        XCTAssertEqual(preview.destination, first.address)
        XCTAssertEqual(model.people.first?.nextPaymentIndex, 0, "review alone reserved the address")
        _ = try await model.send(preview: preview)
        let paid = try XCTUnwrap(model.people.first { $0.id == alex.id })
        XCTAssertEqual(paid.nextPaymentIndex, 1, "the committed payment did not advance the card")
        XCTAssertNotEqual(try model.nextPaymentAddress(for: paid).address, first.address)
    }

    /// Unsaving a recipient takes them off the send screen's shortcut list
    /// and nothing more: a payment already made to them keeps its name.
    func testUnsavingARecipientHidesTheShortcutButKeepsTheLabel() async throws {
        let model = makeModel(network: .signet)
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("people-unsave-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        await model.peopleStore.configure(storageURL: directory.appendingPathComponent("people.json"), network: .signet)
        let key = try TestKeys.keyExpression(master: TestKeys.master(entropyByte: 0xD4))
        let alex = try await model.addPerson(name: "Alex", payTo: PersonPayTo.descriptor("tr(\(key))", network: .signet))
        let (address, _) = try model.nextPaymentAddress(for: alex)
        let script = try AddressDecoder.scriptPubKey(for: address, network: .signet)
        let transaction = Transaction(version: 2, inputs: [Transaction.Input(
            previousOutput: Transaction.Outpoint(txid: Data(repeating: 1, count: 32), vout: 0),
            scriptSig: Data(), sequence: 0xffff_fffd)],
            outputs: [Transaction.Output(value: 20_000, scriptPubKey: script)], locktime: 0)
        let payment = HistoryEntry(txid: transaction.txid, height: 10, received: 0, spent: 21_000,
                                   rawTransaction: transaction.serialized(includeWitness: false))
        XCTAssertEqual(model.savedRecipients.map(\.name), ["Alex"])
        XCTAssertEqual(model.paymentRecipients(payment).first?.person?.name, "Alex")

        try await model.updateRecipient(id: alex.id, saved: false)
        XCTAssertTrue(model.savedRecipients.isEmpty, "an unsaved recipient kept a shortcut")
        XCTAssertEqual(model.people.first?.savedRecipient, false, "the picker's own predicate still lists them")
        XCTAssertEqual(model.people.map(\.name), ["Alex"], "unsaving must not delete the person")
        XCTAssertEqual(model.paymentRecipients(payment).first?.person?.name, "Alex", "the payment lost its label")
        XCTAssertEqual(model.personScripts()[script], "Alex")
    }
}
