@testable import WinnowApp
import WalletCore
import XCTest

@MainActor
final class HistoryDisplayTests: XCTestCase {
    private func entry(_ id: UInt8, height: UInt32 = 0, replacedBy: UInt8? = nil) -> HistoryEntry {
        HistoryEntry(txid: Data(repeating: id, count: 32), height: height,
                     received: 0, spent: 1,
                     replacedBy: replacedBy.map { Data(repeating: $0, count: 32) })
    }

    func testReplacementStaysBesideItsOriginalBeforeAndAfterConfirmation() {
        let receipts = (1 ... 100).map { entry(UInt8($0), height: UInt32($0)) }
        let original = entry(101, replacedBy: 103)
        let otherPending = entry(102)
        let replacement = entry(103)
        let history = receipts + [original, otherPending, replacement]

        XCTAssertEqual(Array(AppModel.historyForDisplay(history).prefix(3)).map(\.txid),
                       [replacement.txid, original.txid, otherPending.txid],
                       "the replaced payment must not be buried below old receipts")

        var confirmed = history
        confirmed[confirmed.count - 1].height = 110
        confirmed.append(entry(104, height: 111))
        XCTAssertEqual(Array(AppModel.historyForDisplay(confirmed).prefix(5)).map(\.txid),
                       [otherPending.txid, entry(104).txid, replacement.txid, original.txid, entry(100).txid],
                       "the whole replacement group must move below newer confirmed payments")
    }

    func testRepeatedBumpsFollowTheirFinalPaymentRegardlessOfImportOrder() {
        let original = entry(1, replacedBy: 2)
        let middle = entry(2, replacedBy: 3)
        let final = entry(3, height: 110)
        let recent = entry(4, height: 111)
        XCTAssertEqual(AppModel.historyForDisplay([middle, recent, original, final]).map(\.txid),
                       [recent.txid, final.txid, middle.txid, original.txid])
    }

    func testIncompleteOrCyclicReplacementLinksDoNotHideHistory() {
        let history = [entry(1, replacedBy: 2), entry(2, replacedBy: 1),
                       entry(3, replacedBy: 9), entry(4, height: 100)]
        let displayed = AppModel.historyForDisplay(history)
        XCTAssertEqual(Set(displayed.map(\.txid)), Set(history.map(\.txid)))
        XCTAssertEqual(displayed.first?.txid, entry(4).txid)
    }
    func testRecipientActionsUseActualExternalOutputs() throws {
        let addresses = [
            "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
        ]
        let scripts = try addresses.map { try AddressDecoder.scriptPubKey(for: $0, network: .mainnet) }
        let alice = PersonRecord(id: "alice", name: "Alice", payTo: .address(addresses[0]))
        let transaction = Transaction(version: 2, inputs: [Transaction.Input(
            previousOutput: Transaction.Outpoint(txid: Data(repeating: 1, count: 32), vout: 0), scriptSig: Data(), sequence: 0xffff_fffd)],
            outputs: scripts.map { Transaction.Output(value: 1_000, scriptPubKey: $0) }, locktime: 0)
        var receipt = HistoryEntry(txid: transaction.txid, height: 10, received: 1_000, spent: 2_100,
                                   rawTransaction: transaction.serialized(includeWitness: false))
        let recipients = AppModel.paymentRecipients(receipt, owned: [scripts[1]],
                                                    people: [scripts[0]: alice], network: .mainnet)
        XCTAssertEqual(recipients.map(\.address), [addresses[0]])
        XCTAssertEqual(recipients.first?.person?.name, "Alice")
        XCTAssertEqual(AppModel.paymentRecipients(receipt, owned: [], people: [:], network: .mainnet).count, 2)
        receipt.spent = 0
        XCTAssertTrue(AppModel.paymentRecipients(receipt, owned: [], people: [:], network: .mainnet).isEmpty,
                      "incoming outputs do not identify a sender")
    }

}
