@testable import WinnowApp
import BitcoinP2P
import WalletCore
import XCTest

/// `SendPreview.authorizes` is the last gate between a reviewed payment and a
/// broadcast one (epic #100, invariant S2).
///
/// `AppModel.send` does not broadcast the transaction the review was computed
/// from. It re-runs `buildSend` and then asks the preview whether the freshly
/// built transaction is the one the user authorized. Every divergence between
/// what was shown and what was signed has to be caught here, because after
/// this guard the transaction goes to the network.
///
/// These tests mutate one authorization-relevant field at a time and require a
/// refusal for each.
final class SendPreviewAuthorizationTests: XCTestCase {
    private let recipientScript = Data([0x51, 0x20] + repeatElement(0xAA, count: 32))
    private let attackerScript = Data([0x51, 0x20] + repeatElement(0xEE, count: 32))
    private let changeScript = Data([0x51, 0x20] + repeatElement(0xBB, count: 32))
    private let txidA = Data(repeating: 0x11, count: 32)
    private let txidB = Data(repeating: 0x22, count: 32)

    private let paymentAmount: Int64 = 50_000
    private let changeValue: Int64 = 40_000
    private let feeValue: Int64 = 10_000

    private var outpoints: [AppModel.SendPreview.ReviewedOutpoint] {
        [.init(txid: txidA, vout: 0), .init(txid: txidB, vout: 1)]
    }

    /// The reviewed payment exactly as the user saw it.
    private func makePreview() -> AppModel.SendPreview {
        AppModel.SendPreview(
            destination: "tb1p-recipient",
            payments: [Payment(amount: paymentAmount, scriptPubKey: recipientScript)],
            silentPayments: [],
            feeRateSatPerVByte: 2,
            fee: feeValue,
            changeAmount: changeValue,
            inputCount: 2,
            selectedOutpoints: outpoints,
            change: Payment(amount: changeValue, scriptPubKey: changeScript)
        )
    }

    /// A built transaction matching the review, unless a caller overrides part
    /// of it to model a divergence.
    private func makeBuilt(outputs: [Transaction.Output]? = nil,
                           inputs: [AppModel.SendPreview.ReviewedOutpoint]? = nil,
                           fee: Int64? = nil,
                           changeAmount: Int64?? = nil) throws -> BuiltTransaction {
        let usedInputs = inputs ?? outpoints
        let transaction = Transaction(
            version: 2,
            inputs: usedInputs.map {
                Transaction.Input(previousOutput: .init(txid: $0.txid, vout: $0.vout),
                                  scriptSig: Data(), sequence: 0xFFFF_FFFD)
            },
            outputs: outputs ?? [
                Transaction.Output(value: paymentAmount, scriptPubKey: recipientScript),
                Transaction.Output(value: changeValue, scriptPubKey: changeScript),
            ],
            locktime: 0)
        let psbt = try PSBT(
            unsignedTx: transaction,
            inputs: transaction.inputs.map { _ in
                PSBT.InputInfo(spentOutput: .init(amount: 50_000, scriptPubKey: recipientScript))
            },
            outputs: transaction.outputs.map { _ in PSBT.OutputInfo() })
        return BuiltTransaction(psbt: psbt, transaction: transaction,
                                fee: fee ?? feeValue,
                                changeAmount: changeAmount ?? self.changeValue)
    }

    /// Positive control. Without this, every refusal below could be explained
    /// by the guard simply rejecting everything.
    func testAuthorizesTheTransactionItReviewed() throws {
        XCTAssertTrue(makePreview().authorizes(try makeBuilt()))
    }

    /// The whole point of a payment: the money must go where the review said.
    /// A build that pays a different script for the same amount, with the same
    /// fee, change and inputs, must not be authorized.
    func testRefusesADifferentRecipientScript() throws {
        let redirected = try makeBuilt(outputs: [
            Transaction.Output(value: paymentAmount, scriptPubKey: attackerScript),
            Transaction.Output(value: changeValue, scriptPubKey: changeScript),
        ])
        XCTAssertFalse(makePreview().authorizes(redirected),
                       "a transaction paying a different script than the one reviewed must be refused")
    }

    /// The reviewed amount must reach the reviewed recipient. Paying the right
    /// script less than was shown is equally a divergence.
    func testRefusesAReducedPaymentToTheRightRecipient() throws {
        let shortPaid = try makeBuilt(outputs: [
            Transaction.Output(value: 1, scriptPubKey: recipientScript),
            Transaction.Output(value: changeValue, scriptPubKey: changeScript),
        ])
        XCTAssertFalse(makePreview().authorizes(shortPaid),
                       "a transaction paying less than the reviewed amount must be refused")
    }

    /// Dropping the recipient output entirely while keeping fee, change and
    /// inputs intact must not authorize.
    func testRefusesAMissingRecipientOutput() throws {
        let noPayment = try makeBuilt(outputs: [
            Transaction.Output(value: changeValue, scriptPubKey: changeScript),
        ])
        XCTAssertFalse(makePreview().authorizes(noPayment),
                       "a transaction with no output to the reviewed recipient must be refused")
    }

    // MARK: - Fields the guard already covered

    func testRefusesADifferentFee() throws {
        XCTAssertFalse(makePreview().authorizes(try makeBuilt(fee: feeValue + 1)))
    }

    func testRefusesADifferentChangeAmount() throws {
        XCTAssertFalse(makePreview().authorizes(try makeBuilt(changeAmount: changeValue + 1)))
    }

    func testRefusesASubstitutedInput() throws {
        let swapped = try makeBuilt(inputs: [
            .init(txid: txidA, vout: 0),
            .init(txid: Data(repeating: 0x33, count: 32), vout: 1),
        ])
        XCTAssertFalse(makePreview().authorizes(swapped))
    }

    func testRefusesAnExtraInput() throws {
        let extra = try makeBuilt(inputs: outpoints + [.init(txid: txidB, vout: 7)])
        XCTAssertFalse(makePreview().authorizes(extra))
    }

    /// Input order is part of the authorization: the same coins in a different
    /// order produce a different transaction and a different txid.
    func testRefusesReorderedInputs() throws {
        XCTAssertFalse(makePreview().authorizes(try makeBuilt(inputs: outpoints.reversed())))
    }

    /// A build that redirects the change to a script the wallet does not own
    /// must be refused even though the amount is unchanged.
    func testRefusesRedirectedChange() throws {
        let stolenChange = try makeBuilt(outputs: [
            Transaction.Output(value: paymentAmount, scriptPubKey: recipientScript),
            Transaction.Output(value: changeValue, scriptPubKey: attackerScript),
        ])
        XCTAssertFalse(makePreview().authorizes(stolenChange))
    }
}
