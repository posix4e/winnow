@testable import WinnowApp
import BitcoinCore
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

    // MARK: - The reviewed outputs must account for the whole transaction

    /// Presence is not enough. Every reviewed output can be exactly right and
    /// the transaction still pay somewhere the reviewer never saw — the fee
    /// and input pins do not forbid it, because an extra output is funded by
    /// shrinking nothing the review pinned.
    func testRefusesAnExtraOutputAlongsideAMatchingPaymentAndChange() throws {
        let withExtra = try makeBuilt(outputs: [
            Transaction.Output(value: paymentAmount, scriptPubKey: recipientScript),
            Transaction.Output(value: changeValue, scriptPubKey: changeScript),
            Transaction.Output(value: 1_000, scriptPubKey: attackerScript),
        ])
        XCTAssertFalse(makePreview().authorizes(withExtra))
    }

    /// The same hole on the no-change branch, which previously returned as
    /// soon as `changeAmount` was nil and never looked at the outputs at all.
    func testRefusesAnExtraOutputWhenThereIsNoChange() throws {
        var preview = makePreview()
        preview.change = nil
        preview.changeAmount = nil
        let withExtra = try makeBuilt(outputs: [
            Transaction.Output(value: paymentAmount, scriptPubKey: recipientScript),
            Transaction.Output(value: 1_000, scriptPubKey: attackerScript),
        ], changeAmount: .some(nil))
        XCTAssertFalse(preview.authorizes(withExtra))
    }

    /// Positive control for the branch above: no change, no extras, authorized.
    func testAuthorizesAChangelessSendWithNoExtraOutputs() throws {
        var preview = makePreview()
        preview.change = nil
        preview.changeAmount = nil
        let built = try makeBuilt(outputs: [
            Transaction.Output(value: paymentAmount, scriptPubKey: recipientScript),
        ], changeAmount: .some(nil))
        XCTAssertTrue(preview.authorizes(built))
    }

    // MARK: - Silent payments (#134)

    /// A BIP352 output script is derived from the selected inputs' private
    /// keys, so the review layer is handed it rather than computing it. These
    /// fixtures stand in for that derived script.
    private let derivedSilentScript = Data([0x51, 0x20] + repeatElement(0xCC, count: 32))
    private let silentAmount: Int64 = 50_000

    /// A silent-payment preview. `payments` is empty, exactly as `previewSend`
    /// builds it for an `sp1…` destination — which is why the old gate, which
    /// only iterated `payments`, had nothing to check.
    private func makeSilentPreview() throws -> AppModel.SendPreview {
        AppModel.SendPreview(
            destination: "tsp1-recipient",
            payments: [],
            silentPayments: [SilentPayment(amount: silentAmount,
                                           address: try Self.silentAddress())],
            feeRateSatPerVByte: 2,
            fee: feeValue,
            changeAmount: changeValue,
            inputCount: 2,
            selectedOutpoints: outpoints,
            change: Payment(amount: changeValue, scriptPubKey: changeScript)
        )
    }

    /// A deterministic throwaway recipient: valid keys, secrets nobody holds.
    private static func silentAddress() throws -> SilentPaymentAddress {
        let master = try HDKey(seed: Data(repeating: 0x5A, count: 32))
        let scan = try master.derived(path: "m/352'/1'/0'/1'/0")
        let spend = try master.derived(path: "m/352'/1'/0'/0'/0")
        return try SilentPaymentAddress(scanKey: scan.neutered.publicKey,
                                        spendKey: spend.neutered.publicKey,
                                        hrp: SilentPayment.hrp(for: .signet))
    }

    private func resolved(_ script: Data, amount: Int64? = nil) -> [Payment] {
        [Payment(amount: amount ?? silentAmount, scriptPubKey: script)]
    }

    /// Positive control: the derived script is present, so this is authorized.
    func testAuthorizesASilentPaymentItReviewed() throws {
        let built = try makeBuilt(outputs: [
            Transaction.Output(value: silentAmount, scriptPubKey: derivedSilentScript),
            Transaction.Output(value: changeValue, scriptPubKey: changeScript),
        ])
        XCTAssertTrue(try makeSilentPreview().authorizes(
            built, resolvedSilentPayments: resolved(derivedSilentScript)))
    }

    /// The case that previously passed unconditionally: the whole reviewed
    /// amount goes to a script that is not the derived one.
    func testRefusesARedirectedSilentPayment() throws {
        let built = try makeBuilt(outputs: [
            Transaction.Output(value: silentAmount, scriptPubKey: attackerScript),
            Transaction.Output(value: changeValue, scriptPubKey: changeScript),
        ])
        XCTAssertFalse(try makeSilentPreview().authorizes(
            built, resolvedSilentPayments: resolved(derivedSilentScript)))
    }

    func testRefusesAReducedSilentPayment() throws {
        let built = try makeBuilt(outputs: [
            Transaction.Output(value: 1, scriptPubKey: derivedSilentScript),
            Transaction.Output(value: changeValue, scriptPubKey: changeScript),
        ])
        XCTAssertFalse(try makeSilentPreview().authorizes(
            built, resolvedSilentPayments: resolved(derivedSilentScript, amount: 1)))
    }

    func testRefusesAnOmittedSilentPayment() throws {
        let built = try makeBuilt(outputs: [
            Transaction.Output(value: changeValue, scriptPubKey: changeScript),
        ])
        XCTAssertFalse(try makeSilentPreview().authorizes(
            built, resolvedSilentPayments: resolved(derivedSilentScript)))
    }

    /// The wallet must hand back one resolved script per reviewed silent
    /// payment. A short list means the two sides disagree about what is being
    /// paid, which is not something to resolve by paying anyway.
    func testRefusesWhenTheWalletResolvesNoSilentPayments() throws {
        let built = try makeBuilt(outputs: [
            Transaction.Output(value: silentAmount, scriptPubKey: derivedSilentScript),
            Transaction.Output(value: changeValue, scriptPubKey: changeScript),
        ])
        XCTAssertFalse(try makeSilentPreview().authorizes(built, resolvedSilentPayments: []))
    }

    /// A mixed send has to satisfy both halves, not whichever one is easier.
    func testMixedSendRequiresBothTheOrdinaryAndSilentOutputs() throws {
        var preview = try makeSilentPreview()
        preview.payments = [Payment(amount: paymentAmount, scriptPubKey: recipientScript)]

        let both = try makeBuilt(outputs: [
            Transaction.Output(value: paymentAmount, scriptPubKey: recipientScript),
            Transaction.Output(value: silentAmount, scriptPubKey: derivedSilentScript),
            Transaction.Output(value: changeValue, scriptPubKey: changeScript),
        ])
        XCTAssertTrue(preview.authorizes(both, resolvedSilentPayments: resolved(derivedSilentScript)))

        let silentRedirected = try makeBuilt(outputs: [
            Transaction.Output(value: paymentAmount, scriptPubKey: recipientScript),
            Transaction.Output(value: silentAmount, scriptPubKey: attackerScript),
            Transaction.Output(value: changeValue, scriptPubKey: changeScript),
        ])
        XCTAssertFalse(preview.authorizes(silentRedirected,
                                          resolvedSilentPayments: resolved(derivedSilentScript)))
    }

    /// Regression: two reviewed payments of the same amount and script must
    /// consume two distinct outputs, not match the same one twice.
    func testDuplicateReviewedPaymentsConsumeDistinctOutputs() throws {
        var preview = makePreview()
        preview.payments = [
            Payment(amount: paymentAmount, scriptPubKey: recipientScript),
            Payment(amount: paymentAmount, scriptPubKey: recipientScript),
        ]
        let onlyOne = try makeBuilt(outputs: [
            Transaction.Output(value: paymentAmount, scriptPubKey: recipientScript),
            Transaction.Output(value: changeValue, scriptPubKey: changeScript),
        ])
        XCTAssertFalse(preview.authorizes(onlyOne))

        let both = try makeBuilt(outputs: [
            Transaction.Output(value: paymentAmount, scriptPubKey: recipientScript),
            Transaction.Output(value: paymentAmount, scriptPubKey: recipientScript),
            Transaction.Output(value: changeValue, scriptPubKey: changeScript),
        ])
        XCTAssertTrue(preview.authorizes(both))
    }

    /// Change is inserted at a random position, so nothing may assume
    /// payments-then-change ordering.
    func testAuthorizesRegardlessOfOutputOrder() throws {
        let changeFirst = try makeBuilt(outputs: [
            Transaction.Output(value: changeValue, scriptPubKey: changeScript),
            Transaction.Output(value: paymentAmount, scriptPubKey: recipientScript),
        ])
        XCTAssertTrue(makePreview().authorizes(changeFirst))
    }
}
