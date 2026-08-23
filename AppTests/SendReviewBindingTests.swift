@testable import WinnowApp
import BitcoinP2P
import WalletCore
import XCTest

final class SendReviewBindingTests: XCTestCase {
    private let baseline = SendReviewInputs(
        destination: "tb1p-old-destination",
        amountText: "10000",
        priority: .medium,
        overrideText: "",
        network: .signet
    )

    func testEveryAuthorizationInputInvalidatesTheReviewIdentity() {
        XCTAssertNotEqual(
            baseline,
            SendReviewInputs(destination: "tb1p-new-destination", amountText: baseline.amountText,
                             priority: baseline.priority, overrideText: baseline.overrideText,
                             network: baseline.network)
        )
        XCTAssertNotEqual(
            baseline,
            SendReviewInputs(destination: baseline.destination, amountText: "20000",
                             priority: baseline.priority, overrideText: baseline.overrideText,
                             network: baseline.network)
        )
        XCTAssertNotEqual(
            baseline,
            SendReviewInputs(destination: baseline.destination, amountText: baseline.amountText,
                             priority: .high, overrideText: baseline.overrideText,
                             network: baseline.network)
        )
        XCTAssertNotEqual(
            baseline,
            SendReviewInputs(destination: baseline.destination, amountText: baseline.amountText,
                             priority: baseline.priority, overrideText: "5.0",
                             network: baseline.network)
        )
        XCTAssertNotEqual(
            baseline,
            SendReviewInputs(destination: baseline.destination, amountText: baseline.amountText,
                             priority: baseline.priority, overrideText: baseline.overrideText,
                             network: .mainnet)
        )
    }

    func testParsingUsesTheCapturedReviewFields() {
        let captured = baseline
        let edited = SendReviewInputs(destination: "tb1p-new-destination", amountText: "20000",
                                      priority: .high, overrideText: "5.0", network: .signet)

        XCTAssertEqual(captured.trimmedDestination, "tb1p-old-destination")
        XCTAssertEqual(captured.amount, 10_000)
        XCTAssertNotEqual(captured, edited)
    }

    func testFeeBumpReviewBindsTransactionAndRequestedRate() {
        let txid = Data(repeating: 0x11, count: 32)
        let baseline = FeeBumpReviewInputs(txid: txid, targetRateText: " 2.5 ")

        XCTAssertEqual(baseline.targetRate, 2.5)
        XCTAssertNotEqual(
            baseline,
            FeeBumpReviewInputs(txid: Data(repeating: 0x22, count: 32), targetRateText: " 2.5 ")
        )
        XCTAssertNotEqual(
            baseline,
            FeeBumpReviewInputs(txid: txid, targetRateText: "3.0")
        )
    }

    func testBuiltSendMustMatchReviewedFeeChangeAndInputs() {
        let reviewedOutpoint = Transaction.Outpoint(
            txid: Data(repeating: 0x11, count: 32), vout: 1)
        let changeScript = Data([0x51, 0x20]) + Data(repeating: 0x22, count: 32)
        let destinationScript = Data([0x00, 0x14]) + Data(repeating: 0x33, count: 20)
        let preview = AppModel.SendPreview(
            destination: "tb1q-reviewed",
            payments: [Payment(amount: 20_000, scriptPubKey: destinationScript)],
            feeRateSatPerVByte: 2,
            fee: 500,
            changeAmount: 79_500,
            inputCount: 1,
            selectedOutpoints: [.init(txid: reviewedOutpoint.txid, vout: reviewedOutpoint.vout)],
            change: Payment(amount: 79_500, scriptPubKey: changeScript)
        )
        func built(fee: Int64 = 500, changeAmount: Int64? = 79_500,
                   outpoint: Transaction.Outpoint = reviewedOutpoint,
                   overrideChangeScript: Data? = nil) -> BuiltTransaction {
            let actualChangeScript = overrideChangeScript ?? changeScript
            let transaction = Transaction(
                version: 2,
                inputs: [.init(previousOutput: outpoint, scriptSig: Data(), sequence: 0xFFFF_FFFD)],
                outputs: [
                    .init(value: 20_000, scriptPubKey: destinationScript),
                    .init(value: 79_500, scriptPubKey: actualChangeScript),
                ],
                locktime: 0
            )
            return BuiltTransaction(psbt: PSBT(globals: [], inputs: [], outputs: []),
                                    transaction: transaction, fee: fee,
                                    changeAmount: changeAmount)
        }

        XCTAssertTrue(preview.authorizes(built()))
        XCTAssertFalse(preview.authorizes(built(fee: 501)))
        XCTAssertFalse(preview.authorizes(built(changeAmount: nil)))
        XCTAssertFalse(preview.authorizes(built(
            outpoint: .init(txid: Data(repeating: 0x44, count: 32), vout: 1))))
        XCTAssertFalse(preview.authorizes(built(
            overrideChangeScript: Data([0x51, 0x20]) + Data(repeating: 0x55, count: 32))))
    }
}
