import BitcoinCore
import Foundation
import Testing
import WalletCore
@testable import WinnowApp

/// The fee is allowed to cost more than the payment delivers, silently (#140).
///
/// Winnow refuses a payment below dust, and refuses a fee rate outside its
/// band. Nothing looks at the relationship *between* the two. A one-input,
/// two-output Taproot spend is 143 vB, so at an unremarkable 5 sat/vB it costs
/// 715 sat to confirm -- and a 500 sat payment clears dust, at a cheap market
/// rate, with coin selection succeeding and value conserved. Every guard
/// passes individually; the composition is what produces a transaction nobody
/// would knowingly authorise.
///
/// This is the last screen before an irreversible action, and the epic spent
/// considerable effort making that screen bind exactly what will be broadcast.
/// Faithfully displaying a transaction nobody would authorise is only half the
/// job.
@Suite("Fee proportion warning")
struct FeeProportionTests {
    private func preview(amount: Int64, fee: Int64) -> AppModel.SendPreview {
        AppModel.SendPreview(
            destination: "tb1p-recipient",
            payments: amount > 0
                ? [Payment(amount: amount,
                           scriptPubKey: Data([0x51, 0x20] + repeatElement(0xAA, count: 32)))]
                : [],
            feeRateSatPerVByte: 5,
            fee: fee,
            changeAmount: nil,
            inputCount: 1,
            selectedOutpoints: [.init(txid: Data(repeating: 0x11, count: 32), vout: 0)],
            change: nil)
    }

    /// The reported case, with the issue's own arithmetic: 143 vB at 5 sat/vB.
    @Test("a payment that costs more to send than it delivers warns")
    func feeExceedingPaymentWarns() {
        let warning = preview(amount: 500, fee: 715).feeProportion
        #expect(warning != nil, "715 sat of fee on a 500 sat payment must not pass in silence")
        #expect(warning?.exceedsAmount == true)
        #expect(warning?.percentOfAmount == 143)
    }

    /// The other end of the acceptance: a payment several times its fee is
    /// ordinary and must not be nagged about.
    @Test("a payment several times its fee does not warn")
    func proportionatePaymentIsQuiet() {
        #expect(preview(amount: 100_000, fee: 715).feeProportion == nil)
        #expect(preview(amount: 3_000, fee: 715).feeProportion == nil)
        // Four times the fee is still comfortably clear of the threshold.
        #expect(preview(amount: 2_860, fee: 715).feeProportion == nil)
    }

    /// The threshold is a ratio, so it has to hold at both ends of the allowed
    /// fee-rate band rather than at one calibrated point. Same shape, same
    /// proportions, fee rates an order of magnitude apart.
    @Test("the threshold holds across the fee-rate band")
    func thresholdIsARatioNotAnAmount() {
        // 143 vB at 5 sat/vB and at 50 sat/vB.
        for fee in [715 as Int64, 7_150] {
            #expect(preview(amount: fee / 2, fee: fee).feeProportion != nil,
                    "a payment half the fee must warn at every rate")
            #expect(preview(amount: fee * 4, fee: fee).feeProportion == nil,
                    "a payment four times the fee must stay quiet at every rate")
        }
    }

    /// Exactly at the boundary, and either side of it.
    @Test("the boundary is half the amount, inclusive")
    func boundaryIsInclusive() {
        #expect(preview(amount: 1_000, fee: 500).feeProportion != nil, "half must warn")
        #expect(preview(amount: 1_000, fee: 499).feeProportion == nil, "just under must not")
        #expect(preview(amount: 1_000, fee: 501).feeProportion != nil)
    }


    /// The warning has to name the actual numbers; a generic caution tells the
    /// user nothing they can act on.
    @Test("the warning names the amounts rather than cautioning generically")
    func warningNamesTheAmounts() throws {
        let warning = try #require(preview(amount: 500, fee: 715).feeProportion)
        let message = warning.message { "\($0) sat" }
        #expect(message.contains("500 sat"))
        #expect(message.contains("715 sat"))
        #expect(message.contains("143%"))
    }

    /// The other wording branch. `warningNamesTheAmounts` only exercises the
    /// case where the fee exceeds the payment, so blanking the sub-100%
    /// sentence killed no test -- an unproven guard, and the reason this one
    /// exists.
    @Test("the sub-100% wording names its amounts too")
    func nonExceedingWarningNamesTheAmounts() throws {
        // 550 on 1,000: over the half threshold, under the amount.
        let warning = try #require(preview(amount: 1_000, fee: 550).feeProportion)
        #expect(warning.exceedsAmount == false, "this must be the other branch")
        let message = warning.message { "\($0) sat" }
        #expect(message.contains("1000 sat"))
        #expect(message.contains("550 sat"))
        #expect(message.contains("55%"))
    }

    /// Guard rather than behaviour: no payment means no ratio to speak of, and
    /// the division must not be attempted.
    @Test("a preview with nothing being sent has no proportion")
    func emptyPaymentHasNoProportion() {
        #expect(preview(amount: 0, fee: 715).feeProportion == nil)
    }
}
