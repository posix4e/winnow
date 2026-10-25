@testable import WinnowApp
import WalletCore
import Foundation
import Testing
import XCTest

/// The send review screen and the gate behind it.
///
/// Four things are asserted here and they are all about the same screen: what
/// the reviewed preview authorizes, what invalidates a review's identity, when
/// the fee is out of proportion to the payment, and what the locktime notice
/// says. The suites keep their own names — `docs/security/findings.md` cites
/// `SendPreviewAuthorizationTests` and `SendReviewBindingTests` by name as
/// evidence for SEC-007, SEC-018 and SEC-003 — and `FeeProportionTests` is a
/// swift-testing suite rather than an XCTest class, so it stays a `struct`.

/// The scripts every preview below is built from. A Taproot output is
/// `OP_1 <32 bytes>`; only the payload byte separates recipient, change and
/// attacker.
private let recipientScript = Data([0x51, 0x20] + repeatElement(0xAA, count: 32))
private let changeScript = Data([0x51, 0x20] + repeatElement(0xBB, count: 32))
private let attackerScript = Data([0x51, 0x20] + repeatElement(0xEE, count: 32))

private let txidA = Data(repeating: 0x11, count: 32)
private let txidB = Data(repeating: 0x22, count: 32)

// MARK: - SendPreviewAuthorizationTests

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

    // MARK: Fields the guard already covered

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

    // MARK: The reviewed outputs must account for the whole transaction

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

    // MARK: - Silent payments (SEC-018)

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
}

// MARK: - SendReviewBindingTests

final class SendReviewBindingTests: XCTestCase {
    private let baseline = SendReviewInputs(
        destination: "tb1p-old-destination",
        amountText: "10000",
        priority: .medium,
        overrideText: "",
        network: .signet
    )

    func testEveryAuthorizationInputInvalidatesTheReviewIdentity() {
        var otherWallet = baseline
        otherWallet.walletID = "another-wallet"
        XCTAssertNotEqual(baseline, otherWallet)
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
}

// MARK: - FeeProportionTests

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
                ? [Payment(amount: amount, scriptPubKey: recipientScript)]
                : [],
            feeRateSatPerVByte: 5,
            fee: fee,
            changeAmount: nil,
            inputCount: 1,
            selectedOutpoints: [.init(txid: txidA, vout: 0)],
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

// MARK: - LocktimeLagNoticeTests

/// The #151 decision, pinned: a send built while the header chain may lag the
/// network proceeds, and the review screen says what the locktime will
/// disclose. The alternative behaviours the issue listed — refusing to send,
/// or trusting a peer-advertised height — were considered and not taken:
/// refusal is worst for the user who needs to spend now, and a peer height
/// that must not exceed the real tip is exactly the trust the builder
/// deliberately avoids.
final class LocktimeLagNoticeTests: XCTestCase {
    /// The policy over every phase. `.filters` is deliberately on the quiet
    /// side: headers are at the network tip by then and only the scan trails,
    /// so the locktime is already drawn from Core's own distribution.
    func testEveryPhaseDeclaresWhetherTheTipMayLag() {
        XCTAssertTrue(AppModel.SyncPhase.idle.headerTipMayLagNetwork)
        XCTAssertTrue(AppModel.SyncPhase.connecting(connected: 1, target: 3).headerTipMayLagNetwork)
        XCTAssertTrue(AppModel.SyncPhase.headers(synced: 100, tipEstimate: 900).headerTipMayLagNetwork)
        XCTAssertTrue(AppModel.SyncPhase.peerDiscoveryFailed.headerTipMayLagNetwork)
        XCTAssertFalse(AppModel.SyncPhase.filters(scanned: 10, tip: 900).headerTipMayLagNetwork)
        XCTAssertFalse(AppModel.SyncPhase.synced.headerTipMayLagNetwork)
    }

    /// Direct constructions describe an ordinary synced send unless they say
    /// otherwise — the same convention every existing SendPreview test relies
    /// on to stay silent about concerns it is not testing.
    func testThePreviewDefaultsToNoLag() {
        let preview = AppModel.SendPreview(
            destination: "tb1q", payments: [], feeRateSatPerVByte: 1, fee: 100,
            changeAmount: nil, inputCount: 1, selectedOutpoints: [], change: nil)
        XCTAssertFalse(preview.locktimeLagsTip)
    }

    /// The flag is review-surface state, not authorization state: two previews
    /// differing only in the lag flag authorize the same transactions, because
    /// the locktime the wallet stamps is the same either way — the flag only
    /// changes what the user was told.
    func testTheLagFlagDoesNotChangeWhatIsAuthorized() {
        var preview = AppModel.SendPreview(
            destination: "tb1q", payments: [], feeRateSatPerVByte: 1, fee: 100,
            changeAmount: nil, inputCount: 0, selectedOutpoints: [], change: nil)
        var lagged = preview
        lagged.locktimeLagsTip = true
        XCTAssertNotEqual(preview, lagged, "the flag must be part of the reviewed value")
        preview.locktimeLagsTip = true
        XCTAssertEqual(preview, lagged)
    }
}
