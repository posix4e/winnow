import Foundation
import Testing
import TestSupport
@testable import WalletCore

/// Choosing coins and pricing the transaction that spends them.
///
/// Three suites merged here: the scenario tests below, the seeded property
/// tests that assert the same arithmetic holds for every input the function
/// accepts, and the fee policy that decides the rate those two are handed.
@Suite("Coin selection")
struct CoinSelectionTests {
    let p2tr = Data([0x51, 0x20] + repeatElement(0x42, count: 32))

    func utxo(_ amount: Int64, index: UInt32 = 0) -> WalletUTXO {
        WalletUTXO(txid: Data(repeating: UInt8(amount % 250 + 1), count: 32), vout: index,
                   amount: amount, scriptPubKey: p2tr, chain: .receive, index: index, height: 100)
    }

    @Test("dust thresholds follow Core's GetDustThreshold (3000 sat/kvB)")
    func dustThresholds() {
        // P2TR: 43-byte txout + 67-byte discounted witness input = 110 × 3.
        #expect(CoinSelection.dustThreshold(scriptPubKey: p2tr) == 330)
        // P2WPKH: 31 + 67 = 98 × 3 = 294.
        #expect(CoinSelection.dustThreshold(scriptPubKey: Data([0x00, 0x14] + repeatElement(0x42, count: 20))) == 294)
        // P2PKH: 34 + 148 = 182 × 3 = 546.
        #expect(CoinSelection.dustThreshold(scriptPubKey: Data([0x76, 0xA9, 0x14] + repeatElement(0x42, count: 20) + [0x88, 0xAC])) == 546)
        // OP_RETURN outputs carry no dust threshold in Core (unspendable) —
        // we simply don't special-case them; verify P2TR scales with feerate.
        #expect(CoinSelection.dustThreshold(scriptPubKey: p2tr, relayFeeSatPerKvB: 6_000) == 660)
    }

    @Test("largest-first: the biggest UTXOs are spent first")
    func largestFirst() throws {
        let utxos = [utxo(10_000, index: 0), utxo(500_000, index: 1), utxo(50_000, index: 2)]
        let payments = [Payment(amount: 100_000, scriptPubKey: p2tr)]
        let selection = try CoinSelection.select(utxos: utxos, payments: payments,
                                                 changeScriptPubKey: p2tr, feeRateSatPerVByte: 1)
        #expect(selection.selected.map(\.amount) == [500_000])
        #expect(selection.changeAmount != nil)
        // fee = vsize(1 in, payment + change) × 1 sat/vB; change = rest.
        let expectedVSize = TransactionBuilder.signedVSize(inputCount: 1, outputs: [
            Transaction.Output(value: 100_000, scriptPubKey: p2tr),
            Transaction.Output(value: 0, scriptPubKey: p2tr),
        ])
        #expect(selection.fee == Int64(expectedVSize))
        #expect(selection.changeAmount == 500_000 - 100_000 - Int64(expectedVSize))
    }

    @Test("dust change folds into the fee instead of creating a dust output")
    func dustChange() throws {
        let payments = [Payment(amount: 100_000, scriptPubKey: p2tr)]
        let changeScript = p2tr
        // Pick the UTXO so the remainder after the 2-output fee is 100 sats.
        let vsizeWithChange = TransactionBuilder.signedVSize(inputCount: 1, outputs: [
            Transaction.Output(value: 100_000, scriptPubKey: p2tr),
            Transaction.Output(value: 0, scriptPubKey: changeScript),
        ])
        let amount = 100_000 + Int64(vsizeWithChange) + 100
        let selection = try CoinSelection.select(utxos: [utxo(amount)], payments: payments,
                                                 changeScriptPubKey: changeScript, feeRateSatPerVByte: 1)
        #expect(selection.changeAmount == nil)
        #expect(selection.fee == amount - 100_000) // fee + 100 dust sats
    }

    @Test("exact change (remainder == fee) creates no change output")
    func exactChange() throws {
        let payments = [Payment(amount: 100_000, scriptPubKey: p2tr)]
        let vsizeWithChange = TransactionBuilder.signedVSize(inputCount: 1, outputs: [
            Transaction.Output(value: 100_000, scriptPubKey: p2tr),
            Transaction.Output(value: 0, scriptPubKey: p2tr),
        ])
        let amount = 100_000 + Int64(vsizeWithChange) // remainder exactly the 2-output fee
        let selection = try CoinSelection.select(utxos: [utxo(amount)], payments: payments,
                                                 changeScriptPubKey: p2tr, feeRateSatPerVByte: 1)
        #expect(selection.changeAmount == nil)
        #expect(selection.fee == Int64(vsizeWithChange))
        // …and the fee still covers the smaller 1-output transaction.
        let vsizeNoChange = TransactionBuilder.signedVSize(inputCount: 1, outputs: [
            Transaction.Output(value: 100_000, scriptPubKey: p2tr),
        ])
        #expect(selection.fee >= Int64(vsizeNoChange))
    }

    @Test("insufficient funds and empty UTXO set throw")
    func failures() {
        let payments = [Payment(amount: 1_000_000, scriptPubKey: p2tr)]
        #expect(throws: CoinSelectionError.noUTXOs) {
            _ = try CoinSelection.select(utxos: [], payments: payments,
                                         changeScriptPubKey: p2tr, feeRateSatPerVByte: 1)
        }
        do {
            _ = try CoinSelection.select(utxos: [utxo(50_000)], payments: payments,
                                         changeScriptPubKey: p2tr, feeRateSatPerVByte: 1)
            Issue.record("should have thrown insufficientFunds")
        } catch let CoinSelectionError.insufficientFunds(available, required) {
            #expect(available == 50_000)
            #expect(required > 1_000_000) // target + fee for the changeless tx
        } catch {
            Issue.record("wrong error: \(error)")
        }
    }

    @Test("a payment below its dust threshold is rejected before building")
    func subDustPaymentRejected() {
        // 100 sats to a P2TR script (dust threshold 330) must not build a
        // non-relayable tx that then strands the committed inputs.
        let payments = [Payment(amount: 100, scriptPubKey: p2tr)]
        #expect(throws: CoinSelectionError.dustOutput(value: 100, threshold: 330)) {
            _ = try CoinSelection.select(utxos: [utxo(1_000_000)], payments: payments,
                                         changeScriptPubKey: p2tr, feeRateSatPerVByte: 1)
        }
        // The threshold is a boundary, not a gradient: one satoshi below is dust.
        #expect(throws: CoinSelectionError.dustOutput(value: 329, threshold: 330)) {
            _ = try CoinSelection.select(utxos: [utxo(1_000_000)],
                                         payments: [Payment(amount: 329, scriptPubKey: p2tr)],
                                         changeScriptPubKey: p2tr, feeRateSatPerVByte: 1)
        }
        // At the threshold it is accepted.
        #expect(throws: Never.self) {
            _ = try CoinSelection.select(utxos: [utxo(1_000_000)],
                                         payments: [Payment(amount: 330, scriptPubKey: p2tr)],
                                         changeScriptPubKey: p2tr, feeRateSatPerVByte: 1)
        }
    }

    @Test("multiple inputs are pulled in until the growing fee is covered")
    func multipleInputs() throws {
        // 4 × 60_000, target 200_000: 3 inputs (180k) don't cover it, 4 do.
        let utxos = (0 ..< 4).map { utxo(60_000, index: UInt32($0)) }
        let payments = [Payment(amount: 200_000, scriptPubKey: p2tr)]
        let selection = try CoinSelection.select(utxos: utxos, payments: payments,
                                                 changeScriptPubKey: p2tr, feeRateSatPerVByte: 2)
        let vsize = TransactionBuilder.signedVSize(inputCount: 4, outputs: [
            Transaction.Output(value: 200_000, scriptPubKey: p2tr),
            Transaction.Output(value: 0, scriptPubKey: p2tr),
        ])
        #expect(selection.selected.count == 4)
        #expect(selection.fee == Int64(2 * vsize))
        #expect(selection.changeAmount == 240_000 - 200_000 - Int64(2 * vsize))
    }

    /// The ceiling is on the transaction, not on the coin count, so it is
    /// reached at wildly different input counts depending on what each input
    /// has to prove: about 1,700 P2TR key-path spends, or about 200 inputs
    /// carrying a 2,000-byte witness.
    @Test("a selection too large to relay is refused before anything is signed",
          arguments: [66, 2_000])
    func standardSizeCeiling(witnessBytesPerInput: Int) throws {
        // The shape a one-payment send has: the payment plus change. Output
        // *values* do not affect size, so the input count that first exceeds
        // the ceiling can be found before the amounts are chosen.
        let shape = [Transaction.Output(value: 0, scriptPubKey: p2tr),
                     Transaction.Output(value: 0, scriptPubKey: p2tr)]
        var pastCeiling = 1
        while TransactionBuilder.signedVSize(inputCount: pastCeiling, outputs: shape,
                                             witnessBytesPerInput: witnessBytesPerInput)
            <= TransactionBuilder.maximumStandardVSize { pastCeiling += 1 }

        // Equal coins, and a payment that only the last one covers, so the
        // loop takes every coin offered. 200,000 sats each pays the fee the
        // final input adds and still leaves non-dust change.
        let coin: Int64 = 200_000
        func spendEveryCoin(count: Int) throws -> Selection {
            try CoinSelection.select(
                utxos: (0 ..< count).map { utxo(coin, index: UInt32($0)) },
                payments: [Payment(amount: Int64(count - 1) * coin, scriptPubKey: p2tr)],
                changeScriptPubKey: p2tr, feeRateSatPerVByte: 1,
                witnessBytesPerInput: witnessBytesPerInput)
        }

        // One input short of the ceiling, the selection is made, change and all.
        let fits = try spendEveryCoin(count: pastCeiling - 1)
        #expect(fits.selected.count == pastCeiling - 1)
        #expect(fits.changeAmount != nil)

        // One input past it, the selection is refused and carries the vsize
        // it measured — and no signature is spent on bytes no peer would take.
        let vsize = TransactionBuilder.signedVSize(inputCount: pastCeiling, outputs: shape,
                                                   witnessBytesPerInput: witnessBytesPerInput)
        #expect(throws: CoinSelectionError.transactionTooLarge(
            vsize: vsize, limit: TransactionBuilder.maximumStandardVSize)) {
            _ = try spendEveryCoin(count: pastCeiling)
        }
    }

    @Test("hostile amounts and malformed wallet coins fail without arithmetic traps")
    func hostileAmountsAndCoins() {
        let valid = utxo(1_000_000)

        #expect(throws: CoinSelectionError.invalidAmount(Int64.max)) {
            _ = try CoinSelection.select(
                utxos: [valid], payments: [Payment(amount: Int64.max, scriptPubKey: p2tr)],
                changeScriptPubKey: p2tr, feeRateSatPerVByte: 1)
        }
        // The boundary itself: one satoshi past MAX_MONEY is refused, not wrapped.
        #expect(throws: CoinSelectionError.invalidAmount(BitcoinAmount.maximum + 1)) {
            _ = try CoinSelection.select(
                utxos: [valid], payments: [Payment(amount: BitcoinAmount.maximum + 1, scriptPubKey: p2tr)],
                changeScriptPubKey: p2tr, feeRateSatPerVByte: 1)
        }
        #expect(throws: CoinSelectionError.amountOverflow) {
            _ = try CoinSelection.select(
                utxos: [valid], payments: [
                    Payment(amount: BitcoinAmount.maximum, scriptPubKey: p2tr),
                    Payment(amount: 330, scriptPubKey: p2tr),
                ], changeScriptPubKey: p2tr, feeRateSatPerVByte: 1)
        }
        #expect(throws: CoinSelectionError.duplicateUTXO) {
            _ = try CoinSelection.select(
                utxos: [valid, valid], payments: [Payment(amount: 10_000, scriptPubKey: p2tr)],
                changeScriptPubKey: p2tr, feeRateSatPerVByte: 1)
        }

        var badOutpoint = valid
        badOutpoint.txid = Data(repeating: 0x11, count: 31)
        #expect(throws: CoinSelectionError.invalidOutpoint) {
            _ = try CoinSelection.select(
                utxos: [badOutpoint], payments: [Payment(amount: 10_000, scriptPubKey: p2tr)],
                changeScriptPubKey: p2tr, feeRateSatPerVByte: 1)
        }
        #expect(throws: CoinSelectionError.emptyScript) {
            _ = try CoinSelection.select(
                utxos: [valid], payments: [Payment(amount: 10_000, scriptPubKey: Data())],
                changeScriptPubKey: p2tr, feeRateSatPerVByte: 1)
        }
        #expect(throws: CoinSelectionError.invalidWitnessSize(-1)) {
            _ = try CoinSelection.select(
                utxos: [valid], payments: [Payment(amount: 10_000, scriptPubKey: p2tr)],
                changeScriptPubKey: p2tr, feeRateSatPerVByte: 1,
                witnessBytesPerInput: -1)
        }
        #expect(throws: CoinSelectionError.invalidWitnessSize(0)) {
            _ = try CoinSelection.select(
                utxos: [valid], payments: [Payment(amount: 10_000, scriptPubKey: p2tr)],
                changeScriptPubKey: p2tr, feeRateSatPerVByte: 1,
                witnessBytesPerInput: 0)
        }
    }

    // MARK: - Properties
    //
    // Integer-boundary properties of coin selection (invariant S9).
    //
    // The scenario tests above check specific cases. The risk this section
    // addresses is different: an arithmetic path that is correct for the
    // amounts someone thought to write down and wrong near a boundary — a fee
    // that underflows into change, a change output that quietly absorbs a
    // satoshi, a sum that wraps. Money is conserved or it is not, and that has
    // to hold for every input the function accepts rather than for a handful
    // of examples.
    //
    // Generation is seeded, so any failure reproduces exactly from the seed
    // printed in the assertion.

    static func script(_ byte: UInt8) -> Data { Data([0x51, 0x20] + repeatElement(byte, count: 32)) }
    static let changeScript = script(0xCC)

    static func generatedUTXO(_ index: Int, amount: Int64) -> WalletUTXO {
        WalletUTXO(txid: Data([UInt8(truncatingIfNeeded: index)] + repeatElement(0x11, count: 31)),
                   vout: UInt32(index), amount: amount, scriptPubKey: script(0xAA),
                   chain: .receive, index: UInt32(index), height: 1)
    }

    /// Everything a successful selection must satisfy, whatever the inputs.
    static func check(_ selection: Selection, payments: [Payment],
                      offered: [WalletUTXO], seed: UInt64, iteration: Int) {
        let context = "seed 0x\(String(seed, radix: 16)) iteration \(iteration)"
        let inputTotal = selection.selected.reduce(Int64(0)) { $0 + $1.amount }
        let paid = payments.reduce(Int64(0)) { $0 + $1.amount }
        let change = selection.changeAmount ?? 0

        // Money is conserved: nothing is created, nothing vanishes.
        #expect(inputTotal == paid + selection.fee + change,
                "value not conserved — \(context)")
        #expect(selection.fee > 0, "non-positive fee — \(context)")
        #expect(change >= 0, "negative change — \(context)")
        #expect(inputTotal <= BitcoinAmount.maximum, "input total above MAX_MONEY — \(context)")

        // A change output that exists must be spendable, not dust.
        if let amount = selection.changeAmount {
            #expect(amount >= CoinSelection.dustThreshold(scriptPubKey: changeScript),
                    "change below the dust threshold — \(context)")
        }

        // Selected coins are a duplicate-free subset of what was offered.
        let offeredOutpoints = Set(offered.map(\.outpoint))
        var seen: Set<Transaction.Outpoint> = []
        for coin in selection.selected {
            #expect(offeredOutpoints.contains(coin.outpoint), "invented a coin — \(context)")
            #expect(seen.insert(coin.outpoint).inserted, "spent a coin twice — \(context)")
        }
    }

    // MARK: Randomized properties

    /// Ordinary magnitudes: the amounts a wallet actually sees.
    @Test("value is conserved across ordinary amounts")
    func conservationOrdinary() throws {
        let seed: UInt64 = 0x5309_1A7E_0000_0001
        var rng = SeededRandom(state: seed)
        var accepted = 0
        for iteration in 0 ..< 4_000 {
            let utxos = (0 ... rng.count(6)).map { Self.generatedUTXO($0, amount: rng.int(1 ... 5_000_000)) }
            let payments = (0 ... rng.count(3)).map {
                _ in Payment(amount: rng.int(1 ... 2_000_000), scriptPubKey: Self.script(0xBB))
            }
            let rate = Double(rng.int(1 ... 500))
            do {
                let selection = try CoinSelection.select(
                    utxos: utxos, payments: payments,
                    changeScriptPubKey: Self.changeScript, feeRateSatPerVByte: rate)
                Self.check(selection, payments: payments, offered: utxos, seed: seed, iteration: iteration)
                accepted += 1
            } catch is CoinSelectionError {
                continue // a refusal is always an acceptable answer
            }
        }
        #expect(accepted > 500, "the generator produced too few accepted selections to be meaningful")
    }

    /// Amounts pressed against MAX_MONEY, where an unchecked add would wrap.
    /// Every one of these must either succeed with money conserved or throw —
    /// never return a wrong number.
    @Test("extreme amounts either conserve value or are refused")
    func conservationAtExtremes() throws {
        let seed: UInt64 = 0x5309_1A7E_0000_0002
        var rng = SeededRandom(state: seed)
        let extremes: [Int64] = [
            1, 2, 329, 330, 331,
            BitcoinAmount.maximum - 1, BitcoinAmount.maximum,
            Int64.max / 2, Int64.max - 1, Int64.max,
        ]
        for iteration in 0 ..< 3_000 {
            let utxos = (0 ... rng.count(4)).map {
                Self.generatedUTXO($0, amount: extremes[rng.count(extremes.count)])
            }
            let payments = (0 ... rng.count(2)).map {
                _ in Payment(amount: extremes[rng.count(extremes.count)], scriptPubKey: Self.script(0xBB))
            }
            let rate = [0.25, 1, 1_000, 9_999, 10_000][rng.count(5)]
            do {
                let selection = try CoinSelection.select(
                    utxos: utxos, payments: payments,
                    changeScriptPubKey: Self.changeScript, feeRateSatPerVByte: rate)
                Self.check(selection, payments: payments, offered: utxos, seed: seed, iteration: iteration)
            } catch is CoinSelectionError {
                continue
            }
        }
    }

    // MARK: Named boundaries

    /// A fee rate is bounded on both sides. Zero, negative, NaN and infinity
    /// would each underflow the fee and inflate change past the inputs;
    /// anything above Winnow's fee safety ceiling silently burns the balance. The
    /// first representable rate past the ceiling is in the list, so the bound
    /// is checked at its edge rather than near it.
    @Test("fee rates outside (0, 10000] are refused",
          arguments: [0.0, -1.0, -5.0, -0.0001, (10_000.0).nextUp, 10_000.001, 10_001.0,
                      100_000.0, Double.nan, Double.infinity, -Double.infinity])
    func feeRateBounds(_ rate: Double) {
        // Asserting the specific case matters: with the ceiling removed the
        // call still throws, but as insufficientFunds, because an absurd rate
        // simply exhausts the inputs. A test that accepted any
        // CoinSelectionError would pass against a missing bound.
        do {
            _ = try CoinSelection.select(
                utxos: [Self.generatedUTXO(0, amount: 1_000_000)],
                payments: [Payment(amount: 100_000, scriptPubKey: Self.script(0xBB))],
                changeScriptPubKey: Self.changeScript, feeRateSatPerVByte: rate)
            Issue.record("fee rate \(rate) was accepted")
        } catch let error as CoinSelectionError {
            guard case .invalidFeeRate = error else {
                Issue.record("fee rate \(rate) was rejected as \(error) rather than invalidFeeRate")
                return
            }
        } catch {
            Issue.record("unexpected error \(error)")
        }
    }

    /// Both ends of the accepted fee-rate range still produce a conserved
    /// selection, so the bounds above are refusals rather than the only
    /// values that work.
    @Test("the extreme accepted fee rates still conserve value", arguments: [0.0001, 10_000.0])
    func acceptedFeeRateExtremes(_ rate: Double) throws {
        let utxos = [Self.generatedUTXO(0, amount: BitcoinAmount.maximum / 4)]
        let payments = [Payment(amount: 1_000_000, scriptPubKey: Self.script(0xBB))]
        let selection = try CoinSelection.select(
            utxos: utxos, payments: payments,
            changeScriptPubKey: Self.changeScript, feeRateSatPerVByte: rate)
        Self.check(selection, payments: payments, offered: utxos, seed: 0, iteration: 0)
    }

    // MARK: - Fee policy
    //
    // Which rate the selection above is handed, and the floor the peer pool
    // puts under it.

    @Test("resolution order: override > observed median > static preset")
    func order() {
        // Static presets when nothing else is known.
        #expect(FeePolicy.resolve(priority: .low) == FeePolicy.Priority.low.satPerVByte)
        #expect(FeePolicy.resolve(priority: .medium) == 5)
        #expect(FeePolicy.resolve(priority: .high) == 12)
        // Observed median beats the preset.
        #expect(FeePolicy.resolve(priority: .high, observed: [3, 7, 4]) == 4)
        // The user override beats everything.
        #expect(FeePolicy.resolve(priority: .high, override: 42, observed: [3, 7, 4]) == 42)
    }

    @Test("the feefilter floor clamps every source from below")
    func floor() {
        #expect(FeePolicy.resolve(priority: .low, floorSatPerVByte: 3.5) == 3.5)
        #expect(FeePolicy.resolve(priority: .low, override: 1, floorSatPerVByte: 2) == 2)
        #expect(FeePolicy.resolve(observed: [10], floorSatPerVByte: 1) == 10) // above floor: untouched
    }

    @Test("median of observed samples")
    func median() {
        #expect(FeePolicy.median([]) == nil)
        #expect(FeePolicy.median([5]) == 5)
        #expect(FeePolicy.median([1, 9, 3]) == 3)
        #expect(FeePolicy.median([1, 3, 9, 5]) == 4)
    }

    @Test("a peer pool with no connected peers has no floor")
    func poolFloor() async {
        let pool = PeerPool(params: .signet)
        #expect(await pool.feeFilterFloorSatPerVByte() == nil)
    }
}
