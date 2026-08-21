import BitcoinCore
import BitcoinP2P
import Foundation
import Testing
@testable import WalletCore

/// Integer-boundary properties of coin selection (epic #100, invariant S9).
///
/// The existing selection tests check specific scenarios. The risk this suite
/// addresses is different: an arithmetic path that is correct for the amounts
/// someone thought to write down and wrong near a boundary — a fee that
/// underflows into change, a change output that quietly absorbs a satoshi, a
/// sum that wraps. Money is conserved or it is not, and that has to hold for
/// every input the function accepts rather than for a handful of examples.
///
/// Generation is seeded, so any failure reproduces exactly from the seed
/// printed in the assertion.
@Suite("Coin selection properties")
struct CoinSelectionPropertyTests {
    /// Same generator as `WinnowFuzz`, so a failing case can be replayed there.
    struct SplitMix64 {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9E37_79B9_7F4A_7C15
            var value = state
            value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
            value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
            return value ^ (value >> 31)
        }
        mutating func int(_ range: ClosedRange<Int64>) -> Int64 {
            let span = UInt64(range.upperBound - range.lowerBound) &+ 1
            return range.lowerBound &+ Int64(next() % max(span, 1))
        }
        mutating func count(_ upperBound: Int) -> Int { Int(next() % UInt64(max(upperBound, 1))) }
    }

    static func script(_ byte: UInt8) -> Data { Data([0x51, 0x20] + repeatElement(byte, count: 32)) }
    static let changeScript = script(0xCC)

    static func utxo(_ index: Int, amount: Int64) -> WalletUTXO {
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

    // MARK: - Randomized properties

    /// Ordinary magnitudes: the amounts a wallet actually sees.
    @Test("value is conserved across ordinary amounts")
    func conservationOrdinary() throws {
        let seed: UInt64 = 0x5309_1A7E_0000_0001
        var rng = SplitMix64(state: seed)
        var accepted = 0
        for iteration in 0 ..< 4_000 {
            let utxos = (0 ... rng.count(6)).map { Self.utxo($0, amount: rng.int(1 ... 5_000_000)) }
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
        var rng = SplitMix64(state: seed)
        let extremes: [Int64] = [
            1, 2, 329, 330, 331,
            BitcoinAmount.maximum - 1, BitcoinAmount.maximum,
            Int64.max / 2, Int64.max - 1, Int64.max,
        ]
        for iteration in 0 ..< 3_000 {
            let utxos = (0 ... rng.count(4)).map {
                Self.utxo($0, amount: extremes[rng.count(extremes.count)])
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

    // MARK: - Named boundaries

    /// The dust threshold is a boundary, not a gradient: one satoshi below is
    /// refused and the threshold itself is accepted.
    @Test("a payment exactly at the dust threshold is accepted, one below is not")
    func dustBoundaryIsExact() throws {
        let script = Self.script(0xBB)
        let dust = CoinSelection.dustThreshold(scriptPubKey: script)
        let utxos = [Self.utxo(0, amount: 1_000_000)]

        let atThreshold = try CoinSelection.select(
            utxos: utxos, payments: [Payment(amount: dust, scriptPubKey: script)],
            changeScriptPubKey: Self.changeScript, feeRateSatPerVByte: 1)
        #expect(atThreshold.fee > 0)

        #expect(throws: CoinSelectionError.self) {
            _ = try CoinSelection.select(
                utxos: utxos, payments: [Payment(amount: dust - 1, scriptPubKey: script)],
                changeScriptPubKey: Self.changeScript, feeRateSatPerVByte: 1)
        }
    }

    /// A fee rate is bounded on both sides. Zero, negative, NaN and infinity
    /// would each underflow the fee and inflate change past the inputs;
    /// anything above Core's relay ceiling silently burns the balance.
    @Test("fee rates outside (0, 10000] are refused",
          arguments: [0.0, -1.0, -0.0001, 10_000.001, 100_000.0,
                      Double.nan, Double.infinity, -Double.infinity])
    func feeRateBounds(_ rate: Double) {
        // Asserting the specific case matters: with the ceiling removed the
        // call still throws, but as insufficientFunds, because an absurd rate
        // simply exhausts the inputs. A test that accepted any
        // CoinSelectionError would pass against a missing bound.
        do {
            _ = try CoinSelection.select(
                utxos: [Self.utxo(0, amount: 1_000_000)],
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
        let utxos = [Self.utxo(0, amount: BitcoinAmount.maximum / 4)]
        let payments = [Payment(amount: 1_000_000, scriptPubKey: Self.script(0xBB))]
        let selection = try CoinSelection.select(
            utxos: utxos, payments: payments,
            changeScriptPubKey: Self.changeScript, feeRateSatPerVByte: rate)
        Self.check(selection, payments: payments, offered: utxos, seed: 0, iteration: 0)
    }

    /// An amount above MAX_MONEY is refused rather than wrapping.
    @Test("an amount above MAX_MONEY is refused")
    func aboveMaxMoneyRefused() {
        #expect(throws: CoinSelectionError.self) {
            _ = try CoinSelection.select(
                utxos: [Self.utxo(0, amount: BitcoinAmount.maximum)],
                payments: [Payment(amount: BitcoinAmount.maximum + 1, scriptPubKey: Self.script(0xBB))],
                changeScriptPubKey: Self.changeScript, feeRateSatPerVByte: 1)
        }
    }

    /// Many payments that individually fit but together exceed MAX_MONEY must
    /// be caught by the running total, not only by the per-payment check.
    @Test("payments summing past MAX_MONEY are refused")
    func summedOverflowRefused() {
        let half = BitcoinAmount.maximum / 2 + 1
        let payments = [
            Payment(amount: half, scriptPubKey: Self.script(0xBB)),
            Payment(amount: half, scriptPubKey: Self.script(0xBC)),
        ]
        #expect(throws: CoinSelectionError.self) {
            _ = try CoinSelection.select(
                utxos: [Self.utxo(0, amount: BitcoinAmount.maximum)], payments: payments,
                changeScriptPubKey: Self.changeScript, feeRateSatPerVByte: 1)
        }
    }
}
