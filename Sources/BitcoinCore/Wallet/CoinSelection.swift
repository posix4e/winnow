import Foundation

public enum CoinSelectionError: Error, Equatable {
    case noUTXOs
    case insufficientFunds(available: Int64, required: Int64)
    /// Feerate was non-positive, non-finite, or above the absurd-fee ceiling.
    case invalidFeeRate(Double)
    /// A payment output is below the dust relay threshold and would not relay.
    case dustOutput(value: Int64, threshold: Int64)
    /// The selection needs more inputs than a standard-sized transaction can
    /// carry, so the transaction spending them would not relay either.
    case transactionTooLarge(vsize: Int, limit: Int)
    /// A payment or stored coin is outside Bitcoin's monetary range.
    case invalidAmount(Int64)
    /// The same outpoint appeared more than once in the spendable set.
    case duplicateUTXO
    /// A stored coin did not carry a 32-byte transaction ID.
    case invalidOutpoint
    /// A raw locking script or change script was empty.
    case emptyScript
    /// A caller supplied an impossible witness-size estimate.
    case invalidWitnessSize(Int)
    /// Summing amounts or calculating a fee exceeded the safe monetary range.
    case amountOverflow
}

extension CoinSelectionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .noUTXOs: "There are no spendable coins."
        case let .insufficientFunds(available, required):
            "Insufficient funds: \(available) sats are available, but \(required) sats are required."
        case let .invalidFeeRate(rate): "Invalid fee rate: \(rate) sat/vB."
        case let .dustOutput(value, threshold):
            "The \(value)-sat payment is below the \(threshold)-sat relay minimum."
        case let .transactionTooLarge(vsize, limit):
            "Spending these coins takes a \(vsize)-vbyte transaction, above the \(limit)-vbyte relay "
                + "maximum. Send a smaller amount, or combine coins into fewer, larger ones first."
        case let .invalidAmount(amount): "Invalid Bitcoin amount: \(amount) sats."
        case .duplicateUTXO: "The wallet contains the same coin more than once. Rescan before spending."
        case .invalidOutpoint: "A wallet coin has an invalid transaction ID. Rescan before spending."
        case .emptyScript: "A payment has no Bitcoin locking script."
        case let .invalidWitnessSize(size): "Invalid transaction witness estimate: \(size) bytes."
        case .amountOverflow: "The transaction amounts exceed Bitcoin's monetary range."
        }
    }
}

/// The outcome of a coin selection: which UTXOs to spend, the fee at the
/// requested feerate, and the change amount (nil = no change output — the
/// remainder folded into the fee).
public struct Selection: Equatable, Sendable {
    public var selected: [WalletUTXO]
    public var fee: Int64
    public var changeAmount: Int64?

    public init(selected: [WalletUTXO], fee: Int64, changeAmount: Int64?) {
        self.selected = selected
        self.fee = fee
        self.changeAmount = changeAmount
    }
}

/// Largest-first coin selection with a dust guard (Bitcoin Core dust policy,
/// policy.cpp GetDustThreshold) and exact fee estimation for P2TR key-path
/// spends.
public enum CoinSelection {
    /// Default minimum relay feerate for dust purposes (3000 sat/kvB, Core's
    /// default dustRelayFee).
    public static let defaultDustRelayFeeSatPerKvB: Int64 = 3_000

    /// Core's dust rule: an output is dust when spending it costs more than
    /// its value at the dust relay feerate. For witness programs Core adds a
    /// fixed 67 bytes for the discounted input (32+4+1+107/4+4), so a 43-byte
    /// P2TR txout is dust below 110 × 3 = **330 sats** at the default rate.
    /// (The often-quoted 294 sats is the *P2WPKH* threshold — 31+67 bytes.)
    public static func dustThreshold(scriptPubKey: Data,
                                     relayFeeSatPerKvB: Int64 = defaultDustRelayFeeSatPerKvB) -> Int64 {
        let outputSize = 8 + TransactionBuilder.compactSizeLength(UInt64(scriptPubKey.count)) + scriptPubKey.count
        // Witness program: OP_0 or OP_1..OP_16 followed by a 2–40 byte push.
        let version = scriptPubKey.first ?? 0xFF
        let isWitness = scriptPubKey.count >= 4
            && (version == 0x00 || (version >= 0x51 && version <= 0x60))
            && scriptPubKey.count == 2 + Int(scriptPubKey[scriptPubKey.index(scriptPubKey.startIndex, offsetBy: 1)])
            && scriptPubKey.count >= 4 && scriptPubKey.count <= 42
        let spendSize = isWitness ? 32 + 4 + 1 + 107 / 4 + 4 : 32 + 4 + 1 + 107 + 4
        return Int64(outputSize + spendSize) * relayFeeSatPerKvB / 1_000
    }

    /// Largest-first: accumulate the biggest UTXOs until the selection covers
    /// the payment total plus the fee for the transaction as built so far
    /// (each added input grows the fee — the loop accounts for it). A change
    /// output is added when the remainder clears its dust threshold; dust
    /// remainders fold into the fee instead of creating an unspendable output.
    /// `witnessBytesPerInput` overrides the per-input witness size used for
    /// fee estimation (default: the 66 bytes of a P2TR key-path spend).
    public static func select(utxos: [WalletUTXO], payments: [Payment],
                              changeScriptPubKey: Data, feeRateSatPerVByte: Double,
                              witnessBytesPerInput: Int = 66) throws -> Selection {
        try checkArguments(utxos: utxos, changeScriptPubKey: changeScriptPubKey,
                           feeRateSatPerVByte: feeRateSatPerVByte,
                           witnessBytesPerInput: witnessBytesPerInput)
        let target = try paymentTarget(of: payments)
        try checkSpendableSet(utxos)
        let paymentOutputs = payments.map {
            Transaction.Output(value: $0.amount, scriptPubKey: $0.scriptPubKey)
        }
        let changeOutput = Transaction.Output(value: 0, scriptPubKey: changeScriptPubKey)

        func fee(inputCount: Int, withChange: Bool) throws -> Int64 {
            try Self.fee(inputCount: inputCount,
                         outputs: withChange ? paymentOutputs + [changeOutput] : paymentOutputs,
                         witnessBytesPerInput: witnessBytesPerInput,
                         feeRateSatPerVByte: feeRateSatPerVByte)
        }

        var selected: [WalletUTXO] = []
        var total: Int64 = 0
        for utxo in utxos.sorted(by: { $0.amount > $1.amount }) {
            selected.append(utxo)
            let (sum, overflow) = total.addingReportingOverflow(utxo.amount)
            guard !overflow, sum <= BitcoinAmount.maximum else {
                throw CoinSelectionError.amountOverflow
            }
            total = sum
            // Try with a change output first — that's the shape the tx will have.
            let required = try checkedAdd(target, fee(inputCount: selected.count,
                                                      withChange: true))
            if total >= required { break }
        }

        let feeWithChange = try fee(inputCount: selected.count, withChange: true)
        let requiredWithoutChange = try checkedAdd(
            target, fee(inputCount: selected.count, withChange: false))
        guard total >= requiredWithoutChange else {
            throw CoinSelectionError.insufficientFunds(
                available: total, required: requiredWithoutChange)
        }

        let change = total - target - feeWithChange
        let withChange = change >= dustThreshold(scriptPubKey: changeScriptPubKey)
        try checkStandardSize(inputCount: selected.count,
                              outputs: withChange ? paymentOutputs + [changeOutput] : paymentOutputs,
                              witnessBytesPerInput: witnessBytesPerInput)
        if withChange {
            return Selection(selected: selected, fee: feeWithChange, changeAmount: change)
        }
        // Change is dust (or exactly zero): no change output; the remainder
        // becomes fee. The fee must still cover the smaller changeless tx.
        let finalFee = total - target
        return Selection(selected: selected, fee: finalFee, changeAmount: nil)
    }

    /// The argument contract: coins to choose from, a real change script, a
    /// witness size a transaction could carry, and a feerate inside (0,
    /// 10 000] sat/vB — a negative/zero/NaN feerate underflows the fee
    /// (inflating change past the inputs into an invalid tx), an absurd one
    /// silently burns the balance, and Core's sendrawtransaction ceiling is
    /// 0.10 BTC/kvB.
    private static func checkArguments(utxos: [WalletUTXO], changeScriptPubKey: Data,
                                       feeRateSatPerVByte: Double,
                                       witnessBytesPerInput: Int) throws {
        guard !utxos.isEmpty else { throw CoinSelectionError.noUTXOs }
        guard !changeScriptPubKey.isEmpty else { throw CoinSelectionError.emptyScript }
        guard (1 ... 100_000).contains(witnessBytesPerInput) else {
            throw CoinSelectionError.invalidWitnessSize(witnessBytesPerInput)
        }
        guard feeRateSatPerVByte.isFinite, feeRateSatPerVByte > 0,
              feeRateSatPerVByte <= 10_000 else {
            throw CoinSelectionError.invalidFeeRate(feeRateSatPerVByte)
        }
    }

    /// Sums the payments under the supply cap. Every payment must clear its
    /// own dust threshold — the change output is guarded at selection time,
    /// but a sub-dust payment builds a tx no peer will relay, stranding the
    /// (locally committed) inputs.
    private static func paymentTarget(of payments: [Payment]) throws -> Int64 {
        var target: Int64 = 0
        for payment in payments {
            guard payment.amount > 0, payment.amount <= BitcoinAmount.maximum else {
                throw CoinSelectionError.invalidAmount(payment.amount)
            }
            guard !payment.scriptPubKey.isEmpty else { throw CoinSelectionError.emptyScript }
            let threshold = dustThreshold(scriptPubKey: payment.scriptPubKey)
            guard payment.amount >= threshold else {
                throw CoinSelectionError.dustOutput(value: payment.amount, threshold: threshold)
            }
            let (sum, overflow) = target.addingReportingOverflow(payment.amount)
            guard !overflow, sum <= BitcoinAmount.maximum else {
                throw CoinSelectionError.amountOverflow
            }
            target = sum
        }
        return target
    }

    /// Refuses a selection whose transaction would exceed Bitcoin Core's
    /// default standardness size limit, so an unlikely-to-relay send does not
    /// commit its coins as spent locally. Sized for the shape the caller will build, which
    /// is why it runs after the change decision rather than inside the loop.
    ///
    /// It runs after the insufficient-funds guard too: a wallet that cannot
    /// cover the payment at all is short of money, not short of room, and
    /// should be told so.
    private static func checkStandardSize(inputCount: Int, outputs: [Transaction.Output],
                                          witnessBytesPerInput: Int) throws {
        let vsize = TransactionBuilder.signedVSize(inputCount: inputCount, outputs: outputs,
                                                   witnessBytesPerInput: witnessBytesPerInput)
        guard vsize <= TransactionBuilder.maximumStandardVSize else {
            throw CoinSelectionError.transactionTooLarge(
                vsize: vsize, limit: TransactionBuilder.maximumStandardVSize)
        }
    }

    /// Every candidate coin is well-formed and no outpoint repeats.
    private static func checkSpendableSet(_ utxos: [WalletUTXO]) throws {
        var seenOutpoints: Set<Transaction.Outpoint> = []
        for utxo in utxos {
            guard utxo.txid.count == 32 else { throw CoinSelectionError.invalidOutpoint }
            guard utxo.amount > 0, utxo.amount <= BitcoinAmount.maximum else {
                throw CoinSelectionError.invalidAmount(utxo.amount)
            }
            guard !utxo.scriptPubKey.isEmpty else { throw CoinSelectionError.emptyScript }
            guard seenOutpoints.insert(utxo.outpoint).inserted else {
                throw CoinSelectionError.duplicateUTXO
            }
        }
    }

    /// The ceiling-rounded fee for a signed transaction of this shape, under
    /// the supply cap.
    private static func fee(inputCount: Int, outputs: [Transaction.Output],
                            witnessBytesPerInput: Int,
                            feeRateSatPerVByte: Double) throws -> Int64 {
        let vsize = TransactionBuilder.signedVSize(inputCount: inputCount, outputs: outputs,
                                                   witnessBytesPerInput: witnessBytesPerInput)
        let calculated = (Double(vsize) * feeRateSatPerVByte).rounded(.up)
        guard calculated.isFinite, calculated <= Double(BitcoinAmount.maximum) else {
            throw CoinSelectionError.amountOverflow
        }
        return Int64(calculated)
    }

    /// `amount + fee`, refused past the supply cap.
    private static func checkedAdd(_ amount: Int64, _ fee: Int64) throws -> Int64 {
        let (sum, overflow) = amount.addingReportingOverflow(fee)
        guard !overflow, sum <= BitcoinAmount.maximum else {
            throw CoinSelectionError.amountOverflow
        }
        return sum
    }
}
