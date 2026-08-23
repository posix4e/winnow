import BitcoinCore
import BitcoinP2P
import Foundation

public enum TxBuildError: Error, Equatable {
    case noInputs
    case noOutputs
    case invalidAmount(Int64)
    case amountOverflow
    case emptyScript
    case invalidOutpoint
    case duplicateInput
    case invalidChangePosition(Int)
}

extension TxBuildError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .noInputs: "A Bitcoin transaction needs at least one input."
        case .noOutputs: "A Bitcoin transaction needs at least one output."
        case let .invalidAmount(amount): "Invalid Bitcoin output amount: \(amount) sats."
        case .amountOverflow: "The transaction outputs exceed Bitcoin's monetary range."
        case .emptyScript: "A transaction output has no Bitcoin locking script."
        case .invalidOutpoint: "A transaction input has an invalid transaction ID."
        case .duplicateInput: "A transaction cannot spend the same coin twice."
        case let .invalidChangePosition(position): "Invalid change-output position: \(position)."
        }
    }
}

/// A payment target: an amount plus its destination scriptPubKey.
public struct Payment: Equatable, Sendable {
    public var amount: Int64
    public var scriptPubKey: Data

    public init(amount: Int64, scriptPubKey: Data) {
        self.amount = amount
        self.scriptPubKey = scriptPubKey
    }

    /// Pays any standard address type (bech32/bech32m segwit, base58 P2PKH/P2SH).
    public init(amount: Int64, address: String, network: BitcoinNetwork) throws {
        self.amount = amount
        scriptPubKey = try AddressDecoder.scriptPubKey(for: address, network: network)
    }
}

/// Transaction building on top of BitcoinP2P's wire model: version 2, segwit,
/// empty scriptSigs, BIP125-signaling sequences. Plus the exact vsize math for
/// P2TR key-path spends used by fee estimation and coin selection.
public enum TransactionBuilder {
    /// Sequence 0xFFFFFFFD: locktime-disabled, opt-in BIP125 replaceable.
    public static let defaultSequence: UInt32 = 0xFFFF_FFFD

    /// The `nLockTime` to stamp on a newly built transaction.
    ///
    /// Bitcoin Core sets this to the current block height on everything it
    /// creates. The mechanism is anti-fee-sniping: a transaction whose locktime
    /// equals the tip cannot be mined into an *earlier* block, which removes
    /// the incentive to re-mine the previous block and take the fees in it.
    ///
    /// The reason it matters here is the anonymity set rather than the fee
    /// theft. Because "a recent block height" is what almost everything emits,
    /// a transaction carrying zero is trivially distinguishable from a
    /// Core-built one — it discloses which software made it to anyone reading
    /// the chain. For a wallet whose whole argument is that it discloses
    /// nothing, that is a poor trade for no benefit (#139).
    ///
    /// Also following Core: about one in ten transactions uses a height from
    /// the previous hundred blocks instead of the tip. Without that, "locktime
    /// is always exactly the tip" becomes its own signal, and a wallet that is
    /// behind on sync stands out from one that is not.
    ///
    /// Never returns a height above `tip`: a locktime in the future is not
    /// final, and the transaction would not relay.
    public static func antiFeeSnipingLocktime(
        tip: UInt32,
        randomness: @Sendable () -> Double = { Double.random(in: 0 ..< 1) }
    ) -> UInt32 {
        guard Self.draw(randomness()) < 0.1 else { return tip }
        let lookback = UInt32(Self.draw(randomness()) * 100) // 0...99, as Core
        return tip >= lookback ? tip - lookback : 0
    }

    /// Confines a draw to `0 ..< 1`.
    ///
    /// The default source already satisfies that, but the parameter exists so
    /// tests can drive both branches deterministically, and an injected value
    /// outside the range would otherwise convert to a lookback of 100 or --
    /// for a negative draw -- trap in the `UInt32` initialiser. Clamping keeps
    /// a bad injection a wrong answer rather than a crash on the money path.
    private static func draw(_ value: Double) -> Double {
        guard value.isFinite else { return 0 }
        return min(max(value, 0), 0.999_999_999)
    }

    /// An unsigned transaction: payments first, the change output inserted at
    /// `changePosition` (a random position when nil, so change isn't always the
    /// last output — a chain-analysis fingerprint).
    public static func build(inputs: [Transaction.Outpoint], payments: [Payment],
                             change: Payment? = nil, changePosition: Int? = nil,
                             sequence: UInt32 = defaultSequence, locktime: UInt32 = 0) throws -> Transaction {
        guard !inputs.isEmpty else { throw TxBuildError.noInputs }
        var seenInputs: Set<Transaction.Outpoint> = []
        for input in inputs {
            guard input.txid.count == 32 else { throw TxBuildError.invalidOutpoint }
            guard seenInputs.insert(input).inserted else { throw TxBuildError.duplicateInput }
        }
        var outputs = payments.map { Transaction.Output(value: $0.amount, scriptPubKey: $0.scriptPubKey) }
        if let change {
            let position = changePosition ?? Int.random(in: 0 ... outputs.count)
            guard position >= 0, position <= outputs.count else {
                throw TxBuildError.invalidChangePosition(position)
            }
            outputs.insert(Transaction.Output(value: change.amount, scriptPubKey: change.scriptPubKey),
                           at: position)
        }
        guard !outputs.isEmpty else { throw TxBuildError.noOutputs }
        var outputTotal: Int64 = 0
        for output in outputs {
            guard output.value > 0, output.value <= BitcoinAmount.maximum else {
                throw TxBuildError.invalidAmount(output.value)
            }
            guard !output.scriptPubKey.isEmpty else { throw TxBuildError.emptyScript }
            let (sum, overflow) = outputTotal.addingReportingOverflow(output.value)
            guard !overflow, sum <= BitcoinAmount.maximum else { throw TxBuildError.amountOverflow }
            outputTotal = sum
        }
        let txInputs = inputs.map {
            Transaction.Input(previousOutput: $0, scriptSig: Data(), sequence: sequence)
        }
        return Transaction(version: 2, inputs: txInputs, outputs: outputs, locktime: locktime)
    }

    /// Exact vsize of the *signed* transaction assuming every input is a P2TR
    /// key-path spend: witness = one stack item of 64 bytes (SIGHASH_DEFAULT
    /// signature). weight = 3·base + total; vsize = ⌈weight / 4⌉ (BIP141).
    /// `witnessBytesPerInput` overrides the per-input witness byte count for
    /// other spend shapes (e.g. multi_a script-path vault inputs).
    public static func signedVSize(inputCount: Int, outputs: [Transaction.Output],
                                   witnessBytesPerInput: Int = 66) -> Int {
        let inputCountSize = compactSizeLength(UInt64(inputCount))
        let outputCountSize = compactSizeLength(UInt64(outputs.count))
        // Base (non-witness) bytes: version, locktime, varints, inputs, outputs.
        var base = 4 + 4 + inputCountSize + outputCountSize
        base += inputCount * (32 + 4 + 1 + 4) // outpoint, empty scriptSig length, sequence
        for output in outputs {
            base += 8 + compactSizeLength(UInt64(output.scriptPubKey.count)) + output.scriptPubKey.count
        }
        // Witness bytes: marker+flag, then per-input witness serialization.
        let witness = 2 + inputCount * witnessBytesPerInput
        return (3 * base + base + witness + 3) / 4
    }

    /// Exact vsize of a fully-signed transaction (witness included).
    public static func vsize(of tx: Transaction) -> Int {
        let base = tx.serialized(includeWitness: false).count
        let total = tx.serialized(includeWitness: true).count
        return (3 * base + total + 3) / 4
    }

    static func compactSizeLength(_ value: UInt64) -> Int {
        switch value {
        case ..<0xFD: 1
        case ...0xFFFF: 3
        case ...0xFFFF_FFFF: 5
        default: 9
        }
    }
}
