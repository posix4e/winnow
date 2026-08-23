import BitcoinCore
import BitcoinP2P
import Foundation

public enum WalletError: Error, Equatable, LocalizedError {
    /// Descriptor isn't the wallet's single-sig form: tr(KEY) with a ranged
    /// BIP389 `<0;1>/*` derivation and origin info (see `Wallet.descriptor`).
    case invalidDescriptor(String)
    /// Bundle descriptor does not match the one derived from its mnemonic.
    case descriptorMismatch
    case invalidBundle(String)
    case noPayments
    /// The built transaction lost its change output (should not happen).
    case changeOutputMissing
    /// A seed-bearing export was requested, but the secret is an xprv (or
    /// missing) rather than a BIP39 mnemonic. Refusing is safer than emitting
    /// a bundle that looks spendable and is not.
    case mnemonicUnavailable
    /// A watch-only bundle cannot faithfully recover silent-payment UTXOs:
    /// validating and spending them requires the BIP352 key derived from the
    /// mnemonic, which the BIP86 descriptor does not contain.
    case silentPaymentExportRequiresMnemonic
    /// A pending send has already removed the parent inputs from the UTXO
    /// set. Exporting now would ship only the unconfirmed change — if the
    /// send never confirms, a forward-only restore cannot see the original
    /// coins (their confirmation height is behind `lastKnownHeight`).
    case exportWhilePending
    /// A matched transaction carried impossible output values or a total
    /// beyond Bitcoin's consensus monetary range. Nothing is applied.
    case invalidTransactionAmounts

    public var errorDescription: String? {
        switch self {
        case let .invalidDescriptor(text):
            "Invalid descriptor: \(text)"
        case .descriptorMismatch:
            "Bundle descriptor does not match the mnemonic."
        case let .invalidBundle(reason):
            "Invalid import bundle: \(reason)"
        case .noPayments:
            "Nothing to send."
        case .changeOutputMissing:
            "The built transaction lost its change output."
        case .mnemonicUnavailable:
            "This wallet has no recovery phrase to export — it was imported from an extended key, not a BIP39 mnemonic."
        case .silentPaymentExportRequiresMnemonic:
            "This wallet contains silent-payment funds. Include the recovery phrase so the exported bundle can validate and spend them."
        case .exportWhilePending:
            "Wait for pending transactions to confirm before exporting. A mid-send backup would drop the coins being spent."
        case .invalidTransactionAmounts:
            "A matched Bitcoin transaction contains invalid amounts. Wallet state was not changed."
        }
    }
}

/// A fee bump can only replace one of this wallet's still-pending sends. The
/// replacement keeps the same inputs and recipient outputs, and pays its
/// higher fee by shrinking (or, when it becomes dust, removing) change.
public enum FeeBumpError: Error, Equatable, LocalizedError {
    case transactionNotPending
    case noChangeOutput
    case changeAlreadySpent
    case invalidFeeRate(Double)
    case feeRateNotHigher(current: Double, requested: Double)
    case insufficientChange(requiredFee: Int64, maximumFee: Int64)

    public var errorDescription: String? {
        switch self {
        case .transactionNotPending:
            "This transaction is no longer pending or was created before fee-bump metadata was available."
        case .noChangeOutput:
            "This transaction has no change output to reduce for a same-input fee bump."
        case .changeAlreadySpent:
            "This transaction's change has already been spent by another pending transaction."
        case let .invalidFeeRate(rate):
            "Invalid replacement fee rate: \(rate) sat/vB."
        case let .feeRateNotHigher(current, requested):
            "Choose a fee rate above \(current.formatted(.number.precision(.fractionLength(2)))) sat/vB (requested \(requested.formatted(.number.precision(.fractionLength(2)))) sat/vB)."
        case let .insufficientChange(requiredFee, maximumFee):
            "The available change can pay at most \(maximumFee) sats in fees; this bump needs \(requiredFee) sats."
        }
    }
}

/// Which chain of the wallet's multipath descriptor an address lives on
/// (BIP44 external/internal).
public enum AddressChain: Int, Codable, Sendable {
    case receive = 0
    case change = 1
}

/// A wallet-controlled unspent output, with the derivation coordinates needed
/// to sign for it.
public struct WalletUTXO: Equatable, Sendable, Codable {
    public var txid: Data // 32 bytes, internal byte order
    public var vout: UInt32
    public var amount: Int64
    public var scriptPubKey: Data
    public var chain: AddressChain
    public var index: UInt32
    /// Block height that confirmed it.
    public var height: UInt32
    /// BIP352: the scalar added to the wallet's silent-payment spend key to
    /// sign for this output (t_k, with any label folded in). It exists only in
    /// scan results, so losing it means a rescan before the output can be
    /// spent. nil for descriptor outputs; when set, `chain`/`index` carry no
    /// meaning.
    public var silentPaymentTweak: Data?
    /// Set when this output was created by a coinbase. Consensus forbids
    /// spending it until `Wallet.coinbaseMaturity` confirmations; the flag is
    /// absent from older state files and treated as false.
    public var isCoinbase: Bool
    /// Set when this coin has been spent. The row is kept rather than deleted
    /// so a reorg can put it back (#127).
    ///
    /// Rescanning forward from the fork cannot recreate a coin whose *creating*
    /// transaction is below the fork, and `HistoryEntry` cannot help: it stores
    /// aggregates -- txid, height, received, spent, fee -- with no outpoints,
    /// scripts, or derivation indices. From "this transaction spent 50,000 sats
    /// of ours" there is no way back to *which coins*. So the one fact that was
    /// being thrown away is retained, and everything else is still re-derived.
    public var spent: SpentMarker?

    /// What spent a coin, and when.
    public struct SpentMarker: Equatable, Sendable, Codable {
        /// The transaction that spent it.
        public var spentBy: Data
        /// The height that confirmed the spend, or nil while the spend exists
        /// only in our own pending send.
        ///
        /// The distinction is what stops a rollback from double-spending the
        /// wallet against itself: a coin whose spender is still in flight must
        /// stay reserved even when the rollback puts confirmed coins back,
        /// because the broadcaster will keep re-relaying that transaction.
        public var height: UInt32?

        public init(spentBy: Data, height: UInt32?) {
            self.spentBy = spentBy
            self.height = height
        }
    }

    /// True once the coin has been spent, confirmed or pending.
    public var isSpent: Bool { spent != nil }

    public init(txid: Data, vout: UInt32, amount: Int64, scriptPubKey: Data,
                chain: AddressChain, index: UInt32, height: UInt32,
                silentPaymentTweak: Data? = nil, isCoinbase: Bool = false,
                spent: SpentMarker? = nil) {
        self.spent = spent
        self.txid = txid
        self.vout = vout
        self.amount = amount
        self.scriptPubKey = scriptPubKey
        self.chain = chain
        self.index = index
        self.height = height
        self.silentPaymentTweak = silentPaymentTweak
        self.isCoinbase = isCoinbase
    }

    public var outpoint: Transaction.Outpoint {
        Transaction.Outpoint(txid: txid, vout: vout)
    }

    public var spentOutput: SighashBIP341.SpentOutput {
        SighashBIP341.SpentOutput(amount: amount, scriptPubKey: scriptPubKey)
    }

    // JSON: txid display hex, scriptPubKey hex (human-inspectable state file).
    private enum CodingKeys: String, CodingKey {
        case txid, vout, amount, scriptPubKey, chain, index, height, silentPaymentTweak, isCoinbase
        case spent
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard let txid = Data(hex: try container.decode(String.self, forKey: .txid)) else {
            throw DecodingError.dataCorruptedError(forKey: .txid, in: container,
                                                   debugDescription: "bad txid hex")
        }
        guard let scriptPubKey = Data(hex: try container.decode(String.self, forKey: .scriptPubKey)) else {
            throw DecodingError.dataCorruptedError(forKey: .scriptPubKey, in: container,
                                                   debugDescription: "bad scriptPubKey hex")
        }
        var tweak: Data?
        if let tweakHex = try container.decodeIfPresent(String.self, forKey: .silentPaymentTweak) {
            guard let decoded = Data(hex: tweakHex) else {
                throw DecodingError.dataCorruptedError(forKey: .silentPaymentTweak, in: container,
                                                       debugDescription: "bad silentPaymentTweak hex")
            }
            tweak = decoded
        }
        self.init(txid: Data(txid.reversed()),
                  vout: try container.decode(UInt32.self, forKey: .vout),
                  amount: try container.decode(Int64.self, forKey: .amount),
                  scriptPubKey: scriptPubKey,
                  chain: try container.decode(AddressChain.self, forKey: .chain),
                  index: try container.decode(UInt32.self, forKey: .index),
                  height: try container.decode(UInt32.self, forKey: .height),
                  silentPaymentTweak: tweak,
                  isCoinbase: try container.decodeIfPresent(Bool.self, forKey: .isCoinbase) ?? false,
                  // Absent in every state file written before #127, which is
                  // exactly right: those wallets deleted spent rows, so any row
                  // still present is unspent.
                  spent: try container.decodeIfPresent(SpentMarker.self, forKey: .spent))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(txid.displayHex, forKey: .txid)
        try container.encode(vout, forKey: .vout)
        try container.encode(amount, forKey: .amount)
        try container.encode(scriptPubKey.hex, forKey: .scriptPubKey)
        try container.encode(chain, forKey: .chain)
        try container.encode(index, forKey: .index)
        try container.encode(height, forKey: .height)
        // Absent for descriptor outputs, so pre-SP state files stay identical.
        try container.encodeIfPresent(silentPaymentTweak?.hex, forKey: .silentPaymentTweak)
        // Absent for live coins, so an unspent row is byte-identical to before.
        try container.encodeIfPresent(spent, forKey: .spent)
        if isCoinbase { try container.encode(true, forKey: .isCoinbase) }
    }
}

/// One line of wallet history: a transaction that paid us and/or spent ours.
public struct HistoryEntry: Equatable, Sendable, Codable {
    public var txid: Data // internal byte order; JSON as display hex
    public var height: UInt32
    /// Total received to our scripts by this tx.
    public var received: Int64
    /// Total of ours spent by this tx.
    public var spent: Int64
    /// Fee paid — known only when every input was ours.
    public var fee: Int64?
    /// The pending transaction that superseded this entry via BIP125. Kept in
    /// history so the old tx is rendered as replaced, not as a second pending
    /// payment. Internal byte order; JSON uses display hex.
    public var replacedBy: Data?

    public init(txid: Data, height: UInt32, received: Int64, spent: Int64,
                fee: Int64? = nil, replacedBy: Data? = nil) {
        self.txid = txid
        self.height = height
        self.received = received
        self.spent = spent
        self.fee = fee
        self.replacedBy = replacedBy
    }

    private enum CodingKeys: String, CodingKey { case txid, height, received, spent, fee, replacedBy }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard let txid = Data(hex: try container.decode(String.self, forKey: .txid)) else {
            throw DecodingError.dataCorruptedError(forKey: .txid, in: container,
                                                   debugDescription: "bad txid hex")
        }
        let replacedBy: Data?
        if let replacementHex = try container.decodeIfPresent(String.self, forKey: .replacedBy) {
            guard let replacement = Data(hex: replacementHex) else {
                throw DecodingError.dataCorruptedError(forKey: .replacedBy, in: container,
                                                       debugDescription: "bad replacement txid hex")
            }
            replacedBy = Data(replacement.reversed())
        } else {
            replacedBy = nil
        }
        self.init(txid: Data(txid.reversed()),
                  height: try container.decode(UInt32.self, forKey: .height),
                  received: try container.decode(Int64.self, forKey: .received),
                  spent: try container.decode(Int64.self, forKey: .spent),
                  fee: try container.decodeIfPresent(Int64.self, forKey: .fee),
                  replacedBy: replacedBy)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(txid.displayHex, forKey: .txid)
        try container.encode(height, forKey: .height)
        try container.encode(received, forKey: .received)
        try container.encode(spent, forKey: .spent)
        try container.encodeIfPresent(fee, forKey: .fee)
        try container.encodeIfPresent(replacedBy?.displayHex, forKey: .replacedBy)
    }
}

/// What applying one matched block changed (drives import verification).
public struct MatchEffect: Equatable, Sendable {
    public struct Spend: Equatable, Sendable {
        public var txid: Data // spent UTXO's txid
        public var vout: UInt32
        public var spentBy: Data // spending txid
        public var height: UInt32

        public init(txid: Data, vout: UInt32, spentBy: Data, height: UInt32) {
            self.txid = txid
            self.vout = vout
            self.spentBy = spentBy
            self.height = height
        }
    }

    public var received: [WalletUTXO] = []
    public var spent: [Spend] = []
    /// Pending conflict-chain transactions invalidated by the confirmed
    /// transaction. Callers should stop relaying these txids.
    public var discardedReplacements: [Data] = []

    public init(received: [WalletUTXO] = [], spent: [Spend] = [],
                discardedReplacements: [Data] = []) {
        self.received = received
        self.spent = spent
        self.discardedReplacements = discardedReplacements
    }
}

/// Private persistence needed to rebuild and sign a same-input replacement
/// after relaunch. The public history deliberately remains a compact display
/// model; this record carries the exact prevouts and raw transaction.
struct PendingSend: Equatable, Sendable, Codable {
    var rawTransaction: Data
    var selected: [WalletUTXO]
    var changeIndex: UInt32?
    var changeOutputIndex: UInt32?
    var fee: Int64

    var transaction: Transaction? { try? Transaction.decode(rawTransaction) }
    var txid: Data? { transaction?.txid }

    private enum CodingKeys: String, CodingKey {
        case rawTransaction, selected, changeIndex, changeOutputIndex, fee
    }

    init(rawTransaction: Data, selected: [WalletUTXO], changeIndex: UInt32?,
         changeOutputIndex: UInt32?, fee: Int64) {
        self.rawTransaction = rawTransaction
        self.selected = selected
        self.changeIndex = changeIndex
        self.changeOutputIndex = changeOutputIndex
        self.fee = fee
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let rawHex = try container.decode(String.self, forKey: .rawTransaction)
        guard let raw = Data(hex: rawHex), (try? Transaction.decode(raw)) != nil else {
            throw DecodingError.dataCorruptedError(forKey: .rawTransaction, in: container,
                                                   debugDescription: "bad raw transaction hex")
        }
        self.init(rawTransaction: raw,
                  selected: try container.decode([WalletUTXO].self, forKey: .selected),
                  changeIndex: try container.decodeIfPresent(UInt32.self, forKey: .changeIndex),
                  changeOutputIndex: try container.decodeIfPresent(UInt32.self, forKey: .changeOutputIndex),
                  fee: try container.decode(Int64.self, forKey: .fee))
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(rawTransaction.hex, forKey: .rawTransaction)
        try container.encode(selected, forKey: .selected)
        try container.encodeIfPresent(changeIndex, forKey: .changeIndex)
        try container.encodeIfPresent(changeOutputIndex, forKey: .changeOutputIndex)
        try container.encode(fee, forKey: .fee)
    }
}

/// The persisted wallet state (JSON at `storageURL`).
public struct WalletState: Codable, Equatable, Sendable {
    public var descriptor: String
    public var network: String
    public var creationHeight: UInt32
    public var nextReceiveIndex: UInt32
    public var nextChangeIndex: UInt32
    /// Height of the next block whose filter must be scanned (mirrors the
    /// FilterSync progress after the last scan).
    public var nextScanHeight: UInt32
    /// Every coin row, spent ones included. Mutations go through this; reads
    /// should almost always use `utxos`, which hides the tombstones.
    public var allUtxos: [WalletUTXO]
    /// The coins the wallet actually has.
    ///
    /// Computed rather than stored so that a spent row cannot reach balance,
    /// coin selection, or the UI by anyone forgetting to filter -- the filter
    /// is the accessor, not N call sites.
    public var utxos: [WalletUTXO] { allUtxos.filter { !$0.isSpent } }
    public var history: [HistoryEntry]
    /// Feerate samples (sat/vB) from our own confirmed transactions, newest last.
    public var observedFeeRates: [Double]
    /// Exact data for locally-created sends that are still replaceable.
    var pendingSends: [PendingSend]

    public init(descriptor: String, network: String, creationHeight: UInt32,
                nextReceiveIndex: UInt32 = 0, nextChangeIndex: UInt32 = 0,
                nextScanHeight: UInt32, utxos: [WalletUTXO] = [],
                history: [HistoryEntry] = [], observedFeeRates: [Double] = []) {
        self.descriptor = descriptor
        self.network = network
        self.creationHeight = creationHeight
        self.nextReceiveIndex = nextReceiveIndex
        self.nextChangeIndex = nextChangeIndex
        self.nextScanHeight = nextScanHeight
        allUtxos = utxos
        self.history = history
        self.observedFeeRates = observedFeeRates
        pendingSends = []
    }

    private enum CodingKeys: String, CodingKey {
        case descriptor, network, creationHeight, nextReceiveIndex, nextChangeIndex
        case nextScanHeight, utxos, history, observedFeeRates, pendingSends
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        descriptor = try container.decode(String.self, forKey: .descriptor)
        network = try container.decode(String.self, forKey: .network)
        creationHeight = try container.decode(UInt32.self, forKey: .creationHeight)
        nextReceiveIndex = try container.decode(UInt32.self, forKey: .nextReceiveIndex)
        nextChangeIndex = try container.decode(UInt32.self, forKey: .nextChangeIndex)
        nextScanHeight = try container.decode(UInt32.self, forKey: .nextScanHeight)
        allUtxos = try container.decode([WalletUTXO].self, forKey: .utxos)
        history = try container.decode([HistoryEntry].self, forKey: .history)
        observedFeeRates = try container.decodeIfPresent([Double].self, forKey: .observedFeeRates) ?? []
        pendingSends = try container.decodeIfPresent([PendingSend].self, forKey: .pendingSends) ?? []

        func validateCoins(_ coins: [WalletUTXO], key: CodingKeys) throws {
            var seen = Set<Transaction.Outpoint>()
            var total: Int64 = 0
            for coin in coins {
                guard coin.txid.count == 32,
                      !coin.scriptPubKey.isEmpty,
                      coin.amount > 0,
                      coin.amount <= BitcoinAmount.maximum,
                      seen.insert(coin.outpoint).inserted
                else {
                    throw DecodingError.dataCorruptedError(
                        forKey: key, in: container,
                        debugDescription: "invalid or duplicate wallet coin")
                }
                let (next, overflow) = total.addingReportingOverflow(coin.amount)
                guard !overflow, next <= BitcoinAmount.maximum else {
                    throw DecodingError.dataCorruptedError(
                        forKey: key, in: container,
                        debugDescription: "wallet coin total exceeds Bitcoin's monetary range")
                }
                total = next
            }
        }
        try validateCoins(utxos, key: .utxos)
        for pending in pendingSends {
            try validateCoins(pending.selected, key: .pendingSends)
            guard pending.fee >= 0, pending.fee <= BitcoinAmount.maximum else {
                throw DecodingError.dataCorruptedError(
                    forKey: .pendingSends, in: container,
                    debugDescription: "pending transaction has an invalid fee")
            }
        }
        guard history.allSatisfy({ entry in
            entry.txid.count == 32
                && (0 ... BitcoinAmount.maximum).contains(entry.received)
                && (0 ... BitcoinAmount.maximum).contains(entry.spent)
                && entry.fee.map { (0 ... BitcoinAmount.maximum).contains($0) } ?? true
        }), observedFeeRates.allSatisfy({ $0.isFinite && $0 > 0 && $0 <= 10_000 }) else {
            throw DecodingError.dataCorruptedError(
                forKey: .history, in: container,
                debugDescription: "wallet history or fee samples contain invalid values")
        }
    }

    /// Written by hand because the stored property is `allUtxos` while the
    /// on-disk key stays `utxos`: the file format does not change, so a state
    /// file written before #127 loads unchanged and one written after is
    /// byte-identical until a coin is actually spent.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(descriptor, forKey: .descriptor)
        try container.encode(network, forKey: .network)
        try container.encode(creationHeight, forKey: .creationHeight)
        try container.encode(nextReceiveIndex, forKey: .nextReceiveIndex)
        try container.encode(nextChangeIndex, forKey: .nextChangeIndex)
        try container.encode(nextScanHeight, forKey: .nextScanHeight)
        try container.encode(allUtxos, forKey: .utxos)
        try container.encode(history, forKey: .history)
        try container.encode(observedFeeRates, forKey: .observedFeeRates)
        try container.encode(pendingSends, forKey: .pendingSends)
    }
}

/// The result of `Wallet.send`: the signed raw transaction plus its PSBT.
public struct BuiltTransaction: Equatable, Sendable {
    public var psbt: PSBT
    /// Fully signed, ready for TxBroadcaster.
    public var transaction: Transaction
    public var fee: Int64
    public var changeAmount: Int64?

    public init(psbt: PSBT, transaction: Transaction, fee: Int64, changeAmount: Int64?) {
        self.psbt = psbt
        self.transaction = transaction
        self.fee = fee
        self.changeAmount = changeAmount
    }
}

/// The economic result of a same-input BIP125 replacement. Previewing does
/// not load keys or mutate wallet state.
public struct FeeBumpPreview: Equatable, Sendable {
    public var originalTxid: Data
    public var currentFeeRateSatPerVByte: Double
    public var feeRateSatPerVByte: Double
    public var fee: Int64
    public var changeAmount: Int64?
    /// Exact non-witness replacement the user reviewed. The signed result
    /// must preserve every input, output, sequence, version, and locktime.
    public var replacementTransaction: Transaction

    public init(originalTxid: Data, currentFeeRateSatPerVByte: Double,
                feeRateSatPerVByte: Double, fee: Int64, changeAmount: Int64?,
                replacementTransaction: Transaction) {
        self.originalTxid = originalTxid
        self.currentFeeRateSatPerVByte = currentFeeRateSatPerVByte
        self.feeRateSatPerVByte = feeRateSatPerVByte
        self.fee = fee
        self.changeAmount = changeAmount
        self.replacementTransaction = replacementTransaction
    }

    /// Binds the signed replacement to the complete reviewed transaction.
    /// Witnesses are intentionally excluded: they are added by signing after
    /// review, while all authorization-relevant transaction fields are fixed.
    public func authorizes(_ built: BuiltTransaction) -> Bool {
        let actual = built.transaction
        let reviewed = replacementTransaction
        guard built.fee == fee,
              built.changeAmount == changeAmount,
              actual.version == reviewed.version,
              actual.locktime == reviewed.locktime,
              actual.outputs == reviewed.outputs,
              actual.inputs.count == reviewed.inputs.count,
              zip(actual.inputs, reviewed.inputs).allSatisfy({ pair in
                  pair.0.previousOutput == pair.1.previousOutput
                      && pair.0.scriptSig == pair.1.scriptSig
                      && pair.0.sequence == pair.1.sequence
              })
        else { return false }

        let vsize = TransactionBuilder.vsize(of: actual)
        return vsize > 0 && Double(built.fee) / Double(vsize) == feeRateSatPerVByte
    }
}

/// The single-sig wallet aggregate (docs/read-side.md: fresh-wallet, forward-
/// only scanning). Keys are BIP86 (m/86'/coin'/account'); the descriptor is
/// the BIP389 multipath form
///
///     tr([MASTERFP/86'/COIN'/0']ACCOUNT_XPUB/<0;1>/*)#checksum
///
/// — one descriptor whose multipath choice 0 is the receive chain and choice 1
/// the change chain (COIN = 0 mainnet, 1 signet/testnet per SLIP-44). The
/// wallet ID is the master key fingerprint (8 hex chars).
///
/// Concurrency: an actor; secrets are only loaded from the KeyStore for the
/// duration of a signing operation, never held in wallet state.
public actor Wallet {
    /// BIP44-style gap limit: how many unused addresses past the last used one
    /// stay on the filter watch list.
    public static let gapLimit: UInt32 = 20
    /// Consensus coinbase maturity (Bitcoin Core `COINBASE_MATURITY`).
    public static let coinbaseMaturity: UInt32 = 100

    public let id: String
    public let network: BitcoinNetwork
    public let descriptor: Descriptor
    /// Neutered account key at m/86'/coin'/0' — public material only.
    public let accountKey: HDKey
    private let keyStore: any KeyStore
    private let storageURL: URL?
    private var state: WalletState
    /// Transient silent-payment scan state: the scanner (which holds b_scan —
    /// deliberately weaker than the signing rule below, a view key can't
    /// spend) and the filter-stage candidates by height. Never persisted.
    private var spScanner: SilentPaymentBlockScanner?
    private var spCandidates: [UInt32: [SilentPaymentCandidate]] = [:]

    init(network: BitcoinNetwork, descriptor: Descriptor, accountKey: HDKey,
         keyStore: any KeyStore, storageURL: URL?, state: WalletState) throws {
        self.network = network
        self.descriptor = descriptor
        self.accountKey = accountKey
        self.keyStore = keyStore
        self.storageURL = storageURL
        self.state = state
        id = String(format: "%08x", try Self.origin(of: descriptor).fingerprint)
    }

    // MARK: - Creation / opening

    /// Creates a fresh wallet: a new BIP39 mnemonic (12 words from 16 bytes of
    /// entropy) stored in the KeyStore, and an empty state scanning forward
    /// from `creationHeight` (a fresh wallet has no history before it).
    public static func create(network: BitcoinNetwork, keyStore: any KeyStore,
                              storageURL: URL? = nil, entropy: Data? = nil,
                              creationHeight: UInt32 = 0, account: UInt32 = 0) throws -> Wallet {
        let mnemonic = try BIP39.mnemonic(entropy: entropy ?? randomEntropy())
        let master = try HDKey(seed: BIP39.seed(mnemonic: mnemonic))
        let coinType = Self.coinType(for: network)
        let accountKey = try BIP86.accountKey(from: master, coinType: coinType, account: account)
        let origin = Descriptor.KeyOrigin(fingerprint: master.fingerprint,
                                          path: [86, coinType, account].map { $0 + HDKey.hardenedOffset })
        let descriptor = Self.makeDescriptor(accountKey: accountKey, origin: origin, network: network)
        let state = WalletState(descriptor: descriptor.serialized(), network: network.rawValue,
                                creationHeight: creationHeight, nextScanHeight: creationHeight)
        let wallet = try Wallet(network: network, descriptor: descriptor,
                                accountKey: accountKey.neutered, keyStore: keyStore,
                                storageURL: storageURL, state: state)
        try keyStore.store(.mnemonic(mnemonic), for: wallet.id)
        do {
            if let storageURL {
                try JSONEncoder().encode(state).write(to: storageURL, options: .atomic)
            }
        } catch {
            // Wallet creation is one logical operation: do not leave a
            // keychain entry that makes an idempotent retry fail after local
            // state persistence was interrupted.
            try? keyStore.delete(walletID: wallet.id)
            throw error
        }
        return wallet
    }

    /// Re-opens a wallet from its persisted JSON state.
    public static func open(storageURL: URL, keyStore: any KeyStore) throws -> Wallet {
        let data = try Data(contentsOf: storageURL)
        let state = try JSONDecoder().decode(WalletState.self, from: data)
        guard let network = BitcoinNetwork(rawValue: state.network) else {
            throw WalletError.invalidBundle("unknown network \(state.network)")
        }
        let descriptor = try Descriptor(state.descriptor)
        _ = try Self.origin(of: descriptor) // validates the wallet descriptor shape
        // The account key is recoverable from the descriptor's xpub.
        guard case let .tr(.single(key), nil) = descriptor.expression,
              case let .extended(accountKey, _) = key.base
        else { throw WalletError.invalidDescriptor(state.descriptor) }
        return try Wallet(network: network, descriptor: descriptor, accountKey: accountKey.neutered,
                          keyStore: keyStore, storageURL: storageURL, state: state)
    }

    /// Builds the canonical multipath tr() descriptor for an account key.
    static func makeDescriptor(accountKey: HDKey, origin: Descriptor.KeyOrigin,
                               network: BitcoinNetwork) -> Descriptor {
        Descriptor(expression: .tr(.single(Descriptor.SingleKey(
            origin: origin,
            base: .extended(accountKey.neutered, network: hdNetwork(for: network)),
            derivation: Descriptor.Derivation([.multipath([0, 1]), .wildcard(hardened: false)]))), nil))
    }

    /// Validates the wallet descriptor shape and returns its key origin.
    static func origin(of descriptor: Descriptor) throws -> Descriptor.KeyOrigin {
        guard case let .tr(.single(key), nil) = descriptor.expression,
              let origin = key.origin,
              key.derivation.elements == [.multipath([0, 1]), .wildcard(hardened: false)]
        else { throw WalletError.invalidDescriptor("expected tr([fp/86'/c'/a']xpub/<0;1>/*)") }
        return origin
    }

    static func coinType(for network: BitcoinNetwork) -> UInt32 {
        network == .mainnet ? 0 : 1 // SLIP-44: all test networks share 1
    }

    static func hdNetwork(for network: BitcoinNetwork) -> HDKey.Network {
        network == .mainnet ? .mainnet : .testnet
    }

    static func randomEntropy() -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0 ..< 16).map { _ in UInt8.random(in: 0 ... 255, using: &generator) })
    }

    // MARK: - Addresses

    public var creationHeight: UInt32 { state.creationHeight }
    public var nextScanHeight: UInt32 { state.nextScanHeight }
    public var nextReceiveIndex: UInt32 { state.nextReceiveIndex }
    public var nextChangeIndex: UInt32 { state.nextChangeIndex }
    /// Safe because every state ingress validates individual coins and the
    /// aggregate against `BitcoinAmount.maximum` before mutation.
    public var balance: Int64 { state.utxos.reduce(0) { $0 + $1.amount } }
    public var utxos: [WalletUTXO] { state.utxos }
    /// Every coin row, spent ones included.
    ///
    /// For rollback and diagnostics only. Never for balance, coin selection,
    /// or anything the user reads as money -- use `utxos` for those, which is
    /// filtered by construction.
    public var allUtxos: [WalletUTXO] { state.allUtxos }
    /// UTXOs consensus allows spending at the last scanned height.
    public var spendableUtxos: [WalletUTXO] { state.utxos.filter(isMature) }

    /// Coinbase outputs need 100 confirmations (`COINBASE_MATURITY`). Tip is
    /// the last fully-scanned height (`nextScanHeight - 1`).
    func isMature(_ utxo: WalletUTXO) -> Bool {
        guard utxo.isCoinbase else { return true }
        let tip = state.nextScanHeight == 0 ? 0 : state.nextScanHeight - 1
        // Subtract only after ordering so a malformed near-UInt32.max height
        // cannot overflow while checking the maturity boundary.
        return tip >= utxo.height && tip - utxo.height >= Self.coinbaseMaturity - 1
    }
    public var history: [HistoryEntry] { state.history }
    public var observedFeeRates: [Double] { state.observedFeeRates }
    /// Locally-created pending sends with persisted metadata and unspent
    /// change available for a same-input fee bump.
    public var feeBumpableTxids: [Data] {
        state.pendingSends.compactMap { pending in
            guard pending.changeIndex != nil, let txid = pending.txid,
                  let vout = pending.changeOutputIndex,
                  state.utxos.contains(where: { $0.txid == txid && $0.vout == vout })
            else { return nil }
            return txid
        }
    }

    /// scriptPubKey at (chain, index), derived from the multipath descriptor.
    public func scriptPubKey(chain: AddressChain, index: UInt32) throws -> Data {
        try descriptor.derived(index: index, network: Self.hdNetwork(for: network))[chain.rawValue].scriptPubKey
    }

    public func address(chain: AddressChain, index: UInt32) throws -> String {
        try descriptor.derived(index: index, network: Self.hdNetwork(for: network))[chain.rawValue].address
    }

    /// The next unused receive address; marks it used (advances the index).
    public func freshReceiveAddress() throws -> String {
        let address = try address(chain: .receive, index: state.nextReceiveIndex)
        state.nextReceiveIndex += 1
        try persist()
        return address
    }

    /// All watched scriptPubKeys: used indices plus the gap-limit lookahead
    /// on both descriptor chains, unioned with every known UTXO script.
    ///
    /// Descriptor lookahead finds new BIP86 payments. Known UTXO scripts find
    /// *spends* of coins we already hold — BIP158 basic filters include the
    /// prevout scriptPubKey. Silent-payment outputs are not on the descriptor
    /// chains, so omitting them lets a third-party spend (or a no-change send
    /// that never confirms locally) pass the filter unnoticed: `apply` would
    /// have removed the UTXO if the block had been fetched. Import
    /// verification (`docs/import.md` §3) relies on this same list to put
    /// claimed scripts in the filter stream.
    public func watchScripts() throws -> [Data] {
        var scripts = Set(try watchMap().keys)
        // Spent rows included. Their scripts must stay in the filter stream so
        // a rescan after a reorg can re-find the coin (#127), and watching a
        // script we already know about discloses nothing new.
        for utxo in state.allUtxos {
            scripts.insert(utxo.scriptPubKey)
        }
        return Array(scripts)
    }

    /// Watched scriptPubKey → owning (chain, index).
    private func watchMap() throws -> [Data: (chain: AddressChain, index: UInt32)] {
        var map: [Data: (AddressChain, UInt32)] = [:]
        for chain in [AddressChain.receive, AddressChain.change] {
            let next = chain == .receive ? state.nextReceiveIndex : state.nextChangeIndex
            for index in 0 ..< next + Self.gapLimit {
                map[try scriptPubKey(chain: chain, index: index)] = (chain, index)
            }
        }
        return map
    }

    // MARK: - Scanning

    /// Forward-only filter scan (docs/read-side.md §2.5): matched blocks are
    /// applied to the UTXO set and history; the scan position mirrors into the
    /// persisted state afterwards. With a tweak index, silent-payment
    /// candidates ride the same filter stream (fail-closed — see
    /// FilterSync.sync).
    public func scan(using sync: FilterSync,
                     silentPaymentIndex: (any TweakIndexClient)? = nil) async throws {
        let scripts = try watchScripts()
        var extras: (@Sendable (ClosedRange<UInt32>) async throws -> [UInt32: [Data]])?
        if let index = silentPaymentIndex {
            extras = { range in
                try await self.silentPaymentCandidateScripts(range: range, index: index)
            }
        }
        try await sync.sync(watchScripts: scripts, extraScripts: extras) { match in
            try await self.apply(match: match)
        }
        try recordScanHeight(await sync.nextScanHeight)
    }

    /// Mirrors FilterSync's frontier into persisted wallet state.
    ///
    /// `apply(match:)` does not move `nextScanHeight` — only this call (or
    /// `scan(using:)`, which ends in it) does. The live app drives FilterSync
    /// directly and must record after each pass, or `exportBundle()` will
    /// emit the creation/import height while the UI shows the filter actor.
    public func recordScanHeight(_ nextScanHeight: UInt32) throws {
        state.nextScanHeight = nextScanHeight
        pruneSpentCoins(scannedTo: nextScanHeight)
        try persist()
    }

    /// How far back spent rows are kept.
    ///
    /// A tombstone exists so a reorg can restore the coin, so it only needs to
    /// outlive the deepest reorg worth surviving. Bitcoin reorgs beyond a
    /// handful of blocks are extraordinary; 100 is the same depth consensus
    /// already uses for coinbase maturity, which makes it a familiar number
    /// rather than a new one to justify.
    ///
    /// Past this depth the information is gone and a reorg that deep needs a
    /// full re-derive from `creationHeight` instead. That is correct but slow,
    /// and a reorg that deep is a different kind of event anyway (#127).
    public static let spentCoinHorizon: UInt32 = 100

    /// Drops spent rows buried deeper than the horizon, so the state file does
    /// not grow without bound in a wallet that spends often.
    ///
    /// Only *confirmed* spends are pruned. A spend with no height is still in
    /// flight, has no depth to measure, and must stay until a block decides
    /// what happened to it.
    private func pruneSpentCoins(scannedTo nextScanHeight: UInt32) {
        guard nextScanHeight > Self.spentCoinHorizon else { return }
        let cutoff = nextScanHeight - Self.spentCoinHorizon
        state.allUtxos.removeAll { utxo in
            guard let spentHeight = utxo.spent?.height else { return false }
            return spentHeight < cutoff
        }
    }

    /// Per-height silent-payment candidate scripts for a filter batch: the
    /// index's tweaks become k=0 output scripts under this wallet's keys.
    /// Hand the result to FilterSync's `extraScripts`; the candidates stay
    /// cached so `apply(match:)` can credit silent payments in matched blocks.
    public func silentPaymentCandidateScripts(
        range: ClosedRange<UInt32>, index: any TweakIndexClient) async throws -> [UInt32: [Data]] {
        let scanner = try spBlockScanner()
        // The frontier is forward-only; drop cache entries the scan moved past.
        spCandidates = spCandidates.filter { $0.key >= range.lowerBound }
        var scripts: [UInt32: [Data]] = [:]
        for height in range {
            let tweaks = try await index.tweaks(forBlockAt: height)
            guard !tweaks.isEmpty else { continue }
            let candidates = try scanner.candidates(tweaks: tweaks)
            spCandidates[height] = candidates
            scripts[height] = candidates.map(\.script)
        }
        return scripts
    }

    private func spBlockScanner() throws -> SilentPaymentBlockScanner {
        if let spScanner { return spScanner }
        let master = try masterKey()
        let coinType = Self.coinType(for: network)
        let scan = try SilentPaymentReceiving.scanKey(from: master, coinType: coinType,
                                                      account: accountIndex)
        let spend = try SilentPaymentReceiving.spendKey(from: master, coinType: coinType,
                                                        account: accountIndex)
        guard let scanSecret = scan.privateKey else {
            throw WalletError.invalidDescriptor("neutered key in scan path")
        }
        let scanner = SilentPaymentBlockScanner(scanPrivateKey: scanSecret,
                                                spendPublicKey: spend.publicKey)
        spScanner = scanner
        return scanner
    }

    /// Consumes one matched block: pays to watched scripts become UTXOs (and
    /// advance gap-limit bookkeeping), spends of our UTXOs shrink the set, and
    /// any touching transaction lands in history. Idempotent per block.
    @discardableResult
    public func apply(match: BlockMatch) throws -> MatchEffect {
        // Validate the whole matched block before changing a single coin. A
        // merkle proof authenticates bytes under the header; it does not by
        // itself enforce Bitcoin's transaction-value consensus rules for an
        // SPV wallet. This also preserves atomicity when a later transaction
        // in the block is malformed.
        for tx in match.block.transactions {
            var outputTotal: Int64 = 0
            for output in tx.outputs {
                guard output.value >= 0, output.value <= BitcoinAmount.maximum else {
                    throw WalletError.invalidTransactionAmounts
                }
                let (next, overflow) = outputTotal.addingReportingOverflow(output.value)
                guard !overflow, next <= BitcoinAmount.maximum else {
                    throw WalletError.invalidTransactionAmounts
                }
                outputTotal = next
            }
        }
        let map = try watchMap()
        // Silent payments: resolve this height's cached filter-stage
        // candidates against the merkle-verified block. The index only
        // steered the block fetch — credits come from the block itself.
        var silentPaymentsByTxid: [Data: [SilentPaymentFound]] = [:]
        if let candidates = spCandidates[match.height], let scanner = spScanner {
            silentPaymentsByTxid = Dictionary(
                grouping: try scanner.matches(in: match.block, candidates: candidates),
                by: \.txid)
        }
        // Everything below is one state transition. If the matched block
        // would violate the wallet-wide monetary invariant (or persistence
        // fails), restore the exact pre-block state before returning an error.
        let stateBeforeBlock = state
        var committed = false
        defer {
            if !committed { state = stateBeforeBlock }
        }
        var effect = MatchEffect()
        for tx in match.block.transactions {
            let txid = tx.txid
            effect.discardedReplacements += reconcileReplacementDescendants(ifAncestorConfirmed: txid)
            let conflictingPending = reconcilePendingConflict(confirmed: tx)
            if let conflictingTxid = conflictingPending?.txid {
                effect.discardedReplacements.append(conflictingTxid)
            }
            let isCoinbase = tx.inputs.first.map {
                $0.previousOutput.txid == Data(repeating: 0, count: 32)
                    && $0.previousOutput.vout == 0xFFFF_FFFF
            } ?? false
            var spentAmount: Int64 = 0
            var receivedAmount: Int64 = 0
            var allInputsOurs = !isCoinbase && !tx.inputs.isEmpty

            if !isCoinbase {
                for input in tx.inputs {
                    // Indexed into `allUtxos`, and only unspent rows count: a
                    // tombstone is not a coin, and an index into the filtered
                    // view would address the wrong row here.
                    guard let index = state.allUtxos.firstIndex(where: {
                        !$0.isSpent
                            && $0.txid == input.previousOutput.txid
                            && $0.vout == input.previousOutput.vout
                    }) else {
                        // A coin we already tombstoned at commit, now being
                        // confirmed. The marker was written with no height
                        // because the spend was only in flight; this is the
                        // moment that stops being true, and it is the only
                        // place the height can be learned.
                        //
                        // Without it every own spend leaves a row that pruning
                        // can never reach -- pruning only measures depth, and
                        // a nil height has none -- and a rollback cannot tell
                        // "still in flight" from "confirmed and buried", which
                        // is the whole reason the height is recorded.
                        //
                        // `spentBy` is rewritten to the confirming transaction
                        // rather than kept: under RBF the replacement is what
                        // confirms, and a marker naming the superseded txid
                        // describes a transaction that no longer exists.
                        if let pendingIndex = state.allUtxos.firstIndex(where: {
                            $0.spent?.height == nil && $0.spent != nil
                                && $0.txid == input.previousOutput.txid
                                && $0.vout == input.previousOutput.vout
                        }) {
                            state.allUtxos[pendingIndex].spent =
                                WalletUTXO.SpentMarker(spentBy: txid, height: match.height)
                        }
                        // Accounting is unchanged: before tombstones this row
                        // was gone by now, so it never contributed here, and
                        // the pending-send path below supplies the amounts.
                        allInputsOurs = false
                        continue
                    }
                    // Marked, not removed: rescanning forward from a fork
                    // cannot recreate a coin created below it (#127).
                    state.allUtxos[index].spent = WalletUTXO.SpentMarker(spentBy: txid,
                                                                         height: match.height)
                    let utxo = state.allUtxos[index]
                    spentAmount += utxo.amount
                    effect.spent.append(MatchEffect.Spend(txid: utxo.txid, vout: utxo.vout,
                                                          spentBy: txid, height: match.height))
                }
            }
            if conflictingPending != nil {
                // The original inputs left the spendable set when its pending
                // send was committed. Exact input-set equality supplies their
                // persisted amounts when a different replacement confirms.
                allInputsOurs = true
            }

            for (vout, output) in tx.outputs.enumerated() {
                // Zero-value outputs are consensus-valid. They are not coins,
                // and admitting one would violate the positive-UTXO invariant
                // below and wedge this forward-only scan at the same block.
                guard output.value > 0,
                      let (chain, index) = map[output.scriptPubKey]
                else { continue }
                if let existing = state.allUtxos.firstIndex(where: {
                    $0.txid == txid && $0.vout == UInt32(vout)
                }) {
                    // Already known: either a re-applied block, or our own
                    // pending change output being confirmed — update its height.
                    state.allUtxos[existing].height = match.height
                    continue
                }
                let utxo = WalletUTXO(txid: txid, vout: UInt32(vout), amount: output.value,
                                      scriptPubKey: output.scriptPubKey, chain: chain,
                                      index: index, height: match.height,
                                      isCoinbase: isCoinbase)
                state.allUtxos.append(utxo)
                receivedAmount += output.value
                effect.received.append(utxo)
                switch chain {
                case .receive where index >= state.nextReceiveIndex:
                    state.nextReceiveIndex = index + 1
                case .change where index >= state.nextChangeIndex:
                    state.nextChangeIndex = index + 1
                default:
                    break
                }
            }

            // Silent-payment outputs of this tx: same idempotency guard as
            // above, and folded into `receivedAmount` so a tx paying us both
            // ways still yields one merged history entry.
            for found in silentPaymentsByTxid[txid] ?? [] {
                // Checked against every row, spent ones included: a coin that
                // has been spent must not be re-added as live by a re-applied
                // block.
                guard found.amount > 0,
                      !state.allUtxos.contains(where: { $0.txid == found.txid && $0.vout == found.vout })
                else { continue }
                let utxo = WalletUTXO(txid: found.txid, vout: found.vout, amount: found.amount,
                                      scriptPubKey: found.scriptPubKey, chain: .receive,
                                      index: 0, height: match.height,
                                      silentPaymentTweak: found.tweak)
                state.allUtxos.append(utxo)
                receivedAmount += found.amount
                effect.received.append(utxo)
            }

            let accountedSpent = conflictingPending?.selected.reduce(Int64(0)) {
                $0 + $1.amount
            } ?? spentAmount
            let touchesWallet = spentAmount > 0 || receivedAmount > 0 || conflictingPending != nil
                || state.history.contains(where: { $0.txid == txid })
            guard touchesWallet else { continue }

            // Fee + feerate sample: exact only when every input was ours (the
            // BIP341 sighash commits to amounts, so our own sends qualify).
            var fee: Int64? = nil
            if allInputsOurs, accountedSpent > 0 {
                let candidate = accountedSpent - tx.outputs.reduce(0) { $0 + $1.value }
                if candidate > 0 {
                    fee = candidate
                    let vsize = TransactionBuilder.vsize(of: tx)
                    if vsize > 0 {
                        state.observedFeeRates.append(Double(candidate) / Double(vsize))
                        if state.observedFeeRates.count > 20 { state.observedFeeRates.removeFirst() }
                    }
                }
            }
            if let existing = state.history.firstIndex(where: { $0.txid == txid }) {
                // Known pending send (height 0) reaching confirmation.
                state.history[existing].height = match.height
            } else {
                state.history.append(HistoryEntry(txid: txid, height: match.height,
                                                  received: receivedAmount, spent: accountedSpent, fee: fee))
            }
            state.pendingSends.removeAll { $0.txid == txid }
        }
        var walletTotal: Int64 = 0
        for coin in state.utxos {
            let (next, overflow) = walletTotal.addingReportingOverflow(coin.amount)
            guard coin.amount > 0, coin.amount <= BitcoinAmount.maximum,
                  !overflow, next <= BitcoinAmount.maximum else {
                throw WalletError.invalidTransactionAmounts
            }
            walletTotal = next
        }
        try persist()
        committed = true
        return effect
    }

    /// A replacement is only a proposal until one member of its conflict
    /// chain confirms. If an ancestor wins the race, discard every descendant
    /// and its locally-counted pending change before applying the winner.
    private func reconcileReplacementDescendants(ifAncestorConfirmed txid: Data) -> [Data] {
        guard let root = state.history.firstIndex(where: { $0.txid == txid }),
              state.history[root].replacedBy != nil else { return [] }
        var descendants: [Data] = []
        var next = state.history[root].replacedBy
        while let txid = next, !descendants.contains(txid) {
            descendants.append(txid)
            next = state.history.first(where: { $0.txid == txid })?.replacedBy
        }
        state.history[root].replacedBy = nil
        // A genuine removal, not a tombstone: these are outputs of transactions
        // that were replaced and never existed on the surviving chain, so a
        // rescan would not re-find them and there is nothing to restore.
        state.allUtxos.removeAll { utxo in descendants.contains(utxo.txid) }
        state.pendingSends.removeAll { pending in
            pending.txid.map(descendants.contains) ?? false
        }
        state.history.removeAll { entry in descendants.contains(entry.txid) }
        return descendants
    }

    /// Handles a replacement that reached the chain without a committed local
    /// state swap (for example, persistence failed after broadcast). Pending
    /// sends retain the exact inputs, so an exact-input conflict can remove the
    /// losing change and preserve correct history/balance accounting.
    private func reconcilePendingConflict(confirmed transaction: Transaction) -> PendingSend? {
        let confirmedInputs = transaction.inputs.map(\.previousOutput)
        guard let index = state.pendingSends.firstIndex(where: { pending in
            guard pending.txid != transaction.txid, let candidate = pending.transaction else {
                return false
            }
            var unmatched = confirmedInputs
            for outpoint in candidate.inputs.map(\.previousOutput) {
                guard let match = unmatched.firstIndex(of: outpoint) else { return false }
                unmatched.remove(at: match)
            }
            return unmatched.isEmpty
        }) else { return nil }

        let pending = state.pendingSends.remove(at: index)
        guard let pendingTxid = pending.txid else { return pending }
        // Outputs of the superseded pending send -- removed, not tombstoned,
        // for the same reason as the descendants above.
        state.allUtxos.removeAll { $0.txid == pendingTxid }
        if let historyIndex = state.history.firstIndex(where: { $0.txid == pendingTxid }) {
            state.history[historyIndex].replacedBy = transaction.txid
        }
        return pending
    }

    // MARK: - Sending

    /// A fully signed, ready-to-broadcast transaction whose selection has NOT
    /// yet been committed to wallet state. Hand `built.transaction` to the
    /// broadcaster, then call `commit(_:)` — never the other way around.
    public struct PreparedSend: Sendable {
        public let built: BuiltTransaction
        /// Public BIP352 input_hash·A for a silent-payment transaction. nil
        /// for an ordinary send; safe to hand to a receiver-side tweak index.
        public let silentPaymentTweakData: Data?
        /// The silent payments of this send with their derived P2TR scripts,
        /// index-aligned with the `silentPayments` argument that produced them.
        ///
        /// A BIP352 output script cannot be known until coin selection has
        /// fixed the input set, and deriving it needs those inputs' private
        /// keys — so it happens in here, and the review layer has no way to
        /// compute it. Without this the app can see a silent-payment output in
        /// the built transaction but cannot tell which reviewed recipient it
        /// belongs to, which is why `SendPreview.authorizes` was unable to
        /// bind silent payments at all.
        public let resolvedSilentPayments: [Payment]
        let selected: [WalletUTXO]
        let change: Payment?
        let changeIndex: UInt32
        let changeOutputIndex: UInt32?
        let fee: Int64
    }

    /// Builds, signs and finalizes a transaction paying `payments` at the given
    /// feerate: coin selection (largest-first, dust-guarded) → unsigned tx →
    /// PSBT creator → per-input key-path signer → finalizer/extractor. The
    /// change output, when any, goes to the next unused internal address.
    ///
    /// `silentPayments` are BIP352 destinations: their P2TR output scripts are
    /// derived after coin selection, when the input set and its keys are known
    /// (BIP352 §Creating outputs), and replace the same-size placeholders used
    /// for fee estimation. Signing stays SIGHASH_DEFAULT — the BIP352-safe
    /// sighash for taproot inputs.
    /// `chainTip` is the validated header-chain tip, and carries no default:
    /// omitting it is what stamps a fingerprint onto the chain (#139), so every
    /// call site is made to decide rather than inherit a silent zero.
    public func buildSend(payments: [Payment], feeRateSatPerVByte: Double,
                          silentPayments: [SilentPayment] = [],
                          chainTip: UInt32,
                          randomness: @Sendable () -> Double = { Double.random(in: 0 ..< 1) }
    ) throws -> PreparedSend {
        guard !payments.isEmpty || !silentPayments.isEmpty else { throw WalletError.noPayments }
        let changeIndex = state.nextChangeIndex
        let changeScript = try scriptPubKey(chain: .change, index: changeIndex)
        let sizingPayments = payments + silentPayments.map {
            Payment(amount: $0.amount, scriptPubKey: SilentPayment.sizingScriptPubKey)
        }
        let selection = try CoinSelection.select(utxos: spendableUtxos, payments: sizingPayments,
                                                 changeScriptPubKey: changeScript,
                                                 feeRateSatPerVByte: feeRateSatPerVByte)
        // Resolve silent payment outputs: the shared secrets commit to the
        // selected inputs, so derivation happens here — at signing time, with
        // the tweaked input keys in hand. All inputs are our own P2TR key-path
        // spends, which is exactly the BIP352 wallet case.
        var resolvedPayments = payments
        var resolvedSilentPayments: [Payment] = []
        var silentPaymentTweakData: Data?
        if !silentPayments.isEmpty {
            let inputs = try selection.selected.map { utxo in
                try SilentPaymentSending.Input(txid: utxo.txid, vout: utxo.vout,
                                               prevoutScriptPubKey: utxo.scriptPubKey,
                                               privateKey: keyPathSecret(for: utxo))
            }
            silentPaymentTweakData = try SilentPaymentSending.tweakData(
                context: SilentPaymentSending.context(inputs: inputs))
            let scripts = try SilentPaymentSending.outputScripts(
                inputs: inputs, recipients: silentPayments.map(\.address))
            resolvedSilentPayments = zip(silentPayments, scripts).map {
                Payment(amount: $0.amount, scriptPubKey: $1)
            }
            resolvedPayments += resolvedSilentPayments
        }
        let change = selection.changeAmount.map { Payment(amount: $0, scriptPubKey: changeScript) }
        let tx = try TransactionBuilder.build(
            inputs: selection.selected.map(\.outpoint), payments: resolvedPayments, change: change,
            locktime: TransactionBuilder.antiFeeSnipingLocktime(tip: chainTip, randomness: randomness))
        let changeOutputIndex = change.flatMap { change in
            tx.outputs.firstIndex { $0.scriptPubKey == change.scriptPubKey && $0.value == change.amount }
        }
        let (psbt, signed) = try sign(transaction: tx, selected: selection.selected,
                                      changeIndex: changeOutputIndex.map { _ in changeIndex },
                                      changeOutputIndex: changeOutputIndex)

        let built = BuiltTransaction(psbt: psbt, transaction: signed, fee: selection.fee,
                                     changeAmount: selection.changeAmount)
        return PreparedSend(built: built, silentPaymentTweakData: silentPaymentTweakData,
                            resolvedSilentPayments: resolvedSilentPayments,
                            selected: selection.selected, change: change,
                            changeIndex: changeIndex,
                            changeOutputIndex: changeOutputIndex.map(UInt32.init), fee: selection.fee)
    }

    /// Commits a prepared send to wallet state: the spent UTXOs leave the
    /// spendable set at once (so a second send can't double-spend the
    /// unconfirmed tx) and the change output enters it as pending (height 0)
    /// until a block match confirms it and updates the height.
    ///
    /// Call this ONLY after the transaction has been handed to the broadcaster,
    /// never before: committing first means a broadcast that never leaves the
    /// device (no stack, disk error) strands the inputs in a locally-spent but
    /// on-chain-unspent limbo that forward-only scanning cannot repair.
    public func commit(_ prepared: PreparedSend) throws {
        let signed = prepared.built.transaction
        // Tombstoned with no height: the spend exists only in our own pending
        // transaction. A rollback must leave these reserved even while it
        // restores confirmed spends, or the wallet re-selects coins its own
        // in-flight transaction is already spending and double-spends itself.
        for index in state.allUtxos.indices
        where prepared.selected.contains(where: { $0.outpoint == state.allUtxos[index].outpoint }) {
            state.allUtxos[index].spent = WalletUTXO.SpentMarker(spentBy: signed.txid, height: nil)
        }
        if let change = prepared.change {
            guard let vout = prepared.changeOutputIndex,
                  signed.outputs.indices.contains(Int(vout)),
                  signed.outputs[Int(vout)].scriptPubKey == change.scriptPubKey,
                  signed.outputs[Int(vout)].value == change.amount
            else { throw WalletError.changeOutputMissing }
            state.allUtxos.append(WalletUTXO(txid: signed.txid, vout: vout, amount: change.amount,
                                          scriptPubKey: change.scriptPubKey, chain: .change,
                                          index: prepared.changeIndex, height: 0))
            state.nextChangeIndex += 1
        }
        state.history.append(HistoryEntry(txid: signed.txid, height: 0,
                                          received: prepared.change?.amount ?? 0,
                                          spent: prepared.selected.reduce(0) { $0 + $1.amount },
                                          fee: prepared.fee))
        state.pendingSends.append(PendingSend(
            rawTransaction: signed.serialized(includeWitness: true), selected: prepared.selected,
            changeIndex: prepared.change == nil ? nil : prepared.changeIndex,
            changeOutputIndex: prepared.changeOutputIndex, fee: prepared.fee))
        try persist()
    }

    /// Convenience: build, sign and immediately commit, with no external
    /// broadcast step in between. Prefer `buildSend` → broadcast → `commit`
    /// wherever a broadcaster exists, so a failed broadcast rolls back cleanly.
    @discardableResult
    public func send(payments: [Payment], feeRateSatPerVByte: Double,
                     silentPayments: [SilentPayment] = [],
                     chainTip: UInt32,
                     randomness: @Sendable () -> Double = { Double.random(in: 0 ..< 1) }
    ) throws -> BuiltTransaction {
        let prepared = try buildSend(payments: payments, feeRateSatPerVByte: feeRateSatPerVByte,
                                     silentPayments: silentPayments, chainTip: chainTip,
                                     randomness: randomness)
        try commit(prepared)
        return prepared.built
    }

    // MARK: - Fee bumping

    /// Prepared replacement whose wallet mutation is deferred until after the
    /// new transaction has been accepted by the broadcaster.
    public struct PreparedFeeBump: Sendable {
        public let originalTxid: Data
        public let built: BuiltTransaction
        let selected: [WalletUTXO]
        let originalChangeOutputIndex: UInt32
        let change: Payment?
        let changeIndex: UInt32
        let changeOutputIndex: UInt32?
    }

    private struct FeeBumpCandidate {
        var pending: PendingSend
        var originalTxid: Data
        var transaction: Transaction
        var fee: Int64
        var change: Payment?
        var changeIndex: UInt32
        var originalChangeOutputIndex: UInt32
        var changeOutputIndex: UInt32?
        var currentFeeRate: Double
        var replacementFeeRate: Double
    }

    /// Bitcoin Core's default incremental relay fee. BIP125 rule 4 requires
    /// the fee increase to pay at least this rate for the replacement's own
    /// virtual size, in addition to exceeding the original absolute fee.
    static let incrementalRelayFeeSatPerVByte = 1.0

    public func pendingFeeRate(txid: Data) throws -> Double {
        guard let pending = state.pendingSends.first(where: { $0.txid == txid }),
              let transaction = pending.transaction else { throw FeeBumpError.transactionNotPending }
        let vsize = TransactionBuilder.vsize(of: transaction)
        guard vsize > 0 else { throw FeeBumpError.transactionNotPending }
        return Double(pending.fee) / Double(vsize)
    }

    /// Computes the exact replacement fee and remaining change without
    /// loading the seed, signing, or changing wallet state.
    public func previewFeeBump(txid: Data, feeRateSatPerVByte: Double) throws -> FeeBumpPreview {
        let candidate = try feeBumpCandidate(txid: txid, feeRateSatPerVByte: feeRateSatPerVByte)
        return FeeBumpPreview(originalTxid: txid,
                              currentFeeRateSatPerVByte: candidate.currentFeeRate,
                              feeRateSatPerVByte: candidate.replacementFeeRate,
                              fee: candidate.fee, changeAmount: candidate.change?.amount,
                              replacementTransaction: candidate.transaction)
    }

    /// Rebuilds and signs a BIP125 replacement with the same inputs and
    /// recipient outputs. The original change output is shrunk, or removed if
    /// the remainder would be dust. Like `buildSend`, this is mutation-free.
    public func buildFeeBump(txid: Data, feeRateSatPerVByte: Double) throws -> PreparedFeeBump {
        let candidate = try feeBumpCandidate(txid: txid, feeRateSatPerVByte: feeRateSatPerVByte)
        let (psbt, signed) = try sign(
            transaction: candidate.transaction, selected: candidate.pending.selected,
            changeIndex: candidate.change.map { _ in candidate.changeIndex },
            changeOutputIndex: candidate.changeOutputIndex.map(Int.init))
        let built = BuiltTransaction(psbt: psbt, transaction: signed, fee: candidate.fee,
                                     changeAmount: candidate.change?.amount)
        return PreparedFeeBump(originalTxid: txid, built: built,
                               selected: candidate.pending.selected,
                               originalChangeOutputIndex: candidate.originalChangeOutputIndex,
                               change: candidate.change, changeIndex: candidate.changeIndex,
                               changeOutputIndex: candidate.changeOutputIndex)
    }

    /// Applies a replacement after it has been handed to the broadcaster.
    /// The original history row becomes `replaced`, its pending change is
    /// swapped for the replacement's change, and the derivation index is not
    /// advanced a second time because the same change script is reused.
    public func commitFeeBump(_ prepared: PreparedFeeBump) throws {
        guard let pendingIndex = state.pendingSends.firstIndex(where: {
            $0.txid == prepared.originalTxid
        }), let historyIndex = state.history.firstIndex(where: {
            $0.txid == prepared.originalTxid && $0.height == 0 && $0.replacedBy == nil
        }) else { throw FeeBumpError.transactionNotPending }

        let signed = prepared.built.transaction
        var updated = state
        // The replaced transaction's own change output: superseded, never on
        // chain, nothing to restore.
        updated.allUtxos.removeAll {
            $0.txid == prepared.originalTxid && $0.vout == prepared.originalChangeOutputIndex
        }
        if let change = prepared.change {
            guard let vout = prepared.changeOutputIndex,
                  signed.outputs.indices.contains(Int(vout)),
                  signed.outputs[Int(vout)].scriptPubKey == change.scriptPubKey,
                  signed.outputs[Int(vout)].value == change.amount
            else { throw WalletError.changeOutputMissing }
            updated.allUtxos.append(WalletUTXO(txid: signed.txid, vout: vout, amount: change.amount,
                                          scriptPubKey: change.scriptPubKey, chain: .change,
                                          index: prepared.changeIndex, height: 0))
        }
        updated.history[historyIndex].replacedBy = signed.txid
        updated.history.append(HistoryEntry(
            txid: signed.txid, height: 0, received: prepared.change?.amount ?? 0,
            spent: prepared.selected.reduce(0) { $0 + $1.amount }, fee: prepared.built.fee))
        updated.pendingSends.remove(at: pendingIndex)
        updated.pendingSends.append(PendingSend(
            rawTransaction: signed.serialized(includeWitness: true), selected: prepared.selected,
            changeIndex: prepared.change == nil ? nil : prepared.changeIndex,
            changeOutputIndex: prepared.changeOutputIndex, fee: prepared.built.fee))
        try persist(updated)
        state = updated
    }

    private func feeBumpCandidate(txid: Data, feeRateSatPerVByte: Double) throws -> FeeBumpCandidate {
        guard feeRateSatPerVByte.isFinite, feeRateSatPerVByte > 0,
              feeRateSatPerVByte <= 10_000 else {
            throw FeeBumpError.invalidFeeRate(feeRateSatPerVByte)
        }
        guard let pending = state.pendingSends.first(where: { $0.txid == txid }),
              let original = pending.transaction,
              let changeIndex = pending.changeIndex,
              let originalChangeOutputIndex = pending.changeOutputIndex,
              original.outputs.indices.contains(Int(originalChangeOutputIndex))
        else {
            if state.pendingSends.contains(where: { $0.txid == txid }) {
                throw FeeBumpError.noChangeOutput
            }
            throw FeeBumpError.transactionNotPending
        }
        guard state.utxos.contains(where: {
            $0.txid == txid && $0.vout == originalChangeOutputIndex
        }) else { throw FeeBumpError.changeAlreadySpent }
        let oldVSize = TransactionBuilder.vsize(of: original)
        guard oldVSize > 0 else { throw FeeBumpError.transactionNotPending }
        let currentRate = Double(pending.fee) / Double(oldVSize)
        guard feeRateSatPerVByte > currentRate else {
            throw FeeBumpError.feeRateNotHigher(current: currentRate, requested: feeRateSatPerVByte)
        }

        let changeOutput = original.outputs[Int(originalChangeOutputIndex)]
        let payments = original.outputs.enumerated().compactMap { index, output -> Payment? in
            index == Int(originalChangeOutputIndex) ? nil
                : Payment(amount: output.value, scriptPubKey: output.scriptPubKey)
        }
        let inputTotal = pending.selected.reduce(Int64(0)) { $0 + $1.amount }
        let paymentTotal = payments.reduce(Int64(0)) { $0 + $1.amount }
        let maximumFee = inputTotal - paymentTotal

        func requiredFee(vsize: Int) -> Int64 {
            let requested = Int64((Double(vsize) * feeRateSatPerVByte).rounded(.up))
            let incremental = Int64((Double(vsize) * Self.incrementalRelayFeeSatPerVByte).rounded(.up))
            return max(requested, pending.fee + incremental)
        }

        let withChangeOutputs = payments.map {
            Transaction.Output(value: $0.amount, scriptPubKey: $0.scriptPubKey)
        } + [changeOutput]
        let withChangeVSize = TransactionBuilder.signedVSize(
            inputCount: pending.selected.count, outputs: withChangeOutputs)
        let feeWithChange = requiredFee(vsize: withChangeVSize)
        let candidateChange = inputTotal - paymentTotal - feeWithChange

        let transaction: Transaction
        let fee: Int64
        let change: Payment?
        let replacementChangeOutputIndex: UInt32?
        let dust = CoinSelection.dustThreshold(scriptPubKey: changeOutput.scriptPubKey)
        if candidateChange >= dust {
            change = Payment(amount: candidateChange, scriptPubKey: changeOutput.scriptPubKey)
            fee = feeWithChange
            transaction = try TransactionBuilder.build(
                inputs: original.inputs.map(\.previousOutput), payments: payments, change: change,
                changePosition: Int(originalChangeOutputIndex), sequence: TransactionBuilder.defaultSequence,
                locktime: original.locktime)
            replacementChangeOutputIndex = originalChangeOutputIndex
        } else {
            let noChangeOutputs = payments.map {
                Transaction.Output(value: $0.amount, scriptPubKey: $0.scriptPubKey)
            }
            let noChangeVSize = TransactionBuilder.signedVSize(
                inputCount: pending.selected.count, outputs: noChangeOutputs)
            let minimum = requiredFee(vsize: noChangeVSize)
            guard maximumFee >= minimum else {
                throw FeeBumpError.insufficientChange(requiredFee: minimum, maximumFee: maximumFee)
            }
            change = nil
            fee = maximumFee
            transaction = try TransactionBuilder.build(
                inputs: original.inputs.map(\.previousOutput), payments: payments,
                sequence: TransactionBuilder.defaultSequence, locktime: original.locktime)
            replacementChangeOutputIndex = nil
        }

        let replacementVSize = TransactionBuilder.signedVSize(
            inputCount: pending.selected.count, outputs: transaction.outputs)
        let actualRate = Double(fee) / Double(replacementVSize)
        guard fee > pending.fee, actualRate > currentRate else {
            throw FeeBumpError.insufficientChange(requiredFee: pending.fee + 1,
                                                  maximumFee: maximumFee)
        }
        return FeeBumpCandidate(pending: pending, originalTxid: txid, transaction: transaction,
                                fee: fee, change: change, changeIndex: changeIndex,
                                originalChangeOutputIndex: originalChangeOutputIndex,
                                changeOutputIndex: replacementChangeOutputIndex,
                                currentFeeRate: currentRate, replacementFeeRate: actualRate)
    }

    /// Builds PSBTv2 input/output metadata, signs every P2TR key-path input,
    /// finalizes, and extracts. Shared by first sends and replacements so the
    /// signing path cannot drift.
    private func sign(transaction: Transaction, selected: [WalletUTXO],
                      changeIndex: UInt32?, changeOutputIndex: Int?) throws -> (PSBT, Transaction) {
        let origin = try Self.origin(of: descriptor)
        let inputInfo = try selected.map { utxo -> PSBT.InputInfo in
            // Silent-payment inputs have no BIP86 derivation coordinates to
            // advertise; their key-path secret is b_spend + tweak.
            guard utxo.silentPaymentTweak == nil else {
                return PSBT.InputInfo(spentOutput: utxo.spentOutput, key: nil)
            }
            return try PSBT.InputInfo(spentOutput: utxo.spentOutput,
                                      key: taprootKey(chain: utxo.chain, index: utxo.index,
                                                      fingerprint: origin.fingerprint,
                                                      originPath: origin.path))
        }
        let outputInfo = try transaction.outputs.enumerated().map { index, _ -> PSBT.OutputInfo in
            guard index == changeOutputIndex, let changeIndex else { return PSBT.OutputInfo(key: nil) }
            return PSBT.OutputInfo(key: try taprootKey(chain: .change, index: changeIndex,
                                                       fingerprint: origin.fingerprint,
                                                       originPath: origin.path))
        }
        var psbt = try PSBT(unsignedTx: transaction, inputs: inputInfo, outputs: outputInfo)
        for (index, utxo) in selected.enumerated() {
            // `keyPathSecret`, never `tweakedPrivateKey` directly: a
            // silent-payment UTXO's output key has no TapTweak, so BIP86
            // coordinates would sign it with the wrong key — valid-looking
            // and unspendable. Both sends and replacements come through here.
            try psbt.signKeyPath(input: index, tweakedPrivateKey: keyPathSecret(for: utxo))
        }
        try psbt.finalize()
        return (psbt, try psbt.extractedTransaction())
    }

    // MARK: - Keys

    /// The BIP371 key-origin metadata for one of our addresses: internal key
    /// plus full derivation path from the master fingerprint.
    private func taprootKey(chain: AddressChain, index: UInt32,
                            fingerprint: UInt32, originPath: [UInt32]) throws -> PSBT.TaprootKey {
        let key = try accountKey.child(at: UInt32(chain.rawValue)).child(at: index)
        return PSBT.TaprootKey(internalKey: BIP86.xonlyPublicKey(of: key),
                               masterFingerprint: fingerprint,
                               path: originPath + [UInt32(chain.rawValue), index])
    }

    private static func originUnchecked(of descriptor: Descriptor) -> Descriptor.KeyOrigin {
        guard case let .tr(.single(key), nil) = descriptor.expression, let origin = key.origin else {
            preconditionFailure("wallet descriptor always carries origin info")
        }
        return origin
    }

    /// The master key from the KeyStore — loaded just for the duration of a
    /// derivation or signing call, never held in wallet state.
    private func masterKey() throws -> HDKey {
        switch try keyStore.load(walletID: id) {
        case let .mnemonic(words):
            try HDKey(seed: BIP39.seed(mnemonic: words))
        case let .masterKey(xprv):
            try HDKey.deserialize(xprv)
        }
    }

    /// BIP86 tweaked private key for one of our addresses (key-path spend).
    /// The secret is loaded from the KeyStore just for this call.
    private func tweakedPrivateKey(chain: AddressChain, index: UInt32) throws -> Data {
        let originPath = Self.originUnchecked(of: descriptor).path
        var key = try masterKey()
        for step in originPath { key = try key.child(at: step) }
        key = try key.child(at: UInt32(chain.rawValue)).child(at: index)
        guard let secret = key.privateKey else {
            throw WalletError.invalidDescriptor("neutered key in signing path")
        }
        return try BIP86.tweakedPrivateKey(secret)
    }

    /// The key-path secret that signs for a UTXO: the BIP86 tweaked key for
    /// descriptor outputs, b_spend + tweak for silent-payment outputs (BIP352
    /// outputs carry no TapTweak). Also the correct BIP352 *input* key when
    /// the UTXO funds a silent-payment send — both cases are "the private key
    /// of the taproot output key".
    private func keyPathSecret(for utxo: WalletUTXO) throws -> Data {
        guard let tweak = utxo.silentPaymentTweak else {
            return try tweakedPrivateKey(chain: utxo.chain, index: utxo.index)
        }
        let spend = try SilentPaymentReceiving.spendKey(from: masterKey(),
                                                        coinType: Self.coinType(for: network),
                                                        account: accountIndex)
        guard let secret = spend.privateKey else {
            throw WalletError.invalidDescriptor("neutered key in signing path")
        }
        return try SilentPaymentReceiving.spendSecret(spendPrivateKey: secret, tweak: tweak)
    }

    // MARK: - Silent payments (receive)

    /// The account index from the descriptor origin (m/86'/coin'/account') —
    /// silent payment keys live at the same account under purpose 352'.
    private var accountIndex: UInt32 {
        let path = Self.originUnchecked(of: descriptor).path
        guard path.count == 3 else { return 0 }
        return path[2] - HDKey.hardenedOffset
    }

    /// The wallet's BIP352 silent payment address ("sp1…"/"tsp1…"): B_scan and
    /// B_spend at m/352'/coin'/account'/{1',0'}/0 from the same master seed.
    /// Unlike BIP86 addresses it is static — one address, unlinkable payments.
    public func silentPaymentAddress() throws -> String {
        let master = try masterKey()
        let coinType = Self.coinType(for: network)
        let scan = try SilentPaymentReceiving.scanKey(from: master, coinType: coinType,
                                                      account: accountIndex)
        let spend = try SilentPaymentReceiving.spendKey(from: master, coinType: coinType,
                                                        account: accountIndex)
        return try SilentPaymentAddress(scanKey: scan.publicKey, spendKey: spend.publicKey,
                                        hrp: SilentPayment.hrp(for: network)).encoded
    }

    // MARK: - Export

    /// Live wallet → import bundle. `lastKnownHeight` is the scan frontier
    /// (`nextScanHeight - 1`, or 0 at genesis) so `verifyImport` resumes at
    /// the same height this wallet would scan next. Callers that drive
    /// FilterSync themselves must `recordScanHeight` first — `apply` does
    /// not move the frontier.
    ///
    /// Watch-only by default. The seed is included only on an explicit
    /// opt-in; an xprv-seeded wallet throws ``WalletError/mnemonicUnavailable``
    /// rather than silently exporting a non-spendable "backup".
    public func exportBundle(includeMnemonic: Bool = false) throws -> ImportBundle {
        // Commit already pulled the parent inputs out of `utxos`. A bundle
        // written now would carry only height-0 change; a restore that
        // scans forward from lastKnownHeight can never put those inputs
        // back if the send fails to confirm.
        if !state.pendingSends.isEmpty || state.utxos.contains(where: { $0.height == 0 }) {
            throw WalletError.exportWhilePending
        }
        if !includeMnemonic, state.utxos.contains(where: { $0.silentPaymentTweak != nil }) {
            throw WalletError.silentPaymentExportRequiresMnemonic
        }
        let lastKnownHeight = state.nextScanHeight == 0 ? 0 : state.nextScanHeight - 1
        let mnemonic: String?
        if includeMnemonic {
            let secret: WalletSecret
            do {
                secret = try keyStore.load(walletID: id)
            } catch let error as KeyStoreError {
                // Missing entry is the same user-facing outcome as an xprv:
                // there is no recovery phrase to put in the file. Don't leak
                // the raw KeyStoreError through the export boundary.
                if case .notFound = error { throw WalletError.mnemonicUnavailable }
                throw error
            }
            switch secret {
            case let .mnemonic(words):
                mnemonic = words
            case .masterKey:
                throw WalletError.mnemonicUnavailable
            }
        } else {
            mnemonic = nil
        }
        return try ImportBundle.export(
            descriptor: descriptor.serialized(),
            network: network.rawValue,
            lastKnownHeight: lastKnownHeight,
            utxos: state.utxos,
            history: state.history,
            nextReceiveIndex: state.nextReceiveIndex,
            nextChangeIndex: state.nextChangeIndex,
            mnemonic: mnemonic
        )
    }

    // MARK: - Persistence

    /// Rewinds every chain-derived fact to a fork height, so the wallet stops
    /// describing a branch that no longer exists (#127).
    ///
    /// A pure function of `forkHeight`. That is what makes it safe to repeat:
    /// running it twice is indistinguishable from running it once, so a crash
    /// part-way through a multi-store rollback needs no partial-state
    /// reasoning, only a redo.
    ///
    /// What it rewinds, and what it must not:
    ///
    /// - coins confirmed above the fork are dropped, because the rescan will
    ///   re-find them if they still exist;
    /// - spends *confirmed* above the fork are undone, restoring the coin;
    /// - spends with no height are left alone. Those are our own transactions,
    ///   still in flight and still being re-relayed, so restoring their inputs
    ///   would let the wallet re-select coins its own transaction is spending
    ///   and double-spend itself;
    /// - history above the fork goes, since it describes blocks that are gone;
    /// - the scan frontier rewinds so those heights are read again.
    ///
    /// Untouched, deliberately: the descriptor, the network, the creation
    /// height, `pendingSends`, and above all the address indices. Rewinding
    /// those would hand out an address that has already been given to someone,
    /// which is a privacy regression in a wallet whose argument is that it
    /// discloses nothing. A reorg must never cost the user their address gap.
    ///
    /// Height 0 means "not in a block yet", not "in block zero", so pending
    /// coins and pending history survive any fork height.
    public func rollBack(to forkHeight: UInt32) throws {
        var candidate = state
        candidate.allUtxos.removeAll { $0.height > forkHeight }
        for index in candidate.allUtxos.indices {
            guard let height = candidate.allUtxos[index].spent?.height,
                  height > forkHeight
            else { continue }
            candidate.allUtxos[index].spent = nil
        }
        candidate.history.removeAll { $0.height > forkHeight }
        // Never forward: a fork at or above the frontier leaves nothing that
        // was scanned in doubt, and advancing here would skip unread blocks.
        candidate.nextScanHeight = min(state.nextScanHeight,
                                       forkHeight == UInt32.max ? forkHeight : forkHeight + 1)
        guard candidate != state else { return }
        try persist(candidate)
        state = candidate
    }

    func persist() throws {
        try persist(state)
    }

    private func persist(_ candidate: WalletState) throws {
        guard let storageURL else { return }
        let data = try JSONEncoder().encode(candidate)
        try data.write(to: storageURL, options: .atomic)
    }
}
