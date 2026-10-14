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
    /// The signed transaction is past Bitcoin Core's standard size limit, so
    /// default relay policy rejects it. Coin selection refuses this earlier, on its
    /// estimate; this measures the bytes that were actually signed.
    case transactionTooLarge(vsize: Int, limit: Int)
    /// A seed-bearing export was requested, but the secret is an xprv (or
    /// missing) rather than a BIP39 mnemonic. Refusing is safer than emitting
    /// a bundle that looks spendable and is not.
    case mnemonicUnavailable
    /// A pending send has already removed the parent inputs from the UTXO
    /// set. Exporting now would ship only the unconfirmed change — if the
    /// send never confirms, a forward-only restore cannot see the original
    /// coins (their confirmation height is behind `lastKnownHeight`).
    case exportWhilePending
    /// A matched transaction carried impossible output values or a total
    /// beyond Bitcoin's consensus monetary range. Nothing is applied.
    case invalidTransactionAmounts
    /// Legacy signing metadata must not be silently discarded by JSONDecoder:
    /// the resulting coin would look ordinary but could not be spent here.
    case unsupportedWalletData
    /// The persisted wallet file is larger than any state this wallet writes,
    /// so it is refused before it is read rather than after it is held.
    case storageTooLarge(maxBytes: Int)

    public var errorDescription: String? {
        switch self {
        // The payload is bound and discarded on purpose; see below.
        case .invalidDescriptor:
            // Deliberately not echoed. This is reached with a descriptor taken
            // straight from an imported bundle, and a descriptor may carry an
            // extended *private* key — repeating it here would put key material
            // on screen, into a screenshot, and into whatever the user pastes
            // into a bug report.
            "That wallet descriptor could not be parsed. It is not repeated here, "
                + "because a descriptor can carry key material."
        case .descriptorMismatch:
            "Bundle descriptor does not match the mnemonic."
        case let .invalidBundle(reason):
            "Invalid import bundle: \(reason)"
        case .noPayments:
            "Nothing to send."
        case .changeOutputMissing:
            "The built transaction lost its change output."
        case let .transactionTooLarge(vsize, limit):
            "The signed transaction is \(vsize) vbytes, above the \(limit)-vbyte relay maximum."
        case .mnemonicUnavailable:
            "This wallet has no recovery phrase to export — it was imported from an extended key, not a BIP39 mnemonic."
        case .exportWhilePending:
            "Wait for pending transactions to confirm before exporting. A mid-send backup would drop the coins being spent."
        case .invalidTransactionAmounts:
            "A matched Bitcoin transaction contains invalid amounts. Wallet state was not changed."
        case .unsupportedWalletData:
            """
            This wallet contains unsupported signing data and cannot be opened here. \
            Keep the original wallet file and use compatible wallet software to recover these coins.
            """
        case let .storageTooLarge(maxBytes):
            "The wallet file is larger than the \(maxBytes / 1_048_576) MB this wallet can hold and was not read."
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
                isCoinbase: Bool = false,
                spent: SpentMarker? = nil) {
        self.spent = spent
        self.txid = txid
        self.vout = vout
        self.amount = amount
        self.scriptPubKey = scriptPubKey
        self.chain = chain
        self.index = index
        self.height = height
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
        // `silentPaymentTweak` is kept although this build never writes one:
        // the decoder needs the key to notice a wallet it must refuse.
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
        // Reject legacy signing metadata even when null or malformed. Dropping
        // this key would silently turn an unsupported coin into an ordinary one.
        if container.contains(.silentPaymentTweak) {
            throw WalletError.unsupportedWalletData
        }
        self.init(txid: Data(txid.reversed()),
                  vout: try container.decode(UInt32.self, forKey: .vout),
                  amount: try container.decode(Int64.self, forKey: .amount),
                  scriptPubKey: scriptPubKey,
                  chain: try container.decode(AddressChain.self, forKey: .chain),
                  index: try container.decode(UInt32.self, forKey: .index),
                  height: try container.decode(UInt32.self, forKey: .height),
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
        // Absent for live coins, so an unspent row is byte-identical to before.
        try container.encodeIfPresent(spent, forKey: .spent)
        if isCoinbase { try container.encode(true, forKey: .isCoinbase) }
    }
}
