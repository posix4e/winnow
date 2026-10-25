import Foundation

/// Collects MatchEffects from FilterSync's @Sendable callback.
private final class EffectCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var collected: [MatchEffect] = []

    var effects: [MatchEffect] {
        lock.lock()
        defer { lock.unlock() }
        return collected
    }

    func add(_ effect: MatchEffect) {
        lock.lock()
        collected.append(effect)
        lock.unlock()
    }
}

/// A wallet import bundle (docs/import.md): everything the previous
/// wallet software knew — the descriptor and/or mnemonic, the known UTXOs and
/// history, and the last height it scanned — so this wallet can resume by
/// forward-scanning from that height. There is no historical back-scan; the
/// bundle *is* the history.
///
/// JSON format (version 2):
///
///     {
///       "version": 2,
///       "network": "signet",                  // or "mainnet"
///       "descriptor": "tr([fp/86'/1'/0']tpub…/<0;1>/*)#checksum",  // optional w/ mnemonic
///       "mnemonic": "word …",                 // optional w/ descriptor; enables spending
///       "lastKnownHeight": 150000,            // state below is claimed as of this height
///       "nextReceiveIndex": 4,                // optional; next unused BIP86 receive index
///       "nextChangeIndex": 2,                 // optional; next unused BIP86 change index
///       "utxos": [{ "txid": "<display hex>", "vout": 0, "amount": 50000,
///                   "scriptPubKey": "5120…", "chain": 0, "index": 3, "height": 149000 }],
///       "transactions": [{ "txid": "<display hex>", "height": 149000,
///                          "received": 50000, "spent": 0, "fee": 250,
///                          "replacedBy": "<replacement display hex>" }]
///     }
///
/// `fee` on a history entry is optional. It is present only when every
/// input of that transaction was ours (the only case a filter client can
/// compute it). Older v1 files omit the field; readers treat absence as
/// unknown. Observed feerate *samples* used by FeePolicy stay on-device
/// and are not in this schema — a restored wallet falls back to presets
/// until it observes new sends.
///
/// Optional `rawTransaction` is the non-witness transaction, encoded as base64.
/// Its txid must match the history entry. Older backups omit it; the app can
/// fetch the known block when the user opens that payment, without rescanning.
///
/// Legacy `silentPaymentTweak` signing data is read only to refuse unsupported
/// coins safely. Version 1 remains readable for ordinary descriptor UTXOs;
/// writers always emit version 2.
/// `isCoinbase` is emitted only when true so maturity survives export/import;
/// older bundles omit it and decode it as false.
///
/// With both descriptor and mnemonic present they must agree; with only a
/// descriptor the import is watch-only (signing needs the secret). Scanning
/// resumes at `lastKnownHeight + 1`.
public struct ImportBundle: Codable, Equatable, Sendable {
    public static let currentVersion = 2
    public static let supportedVersions = 1 ... currentVersion

    public struct UTXO: Codable, Equatable, Sendable {
        public var txid: String // display hex
        public var vout: UInt32
        public var amount: Int64
        public var scriptPubKey: String // hex
        public var chain: Int
        public var index: UInt32
        public var height: UInt32
        /// Legacy data, decoded only so `claimedUTXOs()` can refuse it. Keep
        /// this exact JSON key: silently dropping it would lose signing data.
        public private(set) var silentPaymentTweak: String?
        /// True only for an output created by a coinbase transaction. Optional
        /// so older bundles remain readable; absence means false.
        public var isCoinbase: Bool?

        public init(txid: String, vout: UInt32, amount: Int64, scriptPubKey: String,
                    chain: Int, index: UInt32, height: UInt32,
                    isCoinbase: Bool? = nil) {
            self.txid = txid
            self.vout = vout
            self.amount = amount
            self.scriptPubKey = scriptPubKey
            self.chain = chain
            self.index = index
            self.height = height
            self.isCoinbase = isCoinbase
        }
    }

    public struct KnownTransaction: Codable, Equatable, Sendable {
        public var txid: String // display hex
        public var height: UInt32
        public var received: Int64
        public var spent: Int64
        /// Present only when every input was ours. Omitted from JSON when nil
        /// so older v1 files (no `fee` key) remain valid.
        public var fee: Int64?
        /// The transaction that superseded this one through fee replacement.
        /// Optional so existing v1/v2 bundles remain readable.
        public var replacedBy: String?
        public var rawTransaction: Data?
        public var outputs: HistoryEntry.Outputs?
        /// The block the transaction confirmed in (display hex), so a restore
        /// can check it against headers without fetching the block. Optional
        /// so existing bundles remain readable.
        public var blockHash: String?

        public init(txid: String, height: UInt32, received: Int64, spent: Int64,
                    fee: Int64? = nil, replacedBy: String? = nil, rawTransaction: Data? = nil,
                    blockHash: String? = nil, outputs: HistoryEntry.Outputs? = nil) {
            self.txid = txid
            self.height = height
            self.received = received
            self.spent = spent
            self.fee = fee
            self.replacedBy = replacedBy
            self.rawTransaction = rawTransaction
            self.blockHash = blockHash
            self.outputs = outputs
        }

        private enum CodingKeys: String, CodingKey {
            case txid, height, received, spent, fee, replacedBy, rawTransaction, blockHash, outputs
        }

        public func encode(to encoder: any Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(txid, forKey: .txid)
            try container.encode(height, forKey: .height)
            try container.encode(received, forKey: .received)
            try container.encode(spent, forKey: .spent)
            try container.encodeIfPresent(fee, forKey: .fee)
            try container.encodeIfPresent(replacedBy, forKey: .replacedBy)
            try container.encodeIfPresent(rawTransaction, forKey: .rawTransaction)
            try container.encodeIfPresent(blockHash, forKey: .blockHash)
            try container.encodeIfPresent(outputs, forKey: .outputs)
        }
    }

    public var version: Int
    public var network: String
    public var descriptor: String?
    public var mnemonic: String?
    public var lastKnownHeight: UInt32
    /// The hash of block `lastKnownHeight` (display hex). Optional so existing
    /// bundles remain readable.
    public var lastKnownBlockHash: String?
    public var utxos: [UTXO]
    public var transactions: [KnownTransaction]
    /// Multisig accounts (`MultisigAccountRecord`), under the key the
    /// shared-account Winnow used for all its accounts. Script-path k-of-n
    /// accounts restore; a bundle carrying any other kind of account, such as
    /// a MuSig2 one, is refused outright rather than restored without it
    /// (see `decode`).
    public var vaults: [MultisigAccountRecord]?
    /// Next unused BIP86 receive index. Absent from v1 files and from
    /// writers that only knew UTXO-derived maxima; the importer then
    /// falls back to `max(receive UTXO index) + 1`.
    public var nextReceiveIndex: UInt32?
    /// Next unused BIP86 change index. Same fallback as `nextReceiveIndex`.
    public var nextChangeIndex: UInt32?

    public init(version: Int = ImportBundle.currentVersion, network: String,
                descriptor: String? = nil, mnemonic: String? = nil,
                lastKnownHeight: UInt32, lastKnownBlockHash: String? = nil,
                utxos: [UTXO] = [], transactions: [KnownTransaction] = [],
                nextReceiveIndex: UInt32? = nil, nextChangeIndex: UInt32? = nil) {
        self.version = version
        self.network = network
        self.descriptor = descriptor
        self.mnemonic = mnemonic
        self.lastKnownHeight = lastKnownHeight
        self.lastKnownBlockHash = lastKnownBlockHash
        self.utxos = utxos
        self.transactions = transactions
        self.nextReceiveIndex = nextReceiveIndex
        self.nextChangeIndex = nextChangeIndex
    }

    /// Writer for the documented v2 schema. Txids go out as display hex —
    /// the same convention `claimedUTXOs()` reverses on the way back in.
    public static func export(descriptor: String, network: String, lastKnownHeight: UInt32,
                              lastKnownBlockHash: Data? = nil,
                              utxos: [WalletUTXO], history: [HistoryEntry],
                              nextReceiveIndex: UInt32, nextChangeIndex: UInt32,
                              mnemonic: String? = nil) throws -> ImportBundle {
        return ImportBundle(
            network: network,
            descriptor: descriptor,
            mnemonic: mnemonic,
            lastKnownHeight: lastKnownHeight,
            lastKnownBlockHash: lastKnownBlockHash?.displayHex,
            utxos: utxos.map { utxo in
                UTXO(txid: utxo.txid.displayHex, vout: utxo.vout, amount: utxo.amount,
                     scriptPubKey: utxo.scriptPubKey.hex, chain: utxo.chain.rawValue,
                     index: utxo.index, height: utxo.height,
                     isCoinbase: utxo.isCoinbase ? true : nil)
            },
            transactions: history.map { entry in
                KnownTransaction(txid: entry.txid.displayHex, height: entry.height,
                                 received: entry.received, spent: entry.spent, fee: entry.fee,
                                 replacedBy: entry.replacedBy?.displayHex, rawTransaction: entry.rawTransaction,
                                 blockHash: entry.blockHash?.displayHex, outputs: entry.outputs)
            },
            nextReceiveIndex: nextReceiveIndex,
            nextChangeIndex: nextChangeIndex
        )
    }

    // MARK: - Bounded decoding

    /// A bundle is the one input a user is invited to paste from anywhere, so
    /// it is decoded through here rather than by calling `JSONDecoder`
    /// directly. Foundation already refuses deeply nested JSON and resolves a
    /// duplicate key to its first occurrence, but both are undocumented
    /// defaults; `ImportBundleBoundsTests` pins them so a Foundation change
    /// cannot alter what a bundle means without a test failing.
    ///
    /// The explicit bounds are what Foundation does not provide: it will
    /// happily decode a two-hundred-thousand-entry bundle, and every entry is
    /// then materialised and scanned.
    public static let maximumSerializedBytes = 8 * 1024 * 1024
    public static let maximumEntries = 50_000
    public static let maximumVaults = 100

    /// Decodes a bundle from untrusted text, refusing implausible sizes before
    /// allocating anything proportional to them.
    public static func decode(json: String) throws -> ImportBundle {
        guard let data = json.data(using: .utf8) else {
            throw WalletError.invalidBundle("not UTF-8")
        }
        return try decode(data)
    }

    public static func decode(_ data: Data) throws -> ImportBundle {
        guard data.count <= maximumSerializedBytes else {
            throw WalletError.invalidBundle(
                "bundle is \(data.count) bytes, above the \(maximumSerializedBytes)-byte limit")
        }
        let bundle = try JSONDecoder().decode(ImportBundle.self, from: data)
        guard bundle.utxos.count <= maximumEntries else {
            throw WalletError.invalidBundle(
                "bundle declares \(bundle.utxos.count) coins, above the \(maximumEntries) limit")
        }
        guard bundle.transactions.count <= maximumEntries else {
            throw WalletError.invalidBundle(
                "bundle declares \(bundle.transactions.count) transactions, above the \(maximumEntries) limit")
        }
        guard (bundle.vaults?.count ?? 0) <= maximumVaults,
              (bundle.vaults ?? []).reduce(0, { $0 + $1.allUtxos.count }) <= maximumEntries else {
            throw WalletError.invalidBundle("too many multisig accounts or account coins")
        }
        // MuSig2 accounts from the shared-account Winnow have no home here;
        // their coins must not vanish from a restore.
        if let vaults = bundle.vaults, !vaults.isEmpty {
            guard let network = BitcoinNetwork(rawValue: bundle.network),
                  vaults.allSatisfy({ (try? MultisigAccount($0.descriptor, network: network)) != nil })
            else { throw WalletError.unsupportedWalletData }
        }
        return bundle
    }

    /// Pretty-printed, sorted-key JSON ready for a share sheet. Nil optionals
    /// (mnemonic / descriptor) are omitted rather than encoded as `null`.
    public func serialized() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(self)
        guard let text = String(data: data, encoding: .utf8) else {
            throw WalletError.invalidBundle("export is not UTF-8")
        }
        return text
    }

    private enum CodingKeys: String, CodingKey {
        case version, network, descriptor, mnemonic, lastKnownHeight, lastKnownBlockHash, utxos, transactions
        case nextReceiveIndex, nextChangeIndex, vaults
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(network, forKey: .network)
        try container.encodeIfPresent(descriptor, forKey: .descriptor)
        try container.encodeIfPresent(mnemonic, forKey: .mnemonic)
        try container.encode(lastKnownHeight, forKey: .lastKnownHeight)
        try container.encodeIfPresent(lastKnownBlockHash, forKey: .lastKnownBlockHash)
        try container.encode(utxos, forKey: .utxos)
        try container.encode(transactions, forKey: .transactions)
        try container.encodeIfPresent(nextReceiveIndex, forKey: .nextReceiveIndex)
        try container.encodeIfPresent(nextChangeIndex, forKey: .nextChangeIndex)
        try container.encodeIfPresent(vaults, forKey: .vaults)
    }

    /// The bundle's claimed UTXOs in wallet form.
    public func claimedUTXOs() throws -> [WalletUTXO] {
        let claimed = try utxos.map(Self.parsedClaimedUTXO)
        var seen = Set<Transaction.Outpoint>()
        var total: Int64 = 0
        for coin in claimed {
            guard coin.amount > 0, coin.amount <= BitcoinAmount.maximum else {
                throw WalletError.invalidBundle("invalid UTXO amount \(coin.amount)")
            }
            guard !coin.scriptPubKey.isEmpty else {
                throw WalletError.invalidBundle("empty UTXO scriptPubKey")
            }
            guard seen.insert(coin.outpoint).inserted else {
                throw WalletError.invalidBundle("duplicate UTXO outpoint")
            }
            let (next, overflow) = total.addingReportingOverflow(coin.amount)
            guard !overflow, next <= BitcoinAmount.maximum else {
                throw WalletError.invalidBundle("UTXO total exceeds Bitcoin's monetary range")
            }
            total = next
        }
        return claimed
    }

    /// What an error may repeat of bundle-supplied text: enough to find the
    /// entry, never the whole field — an 8 MB bundle must not become an 8 MB
    /// alert.
    static func excerpt(_ text: String) -> String {
        text.count <= 64 ? text : text.prefix(64) + "…"
    }

    /// Parse and shape-check a claimed coin, refusing unsupported signing data.
    private static func parsedClaimedUTXO(_ utxo: UTXO) throws -> WalletUTXO {
        guard let txid = Data(hex: utxo.txid), txid.count == 32 else {
            throw WalletError.invalidBundle("bad txid \(excerpt(utxo.txid))")
        }
        guard let scriptPubKey = Data(hex: utxo.scriptPubKey) else {
            throw WalletError.invalidBundle("bad scriptPubKey \(excerpt(utxo.scriptPubKey))")
        }
        guard let chain = AddressChain(rawValue: utxo.chain) else {
            throw WalletError.invalidBundle("bad chain \(utxo.chain)")
        }
        if utxo.silentPaymentTweak != nil {
            throw WalletError.unsupportedWalletData
        }
        return WalletUTXO(txid: Data(txid.reversed()), vout: utxo.vout, amount: utxo.amount,
                          scriptPubKey: scriptPubKey, chain: chain, index: utxo.index,
                          height: utxo.height,
                          isCoinbase: utxo.isCoinbase ?? false)
    }
}

/// The outcome of verifying an import bundle by forward-scanning from its
/// height (docs/import.md §3). Discrepancies surface here, never
/// silently: a bundle that claimed an already-spent UTXO shows up in
/// `spentSinceBundle`.
public struct ImportReport: Equatable, Sendable {
    /// A bundle-claimed UTXO the scan found spent.
    public struct SpentClaim: Equatable, Sendable {
        public var txid: Data
        public var vout: UInt32
        public var spentBy: Data
        public var height: UInt32
    }

    public var scannedFromHeight: UInt32
    public var scannedToHeight: UInt32?
    /// Claimed by the bundle and still unspent after the scan.
    public var confirmedUTXOs: [WalletUTXO]
    /// Claimed by the bundle but spent since — the bundle was stale or wrong.
    public var spentSinceBundle: [SpentClaim]
    /// Found by the scan but absent from the bundle (e.g. payments received
    /// after the bundle was exported). Informational, not a mismatch.
    public var discoveredUTXOs: [WalletUTXO]

    /// The bundle is consistent with the chain as scanned.
    public var matchesBundle: Bool { spentSinceBundle.isEmpty }

    /// Pure verification core (unit-testable without a network): the bundle's
    /// claims against the effects of applying every matched block in
    /// [scannedFromHeight, scannedToHeight].
    public static func make(bundle: ImportBundle, effects: [MatchEffect],
                            finalUTXOs: [WalletUTXO], scannedFromHeight: UInt32,
                            scannedToHeight: UInt32?) throws -> ImportReport {
        let claimed = try bundle.claimedUTXOs()
        let claimedOutpoints = Set(claimed.map { OutpointKey(txid: $0.txid, vout: $0.vout) })

        var spentClaims: [SpentClaim] = []
        for spend in effects.flatMap(\.spent)
        where claimedOutpoints.contains(OutpointKey(txid: spend.txid, vout: spend.vout)) {
            spentClaims.append(SpentClaim(txid: spend.txid, vout: spend.vout,
                                          spentBy: spend.spentBy, height: spend.height))
        }
        let spentKeys = Set(spentClaims.map { OutpointKey(txid: $0.txid, vout: $0.vout) })
        let confirmed = finalUTXOs.filter {
            claimedOutpoints.contains(OutpointKey(txid: $0.txid, vout: $0.vout))
                && !spentKeys.contains(OutpointKey(txid: $0.txid, vout: $0.vout))
        }
        let discovered = effects.flatMap(\.received).filter {
            !claimedOutpoints.contains(OutpointKey(txid: $0.txid, vout: $0.vout))
        }
        return ImportReport(scannedFromHeight: scannedFromHeight, scannedToHeight: scannedToHeight,
                            confirmedUTXOs: confirmed, spentSinceBundle: spentClaims,
                            discoveredUTXOs: discovered)
    }

    private struct OutpointKey: Hashable {
        var txid: Data
        var vout: UInt32
    }
}

extension Wallet {
    /// Seeds a wallet from an import bundle (docs/import.md). The
    /// wallet state starts exactly as the bundle claims; `verifyImport` then
    /// checks those claims against the chain. `creationHeight` becomes the
    /// bundle's `lastKnownHeight` — scanning resumes right after it.
    public static func importing(_ bundle: ImportBundle, keyStore: any KeyStore,
                                 storageURL: URL? = nil) throws -> Wallet {
        guard ImportBundle.supportedVersions.contains(bundle.version) else {
            throw WalletError.invalidBundle("unsupported version \(bundle.version)")
        }
        guard let network = BitcoinNetwork(rawValue: bundle.network) else {
            throw WalletError.invalidBundle("unknown network \(ImportBundle.excerpt(bundle.network))")
        }
        guard bundle.descriptor != nil || bundle.mnemonic != nil else {
            throw WalletError.invalidBundle("need a descriptor or a mnemonic")
        }

        let (descriptor, accountKey) = try importedKeyMaterial(
            of: bundle, network: network, keyStore: keyStore)
        let utxos = try validatedClaimedUTXOs(of: bundle, descriptor: descriptor,
                                              network: network)
        let history = try validatedHistory(of: bundle)

        let fromReceiveUTXOs = (utxos.filter { $0.chain == .receive }
            .map(\.index).max().map { $0 + 1 }) ?? 0
        let fromChangeUTXOs = (utxos.filter { $0.chain == .change }
            .map(\.index).max().map { $0 + 1 }) ?? 0
        // Prefer the exported cursor so a spent-out restore does not
        // reissue address 0. Never go below the UTXO-derived floor — a
        // tampered-low cursor would otherwise reuse a live coin's address.
        let cursors = try boundedCursors(
            receive: max(bundle.nextReceiveIndex ?? 0, fromReceiveUTXOs),
            change: max(bundle.nextChangeIndex ?? 0, fromChangeUTXOs))
        guard bundle.lastKnownHeight < UInt32.max else {
            throw WalletError.invalidBundle("last known height \(bundle.lastKnownHeight) is out of range")
        }
        var state = WalletState(
            descriptor: descriptor.serialized(),
            network: network.rawValue,
            creationHeight: bundle.lastKnownHeight,
            nextReceiveIndex: cursors.receive,
            nextChangeIndex: cursors.change,
            nextScanHeight: bundle.lastKnownHeight + 1,
            utxos: utxos,
            history: history
        )
        state.scannedThroughHash = try blockHash(bundle.lastKnownBlockHash, confirmed: true)
        let wallet = try Wallet(network: network, descriptor: descriptor, accountKey: accountKey,
                                keyStore: keyStore, storageURL: storageURL, state: state)
        if let storageURL {
            let data = try JSONEncoder().encode(state)
            try data.write(to: storageURL,
                           options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        }
        return wallet
    }

    /// The bundle's key material, resolved and — when a mnemonic travels with
    /// it — stored: the derived descriptor must match any descriptor the
    /// bundle also claims, and re-importing the same secret is fine while a
    /// different secret under the same fingerprint is not.
    private static func importedKeyMaterial(of bundle: ImportBundle, network: BitcoinNetwork,
                                            keyStore: any KeyStore)
        throws -> (descriptor: Descriptor, accountKey: HDKey) {
        if let mnemonic = bundle.mnemonic {
            try BIP39.validate(mnemonic: mnemonic)
            let master = try HDKey(seed: BIP39.seed(mnemonic: mnemonic))
            let coinType = Self.coinType(for: network)
            let account = try BIP86.accountKey(from: master, coinType: coinType, account: 0)
            let origin = Descriptor.KeyOrigin(fingerprint: master.fingerprint,
                                              path: [86, coinType, 0].map { $0 + HDKey.hardenedOffset })
            let derived = Self.makeDescriptor(accountKey: account, origin: origin, network: network)
            if let bundleDescriptor = bundle.descriptor,
               try Descriptor(bundleDescriptor) != derived
            {
                throw WalletError.descriptorMismatch
            }
            let walletID = String(format: "%08x", master.fingerprint)
            do {
                try keyStore.store(.mnemonic(mnemonic), for: walletID)
            } catch KeyStoreError.alreadyExists {
                guard try keyStore.load(walletID: walletID) == .mnemonic(mnemonic) else {
                    throw KeyStoreError.alreadyExists(walletID: walletID)
                }
            }
            return (derived, account.neutered)
        }
        guard let bundleDescriptor = bundle.descriptor else {
            throw WalletError.invalidBundle("no usable descriptor")
        }
        let parsed = try Descriptor(bundleDescriptor)
        _ = try Self.origin(of: parsed)
        guard case let .tr(key) = parsed.expression,
              case let .extended(account, _) = key.base
        else { throw WalletError.invalidDescriptor(bundleDescriptor) }
        return (parsed, account.neutered)
    }

    /// Every claimed coin re-derived from its BIP86 coordinates: the
    /// descriptor, not the bundle, says which scripts are the wallet's.
    private static func validatedClaimedUTXOs(of bundle: ImportBundle,
                                              descriptor: Descriptor,
                                              network: BitcoinNetwork) throws -> [WalletUTXO] {
        let utxos = try bundle.claimedUTXOs()
        for utxo in utxos {
            let expected = try descriptor
                .derived(index: utxo.index, bitcoinNetwork: network)[utxo.chain.rawValue]
                .scriptPubKey
            guard expected == utxo.scriptPubKey else {
                throw WalletError.invalidBundle(
                    "utxo \(utxo.txid.displayHex):\(utxo.vout) scriptPubKey does not match the descriptor")
            }
        }
        return utxos
    }

    /// The claimed history, with txids well-formed and amounts inside the
    /// supply — bounded hostile input like everything else in a bundle.
    /// The cursors a bundle may set, under the bound `advanceCursors`
    /// enforces: a restore cannot name a window the gap-limit lookahead cannot
    /// derive from, which would trap or spin the first scan after import.
    private static func boundedCursors(receive: UInt32, change: UInt32) throws
        -> (receive: UInt32, change: UInt32) {
        let maximum = HDKey.hardenedOffset - Self.gapLimit
        guard receive <= maximum, change <= maximum else {
            throw WalletError.invalidBundle("address cursors leave no room for the gap-limit window")
        }
        return (receive, change)
    }

    /// A claimed block hash in internal byte order, or nil when the bundle
    /// names none. A pending entry has no block to name.
    private static func blockHash(_ hex: String?, confirmed: Bool) throws -> Data? {
        guard let hex else { return nil }
        guard confirmed, let hash = Data(hex: hex), hash.count == 32 else {
            throw WalletError.invalidBundle("bad block hash \(ImportBundle.excerpt(hex))")
        }
        return Data(hash.reversed())
    }

    private static func validatedHistory(of bundle: ImportBundle) throws -> [HistoryEntry] {
        try bundle.transactions.map { known in
            guard let txid = Data(hex: known.txid), txid.count == 32 else {
                throw WalletError.invalidBundle("bad txid \(known.txid)")
            }
            let replacedBy: Data?
            if let replacementHex = known.replacedBy {
                guard let replacement = Data(hex: replacementHex), replacement.count == 32 else {
                    throw WalletError.invalidBundle("bad replacement txid \(replacementHex)")
                }
                replacedBy = Data(replacement.reversed())
            } else {
                replacedBy = nil
            }
            guard (0 ... BitcoinAmount.maximum).contains(known.received),
                  (0 ... BitcoinAmount.maximum).contains(known.spent),
                  known.fee.map({ (0 ... BitcoinAmount.maximum).contains($0) }) ?? true
            else { throw WalletError.invalidBundle("transaction history has invalid amounts") }
            let entry = HistoryEntry(txid: Data(txid.reversed()), height: known.height,
                                received: known.received, spent: known.spent, fee: known.fee,
                                replacedBy: replacedBy, rawTransaction: known.rawTransaction,
                                blockHash: try blockHash(known.blockHash, confirmed: known.height > 0),
                                outputs: known.outputs)
            _ = try entry.transaction()
            return entry
        }
    }

    /// Verifies an imported bundle by forward-scanning from its height,
    /// consuming every matched block, and comparing the outcome against the
    /// bundle's claims (docs/import.md §3). Mismatches — e.g. a claimed
    /// UTXO discovered spent — surface in the report, never silently.
    public func verifyImport(_ bundle: ImportBundle, using sync: FilterSync,
                             additionalScripts: [Data] = [],
                             onMatch: (@Sendable (BlockMatch) async throws -> Void)? = nil) async throws -> ImportReport {
        let fromHeight = await sync.nextScanHeight
        let collector = EffectCollector()
        try await sync.sync(watchScripts: watchScripts() + additionalScripts) { match in
            collector.add(try await self.apply(match: match))
            try await onMatch?(match)
        }
        let toHeight = await sync.lastScannedHeight
        return try ImportReport.make(bundle: bundle, effects: collector.effects, finalUTXOs: utxos,
                                           scannedFromHeight: fromHeight, scannedToHeight: toHeight)
    }
}
