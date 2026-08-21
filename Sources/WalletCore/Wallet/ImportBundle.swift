import BitcoinCore
import BitcoinP2P
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
///                   "scriptPubKey": "5120…", "chain": 0, "index": 3, "height": 149000,
///                   "silentPaymentTweak": "<32-byte scalar hex>" }],
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
/// `silentPaymentTweak` is absent for descriptor-derived UTXOs. When present,
/// the bundle must also contain the mnemonic: a BIP86 descriptor has no BIP352
/// spend key with which to validate or spend that output. Version 1 remains
/// readable for ordinary descriptor UTXOs; writers always emit version 2.
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
        /// BIP352 t_k (with any label tweak folded in), encoded as 32-byte
        /// scalar hex. nil for descriptor-derived UTXOs and every v1 bundle.
        public var silentPaymentTweak: String?
        /// True only for an output created by a coinbase transaction. Optional
        /// so older bundles remain readable; absence means false.
        public var isCoinbase: Bool?

        public init(txid: String, vout: UInt32, amount: Int64, scriptPubKey: String,
                    chain: Int, index: UInt32, height: UInt32,
                    silentPaymentTweak: String? = nil, isCoinbase: Bool? = nil) {
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

        public init(txid: String, height: UInt32, received: Int64, spent: Int64,
                    fee: Int64? = nil, replacedBy: String? = nil) {
            self.txid = txid
            self.height = height
            self.received = received
            self.spent = spent
            self.fee = fee
            self.replacedBy = replacedBy
        }

        private enum CodingKeys: String, CodingKey {
            case txid, height, received, spent, fee, replacedBy
        }

        public func encode(to encoder: any Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(txid, forKey: .txid)
            try container.encode(height, forKey: .height)
            try container.encode(received, forKey: .received)
            try container.encode(spent, forKey: .spent)
            try container.encodeIfPresent(fee, forKey: .fee)
            try container.encodeIfPresent(replacedBy, forKey: .replacedBy)
        }
    }

    public var version: Int
    public var network: String
    public var descriptor: String?
    public var mnemonic: String?
    public var lastKnownHeight: UInt32
    public var utxos: [UTXO]
    public var transactions: [KnownTransaction]
    /// Next unused BIP86 receive index. Absent from v1 files and from
    /// writers that only knew UTXO-derived maxima; the importer then
    /// falls back to `max(receive UTXO index) + 1`.
    public var nextReceiveIndex: UInt32?
    /// Next unused BIP86 change index. Same fallback as `nextReceiveIndex`.
    public var nextChangeIndex: UInt32?

    public init(version: Int = ImportBundle.currentVersion, network: String,
                descriptor: String? = nil, mnemonic: String? = nil,
                lastKnownHeight: UInt32, utxos: [UTXO] = [], transactions: [KnownTransaction] = [],
                nextReceiveIndex: UInt32? = nil, nextChangeIndex: UInt32? = nil) {
        self.version = version
        self.network = network
        self.descriptor = descriptor
        self.mnemonic = mnemonic
        self.lastKnownHeight = lastKnownHeight
        self.utxos = utxos
        self.transactions = transactions
        self.nextReceiveIndex = nextReceiveIndex
        self.nextChangeIndex = nextChangeIndex
    }

    /// Writer for the documented v2 schema. Txids go out as display hex —
    /// the same convention `claimedUTXOs()` reverses on the way back in.
    public static func export(descriptor: String, network: String, lastKnownHeight: UInt32,
                              utxos: [WalletUTXO], history: [HistoryEntry],
                              nextReceiveIndex: UInt32, nextChangeIndex: UInt32,
                              mnemonic: String? = nil) throws -> ImportBundle {
        if mnemonic == nil, utxos.contains(where: { $0.silentPaymentTweak != nil }) {
            throw WalletError.silentPaymentExportRequiresMnemonic
        }
        return ImportBundle(
            network: network,
            descriptor: descriptor,
            mnemonic: mnemonic,
            lastKnownHeight: lastKnownHeight,
            utxos: utxos.map { utxo in
                UTXO(txid: utxo.txid.displayHex, vout: utxo.vout, amount: utxo.amount,
                     scriptPubKey: utxo.scriptPubKey.hex, chain: utxo.chain.rawValue,
                     index: utxo.index, height: utxo.height,
                     silentPaymentTweak: utxo.silentPaymentTweak?.hex,
                     isCoinbase: utxo.isCoinbase ? true : nil)
            },
            transactions: history.map { entry in
                KnownTransaction(txid: entry.txid.displayHex, height: entry.height,
                                 received: entry.received, spent: entry.spent, fee: entry.fee,
                                 replacedBy: entry.replacedBy?.displayHex)
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

    /// Same JSON as `serialized()`, but a present mnemonic is replaced with
    /// `"<redacted>"` so an on-screen preview cannot screenshot or copy the
    /// seed. The shared file stays the real bundle.
    public static func redactedPreview(_ json: String) -> String {
        guard let data = json.data(using: .utf8),
              var bundle = try? JSONDecoder().decode(ImportBundle.self, from: data),
              bundle.mnemonic != nil
        else { return json }
        bundle.mnemonic = "<redacted>"
        return (try? bundle.serialized()) ?? json
    }

    private enum CodingKeys: String, CodingKey {
        case version, network, descriptor, mnemonic, lastKnownHeight, utxos, transactions
        case nextReceiveIndex, nextChangeIndex
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(network, forKey: .network)
        try container.encodeIfPresent(descriptor, forKey: .descriptor)
        try container.encodeIfPresent(mnemonic, forKey: .mnemonic)
        try container.encode(lastKnownHeight, forKey: .lastKnownHeight)
        try container.encode(utxos, forKey: .utxos)
        try container.encode(transactions, forKey: .transactions)
        try container.encodeIfPresent(nextReceiveIndex, forKey: .nextReceiveIndex)
        try container.encodeIfPresent(nextChangeIndex, forKey: .nextChangeIndex)
    }

    /// The bundle's claimed UTXOs in wallet form.
    public func claimedUTXOs() throws -> [WalletUTXO] {
        let claimed = try utxos.map { utxo in
            guard let txid = Data(hex: utxo.txid), txid.count == 32 else {
                throw WalletError.invalidBundle("bad txid \(utxo.txid)")
            }
            guard let scriptPubKey = Data(hex: utxo.scriptPubKey) else {
                throw WalletError.invalidBundle("bad scriptPubKey \(utxo.scriptPubKey)")
            }
            guard let chain = AddressChain(rawValue: utxo.chain) else {
                throw WalletError.invalidBundle("bad chain \(utxo.chain)")
            }
            let silentPaymentTweak: Data?
            if let tweakHex = utxo.silentPaymentTweak {
                guard version >= 2 else {
                    throw WalletError.invalidBundle("silentPaymentTweak requires version 2")
                }
                guard let tweak = Data(hex: tweakHex),
                      SilentPaymentReceiving.isValidTweak(tweak)
                else {
                    throw WalletError.invalidBundle("bad silentPaymentTweak")
                }
                silentPaymentTweak = tweak
            } else {
                silentPaymentTweak = nil
            }
            return WalletUTXO(txid: Data(txid.reversed()), vout: utxo.vout, amount: utxo.amount,
                              scriptPubKey: scriptPubKey, chain: chain, index: utxo.index,
                              height: utxo.height, silentPaymentTweak: silentPaymentTweak,
                              isCoinbase: utxo.isCoinbase ?? false)
        }
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
            throw WalletError.invalidBundle("unknown network \(bundle.network)")
        }
        guard bundle.descriptor != nil || bundle.mnemonic != nil else {
            throw WalletError.invalidBundle("need a descriptor or a mnemonic")
        }

        var descriptor: Descriptor?
        var accountKey: HDKey?
        var importMasterKey: HDKey?
        if let mnemonic = bundle.mnemonic {
            try BIP39.validate(mnemonic: mnemonic)
            let master = try HDKey(seed: BIP39.seed(mnemonic: mnemonic))
            importMasterKey = master
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
            descriptor = derived
            accountKey = account.neutered
            let walletID = String(format: "%08x", master.fingerprint)
            do {
                try keyStore.store(.mnemonic(mnemonic), for: walletID)
            } catch KeyStoreError.alreadyExists {
                // Re-importing the same secret is fine; a different secret
                // under the same ID (same fingerprint) is not.
                guard try keyStore.load(walletID: walletID) == .mnemonic(mnemonic) else {
                    throw KeyStoreError.alreadyExists(walletID: walletID)
                }
            }
        } else if let bundleDescriptor = bundle.descriptor {
            let parsed = try Descriptor(bundleDescriptor)
            _ = try Self.origin(of: parsed)
            guard case let .tr(.single(key), nil) = parsed.expression,
                  case let .extended(account, _) = key.base
            else { throw WalletError.invalidDescriptor(bundleDescriptor) }
            descriptor = parsed
            accountKey = account.neutered
        }
        guard let descriptor, let accountKey else {
            throw WalletError.invalidBundle("no usable descriptor")
        }

        let utxos = try bundle.claimedUTXOs()
        // Validate every claim from key material in the bundle. Descriptor
        // outputs use their BIP86 coordinates. Silent-payment outputs use the
        // mnemonic-derived BIP352 spend key plus their persisted tweak.
        for utxo in utxos {
            let expected: Data
            if let tweak = utxo.silentPaymentTweak {
                guard let importMasterKey else {
                    throw WalletError.invalidBundle(
                        "silent-payment UTXOs require a mnemonic")
                }
                let origin = try Self.origin(of: descriptor)
                guard origin.path.count == 3,
                      origin.path[2] >= HDKey.hardenedOffset
                else {
                    throw WalletError.invalidDescriptor("missing BIP86 account in key origin")
                }
                let account = origin.path[2] - HDKey.hardenedOffset
                let spend = try SilentPaymentReceiving.spendKey(
                    from: importMasterKey, coinType: Self.coinType(for: network), account: account)
                guard let spendPrivateKey = spend.privateKey else {
                    throw WalletError.invalidBundle("silent-payment spend key is unavailable")
                }
                expected = try SilentPaymentReceiving.outputScript(
                    spendPrivateKey: spendPrivateKey, tweak: tweak)
            } else {
                expected = try descriptor
                    .derived(index: utxo.index,
                             network: Self.hdNetwork(for: network))[utxo.chain.rawValue]
                    .scriptPubKey
            }
            guard expected == utxo.scriptPubKey else {
                throw WalletError.invalidBundle(
                    "utxo \(utxo.txid.displayHex):\(utxo.vout) scriptPubKey does not match the descriptor")
            }
        }

        let history = try bundle.transactions.map { known in
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
            return HistoryEntry(txid: Data(txid.reversed()), height: known.height,
                                received: known.received, spent: known.spent, fee: known.fee,
                                replacedBy: replacedBy)
        }

        let fromReceiveUTXOs = (utxos.filter {
            $0.silentPaymentTweak == nil && $0.chain == .receive
        }.map(\.index).max().map { $0 + 1 }) ?? 0
        let fromChangeUTXOs = (utxos.filter {
            $0.silentPaymentTweak == nil && $0.chain == .change
        }.map(\.index).max().map { $0 + 1 }) ?? 0
        // Prefer the exported cursor so a spent-out restore does not
        // reissue address 0. Never go below the UTXO-derived floor — a
        // tampered-low cursor would otherwise reuse a live coin's address.
        let state = WalletState(
            descriptor: descriptor.serialized(),
            network: network.rawValue,
            creationHeight: bundle.lastKnownHeight,
            nextReceiveIndex: max(bundle.nextReceiveIndex ?? 0, fromReceiveUTXOs),
            nextChangeIndex: max(bundle.nextChangeIndex ?? 0, fromChangeUTXOs),
            nextScanHeight: bundle.lastKnownHeight + 1,
            utxos: utxos,
            history: history
        )
        let wallet = try Wallet(network: network, descriptor: descriptor, accountKey: accountKey,
                                keyStore: keyStore, storageURL: storageURL, state: state)
        if let storageURL {
            try JSONEncoder().encode(state).write(to: storageURL, options: .atomic)
        }
        return wallet
    }

    /// Verifies an imported bundle by forward-scanning from its height,
    /// consuming every matched block, and comparing the outcome against the
    /// bundle's claims (docs/import.md §3). Mismatches — e.g. a claimed
    /// UTXO discovered spent — surface in the report, never silently.
    public func verifyImport(_ bundle: ImportBundle, using sync: FilterSync) async throws -> ImportReport {
        let fromHeight = await sync.nextScanHeight
        let collector = EffectCollector()
        try await sync.sync(watchScripts: watchScripts()) { match in
            collector.add(try await self.apply(match: match))
        }
        let toHeight = await sync.lastScannedHeight
        return try ImportReport.make(bundle: bundle, effects: collector.effects, finalUTXOs: utxos,
                                           scannedFromHeight: fromHeight, scannedToHeight: toHeight)
    }
}
