import CryptoKit
import Foundation

public enum MultisigAccountError: Error, Equatable {
    /// Not a supported account shape: `tr(NUMS, sortedmulti_a(k, …))`.
    case invalidDescriptor(String)
    /// A coin's scriptPubKey does not match the descriptor at its coordinates.
    case scriptMismatch(index: UInt32, choice: Int)
    /// No signer key for this input derives from the loaded key.
    case noSignerKey(input: Int)
    /// An imported spend is not an exact, safe spend of known account coins.
    case invalidSpend(String)
}

extension MultisigAccountError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        // `reason` is interpolated, so it is always a developer-written
        // literal describing the shape that failed: never user input, and
        // never part of the descriptor, which can carry key material.
        case let .invalidDescriptor(reason): "The multisig descriptor is invalid: \(reason)."
        case let .scriptMismatch(index, choice):
            "Multisig key \(choice)/\(index) does not produce the stored Bitcoin output."
        case let .noSignerKey(input): "This device holds no signer key for input \(input + 1)."
        case let .invalidSpend(reason): "This multisig spend is unsafe: \(reason)."
        }
    }
}

/// One stored multisig account: the descriptor, its address frontiers and
/// the coins the wallet's filter scan found for it. Spent coins stay as
/// tombstones so a reorg can restore them. The JSON keys match the vault
/// records of the shared-account Winnow, so its backups of script-path
/// accounts restore here.
public struct MultisigAccountRecord: Codable, Equatable, Identifiable, Sendable {
    /// The descriptor's BIP380 checksum.
    public var id: String
    public var name: String
    public var descriptor: String
    public var createdAtHeight: UInt32
    public var nextReceiveIndex: UInt32 = 0
    public var nextChangeIndex: UInt32 = 0
    public var allUtxos: [WalletUTXO] = []
    /// Present when a Ledger is one of the signers and has registered this
    /// account; absent in records written before Ledger support.
    public var ledger: LedgerRegistration?

    public init(id: String, name: String, descriptor: String, createdAtHeight: UInt32,
                nextReceiveIndex: UInt32 = 0, nextChangeIndex: UInt32 = 0,
                allUtxos: [WalletUTXO] = [], ledger: LedgerRegistration? = nil) {
        self.id = id
        self.name = name
        self.descriptor = descriptor
        self.createdAtHeight = createdAtHeight
        self.nextReceiveIndex = nextReceiveIndex
        self.nextChangeIndex = nextChangeIndex
        self.allUtxos = allUtxos
        self.ledger = ledger
    }

    public var utxos: [WalletUTXO] { allUtxos.filter { !$0.isSpent } }
    public var balance: Int64 { utxos.reduce(0) { $0 + $1.amount } }

    /// A stored Ledger registration must be this account's own policy and
    /// name one of its signers; anything else is refused with the record.
    public func checkLedgerRegistration(for account: MultisigAccount) throws {
        guard let ledger else { return }
        guard ledger.policyID.count == 32, ledger.hmac.count == 32,
              LedgerMultisig.ledgerSigner(of: account, fingerprint: ledger.masterFingerprint, path: ledger.keyPath) != nil,
              (try? LedgerWalletPolicy(name: ledger.policyName, account: account).id) == ledger.policyID else {
            throw MultisigAccountError.invalidDescriptor("the stored Ledger registration does not belong to this account")
        }
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, descriptor, createdAtHeight, nextReceiveIndex, nextChangeIndex, ledger
        case allUtxos = "utxos"
    }
}

/// A raw k-of-n Taproot script-path account:
/// `tr(NUMS, sortedmulti_a(k, XPUB/<0;1>/*, …))` (BIP386, BIP387). The
/// internal key is the BIP341 "nothing up my sleeve" point, so the
/// `multi_a` leaf is the only way to spend: any k of the n signers. Each
/// signer makes an ordinary BIP340 signature over the script-path sighash,
/// with no rounds and no nonce state. Spends travel as PSBT text with the
/// BIP371 leaf, origin and signature fields: the creator builds the PSBT,
/// signers add signatures in any order, and once k verify the finalizer
/// assembles the BIP387 witness.
public struct MultisigAccount: Sendable {
    /// A descriptor coordinate that may legitimately receive money back into
    /// this account. PSBT output metadata is never trusted for ownership.
    public struct OutputCoordinate: Hashable, Sendable {
        public var choice: Int
        public var index: UInt32

        public init(choice: Int, index: UInt32) {
            self.choice = choice
            self.index = index
        }
    }

    public struct SpendReview: Equatable, Sendable {
        public struct Output: Equatable, Sendable {
            public var amount: Int64
            public var scriptPubKey: Data
            public var isAccountOwned: Bool
        }

        public var outputs: [Output]
        public var inputTotal: Int64
        public var outputTotal: Int64
        public var fee: Int64
        /// `.recovery` when every input's sequence meets the recovery lock,
        /// so the recovery leaf can finish it as well as the signers' leaf.
        public var path: SpendPath = .signers
    }

    /// The two ways an account can spend.
    public enum SpendPath: Hashable, Sendable {
        /// Any `threshold` of the signers, at once.
        case signers
        /// The recovery keys, once each coin is `Recovery.blocks` old.
        case recovery
    }

    /// An optional second leaf, `and_v(v:pk(K),older(N))` or
    /// `and_v(v:multi_a(m,…),older(N))`: after a coin has not moved for N
    /// blocks, `threshold` of these keys may spend it without the signers.
    public struct Recovery: Equatable, Sendable {
        public var threshold: Int
        public var keys: [Descriptor.SingleKey]
        /// BIP68 relative lock in blocks, 1...65535 (about 455 days).
        public var blocks: UInt32
    }

    /// How a new account's recovery leaf is chosen.
    public enum RecoveryPlan: Equatable, Sendable {
        /// After the delay, `threshold` of the same signers, each on its
        /// second derivation path `/<2;3>/*`.
        case fewerSigners(threshold: Int, blocks: UInt32)
        /// After the delay, `threshold` of these other keys (`…/<0;1>/*`).
        case separateKeys(threshold: Int, keys: [String], blocks: UInt32)
    }

    public let descriptor: Descriptor
    public let network: BitcoinNetwork
    /// Signatures a spend needs.
    public let threshold: Int
    /// The signers in descriptor order.
    public let signers: [Descriptor.SingleKey]
    /// Whether the leaf is `sortedmulti_a` (keys sorted in the script).
    public let isSorted: Bool
    /// The timelocked recovery leaf, if the account has one.
    public let recovery: Recovery?
    /// Whether the recovery leaf is the tree's first leaf.
    private let recoveryLeafFirst: Bool

    /// The longest relative lock accepted: BIP68's 16-bit block count.
    public static let maximumRecoveryBlocks: UInt32 = 0xFFFF
    /// A signer's key on its second path, for the recovery leaf only.
    static let recoverySuffix: [Descriptor.Derivation.Element] = [.multipath([2, 3]), .wildcard(hardened: false)]

    /// The only signer suffix accepted. Fixed templates are what make signer
    /// independence provable: `K/<0;1>/*` and `K/0/1` differ at (0, 0) and
    /// collide at (1, 0), so comparing keys at one coordinate is not a proof
    /// unless every signer carries the identical suffix (SEC-019).
    static let signerSuffix: [Descriptor.Derivation.Element] = [.multipath([0, 1]), .wildcard(hardened: false)]

    public init(descriptor: Descriptor, network: BitcoinNetwork) throws {
        guard case let .trTree(internalKey, tree) = descriptor.expression else {
            throw MultisigAccountError.invalidDescriptor("expected tr(NUMS, sortedmulti_a(k, …))")
        }
        let primaryLeaf: Descriptor.LeafExpression
        var recoveryLeaf: Descriptor.LeafExpression?
        var recoveryFirst = false
        switch tree {
        case let .leaf(leaf):
            primaryLeaf = leaf
        case let .branch(.leaf(left), .leaf(right)):
            // One leaf of signers and one timelocked recovery leaf, in either order.
            if case .timelocked = left { (primaryLeaf, recoveryLeaf, recoveryFirst) = (right, left, true) } else {
                (primaryLeaf, recoveryLeaf) = (left, right)
            }
        default:
            throw MultisigAccountError.invalidDescriptor(
                "a multisig account has one multi_a leaf, and at most one timelocked recovery leaf beside it")
        }
        let threshold: Int
        let signers: [Descriptor.SingleKey]
        let sorted: Bool
        switch primaryLeaf {
        case let .sortedMultiA(k, keys): (threshold, signers, sorted) = (k, keys, true)
        case let .multiA(k, keys): (threshold, signers, sorted) = (k, keys, false)
        default:
            throw MultisigAccountError.invalidDescriptor("a multisig account has exactly one multi_a leaf")
        }
        // SEC-020: with a real internal key, whoever holds it spends alone,
        // whatever the threshold says.
        guard Self.isUnspendable(internalKey, network: network) else {
            throw MultisigAccountError.invalidDescriptor(
                "the internal key can spend on its own, which would bypass the signers it lists")
        }
        guard signers.count >= 2 else {
            throw MultisigAccountError.invalidDescriptor("a multisig account needs at least two signers")
        }
        guard (1 ... signers.count).contains(threshold) else {
            throw MultisigAccountError.invalidDescriptor("the threshold must be between one and the number of signers")
        }
        for signer in signers {
            try Self.requireAccountKey(signer, network: network)
        }
        self.descriptor = descriptor
        self.network = network
        self.threshold = threshold
        self.signers = signers
        isSorted = sorted
        recoveryLeafFirst = recoveryFirst
        recovery = try recoveryLeaf.map { try Self.recovery(from: $0, signers: signers, network: network) }
        try requireDistinctSigners()
    }

    /// The recovery leaf's rules: a timelock of 1...65535 blocks, distinct
    /// keys, each an origin-bearing public key of this network. A key that is
    /// also a signer appears with that signer's own origin on its second path
    /// `/<2;3>/*`; any other key on `/<0;1>/*` (SEC-019). No derived key is
    /// therefore shared between the leaves, which BIP388 signers such as a
    /// Ledger also require, and a signer finds its key in both leaves by the
    /// same fingerprint and path. Joining with a relabelled signer is refused
    /// in AppTests/MultisigAccountFlowTests.testBuilderMakesAccountWithAnotherWinnowAndRecovery;
    /// the other look-alikes are in TimelockedMultisigTests.admissionRefusals.
    private static func recovery(from leaf: Descriptor.LeafExpression, signers: [Descriptor.SingleKey],
                                 network: BitcoinNetwork) throws -> Recovery {
        guard case let .timelocked(condition, blocks) = leaf else {
            throw MultisigAccountError.invalidDescriptor("the second leaf must be a timelocked recovery path")
        }
        guard (1 ... maximumRecoveryBlocks).contains(blocks) else {
            throw MultisigAccountError.invalidDescriptor("a recovery delay must be 1 to 65535 blocks")
        }
        var signerOrigins: [Data: Descriptor.KeyOrigin] = [:]
        for signer in signers {
            if case let .extended(key, _) = signer.base, let origin = signer.origin {
                signerOrigins[key.publicKey] = origin
            }
        }
        var seen: Set<Data> = []
        for key in condition.keys {
            try requireRecoveryKey(key, signerOrigins: signerOrigins, seen: &seen, network: network)
        }
        return Recovery(threshold: condition.threshold, keys: condition.keys, blocks: blocks)
    }

    /// One recovery key: an extended key not seen before in the leaf; a
    /// signer's key carries that signer's origin and `/<2;3>/*`, any other
    /// key `/<0;1>/*`.
    private static func requireRecoveryKey(_ key: Descriptor.SingleKey, signerOrigins: [Data: Descriptor.KeyOrigin],
                                           seen: inout Set<Data>, network: BitcoinNetwork) throws {
        guard case let .extended(xpub, _) = key.base else {
            throw MultisigAccountError.invalidDescriptor("every recovery key must be an extended public key")
        }
        guard seen.insert(xpub.publicKey).inserted else {
            throw MultisigAccountError.invalidDescriptor("the same recovery key appears more than once")
        }
        let signerOrigin = signerOrigins[xpub.publicKey]
        guard signerOrigin == nil || key.origin == signerOrigin else {
            throw MultisigAccountError.invalidDescriptor(
                "a signer reused for recovery must keep its own fingerprint and path there")
        }
        try requireAccountKey(key, network: network, suffix: signerOrigin == nil ? signerSuffix : recoverySuffix)
    }

    public init(_ string: String, network: BitcoinNetwork) throws {
        try self.init(descriptor: Descriptor(string), network: network)
    }

    /// The canonical account descriptor: `tr(NUMS, sortedmulti_a(k, …))`
    /// over the given signer key expressions (`[fp/86'/1'/0']xpub…/<0;1>/*`),
    /// validated as an account for `network`. The internal key is written as
    /// an extended key on the NUMS point (`unspendableKeyExpression`), so a
    /// BIP388 signer such as a Ledger can register the account.
    ///
    /// The signers, and a recovery leaf's separate keys, are written in one
    /// canonical order whatever order they arrive in: by x-only account key,
    /// ascending. The internal key's chain code hashes the keys in written
    /// order, so without it two people listing the same keys differently,
    /// or someone rebuilding an account from its keys, would get another
    /// account with other addresses. Accounts built before this keep their
    /// stored descriptor, which carries its own internal key. Order
    /// independence is in MultisigAccountTests.signerOrderDoesNotMatter and
    /// TimelockedMultisigTests.recoveryKeyOrderDoesNotMatter;
    /// `scripts/check-multisig-core` holds the addresses to Bitcoin Core.
    public static func descriptor(threshold: Int, signers: [String], recovery: RecoveryPlan? = nil,
                                  network: BitcoinNetwork) throws -> Descriptor {
        let signers = try canonicalOrder(signers)
        let recovery = try recovery.map { plan -> RecoveryPlan in
            guard case let .separateKeys(m, keys, blocks) = plan else { return plan }
            return .separateKeys(threshold: m, keys: try canonicalOrder(keys), blocks: blocks)
        }
        var leaf = "sortedmulti_a(\(threshold),\(signers.joined(separator: ",")))"
        if let recovery { leaf = "{\(leaf),\(try recoveryLeaf(recovery, signers: signers))}" }
        let descriptor: Descriptor
        do {
            let draft = try Descriptor("tr(\(Taproot.unspendableInternalKey.hex),\(leaf))")
            let internalKey = try unspendableKeyExpression(leafKeys: Array(draft.allKeys.dropFirst()), network: network)
            descriptor = try Descriptor("tr(\(internalKey),\(leaf))")
        } catch let error as MultisigAccountError {
            throw error
        } catch {
            throw MultisigAccountError.invalidDescriptor("a signer key expression does not parse")
        }
        _ = try MultisigAccount(descriptor: descriptor, network: network)
        return descriptor
    }

    /// Key expressions sorted by their x-only account key, ascending (the
    /// order `sortedmulti_a` gives its derived keys).
    private static func canonicalOrder(_ expressions: [String]) throws -> [String] {
        let keyed = try expressions.map { expression -> (key: Data, expression: String) in
            guard let parsed = try? Descriptor("tr(\(expression))"), case let .tr(single) = parsed.expression,
                  case let .extended(xpub, _) = single.base else {
                throw MultisigAccountError.invalidDescriptor("a signer key expression does not parse")
            }
            return (Data(xpub.publicKey.dropFirst()), expression)
        }
        return keyed.sorted { $0.key.lexicographicallyPrecedes($1.key) }.map(\.expression)
    }

    /// The recovery leaf's text: `and_v(v:pk(K),older(N))` for one key,
    /// `and_v(v:multi_a(m,…),older(N))` for several. Reused signers move to
    /// their `/<2;3>/*` path.
    private static func recoveryLeaf(_ plan: RecoveryPlan, signers: [String]) throws -> String {
        let (threshold, keys, blocks): (Int, [String], UInt32)
        switch plan {
        case let .fewerSigners(m, n):
            let suffix = "/<0;1>/*"
            guard signers.allSatisfy({ $0.hasSuffix(suffix) }) else {
                throw MultisigAccountError.invalidDescriptor(
                    "every signer must use the /<0;1>/* suffix, so the signers can be shown to be independent")
            }
            (threshold, keys, blocks) = (m, signers.map { String($0.dropLast(suffix.count)) + "/<2;3>/*" }, n)
        case let .separateKeys(m, others, n):
            (threshold, keys, blocks) = (m, others, n)
        }
        guard (1 ... maximumRecoveryBlocks).contains(blocks) else {
            throw MultisigAccountError.invalidDescriptor("a recovery delay must be 1 to 65535 blocks")
        }
        guard (1 ... keys.count).contains(threshold) else {
            throw MultisigAccountError.invalidDescriptor("the recovery threshold must be between one and its number of keys")
        }
        if keys.count == 1 { return "and_v(v:pk(\(keys[0])),older(\(blocks)))" }
        return "and_v(v:multi_a(\(threshold),\(keys.joined(separator: ","))),older(\(blocks)))"
    }

    /// BIP388 wallet policies, and so Ledger's Bitcoin app, admit only
    /// extended keys, never a bare public key. The internal key is therefore
    /// an xpub on BIP341's NUMS point H, built as Liana builds it: chain code
    /// SHA-256 of the leaf keys' compressed public keys in descriptor order,
    /// depth 0, no origin, the shared `/<0;1>/*` suffix. Every child is
    /// H + t·G for a public t, so no one knows its discrete logarithm.
    static func unspendableKeyExpression(leafKeys: [Descriptor.SingleKey], network: BitcoinNetwork) throws -> String {
        var concatenated = Data()
        for key in leafKeys {
            guard case let .extended(xpub, _) = key.base else {
                throw MultisigAccountError.invalidDescriptor("every signer must be an extended public key carrying its origin")
            }
            concatenated.append(xpub.publicKey)
        }
        let nums = HDKey(depth: 0, parentFingerprint: 0, childIndex: 0, chainCode: Data(SHA256.hash(data: concatenated)),
                         privateKey: nil, publicKey: Data([0x02]) + Taproot.unspendableInternalKey)
        return nums.serialized(network: hdNetwork(for: network)) + "/<0;1>/*"
    }

    /// SEC-020: the internal key must be one nobody can sign for. Two forms
    /// qualify: the bare NUMS key H (accounts made before Ledger support),
    /// and an xpub with no origin whose key is H under the signers' suffix,
    /// on this network. Any chain code is safe: children of H stay unknown
    /// logarithms. Anything else is a key someone may hold.
    static func isUnspendable(_ key: Descriptor.SingleKey, network: BitcoinNetwork) -> Bool {
        guard key.origin == nil else { return false }
        switch key.base {
        case let .publicKey(raw):
            return key.derivation.elements.isEmpty
                && (raw.count == 32 ? raw : Data(raw.dropFirst())) == Taproot.unspendableInternalKey
        case let .extended(xpub, keyNetwork):
            return xpub.privateKey == nil && keyNetwork == hdNetwork(for: network)
                && xpub.publicKey == Data([0x02]) + Taproot.unspendableInternalKey
                && key.derivation.elements == signerSuffix
        case .privateKey:
            return false
        }
    }

    /// The account's stable identifier: the descriptor's BIP380 checksum.
    public var id: String { String(descriptor.serialized().suffix(8)) }

    static func hdNetwork(for network: BitcoinNetwork) -> HDKey.Network {
        network == .mainnet ? .mainnet : .testnet
    }

    /// A signer as accepted here: an extended public key with its origin, on
    /// this network, under the fixed `/<0;1>/*` suffix. The origin must
    /// describe the key supplied: as many steps as the key is deep, ending at
    /// the key's own child index.
    private static func requireAccountKey(_ single: Descriptor.SingleKey, network: BitcoinNetwork,
                                          suffix: [Descriptor.Derivation.Element] = signerSuffix) throws {
        guard case let .extended(key, keyNetwork) = single.base, key.privateKey == nil,
              let origin = single.origin else {
            throw MultisigAccountError.invalidDescriptor("every signer must be an extended public key carrying its origin")
        }
        guard origin.path.count == Int(key.depth), key.depth == 0 || origin.path.last == key.childIndex else {
            throw MultisigAccountError.invalidDescriptor("a signer's origin path does not match its key")
        }
        guard keyNetwork == hdNetwork(for: network) else {
            throw MultisigAccountError.invalidDescriptor("a signer's extended key belongs to a different network")
        }
        guard single.derivation.elements == suffix else {
            throw MultisigAccountError.invalidDescriptor(suffix == signerSuffix
                ? "every signer must use the /<0;1>/* suffix, so the signers can be shown to be independent"
                : "a signer reused for recovery must use its /<2;3>/* path there")
        }
    }

    /// Every key expression in the account: the signers, then the recovery keys.
    public var allKeys: [Descriptor.SingleKey] { signers + (recovery?.keys ?? []) }

    /// The keys of `path`'s leaf, in descriptor order; none for a recovery
    /// path the account does not have.
    public func keys(on path: SpendPath) -> [Descriptor.SingleKey] {
        path == .recovery ? (recovery?.keys ?? []) : signers
    }

    /// How many of `path`'s keys must sign.
    public func threshold(on path: SpendPath) -> Int {
        path == .recovery ? (recovery?.threshold ?? 0) : threshold
    }

    /// A k-of-n account is only k-of-n if its signers are n distinct keys
    /// (SEC-009): a repeated signer needs fewer independent signers than the
    /// policy advertises. Account keys are compared as key material, so
    /// relabelling an origin cannot disguise a repeat; with one suffix
    /// template for everyone, distinct account keys never collide below.
    private func requireDistinctSigners() throws {
        var seen: Set<Data> = []
        for signer in signers {
            guard case let .extended(key, _) = signer.base, seen.insert(key.publicKey).inserted else {
                throw MultisigAccountError.invalidDescriptor(
                    "the same signing key appears more than once, so this account needs fewer signers than it claims")
            }
        }
    }

    /// Whether one signer is this account public key, whatever origin label
    /// the descriptor gives it.
    public func includes(accountKey: HDKey) -> Bool {
        allKeys.contains { signer in
            guard case let .extended(base, _) = signer.base else { return false }
            return base.publicKey == accountKey.publicKey
        }
    }

    /// Whether `key` (a master or BIP86 account key) holds one signer.
    public func hasSigner(for key: HDKey) -> Bool {
        allKeys.contains { (try? Self.accountSecretKey(for: $0, from: key)) != nil }
    }

    // MARK: - Watching

    /// scriptPubKey at (multipath choice, index): choice 0 receive, 1 change.
    public func scriptPubKey(index: UInt32, choice: Int = 0) throws -> Data {
        try descriptor.derived(index: index, bitcoinNetwork: network)[choice].scriptPubKey
    }

    public func address(index: UInt32, choice: Int = 0) throws -> String {
        try descriptor.derived(index: index, bitcoinNetwork: network)[choice].address
    }

    /// Both multipath choices for indices 0..<count.
    public func watchScripts(upTo count: UInt32) throws -> [Data] {
        var scripts: [Data] = []
        for index in 0 ..< count {
            for output in try descriptor.derived(index: index, bitcoinNetwork: network) {
                scripts.append(output.scriptPubKey)
            }
        }
        return scripts
    }

    /// The leaf script, its control block and the internal key at
    /// (choice, index), from the descriptor alone.
    struct Leaf {
        var internalKey: Data
        var version: UInt8
        var script: Script
        var controlBlock: Taproot.ControlBlock
        var isRecovery: Bool

        var hash: Data { Taproot.leafHash(version: version, script: script) }
    }

    /// The signers' leaf at (choice, index).
    func leaf(choice: Int, index: UInt32) throws -> Leaf {
        try leaves(choice: choice, index: index).first { !$0.isRecovery }!
    }

    /// Every leaf at (choice, index) in tree order, with its control block.
    func leaves(choice: Int, index: UInt32) throws -> [Leaf] {
        let (internalKey, tree) = try descriptor.resolvedTaproot(index: index, choice: choice)
        let blocks = try Taproot.controlBlocks(internalKey: internalKey, tree: tree)
        var scripts: [(UInt8, Script)] = []
        func collect(_ node: Taproot.Tree) {
            switch node {
            case let .leaf(version, script): scripts.append((version, script))
            case let .branch(left, right):
                collect(left)
                collect(right)
            }
        }
        collect(tree)
        guard scripts.count == blocks.count, scripts.count == (recovery == nil ? 1 : 2) else {
            throw MultisigAccountError.invalidDescriptor("the account's tree does not resolve to its leaves")
        }
        return scripts.enumerated().map { position, leaf in
            Leaf(internalKey: internalKey, version: leaf.0, script: leaf.1, controlBlock: blocks[position],
                 isRecovery: recovery != nil && (position == 0) == recoveryLeafFirst)
        }
    }

    /// Whether `coin` may already be spent on the recovery path in the next
    /// block: confirmed at least `Recovery.blocks` blocks below it.
    public func isUnlockedForRecovery(_ coin: WalletUTXO, chainTip: UInt32) -> Bool {
        guard let recovery, coin.height > 0, chainTip >= coin.height else { return false }
        return chainTip - coin.height + 1 >= recovery.blocks
    }

    /// The first block in which `coin` can be spent on the recovery path;
    /// nil when it is unconfirmed or that block is past `UInt32.max`. Pinned
    /// in TimelockedMultisigTests.fewerSigners, and held to Bitcoin Core's
    /// BIP68 boundary, with `isUnlockedForRecovery`, by
    /// `scripts/check-multisig-core`.
    public func recoveryUnlockHeight(of coin: WalletUTXO) -> UInt32? {
        guard let recovery, coin.height > 0 else { return nil }
        let (unlock, overflow) = coin.height.addingReportingOverflow(recovery.blocks)
        return overflow ? nil : unlock
    }

    // MARK: - Review

    /// Validates a PSBT before it is shown, signed, finalized or broadcast:
    /// every input is a unique known coin of this account with the exact
    /// amount and script the sighash commits to and this account's own leaf
    /// and internal key; every signature commits to all outputs; amounts are
    /// valid; the fee is at most 10% of the inputs. Output ownership comes
    /// only from matching scripts against caller-supplied coordinates, never
    /// from PSBT metadata (SEC-004).
    public func reviewSpend(_ psbt: PSBT, knownUTXOs: [WalletUTXO],
                            ownedOutputCoordinates: [OutputCoordinate],
                            chainTip: UInt32) throws -> SpendReview {
        guard !psbt.inputs.isEmpty else { throw MultisigAccountError.invalidSpend("it has no inputs") }
        guard !psbt.outputs.isEmpty, psbt.outputs.count <= 1_000 else {
            throw MultisigAccountError.invalidSpend("it has no outputs or more than 1,000")
        }
        guard psbt.txVersion == 1 || psbt.txVersion == 2 else {
            throw MultisigAccountError.invalidSpend("transaction version \(psbt.txVersion) is not supported")
        }
        let path = try spendPath(of: psbt)
        let inputTotal = try reviewedInputTotal(of: psbt, knownUTXOs: knownUTXOs, chainTip: chainTip, path: path)
        let outputs = try reviewedOutputs(of: psbt, inputTotal: inputTotal,
                                          ownedOutputCoordinates: ownedOutputCoordinates)
        let fee = inputTotal - outputs.total
        try Self.checkFeeCeiling(fee: fee, inputTotal: inputTotal)
        return SpendReview(outputs: outputs.reviewed, inputTotal: inputTotal, outputTotal: outputs.total, fee: fee,
                           path: path)
    }

    /// The recovery path when every input's sequence meets the recovery
    /// leaf's lock, otherwise the signers' path. The signers' leaf has no
    /// lock, so it can finish either: sequences that meet the lock come from
    /// a recovery spend or, on old coins, from a co-signer's BIP326
    /// anti-fee-sniping, and a mix can only finish on the signers' leaf.
    /// Exercised by the journey's recovery leg (UITests/MultisigJourney.swift)
    /// and, for a mix across two phones,
    /// AppTests/MultisigAccountFlowTests.testTwoPhonesSignACoSignersSpendWithBIP326Sequences.
    func spendPath(of psbt: PSBT) throws -> SpendPath {
        guard let recovery else { return .signers }
        let tx = try psbt.unsignedTransaction()
        let meetsLock = tx.inputs.allSatisfy {
            RelativeLock.isSatisfied(blocks: recovery.blocks, sequence: $0.sequence, txVersion: tx.version)
        }
        return meetsLock ? .recovery : .signers
    }

    private static let maxMoney: Int64 = 2_100_000_000_000_000

    /// One rule for the creator and every reviewer: at most 10% of the
    /// inputs may go to the miner.
    private static func checkFeeCeiling(fee: Int64, inputTotal: Int64) throws {
        guard fee <= inputTotal / 10 else {
            throw MultisigAccountError.invalidSpend("the \(fee)-sat fee exceeds the 10% safety limit for these inputs")
        }
    }

    private func reviewedInputTotal(of psbt: PSBT, knownUTXOs: [WalletUTXO], chainTip: UInt32,
                                    path: SpendPath) throws -> Int64 {
        var seen: Set<Transaction.Outpoint> = []
        var total: Int64 = 0
        for (inputIndex, input) in psbt.inputs.enumerated() {
            guard let txid = input.previousTxid, txid.count == 32, let vout = input.outputIndex else {
                throw MultisigAccountError.invalidSpend("input \(inputIndex + 1) has no complete outpoint")
            }
            let outpoint = Transaction.Outpoint(txid: txid, vout: vout)
            guard seen.insert(outpoint).inserted else {
                throw MultisigAccountError.invalidSpend("input \(inputIndex + 1) repeats an earlier outpoint")
            }
            guard let known = knownUTXOs.first(where: { $0.outpoint == outpoint }) else {
                throw MultisigAccountError.invalidSpend("input \(inputIndex + 1) is not an available coin of this account")
            }
            try checkInput(input, inputIndex: inputIndex, utxo: known, chainTip: chainTip)
            if path == .recovery, !isUnlockedForRecovery(known, chainTip: chainTip) {
                let unlock = recoveryUnlockHeight(of: known).map { "at block \($0)" }
                    ?? (known.height > 0 ? "past the last block height" : "once it confirms")
                throw MultisigAccountError.invalidSpend("input \(inputIndex + 1) unlocks for recovery only \(unlock)")
            }
            let (sum, overflow) = total.addingReportingOverflow(known.amount)
            guard !overflow, sum <= Self.maxMoney else {
                throw MultisigAccountError.invalidSpend("input amounts exceed Bitcoin's supply")
            }
            total = sum
        }
        return total
    }

    private func checkInput(_ input: PSBT.Input, inputIndex: Int, utxo known: WalletUTXO, chainTip: UInt32) throws {
        guard known.amount > 0, known.amount <= Self.maxMoney,
              let claimed = input.witnessUTXO, claimed == known.spentOutput else {
            throw MultisigAccountError.invalidSpend("input \(inputIndex + 1) has the wrong amount or locking script")
        }
        if known.isCoinbase {
            // In 64 bits: a stored height within 100 of the top must refuse, not trap.
            let matureAt = UInt64(known.height) + UInt64(Wallet.coinbaseMaturity) - 1
            guard UInt64(chainTip) >= matureAt else {
                throw MultisigAccountError.invalidSpend(
                    "input \(inputIndex + 1) spends a coinbase that matures in \(matureAt - UInt64(chainTip)) blocks")
            }
        }
        guard try scriptPubKey(index: known.index, choice: known.chain.rawValue) == known.scriptPubKey else {
            throw MultisigAccountError.invalidSpend("input \(inputIndex + 1) does not belong to this descriptor")
        }
        let rawSighash = input.sighashType ?? 0
        guard rawSighash == 0 || rawSighash == 1 else {
            throw MultisigAccountError.invalidSpend("input \(inputIndex + 1) does not commit to every output")
        }
        let expected = try leaves(choice: known.chain.rawValue, index: known.index)
        let expectedLeaves = expected.map {
            PSBT.TapLeafScript(controlBlock: $0.controlBlock, script: $0.script.bytes, leafVersion: $0.version)
        }
        let sortKey = { (leaf: PSBT.TapLeafScript) in leaf.controlBlock.serialized + leaf.script }
        let attached = input.tapLeafScripts.sorted { sortKey($0).lexicographicallyPrecedes(sortKey($1)) }
        guard input.tapInternalKey == expected.first?.internalKey,
              attached == expectedLeaves.sorted(by: { sortKey($0).lexicographicallyPrecedes(sortKey($1)) }) else {
            throw MultisigAccountError.invalidSpend("input \(inputIndex + 1) changes the spending policy")
        }
    }

    private func reviewedOutputs(of psbt: PSBT, inputTotal: Int64, ownedOutputCoordinates: [OutputCoordinate])
        throws -> (reviewed: [SpendReview.Output], total: Int64) {
        let candidates = Array(Set(ownedOutputCoordinates.filter { (0 ... 1).contains($0.choice) }))
        guard candidates.count <= 1_024 else {
            throw MultisigAccountError.invalidSpend("too many candidate account output paths")
        }
        let owned = Set(try candidates.map { try scriptPubKey(index: $0.index, choice: $0.choice) })
        var total: Int64 = 0
        var reviewed: [SpendReview.Output] = []
        for (outputIndex, output) in psbt.outputs.enumerated() {
            guard let amount = output.amount, amount > 0, amount <= Self.maxMoney,
                  let script = output.script, !script.isEmpty else {
                throw MultisigAccountError.invalidSpend("output \(outputIndex + 1) has an invalid amount or script")
            }
            let (sum, overflow) = total.addingReportingOverflow(amount)
            guard !overflow, sum <= Self.maxMoney else {
                throw MultisigAccountError.invalidSpend("output amounts exceed Bitcoin's supply")
            }
            total = sum
            reviewed.append(SpendReview.Output(amount: amount, scriptPubKey: script, isAccountOwned: owned.contains(script)))
        }
        guard total <= inputTotal else { throw MultisigAccountError.invalidSpend("outputs exceed its known inputs") }
        return (reviewed, total)
    }

    // MARK: - Creating a spend

    /// Builds the unsigned spend PSBT: coin selection sized for the BIP387
    /// witness, the transaction with an anti-fee-sniping locktime, the BIP371
    /// leaf and per-signer origins on every input, and the internal key, tap
    /// tree and signer origins on the change output.
    public func createSpend(utxos: [WalletUTXO], payments: [Payment], changeIndex: UInt32,
                            feeRateSatPerVByte: Double, chainTip: UInt32, path: SpendPath = .signers,
                            randomness: @Sendable () -> Double = { Double.random(in: 0 ..< 1) }) throws -> PSBT {
        for utxo in utxos {
            guard try scriptPubKey(index: utxo.index, choice: utxo.chain.rawValue) == utxo.scriptPubKey else {
                throw MultisigAccountError.scriptMismatch(index: utxo.index, choice: utxo.chain.rawValue)
            }
        }
        let (spendable, sequence) = try spendableCoins(utxos, path: path, chainTip: chainTip)
        let changeScript = try scriptPubKey(index: changeIndex, choice: AddressChain.change.rawValue)
        let selection = try CoinSelection.select(utxos: spendable, payments: payments, changeScriptPubKey: changeScript,
                                                 feeRateSatPerVByte: feeRateSatPerVByte,
                                                 witnessBytesPerInput: try witnessBytesPerInput(path: path))
        try Self.checkFeeCeiling(fee: selection.fee, inputTotal: selection.selected.reduce(0) { $0 + $1.amount })
        let change = selection.changeAmount.map { Payment(amount: $0, scriptPubKey: changeScript) }
        let tx = try TransactionBuilder.build(
            inputs: selection.selected.map(\.outpoint), payments: payments, change: change, sequence: sequence,
            locktime: TransactionBuilder.antiFeeSnipingLocktime(tip: chainTip, randomness: randomness))
        var psbt = try PSBT(unsignedTx: tx,
                            inputs: selection.selected.map { PSBT.InputInfo(spentOutput: $0.spentOutput) },
                            outputs: tx.outputs.map { _ in PSBT.OutputInfo() })
        for (inputIndex, utxo) in selection.selected.enumerated() {
            let leaves = try leaves(choice: utxo.chain.rawValue, index: utxo.index)
            try psbt.attachScriptPaths(input: inputIndex,
                                       leaves: leaves.map { ($0.controlBlock, $0.script, $0.version) },
                                       keyOrigins: keyOrigins(choice: utxo.chain.rawValue, index: utxo.index))
        }
        if let change { try describeChange(change, index: changeIndex, in: &psbt) }
        return psbt
    }

    /// The coins a spend on `path` may use and the sequence its inputs carry:
    /// all of them on the signers' path; on the recovery path only those at
    /// least `Recovery.blocks` deep, with that many blocks as the sequence.
    private func spendableCoins(_ utxos: [WalletUTXO], path: SpendPath,
                                chainTip: UInt32) throws -> (coins: [WalletUTXO], sequence: UInt32) {
        guard path == .recovery else { return (utxos, TransactionBuilder.defaultSequence) }
        guard let recovery else { throw MultisigAccountError.invalidSpend("this account has no recovery path") }
        let unlocked = utxos.filter { isUnlockedForRecovery($0, chainTip: chainTip) }
        guard !unlocked.isEmpty else {
            throw MultisigAccountError.invalidSpend(
                "no coin has stayed unmoved for \(recovery.blocks) blocks yet, so none can be recovered")
        }
        return (unlocked, recovery.blocks)
    }

    /// The internal key, tap tree and signer origins on the change output.
    private func describeChange(_ change: Payment, index changeIndex: UInt32, in psbt: inout PSBT) throws {
        let leaves = try leaves(choice: AddressChain.change.rawValue, index: changeIndex)
        let depth: UInt8 = leaves.count == 1 ? 0 : 1
        for outputIndex in psbt.outputs.indices where psbt.outputs[outputIndex].script == change.scriptPubKey
            && psbt.outputs[outputIndex].amount == change.amount {
            psbt.outputs[outputIndex].tapInternalKey = leaves[0].internalKey
            // Right subtree first, as Bitcoin Core's TaprootBuilder lists it:
            // still a BIP371 depth-first order with the same Merkle root, and
            // the bytes Core writes, so its PSBT combines with ours.
            psbt.outputs[outputIndex].tapTree = leaves.reversed().map {
                (depth: depth, leafVersion: $0.version, script: $0.script.bytes)
            }
            psbt.outputs[outputIndex].tapBIP32Derivation = try keyOrigins(
                choice: AddressChain.change.rawValue, index: changeIndex)
        }
    }

    /// Per-input witness bytes for fee estimation, exact for this account's
    /// spend on `path`: item count, one 64-byte signature or empty
    /// placeholder per key slot of that leaf (counted as signatures, the
    /// worst case), the leaf script and its control block (33 bytes, plus 32
    /// for the sibling when the account has two leaves), each length-prefixed.
    func witnessBytesPerInput(path: SpendPath = .signers) throws -> Int {
        let leaves = try leaves(choice: 0, index: 0)
        guard let leaf = leaves.first(where: { $0.isRecovery == (path == .recovery) }) else {
            throw MultisigAccountError.invalidSpend("this account has no recovery path")
        }
        let slots = keys(on: path).count
        let scriptSize = leaf.script.bytes.count
        let controlBlockSize = 33 + 32 * (leaves.count - 1)
        return 1 + slots * 65 + Self.compactSizeLength(scriptSize) + scriptSize + 1 + controlBlockSize
    }

    private static func compactSizeLength(_ value: Int) -> Int {
        value < 0xFD ? 1 : (value <= 0xFFFF ? 3 : 5)
    }

    /// BIP371 key origins for every signer at (choice, index): master
    /// fingerprint, the full path (origin path plus the suffix steps taken at
    /// (choice, index)) and the leaf hashes the key signs for.
    private func keyOrigins(choice: Int, index: UInt32) throws -> [Data: PSBT.KeyOrigin] {
        let leaves = try leaves(choice: choice, index: index)
        let signerLeaf = leaves.first { !$0.isRecovery }!.hash
        let recoveryLeaf = leaves.first { $0.isRecovery }?.hash
        var origins: [Data: PSBT.KeyOrigin] = [:]
        let tagged = signers.map { ($0, signerLeaf) } + (recovery?.keys ?? []).compactMap { key in recoveryLeaf.map { (key, $0) } }
        for (key, leafHash) in tagged {
            guard let origin = key.origin else { continue }
            let xonly = Data(try descriptor.publicKey(of: key, index: index, choice: choice).dropFirst())
            origins[xonly] = PSBT.KeyOrigin(leafHashes: [leafHash], masterFingerprint: origin.fingerprint,
                                            path: origin.path + Self.suffixSteps(of: key, choice: choice, index: index))
        }
        return origins
    }

    /// The suffix steps a key expression takes at (choice, index):
    /// `/<0;1>/*` gives choice, index; `/<2;3>/*` gives 2 + choice, index.
    static func suffixSteps(of key: Descriptor.SingleKey, choice: Int, index: UInt32) -> [UInt32] {
        key.derivation.elements.map { element in
            switch element {
            case let .step(step): step
            case let .multipath(values): values[choice]
            case let .wildcard(hardened): index + (hardened ? HDKey.hardenedOffset : 0)
            }
        }
    }

    // MARK: - Signing

    /// Reviews the spend, then adds a script-path signature to every input
    /// for each signer `key` holds (a master or the BIP86 account key itself).
    /// Throws `noSignerKey` when an input has no signer this key can sign for.
    public func sign(_ psbt: inout PSBT, signingKey key: HDKey, knownUTXOs: [WalletUTXO],
                     ownedOutputCoordinates: [OutputCoordinate], chainTip: UInt32) throws {
        _ = try reviewSpend(psbt, knownUTXOs: knownUTXOs, ownedOutputCoordinates: ownedOutputCoordinates,
                            chainTip: chainTip)
        var signed = psbt
        for input in signed.inputs.indices {
            let utxo = try coin(for: signed, input: input, knownUTXOs: knownUTXOs)
            var secrets: [Data] = []
            for signer in allKeys {
                guard let account = try Self.accountSecretKey(for: signer, from: key) else { continue }
                var child = account
                for step in Self.suffixSteps(of: signer, choice: utxo.chain.rawValue, index: utxo.index) {
                    child = try child.child(at: step)
                }
                guard let secret = child.privateKey else { continue }
                secrets.append(secret)
            }
            guard !secrets.isEmpty else { throw MultisigAccountError.noSignerKey(input: input) }
            try signed.signScriptPath(input: input, privateKeys: secrets)
        }
        psbt = signed
    }

    /// Which signers (by position) have a verified signature on every input,
    /// judged by BIP340 verification against the recomputed sighash, never by
    /// the presence of an entry or any label in the PSBT.
    public func approvals(of psbt: PSBT, knownUTXOs: [WalletUTXO]) throws -> Set<Int> {
        try approvals(of: psbt, knownUTXOs: knownUTXOs, path: .signers)
    }

    /// Which keys of `path`'s leaf (by position: signers, or recovery keys)
    /// have a verified signature on that leaf of every input.
    public func approvals(of psbt: PSBT, knownUTXOs: [WalletUTXO], path: SpendPath) throws -> Set<Int> {
        let keys = keys(on: path)
        guard !keys.isEmpty else { return [] }
        let tx = try psbt.unsignedTransaction()
        let spentOutputs = try psbt.spentOutputs()
        var approved: Set<Int>?
        for input in psbt.inputs.indices {
            let utxo = try coin(for: psbt, input: input, knownUTXOs: knownUTXOs)
            guard let leaf = try leaves(choice: utxo.chain.rawValue, index: utxo.index)
                .first(where: { $0.isRecovery == (path == .recovery) }) else { return [] }
            let verified = try psbt.verifiedScriptPathSigners(input: input, leafHash: leaf.hash, tx: tx,
                                                              spentOutputs: spentOutputs)
            var here: Set<Int> = []
            for (position, key) in keys.enumerated() {
                let derived = try descriptor.publicKey(of: key, index: utxo.index, choice: utxo.chain.rawValue)
                if verified.contains(Data(derived.dropFirst())) { here.insert(position) }
            }
            approved = approved.map { $0.intersection(here) } ?? here
        }
        return approved ?? []
    }

    /// Finalizes a PSBT with at least `threshold` verified signatures per
    /// input and extracts the raw transaction, after one more review.
    public func finalizeSpend(_ psbt: inout PSBT, knownUTXOs: [WalletUTXO],
                              ownedOutputCoordinates: [OutputCoordinate], chainTip: UInt32) throws -> Transaction {
        _ = try reviewSpend(psbt, knownUTXOs: knownUTXOs, ownedOutputCoordinates: ownedOutputCoordinates,
                            chainTip: chainTip)
        var finalized = psbt
        try finalized.finalize()
        let transaction = try finalized.extractedTransaction()
        try Wallet.checkStandardSize(transaction)
        psbt = finalized
        return transaction
    }

    /// The input's coordinates, from the known coin it spends.
    private func coin(for psbt: PSBT, input: Int, knownUTXOs: [WalletUTXO]) throws -> WalletUTXO {
        guard psbt.inputs.indices.contains(input), let txid = psbt.inputs[input].previousTxid,
              let vout = psbt.inputs[input].outputIndex,
              let known = knownUTXOs.first(where: { $0.outpoint == Transaction.Outpoint(txid: txid, vout: vout) })
        else { throw MultisigAccountError.invalidSpend("input \(input + 1) is not an available coin of this account") }
        return known
    }

    // MARK: - Signer secrets

    /// The signer's account key with its private half, when `key` is that
    /// account key itself (an account-key wallet) or the master its origin
    /// descends from; nil otherwise.
    static func accountSecretKey(for single: Descriptor.SingleKey, from key: HDKey) throws -> HDKey? {
        guard case let .extended(base, _) = single.base, key.privateKey != nil else { return nil }
        if key.publicKey == base.publicKey, key.chainCode == base.chainCode { return key }
        guard let origin = single.origin, origin.fingerprint == key.fingerprint else { return nil }
        var derived = key
        for step in origin.path { derived = try derived.child(at: step) }
        guard derived.publicKey == base.publicKey, derived.chainCode == base.chainCode else { return nil }
        return derived
    }
}
