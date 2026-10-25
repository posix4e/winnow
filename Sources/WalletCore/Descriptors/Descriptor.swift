import Foundation
import P256K

public enum DescriptorError: Error, Equatable {
    case invalidChecksum
    case invalidCharacter
    case unexpectedEnd
    case unexpectedCharacter(Character)
    case unknownExpression(String)
    case invalidOrigin
    /// A key origin naming more steps than a BIP32 key can be deep. `HDKey.depth`
    /// is a byte and every walk down the path derives one child per step; the
    /// origin is walked when signing (`Wallet`), not by the descriptor's own
    /// key resolution, which walks only the suffix. Refused at the parse.
    case originTooDeep
    /// A key in the descriptor is already too deep for its own derivation
    /// suffix: a serialized key names any depth, and `HDKey.child(at:)`
    /// refuses past 255. Named here so it is not reported as a tweak failure.
    case keyDepthExhausted
    case invalidKey
    case invalidPath
    case derivationFailed
    /// A `multi_a`/`sortedmulti_a` threshold that is missing or outside
    /// 1...n, or more keys than BIP387 allows.
    case invalidThreshold
    /// An expression used where it is not defined, such as a leaf at the top
    /// level or a script-tree query on a descriptor without a tree.
    case invalidContext
    /// A script tree nested deeper than BIP341's 128 levels (SEC-010).
    case treeTooDeep
    /// An `older(N)` outside miniscript's 1...2^31 − 1.
    case invalidTimelock
}

extension HDKey.Network: Equatable {
    /// Legacy address prefix for callers using extended-key network versions.
    public var hrp: String { self == .mainnet ? "bc" : "tb" }
}

/// Output descriptor parse/serialize/derive engine (BIP380 general operation
/// and checksum, BIP386 `tr()`, BIP387 `multi_a`/`sortedmulti_a`, BIP389
/// multipath). The supported expressions are `tr(KEY)`, `rawtr(KEY)` and
/// `tr(KEY,TREE)`, where KEY is one key with an optional origin and derivation
/// suffix and TREE holds `pk`, `multi_a` and `sortedmulti_a` leaves for
/// script-path spending. `musig()` aggregation is not part of this build.
public struct Descriptor: Sendable, Equatable {
    /// BIP388-style key origin information: `[fingerprint/path]`.
    public struct KeyOrigin: Sendable, Equatable {
        public var fingerprint: UInt32
        /// Derivation steps between fingerprint and key, hardened bit included.
        public var path: [UInt32]

        public init(fingerprint: UInt32, path: [UInt32]) {
            self.fingerprint = fingerprint
            self.path = path
        }
    }

    /// The key material of a key expression (BIP380).
    public enum KeyBase: Sendable, Equatable {
        /// Hex public key: 32-byte x-only, 33-byte compressed, or 65-byte uncompressed.
        case publicKey(Data)
        /// WIF private key (32-byte secret).
        case privateKey(Data, compressed: Bool, network: HDKey.Network)
        /// BIP32 extended key (xpub/xprv/tpub/tprv).
        case extended(HDKey, network: HDKey.Network)
    }

    /// Derivation steps following an extended key (BIP380/BIP389).
    public struct Derivation: Sendable, Equatable {
        public enum Element: Sendable, Equatable {
            /// Single step, hardened bit included.
            case step(UInt32)
            /// BIP389 `<N;M;...>` multipath step, hardened bit included per element.
            case multipath([UInt32])
            /// `/*` or `/*'` wildcard; always the final element.
            case wildcard(hardened: Bool)
        }

        public var elements: [Element]

        public init(_ elements: [Element] = []) {
            self.elements = elements
        }

        /// Number of multipath choices (1 when no multipath element is present).
        public var multipathCount: Int {
            for case let .multipath(values) in elements { return values.count }
            return 1
        }

        public var isRanged: Bool {
            elements.contains { if case .wildcard = $0 { true } else { false } }
        }
    }

    /// A key expression: optional origin, key material, derivation suffix.
    public struct SingleKey: Sendable, Equatable {
        public var origin: KeyOrigin?
        public var base: KeyBase
        public var derivation: Derivation

        public init(origin: KeyOrigin?, base: KeyBase, derivation: Derivation = Derivation()) {
            self.origin = origin
            self.base = base
            self.derivation = derivation
        }
    }

    /// Top-level script expressions.
    public enum ScriptExpression: Sendable, Equatable {
        /// `tr(KEY)`: P2TR output with KEY as the internal key, BIP86-tweaked.
        case tr(SingleKey)
        /// `tr(KEY,TREE)`: P2TR output whose internal key commits to a script
        /// tree (BIP341). A separate case so every single-key caller, which
        /// matches `.tr`, keeps refusing descriptors with a tree.
        case trTree(SingleKey, ScriptTree)
        /// `rawtr(KEY)`: P2TR output with KEY used directly as the output key (no tweak).
        case rawtr(SingleKey)
    }

    /// A tapscript leaf (BIP386/BIP387); valid only inside a `tr()` tree.
    public enum LeafExpression: Sendable, Equatable {
        case pk(SingleKey)
        case multiA(threshold: Int, keys: [SingleKey])
        case sortedMultiA(threshold: Int, keys: [SingleKey])
        /// The miniscript `and_v(v:pk(KEY),older(N))` or
        /// `and_v(v:multi_a(k,KEY,…),older(N))`: these keys may spend only
        /// once the coin is N blocks old (BIP68/BIP112).
        case timelocked(TimelockedKeys, blocks: UInt32)
    }

    /// The keys a timelocked leaf requires.
    public enum TimelockedKeys: Sendable, Equatable {
        case pk(SingleKey)
        case multiA(threshold: Int, keys: [SingleKey])

        public var keys: [SingleKey] {
            switch self {
            case let .pk(key): [key]
            case let .multiA(_, keys): keys
            }
        }

        public var threshold: Int {
            switch self {
            case .pk: 1
            case let .multiA(threshold, _): threshold
            }
        }
    }

    /// BIP386 TREE expression: a leaf or `{TREE,TREE}`.
    public indirect enum ScriptTree: Sendable, Equatable {
        case leaf(LeafExpression)
        case branch(ScriptTree, ScriptTree)
    }

    /// A derived output: P2TR scriptPubKey and its bech32m address.
    public struct DerivedOutput: Sendable, Equatable {
        public let scriptPubKey: Data
        public let address: String
    }

    public let expression: ScriptExpression

    public init(expression: ScriptExpression) {
        self.expression = expression
    }

    /// Parses a descriptor string. When a `#checksum` suffix is present it is
    /// validated (BIP380); the checksum itself is optional.
    public init(_ string: String) throws {
        var body = string
        if let separator = string.lastIndex(of: "#") {
            let checksum = string.suffix(from: string.index(after: separator))
            guard checksum.count == 8 else { throw DescriptorError.invalidChecksum }
            body = String(string.prefix(upTo: separator))
            guard DescriptorChecksum.verify(body: body, checksum: String(checksum)) else {
                throw DescriptorError.invalidChecksum
            }
        }
        var parser = Parser(body)
        let expression = try parser.parseTopLevel()
        guard parser.atEnd else { throw DescriptorError.unexpectedCharacter(parser.peek()!) }
        self.expression = expression
        try validate()
    }

    /// Canonical serialization with a freshly computed BIP380 checksum.
    public func serialized() -> String {
        let body = Serializer.serialize(expression)
        return body + "#" + DescriptorChecksum.create(body)
    }

    /// The top-level key: the only key of `tr(KEY)` and `rawtr(KEY)`, the
    /// internal key of `tr(KEY,TREE)`.
    public var key: SingleKey {
        switch expression {
        case let .tr(key), let .rawtr(key), let .trTree(key, _): key
        }
    }

    /// Every key expression in the descriptor: the top-level key, then the
    /// leaf keys left to right.
    public var allKeys: [SingleKey] {
        guard case let .trTree(internalKey, tree) = expression else { return [key] }
        var keys = [internalKey]
        Self.collectKeys(tree, into: &keys)
        return keys
    }

    private static func collectKeys(_ tree: ScriptTree, into keys: inout [SingleKey]) {
        switch tree {
        case let .leaf(.pk(key)): keys.append(key)
        case let .leaf(.multiA(_, leafKeys)), let .leaf(.sortedMultiA(_, leafKeys)): keys.append(contentsOf: leafKeys)
        case let .leaf(.timelocked(condition, _)): keys.append(contentsOf: condition.keys)
        case let .branch(left, right):
            collectKeys(left, into: &keys)
            collectKeys(right, into: &keys)
        }
    }

    /// Whether any key expression contains a `/*` wildcard.
    public var isRanged: Bool { allKeys.contains { $0.derivation.isRanged } }

    /// BIP389 multipath choices shared by every key (1 when none has one).
    public var multipathCount: Int { allKeys.map(\.derivation.multipathCount).max() ?? 1 }

    /// Structural rules beyond the grammar: every multipath element in the
    /// descriptor must offer the same number of choices (BIP389).
    private func validate() throws {
        let counts = allKeys.map(\.derivation.multipathCount).filter { $0 > 1 }
        if let first = counts.first, counts.contains(where: { $0 != first }) {
            throw DescriptorError.invalidPath
        }
    }

    /// Derives the output(s) at `index` (ignored when the descriptor has no
    /// wildcard). Returns one output per BIP389 multipath choice — receive and
    /// change for the common `<0;1>/*` — in multipath order. The address
    /// prefix is the Bitcoin network's, not the key network's: regtest keys
    /// are testnet keys, but a regtest address is `bcrt1…`, never `tb1…`.
    public func derived(index: UInt32, bitcoinNetwork: BitcoinNetwork) throws -> [DerivedOutput] {
        try (0 ..< multipathCount).map { choice in
            let scriptPubKey = try resolve(expression, index: index, choice: choice)
            let program = scriptPubKey.suffix(32)
            let address = try SegwitAddress.encode(hrp: AddressDecoder.hrp(for: bitcoinNetwork), version: 1, program: program)
            return DerivedOutput(scriptPubKey: scriptPubKey, address: address)
        }
    }

    /// Source-compatible entry point for existing mainnet/testnet-key callers.
    /// Use `bitcoinNetwork:` when an address must distinguish signet and regtest.
    public func derived(index: UInt32, network: HDKey.Network = .mainnet) throws -> [DerivedOutput] {
        try derived(index: index, bitcoinNetwork: network == .mainnet ? .mainnet : .signet)
    }

    /// The `tr(KEY,TREE)` expression resolved at (`index`, multipath
    /// `choice`): the x-only internal key and the tree with every leaf key
    /// resolved, from which spenders build leaf scripts and control blocks.
    public func resolvedTaproot(index: UInt32, choice: Int = 0) throws -> (internalKey: Data, tree: Taproot.Tree) {
        guard case let .trTree(internalKey, tree) = expression else { throw DescriptorError.invalidContext }
        return (xonly(try resolve(internalKey, index: index, choice: choice)),
                try resolve(tree, index: index, choice: choice))
    }

    /// A key expression's 33-byte compressed public key at (`index`,
    /// multipath `choice`), for example one signer of a `multi_a` leaf.
    public func publicKey(of key: SingleKey, index: UInt32, choice: Int = 0) throws -> Data {
        try resolve(key, index: index, choice: choice)
    }

    // MARK: - Derivation

    /// Resolves a top-level expression to a scriptPubKey at (index, multipath choice).
    private func resolve(_ expression: ScriptExpression, index: UInt32, choice: Int) throws -> Data {
        switch expression {
        case let .tr(internalKey):
            let internalKeyBytes = xonly(try resolve(internalKey, index: index, choice: choice))
            return try Taproot.scriptPubKey(internalKey: internalKeyBytes, merkleRoot: nil)
        case let .trTree(internalKey, tree):
            let internalKeyBytes = xonly(try resolve(internalKey, index: index, choice: choice))
            let merkleRoot = Taproot.merkleRoot(of: try resolve(tree, index: index, choice: choice))
            return try Taproot.scriptPubKey(internalKey: internalKeyBytes, merkleRoot: merkleRoot)
        case let .rawtr(key):
            let outputKey = xonly(try resolve(key, index: index, choice: choice))
            return Data([0x51, 0x20]) + outputKey
        }
    }

    /// Resolves a script tree to tapscript leaves at (index, multipath choice).
    private func resolve(_ tree: ScriptTree, index: UInt32, choice: Int) throws -> Taproot.Tree {
        switch tree {
        case let .leaf(leaf):
            return .leaf(script: try script(of: leaf, index: index, choice: choice))
        case let .branch(left, right):
            return try .branch(resolve(left, index: index, choice: choice),
                               resolve(right, index: index, choice: choice))
        }
    }

    private func script(of leaf: LeafExpression, index: UInt32, choice: Int) throws -> Script {
        let keys: (([SingleKey]) throws -> [Data]) = { keys in
            try keys.map { self.xonly(try self.resolve($0, index: index, choice: choice)) }
        }
        switch leaf {
        case let .pk(key):
            let xonlyKey = xonly(try resolve(key, index: index, choice: choice))
            return Script.build {
                $0.appendPush(xonlyKey)
                $0.appendOpcode(Script.Op.checkSig)
            }
        case let .multiA(threshold, leafKeys):
            return try Multisig.script(threshold: threshold, xonlyKeys: keys(leafKeys), sorted: false)
        case let .sortedMultiA(threshold, leafKeys):
            return try Multisig.script(threshold: threshold, xonlyKeys: keys(leafKeys), sorted: true)
        case let .timelocked(.pk(key), blocks):
            return try Multisig.timelockedScript(xonlyKey: xonly(try resolve(key, index: index, choice: choice)),
                                                 blocks: blocks)
        case let .timelocked(.multiA(threshold, leafKeys), blocks):
            return try Multisig.timelockedScript(threshold: threshold, xonlyKeys: keys(leafKeys), blocks: blocks)
        }
    }

    /// Resolves a key expression to a 33-byte compressed public key.
    private func resolve(_ key: SingleKey, index: UInt32, choice: Int) throws -> Data {
        try compressed(derive(key, index: index, choice: choice))
    }

    /// Base key material of a single key plus its own derivation suffix.
    private func derive(_ key: SingleKey, index: UInt32, choice: Int) throws -> KeyBase {
        guard case let .extended(extended, network) = key.base else {
            guard key.derivation.elements.isEmpty else { throw DescriptorError.invalidPath }
            return key.base
        }
        let derived = try apply(key.derivation, to: extended, index: index, choice: choice)
        return .extended(derived, network: network)
    }

    private func apply(_ derivation: Derivation, to key: HDKey, index: UInt32, choice: Int) throws -> HDKey {
        var key = key
        for element in derivation.elements {
            do {
                switch element {
                case let .step(step):
                    key = try key.child(at: step)
                case let .multipath(values):
                    key = try key.child(at: values[choice])
                case let .wildcard(hardened):
                    guard index < HDKey.hardenedOffset else { throw DescriptorError.invalidPath }
                    key = try key.child(at: index + (hardened ? HDKey.hardenedOffset : 0))
                }
            } catch let error as DescriptorError {
                throw error
            } catch BIP32Error.depthExhausted {
                throw DescriptorError.keyDepthExhausted
            } catch {
                throw DescriptorError.derivationFailed
            }
        }
        return key
    }

    /// 33-byte compressed form of resolved key material. X-only keys are lifted
    /// to the even-Y point; uncompressed keys are rejected in Taproot context.
    private func compressed(_ base: KeyBase) throws -> Data {
        switch base {
        case let .publicKey(data):
            switch data.count {
            case 33: return data
            case 32: return Data([0x02]) + data
            default: throw DescriptorError.invalidKey // uncompressed
            }
        case let .privateKey(secret, compressed, _):
            guard compressed else { throw DescriptorError.invalidKey }
            guard let key = try? P256K.Signing.PrivateKey(dataRepresentation: secret) else {
                throw DescriptorError.invalidKey
            }
            return key.publicKey.dataRepresentation
        case let .extended(key, _):
            return key.publicKey
        }
    }

    private func xonly(_ compressedKey: Data) -> Data {
        compressedKey.dropFirst()
    }
}

// MARK: - Parser

/// Recursive-descent parser for the descriptor subset. Character-level (descriptors
/// are ASCII per the BIP380 input charset).
struct Parser {
    private let string: String
    private(set) var index: String.Index

    init(_ string: String) {
        self.string = string
        self.index = string.startIndex
    }

    var atEnd: Bool { index == string.endIndex }

    func peek() -> Character? { atEnd ? nil : string[index] }

    @discardableResult
    mutating func consume(_ character: Character) -> Bool {
        guard peek() == character else { return false }
        index = string.index(after: index)
        return true
    }

    mutating func consume(_ token: String) -> Bool {
        guard string[index...].hasPrefix(token) else { return false }
        index = string.index(index, offsetBy: token.count)
        return true
    }

    mutating func expect(_ character: Character) throws {
        guard consume(character) else {
            throw atEnd ? DescriptorError.unexpectedEnd : DescriptorError.unexpectedCharacter(string[index])
        }
    }

    mutating func takeWhile(_ predicate: (Character) -> Bool) -> String {
        let start = index
        while !atEnd, predicate(string[index]) { index = string.index(after: index) }
        return String(string[start ..< index])
    }

    mutating func take(_ count: Int) -> String? {
        guard string.distance(from: index, to: string.endIndex) >= count else { return nil }
        let end = string.index(index, offsetBy: count)
        defer { index = end }
        return String(string[index ..< end])
    }

    // MARK: Grammar

    /// `tr(KEY)`, `tr(KEY,TREE)` or `rawtr(KEY)`. A `musig()` expression or
    /// any other script is a parse error, not a descriptor this wallet holds.
    mutating func parseTopLevel() throws -> Descriptor.ScriptExpression {
        let name = takeWhile { $0.isLetter || $0 == "_" }
        try expect("(")
        switch name {
        case "tr":
            let key = try parseKeyExpression()
            if consume(",") {
                let tree = try parseTree()
                try expect(")")
                return .trTree(key, tree)
            }
            try expect(")")
            return .tr(key)
        case "rawtr":
            let key = try parseKeyExpression()
            try expect(")")
            return .rawtr(key)
        default:
            throw DescriptorError.unknownExpression(name)
        }
    }

    /// The most steps a key origin may name: the largest `HDKey.depth`, since
    /// a key at depth 255 has no child a byte can count.
    static let maximumOriginSteps = Int(UInt8.max)

    /// BIP341 allows at most 128 levels in a taproot tree: a control block
    /// carries up to 128 sibling hashes, so anything deeper can never be spent.
    ///
    /// The bound does more than reject invalid trees. This parser is
    /// recursive descent, and without a depth limit a hostile descriptor
    /// exhausts the stack and terminates the process (SEC-010). Stack
    /// exhaustion is not a Swift error, so no handler downstream can catch
    /// it; a descriptor from a restored account record would take the app
    /// down at launch. This is the only place it can be stopped.
    static let maximumTreeDepth = 128

    /// A BIP386 tree: `{TREE,TREE}` or one `pk`, `multi_a` or
    /// `sortedmulti_a` leaf.
    mutating func parseTree(depth: Int = 0) throws -> Descriptor.ScriptTree {
        guard depth <= Self.maximumTreeDepth else { throw DescriptorError.treeTooDeep }
        if consume("{") {
            let left = try parseTree(depth: depth + 1)
            try expect(",")
            let right = try parseTree(depth: depth + 1)
            try expect("}")
            return .branch(left, right)
        }
        let name = takeWhile { $0.isLetter || $0 == "_" }
        try expect("(")
        switch name {
        case "pk":
            let key = try parseKeyExpression()
            try expect(")")
            return .leaf(.pk(key))
        case "multi_a", "sortedmulti_a":
            let (threshold, keys) = try parseMultiArguments()
            return .leaf(name == "multi_a"
                ? .multiA(threshold: threshold, keys: keys)
                : .sortedMultiA(threshold: threshold, keys: keys))
        case "and_v":
            return .leaf(try parseTimelockedLeaf())
        default:
            throw DescriptorError.unknownExpression(name)
        }
    }

    /// `k,KEY,…)` after `multi_a(` or `sortedmulti_a(`.
    mutating func parseMultiArguments() throws -> (threshold: Int, keys: [Descriptor.SingleKey]) {
        let thresholdText = takeWhile(\.isNumber)
        guard !thresholdText.isEmpty, let threshold = Int(thresholdText) else {
            throw DescriptorError.invalidThreshold
        }
        var keys: [Descriptor.SingleKey] = []
        while consume(",") {
            guard keys.count < Multisig.maxKeys else { throw DescriptorError.invalidThreshold }
            keys.append(try parseKeyExpression())
        }
        try expect(")")
        guard threshold >= 1, threshold <= keys.count else { throw DescriptorError.invalidThreshold }
        return (threshold, keys)
    }

    /// `v:pk(KEY),older(N))` or `v:multi_a(k,KEY,…),older(N))` after
    /// `and_v(`: the only miniscript this wallet reads. `sortedmulti_a` is a
    /// descriptor form, not a miniscript fragment, so it cannot appear here.
    mutating func parseTimelockedLeaf() throws -> Descriptor.LeafExpression {
        guard consume("v:") else { throw DescriptorError.unknownExpression("and_v") }
        let inner = takeWhile { $0.isLetter || $0 == "_" }
        try expect("(")
        let keys: Descriptor.TimelockedKeys
        switch inner {
        case "pk":
            keys = .pk(try parseKeyExpression())
            try expect(")")
        case "multi_a":
            let (threshold, multiKeys) = try parseMultiArguments()
            keys = .multiA(threshold: threshold, keys: multiKeys)
        default:
            throw DescriptorError.unknownExpression("and_v(v:\(inner)")
        }
        try expect(",")
        guard consume("older(") else { throw DescriptorError.unknownExpression("and_v") }
        let digits = takeWhile(\.isNumber)
        guard !digits.isEmpty, digits.count <= 10, let blocks = UInt32(digits), blocks >= 1, blocks < 0x8000_0000 else {
            throw DescriptorError.invalidTimelock
        }
        try expect(")")
        try expect(")")
        return .timelocked(keys, blocks: blocks)
    }

    mutating func parseKeyExpression() throws -> Descriptor.SingleKey {
        let origin = try parseOrigin()
        let base = try parseKeyBase()
        let derivation = try parseDerivation()
        // Derivation steps are only defined for extended keys (BIP380).
        if case .extended = base {} else if !derivation.elements.isEmpty {
            throw DescriptorError.invalidPath
        }
        return Descriptor.SingleKey(origin: origin, base: base, derivation: derivation)
    }

    /// `[fingerprint/path]` — exactly 8 hex chars, then `/NUM` or `/NUMh` steps.
    mutating func parseOrigin() throws -> Descriptor.KeyOrigin? {
        guard consume("[") else { return nil }
        guard let fingerprintText = take(8), UInt32(fingerprintText, radix: 16) != nil else {
            throw DescriptorError.invalidOrigin
        }
        let fingerprint = UInt32(fingerprintText, radix: 16)!
        var path: [UInt32] = []
        while consume("/") {
            guard peek() != "*" else { throw DescriptorError.invalidOrigin }
            // Bounded at the depth a key can have, because the walk that would
            // otherwise refuse this is `depth + 1` on a `UInt8`, which traps.
            guard path.count < Self.maximumOriginSteps else { throw DescriptorError.originTooDeep }
            path.append(try parsePathStep())
        }
        try expect("]")
        return Descriptor.KeyOrigin(fingerprint: fingerprint, path: path)
    }

    /// A single derivation step: decimal index (< 2^31) with optional `'`/`h`.
    mutating func parsePathStep() throws -> UInt32 {
        let digits = takeWhile(\.isNumber)
        guard !digits.isEmpty, let value = UInt32(digits), value < HDKey.hardenedOffset else {
            throw DescriptorError.invalidPath
        }
        let hardened = consume("'") || consume("h")
        return value + (hardened ? HDKey.hardenedOffset : 0)
    }

    mutating func parseDerivation() throws -> Descriptor.Derivation {
        var elements: [Descriptor.Derivation.Element] = []
        var sawMultipath = false
        while consume("/") {
            if consume("*") {
                let hardened = consume("'") || consume("h")
                elements.append(.wildcard(hardened: hardened))
                guard !consume("/") else { throw DescriptorError.invalidPath } // wildcard is final
            } else if consume("<") {
                // BIP389 multipath: <NUM;NUM;...> with optional hardened markers.
                // One per key expression: `multipathCount` and `derived()` take
                // the choice count from the first element, so a second, narrower
                // one would be indexed past its end on derivation.
                guard !sawMultipath else { throw DescriptorError.invalidPath }
                sawMultipath = true
                var values = [try parsePathStep()]
                while consume(";") { values.append(try parsePathStep()) }
                try expect(">")
                guard values.count >= 2 else { throw DescriptorError.invalidPath }
                elements.append(.multipath(values))
            } else {
                elements.append(.step(try parsePathStep()))
            }
        }
        return Descriptor.Derivation(elements)
    }

    /// Raw hex pubkey (x-only/compressed/uncompressed), WIF private key, or
    /// BIP32 extended key.
    mutating func parseKeyBase() throws -> Descriptor.KeyBase {
        let token = takeWhile(\.isHexLetterOrDigit)
        guard !token.isEmpty else { throw DescriptorError.invalidKey }
        if let data = Data(hex: token), [32, 33, 65].contains(data.count) {
            return try Self.rawPublicKey(data)
        }
        if token.hasPrefix("xpub") || token.hasPrefix("xprv") || token.hasPrefix("tpub") || token.hasPrefix("tprv") {
            guard let key = try? HDKey.deserialize(token) else { throw DescriptorError.invalidKey }
            let network: HDKey.Network = token.hasPrefix("t") ? .testnet : .mainnet
            return .extended(key, network: network)
        }
        return try Self.wifPrivateKey(token)
    }

    /// A bare hex key of a known length, with its leading byte checked: x-only
    /// (32), compressed (33, 0x02/0x03), or uncompressed (65, 0x04).
    private static func rawPublicKey(_ data: Data) throws -> Descriptor.KeyBase {
        switch data.count {
        case 33: guard data.first == 0x02 || data.first == 0x03 else { throw DescriptorError.invalidKey }
        case 65: guard data.first == 0x04 else { throw DescriptorError.invalidKey }
        default: break
        }
        return .publicKey(data)
    }

    /// WIF: version byte + 32-byte secret + optional 0x01 compression marker.
    private static func wifPrivateKey(_ token: String) throws -> Descriptor.KeyBase {
        guard let payload = try? Base58Check.decode(token), payload.count == 33 || payload.count == 34,
              payload.first == 0x80 || payload.first == 0xEF
        else { throw DescriptorError.invalidKey }
        let wifNetwork: HDKey.Network = payload.first == 0x80 ? .mainnet : .testnet
        let secret = payload.dropFirst().prefix(32)
        if payload.count == 34 {
            guard payload.last == 0x01 else { throw DescriptorError.invalidKey }
            return .privateKey(Data(secret), compressed: true, network: wifNetwork)
        }
        return .privateKey(Data(secret), compressed: false, network: wifNetwork)
    }
}

private extension Character {
    /// Base58/hex key characters (alphanumerics).
    var isHexLetterOrDigit: Bool { isLetter || isNumber }
}

// MARK: - Serializer

enum Serializer {
    static func serialize(_ expression: Descriptor.ScriptExpression) -> String {
        switch expression {
        case let .tr(key):
            "tr(\(serialize(key)))"
        case let .trTree(key, tree):
            "tr(\(serialize(key)),\(serialize(tree)))"
        case let .rawtr(key):
            "rawtr(\(serialize(key)))"
        }
    }

    static func serialize(_ tree: Descriptor.ScriptTree) -> String {
        switch tree {
        case let .leaf(.pk(key)):
            "pk(\(serialize(key)))"
        case let .leaf(.multiA(threshold, keys)):
            "multi_a(\(threshold),\(keys.map(serialize).joined(separator: ",")))"
        case let .leaf(.sortedMultiA(threshold, keys)):
            "sortedmulti_a(\(threshold),\(keys.map(serialize).joined(separator: ",")))"
        case let .leaf(.timelocked(.pk(key), blocks)):
            "and_v(v:pk(\(serialize(key))),older(\(blocks)))"
        case let .leaf(.timelocked(.multiA(threshold, keys), blocks)):
            "and_v(v:multi_a(\(threshold),\(keys.map(serialize).joined(separator: ","))),older(\(blocks)))"
        case let .branch(left, right):
            "{\(serialize(left)),\(serialize(right))}"
        }
    }

    static func serialize(_ key: Descriptor.SingleKey) -> String {
        var result = ""
        if let origin = key.origin {
            result += "[" + String(format: "%08x", origin.fingerprint)
            result += origin.path.map { "/\($0 & ~HDKey.hardenedOffset)\($0 >= HDKey.hardenedOffset ? "'" : "")" }.joined()
            result += "]"
        }
        switch key.base {
        case let .publicKey(data):
            result += data.map { String(format: "%02x", $0) }.joined()
        case let .privateKey(secret, compressed, network):
            var payload = Data([network == .mainnet ? 0x80 : 0xEF])
            payload.append(secret)
            if compressed { payload.append(0x01) }
            result += Base58Check.encode(payload)
        case let .extended(key, network):
            result += key.serialized(network: network)
        }
        return result + serialize(key.derivation)
    }

    static func serialize(_ derivation: Descriptor.Derivation) -> String {
        derivation.elements.map { element in
            switch element {
            case let .step(step):
                "/\(step & ~HDKey.hardenedOffset)\(step >= HDKey.hardenedOffset ? "'" : "")"
            case let .multipath(values):
                "/<" + values.map { "\($0 & ~HDKey.hardenedOffset)\($0 >= HDKey.hardenedOffset ? "'" : "")" }
                    .joined(separator: ";") + ">"
            case let .wildcard(hardened):
                hardened ? "/*'" : "/*"
            }
        }.joined()
    }
}

// MARK: - BIP380 checksum

enum DescriptorChecksum {
    static let inputCharset = Array("0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ".utf8)
    static let checksumCharset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l".utf8)
    static let generator: [UInt64] = [0xF5DE_E519_89, 0xA9FD_CA33_12, 0x1BAB_10E3_2D, 0x3706_B167_7A, 0x644D_626F_FD]

    static func polymod(_ symbols: [UInt64]) -> UInt64 {
        var chk: UInt64 = 1
        for value in symbols {
            let top = chk >> 35
            chk = ((chk & 0x7_FFFF_FFFF) << 5) ^ value
            for i in 0 ..< 5 where (top >> i) & 1 == 1 {
                chk ^= generator[i]
            }
        }
        return chk
    }

    /// BIP380 descsum_expand: character -> (group, position) symbols; every third
    /// position symbol is followed by a combined group symbol.
    static func expand(_ string: String) -> [UInt64]? {
        var groups: [UInt64] = []
        var symbols: [UInt64] = []
        for byte in string.utf8 {
            guard let position = inputCharset.firstIndex(of: byte) else { return nil }
            symbols.append(UInt64(position & 31))
            groups.append(UInt64(position >> 5))
            if groups.count == 3 {
                symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
                groups = []
            }
        }
        if groups.count == 1 {
            symbols.append(groups[0])
        } else if groups.count == 2 {
            symbols.append(groups[0] * 3 + groups[1])
        }
        return symbols
    }

    static func verify(body: String, checksum: String) -> Bool {
        guard let symbols = expand(body),
              checksum.utf8.allSatisfy({ checksumCharset.contains($0) })
        else { return false }
        let checksumSymbols = checksum.utf8.map { UInt64(checksumCharset.firstIndex(of: $0)!) }
        return polymod(symbols + checksumSymbols) == 1
    }

    static func create(_ body: String) -> String {
        guard let symbols = expand(body) else { return "" }
        let checksum = polymod(symbols + [UInt64](repeating: 0, count: 8)) ^ 1
        return String((0 ..< 8).map { Character(Unicode.Scalar(checksumCharset[Int((checksum >> UInt64(5 * (7 - $0))) & 31)])) })
    }
}
