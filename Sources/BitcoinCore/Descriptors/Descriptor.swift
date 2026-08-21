import Foundation
import P256K

public enum DescriptorError: Error, Equatable {
    case invalidChecksum
    case invalidCharacter
    case unexpectedEnd
    case unexpectedCharacter(Character)
    case unknownExpression(String)
    case invalidOrigin
    case invalidKey
    case invalidPath
    case invalidThreshold
    case invalidContext
    case invalidMuSig
    case derivationFailed
    case treeTooDeep
}

extension HDKey.Network: Equatable {
    /// BIP173 human-readable part for this network.
    public var hrp: String {
        switch self {
        case .mainnet: "bc"
        case .testnet: "tb"
        }
    }
}

/// Output descriptor parse/serialize/derive engine (BIP380 general operation and
/// checksum, BIP386 `tr()`, BIP387 `multi_a`/`sortedmulti_a` leaves, BIP389
/// multipath, BIP390 `musig()` key expressions). Taproot-only: the supported
/// top-level expressions are `tr(KEY)`, `tr(KEY, TREE)` and `rawtr(KEY)`.
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

    /// A non-aggregated key expression: optional origin, key material, derivation suffix.
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

    /// BIP380/BIP390 key expression.
    public enum KeyExpression: Sendable, Equatable {
        case single(SingleKey)
        /// BIP390 `musig(KEY, KEY, ...)` with optional unhardened BIP328 derivation suffix.
        case musig([SingleKey], Derivation)
    }

    /// Script expressions. `tr`/`rawtr` are top-level only; `pk`/`multiA`/
    /// `sortedMultiA` are only valid as `tr` leaves (BIP386/BIP387).
    public enum ScriptExpression: Sendable, Equatable {
        case tr(KeyExpression, ScriptTree?)
        /// `rawtr(KEY)`: P2TR output with KEY used directly as the output key (no tweak).
        case rawtr(KeyExpression)
        case pk(KeyExpression)
        case multiA(threshold: Int, keys: [KeyExpression])
        case sortedMultiA(threshold: Int, keys: [KeyExpression])
    }

    /// BIP386 TREE expression: a leaf script or `{TREE, TREE}`.
    public indirect enum ScriptTree: Sendable, Equatable {
        case leaf(ScriptExpression)
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
        let body = Serializer.serialize(expression, topLevel: true)
        return body + "#" + DescriptorChecksum.create(body)
    }

    /// Whether any key expression contains a `/*` wildcard.
    public var isRanged: Bool {
        allKeys().contains { key in
            switch key {
            case let .single(single): single.derivation.isRanged
            case let .musig(participants, derivation):
                derivation.isRanged || participants.contains { $0.derivation.isRanged }
            }
        }
    }

    /// Derives the output(s) at `index` (ignored when the descriptor has no
    /// wildcard). Returns one output per BIP389 multipath choice — receive and
    /// change for the common `<0;1>/*` — in multipath order.
    public func derived(index: UInt32, network: HDKey.Network = .mainnet) throws -> [DerivedOutput] {
        try (0 ..< multipathCount()).map { choice in
            let scriptPubKey = try resolve(expression, index: index, choice: choice, topLevel: true)
            let program = scriptPubKey.suffix(32)
            let address = try SegwitAddress.encode(hrp: network.hrp, version: 1, program: program)
            return DerivedOutput(scriptPubKey: scriptPubKey, address: address)
        }
    }

    /// The tr() expression resolved at (`index`, multipath `choice`): the
    /// x-only internal key and the script tree with all leaf keys resolved.
    /// Vaults use this to build leaf scripts and control blocks for spending.
    public func resolvedTaproot(index: UInt32, choice: Int = 0) throws -> (internalKey: Data, tree: Taproot.Tree?) {
        guard case let .tr(key, tree) = expression else { throw DescriptorError.invalidContext }
        let internalKey = try xonly(resolve(key, index: index, choice: choice))
        return (internalKey, try tree.map { try resolve($0, index: index, choice: choice) })
    }

    /// Resolves a key expression to its 33-byte compressed public key at
    /// (`index`, multipath `choice`) — e.g. the cosigner keys of a vault.
    public func publicKey(of key: KeyExpression, index: UInt32, choice: Int = 0) throws -> Data {
        try resolve(key, index: index, choice: choice)
    }

    // MARK: - Validation

    /// Structural rules beyond the grammar (BIP387/BIP389/BIP390).
    private func validate() throws {
        for key in allKeys() {
            guard case let .musig(participants, derivation) = key else { continue }
            // musig() derivation steps must be unhardened (BIP390).
            for element in derivation.elements {
                switch element {
                case let .step(step) where step >= HDKey.hardenedOffset: throw DescriptorError.invalidMuSig
                case let .multipath(values) where values.contains(where: { $0 >= HDKey.hardenedOffset }):
                    throw DescriptorError.invalidMuSig
                case .wildcard(hardened: true): throw DescriptorError.invalidMuSig
                default: break
                }
            }
            if !derivation.elements.isEmpty {
                // With a musig() suffix, all participants must be xpubs without
                // their own wildcard or multipath (BIP390).
                for participant in participants {
                    guard case .extended = participant.base,
                          !participant.derivation.isRanged,
                          participant.derivation.multipathCount == 1
                    else { throw DescriptorError.invalidMuSig }
                }
            }
        }
        // All multipath elements in a descriptor must agree on the choice count (BIP389).
        let counts = allKeys().flatMap { key -> [Int] in
            switch key {
            case let .single(single): [single.derivation.multipathCount]
            case let .musig(participants, derivation):
                participants.map { $0.derivation.multipathCount } + [derivation.multipathCount]
            }
        }.filter { $0 > 1 }
        if let first = counts.first, counts.contains(where: { $0 != first }) {
            throw DescriptorError.invalidPath
        }
    }

    private func multipathCount() -> Int {
        allKeys().flatMap { key -> [Int] in
            switch key {
            case let .single(single): [single.derivation.multipathCount]
            case let .musig(participants, derivation):
                participants.map { $0.derivation.multipathCount } + [derivation.multipathCount]
            }
        }.max() ?? 1
    }

    private func allKeys() -> [KeyExpression] {
        switch expression {
        case let .tr(internalKey, tree):
            var keys = [internalKey]
            if let tree { collectKeys(tree, into: &keys) }
            return keys
        case let .rawtr(key): return [key]
        case let .pk(key): return [key]
        case let .multiA(_, keys), let .sortedMultiA(_, keys): return keys
        }
    }

    private func collectKeys(_ tree: ScriptTree, into keys: inout [KeyExpression]) {
        switch tree {
        case let .leaf(.pk(key)): keys.append(key)
        case let .leaf(.multiA(_, ks)), let .leaf(.sortedMultiA(_, ks)): keys.append(contentsOf: ks)
        case let .branch(left, right):
            collectKeys(left, into: &keys)
            collectKeys(right, into: &keys)
        case .leaf: break
        }
    }

    // MARK: - Derivation

    /// Resolves a top-level expression to a scriptPubKey at (index, multipath choice).
    private func resolve(_ expression: ScriptExpression, index: UInt32, choice: Int, topLevel: Bool) throws -> Data {
        switch expression {
        case let .tr(internalKey, tree):
            let internalKeyBytes = try xonly(resolve(internalKey, index: index, choice: choice))
            var merkleRoot: Data?
            if let tree { merkleRoot = Taproot.merkleRoot(of: try resolve(tree, index: index, choice: choice)) }
            return try Taproot.scriptPubKey(internalKey: internalKeyBytes, merkleRoot: merkleRoot)
        case let .rawtr(key):
            let outputKey = try xonly(resolve(key, index: index, choice: choice))
            return Data([0x51, 0x20]) + outputKey
        case .pk, .multiA, .sortedMultiA:
            throw DescriptorError.invalidContext
        }
    }

    private func resolve(_ tree: ScriptTree, index: UInt32, choice: Int) throws -> Taproot.Tree {
        switch tree {
        case let .leaf(expression):
            let script: Script
            switch expression {
            case let .pk(key):
                script = try Script.build {
                    $0.appendPush(try xonly(resolve(key, index: index, choice: choice)))
                    $0.appendOpcode(Script.Op.checkSig)
                }
            case let .multiA(threshold, keys):
                script = try Multisig.script(threshold: threshold,
                                             xonlyKeys: keys.map { try xonly(resolve($0, index: index, choice: choice)) },
                                             sorted: false)
            case let .sortedMultiA(threshold, keys):
                script = try Multisig.script(threshold: threshold,
                                             xonlyKeys: keys.map { try xonly(resolve($0, index: index, choice: choice)) },
                                             sorted: true)
            case .tr, .rawtr:
                throw DescriptorError.invalidContext
            }
            return .leaf(script: script)
        case let .branch(left, right):
            return try .branch(resolve(left, index: index, choice: choice),
                               resolve(right, index: index, choice: choice))
        }
    }

    /// Resolves a key expression to a 33-byte compressed public key.
    private func resolve(_ key: KeyExpression, index: UInt32, choice: Int) throws -> Data {
        switch key {
        case let .single(single):
            let key = try derive(single, index: index, choice: choice)
            return try compressed(key)
        case let .musig(participants, derivation):
            let keys = try participants.map { try compressed(derive($0, index: index, choice: choice)) }
            let aggregate = try MuSig.aggregate(MuSig.keySort(keys))
            guard !derivation.elements.isEmpty else { return aggregate }
            // BIP328: unhardened BIP32 derivation from the synthetic aggregate xpub.
            let synthetic = try MuSig.syntheticExtendedKey(aggregatePublicKey: aggregate)
            return try apply(derivation, to: synthetic, index: index, choice: choice).publicKey
        }
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

    mutating func parseTopLevel() throws -> Descriptor.ScriptExpression {
        let name = takeWhile { $0.isLetter || $0 == "_" }
        try expect("(")
        switch name {
        case "tr":
            let key = try parseKeyExpression(allowMusig: true)
            var tree: Descriptor.ScriptTree?
            if consume(",") { tree = try parseTree() }
            try expect(")")
            return .tr(key, tree)
        case "rawtr":
            let key = try parseKeyExpression(allowMusig: true)
            try expect(")")
            return .rawtr(key)
        default:
            throw DescriptorError.unknownExpression(name)
        }
    }

    /// BIP341 allows at most 128 levels in a taproot tree: a control block
    /// carries up to 128 sibling hashes, so anything deeper can never produce
    /// a spendable output.
    ///
    /// The bound does more than reject invalid trees. This parser is
    /// recursive descent, and without a depth limit a hostile descriptor
    /// exhausts the stack and terminates the process — around a thousand
    /// levels was enough. Stack exhaustion is not a Swift error, so no
    /// fail-closed handler downstream can catch it; a descriptor arriving
    /// from a restored vault record would take the app down at launch,
    /// before any damaged-storage handling runs. This is the only place it
    /// can be stopped.
    static let maximumTreeDepth = 128

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
            let key = try parseKeyExpression(allowMusig: true)
            try expect(")")
            return .leaf(.pk(key))
        case "multi_a", "sortedmulti_a":
            let thresholdText = takeWhile(\.isNumber)
            guard let threshold = Int(thresholdText), !thresholdText.isEmpty else {
                throw DescriptorError.invalidThreshold
            }
            var keys: [Descriptor.KeyExpression] = []
            while consume(",") { keys.append(try parseKeyExpression(allowMusig: true)) }
            try expect(")")
            guard threshold >= 1, threshold <= keys.count, keys.count <= Multisig.maxKeys else {
                throw DescriptorError.invalidThreshold
            }
            return .leaf(name == "multi_a"
                ? .multiA(threshold: threshold, keys: keys)
                : .sortedMultiA(threshold: threshold, keys: keys))
        default:
            throw DescriptorError.unknownExpression(name)
        }
    }

    mutating func parseKeyExpression(allowMusig: Bool) throws -> Descriptor.KeyExpression {
        let origin = try parseOrigin()
        if allowMusig, consume("musig(") {
            // BIP390 musig(KEY, KEY, ...); nesting musig is not allowed.
            var participants: [Descriptor.SingleKey] = []
            repeat {
                guard case let .single(single) = try parseKeyExpression(allowMusig: false) else {
                    throw DescriptorError.invalidMuSig
                }
                participants.append(single)
            } while consume(",")
            try expect(")")
            guard !participants.isEmpty else { throw DescriptorError.invalidMuSig }
            if origin != nil { throw DescriptorError.invalidMuSig } // origin belongs on participants
            return .musig(participants, try parseDerivation())
        }
        let base = try parseKeyBase()
        let derivation = try parseDerivation()
        // Derivation steps are only defined for extended keys (BIP380).
        if case .extended = base {} else if !derivation.elements.isEmpty {
            throw DescriptorError.invalidPath
        }
        return .single(Descriptor.SingleKey(origin: origin, base: base, derivation: derivation))
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
        while consume("/") {
            if consume("*") {
                let hardened = consume("'") || consume("h")
                elements.append(.wildcard(hardened: hardened))
                guard !consume("/") else { throw DescriptorError.invalidPath } // wildcard is final
            } else if consume("<") {
                // BIP389 multipath: <NUM;NUM;...> with optional hardened markers.
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
        if let data = hexData(token), [32, 33, 65].contains(data.count) {
            switch data.count {
            case 33: guard data.first == 0x02 || data.first == 0x03 else { throw DescriptorError.invalidKey }
            case 65: guard data.first == 0x04 else { throw DescriptorError.invalidKey }
            default: break
            }
            return .publicKey(data)
        }
        let network: HDKey.Network
        if token.hasPrefix("xpub") || token.hasPrefix("xprv") {
            network = .mainnet
        } else if token.hasPrefix("tpub") || token.hasPrefix("tprv") {
            network = .testnet
        } else {
            network = .mainnet // WIF prefix decides below
        }
        if token.hasPrefix("xpub") || token.hasPrefix("xprv") || token.hasPrefix("tpub") || token.hasPrefix("tprv") {
            guard let key = try? HDKey.deserialize(token) else { throw DescriptorError.invalidKey }
            return .extended(key, network: network)
        }
        // WIF: version byte + 32-byte secret + optional 0x01 compression marker.
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

    private func hexData(_ token: String) -> Data? {
        guard token.count % 2 == 0, token.allSatisfy(\.isHexDigit) else { return nil }
        var data = Data()
        data.reserveCapacity(token.count / 2)
        var index = token.startIndex
        while index < token.endIndex {
            let next = token.index(index, offsetBy: 2)
            guard let byte = UInt8(token[index ..< next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        return data
    }
}

private extension Character {
    /// Base58/hex key characters (alphanumerics).
    var isHexLetterOrDigit: Bool { isLetter || isNumber }
}

// MARK: - Serializer

enum Serializer {
    static func serialize(_ expression: Descriptor.ScriptExpression, topLevel: Bool) -> String {
        switch expression {
        case let .tr(key, tree):
            if let tree { return "tr(\(serialize(key)),\(serialize(tree)))" }
            return "tr(\(serialize(key)))"
        case let .rawtr(key):
            return "rawtr(\(serialize(key)))"
        case let .pk(key):
            return "pk(\(serialize(key)))"
        case let .multiA(threshold, keys):
            return "multi_a(\(threshold),\(keys.map(serialize).joined(separator: ",")))"
        case let .sortedMultiA(threshold, keys):
            return "sortedmulti_a(\(threshold),\(keys.map(serialize).joined(separator: ",")))"
        }
    }

    static func serialize(_ tree: Descriptor.ScriptTree) -> String {
        switch tree {
        case let .leaf(expression): serialize(expression, topLevel: false)
        case let .branch(left, right): "{\(serialize(left)),\(serialize(right))}"
        }
    }

    static func serialize(_ key: Descriptor.KeyExpression) -> String {
        switch key {
        case let .single(single): serialize(single)
        case let .musig(participants, derivation):
            "musig(\(participants.map(serialize).joined(separator: ",")))" + serialize(derivation)
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
