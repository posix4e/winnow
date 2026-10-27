import CryptoKit
import Foundation
import WalletCore

/// A software stand-in for Ledger's Bitcoin app, for tests. It plays the
/// device side of the app's interactive protocol, written from the app's
/// documentation separately from the phone's client: it asks for every
/// preimage and Merkle proof it needs, checks each against the commitment,
/// and signs Taproot script-path inputs for its own key with a test seed.
///
/// It shows the phone speaks the protocol consistently. It does not show a
/// real device agrees: Ledger's published vectors and a real Nano X do that.
///
/// Each interrupted command is replayed from the start with the answers
/// received so far, so the device logic stays one synchronous function.
public actor LedgerSimulator: LedgerTransport {
    public enum Decision: Sendable {
        case approve
        case reject
    }

    public let master: HDKey
    public private(set) var decision: Decision = .approve
    /// Addresses shown on the "screen" after a request with display set.
    public private(set) var displayedAddresses: [String] = []
    /// Policies the user approved, by name.
    public private(set) var registeredNames: [String] = []

    private let registrationKey: SymmetricKey
    private var command: Data?
    private var answers: [Data] = []

    public init(master: HDKey) {
        self.master = master
        registrationKey = SymmetricKey(data: SHA256.hash(data: Data("winnow-ledger-simulator".utf8) + master.publicKey))
    }

    public func setDecision(_ decision: Decision) {
        self.decision = decision
    }

    public func exchange(_ apdu: Data) async throws -> Data {
        let bytes = Array(apdu)
        guard bytes.count >= 5, bytes.count == 5 + Int(bytes[4]) else { return Self.status(0x6A87) }
        if bytes[0] == 0xF8, bytes[1] == 0x01 {
            guard command != nil else { return Self.status(0x6D00) }
            answers.append(Data(bytes[5...]))
        } else {
            command = apdu
            answers = []
        }
        var session = Session(answers: answers)
        do {
            let reply = try handle(Array(command!), &session)
            command = nil
            return reply + Self.status(0x9000)
        } catch let interrupt as Interrupt {
            return interrupt.request + Self.status(0xE000)
        } catch let failure as Failure {
            command = nil
            return Self.status(failure.status)
        } catch {
            command = nil
            return Self.status(0x6A80)
        }
    }

    // MARK: - Commands

    private func handle(_ apdu: [UInt8], _ session: inout Session) throws -> Data {
        guard apdu[0] == 0xE1 else { throw Failure(status: 0x6E00) }
        guard apdu[3] == 1 else { throw Failure(status: 0x6A86) }
        var reader = ByteReader(Data(apdu[5...]))
        switch apdu[1] {
        case 0x05:
            return Self.bigEndian(master.fingerprint)
        case 0x00:
            return try extendedPublicKey(&reader)
        case 0x02:
            return try register(&reader, &session)
        case 0x03:
            return try address(&reader, &session)
        case 0x04:
            return try sign(&reader, &session)
        default:
            throw Failure(status: 0x6D00)
        }
    }

    private func extendedPublicKey(_ reader: inout ByteReader) throws -> Data {
        let display = try reader.readUInt8() == 1
        let count = Int(try reader.readUInt8())
        guard count <= 8 else { throw Failure(status: 0x6A80) }
        var path: [UInt32] = []
        for _ in 0 ..< count { path.append(try Self.readBigEndian32(&reader)) }
        guard display || Self.isStandard(path) else { throw Failure(status: 0x6A82) }
        if display, decision == .reject { throw Failure(status: 0x6985) }
        return Data(try derive(path).neutered.serialized(network: .testnet).utf8)
    }

    private func register(_ reader: inout ByteReader, _ session: inout Session) throws -> Data {
        let length = Int(try reader.readVarInt())
        let serialized = try reader.readBytes(length)
        let policy = try Policy(serialized: serialized, session: &session)
        guard decision == .approve else { throw Failure(status: 0x6985) }
        registeredNames.append(policy.name)
        let id = Data(SHA256.hash(data: serialized))
        return id + hmac(id)
    }

    private func address(_ reader: inout ByteReader, _ session: inout Session) throws -> Data {
        let display = try reader.readUInt8() == 1
        let id = try reader.readBytes(32)
        let tag = try reader.readBytes(32)
        let change = try reader.readUInt8()
        let index = try Self.readBigEndian32(&reader)
        guard tag == hmac(id), change <= 1 else { throw Failure(status: 0xB008) }
        let policy = try Policy(serialized: session.preimage(of: id), session: &session)
        let address = try policy.descriptor().derived(index: index, bitcoinNetwork: .signet)[Int(change)].address
        if display {
            guard decision == .approve else { throw Failure(status: 0x6985) }
            displayedAddresses.append(address)
        }
        return Data(address.utf8)
    }

    private func sign(_ reader: inout ByteReader, _ session: inout Session) throws -> Data {
        let global = try Self.readCommitment(&reader)
        let inputCount = Int(try reader.readVarInt())
        let inputsRoot = try reader.readBytes(32)
        let outputCount = Int(try reader.readVarInt())
        let outputsRoot = try reader.readBytes(32)
        let id = try reader.readBytes(32)
        let tag = try reader.readBytes(32)
        guard tag == hmac(id) else { throw Failure(status: 0xB008) }
        _ = try Policy(serialized: session.preimage(of: id), session: &session)

        var document = Data([0x70, 0x73, 0x62, 0x74, 0xFF])
        document += try Self.serializedMap(session.map(global))
        for index in 0 ..< inputCount {
            let commitment = try session.element(root: inputsRoot, size: inputCount, index: index)
            var commitmentReader = ByteReader(commitment)
            document += try Self.serializedMap(session.map(Self.readCommitment(&commitmentReader)))
        }
        for index in 0 ..< outputCount {
            let commitment = try session.element(root: outputsRoot, size: outputCount, index: index)
            var commitmentReader = ByteReader(commitment)
            document += try Self.serializedMap(session.map(Self.readCommitment(&commitmentReader)))
        }
        var psbt = try PSBT(serialized: document)
        guard decision == .approve else { throw Failure(status: 0x6985) }

        for index in psbt.inputs.indices {
            var ownKeys: Set<Data> = []
            var secrets: [Data] = []
            for (xonly, origin) in psbt.inputs[index].tapBIP32Derivation where origin.masterFingerprint == master.fingerprint {
                let key = try derive(origin.path)
                guard Data(key.publicKey.dropFirst()) == xonly, let secret = key.privateKey else { continue }
                ownKeys.insert(xonly)
                secrets.append(secret)
            }
            guard !secrets.isEmpty else { continue }
            try psbt.signScriptPath(input: index, privateKeys: secrets, auxiliaryRand: Data(count: 32))
            // A fixed order: each replay must yield the same signature at the
            // same step, and a Dictionary's order differs between instances.
            let own = psbt.inputs[index].tapScriptSignatures.filter { ownKeys.contains($0.key.publicKey) }
                .sorted { ($0.key.leafHash + $0.key.publicKey).lexicographicallyPrecedes($1.key.leafHash + $1.key.publicKey) }
            for (signer, signature) in own {
                var yielded = Self.compactSize(UInt64(index))
                yielded.append(64)
                yielded += signer.publicKey + signer.leafHash + signature
                _ = try session.ask(Data([0x10]) + yielded)
            }
        }
        return Data()
    }

    // MARK: - Helpers

    private func derive(_ path: [UInt32]) throws -> HDKey {
        var key = master
        for step in path { key = try key.child(at: step) }
        return key
    }

    private func hmac(_ id: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: id, using: registrationKey))
    }

    /// The app's rule for keys it exports without asking: BIP44/45/49/84/86/87
    /// accounts and BIP48 script types 1' and 2', on the test coin.
    static func isStandard(_ path: [UInt32]) -> Bool {
        let hardened: UInt32 = 0x8000_0000
        guard path.count >= 3 else { return false }
        let purpose = path[0] & ~hardened
        let hardenedSteps: Int
        switch purpose {
        case 44, 45, 49, 84, 86, 87: hardenedSteps = 3
        case 48: hardenedSteps = 4
        default: return false
        }
        guard path.count >= hardenedSteps,
              path.prefix(hardenedSteps).allSatisfy({ $0 >= hardened }),
              path.dropFirst(hardenedSteps).allSatisfy({ $0 < hardened }),
              path[1] & ~hardened == 1, path[2] & ~hardened <= 100 else { return false }
        return purpose != 48 || [1, 2].contains(path[3] & ~hardened)
    }

    struct Commitment {
        var count: Int
        var keysRoot: Data
        var valuesRoot: Data
    }

    static func readCommitment(_ reader: inout ByteReader) throws -> Commitment {
        Commitment(count: Int(try reader.readVarInt()), keysRoot: try reader.readBytes(32),
                   valuesRoot: try reader.readBytes(32))
    }

    static func serializedMap(_ pairs: [(key: Data, value: Data)]) -> Data {
        var data = Data()
        for pair in pairs {
            data += compactSize(UInt64(pair.key.count)) + pair.key
            data += compactSize(UInt64(pair.value.count)) + pair.value
        }
        return data + Data([0x00])
    }

    static func compactSize(_ value: UInt64) -> Data {
        switch value {
        case 0 ..< 0xFD: return Data([UInt8(value)])
        case 0xFD ... 0xFFFF: return Data([0xFD, UInt8(value & 0xFF), UInt8(value >> 8)])
        default: return Data([0xFE] + (0 ..< 4).map { UInt8(value >> (8 * UInt64($0)) & 0xFF) })
        }
    }

    static func bigEndian(_ value: UInt32) -> Data {
        Data([UInt8(value >> 24), UInt8(value >> 16 & 0xFF), UInt8(value >> 8 & 0xFF), UInt8(value & 0xFF)])
    }

    static func readBigEndian32(_ reader: inout ByteReader) throws -> UInt32 {
        try reader.readBytes(4).reduce(0) { $0 << 8 | UInt32($1) }
    }

    static func status(_ word: UInt16) -> Data { Data([UInt8(word >> 8), UInt8(word & 0xFF)]) }

    struct Interrupt: Error {
        var request: Data
    }

    struct Failure: Error {
        var status: UInt16
    }

    /// A registered policy, rebuilt from what the client serves.
    struct Policy {
        var name: String
        var template: String
        var keys: [String]

        init(serialized: Data, session: inout Session) throws {
            var reader = ByteReader(serialized)
            guard try reader.readUInt8() == 0x02 else { throw Failure(status: 0x6A80) }
            let nameLength = Int(try reader.readUInt8())
            guard let name = String(data: try reader.readBytes(nameLength), encoding: .ascii) else {
                throw Failure(status: 0x6A80)
            }
            let templateLength = Int(try reader.readVarInt())
            let templateHash = try reader.readBytes(32)
            let keyCount = Int(try reader.readVarInt())
            let keysRoot = try reader.readBytes(32)
            try reader.requireEnd()
            let templateBytes = try session.preimage(of: templateHash)
            guard templateBytes.count == templateLength, let template = String(data: templateBytes, encoding: .ascii) else {
                throw Failure(status: 0x6A80)
            }
            var keys: [String] = []
            for index in 0 ..< keyCount {
                guard let key = String(data: try session.element(root: keysRoot, size: keyCount, index: index),
                                       encoding: .ascii) else { throw Failure(status: 0x6A80) }
                keys.append(key)
            }
            self.name = name
            self.template = template
            self.keys = keys
        }

        /// The template with each `@i/**` replaced by its key and `/<0;1>/*`.
        func descriptor() throws -> Descriptor {
            var text = template
            for index in keys.indices.reversed() {
                text = text.replacingOccurrences(of: "@\(index)/**", with: keys[index] + "/<0;1>/*")
                    .replacingOccurrences(of: "@\(index)/<", with: keys[index] + "/<")
            }
            return try Descriptor(text)
        }
    }

    /// The answers the client has given to this command so far, served in
    /// order; the first question past them interrupts the command.
    struct Session {
        let answers: [Data]
        var cursor = 0

        init(answers: [Data]) {
            self.answers = answers
        }

        mutating func ask(_ request: Data) throws -> Data {
            guard cursor < answers.count else { throw Interrupt(request: request) }
            defer { cursor += 1 }
            return answers[cursor]
        }

        /// GET_PREIMAGE, then GET_MORE_ELEMENTS until the whole preimage is
        /// in; its SHA-256 must be the hash asked for.
        mutating func preimage(of hash: Data) throws -> Data {
            var reader = ByteReader(try ask(Data([0x40, 0x00]) + hash))
            let total = Int(try reader.readVarInt())
            let first = Int(try reader.readUInt8())
            var preimage = try reader.readBytes(first)
            try reader.requireEnd()
            while preimage.count < total {
                var more = ByteReader(try ask(Data([0xA0])))
                let count = Int(try more.readUInt8())
                guard try more.readUInt8() == 1, count > 0 else { throw Failure(status: 0x6A80) }
                preimage += try more.readBytes(count)
                try more.requireEnd()
            }
            guard preimage.count == total, Data(SHA256.hash(data: preimage)) == hash else { throw Failure(status: 0x6A80) }
            return preimage
        }

        /// GET_MERKLE_LEAF_PROOF (and more elements), checked against `root`.
        mutating func leaf(root: Data, size: Int, index: Int) throws -> Data {
            var reader = ByteReader(try ask(Data([0x41]) + root + LedgerSimulator.compactSize(UInt64(size))
                                            + LedgerSimulator.compactSize(UInt64(index))))
            let leaf = try reader.readBytes(32)
            let proofLength = Int(try reader.readUInt8())
            let sent = Int(try reader.readUInt8())
            var proof: [Data] = []
            for _ in 0 ..< sent { proof.append(try reader.readBytes(32)) }
            try reader.requireEnd()
            while proof.count < proofLength {
                var more = ByteReader(try ask(Data([0xA0])))
                let count = Int(try more.readUInt8())
                guard try more.readUInt8() == 32, count > 0 else { throw Failure(status: 0x6A80) }
                for _ in 0 ..< count { proof.append(try more.readBytes(32)) }
                try more.requireEnd()
            }
            guard proof.count == proofLength, Self.root(leaf: leaf, index: index, size: size, proof: proof[...]) == root
            else { throw Failure(status: 0x6A80) }
            return leaf
        }

        /// A committed list element: its leaf, then its 0x00-prefixed preimage.
        mutating func element(root: Data, size: Int, index: Int) throws -> Data {
            let preimage = try preimage(of: leaf(root: root, size: size, index: index))
            guard preimage.first == 0x00 else { throw Failure(status: 0x6A80) }
            return Data(preimage.dropFirst())
        }

        mutating func map(_ commitment: Commitment) throws -> [(key: Data, value: Data)] {
            var pairs: [(key: Data, value: Data)] = []
            for index in 0 ..< commitment.count {
                let key = try element(root: commitment.keysRoot, size: commitment.count, index: index)
                let value = try element(root: commitment.valuesRoot, size: commitment.count, index: index)
                pairs.append((key, value))
            }
            return pairs
        }

        /// Recomputes a root from a leaf and its bottom-up proof: the last
        /// hash is the sibling nearest the root.
        static func root(leaf: Data, index: Int, size: Int, proof: ArraySlice<Data>) -> Data? {
            guard size > 1 else { return proof.isEmpty ? leaf : nil }
            guard let top = proof.last else { return nil }
            var left = 1
            while left * 2 < size { left *= 2 }
            if index < left {
                guard let below = root(leaf: leaf, index: index, size: left, proof: proof.dropLast()) else { return nil }
                return hash(below, top)
            }
            guard let below = root(leaf: leaf, index: index - left, size: size - left, proof: proof.dropLast()) else {
                return nil
            }
            return hash(top, below)
        }

        static func hash(_ left: Data, _ right: Data) -> Data {
            Data(SHA256.hash(data: Data([0x01]) + left + right))
        }
    }
}
