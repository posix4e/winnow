import CryptoKit
import Foundation

/// Why a Ledger exchange failed. Each case names a step the user can act on,
/// or a protocol fault the phone refuses to work around.
public enum LedgerError: Error, Equatable, Sendable {
    /// Bluetooth or framing failed: the device went away or sent malformed frames.
    case transport(String)
    /// The Ledger is locked; unlock it with its PIN.
    case deviceLocked
    /// The Bitcoin app (Bitcoin Test on test networks) is not open on the Ledger.
    case appNotOpen
    /// The user declined on the Ledger's screen.
    case rejectedOnDevice
    /// Any other status word the device returned.
    case status(UInt16)
    /// The device asked for data the phone never committed to, or answered
    /// in a shape the protocol does not allow.
    case protocolViolation(String)
    /// The device's answer disagrees with what the phone derives itself:
    /// a policy id, an address or a signature.
    case mismatch(String)
}

extension LedgerError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        // Every interpolated reason is a developer-written literal, never
        // device or descriptor text.
        case let .transport(reason): "The Ledger connection failed: \(reason)."
        case .deviceLocked: "The Ledger is locked. Unlock it with its PIN and try again."
        case .appNotOpen: "Open the Bitcoin app on the Ledger (Bitcoin Test on signet) and try again."
        case .rejectedOnDevice: "The request was declined on the Ledger."
        case let .status(word): "The Ledger refused the request (status \(String(format: "%04X", word)))."
        case let .protocolViolation(reason): "The Ledger broke its protocol: \(reason)."
        case let .mismatch(reason): "The Ledger disagrees with this phone: \(reason)."
        }
    }

    /// Maps a non-success status word to the step the user can take.
    static func from(status word: UInt16) -> LedgerError {
        switch word {
        case 0x6985: .rejectedOnDevice
        case 0x5515: .deviceLocked
        // Wrong or no app: the dashboard and other apps refuse the class or
        // instruction, or report that no app is running.
        case 0x6E00, 0x6E01, 0x6D00, 0x6D02, 0x6511: .appNotOpen
        default: .status(word)
        }
    }
}

/// The phone's side of the app's interactive protocol. While a command runs,
/// the device interrupts with status 0xE000 and a client command; the
/// interpreter answers from data the phone committed to, and nothing else.
public struct LedgerClientCommandInterpreter {
    enum Code: UInt8 {
        case yield = 0x10
        case getPreimage = 0x40
        case getMerkleLeafProof = 0x41
        case getMerkleLeafIndex = 0x42
        case getMoreElements = 0xA0
    }

    /// Every answer must fit one APDU response.
    public static let maximumResponse = 255

    public private(set) var yielded: [Data] = []
    private var preimages: [Data: Data] = [:]
    private var trees: [Data: [Data]] = [:]
    private var queue: [Data] = []

    public init() {}

    /// A preimage the device may ask for by its SHA-256.
    public mutating func addKnownPreimage(_ preimage: Data) {
        preimages[Data(SHA256.hash(data: preimage))] = preimage
    }

    /// A committed list: each element is served as 0x00 ‖ element under its
    /// element hash, and the tree of element hashes under its root.
    public mutating func addKnownList(_ elements: [Data]) {
        var leaves: [Data] = []
        for element in elements {
            let leaf = LedgerMerkle.elementHash(element)
            preimages[leaf] = Data([0x00]) + element
            leaves.append(leaf)
        }
        trees[LedgerMerkle.root(leaves)] = leaves
    }

    /// A committed map: its sorted keys and its values as two lists.
    public mutating func addKnownMapping(_ pairs: [PSBT.KeyValue]) {
        let sorted = LedgerMerkle.sortedPairs(pairs)
        addKnownList(sorted.map(\.key))
        addKnownList(sorted.map(\.value))
    }

    public mutating func execute(_ request: Data) throws -> Data {
        guard let first = request.first, let code = Code(rawValue: first) else {
            throw LedgerError.protocolViolation("an unknown client command")
        }
        var reader = ByteReader(Data(request.dropFirst()))
        do {
            switch code {
            case .yield:
                yielded.append(Data(request.dropFirst()))
                return Data()
            case .getPreimage: return try preimage(&reader)
            case .getMerkleLeafProof: return try leafProof(&reader)
            case .getMerkleLeafIndex: return try leafIndex(&reader)
            case .getMoreElements: return try moreElements(&reader)
            }
        } catch let error as LedgerError {
            throw error
        } catch {
            throw LedgerError.protocolViolation("a malformed client command")
        }
    }

    private mutating func preimage(_ reader: inout ByteReader) throws -> Data {
        guard try reader.readUInt8() == 0 else { throw LedgerError.protocolViolation("an unsupported preimage request") }
        let hash = try reader.readBytes(32)
        try reader.requireEnd()
        guard queue.isEmpty else { throw LedgerError.protocolViolation("a request before the last answer was read") }
        guard let preimage = preimages[hash] else {
            throw LedgerError.protocolViolation("a preimage this phone never committed to")
        }
        var response = Data()
        response.appendCompactSize(UInt64(preimage.count))
        let payload = min(Self.maximumResponse - response.count - 1, preimage.count)
        response.append(UInt8(payload))
        response += preimage.prefix(payload)
        queue = preimage.dropFirst(payload).map { Data([$0]) }
        return response
    }

    private mutating func leafProof(_ reader: inout ByteReader) throws -> Data {
        let root = try reader.readBytes(32)
        let size = try reader.readVarInt()
        let index = try reader.readVarInt()
        try reader.requireEnd()
        guard queue.isEmpty else { throw LedgerError.protocolViolation("a request before the last answer was read") }
        guard let leaves = trees[root], UInt64(leaves.count) == size, index < size else {
            throw LedgerError.protocolViolation("a proof for a tree this phone never committed to")
        }
        let proof = LedgerMerkle.proof(leaves, index: Int(index))
        let sent = min((Self.maximumResponse - 32 - 1 - 1) / 32, proof.count)
        var response = leaves[Int(index)]
        response.append(UInt8(proof.count))
        response.append(UInt8(sent))
        for hash in proof.prefix(sent) { response += hash }
        queue = Array(proof.dropFirst(sent))
        return response
    }

    private func leafIndex(_ reader: inout ByteReader) throws -> Data {
        let root = try reader.readBytes(32)
        let leaf = try reader.readBytes(32)
        try reader.requireEnd()
        guard let leaves = trees[root] else {
            throw LedgerError.protocolViolation("a leaf search in a tree this phone never committed to")
        }
        var response = Data()
        if let index = leaves.firstIndex(of: leaf) {
            response.append(1)
            response.appendCompactSize(UInt64(index))
        } else {
            response.append(0)
            response.appendCompactSize(0)
        }
        return response
    }

    private mutating func moreElements(_ reader: inout ByteReader) throws -> Data {
        try reader.requireEnd()
        guard let length = queue.first?.count, queue.allSatisfy({ $0.count == length }), length > 0 else {
            throw LedgerError.protocolViolation("a request for elements that were never queued")
        }
        var elements: [Data] = []
        var total = 0
        while let next = queue.first, total + next.count <= Self.maximumResponse - 2 {
            elements.append(next)
            total += next.count
            queue.removeFirst()
        }
        var response = Data([UInt8(elements.count), UInt8(length)])
        for element in elements { response += element }
        return response
    }
}
