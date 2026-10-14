import Foundation

/// Minimal script model for Taproot script-path construction (BIP341/BIP342).
/// This is not an interpreter — only opcodes needed for tapscript leaves.
public struct Script: Sendable, Equatable {
    /// Raw serialized script bytes.
    public private(set) var bytes: Data

    public init(_ bytes: Data) {
        self.bytes = bytes
    }

    /// Script from a hex string.
    public init?(hex: String) {
        var cleaned = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        if cleaned.hasPrefix("0x") { cleaned = String(cleaned.dropFirst(2)) }
        guard cleaned.count % 2 == 0, !cleaned.isEmpty else { return nil }
        var bytes = Data()
        bytes.reserveCapacity(cleaned.count / 2)
        var index = cleaned.startIndex
        while index < cleaned.endIndex {
            let next = cleaned.index(index, offsetBy: 2)
            guard let byte = UInt8(cleaned[index ..< next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }

    /// Lowercase hex serialization.
    public var hex: String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// Opcode constants (subset, BIP342 tapscript).
    public enum Op {
        public static let zero: UInt8 = 0x00 // OP_0
        public static let pushData1: UInt8 = 0x4c
        public static let pushData2: UInt8 = 0x4d
        public static let pushData4: UInt8 = 0x4e
        public static let oneNegate: UInt8 = 0x4f // OP_1NEGATE
        public static let checkSig: UInt8 = 0xac // OP_CHECKSIG
        public static let checkSigAdd: UInt8 = 0xba // OP_CHECKSIGADD
        public static let numEqual: UInt8 = 0x9c // OP_NUMEQUAL
        public static let greaterThanOrEqual: UInt8 = 0xa2 // OP_GREATERTHANOREQUAL

        /// OP_1 through OP_16 (0x51...0x60).
        public static func n(_ value: Int) -> UInt8 {
            precondition(value >= 1 && value <= 16, "OP_N out of range")
            return 0x50 + UInt8(value)
        }
    }

    /// Appends a raw opcode.
    public mutating func appendOpcode(_ opcode: UInt8) {
        bytes.append(opcode)
    }

    /// Appends a data push using the minimal PUSHDATA encoding.
    public mutating func appendPush(_ data: Data) {
        switch data.count {
        case ..<0x4c:
            bytes.append(UInt8(data.count))
        case ...0xFF:
            bytes.append(Op.pushData1)
            bytes.append(UInt8(data.count))
        case ...0xFFFF:
            bytes.append(Op.pushData2)
            withUnsafeBytes(of: UInt16(data.count).littleEndian) { bytes.append(contentsOf: $0) }
        default:
            bytes.append(Op.pushData4)
            withUnsafeBytes(of: UInt32(data.count).littleEndian) { bytes.append(contentsOf: $0) }
        }
        bytes.append(data)
    }

    /// Appends a small integer: OP_0/OP_1...OP_16 for 0...16, otherwise a
    /// minimally-encoded (little-endian, sign-magnitude) script number push.
    public mutating func appendScriptNumber(_ value: Int) {
        precondition(value >= 0, "negative script numbers not supported")
        switch value {
        case 0:
            bytes.append(Op.zero)
        case 1 ... 16:
            bytes.append(Op.n(value))
        default:
            var v = value
            var encoded = Data()
            while v > 0 {
                encoded.append(UInt8(v & 0xFF))
                v >>= 8
            }
            if encoded.last! & 0x80 != 0 { encoded.append(0) } // sign byte
            appendPush(encoded)
        }
    }

    /// Builds a script from opcodes/pushes.
    public static func build(_ body: (inout Script) throws -> Void) rethrows -> Script {
        var script = Script(Data())
        try body(&script)
        return script
    }
}
