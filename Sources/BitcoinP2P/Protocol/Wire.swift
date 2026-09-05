import Foundation

/// Errors thrown while decoding Bitcoin P2P wire data.
public enum WireError: Error, Equatable {
    case truncated(expected: Int, remaining: Int)
    case trailingBytes(Int)
    case invalidVarInt
    case malformed(String)
}

/// Sequential little-endian reader over a byte buffer (Bitcoin P2P wire format).
public struct ByteReader: Sendable {
    public let data: Data
    public private(set) var offset: Int
    /// Data slices can have a nonzero startIndex; all reads are base-relative.
    private let base: Int

    public init(_ data: Data) {
        self.data = data
        base = data.startIndex
        offset = 0
    }

    public var remaining: Int { data.count - offset }

    public mutating func readUInt8() throws -> UInt8 {
        guard remaining >= 1 else { throw WireError.truncated(expected: 1, remaining: remaining) }
        defer { offset += 1 }
        return data[base + offset]
    }

    public mutating func readUInt16() throws -> UInt16 {
        let bytes = try readBytes(2)
        return UInt16(bytes[bytes.startIndex]) | UInt16(bytes[bytes.startIndex + 1]) << 8
    }

    public mutating func readUInt32() throws -> UInt32 {
        let bytes = try readBytes(4)
        let base = bytes.startIndex
        return UInt32(bytes[base]) | UInt32(bytes[base + 1]) << 8 |
            UInt32(bytes[base + 2]) << 16 | UInt32(bytes[base + 3]) << 24
    }

    public mutating func readUInt64() throws -> UInt64 {
        let bytes = try readBytes(8)
        let base = bytes.startIndex
        var value: UInt64 = 0
        for i in 0 ..< 8 { value |= UInt64(bytes[base + i]) << (8 * i) }
        return value
    }

    public mutating func readInt32() throws -> Int32 {
        Int32(bitPattern: try readUInt32())
    }

    public mutating func readInt64() throws -> Int64 {
        Int64(bitPattern: try readUInt64())
    }

    public mutating func readBytes(_ count: Int) throws -> Data {
        guard count >= 0, remaining >= count else {
            throw WireError.truncated(expected: count, remaining: remaining)
        }
        defer { offset += count }
        return data.subdata(in: base + offset ..< base + offset + count)
    }

    /// Bitcoin compactSize ("varint"): 0xFD/0xFE/0xFF prefixes select 2/4/8-byte little-endian.
    ///
    /// Canonical only, as Bitcoin Core's `ReadCompactSize` enforces: a value
    /// carried in a wider form than it needs (`fd 00 00` for zero) is
    /// malformed. The wire has one spelling per number, so anything that hashes
    /// or round-trips serialized bytes can rely on decode∘encode being the
    /// identity; the fuzz harness checks exactly that on filters.
    public mutating func readVarInt() throws -> UInt64 {
        let first = try readUInt8()
        let value: UInt64
        let minimum: UInt64
        switch first {
        case ..<0xFD:
            return UInt64(first)
        case 0xFD:
            value = UInt64(try readUInt16())
            minimum = 0xFD
        case 0xFE:
            value = UInt64(try readUInt32())
            minimum = 0x1_0000
        default:
            value = try readUInt64()
            minimum = 0x1_0000_0000
        }
        guard value >= minimum else {
            throw WireError.malformed("non-canonical compactSize: \(value) encoded with prefix 0x\(String(first, radix: 16))")
        }
        return value
    }

    /// compactSize-prefixed byte string.
    public mutating func readVarData(maxLength: Int = 4_000_000) throws -> Data {
        let length = try readVarInt()
        guard length <= maxLength else { throw WireError.malformed("var data length \(length) exceeds \(maxLength)") }
        return try readBytes(Int(length))
    }

    /// compactSize-prefixed UTF-8 string (user agents, etc.).
    public mutating func readVarString(maxLength: Int = 1_000) throws -> String {
        let bytes = try readVarData(maxLength: maxLength)
        return String(decoding: bytes, as: UTF8.self)
    }

    /// Throws if the buffer was not consumed exactly.
    public func requireEnd() throws {
        guard remaining == 0 else { throw WireError.trailingBytes(remaining) }
    }
}

extension Data {
    mutating func appendUInt8(_ value: UInt8) { append(value) }

    mutating func appendUInt16(_ value: UInt16) {
        Swift.withUnsafeBytes(of: value.littleEndian) { append(contentsOf: $0) }
    }

    mutating func appendUInt32(_ value: UInt32) {
        Swift.withUnsafeBytes(of: value.littleEndian) { append(contentsOf: $0) }
    }

    mutating func appendUInt64(_ value: UInt64) {
        Swift.withUnsafeBytes(of: value.littleEndian) { append(contentsOf: $0) }
    }

    mutating func appendInt32(_ value: Int32) { appendUInt32(UInt32(bitPattern: value)) }
    mutating func appendInt64(_ value: Int64) { appendUInt64(UInt64(bitPattern: value)) }

    mutating func appendCompactSize(_ value: UInt64) {
        switch value {
        case ..<0xFD:
            append(UInt8(value))
        case ...0xFFFF:
            append(0xFD)
            appendUInt16(UInt16(value))
        case ...0xFFFF_FFFF:
            append(0xFE)
            appendUInt32(UInt32(value))
        default:
            append(0xFF)
            appendUInt64(value)
        }
    }

    mutating func appendVarData(_ bytes: Data) {
        appendCompactSize(UInt64(bytes.count))
        append(bytes)
    }

    mutating func appendVarString(_ string: String) {
        appendVarData(Data(string.utf8))
    }
}

extension Data {
    /// Raw byte order (no reversal — see `displayHex` for hash display).
    public init?(hex: String) {
        let cleaned = hex.trimmingCharacters(in: .whitespacesAndNewlines)
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
        self = bytes
    }

    /// Lowercase hex, raw byte order.
    public var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
