import CryptoKit
import Foundation

/// Errors in P2P message framing (24-byte header + payload).
public enum FramingError: Error, Equatable {
    case badMagic
    case badCommand
    case payloadTooLarge(UInt32)
    case checksumMismatch(String)
}

/// Stateful deframer for the Bitcoin P2P message stream. Feed arbitrary TCP
/// chunks via `append`; pull complete messages with `nextMessage`. Handles
/// split and coalesced frames.
///
/// Header layout (24 bytes): magic(4) || command(12, ASCII zero-padded) ||
/// length(4 LE) || checksum(4 = first 4 of SHA256d(payload)).
public struct MessageFramer: Sendable {
    public static let headerSize = 24
    /// MAX_PROTOCOL_MESSAGE_LENGTH in Bitcoin Core.
    public static let maxPayloadSize = 4_000_000

    public let magic: Data
    private var buffer = Data()

    public init(magic: Data) {
        precondition(magic.count == 4, "network magic must be 4 bytes")
        self.magic = magic
    }

    public mutating func append(_ data: Data) {
        buffer.append(data)
    }

    /// Bytes currently buffered (for tests/diagnostics).
    public var bufferedCount: Int { buffer.count }

    /// Where the buffer's live bytes begin. Non-zero after `removeFirst`,
    /// which reslices rather than frees; `compact()` brings it back to zero.
    var bufferStartIndex: Int { buffer.startIndex }

    /// Releases the bytes every consumed frame left behind.
    ///
    /// `removeFirst` on `Data` is a reslice: the storage stays, `startIndex`
    /// moves, and the next `append` grows that same storage in place — so a
    /// connection's memory would otherwise grow with every byte it has ever
    /// received. Called once per receive, after the drain loop, this costs at
    /// most one partial frame per chunk rather than one copy per message.
    public mutating func compact() {
        guard buffer.startIndex != 0 else { return }
        buffer = buffer.isEmpty ? Data() : Data(buffer)
    }

    /// Returns the next complete message, or nil if more bytes are needed.
    /// All indexing is relative to `buffer.startIndex` — `removeFirst` leaves
    /// a Data whose startIndex is not zero.
    public mutating func nextMessage() throws -> (command: String, payload: Data)? {
        guard buffer.count >= Self.headerSize else { return nil }
        let base = buffer.startIndex
        guard buffer[base ..< base + 4] == magic else { throw FramingError.badMagic }
        let commandBytes = buffer[base + 4 ..< base + 16]
        let commandEnd = commandBytes.firstIndex(of: 0) ?? commandBytes.endIndex
        let command = String(decoding: commandBytes[commandBytes.startIndex ..< commandEnd], as: UTF8.self)
        guard !command.isEmpty, command.allSatisfy({ $0.isASCII && !$0.isWhitespace }) else {
            throw FramingError.badCommand
        }
        let length = buffer.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 16, as: UInt32.self).littleEndian }
        guard length <= Self.maxPayloadSize else { throw FramingError.payloadTooLarge(length) }
        let total = Self.headerSize + Int(length)
        guard buffer.count >= total else { return nil }
        let payload = buffer.subdata(in: base + Self.headerSize ..< base + total)
        let checksum = buffer[base + 20 ..< base + Self.headerSize]
        guard SHA256d.hash(payload).prefix(4) == checksum else {
            throw FramingError.checksumMismatch(command)
        }
        buffer.removeFirst(total)
        return (command, payload)
    }

    /// Serializes one framed message (header + payload).
    public static func frame(command: String, payload: Data, magic: Data) -> Data {
        precondition(command.utf8.count <= 12, "command too long")
        var data = Data()
        data.reserveCapacity(headerSize + payload.count)
        data.append(magic)
        data.append(contentsOf: command.utf8)
        data.append(contentsOf: repeatElement(0, count: 12 - command.utf8.count))
        data.appendUInt32(UInt32(payload.count))
        data.append(SHA256d.hash(payload).prefix(4))
        data.append(payload)
        return data
    }
}
