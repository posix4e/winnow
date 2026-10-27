import Foundation

/// One command to a Ledger app: class, instruction, two parameters and at
/// most 255 bytes of data, as ISO 7816-4 short APDUs are.
struct LedgerAPDU: Equatable, Sendable {
    /// The Bitcoin app's commands, and the framework's CONTINUE.
    static let bitcoinClass: UInt8 = 0xE1
    static let frameworkClass: UInt8 = 0xF8
    /// Protocol version 1 of the Bitcoin app, sent as P2 on every command.
    static let protocolVersion: UInt8 = 1

    enum Instruction: UInt8 {
        case getExtendedPublicKey = 0x00
        case registerWallet = 0x02
        case getWalletAddress = 0x03
        case signPSBT = 0x04
        case getMasterFingerprint = 0x05
    }

    var cla: UInt8
    var ins: UInt8
    var p1: UInt8 = 0
    var p2: UInt8 = LedgerAPDU.protocolVersion
    var data: Data

    static func bitcoin(_ instruction: Instruction, _ data: Data = Data()) -> LedgerAPDU {
        LedgerAPDU(cla: bitcoinClass, ins: instruction.rawValue, data: data)
    }

    /// The answer to an interrupted command (status 0xE000).
    static func continueInterrupted(_ data: Data) -> LedgerAPDU {
        LedgerAPDU(cla: frameworkClass, ins: 0x01, data: data)
    }

    func serialized() throws -> Data {
        guard data.count <= 255 else { throw LedgerError.protocolViolation("a command longer than one APDU") }
        return Data([cla, ins, p1, p2, UInt8(data.count)]) + data
    }
}

/// A Ledger's reply: data followed by a two-byte status word.
struct LedgerResponse: Equatable, Sendable {
    static let ok: UInt16 = 0x9000
    static let interrupted: UInt16 = 0xE000

    var data: Data
    var status: UInt16

    init(_ bytes: Data) throws {
        guard bytes.count >= 2 else { throw LedgerError.transport("a reply shorter than its status word") }
        let raw = Array(bytes)
        status = UInt16(raw[raw.count - 2]) << 8 | UInt16(raw[raw.count - 1])
        data = Data(raw.dropLast(2))
    }
}

/// Ledger's Bluetooth framing, as in Ledger's own clients: every frame starts
/// with tag 0x05 and a big-endian sequence number; the first frame also
/// carries the APDU's big-endian length. Frames are at most the size the
/// device reports in answer to the MTU request.
public enum LedgerBluetoothFraming {
    static let tag: UInt8 = 0x05
    /// Asks the device for its frame size.
    public static let mtuRequest = Data([0x08, 0x00, 0x00, 0x00, 0x00])
    /// The frame size to use before the device has answered.
    public static let defaultFrameSize = 20

    /// The frame size in a reply to `mtuRequest` (its sixth byte), or nil for
    /// any other notification.
    public static func frameSize(fromMTUResponse response: Data) -> Int? {
        let bytes = Array(response)
        guard bytes.count >= 6, bytes[0] == 0x08, bytes[5] > 5 else { return nil }
        return Int(bytes[5])
    }

    /// Splits one APDU into frames of at most `frameSize` bytes.
    public static func frames(for apdu: Data, frameSize: Int) throws -> [Data] {
        guard frameSize > 5, apdu.count <= Int(UInt16.max) else {
            throw LedgerError.transport("an unusable frame size")
        }
        var frames: [Data] = []
        var remaining = apdu[...]
        var sequence: UInt16 = 0
        repeat {
            var frame = Data([tag, UInt8(sequence >> 8), UInt8(sequence & 0xFF)])
            if sequence == 0 { frame += [UInt8(apdu.count >> 8), UInt8(apdu.count & 0xFF)] }
            let room = frameSize - frame.count
            frame += remaining.prefix(room)
            remaining = remaining.dropFirst(room)
            frames.append(frame)
            guard sequence < UInt16.max else { throw LedgerError.transport("an APDU too long to frame") }
            sequence += 1
        } while !remaining.isEmpty
        return frames
    }

    /// Reassembles notifications into one reply.
    public struct Reassembler: Sendable {
        private var expected: Int?
        private var buffer = Data()
        private var nextSequence: UInt16 = 0

        public init() {}

        /// Feeds one notification; returns the whole reply once it is complete.
        public mutating func receive(_ frame: Data) throws -> Data? {
            let bytes = Array(frame)
            guard bytes.count >= 3, bytes[0] == LedgerBluetoothFraming.tag else {
                throw LedgerError.transport("a frame without the APDU tag")
            }
            let sequence = UInt16(bytes[1]) << 8 | UInt16(bytes[2])
            guard sequence == nextSequence else { throw LedgerError.transport("a frame out of sequence") }
            var payload = bytes.dropFirst(3)
            if sequence == 0 {
                guard bytes.count >= 5 else { throw LedgerError.transport("a first frame without a length") }
                expected = Int(bytes[3]) << 8 | Int(bytes[4])
                payload = bytes.dropFirst(5)
            }
            guard let expected else { throw LedgerError.transport("a frame before the first") }
            buffer += payload
            nextSequence = sequence &+ 1
            guard buffer.count >= expected else { return nil }
            let reply = buffer.prefix(expected)
            self = Reassembler()
            return Data(reply)
        }
    }
}
