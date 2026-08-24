import BitcoinCore
import BitcoinP2P
import Foundation
@testable import WalletCore

/// Master switch: the differential suite talks to the dev custom-signet node
/// ONLY when WINNOW_DIFF=1 is set. Default `swift test` runs skip cleanly
/// and never touch the network or the node.
///
/// Run it as:
///
///     scripts/signet-fixture up
///     WINNOW_DIFF=1 swift test --filter DiffTests --no-parallel
///
/// `--no-parallel` is required. Two suites mine onto the same tip, and run
/// concurrently they race for every block — each re-mines on the winner, and
/// the run stalls indefinitely instead of failing, which looks exactly like a
/// hang with no output.
let diffEnabled = ProcessInfo.processInfo.environment["WINNOW_DIFF"] == "1"

/// The well-known BIP39 all-"abandon" mnemonic — the harness never holds
/// real funds; this is a disposable signet.
let testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func testMaster() throws -> HDKey {
    try HDKey(seed: BIP39.seed(mnemonic: testMnemonic))
}

/// Thread-safe sink for FilterSync matches.
final class MatchCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [BlockMatch] = []

    var matches: [BlockMatch] {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    func add(_ match: BlockMatch) {
        lock.lock()
        stored.append(match)
        lock.unlock()
    }
}

/// Temporary file URL under a per-run directory.
func tempFileURL(_ name: String) -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("winnow-diff-tests-\(UUID().uuidString)")
        .appendingPathComponent(name)
    try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                             withIntermediateDirectories: true)
    return url
}

extension Data {
    /// Bitcoin compactSize varint (BitcoinP2P's `appendCompactSize` is
    /// module-internal and clashes under @testable double-import).
    mutating func appendVarInt(_ value: UInt64) {
        switch value {
        case ..<0xFD:
            append(UInt8(value))
        case ...0xFFFF:
            append(0xFD)
            Swift.withUnsafeBytes(of: UInt16(value).littleEndian) { append(contentsOf: $0) }
        case ...0xFFFF_FFFF:
            append(0xFE)
            Swift.withUnsafeBytes(of: UInt32(value).littleEndian) { append(contentsOf: $0) }
        default:
            append(0xFF)
            Swift.withUnsafeBytes(of: value.littleEndian) { append(contentsOf: $0) }
        }
    }
}

// MARK: - PSBT envelope conversion for Core

/// Core 31.1 reads BIP174 v0 only and rejects PSBTv2 outright; we emit v2 and
/// our parser rejects v0 (`PSBTError.unsupportedVersion`). So neither side can
/// read the other's envelope, and every exchange with Core has to be converted
/// in both directions. That is an interoperability fact about the pair, not a
/// defect in either, and it is why these two helpers exist.

/// BIP174 v0 serialization of one of our PSBTv2s: the global map carries the
/// unsigned transaction, and the v2-only fields are dropped from each map.
func v0Envelope(_ psbt: PSBT) throws -> String {
    var data = Data([0x70, 0x73, 0x62, 0x74, 0xFF])
    func serializeMap(_ pairs: [PSBT.KeyValue], into data: inout Data) {
        for pair in pairs.sorted(by: { $0.key.lexicographicallyPrecedes($1.key) }) {
            data.appendVarInt(UInt64(pair.key.count))
            data.append(pair.key)
            data.appendVarInt(UInt64(pair.value.count))
            data.append(pair.value)
        }
        data.append(0)
    }
    let unsigned = try psbt.unsignedTransaction().serialized(includeWitness: false)
    serializeMap([PSBT.KeyValue(type: 0x00, value: unsigned)], into: &data)
    for input in psbt.inputs {
        serializeMap(input.pairs.filter { ![0x0E, 0x0F, 0x10].contains($0.type) }, into: &data)
    }
    for output in psbt.outputs {
        serializeMap(output.pairs.filter { ![0x03, 0x04].contains($0.type) }, into: &data)
    }
    return data.base64EncodedString()
}

enum V0ParseError: Error, CustomStringConvertible {
    case malformed(String)
    var description: String {
        switch self { case let .malformed(what): "v0 PSBT: \(what)" }
    }
}

/// The input maps of a BIP174 v0 PSBT, in order. Used to read back what Core
/// added to a PSBT we handed it — our own parser will not accept the v0
/// envelope Core returns, so the pairs are lifted out at the byte level.
func v0InputMaps(base64: String, inputCount: Int) throws -> [[PSBT.KeyValue]] {
    guard let data = Data(base64Encoded: base64) else { throw V0ParseError.malformed("not base64") }
    guard data.starts(with: [0x70, 0x73, 0x62, 0x74, 0xFF]) else {
        throw V0ParseError.malformed("bad magic")
    }
    var cursor = data.startIndex + 5
    func readVarInt() throws -> Int {
        guard cursor < data.endIndex else { throw V0ParseError.malformed("truncated varint") }
        let first = data[cursor]; cursor += 1
        func read(_ count: Int) throws -> Int {
            guard cursor + count <= data.endIndex else { throw V0ParseError.malformed("truncated") }
            var value = 0
            for offset in 0 ..< count { value |= Int(data[cursor + offset]) << (8 * offset) }
            cursor += count
            return value
        }
        switch first {
        case 0xFD: return try read(2)
        case 0xFE: return try read(4)
        case 0xFF: return try read(8)
        default: return Int(first)
        }
    }
    func readMap() throws -> [PSBT.KeyValue] {
        var pairs: [PSBT.KeyValue] = []
        while true {
            let keyLength = try readVarInt()
            if keyLength == 0 { return pairs }
            guard cursor + keyLength <= data.endIndex else {
                throw V0ParseError.malformed("truncated key")
            }
            let key = Data(data[cursor ..< cursor + keyLength]); cursor += keyLength
            let valueLength = try readVarInt()
            guard cursor + valueLength <= data.endIndex else {
                throw V0ParseError.malformed("truncated value")
            }
            let value = Data(data[cursor ..< cursor + valueLength]); cursor += valueLength
            var pair = PSBT.KeyValue(type: key[key.startIndex], value: value)
            pair.key = key
            pairs.append(pair)
        }
    }
    _ = try readMap() // global
    return try (0 ..< inputCount).map { _ in try readMap() }
}
