import CryptoKit
import Foundation

public enum GCSError: Error, Equatable {
    case emptyKey
    case invalidParameters
    case tooManyElements(UInt32)
    case encodedFilterTooLarge(Int)
    case truncatedEncoding
    case nonCanonicalEncoding
    case decodedValueOverflow
}

/// BIP158 Golomb-Coded-Set filter (basic filters: P=19, M=784931).
public struct GCSFilter: Sendable, Equatable {
    public static let defaultP: UInt8 = 19
    public static let defaultM: UInt32 = 784_931
    /// Resource ceiling for an untrusted BIP158 filter. A standard block cannot
    /// produce nearly this many basic-filter elements, while accepting a
    /// claimed UInt32-sized set would make matching loop billions of times.
    public static let maxElementCount: UInt32 = 1_000_000
    public static let maxEncodedSize = 4_000_000

    public let p: UInt8
    public let m: UInt32
    public let key: Data // 16-byte SipHash key (k0 || k1, little-endian)
    public let n: UInt32 // number of items in the hashed set
    public let encoded: Data // Golomb-Rice bitstream, without the N prefix

    /// Builds a filter from arbitrary byte-string items.
    /// Callers supply already-filtered items (BIP158 blocks skip empty and OP_RETURN scripts).
    public init(items: [Data], p: UInt8 = GCSFilter.defaultP, m: UInt32 = GCSFilter.defaultM, key: Data) throws {
        guard key.count == 16 else { throw GCSError.emptyKey }
        self.p = p
        self.m = m
        self.key = key

        let unique = Set(items)
        n = UInt32(unique.count)
        guard n > 0 else {
            encoded = Data()
            return
        }

        let k0 = key.withUnsafeBytes { $0.loadUnaligned(as: UInt64.self).littleEndian }
        let k1 = key.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 8, as: UInt64.self).littleEndian }
        let f = UInt64(n) * UInt64(m)
        let hashed = unique.map { item -> UInt64 in
            let h = SipHash.hash(k0: k0, k1: k1, item)
            return h.multipliedFullWidth(by: f).high
        }.sorted()

        var writer = BitWriter()
        var last: UInt64 = 0
        for value in hashed {
            let delta = value - last
            last = value
            // Golomb-Rice: quotient in unary, remainder in P bits, MSB first.
            let quotient = delta >> p
            for _ in 0 ..< quotient { writer.write(true) }
            writer.write(false)
            let remainder = delta & ((1 << UInt64(p)) - 1)
            for i in stride(from: Int(p) - 1, through: 0, by: -1) {
                writer.write((remainder >> i) & 1 == 1)
            }
        }
        encoded = writer.data
    }

    public init(p: UInt8 = GCSFilter.defaultP, m: UInt32 = GCSFilter.defaultM, key: Data, n: UInt32, encoded: Data) throws {
        guard key.count == 16 else { throw GCSError.emptyKey }
        guard p < 64, m > 0 else { throw GCSError.invalidParameters }
        guard n <= Self.maxElementCount else { throw GCSError.tooManyElements(n) }
        guard encoded.count <= Self.maxEncodedSize else {
            throw GCSError.encodedFilterTooLarge(encoded.count)
        }
        try Self.validateEncoding(p: p, n: n, encoded: encoded)
        self.p = p
        self.m = m
        self.key = key
        self.n = n
        self.encoded = encoded
    }

    /// Validate the complete Golomb-Rice stream once at the hostile-input
    /// boundary. Matching can then remain a small, nonthrowing hot path.
    private static func validateEncoding(p: UInt8, n: UInt32, encoded: Data) throws {
        if n == 0 {
            guard encoded.isEmpty else { throw GCSError.nonCanonicalEncoding }
            return
        }

        // Every item requires a zero terminator and P remainder bits. This
        // rejects tiny encodings with enormous claimed counts before looping.
        let minimumBits = UInt64(n) * UInt64(p + 1)
        guard UInt64(encoded.count) * 8 >= minimumBits else {
            throw GCSError.truncatedEncoding
        }

        var reader = BitReader(encoded)
        var value: UInt64 = 0
        for _ in 0 ..< n {
            let delta = try readGolombRiceDelta(from: &reader, p: p)
            let (next, overflow) = value.addingReportingOverflow(delta)
            guard !overflow else { throw GCSError.decodedValueOverflow }
            value = next
        }

        try checkCanonicalPadding(&reader)
    }

    /// The writer pads the final byte with at most seven zero bits. Extra
    /// bytes or nonzero padding would be a second spelling of the filter.
    private static func checkCanonicalPadding(_ reader: inout BitReader) throws {
        guard reader.remainingBits < 8 else { throw GCSError.nonCanonicalEncoding }
        while let bit = reader.readOptional() {
            guard !bit else { throw GCSError.nonCanonicalEncoding }
        }
    }

    /// One Golomb-Rice codeword: unary quotient, P remainder bits, composed
    /// under overflow checks. Throws on truncation exactly where the stream
    /// ran out.
    private static func readGolombRiceDelta(from reader: inout BitReader,
                                            p: UInt8) throws -> UInt64 {
        var quotient: UInt64 = 0
        while true {
            guard let bit = reader.readOptional() else { throw GCSError.truncatedEncoding }
            if !bit { break }
            let (next, overflow) = quotient.addingReportingOverflow(1)
            guard !overflow else { throw GCSError.decodedValueOverflow }
            quotient = next
        }

        var remainder: UInt64 = 0
        for _ in 0 ..< p {
            guard let bit = reader.readOptional() else { throw GCSError.truncatedEncoding }
            remainder = (remainder << 1) | UInt64(bit ? 1 : 0)
        }
        guard quotient <= UInt64.max >> p else { throw GCSError.decodedValueOverflow }
        return (quotient << p) | remainder
    }

    /// Serialized form: compactSize(N) || encoded bitstream (BIP158 `NBytes`).
    public var serialized: Data {
        var data = Data()
        data.appendCompactSize(UInt64(n))
        data.append(encoded)
        return data
    }

    private func hashedValue(_ item: Data) -> UInt64 {
        let k0 = key.withUnsafeBytes { $0.loadUnaligned(as: UInt64.self).littleEndian }
        let k1 = key.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 8, as: UInt64.self).littleEndian }
        return SipHash.hash(k0: k0, k1: k1, item).multipliedFullWidth(by: UInt64(n) * UInt64(m)).high
    }

    public func contains(_ item: Data) -> Bool {
        guard n > 0 else { return false }
        let target = hashedValue(item)
        var reader = BitReader(encoded)
        var last: UInt64 = 0
        for _ in 0 ..< n {
            var quotient: UInt64 = 0
            while reader.read() == true { quotient += 1 }
            var remainder: UInt64 = 0
            for _ in 0 ..< p { remainder = (remainder << 1) | UInt64(reader.read() ? 1 : 0) }
            let value = last + (quotient << p) + remainder
            if value == target { return true }
            if value > target { return false }
            last = value
        }
        return false
    }

    /// BIP158 `MatchAny`: hash every query into the filter's range, sort once,
    /// then walk the decoded set and the sorted queries together in a single
    /// pass.
    ///
    /// The obvious spelling — `items.contains(where: contains)` — re-decodes
    /// the whole Golomb-Rice stream from the first bit for *every* item. A
    /// wallet watches its gap-limit lookahead on both chains plus every known
    /// UTXO script, so that was tens of full decodes per block (#84). The
    /// filter is delta-encoded in sorted order precisely so one pass suffices.
    public func matchAny(_ items: [Data]) -> Bool {
        guard n > 0, !items.isEmpty else { return false }

        var targets = items.map(hashedValue)
        targets.sort()

        var reader = BitReader(encoded)
        var value: UInt64 = 0
        var index = 0
        for _ in 0 ..< n {
            var quotient: UInt64 = 0
            while reader.read() == true { quotient += 1 }
            var remainder: UInt64 = 0
            for _ in 0 ..< p { remainder = (remainder << 1) | UInt64(reader.read() ? 1 : 0) }
            value += (quotient << p) + remainder

            // Advance past queries this set element has already overtaken;
            // duplicates in `targets` collapse here for free.
            while index < targets.count, targets[index] < value { index += 1 }
            if index == targets.count { return false }
            if targets[index] == value { return true }
        }
        return false
    }

    public func containsAny(_ items: [Data]) -> Bool {
        matchAny(items)
    }

    /// BIP158 filter header chain: SHA256d(SHA256d(filter) || previousHeader).
    /// Headers are 32-byte hashes in internal (little-endian display-reversed) byte order.
    public static func filterHash(_ serializedFilter: Data) -> Data {
        Data(SHA256.hash(data: Data(SHA256.hash(data: serializedFilter))))
    }

    public static func filterHeader(_ serializedFilter: Data, previousHeader: Data) -> Data {
        Data(SHA256.hash(data: Data(SHA256.hash(data: filterHash(serializedFilter) + previousHeader))))
    }
}

struct BitWriter {
    private(set) var data = Data()
    private var bitCount = 0

    mutating func write(_ bit: Bool) {
        if bitCount % 8 == 0 { data.append(0) }
        if bit { data[data.count - 1] |= 1 << UInt8(7 - (bitCount % 8)) }
        bitCount += 1
    }
}

struct BitReader {
    let data: Data
    private var bitCount = 0

    init(_ data: Data) {
        self.data = data
    }

    var remainingBits: Int { data.count * 8 - bitCount }

    mutating func readOptional() -> Bool? {
        let byte = bitCount / 8
        guard byte < data.count else { return nil }
        let bit = (data[byte] >> UInt8(7 - (bitCount % 8))) & 1
        bitCount += 1
        return bit == 1
    }

    mutating func read() -> Bool {
        readOptional() ?? false
    }
}
