import Foundation
import Testing
import TestSupport
@testable import BitcoinCore
@testable import WalletCore

/// BIP158 test vectors (bip-0158/testnet-19.json): reconstruct basic filters
/// from block output scripts + previous output scripts, compare filter and header.
@Suite("BIP158")
struct BIP158Tests {
    @Test("filter construction matches vectors")
    func construction() throws {
        for vector in try Vectors.bip158(in: .module) {
            // BIP158 basic filter items: previous output scripts plus every output
            // scriptPubKey, skipping empty and provably-unspendable (OP_RETURN) scripts.
            let items = (vector.prevScripts + (try blockOutputScripts(vector.rawBlock)))
                .filter { !$0.isEmpty && $0.first != 0x6A }
            let filter = try GCSFilter(items: items, key: vector.blockHash.prefix(16))
            #expect(filter.serialized == vector.filter, "height \(vector.height)")
        }
    }

    @Test("filter headers match vectors")
    func headers() throws {
        for vector in try Vectors.bip158(in: .module) {
            let header = GCSFilter.filterHeader(vector.filter, previousHeader: vector.previousHeader)
            #expect(header == vector.header, "height \(vector.height)")
        }
    }

    @Test("constructed filters match their own items and reject strangers")
    func matching() throws {
        for vector in try Vectors.bip158(in: .module) {
            let items = (vector.prevScripts + (try blockOutputScripts(vector.rawBlock)))
                .filter { !$0.isEmpty && $0.first != 0x6A }
            let filter = try GCSFilter(items: items, key: vector.blockHash.prefix(16))
            for item in Set(items) {
                #expect(filter.contains(item), "height \(vector.height)")
            }
            #expect(!filter.contains(Data([0xDE, 0xAD, 0xBE, 0xEF])))
            #expect(filter.containsAny(Array(items.prefix(1))) == !items.isEmpty)
        }
    }

    @Test("empty filter round-trips")
    func emptyFilter() throws {
        let filter = try GCSFilter(items: [], key: Data(repeating: 0, count: 16))
        #expect(filter.serialized == Data([0]))
        #expect(!filter.contains(Data([0x51])))
    }

    @Test("hostile claimed counts and malformed streams fail before matching")
    func hostileEncodingBounds() throws {
        let key = Data(repeating: 0, count: 16)

        #expect(throws: GCSError.tooManyElements(UInt32.max)) {
            _ = try GCSFilter(key: key, n: UInt32.max, encoded: Data())
        }
        #expect(throws: GCSError.truncatedEncoding) {
            _ = try GCSFilter(key: key, n: 100_000, encoded: Data([0]))
        }
        #expect(throws: GCSError.nonCanonicalEncoding) {
            _ = try GCSFilter(key: key, n: 0, encoded: Data([0]))
        }
        #expect(throws: GCSError.nonCanonicalEncoding) {
            // N=1, P=0: the first zero completes the item; another full byte
            // is not legal padding.
            _ = try GCSFilter(p: 0, m: 1, key: key, n: 1, encoded: Data([0, 0]))
        }
        #expect(throws: GCSError.nonCanonicalEncoding) {
            // N=1, P=0: nonzero padding is not canonical.
            _ = try GCSFilter(p: 0, m: 1, key: key, n: 1, encoded: Data([0x40]))
        }
    }
}

/// `matchAny` replaced a per-item full decode with a single sorted merge pass
/// (#84). The algorithms must agree exactly, including on the awkward cases:
/// duplicates, queries either side of every set element, and empty inputs.
@Suite("GCS matchAny agrees with per-item contains")
struct GCSMatchAnyTests {
    /// Deterministic pseudo-random bytes so a failure is reproducible.
    private func bytes(_ seed: inout UInt64, count: Int) -> Data {
        var out = Data(capacity: count)
        for _ in 0 ..< count {
            seed = seed &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            out.append(UInt8((seed >> 33) & 0xFF))
        }
        return out
    }

    @Test("matches per-item contains across filter and query sizes")
    func agreesWithContains() throws {
        var seed: UInt64 = 0x5EED_1158
        let key = Data((0 ..< 16).map { UInt8($0) })

        for setSize in [1, 2, 7, 64, 400] {
            let members = (0 ..< setSize).map { _ in bytes(&seed, count: 32) }
            let filter = try GCSFilter(items: members, key: key)

            for querySize in [0, 1, 3, 40] {
                // A mix of real members and values that are not in the set.
                var queries = (0 ..< querySize).map { _ in bytes(&seed, count: 32) }
                let expectedMiss = filter.matchAny(queries)
                #expect(expectedMiss == queries.contains(where: filter.contains),
                        "miss case disagreed: set=\(setSize) queries=\(querySize)")

                if let member = members.first, querySize > 0 {
                    queries[querySize / 2] = member
                    #expect(filter.matchAny(queries) == true)
                    #expect(filter.matchAny(queries) == queries.contains(where: filter.contains))
                }
            }

            // Every member individually, and all members at once.
            for member in members {
                #expect(filter.matchAny([member]) == true)
                #expect(filter.matchAny([member]) == filter.contains(member))
            }
            #expect(filter.matchAny(members) == true)

            // Duplicates must not change the answer.
            if let member = members.first {
                #expect(filter.matchAny([member, member, member]) == true)
            }
        }
    }

    @Test("empty query and empty filter both answer false")
    func emptyEdges() throws {
        let key = Data((0 ..< 16).map { UInt8($0) })
        let empty = try GCSFilter(items: [], key: key)
        #expect(empty.matchAny([Data([1, 2, 3])]) == false)

        let populated = try GCSFilter(items: [Data([9, 9, 9])], key: key)
        #expect(populated.matchAny([]) == false)
        #expect(populated.matchAny([Data([9, 9, 9])]) == true)
    }
}
