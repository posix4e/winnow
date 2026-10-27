import CryptoKit
import Foundation
import Testing
import WinnowFuzzCore

/// Each fuzz target's check runs under `swift test` too, not only in fuzz
/// campaigns: every target on small inputs, and the Ledger target on the
/// hostile device bytes it exists for.
@Suite("Fuzz targets")
struct FuzzTargetTests {
    @Test("every target takes empty and arbitrary input without a finding", arguments: FuzzTarget.allCases)
    func everyTarget(_ target: FuzzTarget) throws {
        var rng = SplitMix64(state: 7)
        for input in [Data(), Data([0x00]), Data(repeating: 0xFF, count: 64), Data("tr(".utf8)] {
            try exercise(target, data: input, rng: &rng)
        }
    }

    static func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }

    /// Ledger's Merkle root over 0x00-prefixed element hashes, written here
    /// from the app's description rather than taken from WalletCore.
    static func root(_ leaves: ArraySlice<Data>) -> Data {
        guard leaves.count > 1 else { return leaves.first ?? Data(count: 32) }
        var left = 1
        while left * 2 < leaves.count { left *= 2 }
        let middle = leaves.startIndex + left
        return sha256(Data([0x01]) + root(leaves[..<middle]) + root(leaves[middle...]))
    }

    @Test("hostile Ledger frames, client commands and yields never break the target's invariants")
    func ledgerTarget() throws {
        var rng = SplitMix64(state: 11)
        // A 40-byte reply in 23-byte frames, then the same frames out of order.
        let first = Data([0x05, 0x00, 0x00, 0x00, 40]) + Data(repeating: 0x90, count: 18)
        let second = Data([0x05, 0x00, 0x01]) + Data(repeating: 0x90, count: 20)
        let third = Data([0x05, 0x00, 0x02]) + Data(repeating: 0x90, count: 2)
        let leaves = (0 ..< 100).map { Self.sha256(Data([0x00, UInt8($0)])) }
        let listRoot = Self.root(leaves[...])
        let inputs: [Data] = [
            first + second + third,
            first + third + second,
            Data([0x40, 0x00]) + Self.sha256(Data("winnow".utf8)),
            Data([0x40, 0x00]) + Self.sha256(Data(repeating: 0x5A, count: 600)),
            Data([0x40, 0x01]) + Data(count: 32),
            Data([0x41]) + listRoot + Data([100, 77]),
            Data([0x41]) + listRoot + Data([100, 100]),
            Data([0x42]) + listRoot + leaves[5],
            Data([0xA0]),
            Data([0x10, 0x01, 0x02]),
            Data([0x01, 64]) + Data(repeating: 0x11, count: 64) + Data(repeating: 0x22, count: 64),
            Data([0x09, 64]) + Data(repeating: 0x11, count: 128),
            Data([0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]),
        ]
        for input in inputs {
            try exercise(.ledger, data: input, rng: &rng)
        }
    }
}
