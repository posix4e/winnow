import CryptoKit
import Foundation

/// The Merkle commitments of Ledger's Bitcoin app (`app-bitcoin-new`). The
/// phone commits to a list or a key/value map by its root; the device then
/// asks for one element and its proof at a time and checks each against the
/// root, so it never has to hold the whole PSBT.
enum LedgerMerkle {
    /// The root of an empty tree.
    static let emptyRoot = Data(count: 32)

    /// SHA-256(0x00 ‖ element): the leaf of a committed list element.
    static func elementHash(_ element: Data) -> Data {
        Data(SHA256.hash(data: Data([0x00]) + element))
    }

    /// SHA-256(0x01 ‖ left ‖ right): an inner node.
    static func combine(_ left: Data, _ right: Data) -> Data {
        Data(SHA256.hash(data: Data([0x01]) + left + right))
    }

    /// The left subtree of n ≥ 2 leaves holds the largest power of two
    /// strictly below n, so it is always complete.
    static func leftCount(_ count: Int) -> Int {
        var left = 1
        while left * 2 < count { left *= 2 }
        return left
    }

    /// The root over already-hashed 32-byte leaves.
    static func root(_ leaves: [Data]) -> Data { root(leaves[...]) }

    private static func root(_ leaves: ArraySlice<Data>) -> Data {
        switch leaves.count {
        case 0: return emptyRoot
        case 1: return leaves[leaves.startIndex]
        default:
            let middle = leaves.startIndex + leftCount(leaves.count)
            return combine(root(leaves[..<middle]), root(leaves[middle...]))
        }
    }

    /// The sibling hashes from leaf `index` up to the root, bottom first.
    static func proof(_ leaves: [Data], index: Int) -> [Data] { proof(leaves[...], index: index) }

    private static func proof(_ leaves: ArraySlice<Data>, index: Int) -> [Data] {
        guard leaves.count > 1 else { return [] }
        let left = leftCount(leaves.count)
        let middle = leaves.startIndex + left
        if index < left {
            return proof(leaves[..<middle], index: index) + [root(leaves[middle...])]
        }
        return proof(leaves[middle...], index: index - left) + [root(leaves[..<middle])]
    }

    /// A key/value map sorted by key: compactSize(n) ‖ keys root ‖ values root,
    /// each tree over the element hashes of the keys or values in that order.
    static func mapCommitment(_ pairs: [PSBT.KeyValue]) -> Data {
        let sorted = sortedPairs(pairs)
        var commitment = Data()
        commitment.appendCompactSize(UInt64(sorted.count))
        commitment += root(sorted.map { elementHash($0.key) })
        commitment += root(sorted.map { elementHash($0.value) })
        return commitment
    }

    static func sortedPairs(_ pairs: [PSBT.KeyValue]) -> [PSBT.KeyValue] {
        pairs.sorted { $0.key.lexicographicallyPrecedes($1.key) }
    }
}
