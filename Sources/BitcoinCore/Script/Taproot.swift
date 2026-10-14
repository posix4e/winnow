import CryptoKit
import Foundation
import P256K

public enum TaprootError: Error, Equatable {
    case invalidInternalKey
    case invalidControlBlock
    case tweakFailed
    case leafNotFound
}

/// BIP341 Taproot: tapleaf/tapbranch hashes, script-tree merkle root, taptweak
/// and output key computation, and control block build/serialize/parse.
public enum Taproot {
    /// Leaf version for BIP342 tapscript leaves.
    public static let leafVersion: UInt8 = 0xC0

    /// A Taproot script tree: leaves are (version, script) pairs, inner nodes
    /// are binary branches. Trees may be unbalanced (BIP341).
    public indirect enum Tree: Sendable, Equatable {
        case leaf(version: UInt8 = Taproot.leafVersion, script: Script)
        case branch(Tree, Tree)
    }

    /// BIP341 control block: proof that a leaf is committed to by an output key.
    public struct ControlBlock: Sendable, Equatable {
        /// Leaf version of the revealed script (without the parity bit).
        public let leafVersion: UInt8
        /// Y parity of the tweaked output key Q.
        public let outputKeyParity: Bool
        /// 32-byte x-only internal key.
        public let internalKey: Data
        /// Sibling hashes, leaf level first (bottom-up).
        public let path: [Data]

        public init(leafVersion: UInt8, outputKeyParity: Bool, internalKey: Data, path: [Data]) {
            self.leafVersion = leafVersion
            self.outputKeyParity = outputKeyParity
            self.internalKey = internalKey
            self.path = path
        }

        /// Serialization: control byte (leaf version | parity bit), internal key,
        /// then the 32-byte merkle path hashes (BIP341).
        public var serialized: Data {
            var data = Data([leafVersion | (outputKeyParity ? 1 : 0)])
            data.append(internalKey)
            for hash in path { data.append(hash) }
            return data
        }

        /// Parses a control block; length must be 33 + 32m with m in 0...128.
        public init(serialized: Data) throws {
            guard serialized.count >= 33, (serialized.count - 33) % 32 == 0,
                  (serialized.count - 33) / 32 <= 128
            else { throw TaprootError.invalidControlBlock }
            let controlByte = serialized[serialized.startIndex]
            self.init(leafVersion: controlByte & 0xFE,
                      outputKeyParity: controlByte & 1 != 0,
                      internalKey: serialized.subdata(in: serialized.startIndex + 1 ..< serialized.startIndex + 33),
                      path: stride(from: serialized.startIndex + 33, to: serialized.endIndex, by: 32)
                          .map { serialized.subdata(in: $0 ..< $0 + 32) })
        }
    }

    /// TapLeaf hash: H_TapLeaf(leafVersion || CompactSize(script length) || script).
    public static func leafHash(version: UInt8 = leafVersion, script: Script) -> Data {
        var message = Data([version])
        appendCompactSize(script.bytes.count, to: &message)
        message.append(script.bytes)
        return TaggedHash.hash("TapLeaf", message)
    }

    /// TapBranch hash of the lexicographically sorted pair (BIP341).
    public static func branchHash(_ a: Data, _ b: Data) -> Data {
        let (first, second) = a.lexicographicallyPrecedes(b) ? (a, b) : (b, a)
        return TaggedHash.hash("TapBranch", first + second)
    }

    /// Merkle root of a script tree; nil for a key-only output.
    public static func merkleRoot(of tree: Tree) -> Data {
        hashes(of: tree).root
    }

    /// TapTweak hash: H_TapTweak(internalKey || merkleRoot) — or H_TapTweak(internalKey)
    /// when there is no script tree.
    public static func tweak(internalKey: Data, merkleRoot: Data?) -> Data {
        TaggedHash.hash("TapTweak", internalKey + (merkleRoot ?? Data()))
    }

    /// Tweaked output key Q = P + H_TapTweak(P || root)*G and its Y parity (BIP341).
    public static func tweakedOutputKey(internalKey: Data, merkleRoot: Data? = nil) throws
        -> (key: Data, parity: Bool)
    {
        guard internalKey.count == 32 else { throw TaprootError.invalidInternalKey }
        let t = tweak(internalKey: internalKey, merkleRoot: merkleRoot)
        let key = P256K.Schnorr.XonlyKey(dataRepresentation: internalKey)
        guard let tweaked = try? key.add([UInt8](t)) else { throw TaprootError.tweakFailed }
        return (Data(tweaked.bytes), tweaked.parity)
    }

    /// P2TR scriptPubKey: OP_1 <32-byte output key>.
    public static func scriptPubKey(internalKey: Data, merkleRoot: Data? = nil) throws -> Data {
        var script = Data([0x51, 0x20])
        script.append(try tweakedOutputKey(internalKey: internalKey, merkleRoot: merkleRoot).key)
        return script
    }

    /// Control blocks for every leaf of the tree, in-order. Requires the internal
    /// key to fill in the control block and compute the output key parity.
    public static func controlBlocks(internalKey: Data, tree: Tree) throws -> [ControlBlock] {
        let root = merkleRoot(of: tree)
        let (_, parity) = try tweakedOutputKey(internalKey: internalKey, merkleRoot: root)
        return hashes(of: tree).leaves.map { leaf in
            ControlBlock(leafVersion: leaf.version, outputKeyParity: parity,
                         internalKey: internalKey, path: leaf.path)
        }
    }

    /// Control block for the leaf with the given in-order index.
    public static func controlBlock(internalKey: Data, tree: Tree, leafIndex: Int) throws -> ControlBlock {
        let blocks = try controlBlocks(internalKey: internalKey, tree: tree)
        guard leafIndex >= 0, leafIndex < blocks.count else { throw TaprootError.leafNotFound }
        return blocks[leafIndex]
    }

    /// Verifies a control block against a merkle root by walking the path bottom-up
    /// with sorted TapBranch hashing (BIP341 script-path validation).
    public static func verify(controlBlock: ControlBlock, script: Script, merkleRoot: Data) -> Bool {
        var hash = leafHash(version: controlBlock.leafVersion, script: script)
        for sibling in controlBlock.path { hash = branchHash(hash, sibling) }
        return hash == merkleRoot
    }

    /// BIP341 taproot_tree_helper: returns the root hash and, for every leaf
    /// (in-order), its version, script, and bottom-up sibling path.
    private static func hashes(of tree: Tree)
        -> (root: Data, leaves: [(version: UInt8, script: Script, path: [Data])])
    {
        switch tree {
        case let .leaf(version, script):
            return (leafHash(version: version, script: script), [(version, script, [])])
        case let .branch(left, right):
            let l = hashes(of: left)
            let r = hashes(of: right)
            let leaves = l.leaves.map { ($0.version, $0.script, $0.path + [r.root]) }
                + r.leaves.map { ($0.version, $0.script, $0.path + [l.root]) }
            return (branchHash(l.root, r.root), leaves)
        }
    }

    static func appendCompactSize(_ value: Int, to data: inout Data) {
        switch value {
        case ..<0xFD:
            data.append(UInt8(value))
        case ...0xFFFF:
            data.append(0xFD)
            withUnsafeBytes(of: UInt16(value).littleEndian) { data.append(contentsOf: $0) }
        case ...0xFFFF_FFFF:
            data.append(0xFE)
            withUnsafeBytes(of: UInt32(value).littleEndian) { data.append(contentsOf: $0) }
        default:
            data.append(0xFF)
            withUnsafeBytes(of: UInt64(value).littleEndian) { data.append(contentsOf: $0) }
        }
    }

    /// A provably unspendable "Nothing Up My Sleeve" internal key: the BIP341
    /// example NUMS point H = lift_x(SHA256(uncompressed SEC encoding of G)),
    /// 0x50929b74…ace803ac0 (the same construction as the secp256k1-zkp
    /// rangeproof H and Bitcoin Core's taproot tests). Its discrete log is
    /// unknown, so no party can key-path spend a tr(H, TREE) output — spending
    /// is only possible through the script tree. Used as the internal key of
    /// k-of-n vault descriptors.
    public static let unspendableInternalKey: Data = {
        // G in uncompressed SEC form (secret 1), hashed to derive the x coordinate.
        let generator = try! P256K.Signing.PrivateKey(
            dataRepresentation: Data(repeating: 0, count: 31) + Data([0x01]),
            format: .uncompressed)
        let x = Data(SHA256.hash(data: generator.publicKey.dataRepresentation))
        // lift_x must succeed (the BIP341 example point is on the curve).
        _ = P256K.Schnorr.XonlyKey(dataRepresentation: x)
        return x
    }()
}
