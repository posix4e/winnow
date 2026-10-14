import Foundation
import P256K
import Testing
import TestSupport
@testable import BitcoinCore
@testable import WalletCore

/// BIP341 wallet test vectors (bip341-wallet-test-vectors.json, referenced from
/// bip-0341.mediawiki): merkle root, tweak, tweaked output key, scriptPubKey,
/// address, and control blocks for script trees.
@Suite("BIP341 script trees")
struct BIP341Tests {
    struct Vector {
        let internalPubkey: Data
        let tree: Taproot.Tree?
        let leafVersions: [Int]
        let leafScripts: [Script]
        let leafHashes: [Data]
        let merkleRoot: Data?
        let tweak: Data
        let tweakedPubkey: Data
        let scriptPubKey: Data
        let address: String
        let controlBlocks: [Data]
    }

    static func vectors() throws -> [Vector] {
        let json = try Vectors.json("bip341-wallet-test-vectors.json", in: .module) as! [String: Any]
        return try (json["scriptPubKey"] as! [[String: Any]]).map { entry in
            let given = entry["given"] as! [String: Any]
            let intermediary = entry["intermediary"] as! [String: Any]
            let expected = entry["expected"] as! [String: Any]

            var versions: [Int] = []
            var scripts: [Script] = []
            func buildTree(_ node: Any?) -> Taproot.Tree? {
                guard let node, !(node is NSNull) else { return nil }
                if let leaf = node as? [String: Any] {
                    versions.append(leaf["leafVersion"] as! Int)
                    scripts.append(Script(hex: leaf["script"] as! String)!)
                    return .leaf(version: UInt8(versions.last!), script: scripts.last!)
                }
                let pair = node as! [Any]
                return .branch(buildTree(pair[0])!, buildTree(pair[1])!)
            }
            let tree = buildTree(given["scriptTree"])

            func hex(_ value: String) throws -> Data {
                guard let data = Data(hex: value) else { throw VectorError.badHex(value) }
                return data
            }
            return try Vector(
                internalPubkey: hex(given["internalPubkey"] as! String),
                tree: tree,
                leafVersions: versions,
                leafScripts: scripts,
                leafHashes: (intermediary["leafHashes"] as? [String] ?? []).map { Data(hex: $0)! },
                merkleRoot: (intermediary["merkleRoot"] as? String).flatMap { Data(hex: $0) },
                tweak: hex(intermediary["tweak"] as! String),
                tweakedPubkey: hex(intermediary["tweakedPubkey"] as! String),
                scriptPubKey: hex(expected["scriptPubKey"] as! String),
                address: expected["bip350Address"] as! String,
                controlBlocks: (expected["scriptPathControlBlocks"] as? [String] ?? []).map { Data(hex: $0)! }
            )
        }
    }

    @Test("7 vectors parsed")
    func parsed() throws {
        #expect(try Self.vectors().count == 7)
    }

    @Test("leaf hashes, merkle root, tweak, output key, scriptPubKey, address")
    func outputKeyComputation() throws {
        for vector in try Self.vectors() {
            for (index, script) in vector.leafScripts.enumerated() {
                let hash = Taproot.leafHash(version: UInt8(vector.leafVersions[index]), script: script)
                #expect(hash == vector.leafHashes[index])
            }
            let merkleRoot = vector.tree.map { Taproot.merkleRoot(of: $0) }
            #expect(merkleRoot == vector.merkleRoot)
            #expect(Taproot.tweak(internalKey: vector.internalPubkey, merkleRoot: merkleRoot) == vector.tweak)

            let (outputKey, _) = try Taproot.tweakedOutputKey(internalKey: vector.internalPubkey, merkleRoot: merkleRoot)
            #expect(outputKey == vector.tweakedPubkey)
            #expect(try Taproot.scriptPubKey(internalKey: vector.internalPubkey, merkleRoot: merkleRoot) == vector.scriptPubKey)
            #expect(try SegwitAddress.encode(hrp: "bc", version: 1, program: outputKey) == vector.address)
        }
    }

    @Test("control blocks: serialization, parse round-trip, path verification")
    func controlBlocks() throws {
        for vector in try Self.vectors() {
            guard let tree = vector.tree, let merkleRoot = vector.merkleRoot else { continue }
            let blocks = try Taproot.controlBlocks(internalKey: vector.internalPubkey, tree: tree)
            #expect(blocks.count == vector.controlBlocks.count)
            let (_, parity) = try Taproot.tweakedOutputKey(internalKey: vector.internalPubkey, merkleRoot: merkleRoot)
            for (index, expected) in vector.controlBlocks.enumerated() {
                let block = blocks[index]
                #expect(block.serialized == expected)
                #expect(block.leafVersion == UInt8(vector.leafVersions[index]))
                #expect(block.outputKeyParity == parity)
                #expect(block.internalKey == vector.internalPubkey)

                // Parse round-trip and BIP341 bottom-up path verification.
                let parsed = try Taproot.ControlBlock(serialized: expected)
                #expect(parsed == block)
                #expect(Taproot.verify(controlBlock: parsed, script: vector.leafScripts[index], merkleRoot: merkleRoot))
            }
        }
    }
}

/// The BIP341 "nothing up my sleeve" internal key used for k-of-n vault
/// descriptors: H = lift_x(SHA256(uncompressed G)), the example NUMS point
/// from the BIP (0x50929b74…ace803ac0, the same construction as Bitcoin
/// Core's taproot tests and secp256k1-zkp's rangeproof H).
@Suite("BIP341 NUMS internal key")
struct NUMSKeyTests {
    @Test("matches the BIP341 example point and is x-only liftable")
    func constant() throws {
        let expected = Data(hex: "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")!
        #expect(Taproot.unspendableInternalKey == expected)
        // lift_x succeeds: an x-only key can be formed and taproot-tweaked.
        let key = P256K.Schnorr.XonlyKey(dataRepresentation: expected)
        #expect(!key.parity) // lift_x yields the even-Y point
        _ = try Taproot.tweakedOutputKey(internalKey: expected, merkleRoot: Data(repeating: 0xAB, count: 32))
    }

    @Test("a vault output commits to the NUMS key and a multi_a leaf")
    func vaultConstruction() throws {
        // tr(NUMS, multi_a(2, K1, K2, K3)) — the vault descriptor shape.
        let keys = [Data(hex: "22ca50390e660f601036dd7502bb973bdcd104b5dcb8f2e74de8edc6c292b03a")!,
                    Data(hex: "141481bf1181ed61aa025f1fe708f68cb018c2c9d6eb719ccd94b3f6ff615308")!,
                    Data(hex: "cfc18f02cc004640f2116fdd1f6ca2022e39be25df75e27c80bde842e6b6f938")!]
        let script = try Multisig.script(threshold: 2, xonlyKeys: keys, sorted: false)
        let tree = Taproot.Tree.leaf(script: script)
        let scriptPubKey = try Taproot.scriptPubKey(internalKey: Taproot.unspendableInternalKey,
                                                    merkleRoot: Taproot.merkleRoot(of: tree))
        let control = try Taproot.controlBlock(internalKey: Taproot.unspendableInternalKey,
                                               tree: tree, leafIndex: 0)
        #expect(control.internalKey == Taproot.unspendableInternalKey)
        #expect(control.path.isEmpty) // single-leaf tree
        #expect(Taproot.verify(controlBlock: control, script: script,
                               merkleRoot: Taproot.merkleRoot(of: tree)))
        // The descriptor engine produces the same output for the equivalent text form.
        let descriptor = try Descriptor(
            "tr(\(Taproot.unspendableInternalKey.hex),multi_a(2,\(keys.map(\.hex).joined(separator: ","))))")
        #expect(try descriptor.derived(index: 0).first?.scriptPubKey == scriptPubKey)
    }
}
