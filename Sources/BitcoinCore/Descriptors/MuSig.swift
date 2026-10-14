import Foundation
import P256K

public enum MuSigError: Error, Equatable {
    case invalidPublicKey
    case aggregationFailed
}

/// BIP327 MuSig2 key aggregation over plain (33-byte compressed) public keys,
/// as required by the BIP390 `musig()` key expression. This implementation uses
/// P256K's public point operations (`multiply` / `combine`). The pinned
/// dependency also provides MuSig APIs through its enabled-by-default trait.
public enum MuSig {
    /// secp256k1 curve order n.
    static let groupOrder = Data([
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ])

    /// BIP328 fixed chaincode for synthetic xpubs: SHA256("MuSig2MuSig2MuSig2").
    public static let aggregateChainCode = Data([
        0x86, 0x80, 0x87, 0xCA, 0x02, 0xA6, 0xF9, 0x74, 0xC4, 0x59, 0x89, 0x24, 0xC3, 0x6B, 0x57, 0x76,
        0x2D, 0x32, 0xCB, 0x45, 0x71, 0x71, 0x67, 0xE3, 0x00, 0x62, 0x2C, 0x71, 0x67, 0xE3, 0x89, 0x65,
    ])

    /// BIP327 KeySort: lexicographic order of the compressed public key bytes.
    public static func keySort(_ publicKeys: [Data]) -> [Data] {
        publicKeys.sorted(by: { $0.lexicographicallyPrecedes($1) })
    }

    /// BIP327 KeyAgg: Q = sum(a_i * P_i) over full points with their given parity.
    /// The coefficient of the second distinct key is 1; all others are
    /// H("KeyAgg coefficient", L || P_i) mod n with L = H("KeyAgg list", P_1 || ... || P_n).
    /// Keys must be 33-byte compressed public keys. Returns the compressed aggregate key.
    public static func aggregate(_ publicKeys: [Data]) throws -> Data {
        guard !publicKeys.isEmpty,
              publicKeys.allSatisfy({ $0.count == 33 && ($0.first == 0x02 || $0.first == 0x03) })
        else { throw MuSigError.invalidPublicKey }

        let listHash = TaggedHash.hash("KeyAgg list", publicKeys.reduce(Data(), +))
        // Coefficient 1 for the second distinct key (BIP327); no exception when
        // all keys are identical (every coefficient is then a hash).
        var secondKey: Data?
        for key in publicKeys.dropFirst() where key != publicKeys[0] {
            secondKey = key
            break
        }

        var points: [P256K.Signing.PublicKey] = []
        points.reserveCapacity(publicKeys.count)
        for key in publicKeys {
            guard let point = try? P256K.Signing.PublicKey(dataRepresentation: key, format: .compressed) else {
                throw MuSigError.invalidPublicKey
            }
            if let secondKey, key == secondKey {
                points.append(point)
            } else {
                let coefficient = reduceModGroupOrder(TaggedHash.hash("KeyAgg coefficient", listHash + key))
                guard let scaled = try? point.multiply(coefficient) else {
                    throw MuSigError.aggregationFailed
                }
                points.append(scaled)
            }
        }
        guard let aggregate = try? points[0].combine(Array(points.dropFirst()), format: .compressed) else {
            throw MuSigError.aggregationFailed
        }
        return aggregate.dataRepresentation
    }

    /// The 32-byte x-only form of the aggregate key.
    public static func aggregateXonly(_ publicKeys: [Data]) throws -> Data {
        Data(try aggregate(publicKeys).dropFirst())
    }

    /// BIP328 synthetic extended public key for BIP32 derivation from an
    /// aggregate public key: depth 0, fixed chaincode, compressed aggregate key.
    public static func syntheticExtendedKey(aggregatePublicKey: Data) throws -> HDKey {
        guard aggregatePublicKey.count == 33 else { throw MuSigError.invalidPublicKey }
        return HDKey(depth: 0, parentFingerprint: 0, childIndex: 0,
                     chainCode: aggregateChainCode, privateKey: nil, publicKey: aggregatePublicKey)
    }

    /// Reduces a 32-byte hash modulo the group order. Since the input is below
    /// 2^256 < 2n, a single conditional subtraction suffices.
    static func reduceModGroupOrder(_ hash: Data) -> [UInt8] {
        var value = [UInt8](hash)
        let order = [UInt8](groupOrder)
        if !value.lexicographicallyPrecedes(order) { // lexicographic compare of equal-length big-endian bytes
            var borrow = 0
            for i in stride(from: 31, through: 0, by: -1) {
                let diff = Int(value[i]) - Int(order[i]) - borrow
                value[i] = UInt8(truncatingIfNeeded: diff)
                borrow = diff < 0 ? 1 : 0
            }
        }
        return value
    }
}
