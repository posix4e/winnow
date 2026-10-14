import CryptoKit
import Foundation

/// RIPEMD-160, needed for HASH160 (BIP32 fingerprints, legacy script hashes).
/// Reference: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
public enum RIPEMD160 {
    private static let r1: [Int] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ]
    private static let r2: [Int] = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ]
    private static let s1: [Int] = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    ]
    private static let s2: [Int] = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    ]

    private static func f(_ j: Int, _ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
        switch j / 16 {
        case 0: x ^ y ^ z
        case 1: (x & y) | (~x & z)
        case 2: (x | ~y) ^ z
        case 3: (x & z) | (y & ~z)
        default: x ^ (y | ~z)
        }
    }

    public static func hash(_ data: Data) -> Data {
        var message = [UInt8](data)
        let bitLength = UInt64(message.count) * 8
        message.append(0x80)
        while message.count % 64 != 56 { message.append(0) }
        withUnsafeBytes(of: bitLength.littleEndian) { message.append(contentsOf: $0) }

        var h0: UInt32 = 0x6745_2301
        var h1: UInt32 = 0xEFCD_AB89
        var h2: UInt32 = 0x98BA_DCFE
        var h3: UInt32 = 0x1032_5476
        var h4: UInt32 = 0xC3D2_E1F0

        let k1: [UInt32] = [0x0000_0000, 0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xA953_FD4E]
        let k2: [UInt32] = [0x50A2_8BE6, 0x5C4D_D124, 0x6D70_3EF3, 0x7A6D_76E9, 0x0000_0000]

        for blockStart in stride(from: 0, to: message.count, by: 64) {
            var words = [UInt32](repeating: 0, count: 16)
            for i in 0 ..< 16 {
                let o = blockStart + i * 4
                words[i] = UInt32(message[o]) | UInt32(message[o + 1]) << 8 |
                    UInt32(message[o + 2]) << 16 | UInt32(message[o + 3]) << 24
            }

            var (al, bl, cl, dl, el) = (h0, h1, h2, h3, h4)
            var (ar, br, cr, dr, er) = (h0, h1, h2, h3, h4)

            for j in 0 ..< 80 {
                let tl = al &+ f(j, bl, cl, dl) &+ words[r1[j]] &+ k1[j / 16]
                let rotatedL = tl.rotatedLeft(by: s1[j])
                (al, bl, cl, dl, el) = (el, rotatedL &+ el, bl, cl.rotatedLeft(by: 10), dl)

                let tr = ar &+ f(79 - j, br, cr, dr) &+ words[r2[j]] &+ k2[j / 16]
                let rotatedR = tr.rotatedLeft(by: s2[j])
                (ar, br, cr, dr, er) = (er, rotatedR &+ er, br, cr.rotatedLeft(by: 10), dr)
            }

            let t = h1 &+ cl &+ dr
            h1 = h2 &+ dl &+ er
            h2 = h3 &+ el &+ ar
            h3 = h4 &+ al &+ br
            h4 = h0 &+ bl &+ cr
            h0 = t
        }

        var digest = Data()
        for h in [h0, h1, h2, h3, h4] {
            withUnsafeBytes(of: h.littleEndian) { digest.append(contentsOf: $0) }
        }
        return digest
    }
}

extension UInt32 {
    @inline(__always)
    func rotatedLeft(by bits: Int) -> UInt32 {
        (self << bits) | (self >> (32 - bits))
    }
}

public enum Hash160 {
    public static func hash(_ data: Data) -> Data {
        RIPEMD160.hash(Data(SHA256.hash(data: data)))
    }
}
