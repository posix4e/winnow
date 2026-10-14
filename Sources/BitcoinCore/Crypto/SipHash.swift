import Foundation

/// SipHash-2-4 over arbitrary byte strings, as used by BIP158 (c=2, d=4 rounds).
public enum SipHash {
    public static func hash(k0: UInt64, k1: UInt64, _ data: Data) -> UInt64 {
        var v0: UInt64 = 0x736F_6D65_7073_6575 ^ k0
        var v1: UInt64 = 0x646F_7261_6E64_6F6D ^ k1
        var v2: UInt64 = 0x6C79_6765_6E65_7261 ^ k0
        var v3: UInt64 = 0x7465_6462_7974_6573 ^ k1

        func round() {
            v0 = v0 &+ v1
            v1 = v1.rotatedLeft(by: 13)
            v1 ^= v0
            v0 = v0.rotatedLeft(by: 32)
            v2 = v2 &+ v3
            v3 = v3.rotatedLeft(by: 16)
            v3 ^= v2
            v0 = v0 &+ v3
            v3 = v3.rotatedLeft(by: 21)
            v3 ^= v0
            v2 = v2 &+ v1
            v1 = v1.rotatedLeft(by: 17)
            v1 ^= v2
            v2 = v2.rotatedLeft(by: 32)
        }

        data.withUnsafeBytes { buffer in
            var offset = 0
            while offset + 8 <= data.count {
                let m = buffer.loadUnaligned(fromByteOffset: offset, as: UInt64.self).littleEndian
                v3 ^= m
                round()
                round()
                v0 ^= m
                offset += 8
            }
            var last = UInt64(data.count & 0xFF) << 56
            for i in offset ..< data.count {
                last |= UInt64(buffer[i]) << UInt64(8 * (i - offset))
            }
            v3 ^= last
            round()
            round()
            v0 ^= last
        }

        v2 ^= 0xFF
        round()
        round()
        round()
        round()
        return v0 ^ v1 ^ v2 ^ v3
    }
}

extension UInt64 {
    @inline(__always)
    func rotatedLeft(by bits: Int) -> Self {
        (self << bits) | (self >> (64 - bits))
    }
}
