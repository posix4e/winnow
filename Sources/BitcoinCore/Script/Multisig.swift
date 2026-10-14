import Foundation

public enum MultisigError: Error, Equatable {
    case invalidThreshold
    case tooManyKeys
    case invalidKey
}

/// BIP387 `multi_a` / `sortedmulti_a` k-of-n tapscript multisig construction
/// via OP_CHECKSIGADD.
public enum Multisig {
    /// Maximum number of keys in a `multi_a`/`sortedmulti_a` expression (BIP387).
    public static let maxKeys = 999

    /// Builds the k-of-n multisig tapscript from 32-byte x-only public keys:
    /// `<KEY_1> OP_CHECKSIG <KEY_2> OP_CHECKSIGADD ... <KEY_n> OP_CHECKSIGADD OP_k OP_NUMEQUAL`
    /// (for k <= 16; a minimally-encoded `k` push for k > 16).
    /// When `sorted` is set (`sortedmulti_a`), keys are sorted lexicographically first.
    public static func script(threshold k: Int, xonlyKeys keys: [Data], sorted: Bool) throws -> Script {
        guard k >= 1, k <= keys.count else { throw MultisigError.invalidThreshold }
        guard keys.count <= maxKeys else { throw MultisigError.tooManyKeys }
        guard keys.allSatisfy({ $0.count == 32 }) else { throw MultisigError.invalidKey }
        let ordered = sorted ? keys.sorted(by: { $0.lexicographicallyPrecedes($1) }) : keys
        return Script.build { script in
            for (index, key) in ordered.enumerated() {
                script.appendPush(key)
                script.appendOpcode(index == 0 ? Script.Op.checkSig : Script.Op.checkSigAdd)
            }
            script.appendScriptNumber(k)
            script.appendOpcode(Script.Op.numEqual)
        }
    }

    /// Parses a `multi_a`/`sortedmulti_a` tapscript back into its threshold
    /// and x-only keys **in script order** (the order signatures must follow
    /// when building the BIP387 witness stack). Returns nil for scripts that
    /// don't match the exact canonical shape this builder emits:
    /// `<KEY_1> OP_CHECKSIG <KEY_i> OP_CHECKSIGADD… OP_k OP_NUMEQUAL`.
    public static func parse(_ script: Script) -> (threshold: Int, keys: [Data])? {
        var bytes = script.bytes
        var keys: [Data] = []
        while !bytes.isEmpty {
            guard bytes.first == 0x20, bytes.count >= 34 else { return nil } // 32-byte key push
            keys.append(bytes.subdata(in: bytes.startIndex + 1 ..< bytes.startIndex + 33))
            let opcode = bytes[bytes.startIndex + 33]
            let expected: UInt8 = keys.count == 1 ? Script.Op.checkSig : Script.Op.checkSigAdd
            guard opcode == expected else { return nil }
            bytes = bytes.subdata(in: bytes.startIndex + 34 ..< bytes.endIndex)
            if keys.count > maxKeys { return nil }
            // The threshold + OP_NUMEQUAL trailer follows the last key push.
            if let rest = parseTrailer(bytes) { return (rest, keys) }
        }
        return nil
    }

    /// Parses the `<k> OP_NUMEQUAL` trailer, consuming nothing on failure.
    private static func parseTrailer(_ bytes: Data) -> Int? {
        guard bytes.count >= 2, bytes.last == Script.Op.numEqual else { return nil }
        let head = bytes[bytes.startIndex]
        switch head {
        case 0x51 ... 0x60: // OP_1...OP_16 (k = 0 is invalid for multi_a, BIP387)
            return bytes.count == 2 ? Int(head - 0x50) : nil
        default:
            // k > 16: minimally-encoded script number push.
            let length = Int(head)
            guard length >= 1, bytes.count == 2 + length else { return nil }
            var value = 0
            for index in 0 ..< length {
                value |= Int(bytes[bytes.startIndex + 1 + index]) << (8 * index)
            }
            // Minimal encoding: no trailing zero byte unless the sign bit needs it.
            let top = bytes[bytes.startIndex + length]
            if top == 0, length > 1, bytes[bytes.startIndex + length - 1] & 0x80 == 0 { return nil }
            guard top & 0x80 == 0 else { return nil } // negative
            return value
        }
    }
}
