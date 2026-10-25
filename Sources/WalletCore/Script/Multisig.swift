import Foundation

public enum MultisigError: Error, Equatable {
    case invalidThreshold
    case tooManyKeys
    case invalidKey
    case invalidTimelock
}

/// A script-path leaf this wallet can sign and finalize: any `threshold` of
/// these x-only keys, optionally only once the coin is `relativeLock` blocks
/// old (BIP68/BIP112 `OP_CHECKSEQUENCEVERIFY`).
public struct LeafPolicy: Equatable, Sendable {
    public var threshold: Int
    /// In script order, which is the order signatures follow in the witness.
    public var keys: [Data]
    public var relativeLock: UInt32?

    public init(threshold: Int, keys: [Data], relativeLock: UInt32?) {
        self.threshold = threshold
        self.keys = keys
        self.relativeLock = relativeLock
    }
}

/// BIP387 `multi_a` / `sortedmulti_a` k-of-n tapscript multisig via
/// OP_CHECKSIGADD, and the two timelocked miniscript leaves a recovery path
/// uses: `and_v(v:pk(K),older(N))` and `and_v(v:multi_a(k,…),older(N))`.
public enum Multisig {
    /// Maximum number of keys in a `multi_a`/`sortedmulti_a` expression (BIP387).
    public static let maxKeys = 999

    /// Builds the k-of-n multisig tapscript from 32-byte x-only public keys:
    /// `<KEY_1> OP_CHECKSIG <KEY_2> OP_CHECKSIGADD ... <KEY_n> OP_CHECKSIGADD OP_k OP_NUMEQUAL`
    /// (for k <= 16; a minimally-encoded `k` push for k > 16).
    /// When `sorted` is set (`sortedmulti_a`), keys are sorted lexicographically first.
    public static func script(threshold k: Int, xonlyKeys keys: [Data], sorted: Bool) throws -> Script {
        let ordered = try checkedKeys(threshold: k, keys: keys, sorted: sorted)
        return Script.build { script in
            appendKeys(ordered, to: &script)
            script.appendScriptNumber(k)
            script.appendOpcode(Script.Op.numEqual)
        }
    }

    /// `and_v(v:multi_a(k,…),older(N))`: the multi_a script with
    /// OP_NUMEQUALVERIFY, then `<N> OP_CHECKSEQUENCEVERIFY`.
    public static func timelockedScript(threshold k: Int, xonlyKeys keys: [Data], blocks: UInt32) throws -> Script {
        let ordered = try checkedKeys(threshold: k, keys: keys, sorted: false)
        try checkLock(blocks)
        return Script.build { script in
            appendKeys(ordered, to: &script)
            script.appendScriptNumber(k)
            script.appendOpcode(Script.Op.numEqualVerify)
            script.appendScriptNumber(Int(blocks))
            script.appendOpcode(Script.Op.checkSequenceVerify)
        }
    }

    /// `and_v(v:pk(K),older(N))`: `<K> OP_CHECKSIGVERIFY <N> OP_CHECKSEQUENCEVERIFY`.
    public static func timelockedScript(xonlyKey key: Data, blocks: UInt32) throws -> Script {
        guard key.count == 32 else { throw MultisigError.invalidKey }
        try checkLock(blocks)
        return Script.build { script in
            script.appendPush(key)
            script.appendOpcode(Script.Op.checkSigVerify)
            script.appendScriptNumber(Int(blocks))
            script.appendOpcode(Script.Op.checkSequenceVerify)
        }
    }

    /// Miniscript's `older(N)` range: 1 to 2^31 − 1.
    private static func checkLock(_ blocks: UInt32) throws {
        guard blocks >= 1, blocks < 0x8000_0000 else { throw MultisigError.invalidTimelock }
    }

    private static func checkedKeys(threshold k: Int, keys: [Data], sorted: Bool) throws -> [Data] {
        guard k >= 1, k <= keys.count else { throw MultisigError.invalidThreshold }
        guard keys.count <= maxKeys else { throw MultisigError.tooManyKeys }
        guard keys.allSatisfy({ $0.count == 32 }) else { throw MultisigError.invalidKey }
        return sorted ? keys.sorted(by: { $0.lexicographicallyPrecedes($1) }) : keys
    }

    private static func appendKeys(_ keys: [Data], to script: inout Script) {
        for (index, key) in keys.enumerated() {
            script.appendPush(key)
            script.appendOpcode(index == 0 ? Script.Op.checkSig : Script.Op.checkSigAdd)
        }
    }

    /// Parses a `multi_a`/`sortedmulti_a` tapscript back into its threshold
    /// and x-only keys **in script order**; nil for any other script,
    /// timelocked leaves included.
    public static func parse(_ script: Script) -> (threshold: Int, keys: [Data])? {
        guard let policy = parsePolicy(script), policy.relativeLock == nil else { return nil }
        return (policy.threshold, policy.keys)
    }

    /// Parses any leaf shape this module builds, in exactly the canonical
    /// form it emits: `multi_a` (`… OP_k OP_NUMEQUAL`), timelocked `multi_a`
    /// (`… OP_k OP_NUMEQUALVERIFY <N> OP_CHECKSEQUENCEVERIFY`) and
    /// timelocked `pk` (`<K> OP_CHECKSIGVERIFY <N> OP_CHECKSEQUENCEVERIFY`).
    public static func parsePolicy(_ script: Script) -> LeafPolicy? {
        let bytes = Array(script.bytes)
        if bytes.count >= 34, bytes[0] == 0x20, bytes[33] == Script.Op.checkSigVerify {
            guard let (blocks, end) = scriptNumber(bytes, at: 34), end + 1 == bytes.count,
                  bytes[end] == Script.Op.checkSequenceVerify, blocks >= 1, blocks < 0x8000_0000 else { return nil }
            return LeafPolicy(threshold: 1, keys: [Data(bytes[1 ..< 33])], relativeLock: UInt32(blocks))
        }
        var keys: [Data] = []
        var offset = 0
        while offset + 34 <= bytes.count, bytes[offset] == 0x20 {
            let expected: UInt8 = keys.isEmpty ? Script.Op.checkSig : Script.Op.checkSigAdd
            guard bytes[offset + 33] == expected, keys.count < maxKeys else { return nil }
            keys.append(Data(bytes[offset + 1 ..< offset + 33]))
            offset += 34
        }
        guard !keys.isEmpty, let (threshold, afterThreshold) = scriptNumber(bytes, at: offset),
              threshold >= 1, threshold <= keys.count, afterThreshold < bytes.count else { return nil }
        switch bytes[afterThreshold] {
        case Script.Op.numEqual:
            guard afterThreshold + 1 == bytes.count else { return nil }
            return LeafPolicy(threshold: threshold, keys: keys, relativeLock: nil)
        case Script.Op.numEqualVerify:
            guard let (blocks, end) = scriptNumber(bytes, at: afterThreshold + 1), end + 1 == bytes.count,
                  bytes[end] == Script.Op.checkSequenceVerify, blocks >= 1, blocks < 0x8000_0000 else { return nil }
            return LeafPolicy(threshold: threshold, keys: keys, relativeLock: UInt32(blocks))
        default:
            return nil
        }
    }

    /// A positive, minimally encoded script number at `offset`: OP_1…OP_16
    /// or a push of at most five bytes. Returns the value and the offset just
    /// past it.
    static func scriptNumber(_ bytes: [UInt8], at offset: Int) -> (value: Int, end: Int)? {
        guard offset < bytes.count else { return nil }
        let head = bytes[offset]
        if (0x51 ... 0x60).contains(head) { return (Int(head - 0x50), offset + 1) }
        let length = Int(head)
        guard (1 ... 5).contains(length), offset + 1 + length <= bytes.count else { return nil }
        let number = bytes[(offset + 1) ..< (offset + 1 + length)]
        let top = number.last!
        guard top & 0x80 == 0 else { return nil } // negative
        if top == 0 {
            // A trailing zero is only minimal when it carries the sign bit.
            guard length > 1, number[number.endIndex - 2] & 0x80 != 0 else { return nil }
        }
        let value = number.reversed().reduce(0) { $0 << 8 | Int($1) }
        // OP_N covers 1…16; a push of those is not minimal.
        guard value > 16 else { return nil }
        return (value, offset + 1 + length)
    }
}

/// BIP68/BIP112 relative timelocks, block-based only.
public enum RelativeLock {
    /// Whether an input with `sequence`, in a transaction of `txVersion`,
    /// satisfies `<blocks> OP_CHECKSEQUENCEVERIFY`.
    public static func isSatisfied(blocks: UInt32, sequence: UInt32, txVersion: Int32) -> Bool {
        let disable: UInt32 = 1 << 31
        let typeFlag: UInt32 = 1 << 22
        guard blocks & disable == 0, blocks & typeFlag == 0 else { return false }
        guard txVersion >= 2, sequence & disable == 0, sequence & typeFlag == 0 else { return false }
        return sequence & 0xFFFF >= blocks & 0xFFFF
    }
}
