import Foundation
import P256K

/// BIP86 single-key Taproot derivation: m/86'/coin'/account'/change/index.
public enum BIP86 {
    /// Derives the key at m/86'/coinType'/account'/change/index and returns its
    /// 32-byte Taproot internal x-only public key.
    public static func internalKey(from master: HDKey, coinType: UInt32 = 0,
                                   account: UInt32 = 0, change: UInt32 = 0, index: UInt32) throws -> Data {
        let key = try master.derived(path: "m/86'/\(coinType)'/\(account)'/\(change)/\(index)")
        return xonlyPublicKey(of: key)
    }

    /// The account-level extended key at m/86'/coinType'/account'.
    public static func accountKey(from master: HDKey, coinType: UInt32 = 0, account: UInt32 = 0) throws -> HDKey {
        try master.derived(path: "m/86'/\(coinType)'/\(account)'")
    }

    /// 32-byte x-only internal public key of any HD key.
    public static func xonlyPublicKey(of key: HDKey) -> Data {
        Data(key.publicKey.dropFirst())
    }

    /// BIP341 taptweak with no script tree: Q = P + H_taptweak(P)*G.
    public static func tweakedOutputKey(internalKey: Data) throws -> Data {
        let tweak = TaggedHash.hash("TapTweak", internalKey)
        let key = P256K.Schnorr.XonlyKey(dataRepresentation: internalKey)
        return Data(try key.add([UInt8](tweak)).bytes)
    }

    /// Tweaked private key matching `tweakedOutputKey` (key-path spending).
    public static func tweakedPrivateKey(_ secret: Data) throws -> Data {
        let key = try P256K.Schnorr.PrivateKey(dataRepresentation: secret)
        let tweak = TaggedHash.hash("TapTweak", Data(key.xonly.bytes))
        return try key.add([UInt8](tweak)).dataRepresentation
    }

    /// BIP86 address: bech32m, witness v1, program = tweaked output key.
    public static func address(internalKey: Data, hrp: String = "bc") throws -> String {
        try SegwitAddress.encode(hrp: hrp, version: 1, program: tweakedOutputKey(internalKey: internalKey))
    }

    /// P2TR scriptPubKey: OP_1 <32-byte output key>.
    public static func scriptPubKey(internalKey: Data) throws -> Data {
        var script = Data([0x51, 0x20])
        script.append(try tweakedOutputKey(internalKey: internalKey))
        return script
    }
}
