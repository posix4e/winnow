import Foundation
import enum P256K.SHA256

/// BIP340 tagged hash, delegated to the pinned secp256k1 implementation.
public enum TaggedHash {
    public static func hash(_ tag: String, _ message: Data) -> Data {
        Data(SHA256.taggedHash(tag: Data(tag.utf8), data: message))
    }
}
