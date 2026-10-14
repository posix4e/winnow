import CryptoKit
import Foundation

/// SHA256d — the double-SHA256 used for P2P checksums, txids and block hashes.
package enum SHA256d {
    package static func hash(_ data: Data) -> Data {
        Data(SHA256.hash(data: Data(SHA256.hash(data: data))))
    }
}
