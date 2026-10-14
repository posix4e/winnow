import CryptoKit
import Foundation

public enum BIP39Error: Error, Equatable {
    case invalidEntropyLength
    case invalidWordCount
    case wordNotInWordlist(String)
    case invalidChecksum
}

/// BIP39 mnemonic generation, validation, and seed derivation (English wordlist).
public enum BIP39 {
    public static let wordlist = BIP39Wordlist.english

    /// Entropy (16-32 bytes, multiple of 4) -> mnemonic sentence.
    public static func mnemonic(entropy: Data) throws -> String {
        guard entropy.count >= 16, entropy.count <= 32, entropy.count % 4 == 0 else {
            throw BIP39Error.invalidEntropyLength
        }
        let checksumLength = entropy.count * 8 / 32
        let checksum = Data(SHA256.hash(data: entropy))
        var bits = entropy.flatMap { byte in (0 ..< 8).reversed().map { (byte >> $0) & 1 } }
        let checksumByte = checksum[checksum.startIndex]
        bits += (8 - checksumLength ..< 8).reversed().map { (checksumByte >> $0) & 1 }
        let words = stride(from: 0, to: bits.count, by: 11).map { offset -> String in
            let index = bits[offset ..< offset + 11].reduce(0) { ($0 << 1) | Int($1) }
            return wordlist[index]
        }
        return words.joined(separator: " ")
    }

    /// Validates a mnemonic sentence against the wordlist and its checksum.
    /// Separators after NFKD are exactly one space: `seed` hashes the normalized sentence as
    /// written, so a doubled or leading space that validation forgave would
    /// derive a seed no other wallet agrees with.
    public static func validate(mnemonic: String) throws {
        let words = mnemonic.decomposedStringWithCompatibilityMapping
            .split(separator: " ", omittingEmptySubsequences: false).map(String.init)
        guard [12, 15, 18, 21, 24].contains(words.count) else {
            throw BIP39Error.invalidWordCount
        }
        var bits: [UInt8] = []
        for word in words {
            guard let index = wordlist.firstIndex(of: word) else {
                throw BIP39Error.wordNotInWordlist(word)
            }
            bits += (0 ..< 11).reversed().map { UInt8((index >> $0) & 1) }
        }
        let checksumLength = words.count / 3
        let entropyLength = (bits.count - checksumLength) / 8
        var entropy = Data(repeating: 0, count: entropyLength)
        for i in 0 ..< entropyLength * 8 {
            if bits[i] == 1 { entropy[i / 8] |= 1 << UInt8(7 - (i % 8)) }
        }
        let checksumBits = bits.suffix(checksumLength).reduce(0) { ($0 << 1) | Int($1) }
        let expected = Int(Data(SHA256.hash(data: entropy)).first!) >> (8 - checksumLength)
        guard checksumBits == expected else { throw BIP39Error.invalidChecksum }
    }

    /// Mnemonic -> 64-byte seed via PBKDF2-HMAC-SHA512, salt "mnemonic"+passphrase, 2048 rounds.
    /// BIP39 normalizes both the sentence and the passphrase NFKD. NFD agrees on
    /// ASCII and differs on compatibility characters (U+3000, ligatures, fullwidth
    /// forms), where it would derive a seed no other wallet agrees with.
    public static func seed(mnemonic: String, passphrase: String = "") throws -> Data {
        let password = Data(mnemonic.decomposedStringWithCompatibilityMapping.utf8)
        let salt = Data(("mnemonic" + passphrase).decomposedStringWithCompatibilityMapping.utf8)
        return try PBKDF2.hmacSHA512(password: password, salt: salt)
    }
}
