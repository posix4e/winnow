import Foundation
import Testing
import TestSupport
@testable import BitcoinCore
@testable import WalletCore

/// BIP39 vectors from trezor/python-mnemonic (passphrase "TREZOR").
@Suite("BIP39")
struct BIP39Tests {
    struct Vector {
        let entropy: Data
        let mnemonic: String
        let seed: Data
        let xprv: String
    }

    static func vectors(language: String) throws -> [Vector] {
        let json = try Vectors.decode([String: [[String]]].self, "bip39-vectors.json", in: .module)
        return try json[language]!.map { entry in
            guard let entropy = Data(hex: entry[0]), let seed = Data(hex: entry[2]) else {
                throw VectorError.badHex(entry[0])
            }
            return Vector(entropy: entropy, mnemonic: entry[1], seed: seed, xprv: entry[3])
        }
    }

    @Test("entropy -> mnemonic")
    func entropyToMnemonic() throws {
        for vector in try Self.vectors(language: "english") {
            #expect(try BIP39.mnemonic(entropy: vector.entropy) == vector.mnemonic)
        }
    }

    @Test("mnemonic validation accepts all vectors")
    func validate() throws {
        for vector in try Self.vectors(language: "english") {
            try BIP39.validate(mnemonic: vector.mnemonic)
        }
    }

    @Test("mnemonic -> seed")
    func mnemonicToSeed() throws {
        for vector in try Self.vectors(language: "english") {
            let seed = try BIP39.seed(mnemonic: vector.mnemonic, passphrase: "TREZOR")
            #expect(seed == vector.seed)
        }
    }

    /// The Japanese sentences separate words with U+3000 IDEOGRAPHIC SPACE, which only
    /// compatibility decomposition folds to an ordinary space, so these vectors are the
    /// ones that tell NFKD from NFD. Their words are outside the English wordlist, so
    /// only the seed is checked here.
    @Test("mnemonic -> seed, japanese (NFKD, not NFD)")
    func japaneseMnemonicToSeed() throws {
        for vector in try Self.vectors(language: "japanese") {
            let seed = try BIP39.seed(mnemonic: vector.mnemonic, passphrase: "TREZOR")
            #expect(seed == vector.seed)
        }
    }

    /// The passphrase is normalized the same way, and nothing in the vector file covers
    /// it: every language derives its seed under "TREZOR". U+FB01 LATIN SMALL LIGATURE FI
    /// folds to "fi" under NFKD and is left alone by NFD, so the seed below is the one
    /// "office" derives; it was computed outside this package with Python's
    /// `hashlib.pbkdf2_hmac`.
    @Test("passphrase -> seed (NFKD, not NFD)")
    func passphraseNormalization() throws {
        let mnemonic = try Self.vectors(language: "english")[0].mnemonic
        let ligature = try BIP39.seed(mnemonic: mnemonic, passphrase: "of\u{FB01}ce")
        #expect(ligature == Data(hex: "a82f3f4d9297559940ae10ce91e52f9be22afd06444fd7c1d40fdd1204cab43068fefca566d9f9fa714807a55e02dbc13ab4d7b7481305be8d280bf237139c96"))
    }

    @Test("validation and seed derivation agree on compatibility spaces")
    func compatibilitySpaces() throws {
        let vector = try Self.vectors(language: "english")[0]
        let spaced = vector.mnemonic.replacingOccurrences(of: " ", with: "\u{3000}")
        try BIP39.validate(mnemonic: spaced)
        #expect(try BIP39.seed(mnemonic: spaced, passphrase: "TREZOR") == vector.seed)
        #expect(throws: BIP39Error.invalidWordCount) {
            try BIP39.validate(mnemonic: "\u{3000}" + spaced)
        }
    }

    @Test("seed -> BIP32 master xprv")
    func masterXprv() throws {
        for vector in try Self.vectors(language: "english") {
            let master = try HDKey(seed: vector.seed)
            #expect(master.serialized() == vector.xprv)
        }
    }

    @Test("validation rejects bad checksum and unknown words")
    func rejectsInvalid() throws {
        #expect(throws: BIP39Error.invalidChecksum) {
            try BIP39.validate(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon")
        }
        #expect(throws: BIP39Error.wordNotInWordlist("notaword")) {
            try BIP39.validate(mnemonic: "notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        }
        #expect(throws: BIP39Error.invalidWordCount) {
            try BIP39.validate(mnemonic: "abandon abandon abandon")
        }
        // Separators are exactly one space. `seed` hashes the sentence as
        // written, so a doubled, leading or trailing space that validation
        // forgave would derive a seed no other wallet agrees with.
        let words = Array(repeating: "abandon", count: 11) + ["about"]
        for spaced in [words.joined(separator: " ").replacingOccurrences(of: "abandon abandon", with: "abandon  abandon"),
                       " " + words.joined(separator: " "),
                       words.joined(separator: " ") + " "] {
            #expect(throws: BIP39Error.invalidWordCount) { try BIP39.validate(mnemonic: spaced) }
        }
    }

    @Test("wordlist has 2048 sorted words")
    func wordlistSanity() {
        #expect(BIP39.wordlist.count == 2048)
        #expect(BIP39.wordlist == BIP39.wordlist.sorted())
        #expect(BIP39.wordlist[0] == "abandon")
        #expect(BIP39.wordlist[2047] == "zoo")
    }
}
