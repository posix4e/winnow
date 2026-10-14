import Foundation
import Testing
@testable import BitcoinCore
@testable import WalletCore

@Suite("Crypto primitives")
struct CryptoTests {
    @Test("RIPEMD-160 known vectors")
    func ripemd160() {
        #expect(RIPEMD160.hash(Data()).hex == "9c1185a5c5e9fc54612808977ee8f548b2258d31")
        #expect(RIPEMD160.hash(Data("abc".utf8)).hex == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
        #expect(RIPEMD160.hash(Data("message digest".utf8)).hex == "5d0689ef49d2fae572b881b123a85ffa21595f36")
    }

    // Known answers computed independently with Python hashlib's BIP340 construction.
    @Test("tagged hash preserves empty, binary and UTF-8 inputs", arguments: [
        ("", "", "2dba5dbc339e7316aea2683faf839c1b7b1ee2313db792112588118df066aa35"),
        ("TapTweak", String(repeating: "00", count: 32),
         "38acfd2d72ad71541503bf9521485ed40eb70ad40dd562d29677a32c917d8e61"),
        ("MuSig/nonce", (0...64).map { String(format: "%02x", $0) }.joined(),
         "7baf6ab044a50a6521f6fcba131f9a4aadd6edf92b20d2ff465fe49f7d8626c7"),
        ("tag\u{0000}é", "00ff0080", "993e2a8afb22675b3d03fc2de430ff2addd8757b0152b47e4de8d3fc9ceeb88f"),
    ])
    func taggedHash(tag: String, messageHex: String, expected: String) throws {
        let message = try #require(messageHex.isEmpty ? Data() : Data(hex: messageHex))
        #expect(TaggedHash.hash(tag, message).hex == expected)
    }

    @Test("Base58Check round-trip preserves leading zeros")
    func base58() throws {
        let payload = Data([0, 0, 1, 2, 3, 254, 255])
        let encoded = Base58Check.encode(payload)
        #expect(encoded.hasPrefix("11"))
        #expect(try Base58Check.decode(encoded) == payload)
        #expect(throws: Base58Error.invalidChecksum) {
            _ = try Base58Check.decode(String(encoded.dropLast(1)) + (encoded.hasSuffix("1") ? "2" : "1"))
        }
    }
}
