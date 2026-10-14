import Foundation
import Testing
import TestSupport
@testable import BitcoinCore
@testable import WalletCore

/// BIP350 (and BIP173 segwit address) test vectors parsed from bip-0350.mediawiki.
@Suite("Bech32/BIP350")
struct Bech32Tests {
    /// Extracts the test string from a bullet line: `<tt>x</tt>`, `0xNN + <tt>x</tt>`, or plain.
    private static func extract(_ line: String) -> String? {
        var text = line.trimmingCharacters(in: .whitespaces)
        guard text.hasPrefix("* ") else { return nil }
        text = String(text.dropFirst(2))
        var prefix = ""
        if let hexRange = text.range(of: #"^0x([0-9A-Fa-f]{2}) \+ "#, options: .regularExpression) {
            let hex = text[hexRange].dropFirst(2).prefix(2)
            prefix = String(Unicode.Scalar(UInt8(hex, radix: 16)!))
            text = String(text[hexRange.upperBound...])
        }
        if let tt = text.range(of: "<tt>"), let end = text.range(of: "</tt>") {
            return prefix + String(text[tt.upperBound ..< end.lowerBound])
        }
        return nil
    }

    private static func section(_ name: String, in text: String) throws -> String {
        guard let range = text.range(of: name) else { throw VectorError.malformed("no section \(name)") }
        return String(text[range.upperBound...])
    }

    static func validBech32m() throws -> [String] {
        let text = try section("The following strings are valid Bech32m:", in: Vectors.string("bip-0350.mediawiki", in: .module))
        guard let end = text.range(of: "No string can be simultaneously") else {
            throw VectorError.malformed("valid bech32m list end")
        }
        return text[..<end.lowerBound].components(separatedBy: .newlines).compactMap(extract)
    }

    static func invalidBech32m() throws -> [String] {
        let text = try section("The following string are not valid Bech32m", in: Vectors.string("bip-0350.mediawiki", in: .module))
        guard let end = text.range(of: "===Test vectors for v0-v16") else {
            throw VectorError.malformed("invalid bech32m list end")
        }
        return text[..<end.lowerBound].components(separatedBy: .newlines).compactMap(extract)
    }

    static func validSegwitAddresses() throws -> [(String, String)] {
        let text = try section("The following list gives valid segwit addresses", in: Vectors.string("bip-0350.mediawiki", in: .module))
        guard let end = text.range(of: "The following list gives invalid segwit addresses") else {
            throw VectorError.malformed("valid segwit list end")
        }
        return text[..<end.lowerBound].components(separatedBy: .newlines).compactMap { line in
            let tts = line.components(separatedBy: "<tt>").dropFirst().compactMap { $0.components(separatedBy: "</tt>").first }
            return tts.count == 2 ? (tts[0], tts[1]) : nil
        }
    }

    static func invalidSegwitAddresses() throws -> [String] {
        let text = try section("The following list gives invalid segwit addresses", in: Vectors.string("bip-0350.mediawiki", in: .module))
        guard let end = text.range(of: "==Appendix") else { throw VectorError.malformed("invalid segwit list end") }
        return text[..<end.lowerBound].components(separatedBy: .newlines).compactMap(extract)
    }

    @Test("valid Bech32m strings decode")
    func validBech32mDecode() throws {
        let strings = try Self.validBech32m()
        #expect(strings.count == 7)
        for string in strings {
            let decoded = try Bech32.decode(string)
            #expect(decoded.encoding == .bech32m, "\(string)")
        }
    }

    @Test("invalid Bech32m strings are rejected")
    func invalidBech32mRejected() throws {
        let strings = try Self.invalidBech32m()
        // Reasons in the order of the BIP350 vectors above.
        let errors: [Bech32Error] = [
            .invalidCharacter, .invalidCharacter, .invalidCharacter, .tooLong,
            .missingSeparator, .emptyHRP, .invalidCharacter, .invalidCharacter,
            .invalidChecksum, .invalidCharacter, .invalidCharacter, .invalidChecksum,
            .emptyHRP, .emptyHRP,
        ]
        try #require(strings.count == errors.count)
        for (string, error) in zip(strings, errors) {
            #expect(throws: error, "\(string)") {
                try Bech32.decode(string)
            }
        }
    }

    @Test("valid segwit addresses round-trip to scriptPubKey")
    func segwitAddresses() throws {
        let pairs = try Self.validSegwitAddresses()
        #expect(pairs.count == 8)
        for (address, expectedScript) in pairs {
            let hrp = address.lowercased().hasPrefix("bc") ? "bc" : "tb"
            let (version, program) = try SegwitAddress.decode(address, expectedHRP: hrp)
            var script = Data([version == 0 ? 0x00 : UInt8(0x50 + version), UInt8(program.count)])
            script.append(program)
            #expect(script.hex == expectedScript, "\(address)")

            let reencoded = try SegwitAddress.encode(hrp: hrp, version: version, program: program)
            #expect(reencoded.lowercased() == address.lowercased(), "\(address)")
        }
    }

    @Test("invalid segwit addresses are rejected")
    func invalidSegwitAddressesRejected() throws {
        let strings = try Self.invalidSegwitAddresses()
        let errors: [Bech32Error] = [
            .invalidHRP, .invalidChecksum, .invalidChecksum, .invalidChecksum,
            .invalidChecksum, .invalidChecksum, .invalidCharacter, .invalidWitnessVersion,
            .invalidProgramLength, .invalidProgramLength, .invalidProgramLength,
            .mixedCase, .invalidPadding, .invalidPadding, .invalidWitnessVersion,
        ]
        try #require(strings.count == errors.count)
        for (string, error) in zip(strings, errors) {
            // Check the address on its own network so a prefix mismatch cannot
            // hide a broken checksum, witness version, program length or padding.
            // The tc1 vector must be rejected separately by both Bitcoin networks.
            let hrps = error == .invalidHRP ? ["bc", "tb"] : [String(string.prefix(2)).lowercased()]
            for hrp in hrps {
                #expect(throws: error, "\(string), network \(hrp)") {
                    _ = try SegwitAddress.decode(string, expectedHRP: hrp)
                }
            }
        }
    }

    @Test("BIP86-style taproot address encodes as bech32m")
    func taprootAddressEncoding() throws {
        // From BIP86: output key a60869f0... -> bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr
        let program = Data(hex: "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")!
        let address = try SegwitAddress.encode(hrp: "bc", version: 1, program: program)
        #expect(address == TestScripts.bip86FirstMainnetAddress)
        let decoded = try SegwitAddress.decode(address, expectedHRP: "bc")
        #expect(decoded.version == 1 && decoded.program == program)
    }
}
