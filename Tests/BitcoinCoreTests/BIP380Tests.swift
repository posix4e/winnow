import Foundation
import Testing
import TestSupport
@testable import BitcoinCore
@testable import WalletCore

/// BIP380 checksum and key expression vectors parsed from bip-0380.mediawiki.
@Suite("BIP380 descriptors")
struct BIP380Tests {
    /// Splits at the last '#' exactly like Descriptor.init.
    private static func split(_ string: String) -> (body: String, checksum: String)? {
        guard let separator = string.lastIndex(of: "#") else { return nil }
        return (String(string.prefix(upTo: separator)), String(string.suffix(from: string.index(after: separator))))
    }

    @Test("checksum test cases")
    func checksum() throws {
        let text = try Vectors.string("bip-0380.mediawiki", in: .module)
        var cases: [(label: String, value: String)] = []
        var inSection = false
        for line in text.components(separatedBy: .newlines) {
            if line.hasPrefix("The following tests cover the checksum") { inSection = true; continue }
            if line.hasPrefix("The following tests cover key expressions") { inSection = false }
            guard inSection, line.hasPrefix("* "), let tag = ttTags(in: line).last else { continue }
            let label = String(line.dropFirst(2).prefix { $0 != ":" })
            cases.append((label, tag))
        }
        #expect(cases.count == 8)

        for (label, value) in cases {
            switch label {
            case "Valid checksum":
                let (body, checksum) = try #require(Self.split(value))
                #expect(DescriptorChecksum.verify(body: body, checksum: checksum))
                #expect(DescriptorChecksum.create(body) == checksum)
            case "No checksum":
                #expect(Self.split(value) == nil)
            default:
                // Missing/too long/too short checksums, payload/checksum errors,
                // invalid characters: all must fail verification.
                if let (body, checksum) = Self.split(value), checksum.count == 8 {
                    #expect(!DescriptorChecksum.verify(body: body, checksum: checksum), Comment(rawValue: label))
                }
                // And the full descriptor parser must reject them with a checksum error.
                #expect(throws: DescriptorError.invalidChecksum) { try Descriptor(value) }
            }
        }
    }

    @Test("key expression vectors")
    func keyExpressions() throws {
        let text = try Vectors.string("bip-0380.mediawiki", in: .module)
        var valid: [String] = []
        var invalid: [String] = []
        var section = 0
        for line in text.components(separatedBy: .newlines) {
            if line.hasPrefix("Valid expressions:") { section = 1; continue }
            if line.hasPrefix("Invalid expression:") { section = 2; continue }
            if line.hasPrefix("==Backwards Compatibility==") { section = 0 }
            guard section > 0, line.hasPrefix("* "), let tag = ttTags(in: line).last else { continue }
            if section == 1 { valid.append(tag) } else { invalid.append(tag) }
        }
        #expect(valid.count == 21)
        #expect(invalid.count == 16)

        // Valid key expressions must parse (as tr() internal keys).
        for key in valid {
            #expect(throws: Never.self) { try Descriptor("tr(\(key))") }
        }
        for key in invalid {
            #expect((try? Descriptor("tr(\(key))")) == nil, "accepted: \(key)")
        }
    }
}
