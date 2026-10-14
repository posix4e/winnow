import Foundation
import Testing
import TestSupport
@testable import BitcoinCore
@testable import WalletCore

/// Descriptor engine round-trips (parse/serialize with recomputed checksum),
/// BIP389 multipath expansion, and a BIP388 policy-expanded descriptor sanity check.
@Suite("Descriptor engine")
struct DescriptorTests {
    /// Representative set: plain, tree, nested tree, wildcards, hardened steps,
    /// origins, musig, multipath.
    static let representatives = [
        "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        "tr(0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,pk(669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0))",
        "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{pk(669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0),{multi_a(2,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd),sortedmulti_a(1,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)}})",
        "tr([deadbeef/86'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*)",
        "tr(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/<0;1>/*,{pk(xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0/*),multi_a(2,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/*,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0/0/*)})",
        "rawtr(musig(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9,03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659,023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66))",
        "tr(musig(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y)/0/*)",
        "tr(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,multi_a(1,KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy))",
    ]

    @Test("parse(serialize(x)) == x, with a recomputed valid checksum")
    func roundTrip() throws {
        for text in Self.representatives {
            let descriptor = try Descriptor(text)
            let serialized = descriptor.serialized()
            let checksum = try #require(serialized.split(separator: "#").last)
            #expect(DescriptorChecksum.verify(body: String(serialized.dropLast(9)), checksum: String(checksum)))
            #expect(try Descriptor(serialized) == descriptor, Comment(rawValue: text))
        }
    }

    @Test("hardened markers normalize to ' on serialization")
    func hardenedNormalization() throws {
        let descriptor = try Descriptor("tr([deadbeef/0h/1h]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/3h/4h/5h/*h)")
        #expect(descriptor.serialized().hasPrefix("tr([deadbeef/0'/1']"))
        #expect(descriptor.serialized().contains("/3'/4'/5'/*'"))
    }

    @Test("BIP389 multipath expands to one output per choice")
    func multipath() throws {
        let text = "tr([73c5da0a/86'/0'/0']xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/<0;1>/*)"
        let descriptor = try Descriptor(text)
        #expect(descriptor.isRanged)
        let outputs = try descriptor.derived(index: 0)
        #expect(outputs.count == 2)
        #expect(outputs[0].scriptPubKey != outputs[1].scriptPubKey)

        // Choice 0 (receive) equals the BIP86 first address for this account key.
        #expect(outputs[0].address == TestScripts.bip86FirstMainnetAddress)

        // Mismatched multipath widths are invalid (BIP389).
        let mismatched = "tr(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/<0;1>/*,{pk(xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/<0;1;2>/*)})"
        #expect((try? Descriptor(mismatched)) == nil)

        // One multipath element per key expression (BIP389). A second one
        // used to parse and then trap on derivation, because the choice count
        // comes from the first element and indexed the narrower second.
        let doubled = "tr(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/<0;1;2>/<0;1>/*)"
        #expect(throws: DescriptorError.invalidPath) { _ = try Descriptor(doubled) }
    }

    @Test("BIP388 sortedmulti_a policy descriptor parses, derives, round-trips")
    func bip388PolicyDescriptor() throws {
        let text = try Vectors.string("bip-0388.mediawiki", in: .module)
        // The "Taproot wallet policy with sortedmulti_a and a miniscript leaf" example's
        // expanded Descriptor line (a tr() with sortedmulti_a and multipath keys).
        var descriptorText: String?
        for line in text.components(separatedBy: .newlines) where line.hasPrefix(" Descriptor: tr(") {
            if line.contains("sortedmulti_a") { descriptorText = String(line.dropFirst(13)) }
        }
        let text2 = try #require(descriptorText)
        // The miniscript leaf (or_b(...)) is outside the supported subset; replace it
        // with an equivalent pk() leaf for the engine sanity check.
        let simplified = text2.replacingOccurrences(
            of: "or_b(pk(xpub6GxHB9kRdFfTqYka8tgtX9Gh3Td3A9XS8uakUGVcJ9NGZ1uLrGZrRVr67DjpMNCHprZmVmceFTY4X4wWfksy8nVwPiNvzJ5pjLxzPtpnfEM/<0;1>/*),s:pk(xpub6GjFUVVYewLj5no5uoNKCWuyWhQ1rKGvV8DgXBG9Uc6DvAKxt2dhrj1EZFrTNB5qxAoBkVW3wF8uCS3q1ri9fueAa6y7heFTcf27Q4gyeh6/<0;1>/*))",
            with: "pk(xpub6GxHB9kRdFfTqYka8tgtX9Gh3Td3A9XS8uakUGVcJ9NGZ1uLrGZrRVr67DjpMNCHprZmVmceFTY4X4wWfksy8nVwPiNvzJ5pjLxzPtpnfEM/<0;1>/*)")
        #expect(simplified != text2)
        let descriptor = try Descriptor(simplified)
        #expect(descriptor.isRanged)
        let outputs = try descriptor.derived(index: 5)
        #expect(outputs.count == 2)
        #expect(outputs[0].address.hasPrefix("bc1p"))
        #expect(try Descriptor(descriptor.serialized()) == descriptor)
    }
}
