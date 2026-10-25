import Foundation
import Testing
import TestSupport
@testable import WalletCore

/// People: the pay-to keys a fresh address is derived from, the cards people
/// exchange, and what a paste turns into. Offline, signet-format fixtures.
@Suite("People")
struct PeopleTests {
    static func masters() throws -> [HDKey] { try TestKeys.masters() }

    static func keyExpression(_ master: HDKey) throws -> String {
        try TestKeys.keyExpression(master: master)
    }

    static func account(_ master: HDKey) throws -> HDKey {
        try master.derived(path: "m/86'/1'/0'")
    }

    // MARK: - Pay-to keys

    @Test("a pay-to key is a single public account key with a receive chain")
    func payToAcceptsAndRefuses() throws {
        let master = try Self.masters()[0]
        let account = try Self.account(master)
        let tpub = account.neutered.serialized(network: .testnet)

        let multipath = try PersonPayTo.descriptor("tr(\(Self.keyExpression(master)))", network: .signet)
        let receiveOnly = try PersonPayTo.descriptor("tr(\(tpub)/0/*)", network: .signet)
        #expect(multipath.derivesFreshAddresses)
        #expect(receiveOnly.derivesFreshAddresses)
        #expect(multipath.text.hasPrefix("tr(") && multipath.text.contains("#"))

        #expect(throws: PersonPayToError.privateKey) {
            _ = try PersonPayTo.descriptor("tr(\(account.serialized(network: .testnet))/<0;1>/*)", network: .signet)
        }
        #expect(throws: PersonPayToError.wrongNetwork(expected: .signet)) {
            _ = try PersonPayTo.descriptor("tr(\(account.neutered.serialized(network: .mainnet))/<0;1>/*)", network: .signet)
        }
        #expect(throws: PersonPayToError.singleAddressKey) {
            _ = try PersonPayTo.descriptor("tr(\(tpub))", network: .signet)
        }
        #expect(throws: PersonPayToError.unsupportedDerivation) {
            _ = try PersonPayTo.descriptor("tr(\(tpub)/1/*)", network: .signet)
        }
        // Only a tweaked single key pays a person: a raw output key and a
        // script tree are refused by shape, and a musig() aggregate does not parse.
        #expect(throws: PersonPayToError.notSingleKey) {
            _ = try PersonPayTo.descriptor("rawtr(\(Self.keyExpression(master)))", network: .signet)
        }
        let keys = try Self.masters().map { try Self.keyExpression($0) }
        #expect(throws: PersonPayToError.notSingleKey) {
            _ = try PersonPayTo.descriptor("tr(\(keys[0]),sortedmulti_a(2,\(keys[1]),\(keys[2])))", network: .signet)
        }
        #expect(throws: PersonPayToError.malformed) {
            _ = try PersonPayTo.descriptor("tr(musig(\(keys[0]),\(keys[1]))/<0;1>/*)", network: .signet)
        }
        #expect(throws: PersonPayToError.malformed) {
            _ = try PersonPayTo.descriptor("tr(nonsense)", network: .signet)
        }
    }

    @Test("payment n derives the person's receive address n")
    func freshAddressesFollowTheReceiveChain() throws {
        let master = try Self.masters()[1]
        let account = try Self.account(master)
        let payTo = try PersonPayTo.descriptor("tr(\(Self.keyExpression(master)))", network: .signet)
        for index: UInt32 in [0, 1, 7] {
            let child = try account.child(at: 0).child(at: index)
            let expected = try BIP86.address(internalKey: Data(child.publicKey.dropFirst()), hrp: "tb")
            #expect(try payTo.address(index: index, network: .signet) == expected)
            #expect(try payTo.scriptPubKey(index: index, network: .signet)
                == BIP86.scriptPubKey(internalKey: Data(child.publicKey.dropFirst())))
        }
        #expect(try payTo.scripts(upTo: 3, network: .signet).count == 3)
        #expect(try payTo.identity(network: .signet) == payTo.scriptPubKey(index: 0, network: .signet))

        let fixed = try PersonPayTo.address(try payTo.address(index: 0, network: .signet), network: .signet)
        #expect(!fixed.derivesFreshAddresses)
        #expect(try fixed.address(index: 5, network: .signet) == payTo.address(index: 0, network: .signet))
        #expect(try fixed.scripts(upTo: 30, network: .signet).count == 1)
    }

    @Test("pay-to survives JSON as a tagged value")
    func payToCodable() throws {
        let master = try Self.masters()[2]
        let payTo = try PersonPayTo.descriptor("tr(\(Self.keyExpression(master)))", network: .signet)
        let encoded = try JSONEncoder().encode([payTo, .address("tb1qexample")])
        let json = String(decoding: encoded, as: UTF8.self)
        #expect(json.contains("\"kind\":\"descriptor\"") && json.contains("\"kind\":\"address\""))
        let decoded = try JSONDecoder().decode([PersonPayTo].self, from: encoded)
        #expect(decoded == [payTo, .address("tb1qexample")])
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(PersonPayTo.self, from: Data(#"{"kind":"seed","value":"x"}"#.utf8))
        }
    }

    // MARK: - Cards and paste

    @Test("a card round-trips and a paste of it yields the pay-to key")
    func cardRoundTrip() throws {
        let master = try Self.masters()[0]
        let key = try Self.keyExpression(master)
        let payTo = try PersonPayTo.descriptor("tr(\(key))", network: .signet)
        let card = PersonCard(network: .signet, name: "Alice", payTo: payTo.text)
        let text = try card.serialized()
        #expect(text.hasPrefix("{"))
        #expect(text.contains("/<0;1>/*"), "slashes are written as-is so the key reads as pasted")
        #expect(try PersonCard.decode(text) == card)

        let imported = try PersonPaste.parse(text, network: .signet)
        #expect(imported == PersonImport(name: "Alice", payTo: payTo, source: .card))

        // A card from a Winnow that also carried a signer key still decodes;
        // the field it no longer understands is ignored, not refused.
        let withSignerKey = text.replacingOccurrences(of: "\"winnow\":", with: "\"signerKey\":\"\(key)\",\"winnow\":")
        #expect(withSignerKey != text)
        #expect(try PersonCard.decode(withSignerKey) == card)

        #expect(throws: PersonCardError.wrongNetwork(card: "signet", wallet: .mainnet)) {
            _ = try PersonPaste.parse(text, network: .mainnet)
        }
        #expect(throws: PersonCardError.notACard) {
            _ = try PersonCard.decode(#"{"winnow":"shared-savings","version":1}"#)
        }
        #expect(throws: PersonCardError.unsupportedVersion(9)) {
            _ = try PersonCard.decode(#"{"winnow":"person-card","version":9,"network":"signet","name":"x"}"#)
        }
    }

    @Test("every accepted paste form fills the fields it can")
    func pasteForms() throws {
        let master = try Self.masters()[1]
        let account = try Self.account(master)
        let tpub = account.neutered.serialized(network: .testnet)
        let fingerprint = String(format: "%08x", master.fingerprint)
        let full = try Self.keyExpression(master)
        let bareWithOrigin = "[\(fingerprint)/86'/1'/0']\(tpub)"
        let payTo = try PersonPayTo.descriptor("tr(\(full))", network: .signet)

        #expect(try PersonPaste.parse(full, network: .signet)
            == PersonImport(name: nil, payTo: payTo, source: .keyExpression))
        #expect(try PersonPaste.parse(bareWithOrigin, network: .signet)
            == PersonImport(name: nil, payTo: payTo, source: .keyExpression))

        // An account key with no origin gets the receive/change shape too.
        let bare = try PersonPaste.parse(tpub, network: .signet)
        #expect(bare.payTo == (try PersonPayTo.descriptor("tr(\(tpub)/<0;1>/*)", network: .signet)))
        #expect(bare.source == .keyExpression)

        let descriptor = try PersonPaste.parse("tr(\(full))", network: .signet)
        #expect(descriptor == PersonImport(name: nil, payTo: payTo, source: .descriptor))

        let address = try payTo.address(index: 0, network: .signet)
        #expect(try PersonPaste.parse(" \(address)\n", network: .signet)
            == PersonImport(name: nil, payTo: .address(address), source: .address))

        #expect(throws: PersonPasteError.empty) { _ = try PersonPaste.parse("  ", network: .signet) }
        #expect(throws: PersonPasteError.unrecognised) { _ = try PersonPaste.parse("hello there", network: .signet) }
        #expect(throws: PersonPayToError.privateKey) {
            _ = try PersonPaste.parse("[\(fingerprint)/86'/1'/0']\(account.serialized(network: .testnet))/<0;1>/*",
                                      network: .signet)
        }
        #expect(throws: PersonPayToError.wrongNetwork(expected: .mainnet)) {
            _ = try PersonPaste.parse(full, network: .mainnet)
        }
        #expect(throws: PersonPasteError.unrecognised) {
            _ = try PersonPaste.parse("sp1qqexample", network: .signet)
        }
        #expect(throws: PersonPasteError.unrecognised) {
            _ = try PersonPaste.parse("0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600", network: .signet)
        }
    }

    /// A silent payment code is a reusable pay-to of its own kind: accepted on
    /// its network in canonical lower case, refused on another network with a
    /// message that says so, and identified by its keys rather than a script.
    @Test("a pasted silent payment code becomes a reusable pay-to")
    func silentPaymentCodePaste() throws {
        let master = try HDKey(seed: Data(repeating: 0x5A, count: 32))
        let scan = try master.derived(path: "m/352'/1'/0'/1'/0").neutered.publicKey
        let spend = try master.derived(path: "m/352'/1'/0'/0'/0").neutered.publicKey
        let signet = try SilentPaymentAddress(scanKey: scan, spendKey: spend, hrp: "tsp").encoded
        let mainnet = try SilentPaymentAddress(scanKey: scan, spendKey: spend, hrp: "sp").encoded

        let imported = try PersonPaste.parse(" \(signet.uppercased())\n", network: .signet)
        #expect(imported == PersonImport(name: nil, payTo: .silentPayment(signet), source: .address))
        let payTo = try #require(imported.payTo)
        #expect(payTo.isSilentPayment)
        #expect(!payTo.derivesFreshAddresses)
        #expect(try payTo.address(index: 7, network: .signet) == signet)
        #expect(try payTo.scripts(upTo: 20, network: .signet).isEmpty)
        #expect(try payTo.identity(network: .signet) == scan + spend)
        #expect(throws: PersonPayToError.noFixedScript) { _ = try payTo.scriptPubKey(index: 0, network: .signet) }

        #expect(throws: SilentPaymentAddressError.wrongHRP(expected: "tsp", actual: "sp")) {
            _ = try PersonPaste.parse(mainnet, network: .signet)
        }
        #expect(throws: PersonPasteError.unrecognised) { _ = try PersonPaste.parse("sp1qqexample", network: .signet) }
        let card = PersonCard(network: .signet, name: "Robin", payTo: signet)
        #expect(try PersonPaste.parse(card.serialized(), network: .signet).payTo == .silentPayment(signet))
    }
}
