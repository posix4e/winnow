import BitcoinCore
import BitcoinP2P
import Foundation
import Testing
@testable import WalletCore

/// People: the pay-to keys a fresh address is derived from, the cards people
/// exchange, what a paste turns into, and how a shared-savings vault finds its
/// co-owners and counts their approvals. Offline, signet-format fixtures.
@Suite("People and shared savings")
struct PeopleTests {
    static func masters() throws -> [HDKey] { try VaultFlowTests.masters() }

    static func signer(_ master: HDKey) throws -> String {
        try VaultFlowTests.keyExpression(master: master)
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

        let multipath = try PersonPayTo.descriptor("tr(\(Self.signer(master)))", network: .signet)
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
        let keys = try Self.masters().map { try Self.signer($0) }
        let savings = try Vault.multiADescriptor(threshold: 2, cosigners: keys).serialized()
        #expect(throws: PersonPayToError.notSingleKey) {
            _ = try PersonPayTo.descriptor(savings, network: .signet)
        }
        #expect(throws: PersonPayToError.malformed) {
            _ = try PersonPayTo.descriptor("tr(nonsense)", network: .signet)
        }
    }

    @Test("payment n derives the person's receive address n")
    func freshAddressesFollowTheReceiveChain() throws {
        let master = try Self.masters()[1]
        let account = try Self.account(master)
        let payTo = try PersonPayTo.descriptor("tr(\(Self.signer(master)))", network: .signet)
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
        let payTo = try PersonPayTo.descriptor("tr(\(Self.signer(master)))", network: .signet)
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

    @Test("a card round-trips and a paste of it yields both keys")
    func cardRoundTrip() throws {
        let master = try Self.masters()[0]
        let signer = try Self.signer(master)
        let payTo = try PersonPayTo.descriptor("tr(\(signer))", network: .signet)
        let card = PersonCard(network: .signet, name: "Alice", payTo: payTo.text, signerKey: signer)
        let text = try card.serialized()
        #expect(text.hasPrefix("{"))
        #expect(text.contains("/<0;1>/*"), "slashes are written as-is so the key reads as pasted")
        #expect(try PersonCard.decode(text) == card)

        let imported = try PersonPaste.parse(text, network: .signet)
        #expect(imported == PersonImport(name: "Alice", payTo: payTo, signerKey: signer, source: .card))

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
        let full = try Self.signer(master)
        let bareWithOrigin = "[\(fingerprint)/86'/1'/0']\(tpub)"
        let payTo = try PersonPayTo.descriptor("tr(\(full))", network: .signet)

        #expect(try PersonPaste.parse(full, network: .signet)
            == PersonImport(name: nil, payTo: payTo, signerKey: full, source: .keyExpression))
        #expect(try PersonPaste.parse(bareWithOrigin, network: .signet)
            == PersonImport(name: nil, payTo: payTo, signerKey: full, source: .keyExpression))

        let bare = try PersonPaste.parse(tpub, network: .signet)
        #expect(bare.signerKey == nil, "no origin, so it cannot co-own savings")
        #expect(bare.payTo == (try PersonPayTo.descriptor("tr(\(tpub)/0/*)", network: .signet)))

        let descriptor = try PersonPaste.parse("tr(\(full))", network: .signet)
        #expect(descriptor == PersonImport(name: nil, payTo: payTo, signerKey: full, source: .descriptor))

        let address = try payTo.address(index: 0, network: .signet)
        #expect(try PersonPaste.parse(" \(address)\n", network: .signet)
            == PersonImport(name: nil, payTo: .address(address), signerKey: nil, source: .address))

        #expect(throws: PersonPasteError.empty) { _ = try PersonPaste.parse("  ", network: .signet) }
        #expect(throws: PersonPasteError.unrecognised) { _ = try PersonPaste.parse("hello there", network: .signet) }
        #expect(throws: VaultCosignerKeyError.privateKey) {
            _ = try PersonPaste.parse("[\(fingerprint)/86'/1'/0']\(account.serialized(network: .testnet))/<0;1>/*",
                                      network: .signet)
        }
        #expect(throws: AddressError.self) {
            _ = try PersonPaste.parse("sp1qqexample", network: .signet)
        }
    }

    @Test("the same signer under a relabelled origin is one identity")
    func signerIdentityIgnoresLabels() throws {
        let apostrophe = VaultCosignerIdentityTests.scriptPath(
            "6738736c/48'/0'/0'/100'", VaultCosignerIdentityTests.keyA)
        let letterH = VaultCosignerIdentityTests.scriptPath(
            "6738736C/48h/0h/0h/100h", VaultCosignerIdentityTests.keyA)
        let other = VaultCosignerIdentityTests.scriptPath(
            "b2b1f0cf/44'/0'/0'/100'", VaultCosignerIdentityTests.keyB)
        #expect(try PersonKeys.signerIdentity(apostrophe, network: .mainnet)
            == PersonKeys.signerIdentity(letterH, network: .mainnet))
        #expect(try PersonKeys.signerIdentity(apostrophe, network: .mainnet)
            != PersonKeys.signerIdentity(other, network: .mainnet))
    }

    // MARK: - Shared savings

    @Test("a savings vault finds its co-owners by key, whatever the order")
    func savingsSignersMatchPeople() throws {
        let masters = try Self.masters()
        let keys = try masters.map { try Self.signer($0) }
        let forward = try Vault(descriptor: Vault.multiADescriptor(threshold: 2, cosigners: keys), network: .signet)
        let shuffled = try Vault(descriptor: Vault.multiADescriptor(threshold: 2, cosigners: [keys[2], keys[0], keys[1]]),
                                 network: .signet)
        #expect(try forward.scriptPubKey(index: 0) == shuffled.scriptPubKey(index: 0),
                "sortedmulti_a pays the same script whichever order the keys were listed in")
        #expect(forward.threshold == 2 && forward.signerCount == 3 && forward.isScriptPath)

        let identities = try keys.map { try PersonKeys.signerIdentity($0, network: .signet) }
        #expect(Set(try forward.signerKeys()) == Set(identities))
        #expect(Set(try shuffled.signerKeys()) == Set(identities))
        #expect(forward.cosignerExpressions == keys)
        #expect(shuffled.cosignerExpressions == [keys[2], keys[0], keys[1]])

        let card = SharedSavingsCard(network: .signet, name: "Savings with Alice, Bob",
                                     descriptor: forward.descriptor.serialized())
        let decoded = try SharedSavingsCard.decode(try card.serialized(), network: .signet)
        #expect(decoded.card == card)
        #expect(decoded.vault.descriptor == forward.descriptor)
        #expect(throws: PersonCardError.wrongNetwork(card: "signet", wallet: .mainnet)) {
            _ = try SharedSavingsCard.decode(try card.serialized(), network: .mainnet)
        }
    }

    @Test("approvals are counted from script signatures on every input")
    func signersOfASpend() throws {
        let masters = try Self.masters()
        let keys = try masters.map { try Self.signer($0) }
        let vault = try Vault(descriptor: Vault.multiADescriptor(threshold: 2, cosigners: keys), network: .signet)
        let utxo = try VaultFlowTests.funding(vault: vault, amount: 100_000)
        let destination = Data([0x51, 0x20] + repeatElement(0x77, count: 32))
        var psbt = try vault.createSpend(utxos: [utxo], payments: [Payment(amount: 40_000, scriptPubKey: destination)],
                                         changeIndex: 0, feeRateSatPerVByte: 2, chainTip: 200, randomness: { 0.5 })
        #expect(try vault.signers(of: psbt, knownUTXOs: [utxo]).isEmpty)

        let identities = try keys.map { try PersonKeys.signerIdentity($0, network: .signet) }
        let signerKeys = try vault.signerKeys()
        try vault.partialSign(&psbt, master: masters[1], knownUTXOs: [utxo],
                              ownedOutputCoordinates: [.init(choice: 1, index: 0)])
        let afterOne = try vault.signers(of: psbt, knownUTXOs: [utxo])
        #expect(afterOne == [signerKeys.firstIndex(of: identities[1])!])

        try vault.partialSign(&psbt, master: masters[2], knownUTXOs: [utxo],
                              ownedOutputCoordinates: [.init(choice: 1, index: 0)])
        #expect(try vault.signers(of: psbt, knownUTXOs: [utxo]).count == 2)

        let request = ApprovalRequest(network: .signet, vault: "abcd1234", name: "Savings", psbt: psbt)
        let envelope = try request.serialized()
        let decoded = try ApprovalRequest.decode(envelope, network: .signet)
        #expect(decoded == request)
        #expect(try decoded.decodedPSBT() == psbt)
        let bare = try ApprovalRequest.decode(psbt.base64, network: .signet)
        #expect(bare.vault == nil && bare.name == nil)
        #expect(try bare.decodedPSBT() == psbt)
        #expect(throws: PersonCardError.wrongNetwork(card: "signet", wallet: .mainnet)) {
            _ = try ApprovalRequest.decode(envelope, network: .mainnet)
        }
        #expect(throws: (any Error).self) { _ = try ApprovalRequest.decode("not a psbt", network: .signet) }
        #expect(throws: VaultError.self) {
            _ = try vault.signers(of: psbt, knownUTXOs: [])
        }
    }

    @Test("outputs are labelled savings, person, you, or unknown, in that order")
    func paymentLabels() {
        let alice = Data([0x51, 0x20] + repeatElement(0xAA, count: 32))
        let mine = Data([0x51, 0x20] + repeatElement(0xBB, count: 32))
        let labeler = PaymentLabeler(savingsName: "Savings with Alice",
                                     personScripts: [alice: "Alice", mine: "Alice too"],
                                     ownScripts: [mine])
        #expect(labeler.label(script: alice, isVaultOwned: true) == .savings("Savings with Alice"))
        #expect(labeler.label(script: alice, isVaultOwned: false) == .person("Alice"))
        #expect(labeler.label(script: mine, isVaultOwned: false) == .person("Alice too"),
                "a person's script wins over the wallet's own: it was chosen for them")
        #expect(labeler.label(script: Data([0x51, 0x20, 0x01]), isVaultOwned: false) == .unknown)
        let onlyMine = PaymentLabeler(savingsName: "s", personScripts: [:], ownScripts: [mine])
        #expect(onlyMine.label(script: mine, isVaultOwned: false) == .you)
    }
}
