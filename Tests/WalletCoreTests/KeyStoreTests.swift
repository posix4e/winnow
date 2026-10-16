import Foundation
import Testing
import TestSupport
@testable import WalletCore

@Suite("KeyStore")
struct KeyStoreTests {
    @Test("InMemoryKeyStore store/load/delete round trip")
    func roundTrip() throws {
        let store = InMemoryKeyStore()
        #expect(throws: KeyStoreError.notFound(walletID: "w1")) { _ = try store.load(walletID: "w1") }

        try store.store(.mnemonic(testMnemonic), for: "w1")
        #expect(try store.load(walletID: "w1") == .mnemonic(testMnemonic))

        #expect(throws: KeyStoreError.alreadyExists(walletID: "w1")) {
            _ = try store.store(.mnemonic(testMnemonic), for: "w1")
        }

        try store.delete(walletID: "w1")
        #expect(throws: KeyStoreError.notFound(walletID: "w1")) { _ = try store.load(walletID: "w1") }
        try store.delete(walletID: "w1") // deleting an absent ID is a no-op
    }

    @Test("WalletSecret tagged serialization round trip")
    func secretSerialization() throws {
        for secret in [WalletSecret.mnemonic(testMnemonic),
                       WalletSecret.masterKey("xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu")] {
            #expect(try WalletSecret(serialized: secret.serialized) == secret)
        }
        #expect(throws: KeyStoreError.malformedSecret) {
            _ = try WalletSecret(serialized: Data("unknown\npayload".utf8))
        }
        #expect(throws: KeyStoreError.malformedSecret) {
            _ = try WalletSecret(serialized: Data("no-newline".utf8))
        }
    }

    @Test("account secret encoding preserves legacy bytes and rejects unknown versions safely")
    func accountSerialization() throws {
        let key = try BIP86.accountKey(from: testMaster(), coinType: 1).serialized(network: .testnet)
        let secret = WalletSecret.accountKey(xprv: key, masterFingerprint: 0x73c5da0a)
        #expect(secret.serialized == Data("account/1\n73c5da0a\n\(key)".utf8))
        #expect(try WalletSecret(serialized: secret.serialized) == secret)
        #expect(WalletSecret.mnemonic(testMnemonic).serialized == Data("mnemonic\n\(testMnemonic)".utf8))
        #expect(WalletSecret.masterKey(key).serialized == Data("xprv\n\(key)".utf8))
        for malformed in ["account/1", "account/1\n73c5da0a", "account/1\n73C5DA0A\n\(key)",
                          "account/1\n73c5da0\n\(key)", "account/1\n73c5da0a\n\(key)\nextra",
                          // A header that is not exactly `account/<digits>` is damage,
                          // not a newer version to send the user elsewhere for.
                          "account/1x\n73c5da0a\n\(key)", "account/\n73c5da0a\n\(key)",
                          "account/1 \n73c5da0a\n\(key)"] {
            #expect(throws: KeyStoreError.malformedSecret) {
                _ = try WalletSecret(serialized: Data(malformed.utf8))
            }
        }
        #expect(throws: KeyStoreError.unsupportedSecretVersion("account/2")) {
            _ = try WalletSecret(serialized: Data("account/2\n73c5da0a\n\(key)".utf8))
        }
        do {
            _ = try WalletSecret(serialized: Data("account/2\(key)".utf8))
            Issue.record("unsupported version accepted")
        } catch let error as KeyStoreError {
            #expect(error == .unsupportedSecretVersion("account/2"))
            #expect(!String(describing: error).contains(key.prefix(4)))
            #expect(!error.localizedDescription.contains(key.prefix(4)))
        }
    }
}
