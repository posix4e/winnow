@testable import WinnowApp
import CryptoKit
import Security
import WalletCore
import TestSupport
import XCTest

/// The people file is sealed under a key the app container cannot
/// reach (IR-010). What the seal buys: a file this app did not write on this
/// device — a substituted signer key that validates perfectly and would show
/// up as a co-owner — is refused rather than trusted. What it costs: a file
/// from before sealing is adopted once, on trust, and sealed; from then on the
/// key's existence is the record that the file must verify.
final class StoreAuthenticationTests: XCTestCase {
    private func tempFileURL(_ name: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("winnow-store-auth-\(UUID().uuidString)-\(name)")
    }

    private static let legacyPeople = Data(#"[{"id":"a1","name":"Alice","nextPaymentIndex":0}]"#.utf8)

    private struct PeopleFile: Decodable {
        var people: [PersonRecord]
    }

    // MARK: - People

    func testAPeopleFileFromBeforeSealingIsAdoptedSealedAndBoundToItsKey() async throws {
        let url = tempFileURL("people.json")
        defer { try? FileManager.default.removeItem(at: url) }
        try Self.legacyPeople.write(to: url, options: .atomic)
        let keys = InMemoryStoreKeyVault()
        let store = PeopleStore(keys: keys)
        let opened = await store.configure(storageURL: url, network: .signet)
        XCTAssertEqual(opened, .loaded, "a file from before sealing is adopted")

        let sealed = try Data(contentsOf: url)
        XCTAssertTrue(SealedStoreFile.isSealed(sealed), "an adopted file is sealed on load")
        XCTAssertNotNil(try keys.key(for: "people.signet"), "adoption establishes the file's key")
        XCTAssertEqual(try JSONDecoder().decode(PeopleFile.self, from: unsealedPayload(of: url)).people.map(\.name),
                       ["Alice"], "the payload is the same address book, readable as before")

        let reopened = PeopleStore(keys: keys)
        let reopenedResult = await reopened.configure(storageURL: url, network: .signet)
        XCTAssertEqual(reopenedResult, .loaded, "the store that holds the key reads its file")
        let names = await reopened.all.map(\.name)
        XCTAssertEqual(names, ["Alice"])

        let stranger = PeopleStore(keys: InMemoryStoreKeyVault())
        guard case let .damaged(message) = await stranger.configure(storageURL: url, network: .signet) else {
            return XCTFail("a sealed file was accepted without its key")
        }
        XCTAssertTrue(message.contains("could not be verified"), message)
        XCTAssertEqual(try Data(contentsOf: url), sealed, "a refused file is left as it was")
    }

    func testAnUnsealedPeopleFileIsRefusedOnceTheStoreHasAKey() async throws {
        let url = tempFileURL("people.json")
        defer { try? FileManager.default.removeItem(at: url) }
        let keys = InMemoryStoreKeyVault()
        let store = PeopleStore(keys: keys)
        _ = await store.configure(storageURL: url, network: .signet)
        _ = try await store.add(name: "Alice", payTo: nil)
        XCTAssertTrue(SealedStoreFile.isSealed(try Data(contentsOf: url)), "the first write seals the file")

        // The substitution: a well-formed address book that validates, dropped
        // into the container in place of the sealed one.
        let planted = Data(#"[{"id":"m1","name":"Mallory","nextPaymentIndex":0}]"#.utf8)
        try planted.write(to: url, options: .atomic)
        let reopened = PeopleStore(keys: keys)
        guard case let .damaged(message) = await reopened.configure(storageURL: url, network: .signet) else {
            return XCTFail("an unsealed file was accepted by a store that holds a key")
        }
        XCTAssertTrue(message.contains("could not be verified"), message)
        let people = await reopened.all
        XCTAssertTrue(people.isEmpty, "nothing from the planted file is loaded")
        do {
            _ = try await reopened.add(name: "Bob", payTo: nil)
            XCTFail("a store that refused its file accepted a mutation")
        } catch PeopleStorageError.damaged {}
        XCTAssertEqual(try Data(contentsOf: url), planted, "the refused file is left as evidence")
    }

    func testATamperedPeoplePayloadIsRefused() async throws {
        let url = tempFileURL("people.json")
        defer { try? FileManager.default.removeItem(at: url) }
        let keys = InMemoryStoreKeyVault()
        let store = PeopleStore(keys: keys)
        _ = await store.configure(storageURL: url, network: .signet)
        _ = try await store.add(name: "Alice", payTo: nil)

        // One byte of the payload, under an untouched header.
        let sealed = try Data(contentsOf: url)
        let text = String(decoding: sealed, as: UTF8.self)
        XCTAssertTrue(text.contains("Alice"))
        let tampered = Data(text.replacingOccurrences(of: "Alice", with: "Alicf").utf8)
        try tampered.write(to: url, options: .atomic)
        let reopened = PeopleStore(keys: keys)
        guard case .damaged = await reopened.configure(storageURL: url, network: .signet) else {
            return XCTFail("a payload edited under its seal was accepted")
        }
        XCTAssertEqual(try Data(contentsOf: url), tampered)
    }

    func testAFailedAdoptionWriteLeavesNoKeyBehind() async throws {
        let url = tempFileURL("people.json")
        defer { try? FileManager.default.removeItem(at: url) }
        try Self.legacyPeople.write(to: url, options: .atomic)
        let keys = InMemoryStoreKeyVault()
        enum WriteFailure: Error { case expected }
        let unable = PeopleStore(keys: keys, writeData: { _, _ in throw WriteFailure.expected })
        let opened = await unable.configure(storageURL: url, network: .signet)
        XCTAssertEqual(opened, .loaded, "the address book is still read when it cannot be sealed yet")
        let names = await unable.all.map(\.name)
        XCTAssertEqual(names, ["Alice"])
        XCTAssertNil(try keys.key(for: "people.signet"),
                     "a key that never sealed a file would turn the file on disk into a refusal")
        XCTAssertEqual(try Data(contentsOf: url), Self.legacyPeople, "the file is untouched")

        // The next launch, able to write, adopts it.
        let able = PeopleStore(keys: keys)
        let adopted = await able.configure(storageURL: url, network: .signet)
        XCTAssertEqual(adopted, .loaded)
        XCTAssertNotNil(try keys.key(for: "people.signet"))
        XCTAssertTrue(SealedStoreFile.isSealed(try Data(contentsOf: url)))
    }

    // MARK: - The seal itself

    func testTheSealNamesItsStoreAndNetworkAndKeepsThePayloadReadable() throws {
        let key = SymmetricKey(size: .bits256)
        let payload = Data(#"{"people":[],"senderByTxid":{}}"#.utf8)
        let sealed = SealedStoreFile.seal(payload, store: "people", network: .signet, key: key)
        XCTAssertTrue(String(decoding: sealed, as: UTF8.self).hasSuffix(String(decoding: payload, as: UTF8.self)),
                      "the payload follows the header byte for byte")
        XCTAssertEqual(try SealedStoreFile.open(sealed, store: "people", network: .signet, key: key), payload)

        func failure(_ body: () throws -> Data) -> SealedStoreFile.Failure? {
            do { _ = try body(); return nil } catch { return error as? SealedStoreFile.Failure }
        }
        XCTAssertEqual(failure { try SealedStoreFile.open(sealed, store: "receive-labels", network: .signet, key: key) },
                       .verificationFailed, "a people file cannot be dropped in under another store's name")
        XCTAssertEqual(failure { try SealedStoreFile.open(sealed, store: "people", network: .mainnet, key: key) },
                       .verificationFailed, "a signet file cannot be presented as mainnet")
        XCTAssertEqual(failure { try SealedStoreFile.open(sealed, store: "people", network: .signet,
                                                          key: SymmetricKey(size: .bits256)) },
                       .verificationFailed)
        XCTAssertEqual(failure { try SealedStoreFile.open(payload, store: "people", network: .signet, key: key) },
                       .unsealed)
        var flipped = sealed
        flipped[flipped.count - 1] ^= 0x01
        XCTAssertEqual(failure { try SealedStoreFile.open(flipped, store: "people", network: .signet, key: key) },
                       .verificationFailed)
        var shortCode = sealed
        shortCode.removeSubrange(SealedStoreFile.header.utf8.count + 1 ..< SealedStoreFile.header.utf8.count + 3)
        XCTAssertEqual(failure { try SealedStoreFile.open(shortCode, store: "people", network: .signet, key: key) },
                       .malformed)
    }

    // MARK: - The Keychain item (invariant S1, observed the way KeychainAttributeTests observes the wallet secret)

    func testTheKeychainKeyIsThisDeviceOnlyUnsynchronisedAndAvailableAfterFirstUnlock() throws {
        let service = "org.btc-swift.tests.store-keys"
        let vault = KeychainStoreKeyVault(service: service)
        let account = "people.\(UUID().uuidString)"
        defer { try? vault.discardKey(for: account) }

        XCTAssertNil(try vault.key(for: account))
        let key = try vault.establishKey(for: account)
        XCTAssertEqual(try vault.key(for: account), key, "the key reads back")
        XCTAssertThrowsError(try vault.establishKey(for: account), "a key is never replaced") { error in
            XCTAssertEqual(error as? StoreKeyVaultError, .alreadyEstablished(account))
        }

        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: KeychainStoreKeyVault.accountPrefix + account,
            kSecReturnAttributes: true,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecAttrSynchronizable: kSecAttrSynchronizableAny,
        ]
        var item: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(query as CFDictionary, &item), errSecSuccess)
        let attributes = try XCTUnwrap(item as? [CFString: Any])
        XCTAssertEqual(attributes[kSecAttrAccessible] as? String,
                       kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String,
                       "the key is available exactly when the files it seals are")
        XCTAssertFalse(attributes[kSecAttrSynchronizable] as? Bool ?? false, "the key never leaves the device")

        try vault.discardKey(for: account)
        XCTAssertNil(try vault.key(for: account))
        XCTAssertNoThrow(try vault.discardKey(for: account), "discarding an absent key is a no-op")
    }
}
