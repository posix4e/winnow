@testable import WinnowApp
import Foundation
import TestSupport
import WalletCore
import XCTest

@MainActor
final class CloudAppStateTests: XCTestCase {
    private func fixture() async throws -> (ImportBundle, CloudAppState, URL) {
        let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        let wallet = try Wallet.create(network: .mainnet, keyStore: InMemoryKeyStore(),
                                       entropy: Data(repeating: 8, count: 16), creationHeight: 100)
        let bundle = try await wallet.exportBundle(includeMnemonic: true)
        let person = PersonRecord(id: UUID().uuidString, name: "Saved friend",
                                  payTo: .address("1BoatSLRHtKNngkdXEeobR76b53LETtpyT"),
                                  nextPaymentIndex: 17)
        let script = try AddressDecoder.scriptPubKey(for: "1BoatSLRHtKNngkdXEeobR76b53LETtpyT", network: .mainnet)
        let state = CloudAppState(network: bundle.network, descriptor: bundle.descriptor,
                                  people: .init(people: [person], senderByTxid: [String(repeating: "01", count: 32): person.id]),
                                  receiveLabels: [script.hex: "Private invoice"], ownDisplayName: "Me", advancedMode: true)
        return (bundle, state, directory)
    }

    func testCloudContextRoundTripsPeopleCountersSenderNamesAndReceiveLabels() async throws {
        let (bundle, original, directory) = try await fixture()
        let restored = try XCTUnwrap(CloudAppState.decode(original.encoded(), for: bundle))
        XCTAssertEqual(restored, original)
        let people = PeopleStore(keys: InMemoryStoreKeyVault())
        await people.configure(storageURL: directory.appending(path: "people.json"), network: .mainnet)
        try await people.restore(people.planRestore(restored.people))
        let saved = try await people.backup()
        XCTAssertEqual(saved, original.people)
        let labels = ReceiveAddressLabelStore(storageURL: directory.appending(path: "labels.json"),
                                               walletID: "restored", network: .mainnet)
        try labels.restore(restored.receiveLabels)
        XCTAssertEqual(try labels.backup(), original.receiveLabels)
        let reopened = ReceiveAddressLabelStore(storageURL: directory.appending(path: "labels.json"),
                                                 walletID: "restored", network: .mainnet)
        XCTAssertEqual(try reopened.backup(), original.receiveLabels)
        XCTAssertFalse(try bundle.serialized().contains("Saved friend"), "manual export stays unchanged")
        XCTAssertNil(try CloudAppState.decode(nil, for: bundle), "older backups remain recoverable")
    }

    func testExistingContactsAndNewerPaymentCounterSurviveRestore() async throws {
        let (_, state, directory) = try await fixture()
        let store = PeopleStore(keys: InMemoryStoreKeyVault())
        await store.configure(storageURL: directory.appending(path: "people.json"), network: .mainnet)
        var local = state.people
        local.people[0].id = UUID().uuidString
        local.people[0].name = "Current local name"
        local.people[0].nextPaymentIndex = 24
        local.senderByTxid = [:]
        try await store.restore(local)
        let merged = try await store.planRestore(state.people)
        XCTAssertEqual(merged.people.count, 1)
        XCTAssertEqual(merged.people[0].name, "Current local name")
        XCTAssertEqual(merged.people[0].nextPaymentIndex, 24)
        XCTAssertEqual(merged.senderByTxid.values.first, local.people[0].id)
    }

    func testWrongNetworkOrMalformedLabelsAreRejectedBeforeStoreChanges() async throws {
        let (bundle, state, directory) = try await fixture()
        var changed = try XCTUnwrap(JSONSerialization.jsonObject(with: state.encoded()) as? [String: Any])
        changed["network"] = "signet"
        XCTAssertThrowsError(try CloudAppState.decode(JSONSerialization.data(withJSONObject: changed), for: bundle))
        changed["network"] = "mainnet"
        changed["receiveLabels"] = ["not a script": "Private note"]
        XCTAssertThrowsError(try CloudAppState.decode(JSONSerialization.data(withJSONObject: changed), for: bundle))
        let store = PeopleStore(keys: InMemoryStoreKeyVault())
        await store.configure(storageURL: directory.appending(path: "people.json"), network: .mainnet)
        try await store.restore(state.people)
        var invalid = state.people
        invalid.senderByTxid[String(repeating: "02", count: 32)] = "unknown person"
        do {
            _ = try await store.planRestore(invalid)
            XCTFail("dangling sender name should fail validation")
        } catch { }
        let unchanged = try await store.backup()
        XCTAssertEqual(unchanged, state.people)
    }
}
