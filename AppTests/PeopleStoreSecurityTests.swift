@testable import WinnowApp
import BitcoinCore
import BitcoinP2P
import WalletCore
import XCTest

/// The address book file has the same posture as the vault file: fail the
/// whole snapshot closed, never rewrite what could not be read, roll back a
/// failed write. Plus the one thing that is its own: while damaged, it
/// refuses every mutation instead of taking the app down.
final class PeopleStoreSecurityTests: XCTestCase {
    func testMissingFileIsAnEmptyStore() async {
        let url = temporaryURL()
        let store = PeopleStore()
        let result = await store.configure(storageURL: url, network: .signet)
        let records = await store.all
        XCTAssertEqual(result, .missing)
        XCTAssertEqual(records, [])
    }

    func testMalformedFileFailsClosedRefusesMutationsAndIsNotRewritten() async throws {
        let url = temporaryURL()
        let original = Data("not people json".utf8)
        try original.write(to: url, options: .atomic)
        defer { try? FileManager.default.removeItem(at: url) }
        let store = PeopleStore()

        guard case let .damaged(message) = await store.configure(storageURL: url, network: .signet)
        else { return XCTFail("malformed storage was accepted") }
        XCTAssertTrue(message.contains("left untouched"))
        let records = await store.all
        XCTAssertEqual(records, [])

        let alice = try fixture(0xA1)
        do {
            try await store.add(name: "Alice", payTo: alice.payTo, signerKey: alice.signer)
            XCTFail("a damaged store accepted a mutation")
        } catch PeopleStorageError.damaged {}
        XCTAssertEqual(try Data(contentsOf: url), original)
    }

    func testOneInvalidRecordRejectsTheWholeSnapshot() async throws {
        let alice = try fixture(0xA1)
        let good = PersonRecord(id: "one", name: "Alice", payTo: alice.payTo, signerKey: alice.signer)
        var nameless = good
        nameless.id = "two"
        nameless.name = "  "
        nameless.signerKey = nil
        nameless.payTo = try fixture(0xB2).payTo
        let url = try write([good, nameless])
        defer { try? FileManager.default.removeItem(at: url) }
        let store = PeopleStore()
        guard case .damaged = await store.configure(storageURL: url, network: .signet)
        else { return XCTFail("partially invalid storage was accepted") }
        let records = await store.all
        XCTAssertEqual(records, [])
    }

    func testPrivateKeysAndSharedKeysInTheFileFailClosed() async throws {
        let alice = try fixture(0xA1)
        let bob = try fixture(0xB2)
        let base = PersonRecord(id: "one", name: "Alice", payTo: alice.payTo, signerKey: alice.signer)

        var privateSigner = base
        privateSigner.signerKey = alice.privateSigner
        var sharedPayTo = PersonRecord(id: "two", name: "Bob", payTo: alice.payTo, signerKey: bob.signer)
        var sharedSigner = PersonRecord(id: "two", name: "Bob", payTo: bob.payTo, signerKey: alice.signer)
        var duplicateID = base
        duplicateID.name = "Alice again"
        duplicateID.payTo = bob.payTo
        duplicateID.signerKey = bob.signer
        var outOfRange = base
        outOfRange.nextPaymentIndex = PeopleStore.maximumNextIndex + 1
        var wrongNetwork = base
        wrongNetwork.payTo = .address("bc1qexample")
        sharedPayTo.nextPaymentIndex = 0
        sharedSigner.nextPaymentIndex = 0

        for (label, records) in [
            ("private signer", [privateSigner]),
            ("shared pay-to", [base, sharedPayTo]),
            ("shared signer", [base, sharedSigner]),
            ("duplicate id", [base, duplicateID]),
            ("index out of range", [outOfRange]),
            ("wrong network address", [wrongNetwork]),
        ] {
            let url = try write(records)
            defer { try? FileManager.default.removeItem(at: url) }
            let store = PeopleStore()
            guard case .damaged = await store.configure(storageURL: url, network: .signet)
            else { return XCTFail("\(label) was accepted") }
        }
    }

    func testAddRefusesASecondEntryForTheSameKeyEvenRelabelled() async throws {
        let alice = try fixture(0xA1)
        let store = PeopleStore()
        let url = temporaryURL()
        defer { try? FileManager.default.removeItem(at: url) }
        await store.configure(storageURL: url, network: .signet)
        try await store.add(name: "Alice", payTo: alice.payTo, signerKey: alice.signer)

        // Same account key, hardened marker spelled the other way.
        let relabelled = alice.signer.replacingOccurrences(of: "'", with: "h")
        XCTAssertNotEqual(relabelled, alice.signer)
        do {
            try await store.add(name: "Alice twice", payTo: nil, signerKey: relabelled)
            XCTFail("the same signer was admitted twice")
        } catch PeopleStorageError.duplicate(let existing) {
            XCTAssertEqual(existing, "Alice")
        }
        do {
            try await store.add(name: "Alice by address",
                                payTo: .address(try alice.payTo.address(index: 0, network: .signet)),
                                signerKey: nil)
            XCTFail("the same pay-to script was admitted twice")
        } catch PeopleStorageError.duplicate(let existing) {
            XCTAssertEqual(existing, "Alice")
        }
        do {
            try await store.add(name: "Nobody", payTo: nil, signerKey: nil)
            XCTFail("a person with no keys was saved")
        } catch PeopleStorageError.nothingToSave {}
        let records = await store.all
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(try JSONDecoder().decode([PersonRecord].self, from: Data(contentsOf: url)), records)
        XCTAssertTrue(String(decoding: try Data(contentsOf: url), as: UTF8.self).contains("/<0;1>/*"),
                      "the file keeps key expressions readable")
    }

    func testPaymentIndexAdvancesMonotonicallyAndIdempotently() async throws {
        let alice = try fixture(0xA1)
        let store = PeopleStore()
        let url = temporaryURL()
        defer { try? FileManager.default.removeItem(at: url) }
        await store.configure(storageURL: url, network: .signet)
        let record = try await store.add(name: "Alice", payTo: alice.payTo, signerKey: nil)
        XCTAssertEqual(record.nextPaymentIndex, 0)

        try await store.advancePaymentIndex(id: record.id, past: 0)
        try await store.advancePaymentIndex(id: record.id, past: 0)
        var current = await store.record(id: record.id)?.nextPaymentIndex
        XCTAssertEqual(current, 1)
        try await store.advancePaymentIndex(id: record.id, past: 4)
        try await store.advancePaymentIndex(id: record.id, past: 2)
        current = await store.record(id: record.id)?.nextPaymentIndex
        XCTAssertEqual(current, 5, "a smaller index never moves the counter back")

        // Reloading sees the persisted counter.
        let reopened = PeopleStore()
        let result = await reopened.configure(storageURL: url, network: .signet)
        XCTAssertEqual(result, .loaded)
        let persisted = await reopened.record(id: record.id)?.nextPaymentIndex
        XCTAssertEqual(persisted, 5)
        do {
            try await store.advancePaymentIndex(id: "missing", past: 0)
            XCTFail("an unknown person advanced")
        } catch PeopleStorageError.unknownPerson {}
    }

    func testFailedPersistenceRollsBackTheLiveSnapshotAndLeavesFileUntouched() async throws {
        enum ExpectedFailure: Error { case write }
        let alice = try fixture(0xA1)
        let record = PersonRecord(id: "one", name: "Alice", payTo: alice.payTo, signerKey: alice.signer)
        let url = try write([record])
        let original = try Data(contentsOf: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let store = PeopleStore(writeData: { _, _ in throw ExpectedFailure.write })
        let result = await store.configure(storageURL: url, network: .signet)
        XCTAssertEqual(result, .loaded)

        do {
            try await store.add(name: "Bob", payTo: try fixture(0xB2).payTo, signerKey: nil)
            XCTFail("failed persistence was reported as successful")
        } catch ExpectedFailure.write {
            let records = await store.all
            XCTAssertEqual(records, [record])
            XCTAssertEqual(try Data(contentsOf: url), original)
        }
    }

    func testRemoveAndUpdate() async throws {
        let alice = try fixture(0xA1)
        let bob = try fixture(0xB2)
        let store = PeopleStore()
        let url = temporaryURL()
        defer { try? FileManager.default.removeItem(at: url) }
        await store.configure(storageURL: url, network: .signet)
        let a = try await store.add(name: "Alice", payTo: alice.payTo, signerKey: alice.signer)
        let b = try await store.add(name: "Bob", payTo: bob.payTo, signerKey: nil)

        var renamed = b
        renamed.name = "Robert"
        renamed.signerKey = bob.signer
        try await store.update(renamed)
        var stolen = renamed
        stolen.signerKey = alice.signer
        do {
            try await store.update(stolen)
            XCTFail("an update took another person's key")
        } catch PeopleStorageError.duplicate(let existing) {
            XCTAssertEqual(existing, "Alice")
        }
        try await store.remove(id: a.id)
        let records = await store.all
        XCTAssertEqual(records, [renamed])
    }

    // MARK: - Fixtures

    private struct Fixture {
        var payTo: PersonPayTo
        var signer: String
        var privateSigner: String
    }

    private func fixture(_ byte: UInt8) throws -> Fixture {
        let master = try HDKey(seed: BIP39.seed(mnemonic: BIP39.mnemonic(entropy: Data(repeating: byte, count: 16))))
        let account = try master.derived(path: "m/86'/1'/0'")
        let origin = "[\(String(format: "%08x", master.fingerprint))/86'/1'/0']"
        let signer = "\(origin)\(account.neutered.serialized(network: .testnet))/<0;1>/*"
        return Fixture(payTo: try PersonPayTo.descriptor("tr(\(signer))", network: .signet),
                       signer: signer,
                       privateSigner: "\(origin)\(account.serialized(network: .testnet))/<0;1>/*")
    }

    private func write(_ records: [PersonRecord]) throws -> URL {
        let url = temporaryURL()
        try JSONEncoder().encode(records).write(to: url, options: .atomic)
        return url
    }

    private func temporaryURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("people-store-\(UUID().uuidString).json")
    }
}
