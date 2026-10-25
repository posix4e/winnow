@testable import WinnowApp
import WalletCore
import Foundation
import TestSupport
import XCTest

/// "Who paid you": sender labels in the people store, the funding-address
/// candidates a transaction itself reveals, and the decoding of the opt-in
/// explorer lookup's answer.

// MARK: - SenderLabelStoreTests

/// The label half of the people store, over a real file: round-trip,
/// persistence across a reopen, removal, and the pre-labels file shape.
final class SenderLabelStoreTests: XCTestCase {
    func testNameOnlyLabelPersistsAndDestinationRequiresExplicitAttachment() async throws {
        let keys = InMemoryStoreKeyVault()
        let url = tempStoreURL()
        defer { try? FileManager.default.removeItem(at: url) }
        let store = PeopleStore(keys: keys)
        await store.configure(storageURL: url, network: .signet)
        let person = try await store.add(name: "Alice", payTo: nil)
        let txid = String(repeating: "ab", count: 32)
        try await store.labelSender(txidHex: txid, personID: person.id)
        let reopened = PeopleStore(keys: keys)
        _ = await reopened.configure(storageURL: url, network: .signet)
        let labelled = await reopened.sender(forTxidHex: txid)
        XCTAssertEqual(labelled?.name, "Alice")
        XCTAssertNil(labelled?.payTo)
        let destination = try PersonPayTo.address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", network: .signet)
        try await reopened.attachDestination(id: person.id, payTo: destination, provenance: .localFunding, source: txid)
        let attached = await reopened.sender(forTxidHex: txid)
        XCTAssertEqual(attached?.id, person.id)
        XCTAssertEqual(attached?.payTo, destination)
        XCTAssertEqual(attached?.destinationProvenance, .localFunding)
        XCTAssertEqual(attached?.hasUnverifiedFundingDestination, true)
        let again = PeopleStore(keys: keys)
        _ = await again.configure(storageURL: url, network: .signet)
        let persisted = await again.sender(forTxidHex: txid)
        XCTAssertEqual(persisted?.destinationSource, txid)
    }

    private func personFixture(_ byte: UInt8) throws -> (payTo: PersonPayTo, signer: String) {
        let master = try TestKeys.master(entropyByte: byte)
        let signer = try TestKeys.keyExpression(master: master)
        return (try PersonPayTo.descriptor("tr(\(signer))", network: .signet), signer)
    }

    private func tempStoreURL() -> URL { tempFileURL("sender-labels.json") }

    func testSenderLabelRoundTripPersistsAcrossAReopenAndRemoves() async throws {
        let keys = InMemoryStoreKeyVault()
        let alice = try personFixture(0xA1)
        let url = tempStoreURL()
        defer { try? FileManager.default.removeItem(at: url) }
        let store = PeopleStore(keys: keys)
        await store.configure(storageURL: url, network: .signet)
        let person = try await store.add(name: "Alice", payTo: alice.payTo)
        let txidHex = String(repeating: "ab", count: 32)

        let unlabelled = await store.sender(forTxidHex: txidHex)
        XCTAssertNil(unlabelled)
        do {
            try await store.labelSender(txidHex: txidHex, personID: "no-such-person")
            XCTFail("a label for a missing person was accepted")
        } catch PeopleStorageError.unknownPerson {}
        try await store.labelSender(txidHex: txidHex, personID: person.id)
        let labelled = await store.sender(forTxidHex: txidHex)
        XCTAssertEqual(labelled?.name, "Alice")

        // The label survives reopening the store on the same file.
        let reopened = PeopleStore(keys: keys)
        let result = await reopened.configure(storageURL: url, network: .signet)
        XCTAssertEqual(result, .loaded)
        let persisted = await reopened.sender(forTxidHex: txidHex)
        XCTAssertEqual(persisted?.id, person.id)

        await reopened.removeSenderLabel(txidHex: txidHex)
        let removed = await reopened.sender(forTxidHex: txidHex)
        XCTAssertNil(removed)
        let labels = await reopened.senderLabels
        XCTAssertEqual(labels, [:])
    }

    func testRemovingAPersonDropsTheirSenderLabels() async throws {
        let keys = InMemoryStoreKeyVault()
        let alice = try personFixture(0xA1)
        let bob = try personFixture(0xB2)
        let url = tempStoreURL()
        defer { try? FileManager.default.removeItem(at: url) }
        let store = PeopleStore(keys: keys)
        await store.configure(storageURL: url, network: .signet)
        let a = try await store.add(name: "Alice", payTo: alice.payTo)
        let b = try await store.add(name: "Bob", payTo: bob.payTo)
        let aliceTxid = String(repeating: "a1", count: 32)
        let bobTxid = String(repeating: "b2", count: 32)
        try await store.labelSender(txidHex: aliceTxid, personID: a.id)
        try await store.labelSender(txidHex: bobTxid, personID: b.id)

        try await store.remove(id: a.id)
        let pruned = await store.sender(forTxidHex: aliceTxid)
        XCTAssertNil(pruned)
        let kept = await store.sender(forTxidHex: bobTxid)
        XCTAssertEqual(kept?.name, "Bob")
        do {
            try await store.remove(id: a.id)
            XCTFail("a removed person was removed again")
        } catch PeopleStorageError.unknownPerson {}

        // The pruning is on disk too, not just in memory.
        let reopened = PeopleStore(keys: keys)
        let result = await reopened.configure(storageURL: url, network: .signet)
        XCTAssertEqual(result, .loaded)
        let persistedLabels = await reopened.senderLabels
        XCTAssertEqual(persistedLabels, [bobTxid: b.id])
    }

    func testAPeopleFileFromBeforeSenderLabelsStillDecodes() async throws {
        let keys = InMemoryStoreKeyVault()
        let url = tempFileURL("people-store.json")
        defer { try? FileManager.default.removeItem(at: url) }
        // The pre-labels shape: a bare array of people, no envelope.
        let legacy = Data(#"""
        [{"id":"a1","name":"Alice","payTo":{"kind":"address","value":"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"},"nextPaymentIndex":0}]
        """#.utf8)
        try legacy.write(to: url, options: .atomic)
        let store = PeopleStore(keys: keys)
        let result = await store.configure(storageURL: url, network: .signet)
        XCTAssertEqual(result, .loaded)
        let names = await store.all.map(\.name)
        XCTAssertEqual(names, ["Alice"])
        let labels = await store.senderLabels
        XCTAssertEqual(labels, [:])

        // Mutating upgrades the file to the envelope, keeping everything.
        let people = await store.all
        let person = try XCTUnwrap(people.first)
        let txidHex = String(repeating: "cd", count: 32)
        try await store.labelSender(txidHex: txidHex, personID: person.id)
        XCTAssertTrue(String(decoding: try Data(contentsOf: url), as: UTF8.self).contains("\"senderByTxid\""))
        let reopened = PeopleStore(keys: keys)
        let reopenedResult = await reopened.configure(storageURL: url, network: .signet)
        XCTAssertEqual(reopenedResult, .loaded)
        let persisted = await reopened.sender(forTxidHex: txidHex)
        XCTAssertEqual(persisted?.name, "Alice")
    }

    func testAMalformedLabelInTheFileFailsClosed() async throws {
        let keys = InMemoryStoreKeyVault()
        let url = tempFileURL("people-store.json")
        defer { try? FileManager.default.removeItem(at: url) }
        let damaged = Data(#"{"people":[],"senderByTxid":{"not-a-txid":"a1"}}"#.utf8)
        try damaged.write(to: url, options: .atomic)
        let store = PeopleStore(keys: keys)
        guard case .damaged = await store.configure(storageURL: url, network: .signet) else {
            return XCTFail("a label that names no transaction was accepted")
        }
        XCTAssertEqual(try Data(contentsOf: url), damaged, "a damaged file must not be rewritten")
    }
}

// MARK: - SenderCandidateTests

/// The pure half: which inputs of a received transaction can name a funder.
/// Shapes only, mirroring FundingSourcesTests — no signature is verified.
@MainActor
final class SenderCandidateTests: XCTestCase {
    /// The secp256k1 generator, compressed; its hash160 is the BIP173
    /// reference value.
    private let generator = Data(hex: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")!
    private let generatorHash160 = Data(hex: "751e76e8199196d454941c45d1b3a323f1433bd6")!
    private let derSignature = Data([0x30, 0x44]) + Data(repeating: 0x42, count: 68) + Data([0x01])
    private let schnorrSignature = Data(repeating: 0x5A, count: 64)

    private func input(txid: UInt8 = 0x11, witness: [Data]) -> Transaction.Input {
        Transaction.Input(previousOutput: .init(txid: Data(repeating: txid, count: 32), vout: 0),
                          scriptSig: Data(), sequence: 0xFFFF_FFFE, witness: witness)
    }

    /// An entry as the wallet stores it: the raw is witness-stripped, but the
    /// funding scripts were distilled while the full transaction was in hand.
    private func entry(_ inputs: [Transaction.Input], raw: Bool = true) -> HistoryEntry {
        let transaction = Transaction(version: 2, inputs: inputs,
                                      outputs: [.init(value: 1_000,
                                                      scriptPubKey: Data([0x51, 0x20])
                                                          + Data(repeating: 0x22, count: 32))],
                                      locktime: 0)
        return HistoryEntry(txid: transaction.txid, height: 12, received: 1_000, spent: 0,
                            rawTransaction: raw ? transaction.serialized(includeWitness: false) : nil,
                            fundingScripts: raw ? FundingSources.fundingScripts(of: transaction) : [])
    }

    func testAWitnessKeyHashInputYieldsItsFundingAddress() throws {
        let candidates = AppModel.senderCandidates(
            entry([input(witness: [derSignature, generator])]), network: .mainnet)
        XCTAssertEqual(candidates.count, 1)
        let candidate = try XCTUnwrap(candidates.first)
        XCTAssertEqual(candidate.id, 0)
        XCTAssertEqual(candidate.address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        XCTAssertEqual(candidate.scriptPubKey, Data([0x00, 0x14]) + generatorHash160)
    }

    func testRepeatedFundingScriptsKeepTheFirstSeenInput() {
        let otherKey = Data([0x03]) + Data(repeating: 0x09, count: 32)
        let candidates = AppModel.senderCandidates(entry([
            input(txid: 0x01, witness: [derSignature, generator]),
            input(txid: 0x02, witness: [derSignature, generator]), // the same funder again
            input(txid: 0x03, witness: [schnorrSignature]), // taproot key-path: opaque
            input(txid: 0x04, witness: [derSignature, otherKey]),
        ]), network: .mainnet)
        XCTAssertEqual(candidates.map(\.id), [0, 1])
        XCTAssertEqual(candidates.first?.address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        XCTAssertEqual(Set(candidates.map(\.address)).count, 2)
    }

    func testATaprootKeyPathOnlyTransactionYieldsNoCandidates() {
        let candidates = AppModel.senderCandidates(
            entry([input(witness: [schnorrSignature])]), network: .mainnet)
        XCTAssertTrue(candidates.isEmpty)
    }

    func testAMissingRawTransactionYieldsNoCandidates() {
        let candidates = AppModel.senderCandidates(
            entry([input(witness: [derSignature, generator])], raw: false), network: .mainnet)
        XCTAssertTrue(candidates.isEmpty)
    }
}

// MARK: - EsploraSenderLookupTests

/// The explorer answer's strict decoding, from recorded responses — the
/// lookup itself is never contacted from a test.
final class EsploraSenderLookupTests: XCTestCase {
    func testWrongNetworkDifferentTransactionAndOversizedResponsesFail() {
        let data = Data(#"{"txid":"abcd","vin":[{"prevout":{"scriptpubkey_address":"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"}}]}"#.utf8)
        XCTAssertThrowsError(try EsploraSenderLookup.parseFundingAddresses(data: data, network: .signet))
        XCTAssertThrowsError(try EsploraSenderLookup.parseFundingAddresses(data: data, expectedTxid: "different"))
        XCTAssertThrowsError(try EsploraSenderLookup.parseFundingAddresses(data: Data(repeating: 32, count: EsploraSenderLookup.maximumBytes + 1)))
    }

    func testFundingAddressesAreDistinctInVinOrderAndSkipAddresslessInputs() throws {
        let json = """
        {
          "txid": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
          "version": 2,
          "vin": [
            { "txid": "aa", "vout": 0, "is_coinbase": false,
              "prevout": { "scriptpubkey": "0014751e76e8199196d454941c45d1b3a323f1433bd6",
                           "scriptpubkey_type": "v0_p2wpkh",
                           "scriptpubkey_address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                           "value": 50000 } },
            { "txid": "bb", "vout": 1, "is_coinbase": false,
              "prevout": { "scriptpubkey": "a914000000000000000000000000000000000000000087",
                           "scriptpubkey_type": "p2sh", "value": 1000 } },
            { "txid": "cc", "vout": 2, "is_coinbase": false },
            { "txid": "dd", "vout": 3, "is_coinbase": false,
              "prevout": { "scriptpubkey_type": "p2pkh",
                           "scriptpubkey_address": "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                           "value": 2000 } },
            { "txid": "ee", "vout": 4, "is_coinbase": false,
              "prevout": { "scriptpubkey_address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                           "value": 3000 } }
          ],
          "vout": [],
          "status": { "confirmed": true }
        }
        """
        XCTAssertEqual(try EsploraSenderLookup.parseFundingAddresses(data: Data(json.utf8)),
                       ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                        "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"])
    }

    func testNonconformingAnswersThrow() {
        for (label, json) in [
            ("not json", "this is not json"),
            ("a top-level array", "[]"),
            ("no vin", #"{"txid":"aa","vout":[]}"#),
            ("vin not an array", #"{"vin":{}}"#),
            ("a vin entry that is not an object", #"{"vin":["aa"]}"#),
        ] {
            XCTAssertThrowsError(try EsploraSenderLookup.parseFundingAddresses(data: Data(json.utf8)),
                                 label) { error in
                XCTAssertTrue(error is SenderLookupError, "\(label) threw \(error)")
            }
        }
    }
}
