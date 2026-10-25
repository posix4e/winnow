@testable import WinnowApp
import WalletCore
import Foundation
import TestSupport
import XCTest

/// What the app's persisted stores promise about their files.
///
/// Three stores keep JSON on disk and two of them make the same five promises:
/// a missing file is an empty store, a file that cannot be read fails the
/// whole snapshot closed, that file is never rewritten, one invalid record
/// rejects the snapshot rather than loading the readable part, and a failed
/// write rolls the live snapshot back and leaves the file alone. Those shapes
/// are written once, below, and applied per store.
///
/// What each store does on its own — index ceilings, refused increments,
/// coinbase flags, duplicate-key refusals, and the relay store's quarantine —
/// stays as its own test, because that is where the stores actually differ.

// MARK: - The shared fail-closed harness

/// What a store made of the file it was pointed at. The stores answer with
/// their own result types; this is the one shape the shapes below need.
private enum StoreOpenOutcome: Equatable, Sendable {
    case missing
    case loaded
    case damaged(String)
}

/// The error an injected `writeData` throws, so a shape can tell a refused
/// write from any other failure and does not silently accept the wrong one.
private enum StoreWriteFailure: Error { case expected }

/// One store's fail-closed surface, as the shapes need to see it.
///
/// Closures rather than a protocol: each store has its own result type and its
/// own first mutation, and every closure here captures nothing but the actor
/// it drives, so a fixture is `Sendable` and a shape can be called from any
/// isolation. The three closures a given shape does not use default to no-ops.
private struct StoreFixture: Sendable {
    /// Names the store in failure messages.
    let name: String
    /// The file the store keeps its snapshot in.
    let snapshotURL: URL
    /// Damages the file and hands back exactly the bytes it left there, so a
    /// shape can prove the store did not rewrite them.
    var damage: @Sendable () throws -> Data = { Data() }
    /// Writes a snapshot the store loads cleanly.
    var writeValid: @Sendable () throws -> Void = {}
    /// Points the store at `snapshotURL` and reports what it made of it.
    let configure: @Sendable () async -> StoreOpenOutcome
    /// How many records the store holds now.
    let recordCount: @Sendable () async -> Int
    /// The store's first persisting mutation.
    var mutate: @Sendable () async throws -> Void = {}
}

/// A store with no file yet is an empty store, not a failure.
private func assertMissingFileIsAnEmptyStore(
    _ fixture: StoreFixture,
    file: StaticString = #filePath, line: UInt = #line
) async {
    let outcome = await fixture.configure()
    let count = await fixture.recordCount()
    XCTAssertEqual(outcome, .missing,
                   "\(fixture.name) did not report a missing file as missing",
                   file: file, line: line)
    XCTAssertEqual(count, 0,
                   "\(fixture.name) produced records for a file that is not there",
                   file: file, line: line)
}

/// A snapshot that cannot be read fails the whole store closed, and the file
/// it could not read is left byte for byte as it was: those bytes are the only
/// evidence of what went wrong.
private func assertDamagedSnapshotFailsClosedAndIsNotRewritten(
    _ fixture: StoreFixture,
    file: StaticString = #filePath, line: UInt = #line
) async throws {
    let original = try fixture.damage()
    guard case let .damaged(message) = await fixture.configure() else {
        return XCTFail("\(fixture.name) accepted malformed storage", file: file, line: line)
    }
    XCTAssertTrue(message.contains("left untouched"),
                  "\(fixture.name) did not tell the user its file was kept",
                  file: file, line: line)
    let count = await fixture.recordCount()
    XCTAssertEqual(count, 0,
                   "\(fixture.name) kept records from a file it refused",
                   file: file, line: line)
    XCTAssertEqual(try Data(contentsOf: fixture.snapshotURL), original,
                   "\(fixture.name) rewrote a file it could not read",
                   file: file, line: line)
}

/// One invalid record is enough: the snapshot is rejected whole rather than
/// the store loading the part of it that happens to parse.
private func assertOneInvalidRecordRejectsTheWholeSnapshot(
    _ fixture: StoreFixture,
    file: StaticString = #filePath, line: UInt = #line
) async throws {
    _ = try fixture.damage()
    guard case .damaged = await fixture.configure() else {
        return XCTFail("\(fixture.name) accepted partially invalid storage",
                       file: file, line: line)
    }
    let count = await fixture.recordCount()
    XCTAssertEqual(count, 0,
                   "\(fixture.name) loaded records out of a rejected snapshot",
                   file: file, line: line)
}

/// A write that fails leaves the file exactly as it was, so what is on screen
/// and what is on disk never disagree. Any error other than the injected one
/// escapes and fails the test rather than passing as a rollback.
private func assertFailedWriteRollsBackAndLeavesTheFileUntouched(
    _ fixture: StoreFixture,
    file: StaticString = #filePath, line: UInt = #line
) async throws {
    try fixture.writeValid()
    let original = try Data(contentsOf: fixture.snapshotURL)
    let outcome = await fixture.configure()
    XCTAssertEqual(outcome, .loaded, "\(fixture.name) did not load a valid snapshot",
                   file: file, line: line)
    do {
        try await fixture.mutate()
        XCTFail("\(fixture.name) reported a failed write as successful", file: file, line: line)
    } catch StoreWriteFailure.expected {
        XCTAssertEqual(try Data(contentsOf: fixture.snapshotURL), original,
                       "\(fixture.name) changed a file the failed write must not have touched",
                       file: file, line: line)
    }
}

// MARK: - Per-store fixtures

/// The people file's envelope as a test reads it back: the records plus
/// the sender-label map added after the file was a bare array of people.
private struct PeopleFileProbe: Decodable {
    var people: [PersonRecord]
    var senderByTxid: [String: String]
}

/// The people store as the shapes see it. Its first persisting mutation is
/// adding somebody, so `mutate` adds `newcomer`.
private func peopleStoreFixture(
    _ store: PeopleStore,
    url: URL,
    record: PersonRecord = PersonRecord(id: "unused", name: "unused", payTo: nil),
    newcomer: PersonPayTo? = nil,
    damage: @escaping @Sendable () throws -> Data = { Data() }
) -> StoreFixture {
    StoreFixture(
        name: "the people store",
        snapshotURL: url,
        damage: damage,
        writeValid: { try JSONEncoder().encode([record]).write(to: url, options: .atomic) },
        configure: { await store.configure(storageURL: url, network: .signet).outcome },
        recordCount: { await store.all.count },
        mutate: { _ = try await store.add(name: "Bob", payTo: newcomer) })
}
private extension PeopleStorageOpenResult {
    var outcome: StoreOpenOutcome {
        switch self {
        case .missing: .missing
        case .loaded: .loaded
        case let .damaged(message): .damaged(message)
        }
    }
}

// MARK: - Writing snapshots

/// Writes `bytes` at `url` and hands them back, so a `damage` closure reads as
/// one expression.
private func writeBytes(_ bytes: Data, to url: URL) throws -> Data {
    try bytes.write(to: url, options: .atomic)
    return bytes
}

/// Encodes a snapshot at `url` and hands back the bytes it wrote. Both record
/// stores persist a plain array, so one helper serves them.
private func writeSnapshot<Record: Encodable>(_ records: [Record], to url: URL) throws -> Data {
    let data = try JSONEncoder().encode(records)
    return try writeBytes(data, to: url)
}

/// The same, into a fresh temporary file, for the cases that only need the
/// store to refuse what is there.
private func snapshotFile<Record: Encodable>(_ records: [Record], named name: String) throws -> URL {
    let url = tempFileURL(name)
    _ = try writeSnapshot(records, to: url)
    return url
}

// MARK: - PeopleStoreSecurityTests

/// The address book file fails the whole snapshot closed, never rewrites
/// what could not be read, and rolls back a failed write. Plus the one thing
/// that is its own: while damaged, it refuses every mutation instead of
/// taking the app down.
final class PeopleStoreSecurityTests: XCTestCase {
    func testMissingFileIsAnEmptyStore() async {
        let keys = InMemoryStoreKeyVault()
        await assertMissingFileIsAnEmptyStore(
            peopleStoreFixture(PeopleStore(keys: keys), url: tempFileURL("people-store.json")))
    }

    func testMalformedFileFailsClosedRefusesMutationsAndIsNotRewritten() async throws {
        let keys = InMemoryStoreKeyVault()
        let url = tempFileURL("people-store.json")
        defer { try? FileManager.default.removeItem(at: url) }
        let original = Data("not people json".utf8)
        let store = PeopleStore(keys: keys)
        try await assertDamagedSnapshotFailsClosedAndIsNotRewritten(
            peopleStoreFixture(store, url: url, damage: { try writeBytes(original, to: url) }))

        let alice = try fixture(0xA1)
        do {
            try await store.add(name: "Alice", payTo: alice.payTo)
            XCTFail("a damaged store accepted a mutation")
        } catch PeopleStorageError.damaged {}
        XCTAssertEqual(try Data(contentsOf: url), original)
    }

    func testOneInvalidRecordRejectsTheWholeSnapshot() async throws {
        let keys = InMemoryStoreKeyVault()
        let alice = try fixture(0xA1)
        let good = PersonRecord(id: "one", name: "Alice", payTo: alice.payTo)
        var nameless = good
        nameless.id = "two"
        nameless.name = "  "
        nameless.payTo = try fixture(0xB2).payTo
        let damaged = nameless // immutable copy: the closure below runs concurrently
        let url = tempFileURL("people-store.json")
        defer { try? FileManager.default.removeItem(at: url) }
        try await assertOneInvalidRecordRejectsTheWholeSnapshot(
            peopleStoreFixture(PeopleStore(keys: keys), url: url,
                               damage: { try writeSnapshot([good, damaged], to: url) }))
    }

    func testSharedKeysAndBadRecordsInTheFileFailClosed() async throws {
        let keys = InMemoryStoreKeyVault()
        let alice = try fixture(0xA1)
        let bob = try fixture(0xB2)
        let base = PersonRecord(id: "one", name: "Alice", payTo: alice.payTo)

        var sharedPayTo = PersonRecord(id: "two", name: "Bob", payTo: alice.payTo)
        var duplicateID = base
        duplicateID.name = "Alice again"
        duplicateID.payTo = bob.payTo
        var outOfRange = base
        outOfRange.nextPaymentIndex = PeopleStore.maximumNextIndex + 1
        var wrongNetwork = base
        wrongNetwork.payTo = .address("bc1qexample")
        sharedPayTo.nextPaymentIndex = 0

        for (label, records) in [
            ("shared pay-to", [base, sharedPayTo]),
            ("duplicate id", [base, duplicateID]),
            ("index out of range", [outOfRange]),
            ("wrong network address", [wrongNetwork]),
        ] {
            let url = try snapshotFile(records, named: "people-store.json")
            defer { try? FileManager.default.removeItem(at: url) }
            let store = PeopleStore(keys: keys)
            guard case .damaged = await store.configure(storageURL: url, network: .signet)
            else { return XCTFail("\(label) was accepted") }
        }
    }

    func testAddRefusesASecondEntryForTheSameKeyEvenRelabelled() async throws {
        let keys = InMemoryStoreKeyVault()
        let alice = try fixture(0xA1)
        let store = PeopleStore(keys: keys)
        let url = tempFileURL("people-store.json")
        defer { try? FileManager.default.removeItem(at: url) }
        await store.configure(storageURL: url, network: .signet)
        try await store.add(name: "Alice", payTo: alice.payTo)

        // Same account key, hardened marker spelled the other way.
        let relabelled = try PersonPayTo.descriptor("tr(\(alice.key.replacingOccurrences(of: "'", with: "h")))",
                                                    network: .signet)
        XCTAssertEqual(relabelled, alice.payTo, "the canonical form spells the marker one way")
        do {
            try await store.add(name: "Alice twice", payTo: relabelled)
            XCTFail("the same key was admitted twice")
        } catch PeopleStorageError.duplicate(let existing) {
            XCTAssertEqual(existing, "Alice")
        }
        do {
            try await store.add(name: "Alice by address",
                                payTo: .address(try alice.payTo.address(index: 0, network: .signet)))
            XCTFail("the same pay-to script was admitted twice")
        } catch PeopleStorageError.duplicate(let existing) {
            XCTAssertEqual(existing, "Alice")
        }
        // A name alone is a valid label-only person (received payments can
        // be labelled before any address is known), so "Nobody" now saves.
        let nobody = try await store.add(name: "Nobody", payTo: nil)
        XCTAssertNil(nobody.payTo)
        let records = await store.all
        XCTAssertEqual(records.count, 2)
        XCTAssertEqual(try JSONDecoder().decode(PeopleFileProbe.self, from: unsealedPayload(of: url)).people, records)
        XCTAssertTrue(String(decoding: try Data(contentsOf: url), as: UTF8.self).contains("/<0;1>/*"),
                      "the file keeps key expressions readable")
    }

    func testPaymentIndexAdvancesMonotonicallyAndIdempotently() async throws {
        let keys = InMemoryStoreKeyVault()
        let alice = try fixture(0xA1)
        let store = PeopleStore(keys: keys)
        let url = tempFileURL("people-store.json")
        defer { try? FileManager.default.removeItem(at: url) }
        await store.configure(storageURL: url, network: .signet)
        let record = try await store.add(name: "Alice", payTo: alice.payTo)
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
        let reopened = PeopleStore(keys: keys)
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
        let keys = InMemoryStoreKeyVault()
        let alice = try fixture(0xA1)
        let record = PersonRecord(id: "one", name: "Alice", payTo: alice.payTo)
        let url = tempFileURL("people-store.json")
        defer { try? FileManager.default.removeItem(at: url) }
        let store = PeopleStore(keys: keys, writeData: { _, _ in throw StoreWriteFailure.expected })
        try await assertFailedWriteRollsBackAndLeavesTheFileUntouched(
            peopleStoreFixture(store, url: url, record: record,
                               newcomer: try fixture(0xB2).payTo))
        let records = await store.all
        XCTAssertEqual(records, [record], "the live snapshot rolled forward")
    }

    func testRenameAndUnsavePreserveKeysAndAddressCounter() async throws {
        let keys = InMemoryStoreKeyVault()
        let alice = try fixture(0xA1)
        let bob = try fixture(0xB2)
        let store = PeopleStore(keys: keys)
        let url = tempFileURL("people-store.json")
        defer { try? FileManager.default.removeItem(at: url) }
        await store.configure(storageURL: url, network: .signet)
        let a = try await store.add(name: "Alice", payTo: alice.payTo)
        let b = try await store.add(name: "Bob", payTo: bob.payTo)
        try await store.advancePaymentIndex(id: b.id, past: 6)
        try await store.updateRecipient(id: b.id, name: "Robert", saved: true)
        let renamed = try await store.updateRecipient(id: b.id, saved: false)
        XCTAssertEqual(renamed.name, "Robert")
        XCTAssertEqual(renamed.nextPaymentIndex, 7)
        XCTAssertTrue(a.isSavedRecipient, "older records without the flag remain saved")
        let reopened = PeopleStore(keys: keys)
        await reopened.configure(storageURL: url, network: .signet)
        let hidden = await reopened.record(id: b.id)
        XCTAssertFalse(try XCTUnwrap(hidden).isSavedRecipient)
        let restored = try await reopened.add(name: "Robert", payTo: bob.payTo)
        XCTAssertEqual(restored.id, b.id)
        XCTAssertEqual(restored.nextPaymentIndex, 7)
        XCTAssertTrue(restored.isSavedRecipient)
    }

    // MARK: Fixtures

    private struct Fixture {
        var payTo: PersonPayTo
        var key: String
    }

    private func fixture(_ byte: UInt8) throws -> Fixture {
        let key = try TestKeys.keyExpression(master: TestKeys.master(entropyByte: byte))
        return Fixture(payTo: try PersonPayTo.descriptor("tr(\(key))", network: .signet), key: key)
    }
}

// MARK: - RelayStoreQuarantineTests

/// A damaged relay store must not stop the wallet from syncing (#150).
///
/// The three stores the app keeps are not equally important. Rebroadcast state
/// is best-effort — it exists so a pending transaction keeps being announced,
/// and the wallet's own history is the source of truth for balance and
/// confirmations. Headers and filters are what make the wallet work at all.
///
/// Constructing the broadcaster inside the sync-stack build inverted that: one
/// damaged record in the least important store threw out of the whole build,
/// `stack` was never assigned, and neither header nor filter sync started.
/// Because nothing repaired the file, every relaunch failed identically — and
/// it surfaced as a sync error, so the user had no way of knowing that
/// deleting a file they cannot see was the remedy.
///
/// This store keeps its own class and its own assertions rather than joining
/// the harness above. Its contract is the negation of the shared one: a file
/// it cannot read is *moved aside* and the path reused, where the record
/// stores leave theirs untouched and refuse. It is also `@MainActor`, because
/// the broadcaster is built through `AppModel`, while the record stores are
/// nonisolated actors.
@MainActor
final class RelayStoreQuarantineTests: XCTestCase {
    private func pool() -> PeerPool {
        PeerPool(params: .signet, peerCount: 0, manualPeers: [])
    }

    /// Every shape `load` refuses. Each is a distinct rejection path, so one
    /// broad case would pass even if the others stopped being handled.
    private var damagedStores: [(label: String, bytes: Data)] {
        [
            ("not json at all", Data("this is not json".utf8)),
            ("json of the wrong shape", Data(#"{"version":1,"transactions":"nope"}"#.utf8)),
            ("unsupported version", Data(#"{"version":9999,"transactions":{}}"#.utf8)),
            ("truncated mid-object", Data(#"{"version":1,"transactions":{"ab"#.utf8)),
            ("empty file", Data()),
        ]
    }

    // MARK: The defect

    /// The property that keeps the stack build alive: this must not throw.
    func testDamagedStoreDoesNotThrowOutOfTheBuild() throws {
        for store in damagedStores {
            let url = tempFileURL("broadcast.json")
            defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
            try store.bytes.write(to: url)

            let model = makeModel()
            XCTAssertNoThrow(try model.makeBroadcaster(pool: pool(), storageURL: url),
                             "a \(store.label) store must not take the sync stack down with it")
        }
    }

    /// The damaged file is kept, not deleted: it is the only evidence of what
    /// went wrong and may hold transactions worth recovering by hand.
    func testDamagedStoreIsQuarantinedRatherThanDeleted() throws {
        let url = tempFileURL("broadcast.json")
        let dir = url.deletingLastPathComponent()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = Data("this is not json".utf8)
        try original.write(to: url)

        let model = makeModel()
        _ = try model.makeBroadcaster(pool: pool(), storageURL: url)

        let quarantine = dir.appending(path: AppModel.quarantinedRelayStoreName)
        XCTAssertEqual(try Data(contentsOf: quarantine), original,
                       "the damaged bytes must survive for diagnosis")
    }

    /// …and the original path is usable again, so relay starts fresh rather
    /// than failing identically on every relaunch.
    func testOriginalPathIsUsableAgain() async throws {
        let url = tempFileURL("broadcast.json")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        try Data("this is not json".utf8).write(to: url)

        let model = makeModel()
        let broadcaster = try model.makeBroadcaster(pool: pool(), storageURL: url)
        let pending = await broadcaster.pendingTxids
        XCTAssertTrue(pending.isEmpty, "a fresh broadcaster starts with an empty queue")

        // A second construction on the same path now succeeds cleanly, which
        // is what "recovers on its own" means.
        XCTAssertNoThrow(try model.makeBroadcaster(pool: pool(), storageURL: url))
    }

    /// Reported as a relay problem, not as a sync failure — sync is fine.
    func testSurfacedAsARelayProblemNotASyncFailure() throws {
        let url = tempFileURL("broadcast.json")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        try Data("this is not json".utf8).write(to: url)

        let model = makeModel()
        _ = try model.makeBroadcaster(pool: pool(), storageURL: url)

        let message = try XCTUnwrap(model.status.relayStoreQuarantined)
        XCTAssertTrue(message.contains(AppModel.quarantinedRelayStoreName),
                      "the message must name the file it set aside")
        XCTAssertNil(model.status.lastSyncError,
                     "sync did not fail; saying so would send the user after the wrong problem")
    }

    /// The notice has to survive `refresh`, which rebuilds the status snapshot
    /// from the stores. A quarantine is a fact about the launch, not something
    /// any store reports, so it is carried across like `lastSyncError` -- and
    /// without that it is wiped by the refresh that runs moments after the
    /// stack is built, leaving the user's relay queue silently gone.
    func testTheNoticeSurvivesARefresh() async throws {
        let url = tempFileURL("broadcast.json")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        try Data("this is not json".utf8).write(to: url)

        let model = makeModel()
        _ = try model.makeBroadcaster(pool: pool(), storageURL: url)
        XCTAssertNotNil(model.status.relayStoreQuarantined)

        await model.refresh()
        XCTAssertNotNil(model.status.relayStoreQuarantined,
                        "a refresh must not wipe the only notice the user gets")
    }

    /// Record-level damage, which is the realistic case: the file parses, the
    /// shape is right, and one transaction inside it is out of range. This is
    /// the state an unclamped retry counter used to produce.
    func testRecordLevelDamageIsQuarantinedToo() async throws {
        let url = tempFileURL("broadcast.json")
        let dir = url.deletingLastPathComponent()
        defer { try? FileManager.default.removeItem(at: dir) }

        // A real store, then one field pushed out of range, so the rest of the
        // record stays valid and only the per-record validation objects.
        let seed = makeModel()
        let broadcaster = try seed.makeBroadcaster(pool: pool(), storageURL: url)
        _ = try await broadcaster.broadcast(signedTransactionBytes)
        await broadcaster.shutdown()

        var json = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
        var transactions = json["transactions"] as! [String: Any]
        let key = transactions.keys.first!
        var record = transactions[key] as! [String: Any]
        record["attempt"] = 9_999
        transactions[key] = record
        json["transactions"] = transactions
        try JSONSerialization.data(withJSONObject: json).write(to: url)

        let model = makeModel()
        XCTAssertNoThrow(try model.makeBroadcaster(pool: pool(), storageURL: url))
        XCTAssertNotNil(model.status.relayStoreQuarantined)
        XCTAssertTrue(FileManager.default.fileExists(
            atPath: dir.appending(path: AppModel.quarantinedRelayStoreName).path()))
    }

    /// The control. A healthy store must load normally and quarantine nothing,
    /// or the tests above would pass against a build that always quarantines.
    func testHealthyStoreIsLeftAlone() throws {
        let url = tempFileURL("broadcast.json")
        let dir = url.deletingLastPathComponent()
        defer { try? FileManager.default.removeItem(at: dir) }

        // Written by the broadcaster itself, so this is a real store.
        let seed = makeModel()
        _ = try seed.makeBroadcaster(pool: pool(), storageURL: url)

        let model = makeModel()
        XCTAssertNoThrow(try model.makeBroadcaster(pool: pool(), storageURL: url))
        XCTAssertNil(model.status.relayStoreQuarantined,
                     "an undamaged store must not be set aside")
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: dir.appending(path: AppModel.quarantinedRelayStoreName).path()))
    }

    /// A second failure keeps the most recent evidence rather than refusing to
    /// move because the destination exists.
    func testASecondQuarantineReplacesTheFirst() throws {
        let url = tempFileURL("broadcast.json")
        let dir = url.deletingLastPathComponent()
        defer { try? FileManager.default.removeItem(at: dir) }
        let model = makeModel()

        try Data("first damage".utf8).write(to: url)
        _ = try model.makeBroadcaster(pool: pool(), storageURL: url)
        try Data("second damage".utf8).write(to: url)
        _ = try model.makeBroadcaster(pool: pool(), storageURL: url)

        let quarantine = dir.appending(path: AppModel.quarantinedRelayStoreName)
        XCTAssertEqual(try Data(contentsOf: quarantine), Data("second damage".utf8))
    }
}
