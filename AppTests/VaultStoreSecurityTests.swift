@testable import WinnowApp
import BitcoinCore
import BitcoinP2P
import WalletCore
import XCTest

final class VaultStoreSecurityTests: XCTestCase {
    func testMissingVaultFileIsAnEmptyStore() async {
        let url = temporaryURL()
        let store = VaultStore()

        let result = await store.configure(storageURL: url, network: .signet)
        let records = await store.all
        XCTAssertEqual(result, .missing)
        XCTAssertEqual(records, [])
    }

    func testMalformedVaultFileFailsClosedAndIsNotRewritten() async throws {
        let url = temporaryURL()
        let original = Data("not vault json".utf8)
        try original.write(to: url, options: .atomic)
        defer { try? FileManager.default.removeItem(at: url) }
        let store = VaultStore()

        guard case let .damaged(message) = await store.configure(storageURL: url, network: .signet)
        else { return XCTFail("malformed storage was accepted") }
        XCTAssertTrue(message.contains("left untouched"))
        let records = await store.all
        XCTAssertEqual(records, [])
        XCTAssertEqual(try Data(contentsOf: url), original)
    }

    func testOneInvalidRecordRejectsTheWholeSnapshot() async throws {
        let fixture = try makeFixture()
        var invalid = fixture.record
        invalid.id = "00000000"
        let url = try write([fixture.record, invalid])
        defer { try? FileManager.default.removeItem(at: url) }
        let store = VaultStore()

        guard case .damaged = await store.configure(storageURL: url, network: .signet)
        else { return XCTFail("partially invalid storage was accepted") }
        let records = await store.all
        XCTAssertEqual(records, [])
    }

    func testDuplicateVaultAndOutpointSnapshotsFailClosed() async throws {
        let fixture = try makeFixture()
        var funded = fixture.record
        funded.nextReceiveIndex = 1
        funded.allUtxos = [try funding(vault: fixture.vault, amount: 10_000)]

        var duplicateOutpoint = funded
        duplicateOutpoint.allUtxos.append(funded.allUtxos[0])
        for records in [[fixture.record, fixture.record], [duplicateOutpoint]] {
            let url = try write(records)
            defer { try? FileManager.default.removeItem(at: url) }
            let store = VaultStore()
            guard case .damaged = await store.configure(storageURL: url, network: .signet)
            else { return XCTFail("duplicate persisted identity was accepted") }
        }
    }

    func testWrongScriptAndImpossibleAmountsFailClosed() async throws {
        let fixture = try makeFixture()
        var wrongScript = try funding(vault: fixture.vault, amount: 10_000)
        wrongScript.scriptPubKey = Data([0x51])
        var overMaximum = try funding(vault: fixture.vault, amount: BitcoinAmount.maximum)
        overMaximum.vout = 1
        let oneMore = try funding(vault: fixture.vault, amount: 1)

        let candidates: [[WalletUTXO]] = [
            [wrongScript],
            [try funding(vault: fixture.vault, amount: -1)],
            [overMaximum, oneMore],
        ]
        for utxos in candidates {
            var record = fixture.record
            record.nextReceiveIndex = 1
            record.allUtxos = utxos
            let url = try write([record])
            defer { try? FileManager.default.removeItem(at: url) }
            let store = VaultStore()
            guard case .damaged = await store.configure(storageURL: url, network: .signet)
            else { return XCTFail("invalid vault output metadata was accepted") }
        }
    }

    func testMaximumIndexCannotOverflowLookaheadOrMutation() async throws {
        let fixture = try makeFixture()
        var record = fixture.record
        record.nextReceiveIndex = VaultStore.maximumNextIndex + 1
        let damagedURL = try write([record])
        defer { try? FileManager.default.removeItem(at: damagedURL) }
        let damagedStore = VaultStore()
        guard case .damaged = await damagedStore.configure(storageURL: damagedURL, network: .signet)
        else { return XCTFail("oversized persisted index was accepted") }

        record.nextReceiveIndex = VaultStore.maximumNextIndex
        let validURL = try write([record])
        defer { try? FileManager.default.removeItem(at: validURL) }
        let store = VaultStore()
        let result = await store.configure(storageURL: validURL, network: .signet)
        XCTAssertEqual(result, .loaded)
        do {
            try await store.advanceReceiveIndex(id: record.id)
            XCTFail("maximum index was incremented")
        } catch {
            let currentIndex = await store.all.first?.nextReceiveIndex
            XCTAssertEqual(currentIndex, VaultStore.maximumNextIndex)
        }
    }

    func testFailedPersistenceRollsBackTheLiveSnapshotAndLeavesFileUntouched() async throws {
        enum ExpectedFailure: Error { case write }
        let fixture = try makeFixture()
        let url = try write([fixture.record])
        let original = try Data(contentsOf: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let store = VaultStore(writeData: { _, _ in throw ExpectedFailure.write })
        let result = await store.configure(storageURL: url, network: .signet)
        XCTAssertEqual(result, .loaded)

        do {
            try await store.advanceReceiveIndex(id: fixture.record.id)
            XCTFail("failed persistence was reported as successful")
        } catch ExpectedFailure.write {
            let records = await store.all
            XCTAssertEqual(records, [fixture.record])
            XCTAssertEqual(try Data(contentsOf: url), original)
        }
    }

    private func makeFixture() throws -> (record: VaultRecord, vault: Vault) {
        let masters = try [Data(repeating: 0x31, count: 16), Data(repeating: 0x42, count: 16)]
            .map { try HDKey(seed: BIP39.seed(mnemonic: BIP39.mnemonic(entropy: $0))) }
        let keys = try masters.map { master in
            let account = try master.derived(path: "m/86'/1'/0'")
            return "[\(String(format: "%08x", master.fingerprint))/86'/1'/0']\(account.neutered.serialized(network: .testnet))/<0;1>/*"
        }
        let descriptor = try Vault.multiADescriptor(threshold: 2, cosigners: keys)
        let serialized = descriptor.serialized()
        let id = String(serialized.split(separator: "#").last!)
        return (VaultRecord(id: id, name: "Test vault", descriptor: serialized,
                            createdAtHeight: 100),
                try Vault(descriptor: descriptor, network: .signet))
    }

    private func funding(vault: Vault, amount: Int64) throws -> WalletUTXO {
        WalletUTXO(txid: Data(repeating: UInt8(truncatingIfNeeded: amount), count: 32),
                   vout: 0, amount: amount,
                   scriptPubKey: try vault.scriptPubKey(index: 0),
                   chain: .receive, index: 0, height: 100)
    }

    private func write(_ records: [VaultRecord]) throws -> URL {
        let url = temporaryURL()
        try JSONEncoder().encode(records).write(to: url, options: .atomic)
        return url
    }

    private func temporaryURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("vault-store-\(UUID().uuidString).json")
    }
}
