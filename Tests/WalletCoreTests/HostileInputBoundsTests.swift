import Foundation
import Testing
import TestSupport
@testable import WalletCore

/// Bounds the independent review of 2026-09-14 asked for on inputs the
/// August audit did not see: files are measured before they are read, an
/// error repeats only an excerpt, and BIP39 normalizes the way the
/// specification says. The card and name ceilings are in VaultKit's
/// `CardBoundsTests`. Each test was observed failing against the code it
/// guards before the guard was written.
@Suite("Hostile input bounds")
struct HostileInputBoundsTests {
    private static let words = "abandon abandon abandon abandon abandon abandon "
        + "abandon abandon abandon abandon abandon about"

    /// A sparse file of the given logical size: what a size check sees,
    /// without writing the bytes.
    private func sparseFile(named name: String, bytes: Int) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("winnow-\(name)-\(UUID().uuidString)")
        #expect(FileManager.default.createFile(atPath: url.path, contents: nil))
        let handle = try FileHandle(forWritingTo: url)
        try handle.truncate(atOffset: UInt64(bytes))
        try handle.close()
        return url
    }

    @Test("BIP39 normalizes with NFKD: a compatibility character derives the same seed as its plain form")
    func seedNormalizesNFKD() throws {
        // U+FB01 (ﬁ) and U+FF11 (１) decompose only under NFKD.
        let compatibility = try BIP39.seed(mnemonic: Self.words, passphrase: "\u{FB01}nance\u{FF11}")
        let plain = try BIP39.seed(mnemonic: Self.words, passphrase: "finance1")
        #expect(compatibility == plain)
        #expect(try BIP39.seed(mnemonic: Self.words, passphrase: "\u{FB01}")
            != BIP39.seed(mnemonic: Self.words, passphrase: ""))
    }

    @Test("an error repeats at most an excerpt of bundle-supplied text")
    func errorExcerpt() {
        #expect(ImportBundle.excerpt(String(repeating: "f", count: 10_000)).count == 65)
        #expect(ImportBundle.excerpt("abc") == "abc")
    }

    @Test("a wallet file larger than the ceiling is refused before it is read")
    func oversizedWalletStateRefused() throws {
        let url = try sparseFile(named: "wallet", bytes: Wallet.maximumStateBytes + 1)
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(throws: WalletError.storageTooLarge(maxBytes: Wallet.maximumStateBytes)) {
            try Wallet.open(storageURL: url, keyStore: InMemoryKeyStore())
        }
    }

    @Test("a peers file larger than the ceiling is not read; a small one is")
    func oversizedPeersFileIgnored() throws {
        let url = try sparseFile(named: "peers", bytes: PeerPool.maximumPeersFileBytes + 1)
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(PeerPool.boundedRead(url) == nil)
        try Data("[]".utf8).write(to: url)
        #expect(PeerPool.boundedRead(url) == Data("[]".utf8))
    }

    @Test("a getdata naming one txid many times is served once, and a served peer is not served again")
    func repeatedGetdataServedOnce() async throws {
        let params = NetworkParams.signet
        let node = LoopbackNode(params: params)
        try await node.start()
        defer { Task { await node.stop() } }
        let pool = PeerPool(params: params, peerCount: 1, manualPeers: [await node.endpoint])
        await pool.start()
        let broadcaster = try TxBroadcaster(pool: pool, rebroadcastBaseInterval: .seconds(3_600))
        let seen = EventCollector<TxBroadcaster.Event>()
        let events = await broadcaster.events()
        let consumer = Task { for await event in events { seen.add(event) } }
        defer { consumer.cancel() }

        let tx = makeFakeSegwitTx()
        let txid = try await broadcaster.broadcast(tx.serialized(includeWitness: true))
        guard case .inv = await node.nextMessage(command: "inv") else {
            Issue.record("no inv received")
            return
        }
        let vector = InventoryVector(type: .witnessTx, hash: txid)
        try await node.send(.getdata(InventoryPayload([vector, vector, vector])))
        guard case let .tx(served) = await node.nextMessage(command: "tx") else {
            Issue.record("the transaction was not served")
            return
        }
        #expect(served == tx)
        // The two repeats in the same request are not served, and neither
        // is a fresh request for what this peer already holds.
        #expect(await node.nextMessage(command: "tx", timeout: .milliseconds(500)) == nil)
        try await node.send(.getdata(InventoryPayload([vector])))
        #expect(await node.nextMessage(command: "tx", timeout: .milliseconds(500)) == nil)
        let endpoint = await node.endpoint
        #expect(seen.events.filter { $0 == .served(txid: txid, peer: endpoint) }.count == 1)
        #expect(seen.events.filter { $0 == .requested(txid: txid, peer: endpoint) }.count == 1)
        await pool.stop()
    }

    @Test("sweep removes staging directories a previous process left behind, and nothing else")
    func sweepRemovesLeftovers() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("winnow-sweep-root-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let leftover = root.appendingPathComponent("winnow-export-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: leftover, withIntermediateDirectories: true)
        try Data("seed".utf8).write(to: leftover.appendingPathComponent("wallet.json"))
        let unrelated = root.appendingPathComponent("winnow-other", isDirectory: true)
        try FileManager.default.createDirectory(at: unrelated, withIntermediateDirectories: true)

        ExportStagingFile.sweep(root: root)
        #expect(!FileManager.default.fileExists(atPath: leftover.path))
        #expect(FileManager.default.fileExists(atPath: unrelated.path))
    }
}
