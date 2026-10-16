import Foundation
import Testing
import TestSupport
@testable import WalletCore

@Suite("Wallet cursor reservations")
struct WalletCursorTests {
    @Test("restored cursors survive reopening and backup without reissuing reserved addresses")
    func durableReservations() async throws {
        let file = tempFileURL("wallet.json")
        defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
        let store = InMemoryKeyStore()
        let wallet = try makeTestWallet(storageURL: file, keyStore: store)
        try await wallet.recordScanHeight(500)
        try await wallet.advanceCursors(nextReceiveIndex: 12, nextChangeIndex: 8)
        let scripts = Set(try await wallet.watchScripts())
        for chain in [AddressChain.receive, .change] {
            let cursor: UInt32 = chain == .receive ? 12 : 8
            for index in 0 ..< cursor + Wallet.gapLimit {
                #expect(scripts.contains(try await wallet.scriptPubKey(chain: chain, index: index)))
            }
        }
        let reopened = try Wallet.open(storageURL: file, keyStore: store)
        #expect(await reopened.nextReceiveIndex == 12)
        #expect(await reopened.nextChangeIndex == 8)
        #expect(await reopened.nextScanHeight == 500)
        #expect(try await reopened.freshReceiveAddress()
            == (try await wallet.address(chain: .receive, index: 12)))
        let bundle = try await reopened.exportBundle()
        let restored = try Wallet.importing(bundle, keyStore: InMemoryKeyStore())
        #expect(await restored.nextReceiveIndex == 13)
        #expect(await restored.nextChangeIndex == 8)
        #expect(await restored.nextScanHeight == 500)
    }

    @Test("omitted, equal and lower cursors do not write or rewind either chain")
    func monotonicNoOp() async throws {
        let file = tempFileURL("wallet.json")
        defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
        let wallet = try makeTestWallet(storageURL: file)
        try await wallet.advanceCursors(nextReceiveIndex: 4, nextChangeIndex: 9)
        try FileManager.default.removeItem(at: file)
        try FileManager.default.createDirectory(at: file, withIntermediateDirectories: false)
        // A no-op works even when writing would fail.
        try await wallet.advanceCursors()
        try await wallet.advanceCursors(nextReceiveIndex: 4, nextChangeIndex: 2)
        #expect(await wallet.nextReceiveIndex == 4)
        #expect(await wallet.nextChangeIndex == 9)
    }

    @Test("failed persistence changes neither cursor and the reservation can be retried")
    func atomicFailure() async throws {
        let file = tempFileURL("wallet.json")
        defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
        let store = InMemoryKeyStore()
        let wallet = try makeTestWallet(storageURL: file, keyStore: store)
        let previous = try Data(contentsOf: file)
        try FileManager.default.removeItem(at: file)
        try FileManager.default.createDirectory(at: file, withIntermediateDirectories: false)
        await #expect(throws: (any Error).self) {
            try await wallet.advanceCursors(nextReceiveIndex: 12, nextChangeIndex: 8)
        }
        #expect(await wallet.nextReceiveIndex == 0)
        #expect(await wallet.nextChangeIndex == 0)
        try FileManager.default.removeItem(at: file)
        try previous.write(to: file)
        let reopened = try Wallet.open(storageURL: file, keyStore: store)
        #expect(await reopened.nextReceiveIndex == 0)
        #expect(await reopened.nextChangeIndex == 0)
        try await wallet.advanceCursors(nextReceiveIndex: 12, nextChangeIndex: 8)
        let retried = try Wallet.open(storageURL: file, keyStore: store)
        #expect(await retried.nextReceiveIndex == 12)
        #expect(await retried.nextChangeIndex == 8)
    }

    @Test("hardened and overflowing lookahead cursors are refused atomically",
          arguments: [HDKey.hardenedOffset - Wallet.gapLimit + 1, HDKey.hardenedOffset, UInt32.max])
    func invalidCursor(_ cursor: UInt32) async throws {
        let wallet = try makeTestWallet()
        await #expect(throws: BIP32Error.invalidPath) {
            try await wallet.advanceCursors(nextReceiveIndex: 3, nextChangeIndex: cursor)
        }
        #expect(await wallet.nextReceiveIndex == 0)
        #expect(await wallet.nextChangeIndex == 0)
        await #expect(throws: BIP32Error.invalidPath) {
            try await wallet.advanceCursors(nextReceiveIndex: cursor, nextChangeIndex: 3)
        }
        #expect(await wallet.nextReceiveIndex == 0)
        #expect(await wallet.nextChangeIndex == 0)
    }

    @Test("concurrent reservations keep each chain's highest cursor")
    func concurrentReservations() async throws {
        let wallet = try makeTestWallet()
        try await withThrowingTaskGroup(of: Void.self) { tasks in
            for index: UInt32 in 1 ... 20 {
                tasks.addTask {
                    try await wallet.advanceCursors(nextReceiveIndex: index, nextChangeIndex: 21 - index)
                }
            }
            try await tasks.waitForAll()
        }
        #expect(await wallet.nextReceiveIndex == 20)
        #expect(await wallet.nextChangeIndex == 20)
    }

    /// The same bound on the way in from disk. A state file naming a cursor
    /// the lookahead cannot derive from is reported as damage once, rather
    /// than trapping in `watchScripts` on every launch until the app's data
    /// is deleted.
    @Test("a state file with a cursor past the gap-limit window is damaged, not a crash loop")
    func cursorPastTheWindowIsDamage() async throws {
        let file = tempFileURL("wallet.json")
        defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
        let store = InMemoryKeyStore()
        let wallet = try makeTestWallet(storageURL: file, keyStore: store)
        try await wallet.advanceCursors(nextReceiveIndex: 3)
        let object = try JSONSerialization.jsonObject(with: Data(contentsOf: file))
        var json = try #require(object as? [String: Any])
        json["nextReceiveIndex"] = UInt32.max
        try JSONSerialization.data(withJSONObject: json).write(to: file)
        #expect(throws: (any Error).self) { _ = try Wallet.open(storageURL: file, keyStore: store) }

        json["nextReceiveIndex"] = HDKey.hardenedOffset - Wallet.gapLimit
        try JSONSerialization.data(withJSONObject: json).write(to: file)
        let reopened = try Wallet.open(storageURL: file, keyStore: store)
        #expect(await reopened.nextReceiveIndex == HDKey.hardenedOffset - Wallet.gapLimit)
    }
}
