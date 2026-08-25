import BitcoinCore
import Foundation
import Testing
@testable import BitcoinP2P

/// The broadcaster half of #157: a confirmation is a tombstone, not a
/// deletion, so a reorg that disconnects the confirming block can re-announce
/// the transaction instead of finding its raw bytes gone.
@Suite("TxBroadcaster reorg tombstones")
struct TxBroadcasterReorgTests {
    /// A held entry is silent and invisible — pendingTxids means "in flight",
    /// the raw bytes stay withdrawn (the #155 decision), and the backoff loop
    /// has nothing to run.
    @Test("a confirmed entry is held, not pending")
    func confirmedEntryIsHeld() async throws {
        let pool = PeerPool(params: .signet, peerCount: 0, manualPeers: [])
        let broadcaster = try TxBroadcaster(pool: pool)
        let txid = try await broadcaster.broadcast(
            makeFakeSegwitTx().serialized(includeWitness: true))
        try await broadcaster.markConfirmed(txid, atHeight: 500)

        #expect(await broadcaster.pendingTxids.isEmpty, "held is not in flight")
        #expect(await broadcaster.rawTransaction(txid) == nil,
                "confirmed bytes stay withdrawn, exactly as before this change")
    }

    /// The point of holding it: a reorg above the fork resurrects the entry
    /// and the network hears the transaction again.
    @Test("a reorg past the confirmation re-announces the transaction")
    func reorgReannounces() async throws {
        let params = NetworkParams.signet
        let node = LoopbackNode(params: params)
        try await node.start()
        defer { Task { await node.stop() } }
        let pool = PeerPool(params: params, peerCount: 1, manualPeers: [await node.endpoint])
        await pool.start()
        defer { Task { await pool.stop() } }
        let broadcaster = try TxBroadcaster(pool: pool,
                                            rebroadcastBaseInterval: .milliseconds(100),
                                            maxRebroadcastInterval: .milliseconds(400),
                                            announcementTimeout: .seconds(30))
        let txid = try await broadcaster.broadcast(
            makeFakeSegwitTx().serialized(includeWitness: true))
        #expect(await node.nextMessage(command: "inv") != nil, "initial announcement")

        try await broadcaster.markConfirmed(txid, atHeight: 500)
        #expect(await broadcaster.pendingTxids.isEmpty)

        try await broadcaster.rollBack(to: 400)
        #expect(await broadcaster.pendingTxids == [txid], "in flight again")
        #expect(await node.nextMessage(command: "inv", timeout: .seconds(10)) != nil,
                "the resurrected transaction must reach the wire again")
    }

    /// A fork below the confirmation changes nothing: the block that confirmed
    /// the transaction is still on the surviving chain.
    @Test("a reorg below the confirmation leaves the entry held")
    func shallowReorgLeavesHeld() async throws {
        let pool = PeerPool(params: .signet, peerCount: 0, manualPeers: [])
        let broadcaster = try TxBroadcaster(pool: pool)
        let txid = try await broadcaster.broadcast(
            makeFakeSegwitTx().serialized(includeWitness: true))
        try await broadcaster.markConfirmed(txid, atHeight: 300)

        try await broadcaster.rollBack(to: 350)
        #expect(await broadcaster.pendingTxids.isEmpty,
                "confirmed at 300, fork at 350: the confirmation stands")
    }

    /// Held entries age out on the wallet's own reorg horizon, so the store
    /// cannot grow one entry per confirmed send forever.
    @Test("held entries are pruned past the 100-block horizon")
    func heldEntriesPrune() async throws {
        let pool = PeerPool(params: .signet, peerCount: 0, manualPeers: [])
        let store = tempFileURL("prune-held.json")
        defer { try? FileManager.default.removeItem(at: store.deletingLastPathComponent()) }
        let broadcaster = try TxBroadcaster(pool: pool, storageURL: store)
        let txid = try await broadcaster.broadcast(
            makeFakeSegwitTx().serialized(includeWitness: true))
        try await broadcaster.markConfirmed(txid, atHeight: 500)

        try await broadcaster.pruneConfirmed(scannedTo: 599)
        try await broadcaster.rollBack(to: 400)
        #expect(await broadcaster.pendingTxids == [txid],
                "at 99 deep the entry must survive — the wallet can still reorganise over it")

        try await broadcaster.markConfirmed(txid, atHeight: 500)
        try await broadcaster.pruneConfirmed(scannedTo: 600)
        try await broadcaster.rollBack(to: 400)
        #expect(await broadcaster.pendingTxids.isEmpty,
                "at 100 deep it is gone, the same horizon spent-coin tombstones use")
    }

    /// The tombstone survives a restart, and so does its resurrectability —
    /// a reorg noticed after relaunch still re-announces.
    @Test("a held entry survives a restart and can still be resurrected")
    func heldEntrySurvivesRestart() async throws {
        let pool = PeerPool(params: .signet, peerCount: 0, manualPeers: [])
        let store = tempFileURL("held-restart.json")
        defer { try? FileManager.default.removeItem(at: store.deletingLastPathComponent()) }
        let broadcaster = try TxBroadcaster(pool: pool, storageURL: store)
        let txid = try await broadcaster.broadcast(
            makeFakeSegwitTx().serialized(includeWitness: true))
        try await broadcaster.markConfirmed(txid, atHeight: 500)

        let reloaded = try TxBroadcaster(pool: pool, storageURL: store)
        #expect(await reloaded.pendingTxids.isEmpty, "still held after the restart")
        #expect(await reloaded.rawTransaction(txid) == nil, "still withdrawn after the restart")

        try await reloaded.rollBack(to: 400)
        #expect(await reloaded.pendingTxids == [txid],
                "the raw bytes survived the restart precisely so this works")
    }
}
