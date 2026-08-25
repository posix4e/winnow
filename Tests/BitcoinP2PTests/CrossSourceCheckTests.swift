import Foundation
import Testing
@testable import BitcoinP2P

/// The cross-source half of #3: comparisons must span acquisition channels.
///
/// The diversity ceiling (#159) stops one source class owning the pool, but
/// the per-batch cfheaders cross-check took `prefix(2)` — whichever two peers
/// connected first — and the ceiling permits two seats from one class. A DNS
/// seed's answer compared against the same seed's other answer is one channel
/// agreeing with itself: the comparison the defence rests on, hollowed out
/// exactly when an attacker controls that channel.
@Suite("Cross-source cfheaders check")
struct CrossSourceCheckTests {
    private func connection(_ index: UInt8) -> PeerConnection {
        PeerConnection(endpoint: PeerEndpoint(host: "10.0.\(index).1", port: 1),
                       params: .signet)
    }

    // MARK: - The pure selection policy

    @Test("two classes present: the pair spans them")
    func pairSpansClasses() {
        let a = connection(1), b = connection(2), c = connection(3)
        let picked = FilterSync.crossSourcePair([(a, .dnsSeed), (b, .dnsSeed), (c, .persisted)])
        #expect(picked.count == 2)
        #expect(picked[0] === a)
        #expect(picked[1] === c, "the second same-class peer must be passed over for the other channel")
    }

    @Test("one class present: any two, the degraded mode")
    func singleClassDegrades() {
        let a = connection(1), b = connection(2)
        let picked = FilterSync.crossSourcePair([(a, .dnsSeed), (b, .dnsSeed)])
        #expect(picked.count == 2, "same-class is degraded, not refused — like a single-peer pool")
        #expect(picked[0] === a && picked[1] === b)
    }

    @Test("an unknown source counts as its own channel")
    func unknownIsItsOwnClass() {
        let a = connection(1), b = connection(2), c = connection(3)
        let picked = FilterSync.crossSourcePair([(a, nil), (b, nil), (c, .fallback)])
        #expect(picked[1] === c, "known-vs-unknown is more diverse than unknown-vs-unknown")
    }

    @Test("one peer or none: what there is")
    func degenerateCounts() {
        let a = connection(1)
        #expect(FilterSync.crossSourcePair([]).isEmpty)
        #expect(FilterSync.crossSourcePair([(a, .manual)]).count == 1)
    }

    // MARK: - The wiring, on the wire

    /// Three honest peers: two manual, one persisted, with the persisted one
    /// deliberately last to connect. `prefix(2)` would query the two manuals
    /// and never the other channel; the selection must reach it.
    @Test("the cross-check reaches the second source class")
    func secondClassIsQueried() async throws {
        let synthetic = makeSyntheticChain(length: 6, watchHeight: 3)
        let manualA = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        let manualB = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        // The version delay makes the persisted peer the *last* to be seated,
        // so the pre-#3 prefix(2) deterministically never reaches it — which
        // is what makes the mutation of this test fail every run rather than
        // one run in three.
        let persisted = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                     versionDelay: .milliseconds(300))
        try await manualA.start()
        try await manualB.start()
        try await persisted.start()
        defer { Task { await manualA.stop(); await manualB.stop(); await persisted.stop() } }

        let peersFile = tempFileURL("cross-source-peers.json")
        let stored = PersistedPeers([PeerCandidate(endpoint: await persisted.endpoint,
                                                   source: .persisted)])
        try JSONEncoder().encode(stored).write(to: peersFile)

        let pool = PeerPool(params: synthetic.params, peerCount: 3,
                            manualPeers: [await manualA.endpoint, await manualB.endpoint],
                            peersFileURL: peersFile)
        await pool.start()
        #expect(await pool.connectedPeers().count == 3)
        #expect(await pool.source(of: persisted.endpoint) == .persisted)

        let chain = try HeaderChain(params: synthetic.params)
        let sync = try FilterSync(pool: pool, chain: chain, startHeight: 1,
                                  storageURL: tempFileURL("cross-source-progress.json"),
                                  requiredCheckpointPeers: 3)
        try await sync.sync(watchScripts: [synthetic.watchScript]) { _ in }

        #expect(await persisted.nextMessage(command: "getcfheaders", timeout: .seconds(2)) != nil,
                "the persisted channel was never asked — the cross-check compared one class with itself")
        await pool.stop()
    }
}
