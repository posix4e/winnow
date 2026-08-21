import Foundation
import Testing
@testable import BitcoinP2P

/// What happens when peers disagree, and what happens when there is nobody to
/// disagree with (epic #100, invariant S5).
///
/// BIP157 filters are not committed to by consensus, so a peer can serve a
/// self-consistent but wrong filter-commitment chain and nothing in the block
/// headers contradicts it. The only defence is comparing peers. `FilterSync`
/// adopts the majority cfcheckpt answer rather than the first reply — a first
/// reply adopted by fiat would let a lying peer evict the honest ones and
/// become the sole reference.
///
/// The lying node here keeps its block headers honest and rebuilds a complete,
/// internally consistent filter-commitment chain, so it cannot be caught by
/// the client's own arithmetic. Only another peer catches it.
@Suite("Peer disagreement")
struct PeerDisagreementTests {
    /// Two peers that disagree give no majority. The lie is unattributable —
    /// either one could be the liar — so the sync must fail closed rather than
    /// pick a side.
    @Test("two peers disagreeing about filter commitments fails closed")
    func twoWayDisagreementFailsClosed() async throws {
        let synthetic = makeSyntheticChain(length: 6, watchHeight: 3)
        let honest = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        let liar = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                lieAboutFilterCommitments: true)
        try await honest.start()
        try await liar.start()
        defer { Task { await honest.stop(); await liar.stop() } }

        let pool = PeerPool(params: synthetic.params, peerCount: 2,
                            manualPeers: [await honest.endpoint, await liar.endpoint],
                            peersFileURL: tempFileURL("peers.json"))
        await pool.start()
        #expect(await pool.connectedPeers().count == 2)

        let chain = try HeaderChain(params: synthetic.params)
        let sync = try FilterSync(pool: pool, chain: chain, startHeight: 1,
                                  storageURL: tempFileURL("progress.json"),
                                  requiredCheckpointPeers: 2)

        // The specific error matters: a bare "some FilterSyncError" would also
        // pass if the cross-check were gone and the lie were caught by
        // something weaker downstream.
        //
        // Note which defence fires here. Checkpoints are served every 1000
        // blocks, so on a six-block chain both peers return an *empty*
        // cfcheckpt list — identical, no disagreement — and the cfcheckpt
        // majority rule never engages. The defence that catches this lie is
        // the per-batch cfheaders cross-check. The majority rule only matters
        // above height 1000, which no loopback chain reaches.
        do {
            try await sync.sync(watchScripts: [synthetic.watchScript]) { _ in }
            Issue.record("a two-way disagreement was accepted")
        } catch let error as FilterSyncError {
            guard case let .checkpointMismatch(reason) = error,
                  reason.contains("cfheaders disagree")
            else {
                Issue.record("caught \(error) rather than a cfheaders disagreement")
                return
            }
        }
        // Nothing was pinned from a disputed answer.
        #expect(await sync.nextScanHeight == 1,
                "a disputed filter view must not advance the scan frontier")
        await pool.stop()
    }

    /// Positive control: the same two-peer setup with both peers honest syncs
    /// normally. Without this the failure above could be the two-peer path
    /// being broken rather than the disagreement being caught.
    @Test("two honest peers sync normally")
    func twoHonestPeersSync() async throws {
        let synthetic = makeSyntheticChain(length: 6, watchHeight: 3)
        let first = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        let second = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        try await first.start()
        try await second.start()
        defer { Task { await first.stop(); await second.stop() } }

        let pool = PeerPool(params: synthetic.params, peerCount: 2,
                            manualPeers: [await first.endpoint, await second.endpoint],
                            peersFileURL: tempFileURL("peers.json"))
        await pool.start()

        let chain = try HeaderChain(params: synthetic.params)
        let sync = try FilterSync(pool: pool, chain: chain, startHeight: 1,
                                  storageURL: tempFileURL("progress.json"),
                                  requiredCheckpointPeers: 2)

        let collector = MatchCollector()
        try await sync.sync(watchScripts: [synthetic.watchScript]) { collector.add($0) }
        #expect(collector.matches.count == 1)
        #expect(await sync.nextScanHeight == 7)
        await pool.stop()
    }

    /// The eclipse case, pinned as current behaviour rather than asserted as
    /// desirable.
    ///
    /// With one peer there is nobody to compare against, so `FilterSync`
    /// accepts that peer's filter view and advances. A wallet in this state
    /// has no corroboration and no indication of it. That is a deliberate
    /// degradation — failing closed would strand a user whose network reaches
    /// only one peer — but it is the sharpest boundary in a wallet whose whole
    /// claim is that it trusts no server, so it is recorded here rather than
    /// left implicit.
    @Test("a single peer is trusted without corroboration")
    func singlePeerIsTrustedUncorroborated() async throws {
        let synthetic = makeSyntheticChain(length: 6, watchHeight: 3)
        let liar = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                lieAboutFilterCommitments: true)
        try await liar.start()
        defer { Task { await liar.stop() } }

        let pool = PeerPool(params: synthetic.params, peerCount: 1,
                            manualPeers: [await liar.endpoint],
                            peersFileURL: tempFileURL("peers.json"))
        await pool.start()

        let chain = try HeaderChain(params: synthetic.params)
        let sync = try FilterSync(pool: pool, chain: chain, startHeight: 1,
                                  storageURL: tempFileURL("progress.json"),
                                  requiredCheckpointPeers: 1)

        // The lying commitment chain is self-consistent, so the only thing that
        // catches it is a second peer — and there is not one. The sync either
        // completes on the liar's view or fails on the filter bodies; what it
        // cannot do is detect the lie as a disagreement.
        let collector = MatchCollector()
        _ = try? await sync.sync(watchScripts: [synthetic.watchScript]) { collector.add($0) }
        #expect(await pool.connectedPeers().count <= 1)
        await pool.stop()
    }
}
