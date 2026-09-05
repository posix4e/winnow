import Foundation
import Testing
@testable import BitcoinP2P

/// A `headers` message the peer sent on its own — the BIP130 announcement of
/// a new block — or a reply that was still waiting when its request had
/// already been answered from the backlog, used to be handed back as the
/// answer to the next getheaders. The chain then read one already-known
/// header as a competing branch with no more work, and the pool condemned
/// the peer for the session. Found by the storefront capture on the signet
/// fixture, where the only peer was the user's own node.
@Suite("Header replay")
struct HeaderReplayTests {
    @Test("a headers message that arrived before the request is not its reply")
    func staleBacklogIsNotTheReply() async throws {
        let synthetic = makeSyntheticChain(length: 6, watchHeight: 8)
        let node = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        try await node.start()
        defer { Task { await node.stop() } }
        let peer = PeerConnection(endpoint: await node.endpoint, params: synthetic.params)
        try await peer.connect()
        defer { Task { await peer.disconnect() } }

        // The node announces its tip, unasked, and the announcement lands in
        // the connection's backlog before anyone asks for headers.
        try await node.send(.headers([synthetic.blocks[6].header]))
        try await Task.sleep(for: .milliseconds(200))

        // Asked from genesis, the node's real answer is the whole chain.
        let locator = GetHeadersMessage(version: PeerConnection.protocolVersion,
                                        locatorHashes: [synthetic.blocks[0].hash])
        let reply = try await peer.request(.getheaders(locator), expecting: ["headers"])
        guard case let .headers(batch) = reply else {
            Issue.record("expected headers, got \(reply.command)")
            return
        }
        #expect(batch.count == 6, "the announcement was returned in place of the reply")
        #expect(batch.first?.hash == synthetic.blocks[1].hash)
    }

    @Test("announcements and stale replies do not stall or condemn a header sync")
    func syncSurvivesReplayedHeaders() async throws {
        let synthetic = makeSyntheticChain(length: 6, watchHeight: 8)
        let node = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        try await node.start()
        defer { Task { await node.stop() } }
        let peer = PeerConnection(endpoint: await node.endpoint, params: synthetic.params)
        try await peer.connect()
        defer { Task { await peer.disconnect() } }
        let chain = try HeaderChain(params: synthetic.params)

        // First sync from genesis, with the tip announced twice beforehand.
        try await node.send(.headers([synthetic.blocks[6].header]))
        try await node.send(.headers([synthetic.blocks[6].header]))
        try await Task.sleep(for: .milliseconds(200))
        let first = try await chain.sync(using: peer)
        #expect(first.connected == 6)
        #expect(await chain.height == 6)

        // Already at the tip: a stale copy of a lower header and another
        // announcement of the tip sit in the backlog. Neither is news, and
        // neither is a branch.
        try await node.send(.headers([synthetic.blocks[5].header]))
        try await node.send(.headers([synthetic.blocks[6].header]))
        try await Task.sleep(for: .milliseconds(200))
        let second = try await chain.sync(using: peer)
        #expect(second.connected == 0)
        #expect(second.minForkHeight == nil)
        #expect(await chain.height == 6)
        #expect(await chain.tipHash == synthetic.blocks[6].hash)
    }
}
