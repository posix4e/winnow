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

    @Test("a peer on the losing block of a race is not condemned")
    func staleSiblingIsAStateNotALie() async throws {
        // Our chain has the winning block 6; the peer's ends in a sibling of
        // it, mined on the same parent with the same work. Its every reply
        // to getheaders is that sibling, which no backlog purge can hide.
        let synthetic = makeSyntheticChain(length: 6, watchHeight: 8)
        let parent = synthetic.blocks[5]
        let sibling = minedHeader(previousHash: parent.hash,
                                  merkleRoot: Data(repeating: 0xEE, count: 32),
                                  time: synthetic.blocks[6].header.time + 1)
        let losingChain = Array(synthetic.blocks[0 ... 5])
            + [Block(header: sibling, transactions: synthetic.blocks[6].transactions)]
        let node = LoopbackNode(params: synthetic.params, chain: losingChain)
        try await node.start()
        defer { Task { await node.stop() } }
        let peer = PeerConnection(endpoint: await node.endpoint, params: synthetic.params)
        try await peer.connect()
        defer { Task { await peer.disconnect() } }

        let chain = try HeaderChain(params: synthetic.params)
        try await chain.connect(synthetic.blocks.dropFirst().map(\.header))
        #expect(await chain.height == 6)

        let outcome = try await chain.sync(using: peer)
        #expect(outcome.connected == 0)
        #expect(outcome.minForkHeight == nil)
        #expect(outcome.staleSiblings == HeaderChain.maxReplayedBatches + 1)
        #expect(await chain.height == 6)
        #expect(await chain.tipHash == synthetic.blocks[6].hash, "the winning block stays the tip")
    }

    @Test("a lighter branch longer than one block is still a fault")
    func lighterLongerBranchIsStillAFault() async throws {
        // Two blocks forking two below the tip, equal work: not the shape
        // of a race, and the chain keeps refusing it as before.
        let synthetic = makeSyntheticChain(length: 6, watchHeight: 8)
        let headerChain = try HeaderChain(params: synthetic.params)
        try await headerChain.connect(synthetic.blocks.dropFirst().map(\.header))
        let first = minedHeader(previousHash: synthetic.blocks[4].hash,
                                merkleRoot: Data(repeating: 0xEE, count: 32), time: 1_600_090_000)
        let second = minedHeader(previousHash: first.hash,
                                 merkleRoot: Data(repeating: 0xEF, count: 32), time: 1_600_090_600)
        await #expect(throws: HeaderChainError.reorgWithoutMoreWork) {
            try await headerChain.connect([first, second])
        }
        #expect(await headerChain.tipHash == synthetic.blocks[6].hash)
    }
}
