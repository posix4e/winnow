import Foundation
import Network
import Testing
import TestSupport
@testable import WalletCore

/// The peer pool, by subject: which candidates it dials and how many it keeps,
/// what a failing peer costs it, and which seated peers it unseats.
///
/// Merged from `PeerPoolTests`, `PeerCooldownTests` and
/// `StaleTipEvictionTests`; each `// MARK:` below is one of those suites, in
/// that order. All of it is socket-backed — real 127.0.0.1 listeners, no
/// external network.
///
/// The two-minute limit is the stale-tip cases' budget. A time limit here is
/// a hang guard rather than a performance claim (see `pollUntil`).
@Suite("PeerPool", .timeLimit(.minutes(2)))
struct PeerPoolTests {
    /// No DNS seeds or census: the pool dials exactly the manual
    /// peers the test gives it.
    private let params = NetworkParams.customSignet(challenge: Data([0x51]))

    /// A shorter branch that shares only `best`'s genesis. It has valid
    /// trivial PoW but cannot replace the longer branch's accumulated work.
    private func weakerFork(of best: SyntheticChain, length: Int = 4) -> [Block] {
        var result = [best.blocks[0]]
        var previous = best.blocks[0].hash
        for height in 1 ... length {
            let transaction = best.blocks[height].transactions[0]
            let header = minedHeader(
                previousHash: previous,
                merkleRoot: Data(repeating: UInt8(0xA0 + height), count: 32),
                time: best.blocks[0].header.time + UInt32(height * 601))
            result.append(Block(header: header, transactions: [transaction]))
            previous = header.hash
        }
        return result
    }

    // MARK: - Peer pool dialing

    /// Candidates are raced in parallel with a short per-attempt timeout, the
    /// pool fills across mixed accept/reject/timeout candidates, and a round
    /// that runs out of candidates reports exhaustion (with `retry()`
    /// recovering once a candidate becomes viable).
    @Test("pool fills from mixed accept / reject / silent / refused candidates")
    func mixedCandidates() async throws {
        let goodA = LoopbackNode(params: params)
        let goodB = LoopbackNode(params: params)
        let nonFilter = LoopbackNode(params: params, services: 1) // handshake rejects
        let silent = LoopbackNode(params: params, startSilent: true)
        try await goodA.start()
        try await goodB.start()
        try await nonFilter.start()
        try await silent.start()
        defer {
            Task { await goodA.stop() }
            Task { await goodB.stop() }
            Task { await nonFilter.stop() }
            Task { await silent.stop() }
        }
        let refused = PeerEndpoint(host: "127.0.0.1", port: 1) // nothing listens there

        let pool = PeerPool(params: params, peerCount: 2,
                            manualPeers: [refused, await silent.endpoint, await nonFilter.endpoint,
                                          await goodA.endpoint, await goodB.endpoint],
                            dialTimeout: .milliseconds(500))
        await pool.start()
        var endpoints: [PeerEndpoint] = []
        for peer in await pool.connectedPeers() { endpoints.append(await peer.endpoint) }
        #expect(endpoints.count == 2)
        #expect(endpoints.contains(await goodA.endpoint))
        #expect(endpoints.contains(await goodB.endpoint))
        let status = await pool.connectionStatus
        #expect(status.connected == 2)
        #expect(status.target == 2)
        #expect(status.attempts == 5)
        #expect(!status.exhausted)
        await pool.stop()
    }

    @Test("ready local peers are seated without waiting for DNS")
    func localDialsDoNotWaitForSeeds() async throws {
        let first = LoopbackNode(params: .mainnet)
        let second = LoopbackNode(params: .mainnet)
        try await first.start()
        try await second.start()
        let gate = DiscoveryGate()
        let pool = PeerPool(params: .mainnet, peerCount: 2,
                            manualPeers: [await first.endpoint, await second.endpoint],
                            seedResolver: SeedResolver { _, _, _ in await gate.wait(); return [] })
        let startup = Task { await pool.start() }
        // The blocked resolver is the ordering assertion. Use the shared
        // hang guard so runner scheduling is not mistaken for DNS waiting.
        let connected = await pollUntil { await pool.connectedPeers().count == 2 }
        // Always release the gate so a failing implementation terminates too.
        await gate.release()
        await startup.value
        #expect(connected, "healthy local handshakes must not be held behind DNS lookup")
        await pool.stop()
        await first.stop()
        await second.stop()
    }

    @Test("a usable seed result connects while other seeds are still waiting")
    func seedResultsAreConsumedAsTheyArrive() async throws {
        let node = LoopbackNode(params: .mainnet)
        try await node.start()
        let endpoint = await node.endpoint
        let gate = DiscoveryGate()
        let firstSeed = NetworkParams.mainnet.dnsSeeds[0]
        let pool = PeerPool(params: .mainnet, peerCount: 1,
                            seedResolver: SeedResolver { host, _, _ in
                                if host == firstSeed { return [endpoint] }
                                await gate.wait()
                                return []
                            })
        let startup = Task { await pool.start() }
        let finished = await pollUntil {
            let status = await pool.connectionStatus
            return status.connected == 1 && !status.dialing
        }
        await gate.release()
        await startup.value
        #expect(finished, "one stalled seed must not hold up another seed's usable peer")
        await pool.stop()
        await node.stop()
    }

    @Test("DNS still fills a seat after diversity skips remembered candidates")
    func diversityExhaustionStillResolvesSeeds() async throws {
        var nodes: [LoopbackNode] = []
        for _ in 0..<4 {
            let node = LoopbackNode(params: .mainnet)
            try await node.start()
            nodes.append(node)
        }
        let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appending(path: "peers.json")
        var remembered: [PeerCandidate] = []
        for node in nodes.prefix(3) {
            remembered.append(PeerCandidate(endpoint: await node.endpoint, source: .census))
        }
        try JSONEncoder().encode(PersistedPeers(remembered)).write(to: file)
        let seedPeer = await nodes[3].endpoint
        let pool = PeerPool(params: .mainnet, peerCount: 3, peersFileURL: file,
                            maxParallelDials: 1,
                            seedResolver: SeedResolver { _, _, _ in [seedPeer] })
        await pool.start()
        let peers = await pool.connectedPeers()
        #expect(peers.count == 3)
        #expect(await pool.source(of: seedPeer) == .dnsSeed)
        #expect(!((await pool.connectionStatus).exhausted))
        await pool.stop()
        for node in nodes { await node.stop() }
    }

    @Test("a full pool closes silent surplus dials immediately")
    func fullPoolDoesNotWaitForSilentDial() async throws {
        let good = LoopbackNode(params: params)
        let silent = LoopbackNode(params: params, startSilent: true)
        try await good.start()
        try await silent.start()
        let pool = PeerPool(params: params, peerCount: 1,
                            manualPeers: [await silent.endpoint, await good.endpoint],
                            // Longer than pollUntil's 60-second hang guard:
                            // natural dial timeout cannot make this test pass.
                            dialTimeout: .seconds(90))
        let startup = Task { await pool.start() }
        let finished = await pollUntil {
            let status = await pool.connectionStatus
            return status.connected == 1 && !status.dialing
        }
        await pool.stop()
        await silent.stop()
        await good.stop()
        await startup.value
        #expect(finished, "sync startup must not wait out an unused peer's dial timeout")
    }

    @Test("dialing past the target leaves exactly peerCount peers connected")
    func targetIsRespected() async throws {
        var nodes: [LoopbackNode] = []
        for _ in 0 ..< 4 {
            let node = LoopbackNode(params: params)
            try await node.start()
            nodes.append(node)
        }
        defer { for node in nodes { Task { await node.stop() } } }
        var endpoints: [PeerEndpoint] = []
        for node in nodes { endpoints.append(await node.endpoint) }

        let pool = PeerPool(params: params, peerCount: 2, manualPeers: endpoints,
                            dialTimeout: .milliseconds(500))
        await pool.start()
        #expect(await pool.connectedPeers().count == 2)
        let onlyKeptConnectionsRemain = await pollUntil(.seconds(5)) {
            var count = 0
            for node in nodes { count += await node.activeConnectionCount }
            return count == 2
        }
        #expect(onlyKeptConnectionsRemain, "the nodes must observe unused connections closing")
        await pool.stop()
        #expect(await pool.connectedPeers().isEmpty)
        let allConnectionsClosed = await pollUntil(.seconds(5)) {
            var count = 0
            for node in nodes { count += await node.activeConnectionCount }
            return count == 0
        }
        #expect(allConnectionsClosed, "stopping the pool must close every connection it opened")
    }

    @Test("silent candidates connect together before any handshake is released")
    func exhaustionIsParallel() async throws {
        var nodes: [LoopbackNode] = []
        var endpoints: [PeerEndpoint] = []
        for _ in 0 ..< 5 {
            let node = LoopbackNode(params: params, startSilent: true)
            try await node.start()
            nodes.append(node)
            endpoints.append(await node.endpoint)
        }
        defer { for node in nodes { Task { await node.stop() } } }

        // Hold every handshake until all candidates have accepted a connection.
        // The timeout is only a hang guard; runner speed is not the assertion.
        let pool = PeerPool(params: params, peerCount: 3, manualPeers: endpoints,
                            dialTimeout: .seconds(30))
        let dialing = Task { await pool.start() }
        let allAccepted = await pollUntil(.seconds(10)) {
            var accepted = 0
            for node in nodes { accepted += await node.silentConnectionCount }
            return accepted == nodes.count
        }
        #expect(allAccepted, "every silent candidate must be dialed before any is released")
        #expect(await pool.connectionStatus.dialing)
        await pool.stop()
        for node in nodes { await node.stop() }
        await dialing.value
    }

    @Test("total dial effort is capped per round")
    func dialAttemptsCapped() async throws {
        var nodes: [LoopbackNode] = []
        var endpoints: [PeerEndpoint] = []
        for _ in 0 ..< 5 {
            let node = LoopbackNode(params: params, startSilent: true)
            try await node.start()
            nodes.append(node)
            endpoints.append(await node.endpoint)
        }
        defer { for node in nodes { Task { await node.stop() } } }

        let pool = PeerPool(params: params, peerCount: 3, manualPeers: endpoints,
                            dialTimeout: .milliseconds(300), maxDialAttempts: 3)
        await pool.start()
        let status = await pool.connectionStatus
        #expect(status.attempts == 3)
        #expect(status.exhausted)
        await pool.stop()
    }

    @Test("exhaustion then retry once a candidate is viable fills the pool")
    func retryAfterExhaustion() async throws {
        // One listener, bound for the whole test. It starts silent, so the
        // first round finds nothing to handshake with and exhausts; then it
        // serves, on the same port. The port is never released, so no other
        // node in this suite can take it.
        let node = LoopbackNode(params: params, startSilent: true)
        try await node.start()
        defer { Task { await node.stop() } }
        let endpoint = await node.endpoint

        let pool = PeerPool(params: params, peerCount: 1, manualPeers: [endpoint],
                            dialTimeout: .milliseconds(400))
        await pool.start()
        var status = await pool.connectionStatus
        #expect(status.connected == 0)
        #expect(status.exhausted)

        // The same endpoint now serves: retry connects without a restart.
        await node.beginServing()
        await pool.retry()
        status = await pool.connectionStatus
        #expect(status.connected == 1)
        #expect(!status.exhausted)
        await pool.stop()
    }

    @Test("header sync rejects a stale peer and continues with a healthy fallback")
    func headerSyncFailover() async throws {
        let best = makeSyntheticChain(length: 8, watchHeight: 3)
        let stale = weakerFork(of: best)
        let staleNode = LoopbackNode(params: best.params, chain: stale)
        let goodNode = LoopbackNode(params: best.params, chain: best.blocks)
        try await staleNode.start()
        try await goodNode.start()
        defer {
            Task { await staleNode.stop() }
            Task { await goodNode.stop() }
        }

        let chain = try HeaderChain(params: best.params)
        try await chain.connect(Array(best.blocks.dropFirst().map(\.header)))
        let pool = PeerPool(params: best.params, peerCount: 1,
                            manualPeers: [await staleNode.endpoint, await goodNode.endpoint],
                            dialTimeout: .seconds(1), maxParallelDials: 1)
        await pool.start()
        try await pool.syncHeaders(chain, timeoutPerPeer: .seconds(1), maxAttempts: 2)

        #expect(await chain.height == 8)
        var endpoints: [PeerEndpoint] = []
        for peer in await pool.connectedPeers() { endpoints.append(await peer.endpoint) }
        #expect(endpoints == [await goodNode.endpoint])
        await pool.stop()
    }

    @Test("header sync reports exhaustion after every candidate fails")
    func headerSyncExhaustion() async throws {
        let best = makeSyntheticChain(length: 8, watchHeight: 3)
        let staleNode = LoopbackNode(params: best.params, chain: weakerFork(of: best))
        try await staleNode.start()
        defer { Task { await staleNode.stop() } }

        let chain = try HeaderChain(params: best.params)
        try await chain.connect(Array(best.blocks.dropFirst().map(\.header)))
        let pool = PeerPool(params: best.params, peerCount: 1,
                            manualPeers: [await staleNode.endpoint],
                            dialTimeout: .seconds(1))
        await pool.start()
        var caught: PeerPoolHeaderSyncError?
        do {
            try await pool.syncHeaders(chain, timeoutPerPeer: .seconds(1), maxAttempts: 1)
        } catch let error as PeerPoolHeaderSyncError {
            caught = error
        }
        #expect(caught?.localizedDescription.contains(
            "Winnow tried 1 Bitcoin peer, but none supplied a usable block-header chain") == true)
        #expect(caught?.localizedDescription.contains("older or weaker Bitcoin chain") == true)
        await pool.stop()
    }

    @Test("local header storage damage is not retried against another peer")
    func localStorageFailureIsNotRetried() async throws {
        let best = makeSyntheticChain(length: 4, watchHeight: 2)
        let first = LoopbackNode(params: best.params, chain: best.blocks)
        let second = LoopbackNode(params: best.params, chain: best.blocks,
                                  versionDelay: .milliseconds(200))
        try await first.start()
        try await second.start()
        defer {
            Task { await first.stop() }
            Task { await second.stop() }
        }

        let directory = FileManager.default.temporaryDirectory
            .appending(path: "header-storage-failure-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let storage = directory.appending(path: "headers.bin")
        let chain = try HeaderChain(params: best.params, storageURL: storage)
        // Replacing the not-yet-created file with a directory makes the
        // first atomic persistence fail after valid headers arrive.
        try FileManager.default.createDirectory(at: storage, withIntermediateDirectories: false)

        let pool = PeerPool(params: best.params, peerCount: 1,
                            manualPeers: [await first.endpoint, await second.endpoint],
                            dialTimeout: .seconds(1))
        await pool.start()
        var caught: HeaderChainError?
        do {
            try await pool.syncHeaders(chain, timeoutPerPeer: .seconds(1), maxAttempts: 2)
        } catch let error as HeaderChainError {
            caught = error
        }
        #expect({
            if case .storageUnavailable? = caught { return true }
            return false
        }())
        #expect(await pool.connectedPeers().count == 1)
        await pool.stop()
    }

    // MARK: - Relay-only sessions

    // Keeping a payment moving while nothing is being read.
    //
    // `stop()` is all or nothing: it disconnects every peer, and `TxBroadcaster`
    // announces over exactly those connections, so a wallet that stops its pool
    // with a transaction still pending stops relaying it. `enterRelayOnly` is
    // the state in between — a seat or two held for announcements, nothing
    // dialled, nothing read.

    @Test("a relay-only session keeps only the seats it was given and dials nothing")
    func relayOnlyKeepsSeats() async throws {
        var nodes: [LoopbackNode] = []
        var endpoints: [PeerEndpoint] = []
        for _ in 0 ..< 3 {
            let node = LoopbackNode(params: params)
            try await node.start()
            nodes.append(node)
            endpoints.append(await node.endpoint)
        }
        defer { for node in nodes { Task { await node.stop() } } }

        let pool = PeerPool(params: params, peerCount: 3, manualPeers: endpoints,
                            dialTimeout: .milliseconds(500))
        await pool.start()
        #expect(await pool.connectedPeers().count == 3)

        await pool.enterRelayOnly(seats: 1)
        #expect(await pool.mode == .relayOnly)
        #expect(await pool.isRunning, "a narrowed pool is still running")
        let kept = await pool.connectedPeers()
        #expect(kept.count == 1)
        #expect(await kept.first?.isConnected == true, "the seat that stays must stay connected")
        let status = await pool.connectionStatus
        #expect(status.connected == 1)
        #expect(status.target == 1, "the target is what the session holds, not the sync pool's")

        // Nothing dials it back up: not the retry the UI offers after
        // exhaustion, and not the monitor, which the session cancelled. Two
        // candidates are sitting there unconnected, so a pool that was willing
        // to dial would take them.
        //
        // The attempt counter is the assertion that says *dialled*, not merely
        // *seated*: a pool that dials and then refuses the arrival still spent
        // the connection, still told two more nodes where this wallet is, and
        // would still have resolved DNS seeds to find them.
        await pool.retry()
        try await Task.sleep(for: .milliseconds(200))
        #expect(await pool.connectedPeers().count == 1)
        #expect(await pool.connectionStatus.attempts == 0, "a relay-only session dials nothing")
        #expect(await pool.connectionStatus.dialing == false)
        await pool.stop()
    }

    /// A session that never heals still has to be honest about what it holds.
    ///
    /// `enterRelayOnly` cancels the replacement monitor, and that monitor is
    /// the only thing in the pool that drops a seat nobody reported. So a
    /// remote that simply goes away — the ordinary end of a mobile connection
    /// — left its seat in `peers` for as long as the session lasted:
    /// `connectedPeers()` went on reporting it, every announcement over it
    /// failed silently, and the session had nothing left that could end it.
    /// The prune pass runs in the cancelled monitor's place and does the one
    /// half of its job a relay-only session can have. It drops what has gone,
    /// and it dials nothing: the seat is not replaced, which is the mode, but
    /// it is not claimed either.
    @Test("a relay-only session drops a seat that is gone and dials no replacement")
    func relayOnlyPrunesADeadSeat() async throws {
        var nodes: [LoopbackNode] = []
        var endpoints: [PeerEndpoint] = []
        var byEndpoint: [PeerEndpoint: LoopbackNode] = [:]
        for _ in 0 ..< 2 {
            let node = LoopbackNode(params: params)
            try await node.start()
            nodes.append(node)
            endpoints.append(await node.endpoint)
            byEndpoint[await node.endpoint] = node
        }
        defer { for node in nodes { Task { await node.stop() } } }

        // The pass runs on the replacement monitor's cadence, thirty seconds.
        // This asks for the same pass sooner rather than sleeping through it.
        let pool = PeerPool(params: params, peerCount: 2, manualPeers: endpoints,
                            dialTimeout: .milliseconds(500), monitorInterval: .milliseconds(50))
        await pool.start()
        #expect(await pool.connectedPeers().count == 2)

        await pool.enterRelayOnly(seats: 1)
        let seat = try #require(await pool.connectedPeers().first)
        let kept = try #require(byEndpoint[await seat.endpoint])

        // The remote goes away without anyone telling the pool.
        await kept.stop()
        #expect(await pollUntil(.seconds(10)) { await pool.connectedPeers().isEmpty },
                "a seat whose connection is gone must not go on being reported as held")
        #expect(await pool.mode == .relayOnly)
        #expect(await pool.isRunning, "pruning is not stopping: what the pool is for is the owner's call")
        #expect(await pool.connectionStatus.attempts == 0,
                "the seat is dropped, never replaced — replacing it means dialling")
        await pool.stop()
    }

    @Test("a dial already racing when the pool narrows is not seated")
    func relayOnlyRefusesInFlightDials() async throws {
        // One node answers at once and two answer late, so the pool is still
        // mid-round — dials in flight, seats unfilled — when it narrows.
        let fast = LoopbackNode(params: params)
        let slowA = LoopbackNode(params: params, versionDelay: .milliseconds(400))
        let slowB = LoopbackNode(params: params, versionDelay: .milliseconds(400))
        let nodes = [fast, slowA, slowB]
        for node in nodes { try await node.start() }
        defer { for node in nodes { Task { await node.stop() } } }
        var endpoints: [PeerEndpoint] = []
        for node in nodes { endpoints.append(await node.endpoint) }

        let pool = PeerPool(params: params, peerCount: 3, manualPeers: endpoints,
                            dialTimeout: .seconds(2))
        let dialing = Task { await pool.start() }
        #expect(await pollUntil(.seconds(5)) { await pool.connectedPeers().count == 1 },
                "the fast node must be seated while the slow ones are still handshaking")

        await pool.enterRelayOnly(seats: 1)
        await dialing.value

        // The late arrivals are refused and hung up on rather than seated: a
        // session that asked for one seat must not end up holding three
        // because the dials that were racing happened to land.
        #expect(await pool.connectedPeers().count == 1)
        #expect(await pool.mode == .relayOnly)
        let status = await pool.connectionStatus
        #expect(status.attempts == 0, "no dial was launched after the pool narrowed")
        #expect(!status.exhausted, "a round cut short by narrowing is not a peerless pool")
        await pool.stop()
    }

    @Test("start() leaves a relay-only session and fills the pool again")
    func relayOnlyResumes() async throws {
        var nodes: [LoopbackNode] = []
        var endpoints: [PeerEndpoint] = []
        for _ in 0 ..< 3 {
            let node = LoopbackNode(params: params)
            try await node.start()
            nodes.append(node)
            endpoints.append(await node.endpoint)
        }
        defer { for node in nodes { Task { await node.stop() } } }

        let pool = PeerPool(params: params, peerCount: 3, manualPeers: endpoints,
                            dialTimeout: .milliseconds(500))
        await pool.start()
        await pool.enterRelayOnly(seats: 1)
        #expect(await pool.connectedPeers().count == 1)

        // The app's foreground path is a plain `start()`, and a narrowed pool
        // is already started — so this is the call that has to notice.
        await pool.start()
        #expect(await pool.mode == .full)
        #expect(await pool.connectedPeers().count == 3)
        #expect(await pool.connectionStatus.target == 3)
        await pool.stop()
    }

    @Test("stop() during a relay-only session still disconnects everything")
    func relayOnlyStopIsStillFull() async throws {
        let nodeA = LoopbackNode(params: params)
        let nodeB = LoopbackNode(params: params)
        try await nodeA.start()
        try await nodeB.start()
        defer {
            Task { await nodeA.stop() }
            Task { await nodeB.stop() }
        }

        let pool = PeerPool(params: params, peerCount: 2,
                            manualPeers: [await nodeA.endpoint, await nodeB.endpoint],
                            dialTimeout: .milliseconds(500))
        await pool.start()
        await pool.enterRelayOnly(seats: 1)
        let seat = try #require(await pool.connectedPeers().first)

        // The mode is a narrower pool, never a pool that refuses to be shut
        // down: upstream's teardown must mean exactly what it meant before.
        await pool.stop()
        #expect(await pool.connectedPeers().isEmpty)
        #expect(await seat.isConnected == false)
        #expect(await pool.isRunning == false)
        #expect(await pool.mode == .full, "a stopped pool is not in a session")
    }

    @Test("a relay-only pool refuses header sync and asks its peer nothing")
    func relayOnlyRefusesHeaderSync() async throws {
        let best = makeSyntheticChain(length: 8, watchHeight: 3)
        let node = LoopbackNode(params: best.params, chain: best.blocks)
        try await node.start()
        defer { Task { await node.stop() } }

        let pool = PeerPool(params: best.params, peerCount: 1,
                            manualPeers: [await node.endpoint],
                            dialTimeout: .seconds(1))
        await pool.start()
        await pool.enterRelayOnly(seats: 1)

        let chain = try HeaderChain(params: best.params)
        var caught: PeerPoolHeaderSyncError?
        do {
            try await pool.syncHeaders(chain, timeoutPerPeer: .seconds(1), maxAttempts: 1)
        } catch let error as PeerPoolHeaderSyncError {
            caught = error
        }
        #expect(caught == .relayOnly)
        // Refused before the wire, not after: the seat is being held for a
        // payment, and a header sync over it can burn it on a peer fault.
        #expect(await node.nextMessage(command: "getheaders", timeout: .milliseconds(300)) == nil)
        #expect(await chain.height == 0)
        #expect(await pool.connectedPeers().count == 1, "refusing must not cost the seat")
        await pool.stop()
    }

    /// The seat split is committed before the first disconnect is awaited, so
    /// a removal that interleaves cannot leave the session holding a
    /// connection the narrowing itself tore down.
    ///
    /// `await peer.disconnect()` suspends the pool, and the removals that
    /// arrive there are the ordinary ones: a scan still unwinding reports a
    /// timeout through `transportFailure`, which is exactly what is in flight
    /// when an app narrows the pool on going idle. Taking the prefix after
    /// that await reads a shifted array, and the seat kept is a peer already
    /// disconnected — after which `announce` throws on every send, the monitor
    /// that would prune the dead seat is cancelled by the mode, and nothing
    /// drains the pending set, so the payment silently stops going out over a
    /// pool that is never stopped.
    ///
    /// The invariant is the assertion, not the interleaving: whatever the two
    /// jobs do to each other, a seat the pool reports must be a live
    /// connection. The loop is what makes the window reachable — `mode` is set
    /// on the actor before the first suspension, so waiting for it puts the
    /// failure inside the teardown rather than before or after it — and it
    /// runs enough rounds to hit a window the unfixed code loses roughly one
    /// round in five.
    @Test("a peer dropped while the pool narrows never leaves a disconnected seat")
    func relayOnlyCommitsTheSplitBeforeDisconnecting() async throws {
        var nodes: [LoopbackNode] = []
        var endpoints: [PeerEndpoint] = []
        for _ in 0 ..< 3 {
            let node = LoopbackNode(params: params)
            try await node.start()
            nodes.append(node)
            endpoints.append(await node.endpoint)
        }
        defer { for node in nodes { Task { await node.stop() } } }

        // A fresh pool per round: `transportFailure` cools the endpoint off,
        // and that cooldown is per pool, so reusing one would starve the
        // later rounds of the three seats this needs.
        for round in 0 ..< 25 {
            let pool = PeerPool(params: params, peerCount: 3, manualPeers: endpoints,
                                dialTimeout: .milliseconds(500))
            await pool.start()
            let seated = await pool.connectedPeers()
            try #require(seated.count == 3, "round \(round) needs three seats to narrow")
            let doomed = try #require(seated.first)

            let narrowing = Task { await pool.enterRelayOnly(seats: 1) }
            // The mode is set before `enterRelayOnly` awaits anything, so this
            // returns only once the narrowing is inside its disconnects.
            while await pool.mode != .relayOnly { await Task.yield() }
            await pool.transportFailure(doomed, reason: "test: a scan unwinding while the pool narrows")
            _ = await narrowing.value

            for peer in await pool.connectedPeers() {
                #expect(await peer.isConnected,
                        "round \(round): a relay-only seat must be a live connection")
            }
            await pool.stop()
        }
    }

    /// The count `enterRelayOnly` returns is what the session holds once the
    /// narrowing is done, not what the split set out to keep.
    ///
    /// Committing the split before the first `await peer.disconnect()` closes
    /// one side of that suspension; this is the other. The removals that land
    /// there are the same ones: a scan still unwinding reports the kept seat
    /// through `transportFailure`, which takes it out of `peers` while the
    /// loop is still tearing down the rest. A count taken before the loop
    /// reported that seat as held, and `TxBroadcaster.enterRelayOnly` opens a
    /// session on any count above zero: relay-only mode, so nothing dials and
    /// no monitor runs, over no connection at all, with the pending payment
    /// never announced again and nothing left to drain the pending set.
    ///
    /// The return and the seat count are read as one job on the pool, so
    /// nothing can land between them: whatever the interleaving, what
    /// `enterRelayOnly` reports must be what the pool is seated on when it
    /// returns. The failure is queued from inside that job, so it runs at the
    /// narrowing's first suspension, and the pool drops four peers so the loop
    /// suspends four times; the removal lands inside the loop on nearly every
    /// round, and the run checks that it did at least once, so a fixture
    /// change cannot leave this passing while testing nothing.
    @Test("a seat lost while the pool narrows is not reported as held")
    func relayOnlyCountsTheSeatsItStillHolds() async throws {
        var nodes: [LoopbackNode] = []
        var endpoints: [PeerEndpoint] = []
        for _ in 0 ..< 5 {
            let node = LoopbackNode(params: params)
            try await node.start()
            nodes.append(node)
            endpoints.append(await node.endpoint)
        }
        defer { for node in nodes { Task { await node.stop() } } }

        // A fresh pool per round, as above: the failure cools its endpoint
        // off per pool, and a reused one would run short of seats.
        var lostInsideTheLoop = 0
        for round in 0 ..< 20 {
            let pool = PeerPool(params: params, peerCount: 5, manualPeers: endpoints,
                                dialTimeout: .milliseconds(500))
            await pool.start()
            let seated = await pool.connectedPeers()
            try #require(seated.count == 5, "round \(round) needs five seats to narrow")
            // The split keeps a prefix, so the first seat is the one held.
            let kept = try #require(seated.first)

            let (reported, live) = await narrowWhileTheKeptSeatFails(pool, kept: kept)
            #expect(reported == live,
                    "round \(round): reported \(reported) seat(s) while holding \(live)")
            if live == 0 { lostInsideTheLoop += 1 }
            await pool.stop()
        }
        #expect(lostInsideTheLoop > 0,
                "the removal never landed inside the narrowing, so nothing was tested")
    }

    /// One job on the pool. The failure is queued behind this job and so
    /// runs at the narrowing's first suspension, and the count is read in
    /// the same job as the return, with no suspension between the two.
    private func narrowWhileTheKeptSeatFails(_ pool: isolated PeerPool,
                                             kept: PeerConnection) async -> (reported: Int, live: Int) {
        let failing = Task {
            await pool.transportFailure(kept, reason: "test: the kept seat fails while the pool narrows")
        }
        let reported = await pool.enterRelayOnly(seats: 1)
        let live = pool.connectedPeers().count
        await failing.value
        return (reported, live)
    }

    /// `stop()` clears the run's rejections before it awaits the disconnects,
    /// and a data fault from a scan still unwinding can land in those awaits.
    /// The next `start()` is a new run and owes that fault nothing: the peer
    /// is dialled again.
    @Test("a rejection that lands after stop() does not bar the peer from the next run")
    func lateRejectionDoesNotOutliveStop() async throws {
        let params = NetworkParams.signet
        let node = LoopbackNode(params: params)
        try await node.start()
        defer { Task { await node.stop() } }
        let pool = PeerPool(params: params, peerCount: 1, manualPeers: [await node.endpoint],
                            dialTimeout: .milliseconds(500))
        await pool.start()
        let seat = try #require(await pool.connectedPeers().first)
        await pool.stop()
        // The fault's verdict arrives after the stop already cleared the run.
        await pool.misbehaving(seat, reason: "late data fault")
        #expect(await pool.rejectionReasons[await seat.endpoint] == "late data fault")
        await pool.start()
        #expect(await pollUntil(.seconds(10)) { await pool.connectedPeers().count == 1 },
                "a new run dials the peer the old run's late fault named")
        await pool.stop()
    }

    /// `stopIfRelayOnly` is the whole re-read, done as one job on the pool.
    ///
    /// `TxBroadcaster` ends a session from a detached task and has to ask
    /// whether the caller took the pool back first. Asking and acting as two
    /// jobs is not asking at all: a `start()` between them runs first and the
    /// queued `stop()` then undoes it. Both answers are pinned here, on a pool
    /// with no broadcaster in sight.
    @Test("stopIfRelayOnly stops a narrowed pool and leaves a resumed one alone")
    func stopIfRelayOnlyRespectsAResumedPool() async throws {
        let node = LoopbackNode(params: params)
        try await node.start()
        defer { Task { await node.stop() } }
        let pool = PeerPool(params: params, peerCount: 1, manualPeers: [await node.endpoint],
                            dialTimeout: .milliseconds(500))

        // Full service: not this session's pool to stop.
        await pool.start()
        await pool.stopIfRelayOnly()
        #expect(await pool.isRunning, "a full-service pool belongs to its caller")
        #expect(await pool.connectedPeers().count == 1)

        // Narrowed: exactly what it is for.
        await pool.enterRelayOnly(seats: 1)
        await pool.stopIfRelayOnly()
        #expect(await pool.isRunning == false)
        #expect(await pool.connectedPeers().isEmpty)

        // Narrowed and then resumed, which is the race this exists to close:
        // the pool is in full service again, so the session's stop expires.
        await pool.start()
        await pool.enterRelayOnly(seats: 1)
        await pool.start()
        await pool.stopIfRelayOnly()
        #expect(await pool.isRunning, "a resumed pool is not stopped by an expired session")
        #expect(await pool.connectedPeers().count == 1)
        await pool.stop()
    }

    /// A pool with nothing to keep keeps nothing, and says so. The count is
    /// what tells a caller "relaying over a seat" from "nothing will ever go
    /// out": a zero-seat session announces to nobody, and cannot dial one,
    /// because dialling is what the mode refuses.
    @Test("narrowing a stopped or empty pool reports no seats")
    func relayOnlyReportsSeatsItCouldNotKeep() async throws {
        let node = LoopbackNode(params: params)
        try await node.start()
        defer { Task { await node.stop() } }

        // Never started.
        let stopped = PeerPool(params: params, peerCount: 1, manualPeers: [await node.endpoint],
                               dialTimeout: .milliseconds(500))
        #expect(await stopped.enterRelayOnly(seats: 1) == 0)
        #expect(await stopped.isRunning == false)

        // Started, but with nothing to dial, so there is no seat to hold.
        let empty = PeerPool(params: params, peerCount: 1, manualPeers: [],
                             dialTimeout: .milliseconds(500))
        await empty.start()
        #expect(await empty.connectedPeers().isEmpty)
        #expect(await empty.enterRelayOnly(seats: 1) == 0)
        await empty.stop()

        // And a pool with a seat reports the seat it kept.
        let seated = PeerPool(params: params, peerCount: 1, manualPeers: [await node.endpoint],
                              dialTimeout: .milliseconds(500))
        await seated.start()
        #expect(await seated.enterRelayOnly(seats: 1) == 1)
        await seated.stop()
    }

    // MARK: - Peer cooldown

    // A slow peer is cooled off; a dishonest one is banned (#82).
    //
    // One `chain.sync(using:)` call runs an entire header sync against a single
    // peer — around 460 round trips on mainnet. Every error inside that loop, a
    // single lagging reply included, went through `misbehaving`, which drops the
    // endpoint from `knownGood` *and* bars it for the session. `knownGood` is the
    // persisted peers file, so one slow reply did not merely cost a peer for this
    // run: it degraded every future launch. That is the "peers are lagging me
    // out" report.
    //
    // The distinction these pin is between the connection failing and the peer
    // being untruthful. The first is temporary and common; the second is the
    // thing bans exist for.

    /// Reads the peers file in whichever format it holds. The seeding below
    /// deliberately writes the pre-#3 bare array, so these also exercise the
    /// migration: an old file must still load, and its entries are classed
    /// `persisted` because that is what they are.
    ///
    /// Internal rather than private: `FilterSyncAdversaryTests` asks the same
    /// question of the same file, and one reader beats two.
    static func storedPeers(_ url: URL) throws -> Set<PeerEndpoint> {
        guard let data = try? Data(contentsOf: url),
              let stored = PersistedPeers.decode(data)
        else { return [] }
        return Set(stored.map(\.endpoint))
    }

    // MARK: The escalation schedule, without a clock

    @Test("the cooldown doubles per consecutive failure and holds at the cap")
    func cooldownEscalates() {
        let base = Duration.seconds(30)
        let cap = Duration.seconds(600)
        func cooldown(_ failures: Int) -> Duration {
            PeerPool.cooldown(afterFailures: failures, base: base, cap: cap)
        }

        #expect(cooldown(1) == .seconds(30))
        #expect(cooldown(2) == .seconds(60))
        #expect(cooldown(3) == .seconds(120))
        #expect(cooldown(4) == .seconds(240))
        #expect(cooldown(5) == .seconds(480))
        // 480 doubled is 960, past the cap.
        #expect(cooldown(6) == cap)
        #expect(cooldown(50) == cap)
    }

    /// Which errors mean "the link failed" rather than "the peer lied". This
    /// is the whole decision, so it is asserted directly rather than only
    /// through the pool.
    @Test("transport faults are separated from peer misconduct")
    func transportClassification() {
        #expect(PeerError.timeout.isTransport)
        #expect(PeerError.notConnected.isTransport)
        #expect(PeerError.disconnected("closed").isTransport)
        #expect(PeerError.handshakeFailed("no verack").isTransport)

        #expect(PeerError.protocolViolation("bad framing").isTransport == false)
        #expect(PeerError.missingCompactFilters(services: 0).isTransport == false)
    }

    // MARK: The reported bug

    /// The core of #82: a peer that is merely slow must survive in the
    /// persisted peers file, because that file is what the next launch dials
    /// first.
    @Test("a peer that times out mid-sync stays in the persisted peers file")
    func slowPeerSurvivesInPeersFile() async throws {
        let synthetic = makeSyntheticChain(length: 4, watchHeight: 2)
        let slow = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                withholdHeaders: true)
        try await slow.start()
        defer { Task { await slow.stop() } }
        let endpoint = await slow.endpoint

        let file = tempFileURL("peers.json")
        defer { try? FileManager.default.removeItem(at: file) }
        // Seed the file so the endpoint is already "known good" before the
        // timeout, which is the situation a returning user is in.
        try JSONEncoder().encode([endpoint]).write(to: file)

        let pool = PeerPool(params: synthetic.params, peerCount: 1,
                            manualPeers: [endpoint], peersFileURL: file,
                            dialTimeout: .seconds(2))
        await pool.start()
        #expect(await pool.connectedPeers().count == 1)

        let chain = try HeaderChain(params: synthetic.params)
        var thrown: (any Error)?
        do {
            try await pool.syncHeaders(chain, timeoutPerPeer: .milliseconds(300),
                                       maxAttempts: 2, maxTransportRetries: 1)
        } catch {
            thrown = error
        }
        // Assert *which* failure, not merely that one happened. An earlier
        // version of this test accepted any error, which let the sync start
        // reporting "no Bitcoin peers are available" — false, and less
        // truthful than the behaviour being fixed — without any test noticing.
        guard case .allPeersCoolingDown? = thrown as? PeerPoolHeaderSyncError else {
            Issue.record("expected allPeersCoolingDown, got \(String(describing: thrown))")
            return
        }

        await pool.stop()
        #expect(try Self.storedPeers(file).contains(endpoint),
                "a slow peer must not be struck from the persisted peers file")
    }

    /// The control for the case above, and the whole point of separating the
    /// two paths: misconduct must still be permanent. Both are driven directly
    /// rather than through a synthesised wire fault, because what is being
    /// compared is the *effect* of the two responses on the same peer.
    @Test("misconduct still strikes a peer from the file; a timeout does not")
    func banAndCooldownDifferInEffect() async throws {
        let synthetic = makeSyntheticChain(length: 4, watchHeight: 2)

        // Two identical, healthy nodes. Nothing about the peers differs — only
        // which path the pool takes for each.
        let banned = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        let cooled = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        for node in [banned, cooled] { try await node.start() }
        defer { for node in [banned, cooled] { Task { await node.stop() } } }
        let bannedEndpoint = await banned.endpoint
        let cooledEndpoint = await cooled.endpoint

        let file = tempFileURL("peers.json")
        defer { try? FileManager.default.removeItem(at: file) }
        try JSONEncoder().encode([bannedEndpoint, cooledEndpoint]).write(to: file)

        let pool = PeerPool(params: synthetic.params, peerCount: 2,
                            manualPeers: [bannedEndpoint, cooledEndpoint],
                            peersFileURL: file, dialTimeout: .seconds(2))
        await pool.start()
        #expect(await pool.connectedPeers().count == 2)

        for peer in await pool.connectedPeers() {
            let endpoint = await peer.endpoint
            if endpoint == bannedEndpoint {
                await pool.misbehaving(peer, reason: "sent a header that does not link")
            } else {
                await pool.transportFailure(peer, reason: "timed out waiting for headers")
            }
        }

        // The cooled peer is only unavailable for now; the banned one is gone.
        #expect(await pool.isCoolingDown(cooledEndpoint))
        #expect(await pool.isCoolingDown(bannedEndpoint) == false,
                "a ban is not a cooldown — it must not expire")

        await pool.stop()
        let remaining = try Self.storedPeers(file)
        #expect(remaining.contains(cooledEndpoint),
                "a slow peer stays known-good for the next launch")
        #expect(remaining.contains(bannedEndpoint) == false,
                "a peer that sent bad data must be struck from the file")
    }

    /// `noPeers` has to keep meaning "there is nothing to dial", or the error
    /// the user sees is worse than the bug this change removed.
    @Test("a pool with no candidates at all still reports noPeers")
    func genuinelyPeerlessStillReportsNoPeers() async throws {
        let synthetic = makeSyntheticChain(length: 4, watchHeight: 2)
        let pool = PeerPool(params: synthetic.params, peerCount: 0, manualPeers: [])
        await pool.start()
        let chain = try HeaderChain(params: synthetic.params)

        var thrown: (any Error)?
        do {
            try await pool.syncHeaders(chain, timeoutPerPeer: .milliseconds(200), maxAttempts: 1)
        } catch {
            thrown = error
        }
        #expect((thrown as? PeerPoolHeaderSyncError) == .noPeers,
                "an empty candidate universe is the one case noPeers is for")
        await pool.stop()
    }

    // MARK: Cooling is temporary

    /// A cooling endpoint is skipped while the timer runs and dialled again
    /// once it expires. Time is injected rather than slept through, so this
    /// asserts the policy rather than the machine's speed.
    @Test("a cooled-off endpoint becomes eligible again once the timer expires")
    func cooldownExpires() async throws {
        let synthetic = makeSyntheticChain(length: 4, watchHeight: 2)
        let slow = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                withholdHeaders: true)
        try await slow.start()
        defer { Task { await slow.stop() } }
        let endpoint = await slow.endpoint

        // A clock the test moves by hand.
        let clock = TestClock()
        let pool = PeerPool(params: synthetic.params, peerCount: 1,
                            manualPeers: [endpoint], dialTimeout: .seconds(2),
                            now: { clock.now })
        await pool.start()

        let chain = try HeaderChain(params: synthetic.params)
        _ = try? await pool.syncHeaders(chain, timeoutPerPeer: .milliseconds(300),
                                        maxAttempts: 2, maxTransportRetries: 1)

        #expect(await pool.isCoolingDown(endpoint), "a timed-out peer should be cooling")
        #expect(await pool.rejectionReason(endpoint) != nil,
                "the reason must be recorded, not discarded")

        // Advance past the first cooldown.
        clock.advance(by: .seconds(31))
        #expect(await pool.isCoolingDown(endpoint) == false,
                "the endpoint should be eligible again once the cooldown expires")

        await pool.stop()
    }

    // MARK: - Stale tip eviction

    // A peer far behind the tip cannot serve filters or blocks near it, and
    // asking it about a tip it has never seen makes Bitcoin Core hang up. The
    // pool unseats such a peer on what it reports, judged against the header
    // chain the pool itself validated — never against another peer's claim,
    // and never on what software it runs.

    /// The remembered-peers file the pool reads at start, version 2.
    private static func persistedPeersFile(_ endpoints: [PeerEndpoint]) -> Data {
        let entries = endpoints.map {
            "{\"source\":\"persisted\",\"port\":\($0.port),\"host\":\"\($0.host)\"}"
        }.joined(separator: ",")
        return Data("{\"version\":2,\"peers\":[\(entries)]}".utf8)
    }

    @Test("a peer far behind the validated tip is unseated and cooled off once headers have synced")
    func staleIsUnseated() async throws {
        let synthetic = makeSyntheticChain(length: 120, watchHeight: 3)
        let current = LoopbackNode(params: synthetic.params, chain: synthetic.blocks) // reports 120
        let stale = LoopbackNode(params: synthetic.params) // reports height 0
        try await current.start()
        try await stale.start()
        defer { Task { await current.stop() }; Task { await stale.stop() } }
        let currentEndpoint = await current.endpoint
        let staleEndpoint = await stale.endpoint

        // The stale node arrives as a remembered peer, the way the mainnet
        // stall's dead node did; a manual peer is exempt (see below), so it
        // cannot carry this test. The tip node is manual so the diversity
        // ceiling, which refuses one source class the whole pool, lets both
        // seat.
        let store = tempFileURL("peers.json")
        try Self.persistedPeersFile([staleEndpoint]).write(to: store)
        let pool = PeerPool(params: synthetic.params, peerCount: 2,
                            manualPeers: [currentEndpoint], peersFileURL: store)
        await pool.start()
        let both = await settle(pool) { $0.count == 2 }
        #expect(both.count == 2, "before any header sync there is no validated tip, so nothing is judged")

        // Headers sync against the current node gives the pool a tip it can
        // trust; the stale peer's claim is now 119 behind it.
        let chain = try HeaderChain(params: synthetic.params)
        _ = try await pool.syncHeaders(chain)
        #expect(await chain.height == 120)
        let seated = await settle(pool) { $0 == [currentEndpoint] }
        #expect(seated == [currentEndpoint], "only the peer near the tip keeps its seat")
        #expect(await pool.rejectionReason(staleEndpoint)?.hasPrefix("stale tip:") == true)
        #expect(await pool.coolingEndpoints.contains(staleEndpoint), "cooled off, not banned")
        await pool.stop()
    }

    @Test("a peer claiming an absurd height cannot get honest peers evicted")
    func liarCannotEvictHonestPeers() async throws {
        let synthetic = makeSyntheticChain(length: 120, watchHeight: 3)
        let honest = LoopbackNode(params: synthetic.params, chain: synthetic.blocks) // reports 120
        let liar = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                claimedStartHeight: Int32.max)
        let negative = LoopbackNode(params: synthetic.params, chain: synthetic.blocks,
                                    claimedStartHeight: Int32.min)
        let nodes = [honest, liar, negative]
        for node in nodes { try await node.start() }
        defer { for node in nodes { Task { await node.stop() } } }
        var endpoints: [PeerEndpoint] = []
        for node in nodes { endpoints.append(await node.endpoint) }

        let pool = PeerPool(params: synthetic.params, peerCount: 3, manualPeers: [endpoints[0]],
                            peersFileURL: {
                                let store = tempFileURL("peers.json")
                                try! Self.persistedPeersFile([endpoints[1], endpoints[2]]).write(to: store)
                                return store
                            }())
        await pool.start()
        _ = await settle(pool) { $0.count == 3 }
        let chain = try HeaderChain(params: synthetic.params)
        _ = try await pool.syncHeaders(chain)
        // Int32.min widened, not trapped; Int32.max is ahead of the tip, which
        // this rule does not judge (the header sync does).
        let seated = await settle(pool) { !$0.contains(endpoints[2]) }
        #expect(seated.contains(endpoints[0]), "the honest peer keeps its seat whatever a liar claims")
        #expect(seated.contains(endpoints[1]), "claiming ahead of the tip is not staleness")
        #expect(!seated.contains(endpoints[2]), "a negative height is far behind any tip")
        await pool.stop()
    }

    @Test("peers inside the tolerance keep their seats")
    func nearPeersStay() async throws {
        let synthetic = makeSyntheticChain(length: 120, watchHeight: 3)
        let current = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        let slightlyBehind = LoopbackNode(params: synthetic.params,
                                          chain: Array(synthetic.blocks.prefix(60)))
        try await current.start()
        try await slightlyBehind.start()
        defer { Task { await current.stop() }; Task { await slightlyBehind.stop() } }
        let endpoints = [await current.endpoint, await slightlyBehind.endpoint]

        let pool = PeerPool(params: synthetic.params, peerCount: 2, manualPeers: endpoints)
        await pool.start()
        let chain = try HeaderChain(params: synthetic.params)
        _ = try await pool.syncHeaders(chain)
        let seated = await settle(pool) { $0.count == 2 }
        #expect(Set(seated) == Set(endpoints), "59 blocks apart is inside the tolerance")
        for endpoint in endpoints {
            #expect(await pool.rejectionReason(endpoint) == nil)
        }
        #expect(await pool.coolingEndpoints.isEmpty)
        await pool.stop()
    }

    @Test("a peer the user typed in keeps its seat however far behind it is")
    func manualPeerIsKept() async throws {
        let synthetic = makeSyntheticChain(length: 120, watchHeight: 3)
        let current = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        let ownNode = LoopbackNode(params: synthetic.params) // the user's own node, still syncing
        try await current.start()
        try await ownNode.start()
        defer { Task { await current.stop() }; Task { await ownNode.stop() } }
        let ownEndpoint = await ownNode.endpoint
        let store = tempFileURL("peers.json")
        // The current node arrives as a remembered peer, not a manual one.
        try Self.persistedPeersFile([await current.endpoint]).write(to: store)

        let pool = PeerPool(params: synthetic.params, peerCount: 2, manualPeers: [ownEndpoint],
                            peersFileURL: store)
        await pool.start()
        let chain = try HeaderChain(params: synthetic.params)
        _ = try await pool.syncHeaders(chain)
        let seated = await settle(pool) { $0.count == 2 }
        #expect(seated.contains(ownEndpoint), "the user's explicit choice is not overruled")
        #expect(await pool.rejectionReason(ownEndpoint) == nil)
        await pool.stop()
    }

    @Test("a seat is judged once; the reported height ageing behind a moving tip is not staleness")
    func seatedPeerIsNotRejudgedAsTipAdvances() async throws {
        let long = makeSyntheticChain(length: 250, watchHeight: 3)
        let short = Array(long.blocks.prefix(121)) // heights 0...120, so both report 120
        let manual = LoopbackNode(params: long.params, chain: short)
        let remembered = LoopbackNode(params: long.params, chain: short)
        try await manual.start()
        try await remembered.start()
        defer { Task { await manual.stop() }; Task { await remembered.stop() } }
        let rememberedEndpoint = await remembered.endpoint
        // The remembered peer is the one under judgment; a manual peer is
        // exempt, and one manual seat lets the diversity ceiling seat both.
        let store = tempFileURL("peers.json")
        try Self.persistedPeersFile([rememberedEndpoint]).write(to: store)
        let pool = PeerPool(params: long.params, peerCount: 2,
                            manualPeers: [await manual.endpoint], peersFileURL: store)
        await pool.start()
        _ = await settle(pool) { $0.count == 2 }

        let chain = try HeaderChain(params: long.params)
        _ = try await pool.syncHeaders(chain)
        #expect(await chain.height == 120)
        #expect(await settle(pool) { $0.count == 2 }.count == 2, "judged at 120 against 120: both stay")

        // The chain moves 130 blocks past what the peers reported at their
        // handshake, learned from headers the pool did not get from them.
        _ = try await chain.connect(long.blocks[121...].map(\.header))
        #expect(await chain.height == 250)
        _ = try await pool.syncHeaders(chain)
        let seated = await settle(pool) { $0.count == 2 }
        #expect(seated.contains(rememberedEndpoint),
                "a height that only aged with the tip is not a stale tip; the seat was judged when taken")
        #expect(await pool.rejectionReason(rememberedEndpoint) == nil)
        #expect(await pool.coolingEndpoints.isEmpty)
        await pool.stop()
    }

    @Test("the tolerance is the wallet's reorg horizon")
    func toleranceMatchesHorizon() {
        #expect(PeerPool.staleTipTolerance == 100)
    }

    /// "Reset and shuffle peers" (the Advanced settings control): everything
    /// the pool learned is forgotten — file, cooldowns, session bans — while
    /// the owner's manual peers, being instructions and not memories, stay.
    @Test("forgetKnownGood clears the file and session state; manual peers survive")
    func forgetKnownGoodResetsDiscovery() async throws {
        let synthetic = makeSyntheticChain(length: 4, watchHeight: 2)
        let good = LoopbackNode(params: synthetic.params, chain: synthetic.blocks)
        try await good.start()
        defer { Task { await good.stop() } }
        let goodEndpoint = await good.endpoint
        // A peer that only ever existed as a memory: nothing listens here.
        let ghost = PeerEndpoint(host: "127.0.0.1", port: 29_999)

        let file = tempFileURL("peers-forget.json")
        defer { try? FileManager.default.removeItem(at: file) }
        try JSONEncoder().encode([goodEndpoint, ghost]).write(to: file)

        let pool = PeerPool(params: synthetic.params, peerCount: 1,
                            manualPeers: [goodEndpoint], peersFileURL: file,
                            dialTimeout: .seconds(2))
        await pool.start()
        #expect(await pool.connectedPeers().count == 1)
        if let peer = await pool.connectedPeers().first {
            await pool.transportFailure(peer, reason: "timed out waiting for headers")
        }
        #expect(await pool.isCoolingDown(goodEndpoint))

        await pool.stop()
        #expect(try Self.storedPeers(file).contains(goodEndpoint),
                "stop persists the good peers before the reset")
        try await pool.forgetKnownGood()
        #expect(!FileManager.default.fileExists(atPath: file.path),
                "the persisted peers file is forgotten")
        #expect(await pool.isCoolingDown(goodEndpoint) == false,
                "cooldowns die with the reset")

        // A rebuilt pool dials from instructions alone: the ghost never
        // comes back, and the manual peer reconnects with no memory of the
        // cooldown.
        let rebuilt = PeerPool(params: synthetic.params, peerCount: 1,
                               manualPeers: [goodEndpoint], peersFileURL: file,
                               dialTimeout: .seconds(2))
        await rebuilt.start()
        let rebuiltPeers = await rebuilt.connectedPeers()
        #expect(rebuiltPeers.count == 1)
        #expect(await rebuiltPeers.first?.endpoint == goodEndpoint)
        #expect(await rebuilt.isCoolingDown(goodEndpoint) == false)
        await rebuilt.stop()
        #expect(try Self.storedPeers(file).sorted { $0.port < $1.port } == [goodEndpoint],
                "the re-persisted file holds only peers that actually served")
    }
}

/// A clock the test advances explicitly, so a cooldown can expire without the
/// test taking as long as the cooldown.
final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var offset: Duration = .zero
    private let origin = ContinuousClock.now

    var now: ContinuousClock.Instant {
        lock.lock(); defer { lock.unlock() }
        return origin.advanced(by: offset)
    }

    func advance(by duration: Duration) {
        lock.lock(); defer { lock.unlock() }
        offset += duration
    }
}

private actor DiscoveryGate {
    private var released = false
    func wait() async {
        while !released && !Task.isCancelled { try? await Task.sleep(for: .milliseconds(10)) }
    }
    func release() { released = true }
}
