import Foundation
import Testing
@testable import BitcoinP2P

/// A slow peer is cooled off; a dishonest one is banned (#82).
///
/// One `chain.sync(using:)` call runs an entire header sync against a single
/// peer — around 460 round trips on mainnet. Every error inside that loop, a
/// single lagging reply included, went through `misbehaving`, which drops the
/// endpoint from `knownGood` *and* bars it for the session. `knownGood` is the
/// persisted peers file, so one slow reply did not merely cost a peer for this
/// run: it degraded every future launch. That is the "peers are lagging me
/// out" report.
///
/// The distinction these pin is between the connection failing and the peer
/// being untruthful. The first is temporary and common; the second is the
/// thing bans exist for.
@Suite("Peer cooldown")
struct PeerCooldownTests {

    static func peersFile() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("winnow-cooldown-peers-\(UUID().uuidString).json")
    }

    /// Reads the peers file in whichever format it holds. The seeding below
    /// deliberately writes the pre-#3 bare array, so these also exercise the
    /// migration: an old file must still load, and its entries are classed
    /// `persisted` because that is what they are.
    static func storedPeers(_ url: URL) throws -> Set<PeerEndpoint> {
        guard let data = try? Data(contentsOf: url),
              let stored = PersistedPeers.decode(data)
        else { return [] }
        return Set(stored.map(\.endpoint))
    }

    // MARK: - The escalation schedule, without a clock

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

    // MARK: - The reported bug

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

        let file = Self.peersFile()
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

        let file = Self.peersFile()
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

    // MARK: - Cooling is temporary

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
