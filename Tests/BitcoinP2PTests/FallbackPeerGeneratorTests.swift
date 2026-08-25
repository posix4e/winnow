import BitcoinCore
import Foundation
import Testing
@testable import BitcoinP2P

/// Always-on validation of the committed fallback list (#161).
///
/// The generator below runs only on the release path; this runs on every CI
/// pass, so a hand edit that breaks the list's invariants fails immediately
/// rather than at the next release.
@Suite("Fallback peer list")
struct FallbackPeerListTests {
    @Test("the committed mainnet list holds the generator's own invariants")
    func committedListIsValid() throws {
        let peers = NetworkParams.mainnet.fallbackPeers
        #expect(peers.count >= 8, "shorter than the hand-curated list it replaced")

        var seenBlocks: Set<String> = []
        var seenHosts: Set<String> = []
        for peer in peers {
            // IP literals only: a hostname would add a resolver to the trust
            // story, and `netblock` is nil for hostnames — which doubles as
            // the literal check.
            let block = try #require(peer.netblock,
                                     "\(peer.host) is not a public IP literal")
            #expect(!seenBlocks.contains(block),
                    "\(peer.host) shares a netblock with an earlier entry")
            #expect(!seenHosts.contains(peer.host), "\(peer.host) is listed twice")
            seenBlocks.insert(block)
            seenHosts.insert(peer.host)
            #expect(peer.port == 8_333)
        }
    }
}

/// Release-path generator (#161): `WINNOW_GENERATE_FALLBACK_PEERS=1` only,
/// via `scripts/generate-fallback-peers`. Everything else about the run skips.
///
/// The verification bar is not re-implemented: `PeerConnection.connect`
/// already refuses any peer whose version does not advertise
/// NODE_COMPACT_FILTERS, so a completed handshake *is* the check the
/// hand-curated list was held to. Spread is enforced with the same
/// `netblock` the pool's diversity policy uses.
private let generateEnabled =
    ProcessInfo.processInfo.environment["WINNOW_GENERATE_FALLBACK_PEERS"] == "1"

@Suite("Fallback peer generator", .enabled(if: generateEnabled))
struct FallbackPeerGeneratorTests {
    /// Below this the run fails rather than shipping a thin list: a silent
    /// degradation is exactly what generation exists to prevent.
    private static let floor = 24
    /// Past this the returns diminish; Core's contrib/seeds filters to the
    /// same order of magnitude.
    private static let target = 96
    private static let dialTimeout: Duration = .seconds(5)
    private static let parallelDials = 24

    @Test("resolve, dial, filter, and emit the generated source")
    func generate() async throws {
        let params = NetworkParams.mainnet
        let resolver = SeedResolver.live()
        var candidates = await resolver.resolveSeeds(params.dnsSeeds, port: params.defaultPort,
                                                     allowPrivate: false)
        candidates.shuffle()
        print("generator: \(candidates.count) candidates from \(params.dnsSeeds.count) seeds")
        try #require(candidates.count >= Self.floor,
                     "seed resolution produced too few candidates to even try")

        struct Verified {
            let endpoint: PeerEndpoint
            let userAgent: String
            let startHeight: Int32
        }
        var verified: [Verified] = []
        var blocks: Set<String> = []
        var cursor = 0
        while verified.count < Self.target, cursor < candidates.count {
            let batch = Array(candidates[cursor ..< min(cursor + Self.parallelDials,
                                                        candidates.count)])
            cursor += batch.count
            let results = await withTaskGroup(of: Verified?.self) { group in
                for endpoint in batch {
                    group.addTask {
                        let peer = PeerConnection(endpoint: endpoint, params: params)
                        do {
                            try await peer.connect(timeout: Self.dialTimeout)
                            let agent = await peer.peerUserAgent ?? "?"
                            let height = await peer.peerStartHeight ?? 0
                            await peer.disconnect()
                            return Verified(endpoint: endpoint, userAgent: agent,
                                            startHeight: height)
                        } catch {
                            return nil
                        }
                    }
                }
                var collected: [Verified] = []
                for await result in group { if let result { collected.append(result) } }
                return collected
            }
            for peer in results {
                guard let block = peer.endpoint.netblock, !blocks.contains(block) else { continue }
                blocks.insert(block)
                verified.append(peer)
            }
            print("generator: \(verified.count)/\(Self.target) verified after \(cursor) dials")
        }

        try #require(verified.count >= Self.floor,
                     "only \(verified.count) filter-serving peers verified — refusing to ship a thin list")

        // The observed tip: the median of what the verified peers report,
        // which no single lying peer can move.
        let heights = verified.map(\.startHeight).sorted()
        let tip = heights[heights.count / 2]
        let date = ISO8601DateFormatter().string(from: Date())
        let entries = verified
            .sorted { $0.endpoint.host < $1.endpoint.host }
            .map { peer in
                "        PeerEndpoint(host: \"\(peer.endpoint.host)\", "
                + "port: \(peer.endpoint.port)),  // \(peer.userAgent)"
            }
            .joined(separator: "\n")

        let source = """
        // GENERATED FILE — edit by regenerating, not by hand.
        //
        // scripts/generate-fallback-peers rewrites this file on the release path
        // (#161): it resolves the mainnet DNS seeds, dials candidates with the same
        // PeerConnection the app uses — whose handshake already refuses any peer not
        // advertising NODE_COMPACT_FILTERS — and keeps a /16-spread selection, checked
        // by the same `PeerEndpoint.netblock` the pool's diversity policy uses.
        //
        // The committed copy is the last verified generation and the build's fallback;
        // a release regenerates so freshness tracks releases rather than memory.
        // `FallbackPeerListTests` validates this file on every CI run.
        //
        // What this is not, recorded so it is not over-claimed: the list inherits
        // whatever the generating host could see, and generation is not reproducible —
        // two runs give different lists. The generation log is kept as a release
        // artifact so the list is auditable even though it is not reproducible.
        //
        // Generation: \(date), \(verified.count) peers verified, median reported
        // tip \(tip).
        extension NetworkParams {
            static let generatedMainnetFallbackPeers: [PeerEndpoint] = [
        \(entries)
            ]
        }
        """

        // Tests/BitcoinP2PTests/… → the package root is three levels up.
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let out = root.appending(path: "Sources/BitcoinP2P/Protocol/FallbackPeersGenerated.swift")
        try Data((source + "\n").utf8).write(to: out, options: .atomic)
        print("generator: wrote \(verified.count) peers, median tip \(tip), to \(out.path)")
    }
}
