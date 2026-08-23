import Foundation
import Testing
@testable import BitcoinP2P

/// The pool must not end up behind one operator (#3, #4).
///
/// `replenish` races every candidate and keeps whichever connects first. On a
/// hostile network that is exactly the wrong rule: an attacker running nodes
/// near the device wins every latency race, and can take every slot without
/// doing anything a peer is not allowed to do. Nothing about the wire protocol
/// detects this — every one of those peers behaves correctly and agrees with
/// itself.
///
/// The two rules here are ceilings, not quotas: they say what a pool may not
/// become, never what it must contain. A quota would refuse to connect at all
/// when a class is unreachable, trading a certain outage for a possible
/// attacker.
///
/// The owner decision this backs (2026-08-23) was to accept single-peer
/// operation rather than fail closed, with peer diversity as the mitigation.
@Suite("Peer diversity")
struct PeerDiversityTests {
    private func policy(_ peerCount: Int = 3) -> DiversityPolicy {
        DiversityPolicy(peerCount: peerCount)
    }

    private func candidate(_ host: String, _ source: PeerSource) -> PeerCandidate {
        PeerCandidate(endpoint: PeerEndpoint(host: host, port: 8333), source: source)
    }

    // MARK: - Netblock

    @Test("IPv4 groups by /16 and IPv6 by /32")
    func netblockGrouping() {
        #expect(PeerEndpoint.netblock(forHost: "47.206.253.100") == "v4:47.206")
        #expect(PeerEndpoint.netblock(forHost: "47.206.1.1") == "v4:47.206")
        #expect(PeerEndpoint.netblock(forHost: "47.207.253.100") != "v4:47.206")
        #expect(PeerEndpoint.netblock(forHost: "2a01:4f8:1:2::1") == "v6:2a01:04f8")
        #expect(PeerEndpoint.netblock(forHost: "2a01:4f8:9:9::9") == "v6:2a01:04f8")
        #expect(PeerEndpoint.netblock(forHost: "2a02:4f8:1:2::1") != "v6:2a01:04f8")
    }

    /// Unrestricted, and for two different reasons — see `netblock`.
    @Test("hostnames and non-public addresses are not restricted")
    func unrestrictedHosts() {
        #expect(PeerEndpoint.netblock(forHost: "node.example.com") == nil)
        #expect(PeerEndpoint.netblock(forHost: "127.0.0.1") == nil, "a loopback test pool")
        #expect(PeerEndpoint.netblock(forHost: "192.168.1.10") == nil, "a home network")
        #expect(PeerEndpoint.netblock(forHost: "10.0.0.5") == nil)
        #expect(PeerEndpoint.netblock(forHost: "::1") == nil)
        #expect(PeerEndpoint.netblock(forHost: "fe80::1") == nil)
        #expect(PeerEndpoint.netblock(forHost: "not an address") == nil)
    }

    @Test("a second peer from the same block is refused")
    func sameBlockRefused() {
        let seated = [candidate("47.206.253.100", .fallback)]
        #expect(policy().admits(candidate("47.206.1.1", .dnsSeed), given: seated) == false,
                "one operator's neighbouring addresses are close to one peer")
        #expect(policy().admits(candidate("74.209.75.75", .dnsSeed), given: seated))
    }

    /// The rule must not stop a loopback or home-network pool from filling, or
    /// it breaks a working setup to defend against nothing.
    @Test("several peers on one private network all connect")
    func privateNetworkUnaffected() {
        var seated: [PeerCandidate] = []
        for port in 0 ..< 3 {
            let next = PeerCandidate(endpoint: PeerEndpoint(host: "127.0.0.1",
                                                            port: UInt16(18_333 + port)),
                                     source: .manual)
            #expect(policy().admits(next, given: seated))
            seated.append(next)
        }
    }

    // MARK: - Source class

    @Test("no source class may hold every slot")
    func noClassOwnsThePool() {
        let seated = [candidate("1.1.1.1", .persisted), candidate("2.2.2.2", .persisted)]
        #expect(policy().admits(candidate("3.3.3.3", .persisted), given: seated) == false,
                "the third slot must come from somewhere else")
        #expect(policy().admits(candidate("3.3.3.3", .fallback), given: seated))
        #expect(policy().admits(candidate("3.3.3.3", .dnsSeed), given: seated))
    }

    /// Two of one class is fine — the rule is a ceiling on total capture, not a
    /// requirement that every class be represented.
    @Test("two of one class is allowed")
    func twoOfOneClassAllowed() {
        let seated = [candidate("1.1.1.1", .persisted)]
        #expect(policy().admits(candidate("2.2.2.2", .persisted), given: seated))
    }

    /// A peer the user typed in is instruction, not selection. Someone who
    /// configures three of their own nodes must get three.
    @Test("manual peers are exempt from the source ceiling")
    func manualPeersExempt() {
        let seated = [candidate("1.1.1.1", .manual), candidate("2.2.2.2", .manual)]
        #expect(policy().admits(candidate("3.3.3.3", .manual), given: seated))
    }

    /// …but not from the netblock rule: choosing two neighbouring addresses by
    /// hand does not make them independent.
    @Test("manual peers are still subject to the netblock rule")
    func manualPeersStillBlocked() {
        let seated = [candidate("47.206.253.100", .manual)]
        #expect(policy().admits(candidate("47.206.9.9", .manual), given: seated) == false)
    }

    /// A single-slot pool has nothing to diversify.
    @Test("a one-peer pool admits anything")
    func singleSlotPool() {
        #expect(policy(1).admits(candidate("1.1.1.1", .persisted),
                                 given: [candidate("2.2.2.2", .persisted)]))
    }

    // MARK: - The peers file

    /// A file written before this change is a bare array with no class. It must
    /// still load, and its entries are `persisted` because that is what they
    /// are: peers this device connected to on an earlier run.
    @Test("a pre-existing peers file still loads")
    func legacyPeersFileLoads() throws {
        let endpoints = [PeerEndpoint(host: "47.206.253.100", port: 8333),
                         PeerEndpoint(host: "74.209.75.75", port: 8333)]
        let data = try JSONEncoder().encode(endpoints)
        let decoded = try #require(PersistedPeers.decode(data))
        #expect(decoded.map(\.endpoint) == endpoints)
        #expect(decoded.allSatisfy { $0.source == .persisted })
    }

    /// The class has to survive a restart, because a successful dial promotes
    /// an endpoint into the known-good set whatever its origin. Without this,
    /// every peer collapses to `persisted` after its first connection and the
    /// pool forgets it ever had a diverse set of sources.
    @Test("the source class round-trips through the peers file")
    func sourceSurvivesARestart() throws {
        let candidates = [candidate("47.206.253.100", .dnsSeed),
                          candidate("74.209.75.75", .fallback),
                          candidate("65.109.145.24", .manual)]
        let data = try JSONEncoder().encode(PersistedPeers(candidates))
        let decoded = try #require(PersistedPeers.decode(data))
        #expect(decoded == candidates)
    }

    @Test("an unreadable peers file is not mistaken for an empty one")
    func garbagePeersFile() {
        #expect(PersistedPeers.decode(Data("not json".utf8)) == nil)
    }
}
