import Foundation
import Testing
import TestSupport
@testable import WalletCore

@Suite(.timeLimit(.minutes(1)))
struct TailnetGatewayDiscoveryTests {
    @Test func discoversOnlyTailnetAddressesWithSuccessfulSOCKS() async {
        let discovery = TailnetGatewayDiscovery(resolve: { host in
            host == "winnow-tor-gateway" ? ["8.8.8.8", "127.0.0.1", "100.75.175.127"] : ["100.74.30.8"]
        }, probe: { endpoint in
            #expect(endpoint.host.hasPrefix("100."))
            return endpoint.port == 9050
        })
        let result = await discovery.discover()
        #expect(result.networks == [.tor], "a gateway that answers takes clearnet out")
        #expect(result.torProxy == .init(host: "100.75.175.127", port: 9050))
        #expect(result.i2pProxy == nil)
        let absent = await TailnetGatewayDiscovery(resolve: { _ in [] }, probe: { _ in
            Issue.record("Probed an unresolved host"); return true
        }).discover()
        #expect(absent == .init(), "no gateway: clearnet keeps the wallet syncing")
        let both = await TailnetGatewayDiscovery(resolve: { host in
            host == "winnow-tor-gateway" ? ["100.75.175.127"] : ["100.74.30.8"]
        }, probe: { _ in true }).discover()
        #expect(both.networks == [.tor, .i2p])
        #expect(both.torProxy == .init(host: "100.75.175.127", port: 9050))
        #expect(both.i2pProxy == .init(host: "100.74.30.8", port: 4447))
    }

    @Test func cancelledDiscoveryCannotInstallAnEndpoint() async {
        let task = Task {
            await TailnetGatewayDiscovery(resolve: { _ in
                try? await Task.sleep(for: .seconds(30)); return ["100.75.175.127"]
            }, probe: { _ in Issue.record("Probed after cancellation"); return true }).discover()
        }
        task.cancel()
        #expect(await task.value == .init())
    }

    @Test func liveSOCKSProbeAndCancellation() async throws {
        let ready = FakeSocksProxy(upstreamPort: nil)
        let stalled = FakeSocksProxy(upstreamPort: nil, stall: true)
        try await ready.start(); try await stalled.start()
        #expect(await TailnetGatewayDiscovery.probeSOCKS(await ready.endpoint))
        let endpoint = await stalled.endpoint
        let task = Task { await TailnetGatewayDiscovery.probeSOCKS(endpoint) }
        try await Task.sleep(for: .milliseconds(30))
        task.cancel()
        #expect(await task.value == false)
        #expect(await TailnetGatewayDiscovery.probeSOCKS(endpoint) == false, "Silent gateways must time out")
        await ready.stop(); await stalled.stop()
    }

    private func answer(_ query: GatewayDNSQuery, ip: [UInt8] = [100, 75, 175, 127]) -> Data {
        var data = query.bytes
        data[2] = 0x81; data[3] = 0x80; data[7] = 1
        data.append(contentsOf: [0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4] + ip)
        return data
    }

    @Test func validatesDNSReplyBeforeUsingAnyAddress() {
        let query = GatewayDNSQuery(host: "winnow-tor-gateway", id: 1234)
        let valid = answer(query)
        #expect(query.addresses(in: valid) == ["100.75.175.127"])
        #expect(query.addresses(in: answer(query, ip: [8, 8, 8, 8])).isEmpty)
        #expect(query.addresses(in: answer(query, ip: [100, 100, 100, 100])).isEmpty)
        for count in 0..<valid.count { #expect(query.addresses(in: valid.prefix(count)).isEmpty) }
        for (offset, value) in [(0, UInt8(0)), (2, 0x83), (3, 0x83), (12, 0xc0), (13, 12), (valid.count - 12, 0xc0)] {
            var bad = valid; bad[offset] = value
            #expect(query.addresses(in: bad).isEmpty)
        }
        var wrongOwner = valid
        wrongOwner[query.bytes.count + 1] = UInt8(query.bytes.count)
        #expect(query.addresses(in: wrongOwner).isEmpty, "A compression loop cannot supply an address")
    }

    /// The fuzz harness cannot reach this internal parser, so mutate a valid
    /// reply here: flips, insertions and deletions must never trap, and any
    /// address that survives must still be a tailnet IPv4 address.
    @Test func mutatedDNSRepliesNeverTrapOrLeaveTheTailnet() {
        let query = GatewayDNSQuery(host: "winnow-i2p-gateway", id: 0xbeef)
        let valid = Array(answer(query, ip: [100, 74, 30, 8]))
        var state: UInt64 = 0x5eed
        func next(_ bound: Int) -> Int {
            state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            return Int((state >> 33) % UInt64(bound))
        }
        for _ in 0..<20_000 {
            var bytes = valid
            for _ in 0...next(4) {
                switch next(3) {
                case 0: bytes[next(bytes.count)] = UInt8(next(256))
                case 1: bytes.insert(UInt8(next(256)), at: next(bytes.count + 1))
                default: if bytes.count > 1 { bytes.remove(at: next(bytes.count)) }
                }
            }
            for address in query.addresses(in: Data(bytes)) {
                #expect(TailnetGatewayDiscovery.isTailnetIPv4(address), "\(address)")
            }
        }
    }
}

/// A read-only check over live Tor and I2P through the deployed gateways, by
/// hand from the tailnet (`scripts/check-live-gateways`). A hidden-service dial
/// gets the app's 30-second gateway timeout, so this needs more than a minute.
@Suite(.timeLimit(.minutes(5)))
struct LiveOverlayTests {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["WINNOW_LIVE_GATEWAYS"] == "1"))
    func deployedMagicDNSGateways() async throws {
        let config = await TailnetGatewayDiscovery().discover()
        #expect(config.networks == [.tor, .i2p])
        _ = try #require(config.torProxy)
        _ = try #require(config.i2pProxy)
        print("Discovered gateways: \(config.torProxy?.description ?? "none"), \(config.i2pProxy?.description ?? "none")")
        // The census list a build would ship, which the script fetches first.
        let path = try #require(ProcessInfo.processInfo.environment["WINNOW_LIVE_CENSUS"])
        let catalog = try CensusCatalog.decode(Data(contentsOf: URL(filePath: path)),
                                               minimumEntries: CensusCatalog.minimumClearnetEntries)
        await handshake(catalog, through: config)
    }

    /// Up to five listed peers per overlay, in a fresh order each run, so a
    /// few dead entries at the top of the list cannot fail every check.
    private func handshake(_ catalog: CensusCatalog, through config: PeerGatewayConfiguration) async {
        await withTaskGroup(of: Void.self) { group in
            for network in [PeerNetwork.tor, .i2p] {
                group.addTask {
                    for entry in catalog.networks[network.rawValue, default: []].shuffled().prefix(5) {
                        let peer = PeerConnection(endpoint: entry.endpoint, params: .mainnet,
                                                  socksProxy: config.proxy(for: entry.endpoint))
                        do {
                            try await peer.connect(timeout: .seconds(30))
                            print("Live \(network.rawValue) Bitcoin handshake: \(await peer.peerUserAgent)")
                            await peer.disconnect()
                            return
                        } catch {
                            await peer.disconnect()
                        }
                    }
                    Issue.record("No live \(network.rawValue) peer answered through its gateway")
                }
            }
        }
    }
}

/// Discovery and routing against a real tailnet that scripts/ci-tailnet builds
/// on the runner: Headscale, a client tailscaled whose 100.100.100.100 answers
/// as on a phone, and two gateway nodes under the conventional names that
/// forward 9050 and 4447 to this test's fake SOCKS proxies in front of loopback
/// nodes. No Tor or I2P: the census's daily crawl dials those with this code.
@Suite(.timeLimit(.minutes(2)))
struct TailnetSimulationTests {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["WINNOW_TAILNET_SIMULATION"] == "1"))
    func discoversAndRoutesThroughSimulatedGateways() async throws {
        let torNode = LoopbackNode(params: .signet)
        let i2pNode = LoopbackNode(params: .signet)
        try await torNode.start(); try await i2pNode.start()
        let tor = FakeSocksProxy(upstreamPort: await torNode.endpoint.port, listenPort: 19050)
        let i2p = FakeSocksProxy(upstreamPort: await i2pNode.endpoint.port, listenPort: 14447)
        try await tor.start(); try await i2p.start()
        let config = await TailnetGatewayDiscovery().discover()
        #expect(config.networks == [.tor, .i2p])
        let torProxy = try #require(config.torProxy), i2pProxy = try #require(config.i2pProxy)
        #expect(TailnetGatewayDiscovery.isTailnetIPv4(torProxy.host) && torProxy.port == 9050)
        #expect(TailnetGatewayDiscovery.isTailnetIPv4(i2pProxy.host) && i2pProxy.port == 4447)
        let onion = PeerEndpoint(host: String(repeating: "a", count: 56) + ".onion", port: 8333)
        let destination = PeerEndpoint(host: String(repeating: "b", count: 52) + ".b32.i2p", port: 8333)
        let pool = PeerPool(params: .signet, peerCount: 2, manualPeers: [onion, destination],
                            dialTimeout: .seconds(30), seedResolver: SeedResolver { _, _, _ in [] }, gateways: config)
        await pool.start()
        #expect(await pool.connectedPeers().count == 2)
        #expect(await tor.requestedHosts.contains(onion.host))
        #expect(await i2p.requestedHosts.contains(destination.host))
        await pool.stop(); await tor.stop(); await i2p.stop(); await torNode.stop(); await i2pNode.stop()
    }
}
