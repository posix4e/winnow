import Foundation
import Testing
import TestSupport
@testable import WalletCore

@Suite(.timeLimit(.minutes(1)))
struct PeerGatewayTests {
    private let onion = PeerEndpoint(host: String(repeating: "a", count: 56) + ".onion", port: 8333)
    private let i2p = PeerEndpoint(host: String(repeating: "b", count: 52) + ".b32.i2p", port: 8333)
    private let proxy = PeerEndpoint(host: "100.75.175.127", port: 9050)

    @Test func everyNetworkSelectionFiltersAllCandidateSources() async throws {
        let fixture = CensusCatalogTests()
        let direct = PeerEndpoint(host: "8.8.8.8", port: 8333)
        for bits in 1...7 {
            let networks = Set(PeerNetwork.allCases.enumerated().compactMap { bits & (1 << $0.offset) == 0 ? nil : $0.element })
            let config = PeerGatewayConfiguration(networks: networks, torProxy: proxy, i2pProxy: proxy)
            let file = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
            defer { try? FileManager.default.removeItem(at: file) }
            try JSONEncoder().encode([onion, i2p, direct]).write(to: file)
            let pool = PeerPool(params: .mainnet, manualPeers: [direct, onion, i2p], peersFileURL: file,
                                censusCatalog: fixture.catalog(), gateways: config)
            let candidates = await pool.candidateEndpointsForTest()
            #expect(!candidates.isEmpty)
            #expect(candidates.allSatisfy { networks.contains(PeerNetwork(host: $0.host)) })
            #expect(config.httpProxy == (networks.contains(.clearnet) ? nil : proxy))
            #expect(config.permitsHTTP == !networks.isDisjoint(with: [.clearnet, .tor]))
        }
        for config in [PeerGatewayConfiguration(networks: []), .init(networks: [.tor]), .init(networks: [.i2p])] {
            #expect(!config.isValid)
            #expect(!config.permits(direct))
            #expect(!config.permits(onion))
            #expect(!config.permitsHTTP)
        }
        #expect(!PeerGatewayConfiguration().permits(onion))
        #expect(!PeerGatewayConfiguration().permits(.init(host: "unusable.ONION.", port: 8333)))
    }

    @Test func catalogInterleavesNetworksBeforeFillingDialSlots() async throws {
        let fixture = CensusCatalogTests()
        var catalog = fixture.catalog()
        catalog.networks["i2p"] = [.init(host: i2p.host, port: i2p.port, userAgent: "/Satoshi:30/", startHeight: 900_000)]
        let config = PeerGatewayConfiguration(networks: [.clearnet, .tor, .i2p], torProxy: proxy, i2pProxy: proxy)
        let pool = PeerPool(params: .mainnet, censusCatalog: catalog, gateways: config)
        let candidates = await pool.candidateEndpointsForTest()
        #expect(candidates.prefix(3).map { PeerNetwork(host: $0.host) } == [.clearnet, .tor, .i2p])
    }

    @Test func poolUsesSeparateGatewaysAndKeepsDestinationNames() async throws {
        let node = LoopbackNode(params: .signet)
        try await node.start()
        let torNode = LoopbackNode(params: .signet)
        let i2pNode = LoopbackNode(params: .signet)
        try await torNode.start(); try await i2pNode.start()
        let tor = FakeSocksProxy(upstreamPort: await torNode.endpoint.port)
        let i2pProxy = FakeSocksProxy(upstreamPort: await i2pNode.endpoint.port)
        try await tor.start(); try await i2pProxy.start()
        let config = PeerGatewayConfiguration(networks: [.clearnet, .tor, .i2p], torProxy: await tor.endpoint, i2pProxy: await i2pProxy.endpoint)
        let pool = PeerPool(params: .signet, peerCount: 3, manualPeers: [await node.endpoint, onion, i2p],
                            dialTimeout: .seconds(30), seedResolver: SeedResolver { _, _, _ in [] }, gateways: config)
        await pool.start()
        #expect(await pool.connectedPeers().count == 3)
        #expect(await tor.requestedHosts == [onion.host])
        #expect(await i2pProxy.requestedHosts == [i2p.host])
        await pool.stop(); await tor.stop(); await i2pProxy.stop(); await node.stop()
        await torNode.stop(); await i2pNode.stop()
    }

    @Test func unavailableOverlayDoesNotUseClearnetOrDNSSeeds() async throws {
        let node = LoopbackNode(params: .mainnet)
        try await node.start()
        let refused = FakeSocksProxy(upstreamPort: nil, refuseWith: 4)
        try await refused.start()
        let config = PeerGatewayConfiguration(networks: [.tor], torProxy: await refused.endpoint)
        let pool = PeerPool(params: .mainnet, manualPeers: [await node.endpoint, onion],
                            seedResolver: SeedResolver { _, _, _ in Issue.record("Overlay-only routing queried a clearnet seed"); return [] },
                            gateways: config)
        await pool.start()
        #expect(await pool.connectedPeers().isEmpty)
        #expect(await refused.requestedHosts == [onion.host])
        #expect(await node.nextMessage(command: "version", timeout: .milliseconds(50)) == nil)
        await pool.stop(); await refused.stop(); await node.stop()
        let http = RoutedHTTPClient(enabled: false)
        await #expect(throws: RoutedHTTPClient.Failure.unavailable) {
            try await http.get(URL(string: "https://example.com")!, maximumBytes: 1024)
        }
    }

    @Test func proxyParsingAndOverlayShape() throws {
        #expect(try PeerGatewayConfiguration.parseProxy(" [fd7a:115c:a1e0::1]:9050 ") == .init(host: "fd7a:115c:a1e0::1", port: 9050))
        for value in ["http://example.com:9050", "user@example.com:9050", "host:0", "host", "some onion:9050", "a.onion:9050", "fd7a::1:9050"] {
            #expect(throws: PeerGatewayConfiguration.Invalid.address) { try PeerGatewayConfiguration.parseProxy(value) }
        }
        #expect(PeerNetwork.tor.canonicalHost(onion.host.uppercased()) == onion.host)
        #expect(PeerNetwork.i2p.canonicalHost(i2p.host) == i2p.host)
        #expect(PeerNetwork.tor.canonicalHost("short.onion") == nil)
        #expect(PeerNetwork.i2p.canonicalHost(String(repeating: "0", count: 52) + ".b32.i2p") == nil)
    }

    @Test func torHTTPUsesTheGatewayForRemoteResolution() async throws {
        let server = LoopbackHTTPServer(response: Data("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".utf8))
        try await server.start()
        let proxy = FakeSocksProxy(upstreamPort: await server.port)
        try await proxy.start()
        let http = RoutedHTTPClient(proxy: await proxy.endpoint)
        let body = try await http.get(URL(string: "http://gateway-http.invalid/test")!, maximumBytes: 100)
        #expect(body == Data("ok".utf8))
        #expect(await proxy.requestedHost == "gateway-http.invalid")
        http.cancel()
        await proxy.stop(); await server.stop()
    }
}
