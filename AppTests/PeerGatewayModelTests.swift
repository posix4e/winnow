@testable import WinnowApp
import WalletCore
import XCTest

private actor GatewayReply {
    private var reply: CheckedContinuation<PeerGatewayConfiguration, Never>?
    var waiting: Bool { reply != nil }
    func discover() async -> PeerGatewayConfiguration { await withCheckedContinuation { reply = $0 } }
    func finish(_ config: PeerGatewayConfiguration) { reply?.resume(returning: config); reply = nil }
}

@MainActor
final class PeerGatewayModelTests: XCTestCase {
    private let discovered = PeerGatewayConfiguration(networks: [.tor], torProxy: .init(host: "100.75.175.127", port: 9050))

    func testAutomaticDefaultAndManualOverridePersistAcrossModes() async throws {
        let defaults = makeDefaults()
        let model = makeModel(defaults: defaults)
        XCTAssertEqual(model.gatewaySettings.mode, .automatic)
        let config = PeerGatewayConfiguration(networks: [.i2p], i2pProxy: .init(host: "gateway", port: 4447))
        try await model.setPeerGatewaySettings(.init(mode: .manual, manual: config))
        model.setAdvancedMode(false)
        let relaunched = makeModel(defaults: defaults)
        XCTAssertEqual(relaunched.gatewaySettings, .init(mode: .manual, manual: config))
        // I2P alone makes no HTTP request: its gateway is never asked for a public host.
        XCTAssertFalse(relaunched.httpClient.enabled)
        do {
            try await model.setPeerGatewaySettings(.init(mode: .manual, manual: .init(networks: [])))
            XCTFail("Invalid edit must not overwrite settings")
        } catch {}
        XCTAssertEqual(makeModel(defaults: defaults).gatewaySettings.manual, config)
        try await model.setPeerGatewaySettings(.init(mode: .direct))
        XCTAssertEqual(makeModel(defaults: defaults).gatewaySettings.mode, .direct)
    }

    func testRoutingBannerSaysWhetherPeersSeeTheIPAddress() {
        let tor = PeerEndpoint(host: "100.75.175.127", port: 9050), i2p = PeerEndpoint(host: "100.74.30.8", port: 4447)
        func state(_ mode: PeerGatewaySettings.Mode, _ config: PeerGatewayConfiguration, discovering: Bool = false) -> PeerRoutingState {
            PeerRoutingState.current(mode: mode, active: config, discovering: discovering)
        }
        XCTAssertEqual(state(.automatic, .init(networks: [.tor, .i2p], torProxy: tor, i2pProxy: i2p)), .overlay(tor: true, i2p: true))
        XCTAssertEqual(state(.automatic, .init(networks: [.tor], torProxy: tor)), .overlay(tor: true, i2p: false))
        XCTAssertEqual(state(.automatic, .init()), .direct(fallback: true))
        XCTAssertEqual(state(.direct, .init()), .direct(fallback: false))
        XCTAssertEqual(state(.manual, .init(networks: [.clearnet, .i2p], i2pProxy: i2p)), .mixed)
        XCTAssertEqual(state(.automatic, .init(), discovering: true), .checking)
        XCTAssertEqual(state(.manual, .init(networks: [])), .offline)
        XCTAssertEqual(PeerRoutingState.overlay(tor: true, i2p: true).message, "Private: peers reached through Tor and I2P")
        XCTAssertTrue(PeerRoutingState.direct(fallback: true).message.contains("can see your IP address"))
        XCTAssertTrue(PeerRoutingState.mixed.message.contains("can see your IP address"))
    }

    func testCandidateCountFollowsRoutedNetworks() {
        let entry = CensusCatalog.Entry(host: "8.8.8.8", port: 8333, userAgent: "/Satoshi:30/", startHeight: 900_000)
        let catalog = CensusCatalog(date: "2026-09-28", tip: 900_000,
                                    networks: ["clearnet": [entry, entry], "tor": [entry], "i2p": [entry, entry, entry]])
        XCTAssertEqual(AppModel.candidateCount(catalog), "2 candidates")
        XCTAssertEqual(AppModel.candidateCount(catalog, networks: [.i2p]), "3 candidates")
        XCTAssertEqual(AppModel.candidateCount(catalog, networks: [.tor]), "1 candidate")
        XCTAssertEqual(AppModel.candidateCount(catalog, networks: [.clearnet, .tor, .i2p]), "6 candidates")
    }

    func testCorruptSavedSettingsStayOffline() async {
        let defaults = makeDefaults()
        defaults.set(Data("broken".utf8), forKey: "peerGatewaySettings")
        let model = makeModel(defaults: defaults)
        await model.preparePeerGateways()
        XCTAssertFalse(model.activePeerGateways.isValid)
        XCTAssertFalse(model.httpClient.enabled)
    }

    func testDiscoveredAddressesAreNotPersisted() async {
        let defaults = makeDefaults()
        let config = discovered
        let model = AppModel(e2e: nil, defaults: defaults, discoverGateways: { config })
        await model.preparePeerGateways()
        XCTAssertEqual(model.activePeerGateways, config)
        XCTAssertNil(defaults.object(forKey: "peerGatewaySettings"))
        XCTAssertEqual(makeModel(defaults: defaults).activePeerGateways, .init())
    }

    func testDiscoveryIsSharedUntilTheNetworkingGenerationEnds() async {
        let reply = GatewayReply()
        let model = AppModel(e2e: nil, defaults: makeDefaults(), discoverGateways: { await reply.discover() })
        let first = Task { await model.preparePeerGateways() }
        while !(await reply.waiting) { await Task.yield() }
        let second = Task { await model.preparePeerGateways() }
        await reply.finish(discovered)
        await first.value
        await second.value
        // This must use the completed result, rather than start another
        // suspended query when wallet creation asks for the stack.
        await model.preparePeerGateways()
        XCTAssertEqual(model.activePeerGateways, discovered)
        let waiting = await reply.waiting
        XCTAssertFalse(waiting)
        await model.scenePhaseChanged(.background)
        let next = Task { await model.preparePeerGateways() }
        while !(await reply.waiting) { await Task.yield() }
        await reply.finish(.init())
        await next.value
        XCTAssertEqual(model.activePeerGateways, .init())
    }

    func testBackgroundAndManualChangeDiscardStaleDiscovery() async throws {
        for changeMode in [false, true] {
            let reply = GatewayReply()
            let model = AppModel(e2e: nil, defaults: makeDefaults(), discoverGateways: { await reply.discover() })
            let task = Task { await model.preparePeerGateways() }
            while !(await reply.waiting) { await Task.yield() }
            if changeMode { try await model.setPeerGatewaySettings(.init(mode: .direct)) }
            else { await model.scenePhaseChanged(.background) }
            await reply.finish(discovered)
            await task.value
            XCTAssertEqual(model.activePeerGateways, .init())
            XCTAssertFalse(model.discoveringGateways)
        }
    }
}
