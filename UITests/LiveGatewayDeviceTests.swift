import XCTest

/// Selected explicitly by scripts/check-live-gateways-ui on a paired iPhone or
/// simulator whose network is on the tailnet running both gateways
/// (docs/peer-gateways.md). CI has no tailnet, so the journey skips there.
/// A disposable mainnet wallet with no funds; nothing is sent.
@MainActor
final class LiveGatewayDeviceTests: XCTestCase {
    func testRealGatewaysDiscoverAndRoute() throws {
        guard ProcessInfo.processInfo.environment["WINNOW_LIVE_GATEWAYS_UI"] == "1" else {
            throw XCTSkip("Run scripts/check-live-gateways-ui on the tailnet for the live gateway journey")
        }
        continueAfterFailure = false
        let app = XCUIApplication()
        app.launchEnvironment = [
            "WINNOW_E2E": "1", "WINNOW_E2E_RUN": "live-gateways-\(UUID().uuidString)",
            "WINNOW_E2E_ENTROPY": "000102030405060708090a0b0c0d0e0f",
            "WINNOW_E2E_RESET": "1", "WINNOW_E2E_ADVANCED": "1",
            "WINNOW_E2E_NETWORK": "mainnet", "WINNOW_E2E_TAB": "settings",
            "WINNOW_E2E_LIVE_GATEWAYS": "1",
        ]
        app.launch()
        defer { app.terminate() }
        XCTAssertTrue(app.buttons["createWalletButton"].waitForExistence(timeout: 60))
        app.buttons["createWalletButton"].tap()

        // Automatic: both named gateways are discovered through MagicDNS.
        let routing = app.buttons["gatewayRoutingMode"]
        XCTAssertTrue(scrollUntilExists(app, routing, fullyVisible: true))
        for name in ["Active Tor gateway", "Active I2P gateway"] {
            let label = element(app, beginningWith: name)
            XCTAssertTrue(poll(timeout: 60, interval: 2, name) { scrollUntilExists(app, label, maxSwipes: 2) }, name)
        }
        capture(app, "device-gateways-automatic")

        // I2P alone: a peer from the shipped list is an I2P destination.
        choose(app, networks: [.i2p], gateway: ("i2pGatewayAddress", "winnow-i2p-gateway:4447"))
        waitForPeer(app, suffix: ".b32.i2p:", "a real I2P Bitcoin handshake")
        capture(app, "device-i2p-bitcoin")

        // Tor alone: a peer is an onion destination.
        choose(app, networks: [.tor], gateway: ("torGatewayAddress", "winnow-tor-gateway:9050"))
        waitForPeer(app, suffix: ".onion:", "a real onion Bitcoin handshake")
        capture(app, "device-tor-bitcoin")
    }

    private enum Network: String, CaseIterable { case clearnet, tor, i2p }

    /// Manual routing with exactly `networks` on, one gateway entered, applied.
    private func choose(_ app: XCUIApplication, networks: Set<Network>, gateway: (String, String)) {
        let routing = app.buttons["gatewayRoutingMode"]
        XCTAssertTrue(scrollUntilExists(app, routing, maxSwipes: 16, up: true, fullyVisible: true))
        routing.tap()
        app.buttons["Manual"].tap()
        // Turn wanted networks on before unwanted ones off, so the selection is never empty.
        for on in [true, false] {
            for network in Network.allCases where networks.contains(network) == on {
                let toggle = app.switches["peerType_\(network.rawValue)"]
                XCTAssertTrue(scrollUntilExists(app, toggle, fullyVisible: true))
                if (toggle.value as? String == "1") != on {
                    // SwiftUI exposes the whole labeled row as the switch.
                    toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)).tap()
                }
                XCTAssertEqual(toggle.value as? String, on ? "1" : "0")
            }
        }
        let field = app.textFields[gateway.0]
        XCTAssertTrue(scrollUntilExists(app, field, fullyVisible: true))
        // A fresh wallet's gateway fields start empty.
        if field.value as? String != gateway.1 { app.typeInto(gateway.0, gateway.1) }
        XCTAssertEqual(field.value as? String, gateway.1)
        let apply = app.buttons["applyPeerRouting"]
        XCTAssertTrue(scrollUntilExists(app, apply, fullyVisible: true))
        apply.tap()
    }

    private func waitForPeer(_ app: XCUIApplication, suffix: String, _ message: String) {
        let peers = app.buttons["refreshPeersButton"]
        // A gateway field can keep the keyboard up, and then swipes miss the list.
        app.dismissKeyboard()
        // Applying routing can leave the list above or below this section.
        let found = scrollUntilExists(app, peers, maxSwipes: 16)
            || scrollUntilExists(app, peers, maxSwipes: 16, up: true)
        if !found { capture(app, "peers-section-missing") }
        XCTAssertTrue(found, "Connected peers section not found")
        let peer = app.staticTexts.matching(identifier: "peerEndpoint")
            .matching(NSPredicate(format: "label CONTAINS %@", suffix)).firstMatch
        XCTAssertTrue(poll(timeout: 300, interval: 3, message) {
            peers.tap()
            return peer.waitForExistence(timeout: 2)
        }, message)
    }

    private func element(_ app: XCUIApplication, beginningWith label: String) -> XCUIElement {
        app.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH %@", label)).firstMatch
    }

    private func capture(_ app: XCUIApplication, _ name: String) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
