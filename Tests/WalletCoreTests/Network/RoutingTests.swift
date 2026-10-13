import Foundation
import Testing
import TestSupport
@testable import WalletCore

/// The one HTTP client behind the census refresh, DNS-over-HTTPS and the
/// consented explorer lookup: what it will ask for, what it refuses to
/// follow, and how much of an answer it will take.
struct RoutingTests {
    private func ok(_ body: String) -> Data {
        Data("HTTP/1.1 200 OK\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)".utf8)
    }

    @Test func requestPolicy() {
        #expect(RoutedHTTPClient.permits(URL(string: "https://example.com/")!))
        #expect(RoutedHTTPClient.permits(URL(string: "http://127.0.0.1:8080/")!))
        #expect(RoutedHTTPClient.permits(URL(string: "https://[2606:4700::1111]/")!))
        #expect(!RoutedHTTPClient.permits(URL(string: "ftp://example.com/")!))
        #expect(!RoutedHTTPClient.permits(URL(string: "https://user:password@example.com")!))
        #expect(!RoutedHTTPClient.permits(URL(string: "https://example.com:0/")!))
        #expect(!RoutedHTTPClient.permits(URL(string: "file:///etc/hosts")!))
    }

    @Test func fetchesABoundedBody() async throws {
        let server = LoopbackHTTPServer(response: ok("OK"))
        try await server.start()
        let client = RoutedHTTPClient()
        do {
            let body = try await client.get(await server.url("/proof"), maximumBytes: 8)
            #expect(body == Data("OK".utf8))
            #expect(await server.httpRequests.count == 1)
            #expect(await server.httpRequests[0].hasPrefix("GET /proof HTTP/1.1"))
        } catch { client.cancel(); await server.stop(); throw error }
        client.cancel(); await server.stop()
    }

    /// I2P alone makes no HTTP request at all: its gateway is never asked
    /// for a public host, which an outproxy could carry, so the listener is
    /// never reached.
    @Test func i2pOnlyClientRefusesPublicHosts() async throws {
        let server = LoopbackHTTPServer(response: ok("OK"))
        try await server.start()
        let i2pOnly = PeerGatewayConfiguration(networks: [.i2p], i2pProxy: .init(host: "100.74.30.8", port: 4447))
        let client = RoutedHTTPClient(gateways: i2pOnly)
        #expect(!client.enabled)
        await #expect(throws: RoutedHTTPClient.Failure.unavailable) {
            try await client.get(await server.url("/census/peers.json"), maximumBytes: 8)
        }
        #expect(await server.httpRequests.isEmpty)
        client.cancel(); await server.stop()
    }

    @Test func cancelledClientRefusesNewRequests() async throws {
        let client = RoutedHTTPClient()
        #expect(!client.isCancelled)
        client.cancel()
        #expect(client.isCancelled)
        await #expect(throws: RoutedHTTPClient.Failure.unavailable) {
            try await client.get(URL(string: "https://example.com")!, maximumBytes: 8)
        }
    }

    /// Every fetch names one host on purpose, so a redirect to another host
    /// — even the same listener under another name — is refused, and the
    /// other name is never asked.
    @Test func redirectOffTheAskedHostIsRefused() async throws {
        let server = LoopbackHTTPServer()
        try await server.start()
        let port = await server.port
        await server.respond(to: "127.0.0.1", with: Data(
            "HTTP/1.1 302 Found\r\nLocation: http://localhost:\(port)/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8))
        await server.respond(to: "localhost", with: ok("OK"))
        let client = RoutedHTTPClient()
        await #expect(throws: RoutedHTTPClient.HTTPFailure.self) {
            try await client.get(await server.url(), maximumBytes: 8)
        }
        #expect(await server.requestedHosts == ["127.0.0.1"])
        client.cancel(); await server.stop()
    }

    /// A redirect within the asked host is followed.
    @Test func redirectWithinTheHostIsFollowed() async throws {
        let server = LoopbackHTTPServer()
        try await server.start()
        let port = await server.port
        let client = RoutedHTTPClient()
        // Route both replies before requesting: no scheduler-dependent response swap.
        await server.respond(to: "127.0.0.1", path: "/start", with: Data(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:\(port)/moved\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8))
        await server.respond(to: "127.0.0.1", path: "/moved", with: ok("OK"))
        do {
            #expect(try await client.get(await server.url("/start"), maximumBytes: 8) == Data("OK".utf8))
        } catch { client.cancel(); await server.stop(); throw error }
        #expect(await server.httpRequests.map { $0.split(separator: " ")[1] } == ["/start", "/moved"])
        client.cancel(); await server.stop()
    }

    @Test(arguments: [
        "Content-Length: 9\r\n\r\n123456789",
        "Transfer-Encoding: chunked\r\n\r\n9\r\n123456789\r\n0\r\n\r\n"
    ]) func oversizedHTTPBodiesAreBounded(framing: String) async throws {
        let server = LoopbackHTTPServer(response: Data(("HTTP/1.1 200 OK\r\n" + framing).utf8))
        try await server.start()
        let client = RoutedHTTPClient()
        await #expect(throws: RoutedHTTPClient.Failure.tooLarge) {
            try await client.get(await server.url(), maximumBytes: 8)
        }
        client.cancel(); await server.stop()
    }

    @Test func cancellingTheClientStopsAnUnfinishedBody() async throws {
        let server = LoopbackHTTPServer(response: Data("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n".utf8))
        try await server.start()
        let client = RoutedHTTPClient()
        let url = await server.url()
        let pending = Task { try await client.get(url, maximumBytes: 8) }
        for _ in 0..<100 where await server.requestedHosts.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        #expect(await server.requestedHosts.count == 1)
        client.cancel()
        await #expect(throws: (any Error).self) { try await pending.value }
        await #expect(throws: (any Error).self) {
            try await client.get(url, maximumBytes: 8)
        }
        #expect(await server.requestedHosts.count == 1)
        await server.stop()
    }
}
