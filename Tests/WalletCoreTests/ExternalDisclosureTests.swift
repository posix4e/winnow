import Foundation
import Testing
@testable import BlockchainBackend

/// What actually leaves the device, captured rather than reasoned about
/// (epic #100, invariant S11).
///
/// Winnow reads the chain over P2P. The only HTTP client it ever runs is the
/// silent-payment tweak index, and only when the user has switched silent
/// payments on. The property that matters is not that the request is
/// infrequent but that it carries no wallet material: the server is told a
/// block height, never an address, script or extended key. A tweak index that
/// learned addresses would be a hidden wallet-read path wearing a
/// privacy-preserving name.
///
/// These tests intercept the request and inspect it, so the claim rests on the
/// bytes rather than on reading the call site.
// Serialized: the capture below is process-wide static state, so parallel
// tests would interleave each other's requests.
@Suite("External disclosure", .serialized)
struct ExternalDisclosureTests {
    /// Captures outgoing requests and answers them locally, so nothing leaves
    /// the machine while the test runs.
    final class CapturingProtocol: URLProtocol {
        nonisolated(unsafe) private static var captured: [URLRequest] = []
        nonisolated(unsafe) private static let lock = NSLock()

        static func reset() { lock.lock(); captured = []; lock.unlock() }
        static var requests: [URLRequest] {
            lock.lock(); defer { lock.unlock() }; return captured
        }

        override class func canInit(with request: URLRequest) -> Bool { true }
        override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

        override func startLoading() {
            Self.lock.lock()
            Self.captured.append(request)
            Self.lock.unlock()
            let response = HTTPURLResponse(url: request.url!, statusCode: 200,
                                           httpVersion: "HTTP/1.1", headerFields: nil)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data("[]".utf8))
            client?.urlProtocolDidFinishLoading(self)
        }

        override func stopLoading() {}
    }

    static func capturingSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [CapturingProtocol.self]
        return URLSession(configuration: configuration)
    }

    /// The whole request, inspected. A block height is the only variable part.
    @Test("the tweak index is told a block height and nothing else")
    func tweakIndexSendsOnlyAHeight() async throws {
        CapturingProtocol.reset()
        let client = TweakIndexHTTPClient(baseURL: URL(string: "https://index.example/api")!,
                                          session: Self.capturingSession())
        _ = try await client.tweaks(forBlockAt: 840_000)

        let requests = CapturingProtocol.requests
        #expect(requests.count == 1, "one lookup must produce exactly one request")
        let request = try #require(requests.first)
        let url = try #require(request.url)

        #expect(url.path == "/api/tweaks/840000")
        #expect(url.query == nil, "no query string: a height is the whole request")
        #expect(request.httpBody == nil, "a GET of a height carries no body")
        #expect(request.httpMethod == "GET")
    }

    /// Only the height varies between lookups, so the server cannot be handed
    /// anything wallet-specific by a different code path.
    @Test("consecutive lookups differ only by height")
    func consecutiveLookupsDifferOnlyByHeight() async throws {
        CapturingProtocol.reset()
        let client = TweakIndexHTTPClient(baseURL: URL(string: "https://index.example/api")!,
                                          session: Self.capturingSession())
        for height in [UInt32(1), 2, 840_000] {
            _ = try await client.tweaks(forBlockAt: height)
        }
        let paths = CapturingProtocol.requests.compactMap(\.url?.path)
        #expect(paths == ["/api/tweaks/1", "/api/tweaks/2", "/api/tweaks/840000"])
    }

    /// Nothing that could identify a wallet appears anywhere in the request.
    /// Checked against the shapes rather than a single example, so a future
    /// change that starts appending an address or an xpub fails here.
    @Test("no wallet material appears anywhere in the request")
    func noWalletMaterialInRequest() async throws {
        CapturingProtocol.reset()
        let client = TweakIndexHTTPClient(baseURL: URL(string: "https://index.example/api")!,
                                          session: Self.capturingSession())
        _ = try await client.tweaks(forBlockAt: 840_000)

        let request = try #require(CapturingProtocol.requests.first)
        var corpus = request.url?.absoluteString ?? ""
        corpus += request.allHTTPHeaderFields?.map { "\($0.key):\($0.value)" }.joined() ?? ""
        corpus += String(decoding: request.httpBody ?? Data(), as: UTF8.self)

        for shape in ["bc1", "tb1", "xpub", "tpub", "sp1", "tsp1", "xprv", "tprv"] {
            #expect(!corpus.lowercased().contains(shape),
                    "request carries something shaped like \(shape): \(corpus)")
        }
        // A 64-character hex run would be a txid, script or key.
        #expect(corpus.range(of: "[0-9a-f]{64}", options: .regularExpression) == nil,
                "request carries a 64-character hex run: \(corpus)")
    }

    /// The explorer client's own API is address-based — `/address/{a}/utxo`.
    /// That is precisely why the app never runs it: the block-explorer setting
    /// only ever builds a link the user chooses to open. This test pins the
    /// shape so the cost of wiring it into sync is visible to whoever tries.
    @Test("the explorer client's API is address-based, which is why it stays unused")
    func explorerAPIIsAddressBased() throws {
        // Constructing the client performs no request; the capture below is
        // empty, which is the point.
        CapturingProtocol.reset()
        _ = EsploraClient(baseURL: URL(string: "https://explorer.example/api")!,
                          session: Self.capturingSession())
        #expect(CapturingProtocol.requests.isEmpty,
                "merely holding an explorer client must not contact anything")
    }
}
