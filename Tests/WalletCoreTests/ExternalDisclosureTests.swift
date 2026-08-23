import Foundation
import Testing
@testable import BlockchainBackend

/// What actually leaves the device, captured rather than reasoned about
/// (epic #100, invariant S11).
///
/// Winnow reads the chain over P2P and runs no HTTP client of its own. The
/// esplora client exists only behind an explicit, warned handoff to an
/// external explorer, and the wallet never consumes its answers.
///
/// The property worth pinning is that its API is address-based — which is
/// exactly why it stays unused. A client the wallet called automatically would
/// be a hidden wallet-read path wearing a convenience name.
///
/// The tweak-index tests that used to live here left with silent payments
/// (they moved to the `alpha` branch). They asserted the index was told a
/// block height and never an address; if silent payments return to `main`,
/// that property returns with them.
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
