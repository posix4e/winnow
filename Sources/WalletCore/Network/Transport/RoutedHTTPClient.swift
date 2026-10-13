import Foundation
import os
import Network

/// One ephemeral HTTP session. Every fetch names one host on purpose — a
/// DNS-over-HTTPS resolver, an explorer — so a redirect may move
/// within that host and never down from https, and an answer that sends
/// the client elsewhere is refused rather than followed. No cookies, no
/// persistent cache.
public final class RoutedHTTPClient: Sendable {
    public struct HTTPFailure: Error, LocalizedError {
        public let statusCode: Int
        public var errorDescription: String? { "The server returned HTTP \(statusCode)." }
    }
    public enum Failure: String, Error, LocalizedError {
        case unavailable, response, tooLarge, redirect
        public var errorDescription: String? { "Network request failed: \(rawValue)." }
    }

    /// What this client will ask for at all: http or https, a host, no
    /// credentials in the URL, a real port.
    public static func permits(_ url: URL) -> Bool {
        guard let scheme = url.scheme?.lowercased(), ["http", "https"].contains(scheme),
              let host = url.host, !host.isEmpty, url.user == nil, url.password == nil,
              let port = UInt16(exactly: url.port ?? (scheme == "https" ? 443 : 80)), port > 0 else { return false }
        return true
    }

    private final class RedirectPolicy: NSObject, URLSessionTaskDelegate {
        func urlSession(_ session: URLSession, task: URLSessionTask,
                        willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                        completionHandler: @escaping (URLRequest?) -> Void) {
            guard let url = request.url, RoutedHTTPClient.permits(url),
                  !(response.url?.scheme == "https" && url.scheme != "https"),
                  url.host?.lowercased() == response.url?.host?.lowercased() else {
                completionHandler(nil); return
            }
            completionHandler(request)
        }
    }
    private let session: URLSession
    public let proxy: PeerEndpoint?
    public let enabled: Bool
    private struct Requests {
        var closed = false
        var tasks: [UUID: Task<Data, Error>] = [:]
    }
    private let requests = OSAllocatedUnfairLock(initialState: Requests())
    public convenience init(gateways: PeerGatewayConfiguration) {
        self.init(proxy: gateways.httpProxy, enabled: gateways.permitsHTTP)
    }
    public init(proxy: PeerEndpoint? = nil, enabled: Bool = true) {
        self.proxy = proxy
        self.enabled = enabled && (proxy == nil || PeerGatewayConfiguration.validProxy(proxy))
        let config = URLSessionConfiguration.ephemeral
        config.httpShouldSetCookies = false
        config.httpCookieStorage = nil
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        // Finite inactivity and whole-resource limits.
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 120
        if let proxy, let port = NWEndpoint.Port(rawValue: proxy.port) {
            config.proxyConfigurations = [ProxyConfiguration(socksv5Proxy: .hostPort(host: NWEndpoint.Host(proxy.host), port: port))]
            config.timeoutIntervalForRequest = 90
            config.timeoutIntervalForResource = 180
        }
        session = URLSession(configuration: config, delegate: RedirectPolicy(), delegateQueue: nil)
    }
    deinit { session.invalidateAndCancel() }
    /// Once cancelled a client refuses every later request; the owner makes
    /// a new one when networking resumes.
    public var isCancelled: Bool { requests.withLock { $0.closed } }
    public func cancel() {
        let pending = requests.withLock { state in
            state.closed = true
            return Array(state.tasks.values)
        }
        for task in pending { task.cancel() }
    }
    public func get(_ url: URL, maximumBytes: Int, accept: String? = nil,
                    progress: (@Sendable (Int) -> Void)? = nil) async throws -> Data {
        guard enabled, Self.permits(url), maximumBytes > 0 else { throw Failure.unavailable }
        let id = UUID()
        // Admit and register the owned task under the same lock used by
        // cancel(). Invalidate URLSession only at deinit: Foundation raises an
        // Objective-C exception if an old client creates a task after invalidation.
        let pending = try requests.withLock { state in
            guard !state.closed else { throw Failure.unavailable }
            let task = Task { [session] in try await Self.fetch(session, url, maximumBytes, accept, progress) }
            state.tasks[id] = task
            return task
        }
        defer { _ = requests.withLock { $0.tasks.removeValue(forKey: id) } }
        return try await withTaskCancellationHandler {
            try await pending.value
        } onCancel: { pending.cancel() }
    }
    private static func fetch(_ session: URLSession, _ url: URL, _ maximumBytes: Int,
                              _ accept: String?,
                              _ progress: (@Sendable (Int) -> Void)?) async throws -> Data {
        try Task.checkCancellation()
        var request = URLRequest(url: url)
        if let accept { request.setValue(accept, forHTTPHeaderField: "Accept") }
        let (bytes, response) = try await session.bytes(for: request)
        defer { bytes.task.cancel() }
        guard let http = response as? HTTPURLResponse else { throw Failure.response }
        guard http.statusCode == 200 else { throw HTTPFailure(statusCode: http.statusCode) }
        guard response.expectedContentLength <= maximumBytes else { throw Failure.tooLarge }
        var data = Data()
        for try await byte in bytes {
            guard data.count < maximumBytes else { throw Failure.tooLarge }
            data.append(byte)
            if data.count % 65_536 == 0 { try Task.checkCancellation(); progress?(data.count) }
        }
        try Task.checkCancellation()
        progress?(data.count)
        return data
    }
}
