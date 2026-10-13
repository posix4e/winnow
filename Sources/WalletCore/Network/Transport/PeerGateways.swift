import Foundation

public enum PeerNetwork: String, Codable, CaseIterable, Sendable {
    case clearnet, tor, i2p

    public init(host: String) {
        let host = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        self = host.hasSuffix(".onion") ? .tor : host.hasSuffix(".i2p") ? .i2p : .clearnet
    }

    /// Only v3 onion names and ordinary base32 I2P destinations are candidates.
    /// The proxy resolves them; the system resolver must never see them.
    public func canonicalHost(_ host: String) -> String? {
        guard host == host.trimmingCharacters(in: .whitespacesAndNewlines) else { return nil }
        let host = host.lowercased()
        let suffix: String
        let length: Int
        switch self {
        case .clearnet: return CensusCatalog.canonicalHost(host)
        case .tor: suffix = ".onion"; length = 56
        case .i2p: suffix = ".b32.i2p"; length = 52
        }
        guard host.hasSuffix(suffix) else { return nil }
        let name = host.dropLast(suffix.count)
        guard name.utf8.count == length, name.utf8.allSatisfy({ (97...122).contains($0) || (50...55).contains($0) }) else { return nil }
        return host
    }
}

/// Peer networks are an allowlist. An unavailable overlay never uses direct TCP.
public struct PeerGatewayConfiguration: Codable, Equatable, Sendable {
    public var networks: Set<PeerNetwork>
    public var torProxy: PeerEndpoint?
    public var i2pProxy: PeerEndpoint?

    public init(networks: Set<PeerNetwork> = [.clearnet], torProxy: PeerEndpoint? = nil, i2pProxy: PeerEndpoint? = nil) {
        self.networks = networks; self.torProxy = torProxy; self.i2pProxy = i2pProxy
    }

    public static func validProxy(_ endpoint: PeerEndpoint?) -> Bool {
        guard let endpoint, endpoint.port > 0, !endpoint.host.isEmpty, endpoint.host.utf8.count <= 253,
              !endpoint.host.contains(where: { $0.isWhitespace || "/@?#\\%[]".contains($0) }),
              PeerNetwork(host: endpoint.host) == .clearnet else { return false }
        return endpoint.host.utf8.allSatisfy { (33...126).contains($0) }
    }

    public var isValid: Bool {
        !networks.isEmpty && (!networks.contains(.tor) || Self.validProxy(torProxy))
            && (!networks.contains(.i2p) || Self.validProxy(i2pProxy))
    }

    public func permits(_ endpoint: PeerEndpoint) -> Bool {
        let network = PeerNetwork(host: endpoint.host)
        guard isValid, endpoint.port > 0, networks.contains(network) else { return false }
        return network == .clearnet || network.canonicalHost(endpoint.host) != nil
    }

    public func proxy(for endpoint: PeerEndpoint) -> PeerEndpoint? {
        switch PeerNetwork(host: endpoint.host) {
        case .clearnet: nil
        case .tor: torProxy
        case .i2p: i2pProxy
        }
    }

    /// I2P alone reaches only I2P sites and the wallet fetches none: its
    /// gateway must never be asked for a public host, which an outproxy could
    /// carry. HTTP goes direct with clearnet, through Tor otherwise.
    public var permitsHTTP: Bool { isValid && (networks.contains(.clearnet) || networks.contains(.tor)) }
    public var httpProxy: PeerEndpoint? { networks.contains(.clearnet) ? nil : torProxy }

    public enum Invalid: Error, LocalizedError {
        case configuration, address
        public var errorDescription: String? {
            switch self {
            case .configuration: "Choose at least one peer network and provide a SOCKS gateway for each selected overlay."
            case .address: "Enter a gateway as host:port or [IPv6]:port."
            }
        }
    }

    public static func parseProxy(_ text: String) throws -> PeerEndpoint {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let colon = text.lastIndex(of: ":"), let port = UInt16(text[text.index(after: colon)...]) else { throw Invalid.address }
        var host = String(text[..<colon])
        if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        else if host.contains(":") { throw Invalid.address }
        let endpoint = PeerEndpoint(host: host, port: port)
        guard validProxy(endpoint) else { throw Invalid.address }
        return endpoint
    }
}

public struct PeerGatewaySettings: Codable, Equatable, Sendable {
    public enum Mode: String, Codable, CaseIterable, Sendable { case automatic, direct, manual }
    public var mode: Mode
    public var manual: PeerGatewayConfiguration

    public init(mode: Mode = .automatic, manual: PeerGatewayConfiguration = .init()) {
        self.mode = mode; self.manual = manual
    }
}
