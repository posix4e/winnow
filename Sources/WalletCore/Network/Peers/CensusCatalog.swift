import Darwin
import Foundation

/// Untrusted discovery input, never a replacement for peer/header/filter checks.
/// Shared by the list each release ships and by the census publisher.
///
/// The published list carries `clearnet`, `tor` and `i2p` arrays. The wallet
/// uses overlay entries only when a gateway is configured. Every retained
/// entry is validated before it can reach the peer pool.
public struct CensusCatalog: Codable, Equatable, Sendable {
    public struct Entry: Codable, Equatable, Sendable {
        public var host: String
        public var port: UInt16
        public var userAgent: String
        public var startHeight: Int32
        public init(host: String, port: UInt16, userAgent: String, startHeight: Int32) {
            self.host = host; self.port = port; self.userAgent = userAgent; self.startHeight = startHeight
        }
        public var endpoint: PeerEndpoint { PeerEndpoint(host: host, port: port) }
    }
    public var schemaVersion: Int
    public var date: String
    public var tip: Int32
    public var networks: [String: [Entry]]
    public init(schemaVersion: Int = 1, date: String, tip: Int32, networks: [String: [Entry]]) {
        self.schemaVersion = schemaVersion; self.date = date; self.tip = tip; self.networks = networks
    }
    public static let maximumBytes = 4 * 1_024 * 1_024
    public static let maximumEntries = 65_536
    /// Below this many clearnet entries a list is thin. The publisher never
    /// makes one this small — a daily census lists hundreds of clearnet
    /// nodes — so a list that arrives this small was cut down somewhere in
    /// between, and taking it would empty the automatic pool.
    public static let minimumClearnetEntries = 50

    public enum Invalid: String, Error, LocalizedError {
        case schema, date, size, endpoint, height, duplicate, diversity, thin
        public var errorDescription: String? { "Invalid census peer list: \(rawValue)." }
    }

    public static func day(_ text: String) -> Int? {
        guard text.utf8.count == 10 else { return nil }
        let formatter = DateFormatter()
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.isLenient = false
        guard let date = formatter.date(from: text), formatter.string(from: date) == text else { return nil }
        return Int(floor(date.timeIntervalSince1970 / 86_400))
    }

    /// The census the app was built with: `scripts/import-census` fetches the
    /// census repository's `peers.json` into `build/census/` before XcodeGen
    /// runs, and project.yml bundles it into the app. Nil outside the app.
    /// Peer churn, not a clock, ages it; the next build brings a newer one.
    public static let bundled: Self? = Bundle.main.url(forResource: "peers", withExtension: "json")
        .flatMap { try? Data(contentsOf: $0) }
        .flatMap { try? decode($0, minimumEntries: minimumClearnetEntries) }

    public static func decode(_ data: Data, minimumEntries: Int = 0) throws -> Self {
        guard data.count <= maximumBytes else { throw Invalid.size }
        return try JSONDecoder().decode(Self.self, from: data).validated(minimumEntries: minimumEntries)
    }

    /// `minimumEntries` is the floor the wallet applies to a list it will
    /// use (`minimumClearnetEntries`); the publisher and the tests validate
    /// shape alone.
    public func validated(minimumEntries: Int = 0) throws -> Self {
        guard schemaVersion == 1, let entries = networks["clearnet"] else { throw Invalid.schema }
        guard Self.day(date) != nil else { throw Invalid.date }
        guard tip > 0 else { throw Invalid.height }
        var result = self
        result.networks = ["clearnet": try validatedEntries(entries, minimum: minimumEntries)]
        for network in [PeerNetwork.tor, .i2p] {
            if let entries = networks[network.rawValue] {
                result.networks[network.rawValue] = try validatedOverlayEntries(entries, network: network)
            }
        }
        return result
    }

    private func validatedOverlayEntries(_ entries: [Entry], network: PeerNetwork) throws -> [Entry] {
        // Every verified overlay peer is kept; only the bound every list has
        // applies. The census found 3,212 usable Tor peers on 2026-09-29.
        guard entries.count <= Self.maximumEntries else { throw Invalid.size }
        var seen = Set<PeerEndpoint>()
        return try entries.map { input in
            var entry = input
            guard entry.port > 0, entry.userAgent.utf8.count <= 256,
                  !entry.userAgent.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }),
                  let host = network.canonicalHost(entry.host) else { throw Invalid.endpoint }
            guard Self.nearTip(entry.startHeight, tip: tip) else { throw Invalid.height }
            entry.host = host
            guard seen.insert(entry.endpoint).inserted else { throw Invalid.duplicate }
            return entry
        }.sorted { ($0.host, $0.port) < ($1.host, $1.port) }
    }

    private func validatedEntries(_ entries: [Entry], minimum: Int) throws -> [Entry] {
        guard entries.count >= minimum else { throw Invalid.thin }
        guard entries.count <= Self.maximumEntries else { throw Invalid.size }
        var seen = Set<PeerEndpoint>(), blocks = Set<String>()
        let canonical = try entries.map { input in
            let entry = try validatedEntry(input)
            guard seen.insert(entry.endpoint).inserted else { throw Invalid.duplicate }
            guard let block = entry.endpoint.netblock else { throw Invalid.endpoint }
            guard blocks.insert(block).inserted else { throw Invalid.diversity }
            return entry
        }
        return canonical.sorted { ($0.host, $0.port) < ($1.host, $1.port) }
    }

    private func validatedEntry(_ input: Entry) throws -> Entry {
        var entry = input
        guard entry.port == 8333, entry.userAgent.utf8.count <= 256,
              !entry.userAgent.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }),
              let host = Self.canonicalHost(entry.host) else { throw Invalid.endpoint }
        guard Self.nearTip(entry.startHeight, tip: tip) else { throw Invalid.height }
        entry.host = host
        return entry
    }

    public static func nearTip(_ height: Int32, tip: Int32) -> Bool {
        height >= 0 && tip > 0 && abs(Int64(height) - Int64(tip)) <= 100
    }

    /// Numeric public clearnet only. Collapse mapped IPv4 and IPv6 text aliases
    /// before deduplication and diversity; never invoke DNS here.
    public static func canonicalHost(_ text: String) -> String? {
        guard text.utf8.count <= 255, text == text.trimmingCharacters(in: .whitespacesAndNewlines) else { return nil }
        return canonicalIP(text.lowercased())
    }

    private static func canonicalIP(_ host: String) -> String? {
        var v4 = in_addr()
        if host.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            let bytes = withUnsafeBytes(of: v4) { Array($0) }
            guard publicV4(bytes) else { return nil }
            return bytes.map(String.init).joined(separator: ".")
        }
        var v6 = in6_addr()
        guard host.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 else { return nil }
        let bytes = withUnsafeBytes(of: v6) { Array($0) }
        if bytes.prefix(10).allSatisfy({ $0 == 0 }), bytes[10] == 255, bytes[11] == 255 {
            let mapped = Array(bytes.suffix(4))
            return publicV4(mapped) ? mapped.map(String.init).joined(separator: ".") : nil
        }
        // Accept global unicast 2000::/3, excluding special assignments,
        // documentation and transition mechanisms that can alias IPv4.
        guard bytes[0] & 0xe0 == 0x20,
              !(bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] < 2),
              !(bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8),
              !(bytes[0] == 0x20 && bytes[1] == 0x02),
              !(bytes[0] == 0x3f && bytes[1] == 0xff && bytes[2] < 0x10) else { return nil }
        var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &v6, &output, socklen_t(output.count)) != nil else { return nil }
        return String(decoding: output.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    private static func publicV4(_ b: [UInt8]) -> Bool {
        guard ![0, 10, 127].contains(b[0]), b[0] < 224 else { return false }
        switch (b[0], b[1], b[2]) {
        case (100, 64...127, _), (169, 254, _), (172, 16...31, _),
             (192, 168, _), (192, 0, 0), (192, 0, 2), (192, 88, 99),
             (198, 18...19, _), (198, 51, 100), (203, 0, 113): return false
        default: return true
        }
    }
}
