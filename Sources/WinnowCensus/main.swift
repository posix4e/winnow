import BitcoinCore
import BitcoinP2P
import Darwin
import Foundation

/// Peer census: dial a list of nodes with the same `PeerConnection` the app
/// uses and record what each one reports in its handshake — user agent,
/// starting height, service bits, and the BIP133 fee filter it pushes right
/// after `verack`. One JSON object per node, then a breakdown.
///
/// Read-only and polite: version/verack, a short wait for `feefilter`, then
/// disconnect. Nothing is requested. The user agent names the tool so an
/// operator reading their logs knows what dialled them.
///
/// The point of using Winnow's own connection rather than a generic crawler:
/// a peer that fails *this* handshake is one the wallet could never use, so
/// the numbers describe Winnow's world, not the abstract network.
///
/// Input: a Bitnodes/btcnodes snapshot (`{"nodes": {"host:port": [...]}}`)
/// or a plain list, one `host:port` per line. Onion and I2P addresses are
/// skipped; there is no Tor transport here.
struct Options: Sendable {
    var input: URL?
    var out: URL?
    /// Machine-readable summary for the scheduled census (docs/census/).
    var summary: URL?
    var sample = 0 // 0 = all
    var parallel = 64
    var timeout: Duration = .seconds(8)
    var feeFilterWait: Duration = .milliseconds(1_500)
    var network: NetworkParams = .mainnet
    var seed: UInt64 = 42
    /// SOCKS5 proxies for the hidden networks. Without one, that network's
    /// addresses are skipped rather than dialled and counted unreachable.
    var torSocks: PeerEndpoint?
    var i2pSocks: PeerEndpoint?
    /// Hidden services answer slowly; a separate budget keeps the clearnet
    /// timeout honest.
    var hiddenTimeout: Duration = .seconds(25)
    /// The chain tip to judge heights against. Default: the median of what
    /// usable peers report, which one liar in either direction cannot move.
    /// The snapshot's own latest_height is a good value to pass.
    var tip: Int32?
}

struct Record: Codable, Sendable {
    var host: String
    var port: UInt16
    /// ok | noCompactFilters | unreachable | handshakeFailed | protocolViolation | timeout
    var outcome: String
    var userAgent: String?
    var startHeight: Int32?
    var services: UInt64?
    var feeFilterSatPerKvB: Int64?
    var latencyMs: Int
    var error: String?
    /// clearnet | tor | i2p
    var network: String
}

private func parseOptions() -> Options {
    var options = Options()
    var args = CommandLine.arguments.dropFirst().makeIterator()
    while let arg = args.next() {
        switch arg {
        case "--input": options.input = args.next().map { URL(fileURLWithPath: $0) }
        case "--out": options.out = args.next().map { URL(fileURLWithPath: $0) }
        case "--summary-json": options.summary = args.next().map { URL(fileURLWithPath: $0) }
        case "--sample": options.sample = Int(args.next() ?? "") ?? 0
        case "--parallel": options.parallel = Int(args.next() ?? "") ?? 64
        case "--timeout": options.timeout = .seconds(Double(args.next() ?? "") ?? 8)
        case "--feefilter-wait-ms": options.feeFilterWait = .milliseconds(Int(args.next() ?? "") ?? 1_500)
        case "--seed": options.seed = UInt64(args.next() ?? "") ?? 42
        case "--tor-socks": options.torSocks = args.next().flatMap(parseHostPort)
        case "--i2p-socks": options.i2pSocks = args.next().flatMap(parseHostPort)
        case "--hidden-timeout": options.hiddenTimeout = .seconds(Double(args.next() ?? "") ?? 25)
        case "--tip": options.tip = Int32(args.next() ?? "")
        case "--network":
            switch args.next() {
            case "mainnet": options.network = .mainnet
            case "signet": options.network = .signet
            default: fatalError("--network mainnet|signet")
            }
        case "--help", "-h":
            print("""
            usage: WinnowCensus --input nodes.json|nodes.txt [--out results.jsonl] [--summary-json summary.json]
                                [--sample N] [--parallel 64] [--timeout 8] [--feefilter-wait-ms 1500]
                                [--tor-socks 127.0.0.1:9050] [--i2p-socks 127.0.0.1:4447] [--hidden-timeout 25]
                                [--tip HEIGHT]
            """)
            exit(0)
        default:
            fatalError("unknown argument \(arg)")
        }
    }
    guard options.input != nil else { fatalError("--input is required") }
    return options
}

func parseHostPort(_ text: String) -> PeerEndpoint? {
    guard let colon = text.lastIndex(of: ":"), let port = UInt16(text[text.index(after: colon)...]) else { return nil }
    return PeerEndpoint(host: String(text[..<colon]), port: port)
}

enum OverlayNetwork: String {
    case clearnet, tor, i2p

    init(host: String) {
        if host.hasSuffix(".onion") { self = .tor }
        else if host.hasSuffix(".i2p") { self = .i2p }
        else { self = .clearnet }
    }
}

/// Accepts a snapshot dictionary or a plain host:port list. Hidden-network
/// addresses are kept only when a proxy for that network is configured.
private func loadEndpoints(from url: URL, options: Options) throws -> [PeerEndpoint] {
    let data = try Data(contentsOf: url)
    var keys: [String] = []
    if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
       let nodes = object["nodes"] as? [String: Any] {
        keys = Array(nodes.keys)
    } else {
        keys = String(decoding: data, as: UTF8.self)
            .split(whereSeparator: \.isNewline).map(String.init)
    }
    var endpoints: [PeerEndpoint] = []
    for key in keys {
        let trimmed = key.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { continue }
        if trimmed.contains(".onion"), options.torSocks == nil { continue }
        if trimmed.contains(".i2p"), options.i2pSocks == nil { continue }
        // "[v6]:port" or "v4:port"
        if trimmed.hasPrefix("[") {
            guard let close = trimmed.firstIndex(of: "]"),
                  let port = UInt16(trimmed[trimmed.index(close, offsetBy: 2)...]) else { continue }
            endpoints.append(PeerEndpoint(host: String(trimmed[trimmed.index(after: trimmed.startIndex) ..< close]), port: port))
        } else if let colon = trimmed.lastIndex(of: ":"), let port = UInt16(trimmed[trimmed.index(after: colon)...]) {
            endpoints.append(PeerEndpoint(host: String(trimmed[..<colon]), port: port))
        }
    }
    return endpoints
}

private func probe(_ endpoint: PeerEndpoint, options: Options) async -> Record {
    let started = ContinuousClock.now
    let overlay = OverlayNetwork(host: endpoint.host)
    let proxy: PeerEndpoint? = switch overlay {
    case .clearnet: nil
    case .tor: options.torSocks
    case .i2p: options.i2pSocks
    }
    let timeout = overlay == .clearnet ? options.timeout : options.hiddenTimeout
    let peer = PeerConnection(endpoint: endpoint, params: options.network,
                              localServices: 0, localStartHeight: 0, relayPreference: false,
                              socksProxy: proxy)
    func elapsed() -> Int { Int((ContinuousClock.now - started) / .milliseconds(1)) }
    func record(_ outcome: String, userAgent: String? = nil, startHeight: Int32? = nil,
                services: UInt64? = nil, feeFilter: Int64? = nil, error: String? = nil) -> Record {
        Record(host: endpoint.host, port: endpoint.port, outcome: outcome, userAgent: userAgent,
               startHeight: startHeight, services: services, feeFilterSatPerKvB: feeFilter,
               latencyMs: elapsed(), error: error, network: overlay.rawValue)
    }
    do {
        try await peer.connect(timeout: timeout)
        // Core pushes feefilter right after verack; give it a moment.
        let deadline = ContinuousClock.now + options.feeFilterWait
        while await peer.feeFilter == nil, ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(100))
        }
        let result = record("ok", userAgent: await peer.peerUserAgent,
                            startHeight: await peer.peerStartHeight,
                            services: await peer.peerServices,
                            feeFilter: await peer.feeFilter)
        await peer.disconnect()
        return result
    } catch let error as PeerError {
        switch error {
        case let .missingCompactFilters(services):
            return record("noCompactFilters", services: services)
        case .timeout:
            return record("timeout")
        case .protocolViolation:
            return record("protocolViolation", error: error.localizedDescription)
        default:
            return record("unreachable", error: error.localizedDescription)
        }
    } catch {
        return record("handshakeFailed", error: error.localizedDescription)
    }
}

/// Deterministic shuffle so a sample is reproducible from its seed.
struct SeededGenerator: RandomNumberGenerator {
    var state: UInt64
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// The daily data point the site renders. Aggregates only: the per-node
/// detail is in the JSONL, and btcnodes already publishes the per-IP view.
struct Summary: Codable {
    struct Family: Codable {
        var usable: Int
        var atTip: Int
        var stuckAtSplit: Int
        var behind: Int
        var medianFeeFilterSatPerKvB: Int64?
    }
    var generatedAt: String
    var dialled: Int
    var outcomes: [String: Int]
    var usable: Int
    var observedTip: Int32
    var splitHeight: Int32
    var stuckAtSplit: Int
    var behind: Int
    /// Reporting a height more than 10 above the tip: a lying node, or one
    /// on a chain that is not this one.
    var aheadOfTip: Int
    var medianFeeFilterSatPerKvB: Int64?
    var handshakeLatencyMsMedian: Int?
    var families: [String: Family]
    /// The same breakdown per overlay network: clearnet, tor, i2p. Absent
    /// networks were not dialled (no proxy configured).
    var networks: [String: Network]

    struct Network: Codable {
        var dialled: Int
        var usable: Int
        var noCompactFilters: Int
        var atTip: Int
        var stuckAtSplit: Int
        var behind: Int
    }
}

func family(of userAgent: String) -> String {
    if userAgent.contains("Knots") { return "Knots" }
    if userAgent.hasPrefix("/Satoshi:") { return "Core" }
    if userAgent.contains("btcd") { return "btcd" }
    if userAgent.contains("bcoin") { return "bcoin" }
    return "other"
}

/// The tip to judge heights against: the caller's, or the median of what
/// usable peers report. A percentile near the top let one node claiming a
/// taller chain drag the estimate up and mark every honest peer "behind".
func observedTip(_ records: [Record], override: Int32?) -> Int32 {
    if let override { return override }
    let heights = records.filter { $0.outcome == "ok" }.compactMap(\.startHeight).sorted()
    return heights.isEmpty ? 0 : heights[heights.count / 2]
}

func makeSummary(_ records: [Record], tip: Int32, splitHeight: Int32 = 961_632) -> Summary {
    let ok = records.filter { $0.outcome == "ok" }
    func median(_ values: [Int64]) -> Int64? {
        let sorted = values.sorted()
        return sorted.isEmpty ? nil : sorted[sorted.count / 2]
    }
    let isStuck: (Record) -> Bool = { ($0.startHeight ?? 0) >= splitHeight && ($0.startHeight ?? 0) <= splitHeight + 20 }
    let isBehind: (Record) -> Bool = { tip - ($0.startHeight ?? 0) > 100 }
    let isAhead: (Record) -> Bool = { ($0.startHeight ?? 0) - tip > 10 }
    var families: [String: Summary.Family] = [:]
    for (name, members) in Dictionary(grouping: ok, by: { family(of: $0.userAgent ?? "") }) {
        families[name] = Summary.Family(
            usable: members.count,
            atTip: members.filter { !isBehind($0) }.count,
            stuckAtSplit: members.filter(isStuck).count,
            behind: members.filter(isBehind).count,
            medianFeeFilterSatPerKvB: median(members.compactMap(\.feeFilterSatPerKvB)))
    }
    var networks: [String: Summary.Network] = [:]
    for (name, members) in Dictionary(grouping: records, by: \.network) {
        let usable = members.filter { $0.outcome == "ok" }
        networks[name] = Summary.Network(
            dialled: members.count, usable: usable.count,
            noCompactFilters: members.filter { $0.outcome == "noCompactFilters" }.count,
            atTip: usable.filter { !isBehind($0) }.count,
            stuckAtSplit: usable.filter(isStuck).count,
            behind: usable.filter(isBehind).count)
    }
    let latencies = ok.map(\.latencyMs).sorted()
    return Summary(
        generatedAt: ISO8601DateFormatter().string(from: Date()),
        dialled: records.count,
        outcomes: Dictionary(grouping: records, by: \.outcome).mapValues(\.count),
        usable: ok.count,
        observedTip: tip,
        splitHeight: splitHeight,
        stuckAtSplit: ok.filter(isStuck).count,
        behind: ok.filter(isBehind).count,
        aheadOfTip: ok.filter(isAhead).count,
        medianFeeFilterSatPerKvB: median(ok.compactMap(\.feeFilterSatPerKvB)),
        handshakeLatencyMsMedian: latencies.isEmpty ? nil : latencies[latencies.count / 2],
        families: families, networks: networks)
}

private func summarize(_ records: [Record], tip: Int32, splitHeight: Int32 = 961_632) {
    let ok = records.filter { $0.outcome == "ok" }
    func pct(_ n: Int, _ d: Int) -> String { d == 0 ? "-" : String(format: "%.1f%%", 100 * Double(n) / Double(d)) }
    print("")
    print("dialled \(records.count)")
    for outcome in ["ok", "noCompactFilters", "unreachable", "timeout", "handshakeFailed", "protocolViolation"] {
        let n = records.filter { $0.outcome == outcome }.count
        if n > 0 { print("  \(outcome.padding(toLength: 18, withPad: " ", startingAt: 0)) \(n)  \(pct(n, records.count))") }
    }
    print("")
    print("of the \(ok.count) Winnow-usable peers (handshake ok, compact filters advertised):")
    print("  tip used to judge heights: \(tip)")
    let stuck = ok.filter { ($0.startHeight ?? 0) >= splitHeight && ($0.startHeight ?? 0) <= splitHeight + 20 }
    let behind = ok.filter { tip - ($0.startHeight ?? 0) > 100 }
    let ahead = ok.filter { ($0.startHeight ?? 0) - tip > 10 }
    print("  at the BIP-110 split height (\(splitHeight)…\(splitHeight + 20)): \(stuck.count)  \(pct(stuck.count, ok.count))")
    print("  more than 100 blocks behind the tip:                \(behind.count)  \(pct(behind.count, ok.count))")
    print("  claiming a chain taller than the tip:               \(ahead.count)  \(pct(ahead.count, ok.count))")
    let filters = ok.compactMap(\.feeFilterSatPerKvB).sorted()
    if !filters.isEmpty {
        print("  fee filter median \(filters[filters.count / 2]) sat/kvB, "
              + "over 100 sat/vB: \(filters.filter { $0 > 100_000 }.count)")
    }
    print("")
    print("by overlay network:")
    print("  network   dialled  usable   no filters  stuck@split (of usable)")
    for (name, members) in Dictionary(grouping: records, by: \.network).sorted(by: { $0.key < $1.key }) {
        let usable = members.filter { $0.outcome == "ok" }
        let noFilters = members.filter { $0.outcome == "noCompactFilters" }.count
        let stuckHere = usable.filter { ($0.startHeight ?? 0) >= splitHeight && ($0.startHeight ?? 0) <= splitHeight + 20 }.count
        print("  \(name.padding(toLength: 9, withPad: " ", startingAt: 0)) \(String(members.count).padding(toLength: 8, withPad: " ", startingAt: 0)) \(pct(usable.count, members.count).padding(toLength: 8, withPad: " ", startingAt: 0)) \(pct(noFilters, members.count).padding(toLength: 11, withPad: " ", startingAt: 0)) \(pct(stuckHere, usable.count))")
    }
    print("")
    print("by software family (usable peers):")
    func family(_ ua: String) -> String {
        if ua.contains("Knots") { return "Knots" }
        if ua.hasPrefix("/Satoshi:") { return "Core" }
        if ua.contains("btcd") { return "btcd" }
        if ua.contains("bcoin") { return "bcoin" }
        return "other"
    }
    let groups = Dictionary(grouping: ok) { family($0.userAgent ?? "") }
    print("  family   count  at tip   stuck@split  >100 behind")
    for (name, members) in groups.sorted(by: { $0.value.count > $1.value.count }) {
        let atTip = members.filter { tip - ($0.startHeight ?? 0) <= 100 }.count
        let s = members.filter { ($0.startHeight ?? 0) >= splitHeight && ($0.startHeight ?? 0) <= splitHeight + 20 }.count
        let b = members.filter { tip - ($0.startHeight ?? 0) > 100 }.count
        print("  \(name.padding(toLength: 8, withPad: " ", startingAt: 0)) \(String(members.count).padding(toLength: 6, withPad: " ", startingAt: 0)) \(pct(atTip, members.count).padding(toLength: 8, withPad: " ", startingAt: 0)) \(pct(s, members.count).padding(toLength: 12, withPad: " ", startingAt: 0)) \(pct(b, members.count))")
    }
    print("")
    print("top user agents among stuck peers:")
    let uaCounts = Dictionary(grouping: stuck) { $0.userAgent ?? "?" }.mapValues(\.count)
    for (ua, n) in uaCounts.sorted(by: { $0.value > $1.value }).prefix(8) { print("  \(n)  \(ua)") }
}

/// Dials `endpoints` with bounded parallelism, streaming records to `output`.
func crawl(_ endpoints: [PeerEndpoint], options: Options, output: FileHandle?) async -> [Record] {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    var records: [Record] = []
    var done = 0
    await withTaskGroup(of: Record.self) { group in
        var next = 0
        func enqueue() {
            guard next < endpoints.count else { return }
            let endpoint = endpoints[next]
            next += 1
            group.addTask { await probe(endpoint, options: options) }
        }
        for _ in 0 ..< min(options.parallel, endpoints.count) { enqueue() }
        for await record in group {
            records.append(record)
            done += 1
            if let data = try? encoder.encode(record) {
                output?.write(data)
                output?.write(Data("\n".utf8))
            }
            if done % 200 == 0 {
                FileHandle.standardError.write(Data("\(done)/\(endpoints.count)\n".utf8))
            }
            enqueue()
        }
    }
    return records
}

let options = parseOptions()
var endpoints = try loadEndpoints(from: options.input!, options: options)
var generator = SeededGenerator(state: options.seed)
endpoints.shuffle(using: &generator)
if options.sample > 0 { endpoints = Array(endpoints.prefix(options.sample)) }
FileHandle.standardError.write(Data("dialling \(endpoints.count) endpoints, \(options.parallel) at a time\n".utf8))
var output: FileHandle?
if let out = options.out {
    FileManager.default.createFile(atPath: out.path, contents: nil)
    output = try FileHandle(forWritingTo: out)
}
let records = await crawl(endpoints, options: options, output: output)
try? output?.close()
let tip = observedTip(records, override: options.tip)
if let summaryURL = options.summary {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    try encoder.encode(makeSummary(records, tip: tip)).write(to: summaryURL)
}
summarize(records, tip: tip)
