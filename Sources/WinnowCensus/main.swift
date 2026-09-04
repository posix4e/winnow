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
            """)
            exit(0)
        default:
            fatalError("unknown argument \(arg)")
        }
    }
    guard options.input != nil else { fatalError("--input is required") }
    return options
}

/// Accepts a snapshot dictionary or a plain host:port list.
private func loadEndpoints(from url: URL) throws -> [PeerEndpoint] {
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
        guard !trimmed.isEmpty, !trimmed.hasSuffix(".onion"), !trimmed.contains(".onion:"),
              !trimmed.contains(".i2p") else { continue }
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
    let peer = PeerConnection(endpoint: endpoint, params: options.network,
                              localServices: 0, localStartHeight: 0, relayPreference: false)
    func elapsed() -> Int { Int((ContinuousClock.now - started) / .milliseconds(1)) }
    do {
        try await peer.connect(timeout: options.timeout)
        // Core pushes feefilter right after verack; give it a moment.
        let deadline = ContinuousClock.now + options.feeFilterWait
        while await peer.feeFilter == nil, ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(100))
        }
        let record = Record(host: endpoint.host, port: endpoint.port, outcome: "ok",
                            userAgent: await peer.peerUserAgent,
                            startHeight: await peer.peerStartHeight,
                            services: await peer.peerServices,
                            feeFilterSatPerKvB: await peer.feeFilter,
                            latencyMs: elapsed(), error: nil)
        await peer.disconnect()
        return record
    } catch let error as PeerError {
        switch error {
        case let .missingCompactFilters(services):
            return Record(host: endpoint.host, port: endpoint.port, outcome: "noCompactFilters",
                          userAgent: nil, startHeight: nil, services: services,
                          feeFilterSatPerKvB: nil, latencyMs: elapsed(), error: nil)
        case .timeout:
            return Record(host: endpoint.host, port: endpoint.port, outcome: "timeout",
                          userAgent: nil, startHeight: nil, services: nil,
                          feeFilterSatPerKvB: nil, latencyMs: elapsed(), error: nil)
        case .protocolViolation:
            return Record(host: endpoint.host, port: endpoint.port, outcome: "protocolViolation",
                          userAgent: nil, startHeight: nil, services: nil,
                          feeFilterSatPerKvB: nil, latencyMs: elapsed(), error: error.localizedDescription)
        default:
            return Record(host: endpoint.host, port: endpoint.port, outcome: "unreachable",
                          userAgent: nil, startHeight: nil, services: nil,
                          feeFilterSatPerKvB: nil, latencyMs: elapsed(), error: error.localizedDescription)
        }
    } catch {
        return Record(host: endpoint.host, port: endpoint.port, outcome: "handshakeFailed",
                      userAgent: nil, startHeight: nil, services: nil,
                      feeFilterSatPerKvB: nil, latencyMs: elapsed(), error: error.localizedDescription)
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
    var medianFeeFilterSatPerKvB: Int64?
    var handshakeLatencyMsMedian: Int?
    var families: [String: Family]
}

func family(of userAgent: String) -> String {
    if userAgent.contains("Knots") { return "Knots" }
    if userAgent.hasPrefix("/Satoshi:") { return "Core" }
    if userAgent.contains("btcd") { return "btcd" }
    if userAgent.contains("bcoin") { return "bcoin" }
    return "other"
}

func makeSummary(_ records: [Record], splitHeight: Int32 = 961_632) -> Summary {
    let ok = records.filter { $0.outcome == "ok" }
    let heights = ok.compactMap(\.startHeight).sorted()
    let tip = heights.isEmpty ? 0 : heights[heights.count * 95 / 100]
    func median(_ values: [Int64]) -> Int64? {
        let sorted = values.sorted()
        return sorted.isEmpty ? nil : sorted[sorted.count / 2]
    }
    let isStuck: (Record) -> Bool = { ($0.startHeight ?? 0) >= splitHeight && ($0.startHeight ?? 0) <= splitHeight + 20 }
    let isBehind: (Record) -> Bool = { tip - ($0.startHeight ?? 0) > 100 }
    var families: [String: Summary.Family] = [:]
    for (name, members) in Dictionary(grouping: ok, by: { family(of: $0.userAgent ?? "") }) {
        families[name] = Summary.Family(
            usable: members.count,
            atTip: members.filter { !isBehind($0) }.count,
            stuckAtSplit: members.filter(isStuck).count,
            behind: members.filter(isBehind).count,
            medianFeeFilterSatPerKvB: median(members.compactMap(\.feeFilterSatPerKvB)))
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
        medianFeeFilterSatPerKvB: median(ok.compactMap(\.feeFilterSatPerKvB)),
        handshakeLatencyMsMedian: latencies.isEmpty ? nil : latencies[latencies.count / 2],
        families: families)
}

private func summarize(_ records: [Record], splitHeight: Int32 = 961_632) {
    let ok = records.filter { $0.outcome == "ok" }
    let heights = ok.compactMap(\.startHeight).sorted()
    let tip = heights.isEmpty ? 0 : heights[heights.count * 95 / 100] // robust against liars
    func pct(_ n: Int, _ d: Int) -> String { d == 0 ? "-" : String(format: "%.1f%%", 100 * Double(n) / Double(d)) }
    print("")
    print("dialled \(records.count)")
    for outcome in ["ok", "noCompactFilters", "unreachable", "timeout", "handshakeFailed", "protocolViolation"] {
        let n = records.filter { $0.outcome == outcome }.count
        if n > 0 { print("  \(outcome.padding(toLength: 18, withPad: " ", startingAt: 0)) \(n)  \(pct(n, records.count))") }
    }
    print("")
    print("of the \(ok.count) Winnow-usable peers (handshake ok, compact filters advertised):")
    print("  observed tip (95th percentile of reported heights): \(tip)")
    let stuck = ok.filter { ($0.startHeight ?? 0) >= splitHeight && ($0.startHeight ?? 0) <= splitHeight + 20 }
    let behind = ok.filter { tip - ($0.startHeight ?? 0) > 100 }
    print("  at the BIP-110 split height (\(splitHeight)…\(splitHeight + 20)): \(stuck.count)  \(pct(stuck.count, ok.count))")
    print("  more than 100 blocks behind the tip:                \(behind.count)  \(pct(behind.count, ok.count))")
    let filters = ok.compactMap(\.feeFilterSatPerKvB).sorted()
    if !filters.isEmpty {
        print("  fee filter median \(filters[filters.count / 2]) sat/kvB, "
              + "over 100 sat/vB: \(filters.filter { $0 > 100_000 }.count)")
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
var endpoints = try loadEndpoints(from: options.input!)
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
if let summaryURL = options.summary {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    try encoder.encode(makeSummary(records)).write(to: summaryURL)
}
summarize(records)
