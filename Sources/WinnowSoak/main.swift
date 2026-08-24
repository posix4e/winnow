import BitcoinCore
import BitcoinP2P
import Darwin
import Foundation

/// Sustained-signet soak driver (invariants S5 and S10).
///
/// The unit and loopback suites prove behaviour over seconds against nodes we
/// control. Neither can show what happens over hours against real peers that
/// stall, disconnect, disagree and reorg. This runs the ordinary read path —
/// peer pool, header sync, filter scan — for as long as it is asked to, and
/// writes one JSON object per sample so the result is a timeseries rather than
/// a claim.
///
/// It is deliberately read-only: no wallet, no keys, no spending. Watch scripts
/// are synthetic P2TR outputs that will not match on a public chain, so the
/// scan runs its full filter path every block without ever fetching one. The
/// matched-block path is covered instead by the differential full-loop test,
/// which can mine a match on demand; conflating the two would make this run
/// slower without making it prove more.
private struct Options {
    var network: NetworkParams = .signet
    var samplePeriod: Duration = .seconds(60)
    var runFor: Duration?
    var out: URL?
    var stateDirectory: URL?
    var startHeight: UInt32 = 0
    var peerCount = 3
    var watchScriptCount = 25

    init(arguments: [String]) throws {
        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            func value() throws -> String {
                index += 1
                guard index < arguments.count else { throw SoakError.usage("\(argument) needs a value") }
                return arguments[index]
            }
            switch argument {
            case "--network":
                let name = try value()
                switch name {
                case "signet": network = .signet
                case "mainnet": network = .mainnet
                default: throw SoakError.usage("unknown network \(name)")
                }
            case "--sample-seconds":
                guard let seconds = Int64(try value()), seconds > 0 else {
                    throw SoakError.usage("--sample-seconds must be a positive integer")
                }
                samplePeriod = .seconds(seconds)
            case "--minutes":
                guard let minutes = Int64(try value()), minutes >= 0 else {
                    throw SoakError.usage("--minutes must be zero (forever) or positive")
                }
                runFor = minutes == 0 ? nil : .seconds(minutes * 60)
            case "--out": out = URL(fileURLWithPath: try value())
            case "--state": stateDirectory = URL(fileURLWithPath: try value())
            case "--start-height":
                guard let height = UInt32(try value()) else { throw SoakError.usage("--start-height") }
                startHeight = height
            case "--peers":
                guard let count = Int(try value()), count > 0 else { throw SoakError.usage("--peers") }
                peerCount = count
            case "--help", "-h": throw SoakError.usage(Self.usageText)
            default: throw SoakError.usage("unknown argument \(argument)")
            }
            index += 1
        }
    }

    static let usageText = """
    winnow-soak — sustained read-path soak against a live network

      --network signet|mainnet   default signet
      --minutes N                0 or omitted runs until interrupted
      --sample-seconds S         metrics period (default 60)
      --out PATH                 JSONL timeseries (default stdout only)
      --state DIR                persist headers/filter progress here
      --start-height H           filter scan start (default 0, full history)
      --peers N                  pool target (default 3)
    """
}

private enum SoakError: Error, CustomStringConvertible {
    case usage(String)
    var description: String {
        switch self { case let .usage(message): message }
    }
}

/// Resident set size for this process. `resident_size` is what actually shows
/// up as memory pressure; the soak's whole purpose is to watch it not climb.
private func residentBytes() -> UInt64 {
    var info = mach_task_basic_info()
    var count = mach_msg_type_number_t(
        MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size)
    let status = withUnsafeMutablePointer(to: &info) { pointer in
        pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { raw in
            task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), raw, &count)
        }
    }
    return status == KERN_SUCCESS ? info.resident_size : 0
}

/// Deterministic synthetic P2TR scripts: OP_1 <32 bytes>. They cannot collide
/// with a real output, which is the point — the scan does all its filter work
/// and never fetches a block.
private func syntheticWatchScripts(count: Int) -> [Data] {
    (0 ..< count).map { index in
        var script = Data([0x51, 0x20])
        script.append(Data((0 ..< 32).map { UInt8((index &* 31 &+ $0) & 0xFF) }))
        return script
    }
}

private struct Sample: Encodable {
    var at: String
    var elapsedSeconds: Int
    var residentBytes: UInt64
    var peersConnected: Int
    var peersTarget: Int
    var poolExhausted: Bool
    var chainHeight: UInt32
    var scanFrontier: UInt32
    var passes: Int
    var syncErrors: Int
    var reorgs: Int
    var deepestReorgToHeight: UInt32?
    var frontierRegressions: Int
    var lastError: String?
}

private let options: Options
do {
    options = try Options(arguments: Array(CommandLine.arguments.dropFirst()))
} catch {
    FileHandle.standardError.write(Data("\(error)\n".utf8))
    exit(2)
}

if let directory = options.stateDirectory {
    try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
}
if let out = options.out {
    try? FileManager.default.createDirectory(at: out.deletingLastPathComponent(),
                                             withIntermediateDirectories: true)
    if !FileManager.default.fileExists(atPath: out.path(percentEncoded: false)) {
        FileManager.default.createFile(atPath: out.path(percentEncoded: false), contents: nil)
    }
}

/// Counters shared between the scan task and the sampler.
private actor Counters {
    var passes = 0
    var syncErrors = 0
    var reorgs = 0
    var deepestReorgToHeight: UInt32?
    var frontierRegressions = 0
    var lastError: String?
    private var highWaterFrontier: UInt32 = 0

    func pass() { passes += 1 }

    func failed(_ error: any Error) {
        syncErrors += 1
        lastError = String(describing: error)
    }

    /// A reorg is the *only* legitimate reason for the frontier to move
    /// backwards. Anything else is a defect, so the two are counted apart
    /// rather than folded into one "went backwards" number.
    func reorg(to forkHeight: UInt32) {
        reorgs += 1
        if let deepest = deepestReorgToHeight {
            deepestReorgToHeight = min(deepest, forkHeight)
        } else {
            deepestReorgToHeight = forkHeight
        }
        highWaterFrontier = min(highWaterFrontier, forkHeight)
    }

    func observe(frontier: UInt32) {
        if frontier < highWaterFrontier { frontierRegressions += 1 }
        highWaterFrontier = max(highWaterFrontier, frontier)
    }

    var snapshot: (Int, Int, Int, UInt32?, Int, String?) {
        (passes, syncErrors, reorgs, deepestReorgToHeight, frontierRegressions, lastError)
    }
}

private let counters = Counters()
let scripts = syntheticWatchScripts(count: options.watchScriptCount)
let headerStore = options.stateDirectory?.appendingPathComponent("headers.dat")
let filterStore = options.stateDirectory?.appendingPathComponent("filters.json")
let peersStore = options.stateDirectory?.appendingPathComponent("peers.json")

let chain = try HeaderChain(params: options.network, storageURL: headerStore)
let pool = PeerPool(params: options.network, peerCount: options.peerCount, peersFileURL: peersStore)
let filters = try FilterSync(pool: pool, chain: chain,
                             startHeight: options.startHeight, storageURL: filterStore)

await pool.start()

let started = ContinuousClock.now
let formatter = ISO8601DateFormatter()

/// The scan runs continuously; a throw is recorded and retried rather than
/// ending the run. Transient peer failure is the normal case this is here to
/// survive, not an outcome worth aborting on.
let scan = Task {
    while !Task.isCancelled {
        do {
            try await filters.sync(watchScripts: scripts,
                                   onReorg: { forkHeight in await counters.reorg(to: forkHeight) },
                                   onMatch: { _ in })
            await counters.pass()
        } catch {
            await counters.failed(error)
            try? await Task.sleep(for: .seconds(5))
        }
        try? await Task.sleep(for: .seconds(1))
    }
}

var handle: FileHandle?
if let out = options.out {
    handle = try? FileHandle(forWritingTo: out)
    _ = try? handle?.seekToEnd()
}

let encoder = JSONEncoder()
encoder.outputFormatting = [.sortedKeys]

while true {
    let elapsed = ContinuousClock.now - started
    if let limit = options.runFor, elapsed >= limit { break }

    let status = await pool.connectionStatus
    let (passes, syncErrors, reorgs, deepest, regressions, lastError) = await counters.snapshot
    let frontier = await filters.nextScanHeight
    await counters.observe(frontier: frontier)

    let sample = Sample(at: formatter.string(from: Date()),
                        elapsedSeconds: Int(elapsed.components.seconds),
                        residentBytes: residentBytes(),
                        peersConnected: status.connected,
                        peersTarget: status.target,
                        poolExhausted: status.exhausted,
                        chainHeight: await chain.height,
                        scanFrontier: frontier,
                        passes: passes,
                        syncErrors: syncErrors,
                        reorgs: reorgs,
                        deepestReorgToHeight: deepest,
                        frontierRegressions: regressions,
                        lastError: lastError)

    if let line = try? encoder.encode(sample) {
        var payload = line
        payload.append(0x0A)
        handle?.write(payload)
        FileHandle.standardOutput.write(payload)
    }
    try? await Task.sleep(for: options.samplePeriod)
}

scan.cancel()
await pool.stop()
try? handle?.close()
