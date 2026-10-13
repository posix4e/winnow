import WalletCore
import Foundation
import WinnowFuzzCore

private struct Options {
    var iterations = 2_000
    var seed: UInt64 = 0x5749_4E4E_4F57_4655 // "WINNOWFU"
    var target: FuzzTarget?
    var maxInput = 4_096
    var artifactDirectory: URL?

    /// The `--target` selection as given, so a recorded case can be replayed
    /// with the same interleaving.
    var targetName: String { target?.rawValue ?? "all" }

    init(arguments: [String]) throws {
        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            func value() throws -> String {
                guard index + 1 < arguments.count else { throw RunnerError.usage("missing value for \(argument)") }
                index += 1
                return arguments[index]
            }
            switch argument {
            case "--iterations":
                guard let parsed = Int(try value()), parsed > 0 else { throw RunnerError.usage("iterations must be positive") }
                iterations = parsed
            case "--seed":
                let text = try value()
                let parsed = text.hasPrefix("0x")
                    ? UInt64(String(text.dropFirst(2)), radix: 16)
                    : UInt64(text)
                guard let parsed else {
                    throw RunnerError.usage("seed must be decimal or hexadecimal")
                }
                seed = parsed
            case "--target":
                let name = try value()
                guard name != "all" else { target = nil; break }
                guard let parsed = FuzzTarget(rawValue: name) else { throw RunnerError.usage("unknown target \(name)") }
                target = parsed
            case "--max-input":
                guard let parsed = Int(try value()), parsed > 0, parsed <= 1_000_000 else {
                    throw RunnerError.usage("max input must be 1...1000000")
                }
                maxInput = parsed
            case "--artifact-dir":
                let path = try value()
                let base = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
                artifactDirectory = URL(fileURLWithPath: path, isDirectory: true, relativeTo: base).standardizedFileURL
            default: throw RunnerError.usage("unknown argument \(argument)")
            }
            index += 1
        }
    }
}

private enum RunnerError: Error, CustomStringConvertible {
    case usage(String)
    case invariant(String)

    var description: String {
        switch self {
        case let .usage(message): "\(message)\nusage: WinnowFuzz [--iterations N] [--seed N|0xHEX] [--target all|\(FuzzTarget.allCases.map(\.rawValue).joined(separator: "|"))] [--max-input N] [--artifact-dir PATH]"
        case let .invariant(message): message
        }
    }
}

private let generatorXOnly = Data(hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")!

private func binaryCorpus(for target: FuzzTarget) -> [Data] {
    let minimalTransaction = Data(hex:
        "0200000001" + String(repeating: "00", count: 32) +
            "ffffffff00ffffffff0100000000000000000000000000")!
    switch target {
    case .psbt:
        return [Data(), Data([0x70, 0x73, 0x62, 0x74, 0xFF]), Data(hex:
            "70736274ff01fb040200000001020402000000010401000105010000")!]
    case .descriptor:
        // Extended keys so mutation can reach the multipath, tree, multisig
        // and musig grammar, not just a raw key inside tr().
        let account = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
        let other = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
        return [Data(), Data("tr(\(generatorXOnly.hex))".utf8), Data("rawtr(\(generatorXOnly.hex))".utf8),
                Data("tr([deadbeef/86'/0'/0']\(account)/<0;1>/*)".utf8),
                Data("tr(\(account)/<0;1>/*,{pk(\(other)/0/*),sortedmulti_a(2,\(account)/*,\(other)/0/0/*)})".utf8),
                Data("tr(musig(\(account),\(other))/0/*)".utf8)]
    case .transaction:
        return [Data(), minimalTransaction]
    case .block:
        return [Data(), Data(repeating: 0, count: 80) + Data([0]),
                Data(repeating: 0, count: 80) + Data([1]) + minimalTransaction]
    case .messages:
        return [Data(), minimalTransaction, Data(repeating: 0, count: 8)]
    case .framing:
        return [Data(), MessageFramer.frame(command: "ping", payload: Data(repeating: 0, count: 8),
                                            magic: Data([0x0A, 0x03, 0xCF, 0x40]))]
    case .filter:
        return [Data(), Data([0])]
    case .address:
        let address = try? Descriptor("tr(\(generatorXOnly.hex))").derived(index: 0).first?.address
        return [Data(), Data((address ?? "bc1p").utf8)]
    case .importBundle:
        return [Data(), Data("{\"version\":2,\"network\":\"signet\",\"lastKnownHeight\":0,\"utxos\":[],\"transactions\":[]}".utf8)]
    case .census:
        return [Data(), Data(("{\"schemaVersion\":1,\"date\":\"2026-09-13\",\"tip\":900000,\"networks\":{\"clearnet\":"
                + "[{\"host\":\"8.8.8.8\",\"port\":8333,\"userAgent\":\"/Satoshi:30/\",\"startHeight\":900000}],"
                + "\"tor\":[],\"i2p\":[]}}").utf8)]
    case .dnsJSON:
        return [Data(), Data("{\"Status\":0,\"Answer\":[{\"name\":\"seed.example.\",\"type\":1,\"TTL\":60,\"data\":\"8.8.8.8\"}]}".utf8)]
    case .fundingSources:
        return [Data(), minimalTransaction]
    case .controlBlock:
        return [Data(), Data([0xC0]) + generatorXOnly, Data([0xC1]) + generatorXOnly + Data(repeating: 0, count: 32)]
    case .personPaste:
        return [Data(), Data("tr(\(generatorXOnly.hex))".utf8),
                Data("{\"winnow\":\"person-card\",\"version\":1,\"network\":\"signet\",\"name\":\"Alice\"}".utf8)]
    }
}

private func mutate(_ source: Data, rng: inout SplitMix64, maximum: Int) -> Data {
    var bytes = Array(source.prefix(maximum))
    let operations = 1 + rng.index(8)
    for _ in 0 ..< operations {
        switch rng.index(7) {
        case 0 where !bytes.isEmpty:
            let index = rng.index(bytes.count)
            bytes[index] ^= UInt8(1 << rng.index(8))
        case 1 where !bytes.isEmpty:
            bytes[rng.index(bytes.count)] = UInt8(truncatingIfNeeded: rng.next())
        case 2 where bytes.count < maximum:
            bytes.insert(UInt8(truncatingIfNeeded: rng.next()), at: rng.index(bytes.count + 1))
        case 3 where !bytes.isEmpty:
            bytes.remove(at: rng.index(bytes.count))
        case 4 where !bytes.isEmpty:
            bytes.removeSubrange(rng.index(bytes.count) ..< bytes.count)
        case 5 where !bytes.isEmpty && bytes.count < maximum:
            let start = rng.index(bytes.count)
            let length = min(1 + rng.index(min(32, bytes.count - start)), maximum - bytes.count)
            bytes.insert(contentsOf: bytes[start ..< start + length], at: rng.index(bytes.count + 1))
        default:
            let bombs: [[UInt8]] = [[0xFF], [0xFD, 0xFF, 0xFF], [0xFE, 0xFF, 0xFF, 0xFF, 0xFF],
                                    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]]
            let bomb = bombs[rng.index(bombs.count)]
            let room = maximum - bytes.count
            if room > 0 { bytes.insert(contentsOf: bomb.prefix(room), at: rng.index(bytes.count + 1)) }
        }
    }
    return Data(bytes)
}

/// Standard output through the descriptor, not stdio: a trap never flushes a
/// pipe's buffer, and these lines exist to survive one.
private func emit(_ line: String) {
    FileHandle.standardOutput.write(Data("\(line)\n".utf8))
}

/// Names the case in flight, so a trap (which never reaches `saveFailure`)
/// still leaves the target, seed, and iteration on disk. One plain write per
/// case is the simplest correct option: the kernel keeps the bytes when the
/// process dies, there is no handle to manage, and lines of varying length
/// need no truncation.
private struct InFlightMarker {
    let url: URL?

    init(directory: URL?) {
        url = directory?.appendingPathComponent("in-flight.txt")
        if let directory {
            try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }
    }

    func record(_ line: String) {
        guard let url else { return }
        try? Data("\(line)\n".utf8).write(to: url)
    }

    func clear() {
        guard let url else { return }
        try? FileManager.default.removeItem(at: url)
    }
}

private func saveFailure(_ data: Data, target: FuzzTarget, seed: UInt64, iteration: Int, directory: URL?) {
    guard let directory else { return }
    try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let url = directory.appendingPathComponent("\(target.rawValue)-\(String(seed, radix: 16))-\(iteration).bin")
    FileManager.default.createFile(atPath: url.path, contents: data,
                                   attributes: [.posixPermissions: 0o600])
    emit("saved \(url.path); add this file under Tests/ToolsTests/Cases/\(target.rawValue)/ to keep it as a regression")
}

@main
private enum WinnowFuzzMain {
    static func main() {
        do {
            let options = try Options(arguments: Array(CommandLine.arguments.dropFirst()))
            let targets = options.target.map { [$0] } ?? FuzzTarget.allCases
            let seed = "0x\(String(options.seed, radix: 16))"
            let marker = InFlightMarker(directory: options.artifactDirectory)
            for target in targets {
                emit("fuzzing target=\(target.rawValue) seed=\(seed) iterations=\(options.iterations) max-input=\(options.maxInput)")
            }
            var rng = SplitMix64(state: options.seed)
            var runs = 0
            for iteration in 0 ..< options.iterations {
                for target in targets {
                    marker.record("target=\(target.rawValue) seed=\(seed) iteration=\(iteration) " +
                        "targets=\(options.targetName) max-input=\(options.maxInput)")
                    let corpus = binaryCorpus(for: target)
                    let input = mutate(corpus[rng.index(corpus.count)], rng: &rng, maximum: options.maxInput)
                    do {
                        try exercise(target, data: input, rng: &rng)
                    } catch {
                        saveFailure(input, target: target, seed: options.seed, iteration: iteration,
                                    directory: options.artifactDirectory)
                        throw RunnerError.invariant("target=\(target.rawValue) seed=0x\(String(options.seed, radix: 16)) iteration=\(iteration): \(error)")
                    }
                    runs += 1
                }
            }
            marker.clear()
            print("WinnowFuzz passed \(runs) deterministic cases (seed 0x\(String(options.seed, radix: 16)))")
        } catch {
            FileHandle.standardError.write(Data("\(error)\n".utf8))
            Foundation.exit(1)
        }
    }
}
