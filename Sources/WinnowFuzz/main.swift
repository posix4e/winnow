import BitcoinCore
import BitcoinP2P
import Foundation
import WalletCore

private enum Target: String, CaseIterable {
    case psbt
    case descriptor
    case transaction
    case block
    case messages
    case framing
    case filter
    case address
    case importBundle = "import"
}

private struct SplitMix64 {
    var state: UInt64

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var value = state
        value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
        value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
        return value ^ (value >> 31)
    }

    mutating func index(_ upperBound: Int) -> Int {
        guard upperBound > 0 else { return 0 }
        return Int(next() % UInt64(upperBound))
    }
}

private struct Options {
    var iterations = 2_000
    var seed: UInt64 = 0x5749_4E4E_4F57_4655 // "WINNOWFU"
    var target: Target?
    var maxInput = 4_096
    var artifactDirectory: URL?

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
                guard let parsed = Target(rawValue: name) else { throw RunnerError.usage("unknown target \(name)") }
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
        case let .usage(message): "\(message)\nusage: WinnowFuzz [--iterations N] [--seed N|0xHEX] [--target all|\(Target.allCases.map(\.rawValue).joined(separator: "|"))] [--max-input N] [--artifact-dir PATH]"
        case let .invariant(message): message
        }
    }
}

private let generatorXOnly = Data(hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")!

private func binaryCorpus(for target: Target) -> [Data] {
    let minimalTransaction = Data(hex:
        "0200000001" + String(repeating: "00", count: 32) +
            "ffffffff00ffffffff0100000000000000000000000000")!
    switch target {
    case .psbt:
        return [Data(), Data([0x70, 0x73, 0x62, 0x74, 0xFF]), Data(hex:
            "70736274ff01fb040200000001020402000000010401000105010000")!]
    case .descriptor:
        return [Data(), Data("tr(\(generatorXOnly.hex))".utf8), Data("rawtr(\(generatorXOnly.hex))".utf8)]
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

private func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw RunnerError.invariant(message) }
}

private func exercise(_ target: Target, data: Data, rng: inout SplitMix64) throws {
    switch target {
    case .psbt:
        if let parsed = try? PSBT(serialized: data) {
            try require(try PSBT(serialized: parsed.serialized) == parsed, "PSBT canonical round trip changed semantics")
            try require(try PSBT(base64: parsed.base64) == parsed, "PSBT Base64 round trip changed semantics")
        }
    case .descriptor:
        if let parsed = try? Descriptor(String(decoding: data, as: UTF8.self)) {
            try require(try Descriptor(parsed.serialized()) == parsed, "descriptor canonical round trip changed semantics")
        }
    case .transaction:
        if let parsed = try? Transaction.decode(data) {
            try require(try Transaction.decode(parsed.serialized(includeWitness: true)) == parsed,
                        "transaction canonical round trip changed semantics")
        }
    case .block:
        if let parsed = try? Block.decode(data) {
            try require(try Block.decode(parsed.serialized) == parsed, "block canonical round trip changed semantics")
        }
    case .messages:
        let commands = ["version", "verack", "ping", "pong", "sendheaders", "feefilter", "inv", "getdata",
                        "notfound", "tx", "block", "getheaders", "headers", "getcfilters", "cfilter",
                        "getcfheaders", "cfheaders", "getcfcheckpt", "cfcheckpt"]
        for command in commands {
            if let parsed = try? PeerMessage.decode(command: command, payload: data) {
                try require(try PeerMessage.decode(command: parsed.command, payload: parsed.payload) == parsed,
                            "\(command) message canonical round trip changed semantics")
            }
        }
    case .framing:
        var framer = MessageFramer(magic: Data([0x0A, 0x03, 0xCF, 0x40]))
        var offset = 0
        while offset < data.count {
            let length = min(data.count - offset, 1 + rng.index(31))
            framer.append(data.subdata(in: offset ..< offset + length))
            offset += length
        }
        var decoded = 0
        while true {
            let next: (command: String, payload: Data)?
            do {
                next = try framer.nextMessage()
            } catch {
                break
            }
            guard let message = next else { break }
            let reframed = MessageFramer.frame(command: message.command, payload: message.payload, magic: framer.magic)
            var check = MessageFramer(magic: framer.magic)
            check.append(reframed)
            let roundTrip = try check.nextMessage()
            try require(roundTrip?.command == message.command && roundTrip?.payload == message.payload,
                        "framed message did not round trip")
            decoded += 1
            if decoded == 32 { break }
        }
    case .filter:
        var reader = ByteReader(data)
        if let count = try? reader.readVarInt(), count <= UInt64(UInt32.max) {
            let encoded = data.subdata(in: data.startIndex + reader.offset ..< data.endIndex)
            if let filter = try? GCSFilter(key: Data(repeating: 0, count: 16), n: UInt32(count), encoded: encoded) {
                _ = filter.matchAny([data.prefix(32), Data([0]), Data()])
                try require(filter.serialized == data, "GCS filter canonical round trip changed bytes")
            }
        }
    case .address:
        let string = String(decoding: data, as: UTF8.self)
        for network in [BitcoinNetwork.mainnet, .signet] {
            if let script = try? AddressDecoder.scriptPubKey(for: string, network: network) {
                try require(script.count <= 42, "address produced an oversized standard script")
            }
        }
    case .importBundle:
        guard data.count <= 4_000_000, let bundle = try? JSONDecoder().decode(ImportBundle.self, from: data) else { return }
        let serialized = try bundle.serialized()
        try require(try JSONDecoder().decode(ImportBundle.self, from: Data(serialized.utf8)) == bundle,
                    "import bundle canonical round trip changed semantics")
        _ = try? bundle.claimedUTXOs()
    }
}

private func saveFailure(_ data: Data, target: Target, seed: UInt64, iteration: Int, directory: URL?) {
    guard let directory else { return }
    try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let url = directory.appendingPathComponent("\(target.rawValue)-\(String(seed, radix: 16))-\(iteration).bin")
    FileManager.default.createFile(atPath: url.path, contents: data,
                                   attributes: [.posixPermissions: 0o600])
}

@main
private enum WinnowFuzzMain {
    static func main() {
        do {
            let options = try Options(arguments: Array(CommandLine.arguments.dropFirst()))
            let targets = options.target.map { [$0] } ?? Target.allCases
            var rng = SplitMix64(state: options.seed)
            var runs = 0
            for iteration in 0 ..< options.iterations {
                for target in targets {
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
            print("WinnowFuzz passed \(runs) deterministic cases (seed 0x\(String(options.seed, radix: 16)))")
        } catch {
            FileHandle.standardError.write(Data("\(error)\n".utf8))
            Foundation.exit(1)
        }
    }
}
