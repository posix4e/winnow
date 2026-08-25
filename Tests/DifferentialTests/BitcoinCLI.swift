import Foundation

/// Process-based `bitcoin-cli` runner for the dev custom-signet node
/// (default datadir ~/.bitcoin-mysignet, RPC :38400, P2P :38401 on
/// 127.0.0.1), plus the JSON accessors the differential checks lean on.
///
/// Node location is env-configurable (CI runners reach the node over
/// LAN/Tailscale, not loopback); the defaults reproduce the local dev setup
/// exactly:
/// - WINNOW_NODE_HOST — RPC/P2P host (default 127.0.0.1)
/// - WINNOW_P2P_PORT  — P2P port (default 38401)
/// - WINNOW_RPC_PORT  — RPC port (default 38400)
/// - WINNOW_DATADIR   — datadir for cookie auth (default ~/.bitcoin-mysignet)
/// - WINNOW_BITCOIN_CLI — full path to bitcoin-cli (default: the first hit
///   in `searchPaths`, then PATH)
///
/// Everything here is read-only against the node EXCEPT `generatetoaddress`
/// mining on the disposable custom signet, which is expected and safe.
enum BitcoinCLI {
    /// The node's BIP325 signet challenge (hex); its signing key lives in the
    /// "miner" wallet of the same datadir.
    static let challengeHex =
        "512102d4d3dfe322ab358061c7e08beebb48dc06a4c175342b975ecd0d55a79e6d6cdc51ae"
    static let challenge = Data(hex: challengeHex)!

    /// An environment override; empty values count as unset.
    private static func env(_ key: String) -> String? {
        guard let value = ProcessInfo.processInfo.environment[key], !value.isEmpty else { return nil }
        return value
    }

    static let nodeHost = env("WINNOW_NODE_HOST") ?? "127.0.0.1"
    static let p2pPort: UInt16 = env("WINNOW_P2P_PORT").flatMap { UInt16($0) } ?? 38_401
    static let rpcPort = env("WINNOW_RPC_PORT").flatMap { Int($0) } ?? 38_400
    static let datadir = env("WINNOW_DATADIR") ?? "\(NSHomeDirectory())/.bitcoin-mysignet"

    struct CLIError: Error, CustomStringConvertible, Equatable {
        let arguments: [String]
        let status: Int32
        let output: String

        var description: String {
            "bitcoin-cli \(arguments.joined(separator: " ")) failed (\(status)): \(output)"
        }
    }

    /// bitcoin-util binary (same install as bitcoin-cli), used for PoW grinding.
    static var bitcoinUtilPath: String? {
        if let cli = binaryPath {
            let util = (cli as NSString).deletingLastPathComponent + "/bitcoin-util"
            if FileManager.default.isExecutableFile(atPath: util) { return util }
        }
        return nil
    }

    /// Directories probed for the node binaries, in order: Homebrew on Apple
    /// Silicon, Homebrew on Intel, MacPorts. Both Homebrew prefixes matter —
    /// the CI runners are x86_64 (`/usr/local`) while every dev machine here
    /// is arm64 (`/opt/homebrew`). Kept identical to the UI-test copy; only
    /// that copy was observed failing (#31), because this one's which(1)
    /// fallback inherits a real PATH and covered for the arm64-only
    /// hardcode. Override with WINNOW_BITCOIN_CLI (a full path to the binary).
    static let searchPaths = ["/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin"]

    /// bitcoin-cli binary: WINNOW_BITCOIN_CLI, then `searchPaths`, then PATH.
    static var binaryPath: String? {
        if let override = env("WINNOW_BITCOIN_CLI"),
           FileManager.default.isExecutableFile(atPath: override) { return override }
        if let hit = searchPaths
            .map({ $0 + "/bitcoin-cli" })
            .first(where: { FileManager.default.isExecutableFile(atPath: $0) }) { return hit }
        // which(1) lookup for non-standard installs. Unlike the UI-test copy,
        // this is live code: Foundation `Process` inherits the runner shell's
        // environment, so `which` searches a real PATH.
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        process.arguments = ["bitcoin-cli"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        guard (try? process.run()) != nil else { return nil }
        process.waitUntilExit()
        let found = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return process.terminationStatus == 0 && !found.isEmpty ? found : nil
    }

    /// Runs `bitcoin-cli` with the node selection flags prepended; returns the
    /// trimmed stdout. Throws `CLIError` on a non-zero exit.
    @discardableResult
    static func run(_ arguments: [String], wallet: String? = nil) throws -> String {
        guard let binary = binaryPath else {
            throw CLIError(arguments: arguments, status: -1,
                           output: "bitcoin-cli not found in \(searchPaths.joined(separator: ", "))"
                               + " or on PATH (set WINNOW_BITCOIN_CLI to a full path to override)")
        }
        var full = ["-datadir=\(datadir)", "-rpcport=\(rpcPort)", "-rpcconnect=\(nodeHost)"]
        if let wallet { full.append("-rpcwallet=\(wallet)") }
        full.append(contentsOf: arguments)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: binary)
        process.arguments = full
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        // Drain both pipes *before* waiting. A pipe holds about 64 KB; past
        // that the child blocks writing while the parent blocks in
        // `waitUntilExit`, and neither ever moves again. Reading after the
        // wait worked only because every call here used to return a small
        // answer — `decoderawtransaction` on a transaction with large scripts
        // returns hundreds of kilobytes and deadlocks the suite outright,
        // which silently capped what this harness could ever check.
        try process.run()
        var outData = Data()
        var errData = Data()
        let group = DispatchGroup()
        let queue = DispatchQueue(label: "org.winnow.diff.cli", attributes: .concurrent)
        queue.async(group: group) { outData = stdout.fileHandleForReading.readDataToEndOfFile() }
        queue.async(group: group) { errData = stderr.fileHandleForReading.readDataToEndOfFile() }
        group.wait()
        process.waitUntilExit()
        let out = String(decoding: outData, as: UTF8.self)
        let err = String(decoding: errData, as: UTF8.self)
        guard process.terminationStatus == 0 else {
            throw CLIError(arguments: arguments, status: process.terminationStatus,
                           output: (out + err).trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return out.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Runs a JSON-producing command; nil for empty output, the raw string
    /// for non-JSON results (e.g. a bare `submitblock` reject reason).
    static func runJSON(_ arguments: [String], wallet: String? = nil) throws -> Any? {
        let output = try run(arguments, wallet: wallet)
        guard !output.isEmpty else { return nil }
        // Bare scalars/unquoted text (submitblock rejections) come back raw.
        return (try? JSONSerialization.jsonObject(with: Data(output.utf8),
                                                  options: [.fragmentsAllowed])) ?? output
    }

    static func runObject(_ arguments: [String], wallet: String? = nil) throws -> [String: Any] {
        guard let object = try runJSON(arguments, wallet: wallet) as? [String: Any] else {
            throw CLIError(arguments: arguments, status: -1, output: "expected a JSON object")
        }
        return object
    }

    // MARK: - Convenience accessors for loosely-typed RPC JSON

    static func string(_ object: [String: Any], _ key: String) throws -> String {
        guard let value = object[key] as? String else {
            throw CLIError(arguments: [key], status: -1, output: "missing string field \(key)")
        }
        return value
    }

    static func int(_ object: [String: Any], _ key: String) throws -> Int {
        guard let value = object[key] as? NSNumber else {
            throw CLIError(arguments: [key], status: -1, output: "missing numeric field \(key)")
        }
        return value.intValue
    }

    static func array(_ object: [String: Any], _ key: String) throws -> [Any] {
        guard let value = object[key] as? [Any] else {
            throw CLIError(arguments: [key], status: -1, output: "missing array field \(key)")
        }
        return value
    }

    /// A BTC-amount JSON number as exact sats (Core prints 8 decimals).
    static func sats(_ value: Any) throws -> Int64 {
        guard let number = value as? NSNumber else {
            throw CLIError(arguments: ["amount"], status: -1, output: "expected numeric amount")
        }
        return Int64((number.doubleValue * 100_000_000).rounded())
    }

    // MARK: - Node facts

    static func blockCount() throws -> Int {
        try Int(run(["getblockcount"]))!
    }

    static func blockHash(at height: Int) throws -> String {
        try run(["getblockhash", String(height)])
    }

    static func bestBlockHash() throws -> String {
        try run(["getbestblockhash"])
    }

    /// The scriptPubKey (hex) paid by output `vout` of `txid` (txindex on).
    static func spentScript(txid: String, vout: Int) throws -> String {
        let tx = try runObject(["getrawtransaction", txid, "true"])
        let vouts = try array(tx, "vout")
        let output = vouts[vout] as! [String: Any]
        let scriptPubKey = output["scriptPubKey"] as! [String: Any]
        return scriptPubKey["hex"] as! String
    }
}
