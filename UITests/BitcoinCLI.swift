import Foundation

/// Process-based `bitcoin-cli` runner for the dev custom-signet node
/// (default datadir ~/.bitcoin-mysignet, RPC :38400, P2P :38401 on
/// 127.0.0.1), plus the JSON accessors the differential checks lean on.
///
/// Copy of Tests/DifferentialTests/BitcoinCLI.swift (the SPM test target and
/// the Xcode UI-test target are separate worlds; keep them in sync).
///
/// Node location is env-configurable (CI runners reach the node over
/// LAN/Tailscale, not loopback); the defaults reproduce the local dev setup
/// exactly:
/// - WINNOW_NODE_HOST — RPC/P2P host (default 127.0.0.1)
/// - WINNOW_P2P_PORT  — P2P port (default 38401)
/// - WINNOW_RPC_PORT  — RPC port (default 38400)
/// - WINNOW_DATADIR   — datadir for cookie auth (default ~/.bitcoin-mysignet)
/// - WINNOW_BITCOIN_CLI — full path to bitcoin-cli (default: the first hit
///   in `searchPaths`, which covers both Homebrew prefixes and MacPorts)
///
/// Inside the simulator the process environment is NOT inherited from
/// xcodebuild; the same keys are then read from ~/.winnow-node.env on the
/// host (see env(_:) below).
///
/// Everything here is read-only against the node EXCEPT `generatetoaddress`
/// mining on the disposable custom signet, which is expected and safe.
enum BitcoinCLI {
    /// The node's BIP325 signet challenge (hex); its signing key lives in the
    /// "miner" wallet of the same datadir.
    static let challengeHex =
        "512102d4d3dfe322ab358061c7e08beebb48dc06a4c175342b975ecd0d55a79e6d6cdc51ae"
    static let challenge = Data(hex: challengeHex)!

    /// The HOST home directory: inside the iOS simulator NSHomeDirectory()
    /// is the test runner's container; the node datadir lives in the real
    /// user home.
    static var hostHome: String {
        ProcessInfo.processInfo.environment["SIMULATOR_HOST_HOME"] ?? NSHomeDirectory()
    }

    /// An environment override; empty values count as unset. `xcodebuild
    /// test` does NOT forward its process environment into the iOS-simulator
    /// test runner, so the harness also reads KEY=VALUE lines from
    /// ~/.winnow-node.env on the host (CI writes it before the UI run).
    private static func env(_ key: String) -> String? {
        if let value = ProcessInfo.processInfo.environment[key], !value.isEmpty { return value }
        return fileOverrides[key]
    }

    private static let fileOverrides: [String: String] = {
        let url = URL(fileURLWithPath: hostHome).appending(path: ".winnow-node.env")
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [:] }
        var result: [String: String] = [:]
        for line in text.split(separator: "\n") {
            let parts = line.split(separator: "=", maxSplits: 1)
            let key = String(parts[0]).trimmingCharacters(in: .whitespaces)
            let value = parts.count == 2 ? String(parts[1]).trimmingCharacters(in: .whitespaces) : ""
            if !key.isEmpty, !value.isEmpty { result[key] = value }
        }
        return result
    }()

    static let nodeHost = env("WINNOW_NODE_HOST") ?? "127.0.0.1"
    static let p2pPort: UInt16 = env("WINNOW_P2P_PORT").flatMap { UInt16($0) } ?? 38_401
    static let rpcPort = env("WINNOW_RPC_PORT").flatMap { Int($0) } ?? 38_400
    static let datadir = env("WINNOW_DATADIR") ?? "\(hostHome)/.bitcoin-mysignet"

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
    /// is arm64 (`/opt/homebrew`), and hardcoding the arm64 one is what made
    /// the UI suite unable to find an installed bitcoin-cli on runner-1
    /// (#31). Override with WINNOW_BITCOIN_CLI (a full path to the binary).
    static let searchPaths = ["/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin"]

    /// bitcoin-cli binary: WINNOW_BITCOIN_CLI, else the first hit in
    /// `searchPaths`.
    ///
    /// Deliberately no which(1) fallback, unlike the differential copy. That
    /// copy spawns through Foundation `Process` and inherits the runner
    /// shell's environment, so its `which` searches a real PATH. Here there
    /// is no PATH to search: `xcodebuild test` does not forward its
    /// environment into the iOS-simulator test runner (see env(_:) above),
    /// so any PATH handed to a spawned `which` would be one this file
    /// constructed — making the lookup equivalent to probing `searchPaths`
    /// directly, but with a process spawn and a parse in the way.
    static var binaryPath: String? {
        if let override = env("WINNOW_BITCOIN_CLI"),
           FileManager.default.isExecutableFile(atPath: override) { return override }
        return searchPaths
            .map { $0 + "/bitcoin-cli" }
            .first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    /// Runs `bitcoin-cli` with the node selection flags prepended; returns the
    /// trimmed stdout. Throws `CLIError` on a non-zero exit.
    @discardableResult
    static func run(_ arguments: [String], wallet: String? = nil) throws -> String {
        guard let binary = binaryPath else {
            throw CLIError(arguments: arguments, status: -1,
                           output: "bitcoin-cli not found in \(searchPaths.joined(separator: ", "))"
                               + " (set WINNOW_BITCOIN_CLI to a full path, or add it to"
                               + " \(hostHome)/.winnow-node.env, to override)")
        }
        var full = ["-datadir=\(datadir)", "-rpcport=\(rpcPort)", "-rpcconnect=\(nodeHost)"]
        if let wallet { full.append("-rpcwallet=\(wallet)") }
        full.append(contentsOf: arguments)

        let result = try HostProcess.run(binary, full)
        let out = result.stdout
        guard result.status == 0 else {
            throw CLIError(arguments: arguments, status: result.status,
                           output: (out + result.stderr).trimmingCharacters(in: .whitespacesAndNewlines))
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

    /// A fresh bech32m address from the node's "miner" wallet (send target).
    static func newMinerAddress() throws -> String {
        try run(["getnewaddress", "e2e", "bech32m"], wallet: "miner")
    }

    /// (txid, value in sats, scriptPubKey hex) of a transaction's output 0.
    static func outputZero(txid: String) throws -> (txid: String, amount: Int64, scriptPubKey: String) {
        let tx = try runObject(["getrawtransaction", txid, "true"])
        let vouts = try array(tx, "vout")
        guard let output = vouts.first as? [String: Any],
              let scriptPubKey = output["scriptPubKey"] as? [String: Any],
              let hex = scriptPubKey["hex"] as? String, let value = output["value"]
        else { throw CLIError(arguments: ["getrawtransaction"], status: -1, output: "no vout 0") }
        return (txid, try sats(value), hex)
    }

    /// The coinbase txid of a block.
    static func coinbaseTxid(blockHash: String) throws -> String {
        let block = try runObject(["getblock", blockHash])
        let txs = try array(block, "tx")
        guard let txid = txs.first as? String else {
            throw CLIError(arguments: ["getblock"], status: -1, output: "no coinbase")
        }
        return txid
    }

    /// The height a block was accepted at.
    static func blockHeight(of blockHash: String) throws -> Int {
        try int(runObject(["getblock", blockHash]), "height")
    }

    /// Current mempool txids (display hex).
    static func mempoolTxids() throws -> [String] {
        (try runJSON(["getrawmempool"]) as? [String]) ?? []
    }
}
