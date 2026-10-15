import Foundation
import VaultKit
import WalletCore

/// A Bitcoin Core signer for disposable node/app tests. Core generates the
/// key and signs through RPC; only its public expression goes into the app.
/// The private descriptor is used only to configure the test's Core wallet.
public struct CoreSigner {
    public enum SetupError: Error { case invalid(String) }
    public let wallet: String
    public let publicExpression: String
    public let privateExpression: String

    public init(wallet: String) throws {
        self.wallet = wallet
        if (try? BitcoinCLI.run(["loadwallet", wallet])) == nil,
           (try? BitcoinCLI.runJSON(["listwalletdir"])) != nil {
            _ = try? BitcoinCLI.run(["-named", "createwallet", "wallet_name=\(wallet)"])
        }
        func descriptor(private isPrivate: Bool) throws -> String {
            let listed = try BitcoinCLI.runObject(["listdescriptors", isPrivate ? "true" : "false"],
                                                  wallet: wallet)
            let entries = try BitcoinCLI.array(listed, "descriptors").compactMap { $0 as? [String: Any] }
            guard let entry = entries.first(where: {
                ($0["desc"] as? String)?.hasPrefix("tr(") == true && ($0["internal"] as? Bool) != true
            }), let text = entry["desc"] as? String else {
                throw SetupError.invalid("no external tr() descriptor in \(wallet)")
            }
            return text
        }
        publicExpression = try Self.keyExpression(from: descriptor(private: false))
        privateExpression = try Self.keyExpression(from: descriptor(private: true))
    }

    public func importVault(_ vault: Vault) throws {
        let text = String(vault.descriptor.serialized().split(separator: "#")[0])
        let privateText = text.replacingOccurrences(of: publicExpression, with: privateExpression)
        guard privateText != text else { throw SetupError.invalid("Core key absent from vault") }
        let checksum = try BitcoinCLI.string(BitcoinCLI.runObject(["getdescriptorinfo", privateText]), "checksum")
        let imported = try BitcoinCLI.runJSON(
            ["importdescriptors",
             #"[{"desc":"\#(privateText)#\#(checksum)","timestamp":"now","active":true,"range":[0,5]}]"#],
            wallet: wallet)
        guard ((imported as? [Any])?.first as? [String: Any])?["success"] as? Bool == true else {
            throw SetupError.invalid("Core refused the vault descriptor")
        }
    }

    public func process(_ psbt: PSBT) throws -> PSBT {
        let result = try BitcoinCLI.runObject(
            ["walletprocesspsbt", psbt.base64V0(), "true", "DEFAULT", "true", "false"], wallet: wallet)
        return try psbt.combined(with: [PSBT(base64: BitcoinCLI.string(result, "psbt"))])
    }

    // Parse at the boundary: replacing h/ globally can corrupt base58 keys.
    public static func keyExpression(from text: String) throws -> String {
        let descriptor = try Descriptor(text).serialized()
        guard let open = descriptor.firstIndex(of: "("),
              let close = descriptor.lastIndex(of: ")") else {
            throw SetupError.invalid("unparsable Core descriptor")
        }
        let inner = String(descriptor[descriptor.index(after: open) ..< close])
        guard let range = inner.range(of: "/0/*", options: .backwards) else {
            throw SetupError.invalid("unexpected Core key path")
        }
        return String(inner[..<range.lowerBound])
    }
}
