import BitcoinP2P
import BlockchainBackend
import Foundation

/// The providers Winnow knows how to talk to, with the evidence for each.
///
/// There is no discovery protocol for miners: nothing like a DNS seed
/// exists for submission endpoints, so this list is curated by hand and
/// shipped with the app, like the fallback peers. Adding an entry means
/// adding a documentation URL and a sourced evidence sentence, and the
/// status word follows the canonical paper's four (docs/paper.md §1).
public struct ProviderEntry: Equatable, Sendable, Identifiable {
    public enum Kind: String, Sendable { case slipstream, coreRPC }

    /// The paper's status words, verbatim, so Settings and the paper cannot
    /// drift apart on what a provider is.
    public enum Status: String, Sendable, CaseIterable {
        case planned = "Planned"
        case experimental = "Experimental"
        case implemented = "Implemented"
        case verifiedOnSignet = "Verified on signet"
    }

    public let id: MinerProviderID
    public let name: String
    public let kind: Kind
    public let networks: Set<BitcoinNetwork>
    /// nil means the user has to enter one (their own node).
    public let defaultBaseURL: URL?
    /// What the credential field is called, or nil when there is none.
    public let credentialLabel: String?
    public let documentationURL: URL
    public let status: Status
    /// One sentence, sourced, shown next to the status in Settings.
    public let evidence: String
    /// What the provider receives, for the confirmation alert.
    public let disclosure: String

    public func supports(_ network: BitcoinNetwork) -> Bool {
        networks.contains(network)
    }
}

public enum ProviderDirectory {
    public static let entries: [ProviderEntry] = [
        ProviderEntry(
            id: .slipstream,
            name: "MARA Slipstream",
            kind: .slipstream,
            networks: [.mainnet],
            defaultBaseURL: URL(string: "https://slipstream.mara.com")!,
            credentialLabel: "Client code (optional)",
            documentationURL: URL(string: "https://slipstream.mara.com/docs/")!,
            status: .planned,
            evidence: "Beta API documented by MARA; no Winnow adapter has been built or tested yet.",
            disclosure: "MARA receives this exact signed transaction, your IP address, and the time of the request. It may log, delay, reject, or decline to mine it for fee or policy reasons, and it does not guarantee inclusion."),
        ProviderEntry(
            id: .coreRPC,
            name: "Your own node (Bitcoin Core RPC)",
            kind: .coreRPC,
            networks: [.mainnet, .signet],
            defaultBaseURL: nil,
            credentialLabel: "RPC user and password",
            documentationURL: URL(string: "https://bitcoincore.org/en/doc/31.0.0/rpc/rawtransactions/sendrawtransaction/")!,
            status: .planned,
            evidence: "Bitcoin Core's sendrawtransaction and submitpackage RPCs; no Winnow adapter has been built or tested yet.",
            disclosure: "The node receives this exact signed transaction and your IP address. If it is not your own node, its operator may log, delay, reject, or decline to relay it."),
    ]

    public static func entry(_ id: MinerProviderID) -> ProviderEntry? {
        entries.first { $0.id == id }
    }

    public static func entries(for network: BitcoinNetwork) -> [ProviderEntry] {
        entries.filter { $0.supports(network) }
    }
}
