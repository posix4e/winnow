import BlockchainBackend
import Foundation

/// How a signed transaction leaves the phone. Signing and submission are
/// separate decisions (docs/paper.md §6.1): the route is chosen on the review
/// screen, pinned into the preview, and recorded in the receipt.
///
/// `peers` is the default and the only route a beginner ever sees. The miner
/// routes hand the raw transaction, an IP address and a timestamp to one
/// provider; `minerOnly` never touches Bitcoin peers unless the user later
/// approves a re-route, and that approval is recorded. `export` submits
/// nothing: the signed bytes are handed to another system.
public enum SubmissionRoute: Equatable, Hashable, Codable, Sendable {
    case peers
    case minerOnly(MinerProviderID)
    case minerAndPeers(MinerProviderID)
    case export

    /// Whether this route announces to Bitcoin peers at all.
    public var touchesPeers: Bool {
        switch self {
        case .peers, .minerAndPeers: true
        case .minerOnly, .export: false
        }
    }

    /// The provider this route submits to, if any.
    public var miner: MinerProviderID? {
        switch self {
        case let .minerOnly(provider), let .minerAndPeers(provider): provider
        case .peers, .export: nil
        }
    }

    /// Whether the transaction stays out of the public mempool until the
    /// provider mines it. Only true for `minerOnly`; `minerAndPeers` is
    /// explicitly the less private of the two miner routes.
    public var isPrivateToMiner: Bool {
        if case .minerOnly = self { return true }
        return false
    }

    /// Whether choosing this route performs any network request.
    public var submits: Bool {
        if case .export = self { return false }
        return true
    }

    /// Short label for history rows and receipts.
    public var label: String {
        switch self {
        case .peers: "Bitcoin peers"
        case let .minerOnly(provider): "\(provider.rawValue) only"
        case let .minerAndPeers(provider): "\(provider.rawValue) and peers"
        case .export: "Exported"
        }
    }
}
