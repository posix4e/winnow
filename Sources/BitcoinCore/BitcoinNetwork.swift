import Foundation

/// Bitcoin network identifier: mainnet, the public default signet (BIP325),
/// and regtest for a node on the same machine.
public enum BitcoinNetwork: String, Sendable, CaseIterable {
    case mainnet
    case signet
    /// A private chain on one machine, mined by RPC: what an end-to-end
    /// suite runs against. Never dialled from seeds; peers come from
    /// `PeerPool(manualPeers:)`. It begins at zero wherever it runs, so it
    /// ships no checkpoint.
    case regtest
}
