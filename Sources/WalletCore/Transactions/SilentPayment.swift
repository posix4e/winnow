import BitcoinCore
import BitcoinP2P
import Foundation

/// A BIP352 silent payment destination: an amount plus a silent payment
/// address. Unlike a plain `Payment` it carries no scriptPubKey — the P2TR
/// output script is derived from the transaction's inputs at signing time
/// (BIP352 §Creating outputs), once coin selection has fixed the input set
/// and their private keys are loaded.
public struct SilentPayment: Equatable, Sendable {
    public var amount: Int64
    public var address: SilentPaymentAddress

    public init(amount: Int64, address: SilentPaymentAddress) {
        self.amount = amount
        self.address = address
    }

    /// Parses a silent payment address string, enforcing the network's HRP
    /// ("sp" mainnet, "tsp" test networks — BIP352 §Address encoding).
    public init(amount: Int64, address: String, network: BitcoinNetwork) throws {
        self.amount = amount
        self.address = try SilentPaymentAddress(address, expectedHRP: Self.hrp(for: network))
    }

    /// BIP352 HRPs: "sp" for mainnet, "tsp" for all test networks (signet).
    public static func hrp(for network: BitcoinNetwork) -> String {
        switch network {
        case .mainnet: "sp"
        case .signet: "tsp"
        }
    }

    /// Silent payment outputs are always P2TR; this placeholder keeps the
    /// coin-selection fee math exact before the real script is derived.
    public static let sizingScriptPubKey = Data([0x51, 0x20]) + Data(repeating: 0, count: 32)
}
