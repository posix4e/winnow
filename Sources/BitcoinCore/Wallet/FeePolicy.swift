import Foundation

/// Feerate resolution (docs/write-side.md §4; the read-side names the
/// blindness as weakness 4). Resolution order, strongest first:
///
/// 1. an explicit **user override** (sat/vB);
/// 2. the **median feerate observed** from the wallet's own recently confirmed
///    transactions (the only feerates a filter-only client can compute exactly,
///    since it knows all input amounts);
/// 3. conservative **static presets** per priority;
///
/// …with the result always clamped from below by the peers' BIP133 `feefilter`
/// floor (the minimum a transaction must pay to relay at all).
public enum FeePolicy {
    public enum Priority: String, CaseIterable, Sendable {
        case low, medium, high

        /// Conservative static presets (sat/vB), used when nothing is observed.
        /// Deliberately above typical minima — a mempool-blind wallet must
        /// overpay rather than stall.
        public var satPerVByte: Double {
            switch self {
            case .low: 2
            case .medium: 5
            case .high: 12
            }
        }
    }

    /// Resolves the feerate to use (sat/vB). See the type doc for the order.
    public static func resolve(priority: Priority = .medium, override: Double? = nil,
                               observed: [Double] = [], floorSatPerVByte: Double? = nil) -> Double {
        let base = override ?? median(observed) ?? priority.satPerVByte
        guard let floorSatPerVByte else { return base }
        return max(base, floorSatPerVByte)
    }

    /// Median of the observed samples (nil when empty).
    public static func median(_ samples: [Double]) -> Double? {
        guard !samples.isEmpty else { return nil }
        let sorted = samples.sorted()
        let middle = sorted.count / 2
        return sorted.count % 2 == 1 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2
    }
}

/// Consensus monetary range used at wallet authorization boundaries.
public enum BitcoinAmount {
    /// 21 million BTC in satoshis (`MAX_MONEY` in Bitcoin Core).
    public static let maximum: Int64 = 2_100_000_000_000_000
}
