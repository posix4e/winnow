import Foundation

extension PeerPool {
    /// The strictest BIP133 `feefilter` among connected peers, in sat/vB
    /// (feefilter is sat/kvB). nil when no peer has sent one.
    public func feeFilterFloorSatPerVByte() async -> Double? {
        var floors: [Int64] = []
        for peer in connectedPeers() { // this extension method is already pool-isolated
            if let floor = await peer.feeFilter { floors.append(floor) }
        }
        guard let strictest = floors.max() else { return nil }
        return Double(strictest) / 1_000
    }
}
