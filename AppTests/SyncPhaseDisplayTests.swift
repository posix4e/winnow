@testable import WinnowApp
import XCTest

final class SyncPhaseDisplayTests: XCTestCase {
    func testFilterScanTextUsesLivePhaseInsteadOfStaleWalletSnapshot() {
        let scanned: UInt32 = 162_000
        let tip: UInt32 = 963_221
        let phase = AppModel.SyncPhase.filters(scanned: scanned, tip: tip)

        XCTAssertEqual(
            phase.filterScanText(fallbackScanned: 0, fallbackTip: 0),
            "block \(scanned.formatted()) of \(tip.formatted())"
        )
    }

    func testFilterScanTextClampsNextHeightAtTip() {
        let nextHeight: UInt32 = 963_222
        let tip: UInt32 = 963_221
        let phase = AppModel.SyncPhase.filters(scanned: nextHeight, tip: tip)

        XCTAssertEqual(
            phase.filterScanText(fallbackScanned: 0, fallbackTip: 0),
            "block \(tip.formatted()) of \(tip.formatted())"
        )
    }

    /// This asserted the fallback rendered the committed snapshot in every
    /// other phase, which was the defect rather than the contract: outside a
    /// running scan that snapshot is either zeroed or left over from a
    /// previous launch, and neither is this scan's position (#99).
    func testFilterScanTextGivesNoNumberOutsideAScan() {
        let phase = AppModel.SyncPhase.headers(synced: 100, tipEstimate: 200)

        XCTAssertNil(phase.filterScanText(fallbackScanned: 40, fallbackTip: 100))
    }

    func testFilterScanTextClampsCompletedSnapshotAfterSync() {
        let tip: UInt32 = 963_221
        let phase = AppModel.SyncPhase.synced

        XCTAssertEqual(
            phase.filterScanText(fallbackScanned: tip + 1, fallbackTip: tip),
            "block \(tip.formatted()) of \(tip.formatted())"
        )
    }
}

/// #99: the row must not report a number it does not have.
///
/// `status` is populated by `refresh()`, which is event-driven — none of its
/// call sites is the once-a-second phase poll. So on a fresh mainnet wallet
/// the ~8.5 minutes of header sync rendered whatever the last committed
/// snapshot said, which for a wallet that has never scanned is zeroed.
final class FilterScanRowHonestyTests: XCTestCase {
    func testNoRowWhileHeadersAreStillSyncing() {
        // The reported string, in the phase #87 did not cover.
        let phase = AppModel.SyncPhase.headers(synced: 40_000, tipEstimate: 963_221)
        XCTAssertNil(phase.filterScanText(fallbackScanned: 0, fallbackTip: 0),
                     "a wallet that has never scanned has no scan position")
    }

    func testNoRowWhileConnecting() {
        let phase = AppModel.SyncPhase.connecting(connected: 0, target: 4)
        XCTAssertNil(phase.filterScanText(fallbackScanned: 0, fallbackTip: 0))
    }

    func testNoRowWhenPeerDiscoveryFailed() {
        let phase = AppModel.SyncPhase.peerDiscoveryFailed
        XCTAssertNil(phase.filterScanText(fallbackScanned: 0, fallbackTip: 0))
    }

    func testNoRowWhenIdle() {
        // .idle means there is no stack at all, so nothing can be reported.
        XCTAssertNil(AppModel.SyncPhase.idle.filterScanText(fallbackScanned: 0, fallbackTip: 0))
    }

    /// A returning wallet mid-header-sync still must not present its last
    /// completed scan as current progress: nothing is scanning right now.
    func testNoRowForAStaleSnapshotDuringHeaders() {
        let phase = AppModel.SyncPhase.headers(synced: 900_000, tipEstimate: 963_221)
        XCTAssertNil(phase.filterScanText(fallbackScanned: 800_000, fallbackTip: 900_000))
    }

    /// The two phases that do have an honest number keep reporting it.
    func testLiveScanStillReports() {
        let phase = AppModel.SyncPhase.filters(scanned: 162_000, tip: 963_221)
        XCTAssertEqual(phase.filterScanText(fallbackScanned: 0, fallbackTip: 0),
                       "block \(UInt32(162_000).formatted()) of \(UInt32(963_221).formatted())")
    }

    func testSyncedStillReportsTheFinishedSnapshot() {
        let tip: UInt32 = 963_221
        XCTAssertEqual(AppModel.SyncPhase.synced.filterScanText(fallbackScanned: tip + 1, fallbackTip: tip),
                       "block \(tip.formatted()) of \(tip.formatted())")
    }

    /// A running scan with no tip yet is the same zero, one phase over.
    func testNoRowForAZeroTipEvenWhileScanning() {
        XCTAssertNil(AppModel.SyncPhase.filters(scanned: 0, tip: 0)
            .filterScanText(fallbackScanned: 0, fallbackTip: 0))
    }
}
