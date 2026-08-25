@testable import WinnowApp
import XCTest

/// The #151 decision, pinned: a send built while the header chain may lag the
/// network proceeds, and the review screen says what the locktime will
/// disclose. The alternative behaviours the issue listed — refusing to send,
/// or trusting a peer-advertised height — were considered and not taken:
/// refusal is worst for the user who needs to spend now, and a peer height
/// that must not exceed the real tip is exactly the trust the builder
/// deliberately avoids.
final class LocktimeLagNoticeTests: XCTestCase {
    /// The policy over every phase. `.filters` is deliberately on the quiet
    /// side: headers are at the network tip by then and only the scan trails,
    /// so the locktime is already drawn from Core's own distribution.
    func testEveryPhaseDeclaresWhetherTheTipMayLag() {
        XCTAssertTrue(AppModel.SyncPhase.idle.headerTipMayLagNetwork)
        XCTAssertTrue(AppModel.SyncPhase.connecting(connected: 1, target: 3).headerTipMayLagNetwork)
        XCTAssertTrue(AppModel.SyncPhase.headers(synced: 100, tipEstimate: 900).headerTipMayLagNetwork)
        XCTAssertTrue(AppModel.SyncPhase.peerDiscoveryFailed.headerTipMayLagNetwork)
        XCTAssertFalse(AppModel.SyncPhase.filters(scanned: 10, tip: 900).headerTipMayLagNetwork)
        XCTAssertFalse(AppModel.SyncPhase.synced.headerTipMayLagNetwork)
    }

    /// Direct constructions describe an ordinary synced send unless they say
    /// otherwise — the same convention every existing SendPreview test relies
    /// on to stay silent about concerns it is not testing.
    func testThePreviewDefaultsToNoLag() {
        let preview = AppModel.SendPreview(
            destination: "tb1q", payments: [], feeRateSatPerVByte: 1, fee: 100,
            changeAmount: nil, inputCount: 1, selectedOutpoints: [], change: nil)
        XCTAssertFalse(preview.locktimeLagsTip)
    }

    /// The flag is review-surface state, not authorization state: two previews
    /// differing only in the lag flag authorize the same transactions, because
    /// the locktime the wallet stamps is the same either way — the flag only
    /// changes what the user was told.
    func testTheLagFlagDoesNotChangeWhatIsAuthorized() {
        var preview = AppModel.SendPreview(
            destination: "tb1q", payments: [], feeRateSatPerVByte: 1, fee: 100,
            changeAmount: nil, inputCount: 0, selectedOutpoints: [], change: nil)
        var lagged = preview
        lagged.locktimeLagsTip = true
        XCTAssertNotEqual(preview, lagged, "the flag must be part of the reviewed value")
        preview.locktimeLagsTip = true
        XCTAssertEqual(preview, lagged)
    }
}
