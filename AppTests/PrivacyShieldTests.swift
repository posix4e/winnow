@testable import WinnowApp
import SwiftUI
import UIKit
import XCTest

/// The privacy cover as installed, not as intended (invariant S1).
///
/// `AppPrivacyTests` pins `shouldObscureWallet(for:)`, which is a pure
/// function over `ScenePhase`. That the policy is right says nothing about
/// whether anything acts on it, and the acting is the part with the
/// interesting failure: `PrivacyShield` exists because a cover placed inside
/// the SwiftUI tree stays *behind* a presented sheet, so a recovery phrase on
/// screen would survive into the app-switcher snapshot with the cover politely
/// underneath it. Its answer is a separate `UIWindow` above `.alert`.
///
/// Nothing observed that window until now. These tests drive `setObscured`
/// and read UIKit back.
///
/// **What this cannot show.** That iOS's app-switcher snapshot actually
/// contains the cover. That is the platform's behaviour, not ours, and the
/// simulator does not expose the snapshot it records. The claim earned is that
/// an opaque, non-interactive window is installed above every application
/// presentation window while the scene is not active — which is the condition
/// the snapshot is taken under.
@MainActor
final class PrivacyShieldTests: XCTestCase {
    private let identifier = "appPrivacyCoverWindow"

    override func tearDown() {
        PrivacyShield.shared.setObscured(false)
        super.tearDown()
    }

    /// Every cover window attached to a scene, visible or not. `hide()` drops
    /// its own reference but a `UIWindow` stays attached until UIKit releases
    /// it, so a hidden one from an earlier test is still reachable here.
    private var allCoverWindows: [UIWindow] {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .filter { $0.accessibilityIdentifier == identifier }
    }

    /// The ones actually covering anything. Assertions about the shield's
    /// behaviour belong here: a hidden window obscures nothing, and counting
    /// it makes a passing test depend on which tests ran before it.
    private var coverWindows: [UIWindow] { allCoverWindows.filter { !$0.isHidden } }

    func testObscuringInstallsAVisibleCoverWindow() {
        PrivacyShield.shared.setObscured(false)
        XCTAssertTrue(coverWindows.isEmpty, "a cover was visible before the test obscured anything")
        PrivacyShield.shared.setObscured(true)
        let covers = coverWindows
        XCTAssertEqual(covers.count, 1, "expected exactly one cover window")
        let cover = try? XCTUnwrap(covers.first)
        XCTAssertEqual(cover?.isHidden, false, "the cover exists but is hidden, which covers nothing")
    }

    /// The reason this class exists rather than a `.fullScreenCover`. A sheet
    /// is hosted above its presenting view but inside the application's own
    /// window; only a higher window level is in front of it.
    func testTheCoverSitsAboveEveryApplicationWindow() {
        PrivacyShield.shared.setObscured(true)
        guard let cover = coverWindows.first else { return XCTFail("no cover window") }
        XCTAssertGreaterThan(cover.windowLevel, .alert,
                             "at or below .alert the cover renders behind presented sheets, "
                             + "which is exactly the case it was built for")
        let applicationWindows = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .filter { $0.accessibilityIdentifier != identifier }
        for window in applicationWindows {
            XCTAssertGreaterThan(cover.windowLevel, window.windowLevel,
                                 "an application window renders above the cover")
        }
    }

    func testTheCoverIsOpaqueAndInert() {
        PrivacyShield.shared.setObscured(true)
        guard let cover = coverWindows.first else { return XCTFail("no cover window") }
        XCTAssertNotNil(cover.backgroundColor, "a transparent cover shows the wallet through it")
        XCTAssertFalse(cover.isUserInteractionEnabled,
                       "the cover would swallow or forward taps meant for nothing")
        XCTAssertNotNil(cover.rootViewController, "the window has no content to draw")
    }

    func testUnobscuringRemovesTheCover() {
        PrivacyShield.shared.setObscured(true)
        XCTAssertFalse(coverWindows.isEmpty, "nothing to remove")
        PrivacyShield.shared.setObscured(false)
        XCTAssertTrue(coverWindows.isEmpty, "the wallet stays covered after returning to active")
    }

    /// Scene phase changes arrive repeatedly and in bursts; a shield that
    /// stacked a window per call would leak one for every backgrounding.
    func testRepeatedObscuringDoesNotStackWindows() {
        for _ in 0 ..< 5 { PrivacyShield.shared.setObscured(true) }
        XCTAssertEqual(coverWindows.count, 1, "one window per scene, not per call")
    }

    /// Scene phase flips on every incoming call, notification shade and app
    /// switch, so anything retained per cycle is retained thousands of times a
    /// day. This pins that cycling does not grow the window set without bound
    /// (S10), which counting only visible windows would never notice.
    func testCyclingDoesNotAccumulateWindows() {
        PrivacyShield.shared.setObscured(false)
        let before = allCoverWindows.count
        for _ in 0 ..< 20 {
            PrivacyShield.shared.setObscured(true)
            PrivacyShield.shared.setObscured(false)
        }
        let after = allCoverWindows.count
        XCTAssertLessThanOrEqual(after, before + 1,
                                 "twenty background cycles left \(after - before) extra cover "
                                 + "windows attached to the scene")
        XCTAssertTrue(coverWindows.isEmpty, "a cover is still visible after returning to active")
    }

    /// The policy and the mechanism, joined: the states `shouldObscureWallet`
    /// calls obscured must be the states that actually install a cover. Tested
    /// separately, both can be right while nothing connects them.
    func testEveryObscuredPhaseInstallsACover() {
        for phase in [ScenePhase.active, .inactive, .background] {
            PrivacyShield.shared.setObscured(shouldObscureWallet(for: phase))
            let visible = !coverWindows.isEmpty
            XCTAssertEqual(visible, shouldObscureWallet(for: phase),
                           "phase \(phase) disagrees with the cover it produced")
        }
    }
}
