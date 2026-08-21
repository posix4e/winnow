@testable import WinnowApp
import UIKit
import XCTest

/// Clipboard handoff policy (epic #100, invariant S1).
///
/// The clipboard is the one place wallet material sits outside the app's
/// control, and iOS syncs the general pasteboard to a user's other Apple
/// devices unless told not to. Before this, only the recovery-phrase button
/// set an expiry and kept the item on-device; descriptors, PSBTs and addresses
/// went to the pasteboard bare, with no expiry and free to sync.
///
/// The two policies differ deliberately, and the difference is asserted here
/// so that a later change which "unifies" them has to argue with a test.
@MainActor
final class ClipboardPolicyTests: XCTestCase {
    // MARK: - The policies themselves

    /// Recovery words have no legitimate reason to cross to another device.
    func testRecoveryPhraseNeverLeavesTheDevice() {
        XCTAssertTrue(ClipboardPolicy.recoveryPhrase.localOnly)
        XCTAssertEqual(ClipboardPolicy.recoveryPhrase.lifetime, 120)
    }

    /// A watch-only descriptor is meant to be pasted into desktop software and
    /// a PSBT travels between cosigners, so this one may cross devices. The
    /// accepted risk is Universal Clipboard, which is why it still expires.
    func testInterchangeMayCrossDevicesButStillExpires() {
        XCTAssertFalse(ClipboardPolicy.interchange.localOnly)
        XCTAssertGreaterThan(ClipboardPolicy.interchange.lifetime, 0,
                             "interchange material must not sit on the pasteboard indefinitely")
        XCTAssertLessThanOrEqual(ClipboardPolicy.interchange.lifetime, 600,
                                 "an expiry long enough to be meaningless is not an expiry")
    }

    /// The distinction is the point: a seed and a descriptor are not the same
    /// kind of secret and must not share one policy.
    func testTheTwoPoliciesAreDistinct() {
        XCTAssertNotEqual(ClipboardPolicy.recoveryPhrase, ClipboardPolicy.interchange)
        XCTAssertTrue(ClipboardPolicy.recoveryPhrase.localOnly)
        XCTAssertFalse(ClipboardPolicy.interchange.localOnly)
    }

    // MARK: - What reaches the pasteboard

    func testOptionsCarryLocalOnlyAndAnExpiryInTheFuture() throws {
        for policy in [ClipboardPolicy.recoveryPhrase, .interchange] {
            let options = policy.options
            let localOnly = try XCTUnwrap(options[.localOnly] as? Bool)
            XCTAssertEqual(localOnly, policy.localOnly)

            let expiry = try XCTUnwrap(options[.expirationDate] as? Date)
            let seconds = expiry.timeIntervalSinceNow
            XCTAssertGreaterThan(seconds, 0, "the expiry must be in the future")
            XCTAssertLessThanOrEqual(seconds, policy.lifetime + 5,
                                     "the expiry must match the policy's lifetime")
        }
    }

    /// Applying a policy really does place the text, checked against a scratch
    /// pasteboard so the developer's own clipboard is untouched.
    func testApplyPlacesTheTextOnThePasteboard() {
        let pasteboard = UIPasteboard.withUniqueName()
        defer { UIPasteboard.remove(withName: pasteboard.name) }

        ClipboardPolicy.interchange.apply("tr(musig(a,b))/<0;1>/*", to: pasteboard)
        XCTAssertEqual(pasteboard.string, "tr(musig(a,b))/<0;1>/*")
    }

    func testApplyReplacesPreviousContents() {
        let pasteboard = UIPasteboard.withUniqueName()
        defer { UIPasteboard.remove(withName: pasteboard.name) }

        ClipboardPolicy.interchange.apply("first", to: pasteboard)
        ClipboardPolicy.recoveryPhrase.apply("second", to: pasteboard)
        XCTAssertEqual(pasteboard.string, "second")
        XCTAssertEqual(pasteboard.numberOfItems, 1,
                       "a copy replaces the item rather than accumulating")
    }
}
