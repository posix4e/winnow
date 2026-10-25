@testable import WinnowApp
import Foundation
import UIKit
import XCTest

/// Copy policies and complete text delivery, using a disposable pasteboard.
@MainActor
final class ClipboardPolicyTests: XCTestCase {
    func testRecoveryPhraseNeverLeavesTheDevice() {
        XCTAssertTrue(ClipboardPolicy.recoveryPhrase.localOnly)
        XCTAssertEqual(ClipboardPolicy.recoveryPhrase.lifetime, 120)
    }

    func testInterchangeMayCrossDevicesButStillExpires() {
        XCTAssertFalse(ClipboardPolicy.interchange.localOnly)
        XCTAssertGreaterThan(ClipboardPolicy.interchange.lifetime, 0)
        XCTAssertLessThanOrEqual(ClipboardPolicy.interchange.lifetime, 600)
    }

    func testOptionsCarryLocalOnlyAndAnExpiryInTheFuture() throws {
        for policy in [ClipboardPolicy.recoveryPhrase, .interchange] {
            let options = policy.options
            XCTAssertEqual(try XCTUnwrap(options[.localOnly] as? Bool), policy.localOnly)

            let expiry = try XCTUnwrap(options[.expirationDate] as? Date)
            let seconds = expiry.timeIntervalSinceNow
            XCTAssertGreaterThan(seconds, 0)
            XCTAssertLessThanOrEqual(seconds, policy.lifetime + 5)
        }
    }

    func testCopyPreservesFullTextAndReplacesPreviousContents() {
        let pasteboard = UIPasteboard.withUniqueName()
        defer { UIPasteboard.remove(withName: pasteboard.name) }
        pasteboard.items = [["public.utf8-plain-text": "old item"],
                            ["public.utf8-plain-text": "another old item"]]

        let copies: [(ClipboardPolicy, String)] = [
            (.interchange, "tr(xpubA/<0;1>/*)"),
            (.interchange, String(repeating: "ab", count: 32)), // Full transaction ID.
            (.interchange, String(repeating: "0a", count: 250)), // Raw transaction hex.
            (.recoveryPhrase, "test recovery phrase"),
        ]
        for (policy, text) in copies {
            policy.apply(text, to: pasteboard)
            XCTAssertEqual(pasteboard.string, text)
            XCTAssertEqual(pasteboard.numberOfItems, 1)
        }
    }
}
