@testable import WinnowApp
import Foundation
import UIKit
import XCTest

/// Transactions have to be gettable out of the app.
///
/// A txid is 64 hex characters and does not fit a list row, so rows abbreviate
/// it. Abbreviated text with only `textSelection` cannot be copied whole —
/// selecting it yields the ellipsis, not the identifier — so the transaction
/// list displayed a value that could not actually be obtained. What is shown
/// is a summary; what is copied must always be the whole thing.
@MainActor
final class CopyableIdentifierTests: XCTestCase {
    private let txid = String(repeating: "ab", count: 32)

    override func tearDown() {
        UIPasteboard.general.items = []
        super.tearDown()
    }

    /// The abbreviation is presentation only.
    func testAbbreviationNeverReachesTheClipboard() {
        ClipboardPolicy.interchange.apply(txid)
        XCTAssertEqual(UIPasteboard.general.string, txid)
        XCTAssertEqual(txid.count, 64, "a full txid, not a preview of one")
        XCTAssertFalse(try XCTUnwrap(UIPasteboard.general.string).contains("…"))
    }

    /// A txid is already public on the chain, so it travels under the
    /// interchange policy rather than the recovery-phrase one — crossing to a
    /// desktop is the entire point of copying it.
    func testTransactionsUseTheInterchangePolicy() {
        XCTAssertFalse(ClipboardPolicy.interchange.localOnly,
                       "copying a txid to a desktop is the workflow")
        XCTAssertGreaterThan(ClipboardPolicy.interchange.lifetime, 0,
                            "it still expires rather than sitting there")
    }

    /// …and emphatically not the seed policy, which exists for material that
    /// must never leave the device.
    func testTransactionsDoNotBorrowTheRecoveryPhrasePolicy() {
        XCTAssertNotEqual(ClipboardPolicy.interchange, ClipboardPolicy.recoveryPhrase)
        XCTAssertTrue(ClipboardPolicy.recoveryPhrase.localOnly)
    }

    /// The raw transaction is hex and round-trips as text — the point being
    /// that a user can paste it into a node or explorer that accepts one.
    func testRawTransactionHexCopiesWhole() {
        let raw = String(repeating: "0a", count: 250)
        ClipboardPolicy.interchange.apply(raw)
        XCTAssertEqual(UIPasteboard.general.string, raw)
        XCTAssertEqual(UIPasteboard.general.string?.count, 500)
    }
}
