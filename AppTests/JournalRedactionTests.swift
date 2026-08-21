@testable import WinnowApp
import XCTest

/// What may reach the E2E journal (epic #100, invariant S1).
///
/// `story-events.jsonl` is published as part of the story evidence, so its
/// contents have the same blast radius as the screenshots. The journal
/// documents itself as holding no mnemonics, private keys, entropy or MuSig2
/// secret nonces — but a field-name denylist only catches the mistakes someone
/// labelled honestly. A seed filed under `"note"` passes every name check ever
/// written.
///
/// These tests cover the value-level rules. The strongest of them compares
/// against the run's *actual* seed rather than a guess at what secrets look
/// like, which is why it has no false positives.
final class JournalRedactionTests: XCTestCase {
    private let pinnedHex = "000102030405060708090a0b0c0d0e0f"
    private let pinnedMnemonic = "abandon amount liar amount expire adjust cage candy arch gather drum buyer"

    private func mode() throws -> E2EMode {
        guard case let .active(mode) = E2EMode.resolve(environment: [
            "WINNOW_E2E": "1",
            "WINNOW_E2E_ENTROPY": pinnedHex,
            "WINNOW_E2E_RUN": "redaction-test",
        ]) else {
            throw XCTSkip("E2E mode did not activate")
        }
        return mode
    }

    // MARK: - Shape-based rules

    func testAMnemonicIsRecognisedWhateverItIsCalled() {
        XCTAssertTrue(E2EMode.looksSecret(pinnedMnemonic))
    }

    func testExtendedPrivateKeysAreRecognised() {
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        XCTAssertTrue(E2EMode.looksSecret(xprv))
        XCTAssertTrue(E2EMode.looksSecret("wallet restored from \(xprv) at height 1"),
                      "an extended private key embedded in prose is still a private key")
        XCTAssertTrue(E2EMode.looksSecret("tprv8ZgxMBicQKsPd"))
    }

    /// The journal legitimately carries txids, raw transactions and addresses.
    /// A rule that fired on those would be switched off within a week, so it
    /// must not fire on them.
    func testOrdinaryJournalMaterialIsNotFlagged() {
        let legitimate = [
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", // txid
            "0200000001aabbccdd00000000ffffffff0100e1f505000000001600140102030405", // raw tx
            "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
            "xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7",
            "12", "signet", "", "sync completed in 19.1 seconds",
        ]
        for value in legitimate {
            XCTAssertFalse(E2EMode.looksSecret(value), "false positive on: \(value)")
        }
    }

    /// A 12-word phrase that is not a valid BIP39 sentence is prose, not a
    /// seed, and must not be dropped.
    func testTwelveOrdinaryWordsAreNotAMnemonic() {
        XCTAssertFalse(E2EMode.looksSecret(
            "the quick brown fox jumps over the lazy dog and then some more"))
    }

    // MARK: - Comparison against this run's actual seed

    func testTheRunsOwnEntropyIsRecognised() throws {
        let mode = try mode()
        XCTAssertTrue(mode.carriesThisRunsSeed(pinnedHex))
        XCTAssertTrue(mode.carriesThisRunsSeed("seed=\(pinnedHex) height=1"),
                      "the seed embedded in a larger string is still the seed")
        XCTAssertTrue(mode.carriesThisRunsSeed(pinnedHex.uppercased()),
                      "case must not be a way around the check")
    }

    func testTheRunsOwnMnemonicIsRecognised() throws {
        let mode = try mode()
        XCTAssertTrue(mode.carriesThisRunsSeed(pinnedMnemonic))
        XCTAssertTrue(mode.carriesThisRunsSeed("restored: \(pinnedMnemonic)"))
    }

    func testUnrelatedValuesAreNotFlaggedAsTheRunsSeed() throws {
        let mode = try mode()
        for value in ["000102030405060708090a0b0c0d0e10", // one byte different
                      "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
                      "signet", ""] {
            XCTAssertFalse(mode.carriesThisRunsSeed(value), "false positive on: \(value)")
        }
    }

    /// Together the two rules cover what the journal's own documentation
    /// promises: a seed reaches the journal under no name at all.
    func testASeedUnderAnInnocentFieldNameIsCaughtByValue() throws {
        let mode = try mode()
        // "note" passes every field-name denylist.
        XCTAssertTrue(mode.carriesThisRunsSeed(pinnedHex) || E2EMode.looksSecret(pinnedMnemonic))
        XCTAssertTrue(E2EMode.looksSecret(pinnedMnemonic))
        XCTAssertTrue(mode.carriesThisRunsSeed(pinnedHex))
    }
}
