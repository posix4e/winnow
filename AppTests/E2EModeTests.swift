@testable import WinnowApp
import WalletCore
import XCTest

/// `E2EMode`, from all three sides it is asked about.
///
/// It decides whether a capture run may start at all (pinned entropy or
/// nothing), and it owns `looksSecret` and `carriesThisRunsSeed`, the
/// value-level checks that decide what may reach the published story journal
/// and, since SEC-027, what an error message is allowed to repeat back.
///
/// The three classes keep their names: docs/security/findings.md records
/// `-only-testing:WinnowAppTests/E2EEntropyPinningTests` and
/// `…/JournalRedactionTests` as run evidence for SEC-006 and SEC-015, and
/// cites `ErrorSurfaceTests` for SEC-027 and SEC-028.

/// The canonical incrementing-byte test vector the harness pins, and the BIP39
/// sentence it decodes to. Real shapes, not the word "secret": a detector that
/// only catches placeholder text would pass every suite here and fail the case
/// that matters. All three classes below plant the same material, so it is
/// declared once.
private let pinnedHex = "000102030405060708090a0b0c0d0e0f"
private let pinnedMnemonic = "abandon amount liar amount expire adjust cage candy arch gather drum buyer"
private let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

// MARK: - E2EEntropyPinningTests

/// A capture run must never generate a real seed (epic #100, invariant S1,
/// finding SEC-006).
///
/// The E2E screenshots include the recovery-phrase screen, and those images
/// are committed to a public repository and published to the site. That is
/// safe only because the harness pins a known public test vector. With no
/// pinned entropy the app fell through to ordinary onboarding and generated a
/// real seed, so a capture run that merely forgot the variable would have
/// published live key material — silently, and irreversibly once pushed.
///
/// Every launcher passes the variable today, so this can only be reached by
/// mistake. That is precisely when failing loudly beats carrying on.
final class E2EEntropyPinningTests: XCTestCase {
    private func resolve(_ environment: [String: String]) -> E2EMode.Resolution {
        E2EMode.resolve(environment: environment)
    }

    // MARK: Inactive

    func testAbsentFlagIsInactive() {
        guard case .inactive = resolve([:]) else {
            return XCTFail("an empty environment must not activate E2E mode")
        }
    }

    func testNonOneFlagIsInactive() {
        guard case .inactive = resolve(["WINNOW_E2E": "0", "WINNOW_E2E_ENTROPY": pinnedHex]) else {
            return XCTFail("only WINNOW_E2E=1 activates E2E mode")
        }
    }

    // MARK: Active with pinned material

    func testPinnedEntropyActivates() {
        guard case let .active(mode) = resolve(["WINNOW_E2E": "1", "WINNOW_E2E_ENTROPY": pinnedHex]) else {
            return XCTFail("pinned entropy must activate E2E mode")
        }
        XCTAssertEqual(mode.entropy?.count, 16)
    }

    func testPinnedMnemonicActivates() {
        guard case let .active(mode) = resolve(["WINNOW_E2E": "1",
                                                "WINNOW_E2E_MNEMONIC": pinnedMnemonic]) else {
            return XCTFail("a pinned mnemonic must activate E2E mode")
        }
        // The mnemonic decodes to the same canonical vector as the hex form.
        XCTAssertEqual(mode.entropy?.map { String(format: "%02x", $0) }.joined(), pinnedHex)
    }

    // MARK: Fail closed

    /// The case that motivated the finding: the flag is set and nothing pins
    /// the seed.
    func testActiveWithoutAnyPinnedEntropyIsRefused() {
        guard case .missingPinnedEntropy = resolve(["WINNOW_E2E": "1", "WINNOW_E2E_RUN": "backup"]) else {
            return XCTFail("an E2E run with no pinned entropy must be refused, not generated")
        }
    }

    /// A value that was meant to be pinned but cannot be read is the same kind
    /// of mistake — not a licence to generate one.
    func testUnreadableEntropyIsRefused() {
        for bad in ["", "zzzz", "0001020304050607080", "not-hex-at-all"] {
            guard case .missingPinnedEntropy = resolve(["WINNOW_E2E": "1", "WINNOW_E2E_ENTROPY": bad]) else {
                XCTFail("unreadable entropy \(bad.isEmpty ? "<empty>" : bad) must be refused")
                continue
            }
        }
    }

    func testInvalidMnemonicIsRefused() {
        guard case .missingPinnedEntropy = resolve(["WINNOW_E2E": "1",
                                                    "WINNOW_E2E_MNEMONIC": "not a real mnemonic at all"]) else {
            return XCTFail("an invalid mnemonic must be refused rather than generating a seed")
        }
    }

    // MARK: The runner's controls

    /// The story's control file, peer target and sync interval are read
    /// from the launch environment; a value that makes no sense is ignored
    /// rather than applied.
    func testTheRunnerControlsAreParsed() throws {
        guard case let .active(mode) = resolve(["WINNOW_E2E": "1", "WINNOW_E2E_ENTROPY": pinnedHex,
                                               "WINNOW_E2E_CONTROL_FILE": "/tmp/winnow-e2e-control.json",
                                               "WINNOW_E2E_PEER_COUNT": "1",
                                               "WINNOW_E2E_SYNC_INTERVAL": "10"]) else {
            return XCTFail("pinned entropy must activate E2E mode")
        }
        XCTAssertEqual(mode.controlFile?.path, "/tmp/winnow-e2e-control.json")
        XCTAssertEqual(mode.peerCount, 1)
        XCTAssertEqual(mode.syncInterval, .seconds(10))
        guard case let .active(unusable) = resolve(["WINNOW_E2E": "1", "WINNOW_E2E_ENTROPY": pinnedHex,
                                                   "WINNOW_E2E_PEER_COUNT": "0",
                                                   "WINNOW_E2E_SYNC_INTERVAL": "soon"]) else {
            return XCTFail("pinned entropy must activate E2E mode")
        }
        XCTAssertNil(unusable.controlFile)
        XCTAssertNil(unusable.peerCount)
        XCTAssertNil(unusable.syncInterval)
        XCTAssertNil(unusable.control(), "no control file, nothing to read")
    }

    /// The control file is read when it is needed, so a rewrite by the
    /// runner is what the next paste or refresh sees, and a file that is gone
    /// or damaged reads as nothing rather than as stale text.
    func testTheControlFileIsReadOnEachCall() throws {
        let file = FileManager.default.temporaryDirectory
            .appending(path: "winnow-e2e-control-test-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: file) }
        guard case let .active(mode) = resolve(["WINNOW_E2E": "1", "WINNOW_E2E_ENTROPY": pinnedHex,
                                               "WINNOW_E2E_CONTROL_FILE": file.path]) else {
            return XCTFail("pinned entropy must activate E2E mode")
        }
        XCTAssertNil(mode.control(), "the file does not exist yet")
        try Data(#"{"clipboard":"first"}"#.utf8).write(to: file)
        XCTAssertEqual(mode.control()?.clipboard, "first")
        try Data(#"{"clipboard":"second"}"#.utf8).write(to: file)
        XCTAssertEqual(mode.control()?.clipboard, "second")
        try Data("not json".utf8).write(to: file)
        XCTAssertNil(mode.control())
    }

    /// The other launch variables are irrelevant to the rule: nothing else
    /// substitutes for pinned entropy.
    func testOtherVariablesDoNotSubstituteForEntropy() {
        let environment = [
            "WINNOW_E2E": "1",
            "WINNOW_E2E_RUN": "main",
            "WINNOW_E2E_NETWORK": "signet",
            "WINNOW_STORY_PERSONA": "alex",
            "WINNOW_E2E_DEVICE_AUTH": "1",
        ]
        guard case .missingPinnedEntropy = resolve(environment) else {
            return XCTFail("a fully configured run without entropy must still be refused")
        }
    }
}

// MARK: - JournalRedactionTests

/// What may reach the E2E journal (epic #100, invariant S1).
///
/// `story-events.jsonl` is published as part of the story evidence, so its
/// contents have the same blast radius as the screenshots. The journal
/// documents itself as holding no mnemonics, private keys or entropy — but
/// a field-name denylist only catches the mistakes someone
/// labelled honestly. A seed filed under `"note"` passes every name check ever
/// written.
///
/// These tests cover the value-level rules. The strongest of them compares
/// against the run's *actual* seed rather than a guess at what secrets look
/// like, which is why it has no false positives.
final class JournalRedactionTests: XCTestCase {
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

    // MARK: Shape-based rules

    func testAMnemonicIsRecognisedWhateverItIsCalled() {
        XCTAssertTrue(E2EMode.looksSecret(pinnedMnemonic))
    }

    func testExtendedPrivateKeysAreRecognised() {
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

    // MARK: Comparison against this run's actual seed

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

// MARK: - ErrorSurfaceTests

/// What an error message is allowed to repeat back (invariant S1).
///
/// S1 asks for "error and OS-log inspection". The OS-log half is nearly empty
/// by construction: the production sources contain no `os.Logger`, `os_log`,
/// `NSLog` or `print`, so first-party code writes nothing to the system log at
/// all. That leaves the error text itself, which is the surface users actually
/// see — on screen, in a screenshot, pasted into a bug report.
///
/// The risk is not that we log secrets deliberately. It is that an error
/// echoes whatever it was handed, and what a user hands a descriptor field is
/// sometimes their recovery phrase. `E2EMode.looksSecret` already decides this
/// question by value for the story journal, with false-positive controls; the
/// same judgement applies here.
final class ErrorSurfaceTests: XCTestCase {
    /// Every user-facing message produced from *externally supplied* text. If
    /// an error type starts interpolating something a user or a file can
    /// control, it belongs here.
    private func messages(embedding secret: String) -> [(label: String, text: String)] {
        [
            ("WalletError.invalidDescriptor",
             WalletError.invalidDescriptor(secret).errorDescription ?? ""),
            ("AddressError.invalidAddress",
             AddressError.invalidAddress(secret).errorDescription ?? ""),
            ("AddressError.wrongNetwork",
             AddressError.wrongNetwork(secret).errorDescription ?? ""),
        ]
    }

    func testNoErrorMessageRepeatsARecoveryPhrase() {
        for (label, text) in messages(embedding: pinnedMnemonic) {
            XCTAssertFalse(E2EMode.looksSecret(text),
                           "\(label) put a recovery phrase in a message the user is shown: \(text.prefix(120))")
        }
    }

    func testNoErrorMessageRepeatsAnExtendedPrivateKey() {
        for (label, text) in messages(embedding: xprv) {
            XCTAssertFalse(E2EMode.looksSecret(text),
                           "\(label) put an extended private key in a message the user is shown")
        }
    }

    /// The control. These errors must still say something useful about what
    /// went wrong, or "redact everything" would pass while making the app
    /// unusable.
    func testErrorsStillDescribeTheProblem() {
        for (label, text) in messages(embedding: "tr(not-a-real-key)") {
            XCTAssertFalse(text.isEmpty, "\(label) produced no message at all")
            XCTAssertGreaterThan(text.count, 15, "\(label) message is too terse to act on: \(text)")
        }
    }

    /// `looksSecret` caught an extended private key inside prose but required
    /// a mnemonic to be the entire string, so anything with a prefix — a note,
    /// a label, an error message — slipped past. That asymmetry favoured the
    /// less dangerous of the two: an xprv derives one account, a recovery
    /// phrase is the whole backup.
    func testARecoveryPhraseIsFoundInsideALongerString() {
        XCTAssertTrue(E2EMode.looksSecret(pinnedMnemonic), "the bare phrase")
        XCTAssertTrue(E2EMode.looksSecret("note: \(pinnedMnemonic)"), "prefixed")
        XCTAssertTrue(E2EMode.looksSecret("\(pinnedMnemonic) — written down"), "suffixed")
        XCTAssertTrue(E2EMode.looksSecret("wallet \(pinnedMnemonic) restored at height 1"), "embedded")
    }

    /// The control that keeps the window scan honest. Ordinary prose of the
    /// same length must not trip it, or redaction would swallow every message.
    func testOrdinaryProseIsNotMistakenForAPhrase() {
        XCTAssertFalse(E2EMode.looksSecret(
            "the wallet could not open because the file on disk was written by a newer build than this one here"))
        XCTAssertFalse(E2EMode.looksSecret("abandon abandon abandon"), "too few words to be a phrase")
    }
}
