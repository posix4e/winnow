@testable import WinnowApp
import BitcoinCore
import WalletCore
import XCTest

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
    /// Real shapes, not the word "secret": a valid BIP39 mnemonic and a real
    /// extended private key. A detector that only catches placeholder text
    /// would pass this suite and fail the case that matters.
    private let mnemonic = "abandon amount liar amount expire adjust cage candy arch gather drum buyer"
    private let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

    /// Every user-facing message produced from *externally supplied* text. If
    /// an error type starts interpolating something a user or a file can
    /// control, it belongs here.
    ///
    /// `VaultError.invalidDescriptor` is deliberately absent: it interpolates
    /// too, but its payload is contractually a developer-authored literal
    /// naming the shape that failed, and every caller passes one. Planting a
    /// secret in it would test a call that cannot happen; the contract is
    /// stated at the case instead.
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
        for (label, text) in messages(embedding: mnemonic) {
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
        XCTAssertTrue(E2EMode.looksSecret(mnemonic), "the bare phrase")
        XCTAssertTrue(E2EMode.looksSecret("note: \(mnemonic)"), "prefixed")
        XCTAssertTrue(E2EMode.looksSecret("\(mnemonic) — written down"), "suffixed")
        XCTAssertTrue(E2EMode.looksSecret("wallet \(mnemonic) restored at height 1"), "embedded")
    }

    /// The control that keeps the window scan honest. Ordinary prose of the
    /// same length must not trip it, or redaction would swallow every message.
    func testOrdinaryProseIsNotMistakenForAPhrase() {
        XCTAssertFalse(E2EMode.looksSecret(
            "the wallet could not open because the file on disk was written by a newer build than this one here"))
        XCTAssertFalse(E2EMode.looksSecret("abandon abandon abandon"), "too few words to be a phrase")
    }
}
