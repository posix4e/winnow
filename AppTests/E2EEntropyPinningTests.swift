@testable import WinnowApp
import XCTest

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
    /// The canonical incrementing-byte test vector the harness pins.
    private let pinnedHex = "000102030405060708090a0b0c0d0e0f"
    private let pinnedMnemonic = "abandon amount liar amount expire adjust cage candy arch gather drum buyer"

    private func resolve(_ environment: [String: String]) -> E2EMode.Resolution {
        E2EMode.resolve(environment: environment)
    }

    // MARK: - Inactive

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

    // MARK: - Active with pinned material

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

    // MARK: - Fail closed

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
