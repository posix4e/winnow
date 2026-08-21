# Security findings register

This public register contains fixed findings and sanitized open risks. Details
that would enable exploitation before a fix belong in a private GitHub security
advisory, not here.

| ID | Severity | Invariant | Status | Summary | Evidence |
|---|---|---|---|---|---|
| SEC-001 | Medium | S7, S10 | Fixed on `codex/security-hardening-100-phase0` | PSBT import trusted attacker-controlled CompactSize values when converting to native integers and had no document/map budget. A malicious cosigning document could terminate the importing process. Raw and Base64 sizes, map keys/pairs, input/output counts, and fixed-width known fields are now bounded and validated before use. | `PSBTTests.hostileLengths`; targeted AddressSanitizer run; full 311-test run; iOS simulator build |
| SEC-002 | Low | S12 | Fixed on `codex/security-hardening-100-phase0` | The application manifest pinned the secp package by version, but `.gitignore` excluded the resolved source revision. `Package.resolved` now records the audited dependency commit. | `Package.resolved`; clean package resolution and app build |
| SEC-003 | High | S2 | Fixed on `codex/security-send-review-binding` | Payment and fee-replacement reviews were not bound to every live authorization input or late async response. Reviews are now invalidated on edits, obsolete responses are discarded, and signing uses the immutable request that produced the visible review. | `SendReviewBindingTests`; 310 package tests; 7 iOS app tests; draft PR #102 |
| SEC-004 | High | S2, S8, S9 | Fixed on `codex/security-vault-psbt-validation` | Vault review treated untrusted PSBT output derivation metadata as proof that an output was change and did not centrally validate the known input amount/script and descriptor policy before each action. Review now derives ownership from actual descriptor scripts and rejects unknown, duplicated, altered, non-output-committing, or economically invalid proposals before display, signing, finalization, or broadcast. | `VaultFlowTests.vaultSpendReview`; 312 package tests; 6 vault tests under AddressSanitizer; clean iOS app test build |
| SEC-005 | Medium | S12 | Open on `codex/security-ci-provenance` | The `package-tests` job in `ci.yml` runs on the owner's persistent self-hosted macOS runner and is triggered by `pull_request` on a public repository. Once a fork pull request is approved, its code executes on a long-lived machine that reaches the signet node over the tailnet, so the exposure is credential and lateral-movement risk on a non-ephemeral host rather than a compromised build result. Every job added by the CI/provenance lane correctly uses ephemeral `macos-latest`; this is the one pre-existing path that still does not. | `.github/workflows/ci.yml` job `package-tests` at `2bf7a65`; `site.yml` already carries the same-repository guard this job needs |
| SEC-006 | Low | S1 | Open on `codex/security-hardening-integration` | `E2EMode.current` accepts a capture run with no pinned entropy: when `WINNOW_E2E=1` but neither `WINNOW_E2E_ENTROPY` nor `WINNOW_E2E_MNEMONIC` is set it leaves entropy nil and falls through to ordinary onboarding, which generates a real seed. Both current call sites pass the pinned constant, so no published artifact is affected. The risk is a later capture run that omits the variable silently producing screenshots of a genuine recovery phrase, which are then committed to a public repository and published to the site. Failure is silent and the blast radius is the whole wallet. | `Sources/WinnowApp/E2EMode.swift:59-67`; call sites `UITests/WinnowAppUITests.swift:82` and `:575`; published captures confirmed to show only the pinned public vector |

## Open release risks (not vulnerability claims)

These are gaps in required evidence and remain release-blocking under epic
#100 even when no concrete exploit has been established:

- S1: release-artifact secret containment is now evidenced (E2E exclusion with a
  proven negative control, and a canary-controlled secret scan of the release
  archive). iOS Keychain, device-authentication, clipboard, and
  screenshot/background checks remain incomplete, and `SEC-006` is open.
- S2: the fixed send/RBF and vault boundaries still need UI automation,
  double-submit/interruption tests, and an independent review.
- S4: MuSig2 nonce interruption/replay/concurrency coverage is incomplete.
- S5/S10: sanitizer and sustained fuzz evidence now exists (ThreadSanitizer over
  the full suite, and 225,000 AddressSanitizer plus 225,000 ThreadSanitizer
  deterministic fuzz cases in CI). Hostile-peer, reorg, and long-duration
  resource evidence remains incomplete.
- S12: Actions are pinned to immutable commits, an SPDX dependency SBOM and
  build provenance are produced, workflow permissions and signing-secret scope
  were audited, and the release binary was feature-scanned. `SEC-005`,
  independent review, and the written limited-mainnet gate remain open.

## Validation record

| Date | Source | Command | Result |
|---|---|---|---|
| 2026-08-21 | `98d9056` baseline | `swift test` | 310 tests / 60 suites passed; environment-gated suites skipped |
| 2026-08-21 | Phase 0 working tree | `swift test --filter PSBTTests` | 6 tests / 1 suite passed |
| 2026-08-21 | Phase 0 working tree | `swift test --sanitize=address --filter PSBTTests` | 6 tests / 1 suite passed under AddressSanitizer |
| 2026-08-21 | Phase 0 working tree | `swift test` | 311 tests / 60 suites passed; environment-gated suites skipped |
| 2026-08-21 | Phase 0 working tree | `xcodegen && xcodebuild ... generic/platform=iOS Simulator ... build` | Build succeeded for arm64 and x86_64 simulator |
| 2026-08-21 | Vault-validation stack | `swift test` | 312 tests / 60 suites passed; environment-gated suites skipped |
| 2026-08-21 | Vault-validation stack | `swift test --sanitize=address --filter VaultFlowTests` | 6 tests / 1 suite passed under AddressSanitizer |
| 2026-08-21 | Vault-validation stack | clean DerivedData `xcodebuild ... -only-testing:WinnowAppTests test` | App compiled; 4 iOS app tests passed |
| 2026-08-21 | `9c07d37` verification worktree | `swift test --sanitize thread` | 339 tests / 61 suites passed under ThreadSanitizer; zero data-race reports |
| 2026-08-21 | `9c07d37` verification worktree | clean-DerivedData `xcodebuild ... -destination 'generic/platform=iOS Simulator' build` | Build succeeded; zero warnings in the app target |
| 2026-08-21 | `9c07d37` verification worktree | clean-DerivedData `xcodebuild test ... -only-testing:WinnowAppTests` | 22 XCTest cases passed, 0 failures, plus the `App privacy cover` Swift test |
| 2026-08-21 | `9c07d37` verification worktree | `xcodebuild ... -destination 'generic/platform=iOS' archive` unsigned | Archive succeeded; `lipo -archs` reports arm64, a real device binary |
| 2026-08-21 | `9c07d37` verification worktree | `scripts/verify-release-e2e-exclusion <archive>.app` | Passed. Negative control: the same script run against the Debug build fails on all five forbidden markers, so the pass is discriminating |
| 2026-08-21 | `9c07d37` verification worktree | canary-controlled secret scan of the release archive | Clean against 25 test mnemonics, 359 test extended keys, 70 candidate word runs and six generic secret shapes, with positive, canary and planted-secret controls all proven live |
| 2026-08-21 | `2bf7a65` CI/provenance lane | Actions run 32516855373, sustained sanitizer matrix | 225,000 deterministic cases under AddressSanitizer and 225,000 under ThreadSanitizer passed |
| 2026-08-21 | `2bf7a65` CI/provenance lane | workflow secret-scope and permission re-audit | Six of seven prior findings closed: signing secrets are step-scoped, `contents: write` is isolated to a publish job, all ten checkouts set `persist-credentials: false`, `ci.yml` declares least privilege, and artifact retention is bounded. The seventh is `SEC-005` |
| 2026-08-21 | `15c9c25` + S4 suite | `swift test` | 347 tests / 62 suites passed (339 baseline plus 8 MuSig2 session-safety tests) |
| 2026-08-21 | `15c9c25` + S4 suite | `swift test --sanitize thread` | 347 tests / 62 suites passed under ThreadSanitizer; zero data-race reports |
| 2026-08-21 | S4 suite, mutation 1 | `partialSign` nonce-zeroing `defer` removed, then `swift test --filter MuSig2SessionSafetyTests` | 4 tests failed with 7 issues, including a second message signed with an already-used nonce. Confirms the suite detects the catastrophic case rather than passing vacuously |
| 2026-08-21 | S4 suite, mutation 2 | `partialSign` signer-binding guard removed, then same filter | 2 tests failed; one cosigner's nonce was accepted for another cosigner's key. Implementation restored pristine after both mutations |
| 2026-08-21 | `74290ab` + S3 suites | `swift test` | 363 tests / 64 suites passed (16 new cosigner-identity and vault-draft tests) |
| 2026-08-21 | `74290ab` + S3 suites | `swift test --sanitize address --filter` on the three new suites | 24 tests / 3 suites passed under AddressSanitizer |
| 2026-08-21 | S3 suites, mutation 1 | duplicate-identity guard removed from `Vault.multiADescriptor`, then the identity suite | 4 tests failed; a vault was built from one account key wearing two origin labels |
| 2026-08-21 | S3 suites, mutation 2 | origin depth/child consistency guard removed from `VaultCosignerKey`, then the identity suite | 2 tests failed; origin labels describing a different key were accepted |
| 2026-08-21 | S3 suites, mutation 3 | duplicate guard removed from `VaultDraft.add`, then the draft suite | 1 test failed with 3 issues; the creation screen accepted a third cosigner that was the first key relabelled. Sources restored pristine after all three |
