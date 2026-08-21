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
| SEC-007 | Medium | S2 | Fixed on `claude/security-gate-100` | `SendPreview.authorizes` is the last gate before broadcast: `AppModel.send` does not send the transaction the review was computed from, it re-runs `buildSend` and asks the preview to authorize the result. The check verified the fee, the change amount, the exact input outpoints and the change output, but never the payment outputs. A build that paid a different script, paid the reviewed script one satoshi, or omitted the recipient output entirely was authorized as long as fee, change and inputs matched. No divergence path is known today because `buildSend` is handed `preview.payments`, so this was a defence-in-depth control that did not implement its stated invariant rather than a live exploit. Reviewed payments are now matched against transaction outputs and consumed as they match, so one output cannot satisfy both a payment and the change. | `SendPreviewAuthorizationTests`: 3 of its 10 tests failed against the unfixed check and pass after it; 32 app tests pass; silent-payment sends are unaffected because `payments` and `silentPayments` are disjoint in `previewSend` |
| SEC-008 | Medium | S2 | Fixed on `claude/security-gate-100` | `send` and `bumpFee` move money and are `@MainActor`, which serializes their entry but not their execution: each releases the main actor at every await — device authentication, build, broadcast, commit — so a second entry could begin in any of those gaps and run concurrently with the first. The only protection was the send screen disabling its button, which is presentation rather than a guarantee and covers only the one path that renders that button. Both paths now claim a shared `spending` gate before any await, and release it on every exit including the throwing one so a failed payment cannot wedge the wallet. A fee bump shares the gate with a send because both spend from the same UTXO set and both commit wallet state. | `SpendExclusionTests`: 5 tests; removing the exclusion check fails 3 of them, and bypassing the gate in `send` reproduces the pre-fix behaviour and fails the wiring test |
| SEC-009 | Medium | S3, S4, S8 | Fixed on `claude/security-gate-100` | `Vault.multiADescriptor` refuses a repeated cosigner while building a vault and the creation screen refuses one while drafting, but `Vault.init` — the boundary every other path crosses — accepted a policy that repeats a signer. `tr(musig(K,K)/<0;1>/*)` and `tr(NUMS,sortedmulti_a(2,K,K))` both constructed usable vaults with valid addresses. A repeated participant makes a policy that needs fewer independent signers than it advertises: a `musig(K,K)` presented as 2-of-2 is spendable by whoever holds K alone, because both partial signatures come from the same key. Reachable through restored persisted records, an imported bundle, a pasted descriptor, or a tampered vault store, which is the epic's own hostile-persistence threat model rather than a hypothetical. Construction now requires signers to derive to distinct public keys, compared as derived material so an origin relabelling cannot disguise a repeat. | `VaultSignerIndependenceTests`: 7 tests; 5 of them fail against the pre-fix initializer |
| SEC-010 | High | S7, S10 | Fixed on `claude/security-gate-100` | The descriptor parser is recursive descent and `parseTree` had no depth bound. A tap tree nested about a thousand levels deep exhausted the stack and terminated the process with a signal rather than raising an error. Stack exhaustion is not a Swift error, so none of the fail-closed damaged-storage handling can intercept it. Descriptors are parsed while the app starts up, when vault records are validated, so a single hostile or corrupted record would crash the app at every launch and leave the wallet unreachable until the file was removed by hand. Trees deeper than BIP341's 128 levels were also accepted despite never being able to produce a valid control block. `parseTree` now carries a depth counter bounded at 128. | `DescriptorBoundsTests`: 6 tests. Against the unbounded parser the test process is killed by signal 10 before the suite completes; with the bound all six pass, including depth 128 accepted as a positive control |
| SEC-011 | Low | S7, S10 | Fixed on `claude/security-gate-100` | An imported bundle is the one input a user is invited to paste from anywhere, and it was decoded with no explicit bound. Foundation accepted a 200,000-entry, 17 MB bundle; every declared coin is then materialised and scanned. Two properties the importer relied on also belonged to Foundation rather than to Winnow and were untested: deeply nested JSON is refused, and a duplicate key resolves to its first occurrence — so a bundle repeating `network` keeps the first value rather than a later `mainnet`. Both behaviours are safe, but nothing pinned them. Import now goes through `ImportBundle.decode`, which bounds serialized bytes and entry counts before allocating, and the Foundation semantics are pinned by test. | `ImportBundleBoundsTests`: 7 tests; removing the two bounds fails both limit tests. No production path decodes a bundle without them |
| SEC-012 | Low | S10 | Fixed on `claude/security-gate-100` | The persisted header file was read with `Data(contentsOf:)` and no size bound, while the compact-filter progress file has refused to be read past a ceiling since `#114`. Header storage is read during startup, so a damaged or tampered file of arbitrary size would be pulled into memory before the length check rejected it — the fail-closed corruption handling runs only after the allocation it is meant to protect against. The file is now measured before it is read and re-checked afterwards, mirroring the filter-progress idiom. A real mainnet chain is roughly 72 MB and grows about 4 MB a year, so the 256 MB ceiling cannot affect one. | `HeaderStorageBoundsTests`: 3 tests; with the guards disabled the oversized file is read and then rejected as a bad length, showing the allocation happened first |

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
| 2026-08-21 | `bc1f027` + S8 suite | `swift test` | 371 tests / 65 suites passed (8 new threshold and signing-coverage tests, 15 cases) |
| 2026-08-21 | `bc1f027` + S8 suite | `swift test --sanitize address --filter VaultThresholdTests` | passed under AddressSanitizer |
| 2026-08-21 | S8 suite, mutation A | BIP387 witness reversal dropped in `Signer.multisigWitness`, then the threshold suite | Pair (1,2) fell to 0 valid signatures while pairs (0,1) and (0,2) fell to 1, and the 3-of-3 fell to 1. The fully-broken pair is one the pre-existing single-pair test never exercised |
| 2026-08-21 | S8 suite, mutation B | `multi_a` threshold range guard removed from the descriptor parser | 3 of 4 out-of-range thresholds were accepted; k = -1 was still refused by the separate parse guard, confirming two independent checks |
| 2026-08-21 | S8 suite, mutation C | `VaultThreshold.clamped` made an identity function | Exhaustive clamping test failed on negative, zero and over-count thresholds. Sources restored pristine after all mutations |
| 2026-08-21 | `e30068b` + S2 suite, before fix | `xcodebuild test -only-testing:WinnowAppTests/SendPreviewAuthorizationTests` | 10 tests, 3 failures: a redirected recipient script, a one-satoshi payment to the right script, and a missing recipient output were all authorized |
| 2026-08-21 | `SEC-007` fix | same command | 10 tests passed |
| 2026-08-21 | `SEC-007` fix | `xcodebuild test -only-testing:WinnowAppTests` | 32 tests / 0 failures |
| 2026-08-21 | `SEC-007` fix | `swift test` | 371 tests / 65 suites passed |
| 2026-08-21 | `SEC-008` fix | `xcodebuild test -only-testing:WinnowAppTests/SpendExclusionTests` | 5 tests passed |
| 2026-08-21 | `SEC-008` mutation A | exclusion check removed from `exclusively` | 3 of 5 failed, including both wiring tests |
| 2026-08-21 | `SEC-008` mutation B | `send` routed around the gate, reproducing pre-fix behaviour | the wiring test failed with "send reached its wallet check, so it did not consult the gate" |
| 2026-08-21 | `SEC-008` fix | `xcodebuild test -only-testing:WinnowAppTests` | 37 tests / 0 failures |
| 2026-08-21 | `SEC-008` fix | `swift test` | 371 tests / 65 suites passed |
| 2026-08-21 | `SEC-009`, pre-fix | `swift test --filter VaultSignerIndependenceTests` against the unmodified initializer | 5 of 7 failed; duplicate-participant MuSig2 and script-path vaults were both constructed with valid addresses |
| 2026-08-21 | `SEC-009` fix | same command | 7 tests passed; also passed under AddressSanitizer |
| 2026-08-21 | `SEC-009` fix | `swift test` | 378 tests / 66 suites passed |
| 2026-08-21 | `SEC-009` fix | `xcodebuild test -only-testing:WinnowAppTests` | 37 tests / 0 failures, so vault-store loading is unaffected |
| 2026-08-21 | `SEC-010`, pre-fix | `swift test --filter DescriptorBoundsTests` against the unbounded parser | process terminated by signal 10 (stack exhaustion); the suite did not complete |
| 2026-08-21 | `SEC-010` fix | same command | 6 tests passed, including depth 128 accepted and depths 129, 1,000, 5,000 and 50,000 refused |
| 2026-08-21 | `SEC-010` fix | `swift test` | 384 tests / 67 suites passed |
| 2026-08-21 | `SEC-010` fix | `swift test --sanitize address --filter DescriptorBoundsTests` | 6 tests passed under AddressSanitizer |
| 2026-08-21 | `SEC-010` fix | `WinnowFuzz --iterations 20000 --target descriptor` under AddressSanitizer | 20,000 deterministic cases passed, seed 0x57494e4e4f574655 |
| 2026-08-21 | `SEC-011` probe | duplicate-key, nesting and array-size probe of `JSONDecoder` on `ImportBundle` | duplicate key resolved to the FIRST value; nesting refused at depth 512 and beyond; a 200,000-entry 17 MB bundle decoded without complaint |
| 2026-08-21 | `SEC-011` fix | `swift test --filter ImportBundleBoundsTests` | 7 tests passed, including a bundle exactly at the entry limit accepted |
| 2026-08-21 | `SEC-011` mutation | both bounds removed from `ImportBundle.decode` | the byte-limit and entry-limit tests failed |
| 2026-08-21 | `SEC-011` fix | `swift test` | 391 tests / 68 suites passed |
| 2026-08-21 | `SEC-011` fix | `xcodebuild test -only-testing:WinnowAppTests` | 37 tests / 0 failures |
| 2026-08-21 | S9 property suite | `swift test --filter CoinSelectionPropertyTests` | 7 tests passed: 7,000 seeded scenarios plus named dust, fee-rate and MAX_MONEY boundaries; also green under AddressSanitizer |
| 2026-08-21 | S9 mutation A | change computation altered by one satoshi in `CoinSelection.select` | value-conservation property failed immediately, naming the seed and iteration for replay |
| 2026-08-21 | S9 mutation B, first attempt | fee-rate ceiling removed | **no test failed** — an absurd rate still threw, as `insufficientFunds` rather than `invalidFeeRate`, and the assertion accepted any `CoinSelectionError` |
| 2026-08-21 | S9 mutation B, after tightening | same mutation against the case-specific assertion | the fee-rate test failed for rates 10000.001 and 100000, reporting the wrong error case. Recorded because a mutation that kills no test means the test is weaker than it looks, not that the code is safe |
| 2026-08-21 | S9 property suite | `swift test` | 398 tests / 69 suites passed |
| 2026-08-21 | `SEC-012` fix | `swift test --filter HeaderStorageBoundsTests` | 3 tests passed, including a real persisted chain round-tripping |
| 2026-08-21 | `SEC-012` mutation | both size guards disabled | the oversized-file test failed, reporting rejection as `storageCorrupt("bad length")` — the file had already been read |
| 2026-08-21 | S10 survey | message-command inventory of `Sources/BitcoinP2P` | Winnow handles no `addr` or `addrv2` message, so there is no gossip-address cache to bound; that requirement is not applicable by design rather than open |
| 2026-08-21 | `SEC-012` fix | `swift test` | 401 tests / 70 suites passed |
