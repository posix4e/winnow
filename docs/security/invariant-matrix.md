# Security invariant and evidence matrix

Baseline: `98d90563a2c20b7137c708cb121e72b9b34552a3`

Epic: [#100](https://github.com/posix4e/winnow/issues/100)

Overall state: **incomplete — no mainnet go decision**

Status vocabulary:

- **Partial:** useful evidence exists, but the invariant is not fully closed.
- **Gap:** no adequate evidence exists for a required property.
- **Blocked release:** an acceptance requirement for a mainnet beta remains
  open; this does not assert that an exploitable vulnerability is known.

| ID | Invariant | Current deterministic evidence | Required negative/manual evidence | Status |
|---|---|---|---|---|
| S1 | Secrets never enter ordinary state, persistent logs, E2E journals, or public artifacts. | `KeyStoreTests`, export redaction/staging tests, story publication/redaction tests. Keychain uses `WhenUnlockedThisDeviceOnly` and disables synchronization by construction. | Release-binary E2E exclusion **done** (negative control: the same check fails on the Debug build with all five markers) and secret canary scan **done** (positive, canary and planted-secret controls proven; clean against the arm64 release archive). Remaining: iOS Keychain integration; inspect every journal/log/error; clipboard expiry/local-only behavior; screenshot/background/crash checks; close `SEC-006`. | Partial; blocked release |
| S2 | Signing authorizes exactly the reviewed transaction and policy; stale or mutated review fails closed. | Sighash vectors, signer verification, PSBT signer/finalizer tests, wallet send/RBF tests. Send/RBF form identities invalidate stale reviews and late responses (`SEC-003`). Vault review now validates known outpoints, witness amounts/scripts, descriptor policy fields, sighashes, economics, and descriptor-derived owned outputs (`SEC-004`). | Add UI automation for mutation, interruption, and double-submit paths; bind a versioned review digest at remaining external-signer boundaries; independent review. | Partial; blocked release |
| S3 | Duplicate or inconsistent keys, origins, derivations, networks, and roles are rejected before funding. | Descriptor invalid vectors and `VaultFlowTests` signer-key checks. | Canonical duplicate-key tests across alternate origin spelling; origin depth/child consistency; cross-network xpubs; duplicate derived participants in core and UI. | Partial; blocked release |
| S4 | MuSig2 secret nonces are unique, one-use, session/message-bound, consumed, and interruption-safe. | BIP327 vectors; vault MuSig2 flow verifies partials and consumes companion nonce. | Reuse across sessions/messages, crash at every round boundary, replay/reorder, duplicated participant, persistence rollback, cancellation, concurrent-session tests. | Partial; blocked release |
| S5 | Spendable state derives only from validated headers and verified relevant blocks; peer failure and local corruption remain distinct. | `HeaderChainTests`, `FilterMatchingTests`, loopback full BIP157 test, merkle verification, stale-peer failover, local-corruption-no-retry. | ThreadSanitizer over the full suite **done** (339 tests, 0 data races, covering the loopback peer, mempool and broadcaster paths). Remaining: reorg wallet-state rollback, multi-peer disagreement/eclipsed view, corrupted block/filter/header state at each write boundary, sustained signet/differential evidence. | Partial; blocked release |
| S6 | Network-specific state, peers, addresses, explorers, descriptors, and caches never cross-contaminate silently. | Address network rejection, import network checks, network parameter tests, per-network app paths by source inspection. | Network-switch UI/E2E with preexisting wallets/vaults/caches; manual peer/explorer mismatch; cross-network PSBT and descriptor cases; crash during switch. | Partial; blocked release |
| S7 | Imported bundles, descriptors, PSBTs, and public keys are bounded hostile input and migrate fail closed. | Descriptor invalid vectors; PSBT malformed/required-field/conflict tests; 17 import tests including bad claims and corrupt stores; wire allocation caps. PSBT raw/Base64, map, key, and count limits plus fixed-field validation added in `SEC-001`. | Extend explicit byte/count/depth limits to remaining text/JSON parsers; duplicate JSON semantics; corpus fuzzing; pathological Unicode where applicable; UI file/QR limits. | Partial; blocked release |
| S8 | Vault construction creates only intended spend paths; thresholds and every valid signing pair are independently tested. | BIP387/BIP390 vectors; 2-of-3 script-path and 2-of-2 MuSig2 end-to-end tests; NUMS/control-block checks; wrong-key partial rejection. | Exhaustive threshold boundaries and all 2-of-3 pairs; duplicate-derived-key funding refusal; UI stepper/deletion/policy transitions; mixed implementation PSBT fixtures. | Partial; blocked release |
| S9 | Amount, fee, change, dust, integer, sighash, selection, and RBF calculations preserve intent without overflow/truncation. | Coin selection, fee policy, transaction builder, BIP341 sighash, wallet RBF/reconciliation, dust and malformed-feerate tests. Vault PSBT review uses overflow-checked input/output conservation, Bitcoin supply bounds, and exact known witness amounts/scripts (`SEC-004`). | Property tests at remaining integer boundaries; cross-check a larger transaction corpus against Bitcoin Core; add explicit fee-warning policy. | Partial; blocked release |
| S10 | Peers and interchange inputs cannot cause unbounded memory, disk, CPU, retries, connections, queues, or UI growth. | Framing maximum payload, oversized count tests, capped dial rounds, seen-buffer eviction, timeout/backoff tests, and PSBT document/map budgets (`SEC-001`). | Structured fuzzing and sanitizer runs **done** (`WinnowFuzz` over nine surfaces; a bounded PR smoke plus a scheduled sustained matrix that has passed 225,000 AddressSanitizer and 225,000 ThreadSanitizer cases). Remaining: slowloris and cancellation races, header/filter/block disk quotas, peer-address/cache caps, long-duration memory/CPU measurements. | Partial; blocked release |
| S11 | External disclosure is deliberate, warned, and never becomes a hidden wallet-read path. | Settings and backend separation by source inspection; Esplora client tests; experimental silent index is opt-in. | UI tests for warning/cancel/custom endpoint; inventory every URLSession call and query payload; network capture; ensure default wallet reads stay P2P; document miner/provider disclosure. | Partial; blocked release |
| S12 | Exact source, dependencies, toolchains, tests, findings, and artifact provenance are reproducible. | This manifest records source/toolchains/test result; `Package.resolved` records the secp dependency revision. | Actions pinned to immutable commits, SPDX 2.3 dependency SBOM and build provenance emitted, signing/workflow permission audit **done** (six of seven findings closed), and release-binary feature scan **done**. Remaining: `SEC-005` (fork pull requests execute on the persistent self-hosted runner), independent reproduction and reviewer sign-off. | Partial; blocked release |

## First-pass execution order

1. Close S2/S3/S4/S8 together across wallet core and signing UI because a
   display-only check cannot repair an authorization or custody invariant.
2. Close parser bounds for S7/S9/S10, then use those explicit limits as fuzz
   oracles rather than fuzzing unspecified behavior.
3. Exercise S1/S6/S11 on a real iOS app target where Keychain, authentication,
   clipboard, app lifecycle, and URLSession behavior actually exist.
4. Add sanitizer/fuzz CI and hostile-peer fixtures for S5/S7/S10.
5. Complete provenance and independent review for S12 before writing the
   limited-mainnet gate.

## Review log

| Date | Commit | Scope | Reviewer | Result |
|---|---|---|---|---|
| 2026-08-21 | `98d9056` | Phase 0 inventory and baseline test classification | Codex first pass | 310 tests pass; gaps above remain open |
| 2026-08-21 | `9c07d37` | Release-artifact verification legs: clean-DerivedData app build and tests, unsigned device archive, E2E exclusion with negative control, canary-controlled secret scan, ThreadSanitizer suite | Same-project agent pass, **not independent** | All legs passed; `SEC-006` raised. Does not satisfy the independent-review requirement |
| 2026-08-21 | `2bf7a65` | Workflow secret scope, token permissions, artifact retention, action pinning | Same-project agent pass, **not independent** | Six of seven prior findings closed; `SEC-005` remains open |

Independent review rows must name the reviewer and exact commit. “Reviewed”
without a commit and disposition is not accepted by the release gate.
