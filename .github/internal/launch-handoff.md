# v1 launch handoff

Status recorded 2026-08-17. This is a handoff checkpoint, not authorization to spend bitcoin, switch the default network, tag v1.0.0, upload assets, or submit the app.

## Merged and verified

- PR #36 is merged. Push and pull-request CI now runs only the package and app-build suites; both passed on the PR and again on `main`. Node-backed differential/UI E2E is manual-only and requires a dedicated `node-e2e` runner label, so it cannot fall back to a developer workstation. The former local custom-signet services and repository RPC credential were removed. Issue #35 is closed.
- PR #37 is merged. Bundle v2 carries validated `silentPaymentTweak` recovery metadata, ordinary v1 bundles remain readable, and watch-only export refuses to create an incomplete backup when silent-payment funds are present. The rebased package suite passed 263 tests, app-build CI passed, and the recovery test signs and independently Schnorr-verifies a restored spend. Issue #19 is closed.
- The 2026-08-17 iPhone 17 Pro Max / iOS 26.5 signet run passed all 10 UI tests and produced 22 screenshots at 1320 × 2868. The six composition candidates were visually inspected; none contains a mnemonic or development endpoint. See [`app-store-screenshots.md`](app-store-screenshots.md).
- The uncontended UI mining sample completed 102 first-attempt tip wins with zero lost races. This supports the low-contention observation for #28 but does not replace the deliberately contended measurement required to close it.

## Optional node-backed CI

Winnow is a direct-P2P compact-filter client; neither the app nor normal development requires `bitcoind`. Keep the manual Node E2E workflow disabled until a disposable custom-signet fixture is attached to a dedicated runner carrying the `node-e2e` label. Its RPC credential must belong to that fixture, not to an owner's machine. Issue #11 tracks that separate CI capability; issue #14 is obsolete under this design.

## Owner-gated launch sequence

1. Perform #8 exactly as written with a deliberately small real-mainnet amount and retain the launch recording. This is the only step here that spends real bitcoin.
2. If #8 passes, implement #9: make mainnet the default, recheck fee presets and peer diversity, and update onboarding copy.
3. Recapture the six 6.9-inch composition candidates after #9. Confirm dimensions, visually recheck every candidate for mnemonic/development data, then upload them for #6. The current signet captures must not be uploaded unchanged.
4. Provision and verify the dedicated Node E2E environment for #11 if it remains a v1 gate; do not restore the owner-workstation dependency. Keep #28 open until a deliberately contended mining sample sizes the retry bound.
5. **Refresh the shipped header checkpoint** (owner decision on #89,
   2026-08-24: manual, at release time). Regenerate from a genesis-validated
   `headers.bin` via `swift test --filter CheckpointGenerator` with
   `WINNOW_HEADERS_BIN` set, bump the `NetworkParams.mainnet.checkpoint`
   constant, and update its provenance note. The constant currently sits at
   block 900,000; every release it ages costs each fresh install the headers
   since.
6. Only after the owner confirms every gate: tag v1.0.0, archive, upload, and submit for #7.
