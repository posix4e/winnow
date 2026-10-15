[Back to main README](../../README.md)

# Vault and contact card tests

These tests protect contact cards and pasted input, vault admission, and vault
spends: thresholds, MuSig2 and script-path signing, combining, finalizing, and
the anti-fee-sniping locktime. Fixtures come from [TestSupport](../Support/README.md).

Run `swift test --filter VaultKitTests` from the repository root.
The [UI journey](../../UITests/README.md) spends from both kinds of vault through the app.
