[Back to main README](../../README.md)

# Bitcoin primitive tests

Known-answer and adversarial tests protect the cryptographic, key-derivation,
descriptor, and script rules behind receiving, recovery, and shared signing.
They exercise BitcoinCore primitives directly so a wrong primitive is easier to locate
than through a complete app journey.

The [vectors](Vectors/README.md) provide independent
expected values; [TestSupport](../Support/README.md) supplies shared loaders.
The standalone consumer in `Examples/OfflineWallet` verifies the public BitcoinCore
product without bringing in WalletCore or the shared fixture target.

Run `swift test --filter BitcoinCoreTests` from the repository root.
[CI](../../.github/workflows/ci.yml) runs the package suite on hosted Apple silicon.
Passing vectors demonstrate agreement on their cases, not exhaustive correctness
or completion of an independent security review.
