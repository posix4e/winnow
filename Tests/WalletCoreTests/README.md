[Back to main README](../../README.md)

# Wallet decisions and recovery tests

These tests protect balances, coin selection, fees, key storage, imports,
transaction signing, silent payment sends, people, and reorg recovery. They exercise the shared
wallet rules used by the GUI instead of reproducing those rules in app tests.

The same target includes [network tests](Network/README.md)
and loads [reference vectors](Vectors/README.md) through
[TestSupport](../Support/README.md).

Run `swift test --filter WalletCoreTests` from the repository root.
[App tests](../../AppTests/README.md) add persistence and authorization checks at the
presentation boundary; [UI journey](../../UITests/README.md) checks one payment through the app. Package tests alone do not prove that the screen communicates the result.
