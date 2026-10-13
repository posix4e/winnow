[Back to main README](../../../README.md)

# Real-node test helpers

BitcoinCLI, HostProcess, and SignetMiner let tests query a node and mine blocks
on the disposable custom signet. The UI journey uses these chain operations
for ordinary-wallet, MuSig2 and 2-of-3 payments. CoreSigner creates real
Core-held keys and exchanges PSBTs for the other signing wallets.

`SignetFixture` shares the bank setup used by the native
[winnow-fixture prepare-bank](../../../Tools/Fixture/README.md) command and the UI journey's readiness checks.
The host command reuses `BitcoinCLI` and `SignetMiner` to mature the bank before
recording or XCTest starts. A fresh CI fixture still mines 101 blocks; no bank
snapshot is reused across CI runs. The UI test then checks the chain and ready
balance, and mines only the blocks needed for its payments.

The [UI journey](../../../UITests/README.md) consumes these helpers from the framework-agnostic
[TestSupport library](../README.md); assertions belong to callers.

[HostProcess tests](../../WalletCoreTests/HostProcessTests.swift) cover
subprocess behavior, and [CoreSigner tests](../../WalletCoreTests/CoreSignerTests.swift)
cover descriptor parsing without a node. The required [CI workflow](../../../.github/workflows/ci.yml)
exercises the RPC/miner path through host bank preparation and the UI journey
against its temporary node. This directory does not
register runners.
