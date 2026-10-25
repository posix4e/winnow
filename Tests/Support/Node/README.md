[Back to main README](../../../README.md)

# Real-node test helpers

BitcoinCLI, HostProcess, and SignetMiner let tests query a node and mine blocks
on the disposable custom signet. The UI journey uses these chain operations
to fund the phone and confirm its payments. `CoreSigner` gives Bitcoin Core
its own key in a disposable wallet: the journey's 2-of-2 multisig account
names Core's public key expression, Core imports the account with its own key
private, and `walletprocesspsbt` adds Core's script-path signature with its
own libsecp256k1. SignetMiner has the node's `miner`
wallet sign each block's BIP325 challenge over RPC
(`signrawtransactionwithwallet`), as Bitcoin Core's reference miner does, so
the harness carries no ECDSA and the challenge key never leaves the node.

`SignetFixture` shares the bank setup used by the native
[winnow-fixture prepare-bank](../../../Tools/Fixture/README.md) command and the UI journey's readiness checks.
The host command reuses `BitcoinCLI` and `SignetMiner` to mature the bank before
recording or XCTest starts. A fresh CI fixture still mines 101 blocks; no bank
snapshot is reused across CI runs. The UI test then checks the chain and ready
balance, and mines only the blocks needed for its payments.

The [UI journey](../../../UITests/README.md) consumes these helpers from the framework-agnostic
[TestSupport library](../README.md); assertions belong to callers.

[HostProcess tests](../../WalletCoreTests/HostProcessTests.swift) cover
subprocess behavior. The required [CI workflow](../../../.github/workflows/ci.yml)
exercises the RPC/miner path through host bank preparation and the UI journey
against its temporary node. This directory does not
register runners.
