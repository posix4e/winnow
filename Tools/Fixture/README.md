[Back to main README](../../README.md)

# Native signet bank preparation and the multisig differential

`winnow-fixture` prepares the disposable signet bank before the recorded iPhone
journey, and holds the Taproot script-path multisig to Bitcoin Core on a
disposable regtest node (see [the multisig differential](#the-multisig-differential) below). It is a host executable, outside the shipping app. It uses
[SignetFixture](../../Tests/Support/Node/SignetFixture.swift), the same helper
that the UI test uses to check readiness.

From the repository root, after starting the isolated node:

```sh
swift run winnow-fixture --help
swift run winnow-fixture prepare-bank
```

`--help` performs no node work. `prepare-bank` checks that the node reports
signet, creates or opens `ui-bank`, and mines 101 blocks if the bank lacks
sufficient mature funds. Use the configured disposable fixture, not public signet.
It reports `SIGNET_BANK_PREPARATION_SECONDS`; errors exit nonzero. Repeating it
on a prepared bank checks readiness without mining another 101 blocks.

The command reads `WINNOW_NODE_HOST` (default `127.0.0.1`), `WINNOW_RPC_PORT`
(default `38400`), `WINNOW_DATADIR` (default `~/.bitcoin-mysignet`), and optional
`WINNOW_BITCOIN_CLI`. It uses the node’s cookie for authentication. Use the same
configuration as [signet-fixture](../../scripts/signet-fixture); the
[UI runbook](../../UITests/README.md#run-locally) shows isolated local paths and ports.
This command does not start the node or simulator, run tests, or record video.

[CI](../../.github/workflows/ci.yml) invokes it in fixture initialization;
[ci-ui-journey](../../scripts/ci-ui-journey) checks the bank again before recording.
The journey validates the resulting funded payments. Hosted CI always starts
from a fresh chain; prepared-bank snapshots are only a local convenience.

## The multisig differential

`scripts/check-multisig-core` starts a throwaway regtest `bitcoind` in a new
temporary datadir (RPC 38710 and P2P 38711 by default, never the signet
fixture's 38400), runs `swift run winnow-fixture multisig-differential` against
it, then stops and deletes the node:

```sh
scripts/check-multisig-core                    # 24 cases from the default seed
scripts/check-multisig-core --cases 40 --seed 1a2b
```

Each seeded case is an account of two to five signers with any threshold,
where zero to two signers are Bitcoin Core wallets (keys Core generated and
signs with its own libsecp256k1), the signers listed in a shuffled order, and
an optional recovery leaf (fewer of the same signers, or separate keys, after
1 to 4 blocks; 16, 144, 4,032 or 65,535 blocks are checked for addresses
only). Core must agree with Winnow on the descriptor checksum, the first four
receive and change addresses (and listing the keys in another order must
build the same descriptor), which signers a PSBT carries valid signatures
from, and every subset of exactly k signers: Winnow finalizes, Core's mempool
accepts, Core's own finalizer produces the same bytes, and one spend is mined.
k − 1 signers finish on neither side; k + 1 still finish. On the recovery
leaf, both sides refuse every threshold subset one block before the lock
opens and accept it in the block it opens, and the signers' leaf finishes a
spend carrying the recovery sequence (BIP326).

[MultisigDifferential.swift](MultisigDifferential.swift) has the checks.
The command prints how many checks of each kind agreed and every
disagreement with the seed and case that reproduce it; it exits non-zero on
any disagreement. Forty cases take
about two minutes. It is a local check; CI does not run it.

