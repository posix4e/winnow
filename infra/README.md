# CI infrastructure for the node-backed suite

`node-tests.yml` needs two things no hosted runner provides: a macOS runner
with Xcode and `bitcoin-cli`, and a Bitcoin Core node running the disposable
custom signet the differential and UI suites mine on. Both live on one
libvirt/docker host on the tailnet. This directory is what it takes to
recreate either from scratch.

| Piece | Where it runs | Recreated by |
|---|---|---|
| Signet fixture (Core 31.1, custom signet) | a docker container on the host, RPC and P2P on the host's Tailscale address | `infra/fixture/bootstrap.sh` |
| macOS runner `macvm-N-btc` (labels `self-hosted, macOS, btc-swift, node-e2e`) | an OSX-KVM guest on the same host | `infra/runner/README.md` |

The workflow finds the fixture through the repo variable `BTC_SWIFT_NODE_HOST`
(the host's Tailscale IPv4) and authenticates RPC with the fixed `winnow-ci`
credential in the secret `BTC_SWIFT_RPC_COOKIE`, whose `rpcauth` line the
bootstrap writes into the node's config. Nothing on the fixture is secret:
the chain holds no value and the block-signing key is a published constant.

## The fixture

```sh
# on the host, once per machine (or after losing the datadir)
git clone https://github.com/posix4e/winnow ~/src/winnow
cd ~/src/winnow/infra/fixture
WINNOW_RPCAUTH='rpcauth=winnow-ci:<salt>$<hash>' ./bootstrap.sh
```

Reruns are no-ops apart from the wallet check, so the same command repairs a
fixture whose container was removed or whose config drifted. A fresh datadir
starts a fresh chain at height 0, which every suite accepts: they mine what
they need. Copying a chain from elsewhere is never required.

The credential pair is created once: `rpcauth` line into the config through
`WINNOW_RPCAUTH`, `winnow-ci:<password>` into the repo secret. Bitcoin Core's
`share/rpcauth/rpcauth.py winnow-ci` prints both.

Local development keeps its own fixture on the developer's machine
(`scripts/signet-fixture up`, localhost, cookie auth). The two never share a
mempool, which matters: a transaction left in the CI fixture's mempool by a
local run once made a differential funding coinbase 770 sats too rich.

## The runner

See `infra/runner/README.md`. Cloning a macOS guest is an operator action on
the host; registering it and provisioning what the workflow needs is scripted.

## Checking

`node-tests.yml` probes both ports of the fixture before doing anything and
refuses to run without `bitcoin-cli` and Xcode on the runner, so a broken
piece fails in the first minute with a named step.
