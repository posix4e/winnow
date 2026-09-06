#!/usr/bin/env bash
# Brings the CI signet fixture up on a docker host, idempotently: writes
# bitcoin.conf from the template, starts the container, waits for RPC, and
# makes sure the miner wallet (the block-signing key) exists. Safe to rerun;
# an already-running fixture is left alone apart from the wallet check.
#
#   WINNOW_FIXTURE_DIR   datadir on the host (default: ./data next to this script)
#   WINNOW_BIND_ADDRESS  address RPC also binds on (default: this host's Tailscale IPv4)
#   WINNOW_RPCAUTH       the `rpcauth=winnow-ci:<salt>$<hash>` line, or a file holding it
#                        (default: keep the line already in bitcoin.conf; refuse if none)
#
# A fresh datadir starts a fresh chain at height 0. That is fine: every
# suite mines what it needs, and the differential checks that read the tip
# mine their own first blocks. Chain history is never required.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

DIR="${WINNOW_FIXTURE_DIR:-$PWD/data}"
CONF="$DIR/bitcoin.conf"
BIND="${WINNOW_BIND_ADDRESS:-$(tailscale ip -4 2>/dev/null | head -1)}"
[ -n "$BIND" ] || { echo "no bind address: set WINNOW_BIND_ADDRESS" >&2; exit 1; }

RPCAUTH="${WINNOW_RPCAUTH:-}"
if [ -n "$RPCAUTH" ] && [ -f "$RPCAUTH" ]; then RPCAUTH=$(grep -m1 '^rpcauth=' "$RPCAUTH"); fi
if [ -z "$RPCAUTH" ] && [ -f "$CONF" ]; then RPCAUTH=$(grep -m1 '^rpcauth=winnow-ci:' "$CONF" || true); fi
case "$RPCAUTH" in
  rpcauth=winnow-ci:*) ;;
  *) echo "no winnow-ci rpcauth line: set WINNOW_RPCAUTH to the line or a file holding it" >&2; exit 1 ;;
esac

mkdir -p "$DIR"
sed -e "s|@BIND_ADDRESS@|$BIND|" -e "s|@RPCAUTH@|$RPCAUTH|" bitcoin.conf.tmpl > "$CONF.new"
if ! cmp -s "$CONF.new" "$CONF" 2>/dev/null; then
  mv "$CONF.new" "$CONF"
  echo "wrote $CONF (rpc on 127.0.0.1 and $BIND)"
  restart=1
else
  rm -f "$CONF.new"
  restart=0
fi
# The image runs bitcoind as uid 1000.
sudo chown -R 1000:1000 "$DIR"

export WINNOW_FIXTURE_DIR="$DIR"
if [ "$restart" = 1 ] && docker ps --format '{{.Names}}' | grep -qx winnow-signet; then
  docker compose restart winnow-signet >/dev/null
else
  docker compose up -d >/dev/null
fi

cli() { docker exec winnow-signet bitcoin-cli -datadir=/home/bitcoin/.bitcoin -signet "$@"; }
for _ in $(seq 1 90); do cli getblockchaininfo >/dev/null 2>&1 && break; sleep 2; done
cli getblockchaininfo >/dev/null || { echo "the fixture did not answer RPC" >&2; exit 1; }

# The block-signing key: a published dev constant, the same one
# scripts/signet-fixture uses for the local fixture. SignetMiner reads
# descriptors[0].desc and takes the last comma-separated field as the WIF,
# so this exact descriptor shape matters.
WIF="cU5G84sozM6AUeMTmh6M6E6bUZ8fkFAw7gyhLiQoxjQEQgM6HnhM"
if ! cli listwallets | grep -q '"miner"'; then
  cli loadwallet miner >/dev/null 2>&1 || cli -named createwallet wallet_name=miner blank=true >/dev/null
  checksum=$(cli getdescriptorinfo "multi(1,$WIF)" | python3 -c 'import sys,json;print(json.load(sys.stdin)["checksum"])')
  cli -rpcwallet=miner importdescriptors \
    "[{\"desc\":\"multi(1,$WIF)#$checksum\",\"timestamp\":\"now\",\"active\":false}]" >/dev/null
  echo "miner wallet created"
fi

height=$(cli getblockcount)
version=$(cli getnetworkinfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["subversion"])')
echo "fixture up: $version height $height rpc=$BIND:38400 p2p=$BIND:38401"
