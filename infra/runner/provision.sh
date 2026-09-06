#!/usr/bin/env bash
# Provisions a freshly cloned macOS guest as a node-tests runner, from the
# host, over the guest's forwarded SSH port:
#   1. Homebrew's bitcoin bottle, for bitcoin-cli on PATH
#   2. a check that /Applications/Xcode.app exists (Xcode is part of the
#      golden image; this script does not install it)
#   3. runner registration with the labels node-tests.yml selects on, as a
#      LaunchDaemon, using the guest's own register.sh from the golden image
#
# Usage: provision.sh <runner-name> <ssh-port> <registration-token-file> [github-url]
#   The token comes from:
#     gh api -X POST repos/posix4e/winnow/actions/runners/registration-token --jq .token
#   and is read from a file so it never sits in a shell history line.
# Safe to rerun: brew and the registration are both idempotent.
set -euo pipefail

NAME="${1:?runner name}"
PORT="${2:?guest ssh port}"
TOKEN_FILE="${3:?registration token file}"
URL="${4:-https://github.com/posix4e/winnow}"
KEY="${MACVM_SSH_KEY:-$HOME/.ssh/macvm_key}"
USER_AT_GUEST="${MACVM_USER:-macdev}@127.0.0.1"
LABELS="${WINNOW_RUNNER_LABELS:-btc-swift,node-e2e}"

guest() { ssh -i "$KEY" -p "$PORT" -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "$USER_AT_GUEST" "$@"; }

echo "== guest"
guest 'sw_vers; echo "xcode: $(xcode-select -p 2>&1)"; test -d /Applications/Xcode.app || { echo "no /Applications/Xcode.app: install Xcode in the golden image first" >&2; exit 1; }'

echo "== bitcoin-cli"
guest 'export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"; command -v brew >/dev/null || { echo "no Homebrew in the guest" >&2; exit 1; }; command -v bitcoin-cli >/dev/null || brew install bitcoin; bitcoin-cli --version | head -1'

echo "== hostname"
guest "sudo -n scutil --set HostName '$NAME' 2>/dev/null || true; scutil --get HostName"

echo "== register ($LABELS)"
TOKEN=$(tr -d '[:space:]' < "$TOKEN_FILE")
[ -n "$TOKEN" ] || { echo "empty token file" >&2; exit 1; }
if guest "test -f ~/runners/$NAME/.runner"; then
  echo "runner $NAME already registered in the guest"
else
  # register.sh <name> <github-url> <token> [extra-labels] installs the runner
  # under ~/runners/<name> and loads it as a LaunchDaemon.
  guest "cd ~/actions-runner && ./register.sh '$NAME' '$URL' '$TOKEN' '$LABELS'"
fi
unset TOKEN

echo "== fixture reachability from the guest"
HOST_TS_IP="${WINNOW_NODE_HOST:-$(tailscale ip -4 2>/dev/null | head -1)}"
guest "nc -z -G 5 $HOST_TS_IP 38401 && echo 'p2p ok' || echo 'p2p unreachable'; nc -z -G 5 $HOST_TS_IP 38400 && echo 'rpc ok' || echo 'rpc unreachable'"

echo "done: $NAME registered to $URL with labels $LABELS"
