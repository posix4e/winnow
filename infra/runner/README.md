# The macOS runner for node-tests

`node-tests.yml` runs on `[self-hosted, macOS, btc-swift, node-e2e]`. The
runner is a macOS guest on the libvirt/docker host that also serves the
fixture, cloned from a golden OSX-KVM image with the host's
`OSX-KVM/clone-runner.sh`. That clone step is an operator action on the host
(it is in that repository, not this one); everything after it is
`provision.sh` here.

## What the workflow expects on the runner

- `/Applications/Xcode.app` with the iOS simulator runtime, and an iPhone
  simulator (the workflow creates one from "iPhone 17/16/15" if none exists).
- `bitcoin-cli` on `PATH` (Homebrew's `bitcoin` bottle). The workflow refuses
  to run without it: it never installs a node binary itself.
- Reachability to the fixture host's Tailscale address on 38400 (RPC) and
  38401 (P2P). A guest on the same host reaches it through the host's tailnet
  address without joining the tailnet itself.
- The runner registered with labels `btc-swift,node-e2e`. A run queued
  before a label existed is never re-matched: cancel it and dispatch again.

## Bringing one up

```sh
# on the host: clone the golden image and boot it (see OSX-KVM/README-local.md)
cd ~/OSX-KVM && ./clone-runner.sh macvm-1-btc 1
nohup runners/start-macvm-1-btc.sh > runners/macvm-1-btc.log 2>&1 &

# on the host, once the guest answers on its forwarded SSH port:
gh api -X POST repos/posix4e/winnow/actions/runners/registration-token --jq .token > /tmp/reg-token
~/src/winnow/infra/runner/provision.sh macvm-1-btc 2201 /tmp/reg-token
rm /tmp/reg-token
```

`provision.sh` installs the Homebrew `bitcoin` bottle, checks Xcode, and
registers the runner with the labels above as a LaunchDaemon, so it survives
reboots without a GUI login. It is safe to rerun.

## Retiring one

Remove the runner from the repo's runner list (or `./config.sh remove` in the
guest), shut the guest down through its monitor socket, and delete the
overlay image under `runners/`. The golden image is untouched.
