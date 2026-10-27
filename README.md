# Winnow

A Bitcoin wallet for iOS with on-device compact-filter matching, written in Lean 4 and rendered by
ElmLean's generic native shell (see [PORT.md](PORT.md)).

**[Download on the App Store](https://apps.apple.com/app/id6801502501)** — pre-release builds ship through [TestFlight](https://testflight.apple.com/join/83djpNE7). Mainnet by default; signet is one Advanced-mode toggle away. The broader beta is planned for 0.9; see the [release roadmap](https://winnowwallet.com/roadmap).

- **Pure P2P by default.** The read side is BIP157/158 compact block filters served by full-node peers — the wallet does not send its watch list to a wallet-history server. Peers still observe requests, relay traffic and connection metadata. Bounded **mempool windows** (short full-relay subscriptions while the Receive or Send screen is open) give 0-conf payment detection and propagation tracking without any server. Read [how it works](docs/architecture.html).
- **Taproot today.** Current receiving uses P2TR (BIP86), with no ECDSA signing path. The planned 0.7 P2WSH Safe is a separate, opt-in addition.
- **Pay people and share control.** Save a public payment card or Bitcoin address. From Wallet, create shared savings with a threshold such as 2-of-3: any two keys can spend while one is unavailable. A 1-of-n policy permits one key to spend. Cards carry public keys only.
- **Require another signing device.** Advanced mode offers MuSig2 accounts where every key must participate. The single integration journey receives and sends with a phone-plus-Core account, followed by a script-path 2-of-3 account. Focused tests check wallet and account rules. Hardware-wallet compatibility needs its own test. Read about [shared signing and its limits](docs/vaults.html).
- **Bitcoin cryptography:** secp256k1, BIP340 and MuSig2 in Lean (`Lean/Secp`, with machine-checked proofs of the field and curve arithmetic), no third-party dependency. The embedded Tor client shipped in 0.6 through 0.7.0 was removed in 0.7.1 (its source is kept on the `archive/tor-0.7.0` branch); Tor and I2P are on the [roadmap](https://winnowwallet.com/roadmap#private-transports).
- **Warned explorer links** — choose mempool.space or a custom Esplora website; Winnow opens it only after a tap and privacy warning, never as a wallet backend.

## Release roadmap

The [public roadmap](https://winnowwallet.com/roadmap) keeps planned work
separate from current features. Each milestone describes the user outcome,
the journeys that must pass, and unresolved work. Milestones are targets,
not shipped capabilities or promised dates.

## Layout

- `Lean/`: the wallet in Lean 4 (`Winnow/`): keys, transactions, PSBTs, descriptors, vaults and
  MuSig2, the wallet, compact-filter sync, peers, mempool windows and the broadcaster, over libuv TCP.
  `Secp/` is the proven secp256k1. `IOTest.lean` (`io-test`) runs the network layer against a disposable
  regtest bitcoind.
- `LeanApp/`: the app: `WinnowApp/` holds the model, update, views and commands (Elm-style, ElmLean),
  `WinnowApp/Real/` the backend, `WinnowApp/E2E.lean` the Debug-only test mode. `ios/` is the XcodeGen
  project that links the Lean-generated C with ElmLean's native shell (renderer, C shim, capabilities:
  Keychain, device authentication, clipboard, HTTPS, paths). The shell is Objective-C printed from Lean
  at build time into `ios/build/native-shell/`, never checked in; the app compiles no Swift at all.
- `docs/`: the website and the papers the app bundles.
- [PORT.md](PORT.md): how the port was done and verified, and what differs from the Swift original
  (removed from this tree; it remains in the history before this port).

## Build & test

```sh
cd LeanApp
lake build backend-test records-test        # Lean toolchain leanprover/lean4:v4.35.0 (elan)
./.lake/build/bin/backend-test               # end to end against a fresh regtest bitcoind
./.lake/build/bin/records-test
<framework>/native/scripts/ios_lean_sources.sh . WinnowApp ios/build iossim
cd ios && xcodegen generate && xcodebuild -scheme WinnowLean -destination 'platform=iOS Simulator,id=<udid>' build
```

`backend-test --fixture <dir>` leaves a funded regtest node running for manual simulator runs.
`scripts/install-xcodegen` installs XcodeGen 2.46.0. Simulator builds are ad-hoc signed (an unsigned
app has no Keychain entitlement).

Mainnet is the default network, and the app starts in beginner mode: one
screen with the balance, Receive, Send, your activity, shared savings once you
have any, and the backup. Advanced switches to the three-tab interface —
Wallet, Send, Settings — with the test network, your own peers, chain
verification, the block explorer, custom fees, fee bumping and the vault tools.
Point the app at your own filter-serving node (Settings → Manual peers); the
node needs `blockfilterindex=1` and `peerblockfilters=1`.

Screenshot PNGs in `docs/screenshots/` are stored in Git LFS. After cloning,
install Git LFS and download the image objects before viewing or publishing them:

```sh
git lfs install --local
git lfs pull
```

## License

Winnow is available under the [MIT License](LICENSE).
