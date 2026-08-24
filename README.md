# Winnow

A private, opinionated, modern Bitcoin wallet for iOS — 100% Swift, one dependency.

**[Public beta on TestFlight](https://testflight.apple.com/join/83djpNE7)** — signet by default.

- **Pure P2P by default.** The read side is BIP157/158 compact block filters served by full-node peers — no server ever learns your addresses. Bounded **mempool windows** (short full-relay subscriptions while the Receive or Send screen is open) give 0-conf payment detection and propagation tracking without any server. Design papers, framed around the phone: [design-paper index](.github/internal/design-papers.md).
- **Taproot only.** P2TR receiving (BIP86); no legacy address types, no ECDSA signing paths.
- **Two modern multisig flavors.** MuSig2 (BIP327) n-of-n vaults and script-path k-of-n (`multi_a`, BIP387/388), coordinated over PSBTv2 (BIP370/371/373).
- **Silent payments** (BIP352) live on the [`alpha`](../../tree/alpha) branch, not here. Receiving needs a per-block tweak-data server that does not exist as public infrastructure, which is the unsolved part; see `ALPHA.md` on that branch.
- **One runtime dependency:** [`swift-secp256k1`](https://github.com/21-DOT-DEV/swift-secp256k1) (Bitcoin Core's libsecp256k1), pinned.
- **Warned explorer links** — choose mempool.space or a custom Esplora website; Winnow opens it only after a tap and privacy warning, never as a wallet backend.

## Layout

Architecture invariant: **all logic lives in the SPM package, where it is tested; the app target is a thin shell.** No wallet, protocol, or crypto logic may move into `WinnowApp` — if the UI needs something, expose it from a library.

- `Sources/BitcoinCore` — crypto, keys (BIP39/32/86), Taproot (BIP341), descriptors (BIP380/387/389/390), MuSig2 (BIP327)
- `Sources/BitcoinP2P` — wire protocol, peers, header chain, BIP157 filter sync, tx broadcast
- `Sources/BlockchainBackend` — isolated HTTP protocol clients; production wallet reads remain P2P
- `Sources/WalletCore` — wallet/vault actors, sighash + signing, PSBTv2, coin selection, fee policy, import bundles
- `Sources/WinnowApp` — the iOS app (SwiftUI, iOS 17+)
- `docs/` — public design papers (phone, read, write, vaults, import) + webpage; see the [design-paper index](.github/internal/design-papers.md)
- [`.github/internal/story-run.md`](.github/internal/story-run.md) — reproducible, resumable whole-app public-signet story and release checklist (no local `bitcoind`)
- `scripts/` — story runner, icon generation, App Store Connect API tooling, and TestFlight pipeline

## Build & test

```sh
swift build
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test   # unit, protocol, vector, and story-run tests
/opt/homebrew/bin/xcodegen && open WinnowApp.xcodeproj                # iOS app
```

Default network for development is signet. Point the app at your own
filter-serving node (Settings → Manual peers); the node needs
`blockfilterindex=1` and `peerblockfilters=1`.

## License

Winnow is available under the [MIT License](LICENSE).
