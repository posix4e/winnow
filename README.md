# Winnow

A Bitcoin wallet for iOS with on-device compact-filter matching, written in Swift.

**[Download on the App Store](https://apps.apple.com/app/id6801502501)** — pre-release builds ship through [TestFlight](https://testflight.apple.com/join/83djpNE7). Mainnet by default; signet is one Advanced-mode toggle away. See the [roadmap](https://winnowwallet.com/roadmap) for the status of earlier proposals.

- **Pure P2P by default.** The read side is BIP157/158 compact block filters served by full-node peers — the wallet does not send its watch list to a wallet-history server. Peers still observe requests, relay traffic and connection metadata. Bounded **mempool windows** (short full-relay subscriptions while the Receive or Send screen is open) give 0-conf payment detection and propagation tracking without any server. Read [how it works](https://winnowwallet.com/architecture).
- **Taproot today.** Ordinary receiving uses P2TR (BIP86); shared accounts use MuSig2 key-path or threshold script-path signing. There is no ECDSA signing path or P2WSH Safe.
- **Pay people and share control.** Save a public payment card or Bitcoin address. From Wallet, create shared savings with a threshold such as 2-of-3: any two keys can spend while one is unavailable. A 1-of-n policy permits one key to spend. Cards carry public keys only.
- **Require another signing device.** Advanced mode offers MuSig2 accounts where every key must participate. The single integration journey receives and sends with a phone-plus-Core account, followed by a script-path 2-of-3 account. Focused tests check wallet and account rules. Hardware-wallet compatibility needs its own test. Read about [shared signing and its limits](docs/vaults.html).
- **Bitcoin cryptography:** [`swift-secp256k1`](https://github.com/21-DOT-DEV/swift-secp256k1) (Bitcoin Core's libsecp256k1), pinned; the only third-party dependency. The embedded Tor client shipped in 0.6 through 0.7.0 was removed in 0.7.1 (its source is kept on the `archive/tor-0.7.0` branch). Winnow bundles no Tor or I2P client; it can route peer connections through Tor and I2P SOCKS gateways you run on your own Tailscale network ([peer gateways](docs/peer-gateways.md)).
- **Warned explorer links** — choose mempool.space or a custom Esplora website; Winnow opens it only after a tap and privacy warning, never as a wallet backend.

## Release roadmap

The [public roadmap](https://winnowwallet.com/roadmap) separates current behavior
from proposals that are not scheduled. It does not promise a release date or
make the historical audit follow-ups into current requirements.

## Layout

The app, Bitcoin implementation, CLI, fuzz harness, debugging tools and website
live in this repository. The app and all development tools use one root
Swift package and dependency lockfile. There is one release version and one source revision.

The app owns the user flows. WalletCore contains Bitcoin primitives, wallet
state, and P2P networking in one target. The winnow-debug tool and fuzz harness
use that same implementation. Explorer links open an external website after a warning.

The [testing and feature policy](docs/testing.md) keeps one iPhone integration
journey: an ordinary receive/send, MuSig2 receive/send with one Core cosigner,
then script-path 2-of-3 receive/send with two Core cosigners available. The phone
and one Core key approve the 2-of-3 payment; the third key stays unused. The
private signet fixture mines blocks automatically for prompt confirmation.
App, wallet, and protocol tests cover detailed rules; there is no separate
DifferentialTests target or broad interoperability matrix. One continuous
video presents the journey on the [recording page](https://winnowwallet.com/recording).
The automated UI journey currently runs only on iPhone; it does not establish
iPad UI coverage. The homepage gives an overview, illustrates
the signing choices, shows the run's sixteen checkpoint screenshots in order,
and links to the full recording. Detailed guidance and test evidence live on
separate pages.
The public site and its generator live in [winnowwallet/website](https://github.com/winnowwallet/website). Wallet CI retains the original recording evidence without building or deploying the site.

## Directory guides

Each guide explains what its directory owns, why the app or debugging needs it,
and which consumers and tests support that purpose. Every guide links back here.
When adding an owned directory with code, data, or documentation, add its README
and index link together. Parent folders with their own files need a guide too;
asset catalogs are documented by their owner, outside the bundle.

### App and Bitcoin rules

- App and inspection: [iPhone app](Sources/WinnowApp/README.md), [debugging and offline inspection](Tools/Debug/README.md).
- WalletCore primitives: [crypto/encodings](Sources/WalletCore/Crypto/README.md), [descriptors](Sources/WalletCore/Descriptors/README.md), [scripts](Sources/WalletCore/Script/README.md).
- WalletCore: [keys and secret storage](Sources/WalletCore/Keys/README.md), [PSBTs](Sources/WalletCore/PSBT/README.md), [transactions](Sources/WalletCore/Transactions/README.md), [wallet policy](Sources/WalletCore/Wallet/README.md).
- Network synchronization: [filters](Sources/WalletCore/Network/Filters/README.md), [headers](Sources/WalletCore/Network/Headers/README.md), [peer selection](Sources/WalletCore/Network/Peers/README.md).
- Network communication: [relay](Sources/WalletCore/Network/Broadcast/README.md), [mempool](Sources/WalletCore/Network/Mempool/README.md), [wire formats](Sources/WalletCore/Network/Protocol/README.md), [transport](Sources/WalletCore/Network/Transport/README.md).

### Tests and reference data

- User experience: [app decisions](AppTests/README.md), [integration journey](UITests/README.md).
- Rules and interoperability: [Bitcoin primitives](Tests/BitcoinCoreTests/README.md), [wallet rules](Tests/WalletCoreTests/README.md), [network cases](Tests/WalletCoreTests/Network/README.md).
- Shared fixtures: [TestSupport](Tests/Support/README.md), [real nodes](Tests/Support/Node/README.md), [controlled peers](Tests/Support/P2P/README.md).
- Reference data: [Bitcoin vectors](Tests/BitcoinCoreTests/Vectors/README.md), [MuSig2 vectors](Tests/BitcoinCoreTests/Vectors/bip327/README.md), [wallet/network vectors](Tests/WalletCoreTests/Vectors/README.md).
- Development tools: [tool tests](Tests/ToolsTests/README.md), [filter regressions](Tests/ToolsTests/Cases/filter/README.md), [PSBT regressions](Tests/ToolsTests/Cases/psbt/README.md).

### Debugging and fuzzing

- Integration fixture: [native bank preparation](Tools/Fixture/README.md).
- GUI/network debugging: [runbook](Tools/Debug/README.md), [implementation](Tools/Debug/Sources/WinnowDebug/README.md), [release-data generators](Tools/Generate/README.md).
- Fuzzing: [runbook](Tools/Fuzz/README.md), [executable](Tools/Fuzz/Sources/WinnowFuzz/README.md), [shared invariants](Tools/Fuzz/Sources/WinnowFuzzCore/README.md).

### Website and repository operations

- Website and blog: [winnowwallet/website](https://github.com/winnowwallet/website). Offline guides and engineering records remain in [docs](docs/README.md).
- Security: [reports and claims](docs/security/README.md), [retained soak evidence](docs/security/evidence/README.md).
- Operations: [public contributor runbooks](.github/internal/README.md), [workflows](.github/workflows/README.md), [scripts](scripts/README.md), [tooling regressions](scripts/tests/README.md).

## Build & test

```sh
swift test
swift run winnow-debug inspect tx <hex>
scripts/import-census
xcodegen
scripts/ci-app-tests /tmp/winnow-app-tests
scripts/ci-debug
```

Use XcodeGen 2.46.0. `scripts/install-xcodegen` downloads and verifies that
version; locally it prints the executable path to use. The generated Xcode
project is ignored. Run app tests with a fresh results directory.
Test fixtures live once, in the `TestSupport` library
([`Tests/Support`](Tests/Support/README.md)); it imports neither `Testing` nor
`XCTest`, so the swift-testing targets and the Xcode bundles share it and every
assertion stays at the call site.
`scripts/check-dependencies --xcode /path/to/DerivedData` verifies that Xcode uses the root
package and its committed third-party dependency revision.

[CI and release operations](.github/internal/ci-release.md) describes the shared
validation gates, node fixture, TestFlight recovery and website deployment.
Same-repository CI runs four parallel jobs on WarpBuild Apple silicon runners
([parallel lane](.github/workflows/ci-parallel.yml)); fork PRs
and the manual `hosted` input use one GitHub-hosted Apple silicon (`macos-26`)
`build` job for package, app, fuzz, lint, and release checks. Either lane is
followed by a `website` job that deploys its ready artifact. Fresh runs use per-run build products and a new signet
fixture, with no dependence on a developer Mac. One Debug build serves app
unit tests and the signet journey on the same simulator. Fresh runs retain both
result bundles, the video, and screenshots in `app-tests-…`.
Website-only edits reuse normalized journey media from a successful run with
matching test and build inputs, then generate and check a fresh website.
App-bundled HTML/CSS changes still require fresh tests. Missing evidence runs
the full checks; manual, nightly, and release runs always run fresh.

Mainnet is the default network, and the app starts in beginner mode: one
screen with the balance, Receive, Send, your activity, shared savings once you
have any, and automatic backup status — no settings. Manual backup is offered when
iCloud is unavailable; Advanced contains recovery words and the cloud-backup switch. Open a payment to save or rename its
recipient, then pick them from Saved recipients in Send. The same Send form
handles every account: choose the account, recipient, and amount, then review
the fee. Shared accounts continue to their required approvals before anything
is sent. Advanced, in the corner of that screen, switches to the three-tab
interface — Wallet, Send, Settings — with the test network, your own peers,
chain verification, the block explorer, custom fees, fee bumping, build
details and the raw vault tools; Simple, on the Wallet tab, switches back and
keeps every setting. Switch to signet there for development. Point the app at
your own filter-serving node (Settings → Manual peers); the node needs
`blockfilterindex=1` and `peerblockfilters=1`.

## App demonstration

GUI diagnostics live in [Tools/Debug](Tools/Debug/README.md). Use
`scripts/winnow-debug doctor` for environment checks and
`scripts/winnow-debug diagnostics` for local simulator logs and screenshots.
The demo and publication workflow has been retired. The single
`test01CreateReceiveSendConfirm` journey in `UITests/WinnowAppUITests.swift`
covers ordinary, MuSig2, and script-path 2-of-3 payments on iPhone. The host
records one continuous video; checkpoint screenshots remain secondary artifacts.
Lower-level tests cover detailed feature behavior. The recording’s provenance
identifies exactly which version and payments it shows.

Website screenshots and the reference recording live in the website repository, with Git LFS. Wallet CI normalizes new journey recordings into media artifacts and retains their original source and run provenance. Local test runs use fresh temporary directories; committed
historical images remain in the website repository.

## License

Winnow is available under the [MIT License](LICENSE).
