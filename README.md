# Winnow

Winnow is a Bitcoin wallet for iPhone and iPad, also available on Apple silicon
Mac as an iPad app. It receives and sends bitcoin, saves recipients, and supports
shared accounts with more than one signing key.

[App Store](https://apps.apple.com/app/id6801502501) ·
[TestFlight](https://testflight.apple.com/join/83djpNE7) ·
[User guides](https://winnowwallet.com) ·
[Report a bug](https://github.com/winnowwallet/winnow/issues)

## Using the wallet

Winnow starts on mainnet in Simple mode. One screen holds your balance,
Receive, Send, activity, shared savings and backup status. Open a payment to
save its recipient; choose saved recipients from the Send form.

Advanced mode adds Wallet, Send and Settings tabs, with signet, manual peers,
fee controls, recovery words and raw signing exchanges. Switching modes keeps
your wallet and settings. Use signet and test funds when trying a development
build or a new signing setup.

Shared savings can require a threshold of keys, such as any two of three.
Advanced mode also offers MuSig2 accounts requiring every participating key.
The descriptor determines who can spend: a 1-of-n account needs only one key.
Keep each signer's backup separately. See the
[shared-wallet guide](docs/vaults.html) for setup and signing limits.

## Connections and privacy

Winnow connects to Bitcoin peers and matches compact block filters on your
device. It does not send your address watch list to a wallet-history server.
Direct peers can still observe your IP address, requests and relay traffic.
The app syncs while open and during short background checks scheduled by iOS;
new payments may appear at the next sync.

You can use your own filter-serving node or route peer connections through Tor
and I2P SOCKS gateways on your Tailscale network. Winnow bundles no Tor or I2P
client. See [peer gateway setup](docs/peer-gateways.md). Explorer links open an
external website after a privacy warning; they do not supply wallet balances.

## Backups

Keep a current manual backup file and your recovery words. The default file
excludes the words and restores a watch-only wallet. To restore signing through
the file-import screen, the file must include the recovery phrase; that screen
has no separate word entry. Winnow scans forward from a backup's recorded
height, so words alone do not reconstruct its past transaction history.

Automatic iCloud backup is enabled by default when available. It saves an
encrypted copy containing this phone's signing secret and wallet state. A
successful save date confirms an upload. Keep the manual file and words as
well, and back up other signers independently. The
[backup guide](docs/import.html) explains the formats and their limits.

## Development

Start with the [architecture guide](docs/architecture.md) for source ownership,
module dependencies and directory links. The [testing guide](docs/testing.md)
explains local checks, CI evidence and what still needs physical-device testing.
[Release operations](.github/internal/ci-release.md) covers TestFlight and
App Store Connect.

For package tests on a Mac with the Swift toolchain installed:

```sh
swift test
```

For the app, install Xcode and use the pinned XcodeGen 2.46.0. From the repository
root, fetch the public peer census before generating the project:

```sh
scripts/import-census
scripts/install-xcodegen
"${RUNNER_TEMP:-${TMPDIR:-/tmp}}/winnow-xcodegen-2.46.0/xcodegen/bin/xcodegen"
open WinnowApp.xcodeproj
```

The generated project and build products are ignored. Select the WinnowApp
scheme and an iPhone simulator. [App test commands](docs/testing.md#run-locally)
and [debugging tools](Tools/Debug/README.md) cover the next steps.

The public website is maintained in
[winnowwallet/website](https://github.com/winnowwallet/website). This repository
contains the app's offline guides and engineering records; wallet CI retains
test evidence without deploying the site. The [roadmap](https://winnowwallet.com/roadmap)
tracks proposed work separately from current behavior.

Winnow is available under the [MIT License](LICENSE).
