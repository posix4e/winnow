# Winnow

Winnow is a Bitcoin wallet for iPhone and iPad, also available on Apple silicon
Mac as an iPad app. It receives and sends bitcoin and saves recipients. This
build signs with this phone's key, alone or as one signer of a k-of-n multisig
account, and the curve arithmetic behind every signature is Winnow's own Swift.

[App Store](https://apps.apple.com/app/id6801502501) ·
[TestFlight](https://testflight.apple.com/join/83djpNE7) ·
[User guides](https://winnowwallet.com) ·
[Report a bug](https://github.com/winnowwallet/winnow/issues)

## Using the wallet

Winnow starts on mainnet in Simple mode. One screen holds your balance,
Receive, Send, activity and backup status. Open a payment to
save its recipient; choose saved recipients from the Send form.

Advanced mode adds Wallet, Send and Settings tabs, with signet, manual peers,
fee controls and recovery words. Switching modes keeps your wallet and
settings. Use signet and test funds when trying a development build.

Advanced mode adds raw k-of-n multisig accounts: a
`tr(NUMS, sortedmulti_a(k, …))` descriptor in, addresses and PSBTs out, signed
by any k signers in any order with no rounds between them. "New multisig
account" builds one from this phone, other Winnows' keys and a Ledger, for
example a 2-of-3 of two phones and a Ledger, with an optional recovery path: a
coin that has not moved for a chosen number of blocks can then be spent by
fewer of the same signers, or by a separate recovery key. A Ledger (Bitcoin
app 2.1.2 or later; 2.2.1 for a recovery path) can be a signer: Winnow pairs with it
over Bluetooth, registers the account on it, and asks it to sign after it shows
the payment on its own screen ([Ledger signer](Sources/WalletCore/Ledger/README.md)).
There are no MuSig2 accounts, cosigner cards or shared-savings screens. A backup carrying a MuSig2
account from the shared-account Winnow is refused rather than restored without
those funds.

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
well. The
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
