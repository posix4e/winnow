# Winnow

Winnow is a Bitcoin wallet for iPhone and iPad, also available on Apple silicon
Mac as an iPad app. It receives and sends bitcoin and saves recipients. This
build signs with this phone's key, alone or as one signer of a k-of-n multisig
account. It is written in Lean 4: the wallet, the networking and the app's
model, update and view, compiled to C and rendered by ElmLean's generic native
shell; the curve arithmetic behind every signature is the proven secp256k1 in
`Lean/Secp`.

[App Store](https://apps.apple.com/app/id6801502501) ·
[TestFlight](https://testflight.apple.com/join/83djpNE7) ·
[User guides](https://winnowwallet.com) ·
[Report a bug](https://github.com/winnowwallet/winnow/issues)

> **Port status.** This branch brings the Lean port up to upstream 0.8.13 and the
> Ledger signer (winnowwallet/winnow#255). The sections below describe that
> version; [PORT.md](PORT.md) lists what the Lean code has reached so far and how
> each part is verified.


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

## Layout

- `Lean/`: the wallet in Lean 4 (`Winnow/`): keys, transactions, PSBTs, descriptors, vaults and
  MuSig2, the wallet, compact-filter sync, peers, mempool windows and the broadcaster, over libuv TCP.
  `Secp/` is the proven secp256k1. `IOTest.lean` (`io-test`) runs the network layer against a disposable
  regtest bitcoind.
- `LeanApp/`: the app: `WinnowApp/` holds the model, update, views and commands (Elm-style, ElmLean),
  `WinnowApp/Real/` the backend, `WinnowApp/E2E.lean` the Debug-only test mode. `ios/` is the XcodeGen
  project that links the Lean-generated C with ElmLean's native shell (renderer, C shim, capabilities:
  Keychain, device authentication, clipboard, HTTPS, paths). The shell's Swift is printed from Lean at
  build time into `ios/build/native-shell/` and is not checked in.
- `docs/`: the website and the papers the app bundles.
- [PORT.md](PORT.md): how the port was done and verified, and what differs from the Swift original
  (removed from this tree; it remains in the history before this port).

## Build & test

```sh
scripts/import-census                       # the census peer list the app ships (build/census)
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

The public website is maintained in
[winnowwallet/website](https://github.com/winnowwallet/website). This repository
contains the app's offline guides and engineering records. The
[roadmap](https://winnowwallet.com/roadmap) tracks proposed work separately from current behavior.

## License

Winnow is available under the [MIT License](LICENSE).
