# Winnow in Lean: the port

Goal: all of Winnow written in Lean 4 (ElmLean for the app), with **no Winnow-specific Swift**.
This file is the plan and the status board; it is updated as each module lands.

## What "no direct Swift" means here

* Every line of `Sources/WalletCore` and `Sources/WinnowApp` is replaced by Lean: wallet logic,
  crypto, networking, storage, timers, and the app's `Model`/`Msg`/`update`/`view`.
* The Lean code is compiled by Lean's own compiler to C and linked into the iOS app together with
  Lean's runtime and standard library (`libleanrt`, `libInit`, `libStd`, `libuv`, `libgmp`), retargeted
  to iOS. Networking uses Lean's libuv TCP; there is no Swift networking.
* The only Swift in the app is **generic ElmLean framework code**, the same for any app, and it is
  **generated**: a SwiftUI renderer of the view tree Lean produces, the store around a small C shim
  (runtime start-up, callbacks), and a capability host for what only iOS can do: Keychain, Face ID /
  passcode, clipboard, share sheet, opening bundled pages. Winnow names none of its types. Since
  2026-10-27 (the user accepted generated Swift, provided it is not checked in) no Swift source exists in
  either repository: the framework holds the shell as Lean data (`framework/lean/ElmShell`), and
  `ios_lean_sources.sh` has `lake exe elmshell` print it into `LeanApp/ios/build/native-shell/`
  (gitignored) on every build. Its grammar-dependent parts (node cases and decoding, the render dispatch,
  string enums, events) come from one table that the framework's build checks against `Wire.toJson` and
  `Event.fromJson?`.
* This is ElmLean's **native mode** (full Lean, compiled to C, generic renderer). It brings back a
  generic in-process renderer, which was dropped earlier in favour of generated SwiftUI; the difference
  from the dropped served mode is that there is no server and no second process. ElmLean keeps its
  **generated mode** (elmgen, subset apps such as Todo, Counter, Send) alongside.

## Scope

* Ported: `Sources/WalletCore` (≈18,100 lines) and `Sources/WinnowApp` (≈9,900 lines).
* **Removed (2026-10-27, at the user's request):** the Swift original and everything that compiled
  against it — `Sources/`, the Swift tests (`Tests/`, `AppTests/`, `UITests/`), `Package.swift` and its
  lockfile, the Swift app's `project.yml`, the Swift tools (`Tools/Debug|Fixture|Fuzz|Generate`), the
  Swift-app CI/release/site scripts and `.github/workflows`. The tree holds no `.swift` file; the only
  Swift in the app is the generic ElmLean shell, generated at build time (above). The original remains in
  history at `9cca3fc`.
* **During the port** the Swift WalletCore was the **oracle**: for each module, a Swift driver exercised
  the original and a Lean CLI answered the same requests, compared step by step. The results below were
  recorded against it. The harness (Swift drivers, `gen/*.py`, `lockstep.py`, the Swift `Package.swift`
  with the oracle products) was moved out of the tree to `~/src/winnow-lean-swift-archive/LeanOracle`
  ("`LeanOracle/…`" in Lean comments means that harness); to rerun it, restore `Sources/` from `9cca3fc`
  next to it. The Lean-side oracle executables (`Lean/Oracle*.lean`, `LeanApp/Oracle*.lean`) are kept.
  `io-test --swift` likewise needs the archived `oracle-io`; without it `io-test` runs its 73 Lean checks.
* Platform APIs replaced: CryptoKit / CommonCrypto / P256K → Lean crypto; Network → Lean TCP;
  CoreImage QR → a QR encoder in Lean and a `qr` node; WKWebView (bundled design papers) → a generic
  bundled-page node; Security (Keychain), LocalAuthentication, UIKit pasteboard/share → capabilities.

## Known fragility

* The runtime libraries are macOS arm64 objects with their Mach-O `LC_BUILD_VERSION` rewritten to the
  iOS simulator (`retarget_ar.py`). Lean does not support this. Verified: the simulator runs Lean code
  with GMP, tasks and libuv TCP (2026-10-26). Device (platform 2): the demo links (unsigned); not run on a device.
* iOS suspends background apps and drops sockets: the peer layer needs reconnect-on-foreground.
* HTTPS (census catalog, DNS-over-HTTPS, explorer) cannot be Lean: Lean's runtime links OpenSSL but exposes
  no TLS API, and `Std.Http` is server-only. It is the generic shell capability `http.get` (URLSession,
  ephemeral, same-host redirects only, never https→http); `RoutedHTTPClient`'s policy is ported to Lean.
  Bitcoin P2P is plain TCP and stays Lean (libuv).

## Tracking upstream 0.8.13 and the Ledger signer

On 2026-10-27 the user asked for the port to follow the newer upstream: winnowwallet/winnow#255
(`ledger-on-main`, 1cf93fb, "Ledger Nano X as a signer of Taproot multisig accounts"), which is on
upstream `main` at 0.8.13 (#252: raw Taproot multisig accounts in Advanced mode replace vaults). That is 43
upstream commits after this port's base: upstream's f4bab06 has the same tree as 9cca3fc. The Swift
changes are Sources/WalletCore 60 files (+6,593/−4,217) and the app 35 files (+4,466/−3,545). No new
third-party dependency.

- Branch `lean-port-ledger`. Its merge commit 5acf15d has 1cf93fb as a parent and applies exactly
  `f4bab06..1cf93fb` minus the Swift sources, tests, tools and workflows, so a PR based on `ledger-on-main`
  shows only the Lean work.
- Oracle: the Swift at 1cf93fb, checked out at `~/src/winnow-ledger` (kept pristine). The lockstep harness in
  `~/src/winnow-lean-swift-archive/LeanOracle` builds its oracle products against that checkout's `Sources/`.

| Phase | Upstream Swift | Status | Verified by |
|---|---|---|---|
| A. Removals | Vault, VaultRecord, VaultSetup, MuSig/MuSig2 descriptors, CensusSignature, CensusCatalogStore, FallbackPeersGenerated; the app's vault, shared-savings and MuSig2 screens and stores; their parts of People, PSBTRoles, Descriptor, ImportBundle (a bundle with a MuSig2 account is refused) | **done** (91c6e91, dc439e3): a bundle with accounts is refused (`unsupportedWalletData`); the census is the list shipped with the build (`CensusCatalog.bundled`), but importing it into the iOS build (scripts/import-census plus a resource line in project.yml) is still to do | every Lean target builds; records-test 99/99, backend-test 76/76, io-test 71/71; the simulator app builds and launches |
| B. WalletCore: multisig | Descriptor and Script/Multisig changes (`tr(NUMS, sortedmulti_a(k, …))` with recovery paths), MultisigAccount, PSBTRoles, HistoryOutputs, and the Wallet, KeyStore/BIP32 and FeePolicy changes they need | not started | lockstep per area against 1cf93fb; a Lean `multisig-differential` against Bitcoin Core (upstream's scripts/check-multisig-core) |
| C. Ledger, pure | LedgerAPDU, LedgerMerkle, LedgerWalletPolicy, LedgerClientCommands, LedgerBitcoinClient, LedgerMultisig | not started | lockstep with recorded APDU exchanges |
| D. App | AppModel's multisig and Ledger parts, MultisigStore, MultisigViews, MultisigBuildView, LedgerViews, LedgerBluetooth's protocol | not started | records/app tests mirroring upstream's MultisigStoreTests, MultisigAccountFlowTests, LedgerPairingTests; simulator in test mode |
| E. Shell capability | Bluetooth (GATT) for the Ledger: a generic capability row in ElmLean's shell (`framework/lean/ElmShell/Capabilities.lean`, Objective-C), not Winnow code | not started | E2E fake: a Ledger transport answering recorded APDUs |

Scope, as the user set it on 2026-10-27: the Ledger signer and the Taproot multisig ("ledger, and the fancy
multi, no need for musig2 right now"). The other upstream changes in this range are deferred, not ported
yet: silent-payment sending (BIP352), automatic iCloud backup (CloudKit), background sync, Tor/I2P peer
gateways over Tailscale, RangeScan, the peer-pool and broadcaster changes, the census shipped with the build,
and Onboarding/Home/Settings changes outside multisig.

The layer table below was written for the 0.7.3 port. Phase A removed its MuSig2 (layer 4), musig()
descriptors and MuSig2 rounds (layer 7), vaults and vault records (layer 8), fallback peers and the signed,
downloaded census (layer 9), and VaultStore, shared savings and approvals (layer 10). The test counts there
are now records-test 99, backend-test 76 and io-test 71 (before: 192, 84 and 73).

The simulator has no Bluetooth, so phases D and E are verified with a test-mode fake and the pure oracles.
A device run with a Ledger is not claimed until one happens.

## Layers and status

Each module is done when its lockstep run against the Swift original passes and its vectors pass.

| Layer | Modules | Status |
|---|---|---|
| 0. Native runtime | ElmLean native mode: C ABI, renderer, capabilities, iOS build | **done (simulator)**: examples/native-demo in ElmLean runs a Lean view, a Lean background task, Lean TCP and the `auth` capability; links for device, not run |
| 1. Bytes | hex, little/big-endian, CompactSize, readers/writers | **done** (`Lean/Winnow/Bytes.lean`) |
| 2. Hashes | SHA-256, SHA-512, HMAC, PBKDF2-HMAC-SHA512, RIPEMD-160, SipHash, tagged hash | **done**: lockstep `a_crypto` OK, seeds 1–5 (3,169 requests per seed at 300 cases) |
| 3. Encodings | Base58(check), Bech32/Bech32m, segwit addresses (GCS filters moved to Net) | **done**: same lockstep |
| 4. Curves | **done**: secp256k1 as WalletCore uses P256K (on the proven `Secp`), BIP340, MuSig2 (BIP327), Ed25519 (RFC 8032) + census signatures — lockstep `b_p256k b_musig b_ed25519` OK seeds 1–3 |
| 5. Keys | **done**: BIP32, BIP39 (+ Foundation-exact NFKD), BIP86, Taproot, KeyStore + in-memory store — lockstep `b_bip32 b_bip39 b_bip86 b_taproot b_keystore` OK seeds 1–3; Keychain store becomes the shell's keychain capability |
| 6. Script, Transactions | wire, transactions, scripts, multisig, addresses, sighash (BIP341), builder, funding sources | **done**: lockstep `c_wire c_transaction c_script c_address c_sighash c_builder c_funding` OK seeds 1–3; BIP341 vectors (23 sighashes) match |
| 7. Descriptors, PSBT | **done**: PSBT format (`c_psbt`), descriptors (`e_descriptor`), Signer + PSBT roles incl. MuSig2 rounds (`e_psbtroles`, whole flows compared step by step) — OK seeds 1–3 |
| 8. Wallet | **done**: fee policy, wallet data types + wallet.json (sorted-keys form), coin selection, export staging, the wallet itself (create/open/import, scan, receive, send, fee bump, reorgs), vaults (multi_a and MuSig2 spends), vault records and setup, people, import bundles — lockstep `e_feepolicy e_types e_coinselection e_descriptor e_psbtroles e_wallet e_vault e_people` OK seeds 1–3 (and 7). Random draws (aux rand, nonces, change position) are compared by shape. Untested: persist-failure paths, the 64 MB state limit; Swift traps on some UInt32 overflows where Lean wraps (inputs avoided). `SwiftJSON.parse?` skips one leading byte-order mark as `JSONDecoder` does (2026-10-27; tested through `f_records` raw-byte prefixes, since the oracle transport's `JSONSerialization` drops one leading U+FEFF from Swift-side string fields); `e_types e_people e_vault e_wallet` rerun OK seeds 1–3. Swift `Character`s (`Wallet/Characters.lean`): the full UAX #29 segmenter (GB9b Prepend, GB9c Indic conjuncts, GB11, SpacingMark incl. Thai/Lao SARA AM) over property tables measured from Swift 6.4 itself (`Tools/LeanOracle/Characters/tables.py` regenerates `CharactersData.lean`); fuzzed against Swift with ~1.35 million strings, 0 disagreements. The Keys area's `split(separator:)` (BIP39 words, key-store lines) now splits on those `Character`s too (lockstep `b_bip39` with joining-separator cases, `b_keystore` OK seeds 1–3) |
| 9. Network | data **done**: GCS filters, UInt256, headers + HeaderChain (retarget, reorg, storage), params, fallback peers, addresses, inventory, framing, blocks, messages, FilterSync/MempoolWindow pure logic — lockstep `d_gcs d_headers d_protocol d_filters` OK seeds 1–3 (BIP158 vectors, 2,000 mainnet headers); I/O **done** (`Lean/Winnow/IO`: transport over libuv TCP, peer pool, seeds, diversity, census, header/filter sync, mempool window, broadcaster, HTTP policy with injected fetch): `io-test` 83/83 against a fresh regtest bitcoind, and Winnow's Swift against the same node gives the same tip, matches, filter header and byte-identical headers.bin; gaps listed in `IO.lean` (live HTTPS, fsync, cancellation) |
| 10. App | AppModel and every view, as an ElmLean native app (`LeanApp/`, survey in `Lean/APP-SURVEY.md`) | **done** except the gaps below: every screen ported. `Backend.real` (`Real/Full.lean`) joins two halves through `Hooks`: the core (`Real/{Base,Stack,Wallet,Send,Peers,Shell,Assemble}.lean`: wallet, storage, network stack, 45 s sync loop, receive, send, fee bump, census, backup) and the records (`Real/Records*.lean`: VaultStore, PeopleStore, ReceiveAddressLabelStore as sealed files keyed from the Keychain; people, pastes, sender lookup, vaults, shared savings, the vault send path, approvals, MuSig2). `records-test` 192/192; lockstep `f_records` OK seeds 1–3 (sealing, store files under every wrap, people mutation scripts byte-exact, derived data, pastes, labels, explorer answers). `backend-test` 84/84 against a fresh regtest bitcoind (create, backup-pending, sync, receive, send, RBF bump, a 2-of-2 shared savings funded from the wallet and credited by the sync loop, the vault payment marked as owned, a vault spend previewed and prepared only as reviewed, export/import carrying the vault and its coins, stop leaves no loop, reopen, delete). Pure helpers (`Pure.lean`): lockstep `f_pure` OK seeds 1–4 (5,559 requests per seed: sync text, history rows, explorer URLs with Foundation's URL rules, peers, labels, fee warning, rate parsing with Swift's `Double(String)` grammar, the bump suggestion from the unrounded rate, thresholds, approvals, MuSig2 labels); it found and fixed six port bugs. Renderer parity (2026-10-27, framework changes with `make check` green): the steppers show "2 of 3" in one row as SwiftUI's `LabeledContent` does, both home screens pull to refresh (`syncNow`), the backup is staged as `winnow-export-<UUID>/winnow-<network>-<id>.json` (excluded from backup, `FileProtectionType.complete`, removed on reset/close/background and swept at boot) and shared as a file, fee-rate fields use the decimal pad. Gaps: the records keep store keys as `.masterKey <hex>` Keychain items where Swift keeps raw bytes (files are shared, Keychain items are not); Test mode (E2EMode.swift → `WinnowApp/E2E.lean`, 2026-10-27): Debug builds only (the shell's `build` capability), `WINNOW_E2E=1` with pinned entropy (fails closed without), run-scoped storage and Keychain service with reset, manual peer, custom signet, peer count, sync interval, census URL/keys, forced network (picker locked), first tab, advanced mode, clipboard and control file, device authentication skipped unless asked, and the event journal with Swift's secret filters; lockstep `f_e2e` OK seeds 1–5. In it the simulator app created a wallet from pinned entropy (words checked against BIP39), received 1,000,000 sats from a regtest node and sent 300,000 back (fee 710 as reviewed; the node's mempool held exactly that transaction; confirmed at block 104, balance 699,290). The journal records every event AppModel journals, at the same points with the same field names and formats (backend-test checks 24 of them; 84/84). A second run journaled the create, sync and receive with Swift's field sets, and the app's own send: the journal's `raw` decoded to the txid in the node's mempool, and the file never contained the entropy or the words. Store MACs compare in constant time as CryptoKit's do; the records files get `completeUntilFirstUserAuthentication`, Swift's explicit write option, as iOS's default class (the app has no data-protection entitlement). |
| 11. Integration | the app on the iOS Simulator against a Bitcoin node | regtest **done**: the simulator app imports a watch-only backup and verifies it over Lean TCP, syncs headers and filters, shows an unconfirmed payment within seconds (mempool window), picks up the confirming block in the 45 s loop, and reopens from disk (`backend-test --fixture <dir>` starts the node). Independence (2026-10-27): a copy of `Lean/`, `LeanApp/` and `docs/` with no `.swift` file and no `Sources/` builds from a clean Lean build to the iOS app; its only Swift compilations are the framework's five shell files (Capabilities, NativeApp, NativeNode, NativeStore, NativeView), which since 2026-10-27 are generated into `ios/build/native-shell` by `lake exe elmshell` rather than checked in. With the generated shell (2026-10-27) the app built and, in test mode in the simulator, created a wallet, synced from signet peers, took a typed label through the Receive sheet and showed the address and its QR code; after formatting, the generated files match the hand-written ones they replaced except for binding names and case order. `Sources/` remains only as the lockstep oracle. Outside test mode, sending in the simulator stops at device authentication: even a freshly created iOS 26.4 simulator shows the system passcode prompt at the app's `auth` step, and no passcode is entered for it. `NormalModeSendUITests.swift` (archived with the oracle harness in `~/src/winnow-lean-swift-archive`; restore a seed-bearing fixture backup, then send; inputs via TEST_RUNNER_WINNOW_UI_*) reaches that prompt and runs where authentication can pass. Accepted 2026-10-27: sending is verified by test mode in the simulator (the node's mempool held exactly the reviewed transaction) and by `backend-test`, since no simulator passcode is available; in test mode (below), which skips it as Swift's does, create, receive and send all ran in the simulator app. Signet **done** (2026-10-27): from a clean install the simulator app finds real signet peers itself (seeds/DoH through the shell's `http.get`), imports a watch-only backup, syncs headers from the built-in checkpoint (258,000) to the tip (328,174) and verifies the backup by filter-scanning 327,674–328,174, in about 90 s. Records on signet (2026-10-27): a co-owner added from a pasted card, a 2-of-2 shared savings created and shown, its sealed `vaults.json` / `people.json` reopened after a restart. Simulator builds are ad-hoc signed: unsigned, the app has no Keychain entitlement and every Keychain write fails (-34018). |

## How to port a module (the pattern every area follows)

Layout during the port (the Swift parts are now in the archive, see Scope):

| What | Where |
|---|---|
| Lean code of area `A` (`Keys`, `Tx`, `Net`, `Wallet`) | `Lean/Winnow/A/*.lean`, each imported by the aggregator `Lean/Winnow/A.lean` |
| Lean oracle ops of area `A` | `Lean/Oracle/A.lean` (list `aOps`), executable `oracle-a` (`Lean/OracleA.lean`) |
| Swift oracle of area `A` (Winnow's original WalletCore) | `Tools/LeanOracle/A/main.swift` (`ops["name"] = { r in … }`), product `oracle-a` |
| Request generators | `Tools/LeanOracle/gen/<n>_<module>.py` with `AREA = "a"` and `cases(rng, n)` |
| Shared helpers | Lean: `Lean/Oracle/Base.lean`; Swift: `Tools/LeanOracle/Common/Oracle.swift`; Python: `gen/_util.py` |

Commands:

```
cd Lean && lake build Winnow.A oracle-a                                  # Lean side
swift build -c release -Xswiftc -enable-testing --product oracle-a       # Swift side (from the root)
python3 Tools/LeanOracle/lockstep.py 300 1 <generator file stem>         # compare
```

Rules:

* **Same behaviour, same errors.** The Lean function returns what the Swift one returns, and fails
  where it throws, with the same error case name (`{"error":"<caseName>"}`; the Swift side prints
  `kind(error)`, the enum case without its payload). Mirror the Swift types as Lean structures and
  inductives with the same field and case names.
* **Requests are data**: bytes as hex strings, 64-bit integers as decimal strings, small ints as JSON
  numbers. Replies must serialize identically on both sides (`{"ok":…}`).
* **Generators** cover random inputs, edge cases (lengths, boundaries, malformed encodings) and the
  published vectors Winnow's tests use (`Tests/**/Vectors`, BIP vectors). A module is done when its
  generator passes for several seeds with both successes and refusals exercised.
* **Lean style**: ordinary Lean 4 (v4.35, no Mathlib); `ByteArray` for bytes, `Except` for failures,
  `Winnow.Reader` for parsing. Reuse `Secp` (proven secp256k1: field, curve, BIP340, tweaks) instead of
  re-implementing curve arithmetic. Proofs are welcome but not required for a port.
* **Scope** (during the port): an area touched only its own files above, never `Package.swift` or `Sources/`.
