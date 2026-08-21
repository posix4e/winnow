# Winnow security audit manifest

Status: **Phase 0 baseline; not a mainnet approval**

This file freezes the source and evidence boundary for security-hardening epic
[#100](https://github.com/posix4e/winnow/issues/100). A checked box or passing
test proves only the named property. It is not a general wallet-safety claim.

## Frozen target

| Item | Value |
|---|---|
| Source commit | `98d90563a2c20b7137c708cb121e72b9b34552a3` |
| Commit date | 2026-08-20 06:55:20 -04:00 |
| Swift | Apple Swift 6.3.3 (`swiftlang-6.3.3.1.3`) |
| Xcode | 26.6 (`17F113`) |
| Host target | `arm64-apple-macosx26.0` |
| Installed iOS runtimes | 26.4.1, 26.5 |
| Minimum package platforms | iOS 17, macOS 14 |
| Build configuration exercised | SwiftPM debug |
| Baseline command | `swift test` |
| Baseline result | 310 tests in 60 suites passed |
| Hardened branch result | 311 tests in 60 suites passed; targeted PSBT AddressSanitizer run passed; iOS simulator build passed |

The baseline run did **not** execute suites gated by `WINNOW_DIFF`,
`WINNOW_SIGNET`, or the checkpoint-generation environment. App/UI tests and an
iOS release configuration were also outside this run. Those are open evidence
items, not implied passes.

## Size and dependency boundary

Counts use `cloc 2.08`, exclude comments, blank lines, dependencies, generated
projects, tests, and documentation, and are measured at the frozen commit.

| Production surface | Files | Logical lines |
|---|---:|---:|
| Bitcoin primitives | 20 | 2,771 |
| P2P networking | 17 | 3,022 |
| Optional blockchain backends | 2 | 166 |
| Wallet and signing core | 19 | 2,501 |
| iOS application/UI | 14 | 3,501 |
| **Production total** | **72** | **11,961** |
| **Core before UI** | **58** | **8,460** |

The only external Swift package is
`21-DOT-DEV/swift-secp256k1` version `0.23.2`, resolved to commit
`e70a10e036a55fffea31568f0af92d69b6d449cd`. It exposes the `P256K` product
with MuSig, Schnorr, recovery, and ECDH traits. `Package.resolved` is part of
this audit branch so builds record the reviewed revision rather than only a
version label. Provenance review and update policy remain Phase 7 work.

## Severity rules

| Severity | Release meaning |
|---|---|
| Critical | Practical unauthorized fund loss or broad secret extraction. Stop release; handle exploitable details privately. |
| High | Authorization bypass, key/nonce compromise, unintended spend path, or trusted-state corruption under a credible attacker. Stop release. |
| Medium | Security control weakness needing meaningful preconditions, bounded privacy disclosure, recoverable corruption, or resource exhaustion. Fix or record owner, mitigation, and release decision. |
| Low | Defense-in-depth, diagnostic, or hardening gap without a credible direct loss path. Track normally. |

Availability becomes high only when a credible input can permanently strand
funds or destroy the only usable recovery state. Findings are scored by impact
and credible prerequisites, not by code location.

## Trust boundaries

1. **Device secret boundary:** recovery words and extended private keys enter
   `KeyStore`, iOS Keychain, derivation, signing, authenticated reveal, and
   explicitly seed-bearing export paths.
2. **Authorization boundary:** SwiftUI review state feeds wallet transaction
   construction, PSBT fields, sighash calculation, signing, finalization, and
   broadcast. Mutation after review must fail closed.
3. **Untrusted network boundary:** DNS, peers, Esplora, and the experimental
   silent-payment index supply attacker-controlled bytes or JSON.
4. **Untrusted interchange boundary:** addresses, descriptors, cosigner keys,
   PSBTs, and import bundles are attacker-controlled text/files even when they
   arrive from a known person.
5. **Persistent-state boundary:** wallet JSON, vault JSON, headers, filter
   progress, peer cache, settings, export staging files, and E2E journals have
   different authority and confidentiality.
6. **Build/distribution boundary:** package revisions, GitHub Actions, Xcode,
   signing credentials, TestFlight, and published evidence determine whether
   reviewed source is the source users receive.

## External disclosure inventory

Every point at which bytes can leave the device, and what each one carries.
Re-derive with `grep -rn "URLSession\|NWConnection\|getaddrinfo" Sources/`.

| Egress | Transport | Carries | When |
|---|---|---|---|
| Peer connections | `NWConnection` (`BitcoinP2P/Transport/PeerConnection.swift`) | BIP157/158 filter and header requests, and transactions the user broadcasts | Always: this is how the wallet reads the chain |
| DNS seeds | DoH over `URLSession`, falling back to `getaddrinfo` (`Peers/SeedResolver.swift`) | Seed hostnames only | At startup, to find peers |
| Silent-payment tweak index | `URLSession` (`BlockchainBackend/TweakIndexHTTPClient.swift`) | A block height — `GET /tweaks/{height}` | Only when the user enables silent-payment receive and sets a server |
| Block explorer | **none** | — | Never contacted. The setting builds a link the user may tap; `EsploraClient` is not instantiated anywhere in `Sources/` |

Two things are worth stating plainly because they are easy to erode.

The tweak index is told a height, never an address. A server that learned
addresses would be a hidden wallet-read path wearing a privacy-preserving
name, so the request is captured and inspected in
`ExternalDisclosureTests` rather than argued for from the call site.

`EsploraClient` exists and its API is address-based — `/address/{a}/utxo`.
That is exactly why the app does not use it. Wiring it into sync to make
scanning faster would, in one step, turn a wallet that tells no server
anything into one that tells a server every address it owns.

## Production source inventory

Every production file is listed below. “Owner” means the responsible module,
not a named person; a named human reviewer is still required before Phase 8.

### BitcoinCore — owner: primitives review

Parsed input and trust boundary: keys, addresses, descriptors, scripts, vector
and transaction-derived bytes. Secrets: BIP39/BIP32 keys, signing tweaks,
MuSig2 nonces. Persistence: none directly. Primary test owners:
`BitcoinCoreTests`, `WalletCoreTests`, and `DifferentialTests`.

- `Crypto/Base58.swift`, `Crypto/Bech32.swift`, `Crypto/GCSFilter.swift`
- `Crypto/PBKDF2.swift`, `Crypto/RIPEMD160.swift`, `Crypto/SipHash.swift`, `Crypto/TaggedHash.swift`
- `Descriptors/Descriptor.swift`, `Descriptors/MuSig.swift`, `Descriptors/MuSig2.swift`
- `Keys/BIP32.swift`, `Keys/BIP39.swift`, `Keys/BIP39Wordlist.swift`, `Keys/BIP86.swift`
- `Script/Multisig.swift`, `Script/Script.swift`, `Script/Taproot.swift`
- `SilentPayments/Receiving.swift`, `SilentPayments/Sending.swift`, `SilentPayments/SilentPaymentAddress.swift`

### BitcoinP2P — owner: network/chain review

Parsed input and trust boundary: arbitrary peer and DNS bytes. Secrets: none;
addresses and watched transaction data are privacy-sensitive. Persistence:
header chain, filter frontier, peer cache, and broadcaster state. Primary test
owners: `BitcoinP2PTests`, `DifferentialTests`, and wallet integration tests.

- `BitcoinP2P.swift`, `Broadcast/TxBroadcaster.swift`, `Filters/FilterSync.swift`
- `Headers/HeaderChain.swift`, `Headers/UInt256.swift`, `Mempool/MempoolWindow.swift`
- `Peers/PeerPool.swift`, `Peers/SeedResolver.swift`
- `Protocol/Block.swift`, `Protocol/Framing.swift`, `Protocol/Inventory.swift`, `Protocol/Messages.swift`
- `Protocol/NetworkParams.swift`, `Protocol/PeerAddress.swift`, `Protocol/Transaction.swift`, `Protocol/Wire.swift`
- `Transport/PeerConnection.swift`

### BlockchainBackend — owner: optional-service review

Parsed input and trust boundary: HTTP status, payload sizes, and remote JSON.
Secrets: none; queries can disclose wallet-linked information. Persistence:
none directly. Primary test owners: `EsploraClientTests` and silent-payment
pipeline tests.

- `EsploraClient.swift`, `TweakIndexHTTPClient.swift`

### WalletCore — owner: wallet authorization review

Parsed input and trust boundary: persisted wallet state, addresses, descriptors,
PSBTs, cosigner keys, and import/export bundles. Secrets: recovery words, master
keys, derived signing keys, and silent-payment spend/view material. Persistence:
Keychain, wallet JSON, and export staging files. Primary test owner:
`WalletCoreTests`, with vector and differential coverage from lower layers.

- `Internal/Serialization.swift`
- `Keys/KeyStore.swift`, `Keys/KeychainStore.swift`
- `PSBT/PSBT.swift`, `PSBT/PSBTRoles.swift`
- `Transactions/AddressDecoder.swift`, `Transactions/SighashBIP341.swift`, `Transactions/Signer.swift`
- `Transactions/SilentPayment.swift`, `Transactions/TransactionBuilder.swift`
- `Wallet/CoinSelection.swift`, `Wallet/ExportStagingFile.swift`, `Wallet/FeePolicy.swift`
- `Wallet/ImportBundle.swift`, `Wallet/SilentPaymentSync.swift`, `Wallet/Vault.swift`, `Wallet/VaultSetup.swift`, `Wallet/Wallet.swift`
- `WalletCore.swift`

### WinnowApp — owner: iOS authorization/UI review

Parsed input and trust boundary: user text, clipboard, files, settings, app
lifecycle, device authentication, and E2E launch environment. Secrets: recovery
display/copy, wallet creation handoff, and seed-bearing export. Persistence:
UserDefaults, app files, vault store, and E2E journal. Primary test owners:
`AppTests`, `UITests`, plus library tests for logic that remains below the UI.

- `AppModel.swift`, `Components.swift`, `E2EMode.swift`, `HomeView.swift`
- `OnboardingView.swift`, `ReceiveView.swift`, `SendView.swift`, `SettingsView.swift`
- `VaultDetailView.swift`, `VaultSignView.swift`, `VaultStore.swift`, `VaultsView.swift`, `WinnowApp.swift`
- `Assets.xcassets/AppIcon.appiconset/Contents.json`

## Baseline evidence and gaps

- Present: BIP/vector suites; parser negatives; wallet create/send/RBF/import;
  Taproot script-path and MuSig2 flows; peer loopback, failover, filter, and
  broadcaster tests; story redaction/idempotency checks.
- Not executed here: Bitcoin Core differential tests, public/custom signet
  integrations, checkpoint agreement/generation, iOS Keychain behavior, app
  build, device authentication, background/screenshot/clipboard behavior, UI
  mutation-after-review, sanitizers, fuzzing, and release provenance.
- Structural gap: `KeychainStore` states that entitlements prevent SwiftPM
  coverage. This requires a full-Xcode integration test and manual device check;
  source review alone is not equivalent evidence.
- Reproducibility gap addressed in this branch: the dependency lockfile was
  ignored. The manifest already used an exact version, but did not record the
  resolved commit in the repository.
- Hostile-input gap addressed in this branch: PSBT raw/Base64 documents, maps,
  keys, input/output counts, and known fixed-width fields now have explicit
  limits and fail with ordinary errors instead of trapping on oversized
  CompactSize values. The regression is recorded as `SEC-001`.

## Change control

The frozen commit remains the comparison base. Each bounded security PR must
name the invariant, tests, residual risk, and rollback. Unrelated refactors in
the inventoried modules should wait until the first review pass or be reviewed
as changes to the audit target. Exploitable findings remain private until fixed.
