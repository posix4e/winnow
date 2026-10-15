# Wallet architecture

Winnow's app owns the user interaction and device integration. Two Swift
libraries provide its Bitcoin and shared-account rules. The app and development
tools use the root [Package.swift](../Package.swift) and
[Package.resolved](../Package.resolved).

## Source ownership

| Component | Owns | Depends on |
| --- | --- | --- |
| [WinnowApp](../Sources/WinnowApp/README.md) | SwiftUI screens, payment review, authentication, lifecycle, persistence, background scheduling and iCloud backup | WalletCore, VaultKit and Apple frameworks |
| WalletCore | Keys, descriptors, scripts, PSBTs, transactions, wallet state and Bitcoin P2P networking | P256K from swift-secp256k1 |
| [VaultKit](../Sources/VaultKit/README.md) | People and public contact cards, shared-account setup, vault spends and approvals | WalletCore's public interface and P256K |
| [TestSupport](../Tests/Support/README.md) | In-memory keys, controlled peers and disposable Bitcoin Core fixtures | WalletCore, VaultKit and P256K; development only |
| [winnow-debug](../Tools/Debug/README.md) | Offline inspection, diagnostics, generators and network soaks | WalletCore |
| [WinnowFuzz](../Tools/Fuzz/README.md) | Bounded hostile-input parsing and invariants | WalletCore and VaultKit through WinnowFuzzCore |
| [winnow-fixture](../Tools/Fixture/README.md) | Test-bank preparation | TestSupport |

WalletCore never imports VaultKit. `VaultRecord` stays in WalletCore because
wallet state and backup imports carry optional shared accounts. A saved account
record contains public policy and state; it does not contain another signer's
private key or an active MuSig2 nonce session.

WalletCore and VaultKit are SwiftPM library products. They share the app's source
revision and version tags; there is no separate library release train. The only
third-party package dependency is swift-secp256k1, pinned in the root lockfile.
The app's resolved dependencies are checked against that file.

## Receiving and synchronization

[AppModel](../Sources/WinnowApp/AppModel.swift) coordinates wallet state and the
network actors. Peers supply headers, compact block filters and requested
blocks. The wallet matches filters locally, fetches candidate blocks and
updates its tracked coins and transaction history. Short mempool subscriptions
provide unconfirmed-payment detection while the relevant screens are open.

This is a compact-filter wallet. Its checks do not establish the same view as
independently validating every block from genesis. Peer choice, checkpoints,
filter agreement and catch-up limits are described in the bundled
[read-side guide](read-side.html). Direct peers observe connection metadata and
requests. Optional SOCKS gateways change transport; they do not remove the
wallet's chain-verification assumptions.

## Payment review and signing

The app presents the recipient, amount, account and fee, authenticates protected
actions, and invalidates stale reviews when payment inputs change. WalletCore
constructs transactions and validates PSBT commitments. VaultKit handles the
shared account's policy and approval exchange using those core rules.

Ordinary receiving uses BIP86 Taproot. Shared accounts use MuSig2 key-path
signing or threshold script-path signing. Signer names and contact-card labels
do not establish authority; the descriptor and verified signatures do. Different
keys alone do not prove different people or physically separate devices. The
[write-side](write-side.html) and [shared-wallet](vaults.html) guides explain the
protocols and their limits.

## Persistence, keys and backup

The app persists wallet and presentation state and supplies the Keychain-backed
implementation of WalletCore's key-store interface. Local signing secrets use
device-only, user-presence-protected Keychain entries. In-memory key storage
belongs to TestSupport.

The app also owns [CloudWalletBackup](../Sources/WinnowApp/CloudWalletBackup.swift),
[CloudBackupController](../Sources/WinnowApp/CloudBackupController.swift) and
[ICloudBackupStore](../Sources/WinnowApp/ICloudBackupStore.swift). They encode and
encrypt backup contents, schedule retries and perform private CloudKit writes.
The backup wrapping key uses a separate, synchronizable iCloud Keychain service.
That cloud copy adds Apple Account and iCloud Keychain dependencies to secret
protection; it does not change the local signing key's access controls.

A successful save date confirms the upload of encrypted contents. Manual files
and recovery words remain part of the [backup guidance](import.html).
[CloudKit setup](../CloudKit/README.md) covers schema, encryption and validation.

## Source map

WalletCore directories organize one module:

- Primitives: [crypto and encodings](../Sources/WalletCore/Crypto/README.md),
  [keys](../Sources/WalletCore/Keys/README.md),
  [descriptors](../Sources/WalletCore/Descriptors/README.md) and
  [scripts](../Sources/WalletCore/Script/README.md).
- Spending: [wallet state](../Sources/WalletCore/Wallet/README.md),
  [PSBTs](../Sources/WalletCore/PSBT/README.md) and
  [transactions](../Sources/WalletCore/Transactions/README.md).
- Synchronization: [headers](../Sources/WalletCore/Network/Headers/README.md),
  [filters](../Sources/WalletCore/Network/Filters/README.md) and
  [peer selection](../Sources/WalletCore/Network/Peers/README.md).
- Communication: [transport](../Sources/WalletCore/Network/Transport/README.md),
  [wire protocol](../Sources/WalletCore/Network/Protocol/README.md),
  [broadcast](../Sources/WalletCore/Network/Broadcast/README.md) and
  [mempool](../Sources/WalletCore/Network/Mempool/README.md).

The [testing guide](testing.md) maps the test targets to these responsibilities.
[Scripts](../scripts/README.md) and [workflows](../.github/workflows/README.md)
index the build and release entry points. Security reports and dated audit
evidence live under [security](security/README.md); their findings and results
apply to the revisions they identify.

The public website has its own
[repository](https://github.com/winnowwallet/website). The app bundles five
HTML guides and their stylesheet from this repository's `docs/` directory.
Changes to those bundled files are app changes and participate in CI's build
fingerprint.
