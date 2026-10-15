[Back to main README](../../README.md)

# The wallet app

SwiftUI screens and AppModel turn wallet and network state into receiving,
sending, recovery, saved recipients, and shared accounts. The app owns user review,
authentication, presentation, and lifecycle; WalletCore and VaultKit own the Bitcoin rules.
The [architecture guide](../../docs/architecture.md) maps these responsibilities.
The app supports iPhone, iPad, and Apple silicon Mac (Designed for iPad).
Simple mode uses one screen; Advanced mode adds Wallet, Send, and Settings tabs.
The automated UI journey currently covers iPhone only.

Wallet is the one account and transaction list. Payment details save or rename a
recipient; Send holds the account and saved-recipient pickers. Ordinary payments,
shared savings, and extra-device accounts use the same form and review. The
reviewed proposal goes directly to the account's approval screen; each signing
method keeps its own approval rules. Every script-path account uses Approve a
request, including raw PSBTs and group co-signers; there is no second Advanced
signing screen for the same account. Advanced mode exposes Raw PSBT for exchanges
with other wallets. MuSig2 keeps its separate two-round exchange.
Shared savings and extra-device accounts also use one detail screen for receiving,
balances, Send, and backup. Their approval actions follow the descriptor's rules;
co-owner cards belong to shared savings. Advanced mode keeps coins and the raw
descriptor under Technical details.
Removing a shortcut preserves
past labels, signer identities, and fresh-address counters in the existing
people.json store. Receive shares the wallet’s payment card.

[Documented journeys](https://github.com/winnowwallet/website/blob/main/docs/journeys.json) identify the supported experiences.
[App tests](../../AppTests/README.md) check state and protected actions;
[UI tests](../../UITests/README.md) drive the simulator against a disposable node.
Simulator tests do not establish physical-device lock behavior or battery life.

Assets.xcassets contains the app icon and its Xcode metadata; it is an asset bundle,
not another code layer. [make-icon.swift](../../scripts/make-icon.swift) creates icon
artwork; changing it requires inspecting the rendered icon and building the app.
Keep documentation outside the asset catalog so it is not treated as an asset.

[Automatic iCloud backup](../../CloudKit/README.md) updates an encrypted wallet
copy by default when available. Simple mode shows upload status; Advanced holds
manual export, recovery words and the persistent opt-out. A successful save date
confirms the upload; keep a manual file and recovery words as well.
CloudBackupController owns backup preferences, encrypted retries, lifecycle and last-success state;
ICloudBackupStore owns private CloudKit transport and separate wrapping keys.
CloudWalletBackup is the encrypted file itself: the phrase and the wallet state, sealed separately.
