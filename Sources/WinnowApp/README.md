[Back to main README](../../README.md)

# The wallet app

SwiftUI screens and AppModel turn wallet and network state into receiving,
sending, recovery, and saved recipients. The app owns user review,
authentication, presentation, and lifecycle; WalletCore owns the Bitcoin rules.
The [architecture guide](../../docs/architecture.md) maps these responsibilities.
The app supports iPhone, iPad, and Apple silicon Mac (Designed for iPad).
Simple mode uses one screen; Advanced mode adds Wallet, Send, and Settings tabs.
The automated UI journey currently covers iPhone only.

The Send field takes any address or a BIP352 silent payment code
(`sp1…`/`tsp1…`); the review names the code, notes that the on-chain address
is made for this transaction, and the receipt and payment details show both.
Only the everyday wallet can pay a code — shared accounts spend through script
paths BIP352 excludes — and the review gate binds the scripts the wallet derived
(SEC-018). A saved person may be a code too: reusable, never counted.

Wallet is the one account and transaction list. Payment details save or rename a
recipient; Send holds the saved-recipient picker and the amount. The reviewed
proposal is signed with this phone's key after the owner authenticates.
Advanced mode keeps coins and the raw descriptor under Technical details, and
its Wallet tab adds a Multisig section. "New multisig account"
([MultisigBuildView](MultisigBuildView.swift)) builds a k-of-n account from
this phone's key, other signers' pasted keys and optionally a Ledger's, with an
optional timelocked recovery path, and shows the descriptor for the others to
join with; the PSBT screen then offers the signers' path or, for coins old
enough, the recovery path. Or join a k-of-n account by pasting its
descriptor, receive into it, and create or paste a PSBT that this phone signs,
combines with other signers' copies, and broadcasts once enough signatures
verify. "Pair a Ledger" makes a 2-of-2 with a Ledger instead: the Ledger's
key comes from its Bitcoin app, the user approves the account on the Ledger,
"Verify on Ledger" shows a receive address on its screen, and "Sign with
Ledger" asks it for the second signature
([LedgerViews](LedgerViews.swift), [LedgerBluetooth](LedgerBluetooth.swift)).
Every Ledger entry point is in that Advanced-mode section, the model refuses
Ledger actions in Simple mode, and iOS asks for Bluetooth only when pairing
starts. Accounts live in the sealed per-wallet `multisig.json`
([MultisigStore](MultisigStore.swift)), scanned with the wallet's own filters.
Removing a shortcut preserves
past labels and fresh-address counters in the existing
people.json store. Receive shares the wallet’s payment card.

[Documented journeys](https://github.com/winnowwallet/website/blob/main/docs/journeys.json) identify the supported experiences.
[App tests](../../AppTests/README.md) check state and protected actions,
including [paying a silent payment code](../../AppTests/SilentPaymentSendFlowTests.swift);
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
