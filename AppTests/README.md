[Back to main README](../README.md)

# App decisions and protected actions

These tests exercise the app's state transitions, persistence, privacy, and
authorization boundaries without driving every case through screen taps.
They protect the decisions behind payment review, recovery, and the address book.
[Silent payment flow tests](SilentPaymentSendFlowTests.swift) pay a BIP352 code
through the model and check the derived output against a receiver written from
the BIP in TestSupport.

The tests run in the [iOS app host](../Sources/WinnowApp/README.md) and share
fixtures from [TestSupport](../Tests/Support/README.md).
The local `makeModel` helper gives each test a separate settings suite and removes
it at teardown. Pass the same suite to two models when testing persistence.
The [UI journey](../UITests/README.md) provides complementary screen-level
checks for the receive and send flow.

Run `scripts/ci-app-tests /tmp/winnow-app-tests` from the repository root with
Xcode and a simulator installed. [CI](../.github/workflows/ci.yml) retains the
result bundle and logs. Keychain attributes and authentication policy are tested;
actual locked-device behavior still needs [device evidence](../docs/security/README.md).

[Receive address labels](ReceiveAddressLabelTests.swift) check wallet/network
isolation, atomic persistence, address rotation and relaunch, bounded metadata,
and exact output matching without creating a sender contact.

`LedgerBluetoothTests` check the Bluetooth transport's decisions without a radio:
what each Bluetooth state means while connecting, and how notifications reach
the step in flight. `LedgerPairingTests` drive the app model against the Ledger simulator:
Ledger actions refused in Simple mode, pairing and re-pairing, the address
shown on the device, a spend the phone and the Ledger both sign with the
signing screen's counts and next step checked at each step, a device whose
signatures name the wrong leaf, a refusal on the device, a forged registration
refused by the store, and the account builder with a Ledger among the signers:
two Winnows and a Ledger in a 2-of-3 with a recovery path.

`MultisigAccountFlowTests` drive the account builder and spend signing through
the app model with no hardware signer: two Winnows in a 2-of-2 with a recovery
path, joining refused when the recovery leaf relabels a signer, a separate
recovery key, two phones signing a co-signer's spend with BIP326 sequences,
young coins refused on the recovery path, and nothing in Simple mode.

`MultisigStoreTests` checks the sealed `multisig.json`: backups that wait for
confirmations and refuse a changed coin, payments, spends and reorg rollback
driven by the filter scan, and tampered, unsealed or oversized files left
untouched and refused.

`CloudBackupTests` checks automatic defaults, persistent opt-out, failed uploads, cancellation and wallet/account
changes with in-memory cloud and key stores. It does not establish actual iCloud
or iCloud Keychain synchronization; see [cloud backup validation](../CloudKit/README.md#validation).
`CloudWalletBackupTests` round-trips the encrypted file, keeps the sealed phrase across automatic updates and
upgrades a legacy backup; it refuses a wrong key, changed metadata, a mismatched wallet or a missing phrase.

`AutomaticCloudBackupTests` checks cancelled initialization authentication and mode
changes; `CloudAppStateTests` checks complete context recovery and safe contact merges.
`WalletStartupTests` covers automatic creation and migration from the old phrase checklist.
[Peer gateway model tests](PeerGatewayModelTests.swift) check routing persistence,
corrupt preferences and stale discovery after backgrounding or a settings change.
[Background sync tests](BackgroundSyncTests.swift) check that a background check completes
once, cannot report success after iOS expires it, never runs beside foreground networking,
and does not connect directly after Automatic routing last used a gateway; they also cover
which peer errors Simple mode waits out.
