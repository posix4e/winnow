[Back to main README](../../../README.md)

# Wallet state and spending policy

Balances, coin selection, fees, and recovery imports live here. They supply the
state and decisions behind receiving, sending, and recovery; the GUI should not
carry a second wallet implementation. Shared-savings vaults and people are in
[VaultKit](../../VaultKit/README.md). The
[architecture guide](../../../docs/architecture.md) maps the rest of WalletCore.

[AppModel](../../WinnowApp/AppModel.swift) coordinates these rules with
WalletCore networking, [key storage](../Keys/README.md), and
[signing](../Transactions/README.md).
VaultRecord stays here: it is shared by app persistence and the optional accounts
in a wallet backup, so there is one representation to restore. Signing keys and live
MuSig2 nonce sessions are not part of an account record.

An embedding application can restore its reserved address ranges with
`Wallet.advanceCursors(nextReceiveIndex:nextChangeIndex:)`. Each cursor is the
next unused index: every lower index remains watched and must not be issued
again. Omitted or smaller values leave that chain unchanged. Both reservations
are saved atomically before becoming live, survive reopening and public backup
round trips, and do not alter the forward scan height. The method reserves
addresses; historical discovery still requires a separate verified scan.

The caller must validate its recovery record and bound the number of addresses
it asks the wallet to watch. The library refuses cursors that leave no room for
the non-hardened gap-limit window; that protocol boundary is not a practical
mobile resource budget. Watch-set construction costs work proportional to the
reserved ranges. No recovery record or new cursor is proof that those addresses
have been scanned.

[WalletCore tests](../../../Tests/WalletCoreTests/README.md) cover balances, selection,
imports, and reorg recovery. [App tests](../../../AppTests/README.md)
check persistence and protected actions; [UI journeys](../../../UITests/README.md)
check the complete user flow.

Known send recipients are recorded in `HistoryEntry.outputs`, alongside existing
transaction bytes and confirmation hashes. Missing metadata stays unknown; an
empty external list means the known send paid no external recipient. Receive
outputs owned by the wallet are excluded, change vouts are separate, and the
breakdown survives confirmation, fee bumps, reopening and public backup import.
If transaction bytes exist, the recorded recipients must match them. Without
bytes, this is display metadata and cannot establish inclusion or spending rights.
Block hashes identify the claimed chain position; recording one alone does not
validate a restored backup or prove a transaction's inclusion.

Fee resolution uses a majority of configured peer seats, with missing reports
counting as zero. `FeePolicy.resolution` reports both the selected rate and any
peer floor above its automatic 120 sat/vB cap. Applications must refuse a rate
below that reported floor or obtain a new explicit fee decision before signing;
the app offers a manually entered override in Advanced mode and rechecks the live
floor before broadcasting. An override or the wallet's observed confirmed rate
can exceed the peer cap. Advertised floors are peer hints, not fee-market
estimates or promises of relay. See [BIP133](https://github.com/bitcoin/bips/blob/master/bip-0133.mediawiki).
