[Back to main README](../../../README.md)

# Wallet state and spending policy

Balances, coin selection, fees, recovery imports and people live here. They
supply the state and decisions behind receiving, sending and recovery; the
GUI should not carry a second wallet implementation. The
[architecture guide](../../../docs/architecture.md) maps the rest of WalletCore.

[AppModel](../../WinnowApp/AppModel.swift) coordinates these rules with
WalletCore networking, [key storage](../Keys/README.md), and
[signing](../Transactions/README.md). `MultisigAccount` holds the rules for a
raw k-of-n `tr(NUMS, sortedmulti_a(k, …))` account, optionally with a second,
timelocked recovery leaf `and_v(v:pk(K),older(N))` or
`and_v(v:multi_a(m,…),older(N))` for N of 1 to 65535 blocks, whose keys are
either the same signers on their `/<2;3>/*` path or other keys on `/<0;1>/*`.
A recovery spend sets each input's sequence to N and selects only coins at
least N blocks deep; when every input's sequence meets the lock, either leaf
may finish the spend, and the finalizer puts exactly k signatures in the
witness. The account holds the shape and signer checks
from the shared-account Winnow's audit (SEC-009, SEC-019, SEC-020), spend
creation, the review every signer repeats before signing (SEC-004),
signing and finalization. New accounts write the internal key as an xpub on
the NUMS point, which BIP388 signers such as a Ledger can register; accounts
with the bare NUMS key still load. A record may carry the registration of its
[Ledger signer](../Ledger/README.md), checked against the account whenever the
record is read. Import bundles carry these accounts under `vaults`;
a bundle carrying any other kind of account is refused rather than restored
without it. [Account tests](../../../Tests/WalletCoreTests/MultisigAccountTests.swift)
cover each rule.

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
imports, people, and reorg recovery. [App tests](../../../AppTests/README.md)
check persistence and protected actions; the [UI journey](../../../UITests/README.md)
checks the complete user flow.

`Wallet.buildSend` takes silent payments beside ordinary ones: coin selection
sees a same-size placeholder, then the chosen inputs' tweaked keys derive the
real BIP352 scripts ([SilentPayments](../SilentPayments/README.md)) before the
transaction is built and signed. The prepared send hands those scripts back so
the app's review gate can bind them (SEC-018). A fee bump keeps the same inputs,
so the derived scripts stay valid without re-derivation.

Known send recipients are recorded in `HistoryEntry.outputs`, alongside existing
transaction bytes and confirmation hashes. An output derived for a silent
payment also records the code it was paid for; without that the history could
only show a one-time address. Missing metadata stays unknown; an
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
