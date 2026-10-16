[Back to main README](../../../../README.md)

# Payment relay

TxBroadcaster announces signed payments, handles peer fee filters and retry
state, and retains enough history to relay a payment again after a chain reorg.
The app needs this to distinguish a signed payment from one actually announced.

[AppModel](../../../WinnowApp/AppModel.swift) coordinates relay with the
wallet and [mempool observations](../Mempool/README.md).
This is one part of WalletCore networking, not a separate backend.

[Relay tests](../../../../Tests/WalletCoreTests/Network/TxBroadcasterTests.swift) exercise
announcements and retry policy. [Store tests](../../../../Tests/WalletCoreTests/Network/TxBroadcasterStoreTests.swift)
cover damaged persistence and reorg recovery. [App journeys](../../../../UITests/README.md)
check the resulting payment history against a node.

An embedding application may opt into `TxBroadcaster.enterRelayOnly(seats:)`
after cancelling and awaiting its scans. It keeps existing connections for
already authorized transactions, dials no replacements and refuses new chain
reads. The broadcaster ends the session when pending relay drains or its seats
are lost; `PeerPool.start()` returns to full service. A transport handoff is
recorded separately from acceptance, propagation and confirmation. Winnow's app
continues to use its existing networking lifecycle.
