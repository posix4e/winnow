[Back to main README](../../../../README.md)

# Bitcoin wire formats and network parameters

Messages, framing, blocks, peer addresses, and network parameters live here.
Transaction serialization and shared byte encoders live in
[BitcoinCore](../../../BitcoinCore/Serialization/README.md), so offline signing
does not depend on the P2P implementation.

[Transport](../Transport/README.md),
[scanning](../Filters/README.md), and
[transaction construction](../../../BitcoinCore/Transactions/README.md) use them.
[Wire tests](../../../../Tests/WalletCoreTests/Network/WireTests.swift),
[transaction tests](../../../../Tests/WalletCoreTests/Network/TransactionTests.swift), and
[network-parameter tests](../../../../Tests/WalletCoreTests/Network/NetworkParamsTests.swift)
cover encoding, parsing, and network selection.

Peer discovery lives in [Peers](../Peers/README.md); no peer-address list is compiled into the app.
