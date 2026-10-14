[Back to main README](../../../README.md)

# Offline selection and fee policy

Coin selection, fee-rate policy, monetary bounds, and the wallet coin/address
value types live in BitcoinCore. They accept values from the caller and have no
network, database, or secret-storage dependency. The PeerPool fee-floor adapter
remains in WalletCore; its policy result is an explicit input here.

[Selection tests](../../../Tests/WalletCoreTests/CoinSelectionTests.swift) cover
bounds, dust, fees, and selection behavior. Wallet persistence and chain
synchronization remain in [WalletCore](../../WalletCore/Wallet/README.md).
