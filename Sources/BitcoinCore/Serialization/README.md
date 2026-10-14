[Back to main README](../../../README.md)

# Transaction serialization

The transaction model, sequential byte reader, compact-size encoding, and hash
formatting are shared by offline signing and WalletCore's network protocol.
Package-only encoding helpers remain implementation details; public transaction
and reader APIs are available to embedding applications.

[Wire](../../../Tests/WalletCoreTests/Network/WireTests.swift) and
[transaction](../../../Tests/WalletCoreTests/Network/TransactionTests.swift)
tests cover malformed input, byte order, and round trips.
