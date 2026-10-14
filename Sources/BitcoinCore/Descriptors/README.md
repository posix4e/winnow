[Back to main README](../../../README.md)

# Descriptors and shared signing

Descriptors turn public key expressions into the addresses and spending policies
used by wallet imports and shared savings. MuSig key aggregation and MuSig2
sessions support the advanced jointly signed vault flow.

The [wallet and vault code](../../WalletCore/Wallet/README.md) and
[offline inspector](../../../Tools/Debug/README.md) consume this BitcoinCore code.
It describes policies and signing operations; it does not own app state or peers.

[Descriptor tests](../../../Tests/BitcoinCoreTests/DescriptorTests.swift),
[parser bounds](../../../Tests/BitcoinCoreTests/DescriptorBoundsTests.swift), and
[MuSig2 tests](../../../Tests/BitcoinCoreTests/MuSig2Tests.swift) cover derivation,
malformed input, known answers, and session safety. The [UI journey](../../../UITests/README.md)
uses Core wallets as the other signers for MuSig2 and 2-of-3 payments.
