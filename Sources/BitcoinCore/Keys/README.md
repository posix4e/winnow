[Back to main README](../../../README.md)

# Offline key derivation

BIP39 mnemonic/seed conversion, BIP32 hierarchical keys, and BIP86 Taproot
addresses belong to the offline product. Derivation is shared by library
clients and WalletCore. These types do not load or persist secrets; the
[WalletCore keystore](../../WalletCore/Keys/README.md) retains that responsibility.

[BIP39](../../../Tests/BitcoinCoreTests/BIP39Tests.swift),
[BIP32](../../../Tests/BitcoinCoreTests/BIP32Tests.swift), and
[BIP86](../../../Tests/BitcoinCoreTests/BIP86Tests.swift) cover independent vectors.
