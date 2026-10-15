[Back to main README](../../../README.md)

# Taproot spending scripts

Script encoding, Taproot trees, and multisignature policy construction define
which keys can spend a wallet or shared-savings output. The signer and other
participants must agree on exactly the same script and commitment.

[Descriptors](../Descriptors/README.md) and
[vaults](../../VaultKit/README.md) consume this WalletCore code.
The directory is an organizational boundary, not another runtime layer.

[BIP341 tests](../../../Tests/BitcoinCoreTests/BIP341Tests.swift) cover commitments
and signatures; [BIP387](../../../Tests/BitcoinCoreTests/BIP387Tests.swift) and
[BIP390 tests](../../../Tests/BitcoinCoreTests/BIP390Tests.swift) cover script policies.
The [UI journey](../../../UITests/README.md)
exercises shared spending with Core-held cosigner keys.
