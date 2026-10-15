[Back to main README](../../README.md)

# Vaults and shared savings

Shared-savings vaults and the people and contact cards they are built from, on
WalletCore's public interface. A card names a person and how to pay them; a vault is a MuSig2 or
script-path multisig account with its cosigner keys, spends and approvals.
WalletCore never imports this library, so a client of the core does not carry it.

[VaultRecord](../WalletCore/Wallet/VaultRecord.swift) stays in WalletCore because a
wallet backup carries the optional accounts. Signing keys and live MuSig2 nonce
sessions are not part of an account record.

[VaultKit tests](../../Tests/VaultKitTests/README.md) cover cards, vault admission
and spends; the [fuzz harness](../../Tools/Fuzz/README.md) parses pasted cards.
