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

[WalletCore tests](../../../Tests/WalletCoreTests/README.md) cover balances, selection,
imports, and reorg recovery. [App tests](../../../AppTests/README.md)
check persistence and protected actions; [UI journeys](../../../UITests/README.md)
check the complete user flow.
