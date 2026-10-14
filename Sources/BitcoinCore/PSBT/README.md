[Back to main README](../../../README.md)

# Shared transaction signing

PSBT parsing and signing roles carry partially signed transactions between the
wallet and other signers. They support imported signing requests, shared savings,
and the Advanced PSBT workflow without requiring a coordination server.
Imports accept v0 and v2; v0 is normalized to the same v2 representation.
The app exports v0 for Core. MuSig2 participant lists identify the root key,
while nonces and partial signatures identify the derived output key.

[Transaction construction](../Transactions/README.md),
[vault policy](../../WalletCore/Wallet/README.md), and
[app signing screens](../../WinnowApp/README.md) consume these types.

[PSBT tests](../../../Tests/WalletCoreTests/PSBTTests.swift) cover parsing, combination,
and finalization; the [UI journey](../../../UITests/README.md)
exchanges MuSig2 and 2-of-3 PSBTs with Core signers. [Fuzz regressions](../../../Tests/ToolsTests/Cases/psbt/README.md)
keep a previously problematic encoding in the ordinary test run.
Accepting a PSBT does not itself authorize its payment outputs; the app reviews those.
