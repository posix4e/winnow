[Back to main README](../../../README.md)

# Transaction signing documents

PSBT parsing and the creator, signer, combiner and finalizer roles carry the
wallet's own key-path transactions from construction to a broadcastable
transaction, and read documents from other software. Imports accept v0 and
v2; v0 is normalized to the same v2 representation, and the app exports v0
for Core. Key-path inputs are signed into PSBT_IN_TAP_KEY_SIG. Multisig
inputs carry the BIP371 leaf script, leaf-hashed origins and
PSBT_IN_TAP_SCRIPT_SIG entries; the finalizer verifies every script-path
signature against the recomputed sighash, checks the leaf commits to the spent
output, and builds the BIP387 witness once the leaf's threshold is met.
MuSig2 fields are carried as unknown pairs and never interpreted.

[Transaction construction](../Transactions/README.md) and the
[wallet](../Wallet/README.md) consume these types.

[PSBT tests](../../../Tests/WalletCoreTests/PSBTTests.swift) cover parsing, combination,
and finalization. [Fuzz regressions](../../../Tests/ToolsTests/Cases/psbt/README.md)
keep a previously problematic encoding in the ordinary test run.
Accepting a PSBT does not itself authorize its payment outputs; the app reviews those.
