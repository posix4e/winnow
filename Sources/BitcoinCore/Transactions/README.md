[Back to main README](../../../README.md)

# Constructing and signing payments

Address decoding, transaction construction, Taproot signature hashes, and signing
turn a reviewed payment into Bitcoin transaction bytes. These rules are shared
by ordinary sends, fee replacement, and vault spending.
[Funding sources](FundingSources.swift) reconstruct the addresses that funded a
transaction's inputs from the data those inputs reveal, for the app's
received-payment labeling.

[Wallet state](../../WalletCore/Wallet/README.md) supplies coins and policy;
[the app](../../WinnowApp/README.md) owns review and authorization.
[PSBTs](../PSBT/README.md) carry work that needs another signer.

[Builder tests](../../../Tests/WalletCoreTests/TransactionBuilderTests.swift),
[signer tests](../../../Tests/WalletCoreTests/SignerTests.swift),
[sighash tests](../../../Tests/WalletCoreTests/SighashBIP341Tests.swift), and
[funding-source tests](../../../Tests/WalletCoreTests/FundingSourcesTests.swift)
check the rules.
[Send-preview tests](../../../AppTests/SendPreviewTests.swift) protect the app boundary,
and the [UI journey](../../../UITests/README.md)
checks that Core accepts and confirms the app's ordinary and shared-account payments.
