[Back to main README](../../../README.md)

# Constructing and signing payments

Address decoding, transaction construction, Taproot signature hashes, and signing
turn a reviewed payment into Bitcoin transaction bytes. These rules are shared
by ordinary sends, fee replacement, and vault spending.
A [silent payment](SilentPayment.swift) is a payment whose script does not exist
yet: an amount and a BIP352 code, sized with a same-length placeholder until
[the sender derivation](../SilentPayments/README.md) runs on the chosen inputs.
[Funding sources](FundingSources.swift) reconstruct the addresses that funded a
transaction's inputs from the data those inputs reveal, for the app's
received-payment labeling.

[Wallet state](../Wallet/README.md) supplies coins and policy;
[the app](../../WinnowApp/README.md) owns review and authorization.
[PSBTs](../PSBT/README.md) carry work that needs another signer.

[Builder tests](../../../Tests/WalletCoreTests/TransactionBuilderTests.swift),
[signer tests](../../../Tests/WalletCoreTests/SignerTests.swift),
[sighash tests](../../../Tests/WalletCoreTests/SighashBIP341Tests.swift), and
[funding-source tests](../../../Tests/WalletCoreTests/FundingSourcesTests.swift)
check the rules.
[Silent payment send tests](../../../Tests/WalletCoreTests/SilentPaymentSendTests.swift)
derive BIP352 outputs from the wallet's inputs.
[Send-preview tests](../../../AppTests/SendPreviewTests.swift) protect the app boundary,
and the [UI journey](../../../UITests/README.md)
checks that Core accepts and confirms the app's ordinary and shared-account payments.
