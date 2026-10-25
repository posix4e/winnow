[Back to main README](../../../README.md)

# Taproot scripts and commitments

Script encoding, Taproot leaf and branch hashes, output-key tweaks and
control blocks, plus the BIP387 `multi_a` leaf builder and parser and the
timelocked leaves `<K> OP_CHECKSIGVERIFY <N> OP_CHECKSEQUENCEVERIFY` and
`… OP_k OP_NUMEQUALVERIFY <N> OP_CHECKSEQUENCEVERIFY`, with the BIP68/BIP112
rule for when an input's sequence meets them. The wallet's own outputs are
plain BIP86 key-path outputs; multisig accounts spend through a `multi_a` leaf
under the NUMS internal key, or a timelocked recovery leaf beside it, and the same
tree and control-block code reads the script-path spends of incoming
transactions, so received payments can be labelled by the address that
funded them.

[Descriptors](../Descriptors/README.md) and
[funding sources](../Transactions/FundingSources.swift) consume this WalletCore
code. The directory is an organizational boundary, not another runtime layer.

[BIP341 tests](../../../Tests/BitcoinCoreTests/BIP341Tests.swift) cover
commitments, control blocks and the NUMS internal key against the official
wallet vectors.
