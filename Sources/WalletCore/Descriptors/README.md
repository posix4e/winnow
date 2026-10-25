[Back to main README](../../../README.md)

# Descriptors

Descriptors turn a public key expression into the addresses a wallet or a
person is paid at: `tr(KEY)`, `rawtr(KEY)` and `tr(KEY,TREE)` with BIP380
origins and checksums and BIP389 multipath suffixes. Trees hold `pk`,
`multi_a` and `sortedmulti_a` leaves (BIP386, BIP387) and the two timelocked
miniscript leaves a recovery path uses, `and_v(v:pk(KEY),older(N))` and
`and_v(v:multi_a(k,KEY,…),older(N))`, and are bounded at
BIP341's 128 levels, so a hostile descriptor cannot exhaust the parser's stack.
`musig()` aggregation is not grammar here; such text fails at the parse.

The [wallet](../Wallet/README.md), [people](../Wallet/People.swift) and the
[offline inspector](../../../Tools/Debug/README.md) consume this WalletCore code.
It describes derivation; it does not own app state or peers.

[Descriptor tests](../../../Tests/BitcoinCoreTests/DescriptorTests.swift) and
[parser bounds](../../../Tests/BitcoinCoreTests/DescriptorBoundsTests.swift) cover
derivation, malformed input, refused forms, the tree depth bound and origin
bounds; [BIP387 tests](../../../Tests/BitcoinCoreTests/BIP387Tests.swift) run the
BIP's own `multi_a` vectors.
