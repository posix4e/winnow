[Back to main README](../../../README.md)

# Wallet and network reference data

These fixtures provide BIP158 filters, BIP341 signing examples, controlled DNS
replies, and real mainnet headers. They give wallet/network tests stable inputs
without querying a changing public service during each run.

[SighashBIP341Tests](../SighashBIP341Tests.swift),
[PeerPolicyTests](../Network/PeerPolicyTests.swift), and
[HeaderChainTests](../Network/HeaderChainTests.swift) are consumers.
SwiftPM copies the directory into the test resource bundle.

`bip341-scriptpath-test-vectors.json` is a `tr(NUMS, multi_a(2, K1, K2, K3))`
spend generated once with Bitcoin Core's functional-test framework, for the
script-path sighash (BIP342 ext_flag 1) across all eight hash types with and
without an annex: the SigMsg bytes, sighashes, signatures under zero auxiliary
randomness, and the BIP387 witness. It is carried over unchanged from the
shared-account Winnow; the native signer must reproduce its signatures byte
for byte.

`core-timelocked-multisig.json` holds Bitcoin Core 31.1's answers for four
multipath descriptors with a timelocked recovery leaf (a separate key, the same
signers on `/<2;3>/*`, a three-block lock and the maximum lock with the recovery
leaf first): `getdescriptorinfo` checksums and `deriveaddresses` for both
choices at indices 0 to 2, recorded once on a throwaway regtest node over
public test keys from Ledger's vectors. [TimelockedMultisigTests](../TimelockedMultisigTests.swift)
recomputes each.

`difficulty-boundaries.json` holds the period-start, previous, and adjustment
headers for mainnet heights 32,256 and 901,152. Retrieved on 2026-09-09 through
[Blockstream's block API](https://github.com/Blockstream/esplora/blob/master/API.md#blocks):
resolve each height with `/block-height/:height`, then fetch `/block/:hash/header`.
Each serialized header's double-SHA256 was checked against its returned block hash.
[HeaderDifficultyTests](../Network/HeaderDifficultyTests.swift) checks proof of work,
the adjacent headers' linkage, and the calculated adjustment. Its fixed Core
calculation vectors come from [Bitcoin Core v31.0 pow_tests.cpp](https://github.com/bitcoin/bitcoin/blob/v31.0/src/test/pow_tests.cpp).

Refresh Bitcoin vectors from their named specifications and record the source
revision; DNS JSON files are deliberately controlled response fixtures.
The 2,000-header file is produced by the [checkpoint generator](../../../Tools/Generate/README.md)
from a genesis-validated header file. Preserve that provenance and run
`swift test --filter WalletCoreTests`; do not replace expected data just to make tests pass.
