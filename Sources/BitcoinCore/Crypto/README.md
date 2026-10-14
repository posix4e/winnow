[Back to main README](../../../README.md)

# Hashing and encodings

These primitives encode addresses and keys, derive seed material, and match compact
filters. Receiving, recovery, and private chain scanning need the same byte-level
rules in the app and debugging tools.

Consumers include [key derivation](../Keys/README.md),
[Taproot scripts](../Script/README.md), and
[filter scanning](../../WalletCore/Network/Filters/README.md).
This is a source grouping inside WalletCore, not a separate service.

[Crypto tests](../../../Tests/BitcoinCoreTests/CryptoTests.swift),
[Bech32 tests](../../../Tests/BitcoinCoreTests/Bech32Tests.swift), and
[BIP158 tests](../../../Tests/BitcoinCoreTests/BIP158Tests.swift) exercise known answers
and invalid inputs. These checks support the implementation; they do not replace
an independent cryptographic review.

`TaggedHash` keeps WalletCore's `String`/`Data` interface but delegates hashing to
`P256K.SHA256.taggedHash` in the pinned secp256k1 dependency. Known-answer tests
cover empty, binary, and UTF-8 inputs; BIP341 and MuSig vector tests exercise its
protocol callers.

The upstream Schnorr signer signs a digest supplied by the caller. WalletCore
still owns transaction signature-message construction in `SighashBIP341`, and
script-tree/control-block construction in `Taproot`; these are not replaced by
key-tweak or signature APIs.
