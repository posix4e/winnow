[Back to main README](../../README.md)

# Offline Bitcoin library

The `BitcoinCore` Swift package product contains Winnow's existing offline
encodings, key derivation, descriptors, scripts, PSBTs, coin selection,
transaction construction, and signing. It depends on the pinned P256K product.
It does not include wallet storage, Keychain access, or peer connections.

Add the repository as a Swift package dependency and select this product:

```swift
.product(name: "BitcoinCore", package: "winnow")
```

Then `import BitcoinCore`. Existing `import WalletCore` source continues to
work: WalletCore depends on and re-exports BitcoinCore. The wallet's send and
network behavior is unchanged; moved declarations keep their public APIs.
Precompiled consumers must rebuild because some types now live in a new module.

An embedding application supplies validated chain data and unspent outputs,
reserves its inputs and change addresses, authorizes signing, manages its keys,
and broadcasts transactions. These primitives do not verify that externally
reported coins are still unspent or manage a payment review lifecycle.

The [standalone consumer](../../Examples/OfflineWallet/README.md) derives the BIP86
reference address and constructs and signs a payment using this product alone.
Its manifest has no WalletCore or TestSupport dependency. Run it from the root:

```sh
swift test --package-path Examples/OfflineWallet
```

See [keys](Keys/README.md), [serialization](Serialization/README.md),
[selection and fees](Wallet/README.md), [transactions](Transactions/README.md),
and [PSBTs](PSBT/README.md) for implementation and existing test coverage.
