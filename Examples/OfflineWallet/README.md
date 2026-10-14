[Back to main README](../../README.md)

# Offline wallet consumer

This separate Swift package depends on the **BitcoinCore product only**. Its
test derives the BIP86 reference address, selects coins, builds a transaction,
and signs it with the existing public primitives. It uses an invented outpoint
and a public test mnemonic, without a node, wallet storage, or Keychain access.

From the repository root:

```sh
swift test --package-path Examples/OfflineWallet
```

The manifest does not declare WalletCore or TestSupport. A separate build
checks that an external package can use the public offline API without
compiling the wallet runtime. See the [BitcoinCore guide](../../Sources/BitcoinCore/README.md)
for the embedding application's responsibilities.
