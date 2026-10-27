[Back to main README](../../../README.md)

# Ledger signer

A Ledger with the Bitcoin app (version 2.1.2 or later; Bitcoin Test on signet)
can be the second signer of a [multisig account](../Wallet/README.md): a 2-of-2
`tr(NUMS, sortedmulti_a(2, phone, Ledger))` where the phone adds one
script-path signature and the Ledger adds the other after showing the payment
on its own screen. Nothing here depends on Ledger code: the client is written
from the app's documented protocol and its open-source Python client, and
talks to any `LedgerTransport` (Bluetooth in the app, a simulator in tests).

- `LedgerBluetoothFraming` splits APDUs into the tagged, sequenced frames
  Ledger's Bluetooth service carries and reassembles replies.
- `LedgerMerkle` and `LedgerClientCommandInterpreter` implement the app's
  Merkle commitments and its interrupt protocol: while a command runs the
  device asks for preimages, proofs and list elements by hash, and the phone
  answers only from data it committed to.
- `LedgerWalletPolicy` turns an account into a BIP388 wallet policy, template
  `tr(@0/**,sortedmulti_a(2,@1/**,@2/**))` and its key list, with the
  version-2 serialization and policy id. An account with a recovery path adds
  its second leaf, a reused signer keeping one placeholder on `/<2;3>/*`:
  `tr(@0/**,{sortedmulti_a(2,@1/**,@2/**,@3/**),and_v(v:multi_a(1,@1/<2;3>/*,@2/<2;3>/*,@3/<2;3>/*),older(N))})`.
  Miniscript leaves need the Bitcoin app 2.2.0 or later, and a reused
  signer's `/<2;3>/*` key needs 2.2.1: earlier versions return wrong leaf
  hashes for a key whose path does not end in `/**` or `/<0;1>/*`, so the
  phone would refuse their recovery-leaf signatures. Version 2.1.2 is the
  first with `multi_a` and `sortedmulti_a` leaves
  ([CHANGELOG](https://github.com/LedgerHQ/app-bitcoin-new/blob/92d330c20f19185ca2f55970331516a19c9c43b5/CHANGELOG.md)).
- `LedgerBitcoinClient` sends the app's commands: master fingerprint,
  extended public key, register a policy, get or show an address, and sign a
  PSBTv2, whose yielded script-path signatures it decodes.
- `LedgerMultisig` is what the app calls. The Ledger's key is its BIP87
  account `m/87'/coin'/0'`, a path the app exports without a warning.
  Registration must return the policy's own id, and the Ledger must derive
  the phone's first address. A shown address must equal the phone's. A
  signature is kept only after it verifies against the recomputed BIP342
  sighash for that input's leaf; one bad signature leaves the PSBT unchanged.

BIP388 policies admit only extended keys, so an account's internal key is an
xpub on BIP341's NUMS point H with a chain code derived from the signers'
keys, as Liana builds it; every child of H is unspendable. Ledger's own test
vectors include such a key, which the app labels "unspendable".

[Ledger tests](../../../Tests/WalletCoreTests/LedgerTests.swift) check policy
ids and Taproot addresses against Ledger's published vectors, the Merkle
trees against an independent oracle, framing and the interpreter, and whole
pairings and spends against the [device simulator](../../../Tests/Support/LedgerSimulator.swift).
No test here proves a real device agrees; a Nano X did, co-signing a mainnet
2-of-2 spend on 2026-10-26 ([evidence](../../../docs/security/evidence/ledger-mainnet-2026-10-26.md)).
