[Back to main README](../../../README.md)

# Silent payments, send side

BIP352 lets a recipient publish one reusable code (`sp1…`, or `tsp1…` on test
networks) while every payment to it lands on a fresh Taproot address that only
the two parties can connect to the code. Winnow sends to such codes; it does
not receive at one. The address codec and the sender derivation live here:
which inputs count, the sum of their keys, the input hash over the smallest
outpoint, the shared secret with the recipient's scan key, and the output key
tweaked from their spend key. Every curve operation comes from the pinned
secp256k1 dependency; the tagged hashes are [TaggedHash](../Crypto/TaggedHash.swift).

Receiving is left out on purpose. A phone cannot find silent payments from
blocks alone — a Taproot key-path input reveals only a signature, and the key
the receiver needs sits in the prevout — so a mobile receiver depends on a
tweak-index server, the one non-peer read path Winnow retired at v0.5.0. A
receiver would reuse this file's eligibility rules unchanged.

[Transactions](../Transactions/README.md) carries the `SilentPayment` payment
kind and its sizing placeholder; [the wallet](../Wallet/README.md) derives the
scripts once coin selection has fixed the inputs, inside the same
authentication window as signing; [the app](../../WinnowApp/README.md) binds
the derived scripts in its review gate (SEC-018).

[Silent payment tests](../../../Tests/BitcoinCoreTests/SilentPaymentTests.swift)
run every official sending vector from
[bip352-send-receive-vectors.json](../../../Tests/BitcoinCoreTests/Vectors/bip352-send-receive-vectors.json)
plus the address codec's negatives;
[silent payment send tests](../../../Tests/WalletCoreTests/SilentPaymentSendTests.swift)
derive from the wallet's own inputs and re-derive independently;
[the app flow](../../../AppTests/SilentPaymentSendFlowTests.swift) pays a code
end to end against a receiver written from the BIP; the
[fuzz harness](../../../Tools/Fuzz/README.md) parses codes.
