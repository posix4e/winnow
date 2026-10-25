[Back to main README](../../../README.md)

# Reference data for Bitcoin primitives

These copies of Bitcoin specifications and known-answer data anchor derivation,
signatures, descriptors, and encoding tests to expected values outside Winnow.
`bip352-send-receive-vectors.json` and `bip-0352.mediawiki` are the BIP352
sending and receiving vectors and text from bitcoin/bips
(`bip-0352/send_and_receive_test_vectors.json`, SHA-256
`f5f9ed4afd76a1b76f3c70b1cbe67532f89abbe559f8e02d7fc3d8ecb93af4a1`, identical
to upstream master on 2026-10-25); only the sending cases are run.

`bip-0387.mediawiki` is BIP387's text; its `multi_a` and `sortedmulti_a`
vectors drive [BIP387Tests](../BIP387Tests.swift).

[Primitive tests](../README.md) load named resources through
[Vectors.swift](../../Support/Vectors.swift). SwiftPM copies this directory
into the test resource bundle; it is not shipped with the app.

Keep the specification text and reference data intact. When refreshing a dataset,
record its upstream source and revision in the change, then run
`swift test --filter BitcoinCoreTests`. Do not regenerate expected values with
the implementation being tested. These are fixed examples, not live network data.
