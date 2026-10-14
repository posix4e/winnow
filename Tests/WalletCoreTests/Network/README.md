[Back to main README](../../../README.md)

# Wallet networking tests

This group tests the networking code inside WalletCore: headers, compact-filter
scans, peer policy, wire parsing, mempool windows, and payment relay.
A wallet needs both accurate balances and understandable recovery from peer faults.

[Controlled peers](../../Support/P2P/README.md) supply forks, disconnects,
and adversarial answers. The tests are part of WalletCoreTests, not a separate
P2P package or another test runner.

Run `swift test --filter WalletCoreTests` from the repository root.
[FilterSync adversaries](FilterSyncAdversaryTests.swift)
and [relay-store tests](TxBroadcasterStoreTests.swift)
cover important failure paths. [Gateway](PeerGatewayTests.swift),
[tailnet discovery](TailnetGatewayDiscoveryTests.swift), [routing](RoutingTests.swift)
and [SOCKS5](SocksProxyTests.swift) tests cover Tor and I2P through the user's
own gateways; the live case skips unless `scripts/check-live-gateways` enables it,
and the tailnet simulation runs in CI through `scripts/ci-tailnet`.
The [UI journey](../../../UITests/README.md)
exercises payment discovery and relay against a real signet node.
Retained [soak evidence](../../../docs/security/evidence/README.md) provides additional observations.
