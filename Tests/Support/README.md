[Back to main README](../../README.md)

# TestSupport

One fixture library for every test target: the SwiftPM suites
(`BitcoinCoreTests`, `WalletCoreTests`, `VaultKitTests`)
and the Xcode bundles (`WinnowAppTests`, `WinnowAppUITests`) all link the
`TestSupport` product declared in `Package.swift`, so a helper is written once
and imported with `import TestSupport`.

## The rule

**Framework-agnostic: no `import Testing`, no `import XCTest`.** The
swift-testing targets and the XCTest bundles both consume this library, so a
helper never asserts. It returns a value or throws, and the assertion stays at
the call site (`#expect` there, `XCTAssert` here). A helper that needs a
deadline reports the outcome (`pollUntil` returns `Bool`) rather than failing
the test itself.

Everything the tests use is `public`; only public API of the modules under
test is used (no `@testable import`), so the library builds in any
configuration and under Xcode.

## What lives here

| File | Contents |
| --- | --- |
| `InMemoryKeyStore.swift` | Test-only secret storage, outside the production Keychain implementation, plus `CountingKeyStore` (the same store, counting its `load` calls) |
| `Vectors.swift` | `Vectors.data/string/json/decode` (each target passes its own `Bundle.module`), `VectorError`, `ttTags`, the shared BIP158 and BIP387/BIP390 vector loaders |
| `TempFiles.swift` | `TempDir` (removed on deinit) and `tempFileURL(_:)` under one per-process root |
| `ParkGate.swift` | `ParkGate`: parks code at a suspension point until the test releases it, so a race becomes an ordering |
| `SeededRandom.swift` | `SeededRandom` (SplitMix64) with the `int`/`count` draws for coin-selection property tests |
| `Collectors.swift` | `MatchCollector`, `EventCollector`, `pollUntil`, `settle` |
| `WalletFixtures.swift` | `testEntropy`, `testMnemonic`, `testMaster`, `fakeHeader`, `coinbaseInput`, `fakeMatch`, `matureCoinbase`, `testChainTip`, `makeTestWallet`, `fund`, `fundedWallet` |
| `TestScripts.swift` | `TestScripts.p2trDestination`, `TestScripts.bip86FirstMainnetAddress` |
| `TestVaults.swift` | Deterministic cosigner masters, key expressions, the 2-of-3 `multi_a` and 2-of-2 MuSig2 vault builders, `funding` |
| `P2P/` | `SyntheticChain`/`makeSyntheticChain`, `minedHeader`, `makeTestParams`, `makeFakeSegwitTx`, `ResumeOnce`, `LoopbackNode`, `LoopbackHTTPServer` |
| `Node/` | `BitcoinCLI`, `CoreSigner`, `HostProcess`, `SignetMiner`, `SignetFixture`: the custom-signet node and other signing wallets used by the UI journey |

Helpers that only one target can use stay in that target: `blockOutputScripts`
in `BitcoinCoreTests/TestHelpers.swift` and anything that
conforms to an app protocol (`SilentAuthenticator`) in `AppTests/TestSupport.swift`.

These helpers support [wallet tests](../WalletCoreTests/README.md),
[VaultKit tests](../VaultKitTests/README.md) and the [UI journey](../../UITests/README.md).
Run their consuming suites to validate changes; fixture code alone makes no assertions.
