// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Winnow",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "BitcoinCore", targets: ["BitcoinCore"]),
        .library(name: "WalletCore", targets: ["WalletCore"]),
        // Test fixtures shared by every test target, SwiftPM and Xcode alike.
        .library(name: "TestSupport", targets: ["TestSupport"]),
        .executable(name: "winnow-debug", targets: ["WinnowDebug"]),
        .executable(name: "WinnowFuzz", targets: ["WinnowFuzz"]),
        .executable(name: "winnow-fixture", targets: ["WinnowFixture"]),
    ],
    dependencies: [
        .package(url: "https://github.com/21-DOT-DEV/swift-secp256k1", exact: "0.23.2"),
    ],
    targets: [
        .target(
            name: "BitcoinCore",
            dependencies: [.product(name: "P256K", package: "swift-secp256k1")],
            exclude: ["README.md", "Keys/README.md", "Serialization/README.md", "Wallet/README.md",
                      "Crypto/README.md", "Descriptors/README.md", "Script/README.md",
                      "PSBT/README.md", "Transactions/README.md"]
        ),
        .target(
            name: "WalletCore",
            dependencies: ["BitcoinCore", .product(name: "P256K", package: "swift-secp256k1")],
            exclude: [
                "Keys/README.md",
                "Network/Broadcast/README.md",
                "Network/Filters/README.md",
                "Network/Headers/README.md",
                "Network/Mempool/README.md",
                "Network/Peers/README.md",
                "Network/Protocol/README.md",
                "Network/Transport/README.md",
                "Wallet/README.md",
            ]
        ),
        .executableTarget(
            name: "WinnowDebug",
            dependencies: ["WalletCore"],
            path: "Tools/Debug/Sources/WinnowDebug",
            exclude: ["README.md"]
        ),
        .target(
            name: "WinnowFuzzCore",
            dependencies: ["WalletCore"],
            path: "Tools/Fuzz/Sources/WinnowFuzzCore",
            exclude: ["README.md"]
        ),
        .executableTarget(
            name: "WinnowFuzz",
            dependencies: ["WalletCore", "WinnowFuzzCore"],
            path: "Tools/Fuzz/Sources/WinnowFuzz",
            exclude: ["README.md"]
        ),
        // Framework-agnostic fixtures (no Testing, no XCTest) so the
        // swift-testing targets below and the Xcode app test bundles share one
        // implementation. P256K: the signet miner signs block challenges.
        .target(
            name: "TestSupport",
            dependencies: ["WalletCore",
                           .product(name: "P256K", package: "swift-secp256k1")],
            path: "Tests/Support",
            exclude: ["Node/README.md", "P2P/README.md", "README.md"]
        ),
        .executableTarget(
            name: "WinnowFixture",
            dependencies: ["TestSupport"],
            path: "Tools/Fixture",
            exclude: ["README.md"]
        ),
        .testTarget(
            name: "BitcoinCoreTests",
            dependencies: ["BitcoinCore", "WalletCore", "TestSupport"],
            exclude: ["README.md"],
            resources: [.copy("Vectors")]
        ),
        .testTarget(
            name: "WalletCoreTests",
            dependencies: ["BitcoinCore", "WalletCore", "TestSupport"],
            exclude: ["Network/README.md", "README.md"],
            resources: [.copy("Vectors")]
        ),
        // The development tools, tested together: the debugging commands, the
        // release-path generators, and the fuzz crash corpus replayed out of
        // `Cases`. One target, so a tool suite costs no more manifest than a
        // library one and `swift test` links the tools once.
        .testTarget(
            name: "ToolsTests",
            dependencies: ["WinnowDebug", "WinnowFuzzCore"],
            exclude: ["README.md"],
            resources: [.copy("Cases")]
        ),
    ]
)
