// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "winnow",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "BitcoinCore", targets: ["BitcoinCore"]),
        .library(name: "BitcoinP2P", targets: ["BitcoinP2P"]),
        .library(name: "BlockchainBackend", targets: ["BlockchainBackend"]),
        .library(name: "WalletCore", targets: ["WalletCore"]),
        .executable(name: "WinnowFuzz", targets: ["WinnowFuzz"]),
        .executable(name: "WinnowSoak", targets: ["WinnowSoak"]),
    ],
    dependencies: [
        .package(url: "https://github.com/21-DOT-DEV/swift-secp256k1", exact: "0.23.2"),
    ],
    targets: [
        .target(
            name: "BitcoinCore",
            dependencies: [.product(name: "P256K", package: "swift-secp256k1")]
        ),
        .target(
            name: "BitcoinP2P",
            dependencies: ["BitcoinCore"]
        ),
        .target(
            name: "BlockchainBackend",
            dependencies: ["BitcoinCore"]
        ),
        .target(
            name: "WalletCore",
            dependencies: ["BitcoinCore", "BitcoinP2P", "BlockchainBackend"]
        ),
        .executableTarget(
            name: "WinnowFuzz",
            dependencies: ["BitcoinCore", "BitcoinP2P", "WalletCore"]
        ),
        .executableTarget(
            name: "WinnowSoak",
            dependencies: ["BitcoinCore", "BitcoinP2P"]
        ),
        .testTarget(
            name: "BitcoinCoreTests",
            dependencies: ["BitcoinCore"],
            resources: [.copy("Vectors")]
        ),
        .testTarget(
            name: "BitcoinP2PTests",
            dependencies: ["BitcoinP2P", "BitcoinCore"],
            resources: [.copy("Vectors")]
        ),
        .testTarget(
            name: "WalletCoreTests",
            dependencies: ["WalletCore", "BitcoinP2P", "BlockchainBackend"],
            resources: [.copy("Vectors")]
        ),
        .testTarget(
            name: "DifferentialTests",
            dependencies: ["BitcoinCore", "BitcoinP2P", "WalletCore"]
        ),
    ]
)
