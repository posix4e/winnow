// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "OfflineWallet",
    platforms: [.macOS(.v14)],
    dependencies: [.package(name: "winnow", path: "../..")],
    targets: [
        .testTarget(
            name: "OfflineWalletTests",
            dependencies: [.product(name: "BitcoinCore", package: "winnow")]
        ),
    ]
)
