// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AIAClient",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "AIAClient", targets: ["AIAClient"]),
    ],
    dependencies: [
        // swift-crypto provides CryptoKit-backed primitives on Linux too
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "AIAClient",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "AIAClientTests",
            dependencies: ["AIAClient"]
        ),
    ]
)
