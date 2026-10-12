// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "ACPSwiftChecks",
    platforms: [.macOS(.v13)],
    products: [.executable(name: "acp-swift-checks", targets: ["ACPSwiftChecks"])],
    dependencies: [.package(url: "https://github.com/swiftlang/swift-syntax.git", exact: "603.0.1")],
    targets: [
        .executableTarget(name: "ACPSwiftChecks", dependencies: [
            .product(name: "SwiftSyntax", package: "swift-syntax"),
            .product(name: "SwiftParser", package: "swift-syntax")
        ]),
        .testTarget(name: "ACPSwiftChecksTests", dependencies: ["ACPSwiftChecks"])
    ]
)
