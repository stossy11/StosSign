// swift-tools-version: 5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "StosSign",
    platforms: [
        .iOS(.v14),
        .macOS(.v11),
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "StosSign",
            targets: ["StosOpenSSL", "StosSign"]),
    ],
    dependencies: [
        .package(url: "https://github.com/stossy11/CoreCrypto-SPM", branch: "master"),
        .package(url: "https://github.com/marmelroy/Zip.git", branch: "master"),
        .package(url: "https://github.com/zwsn/zsign-ios.git", branch: "main")
        //https://github.com/marmelroy/Zip
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "StosSign",
            dependencies: [
                .product(name: "ZSignApple", package: "zsign-ios"),
                .product(name: "CoreCrypto", package: "CoreCrypto-SPM"),
                .product(name: "Zip", package: "Zip"),
                "StosOpenSSL"
            ]
        ),
        .target(
            name: "StosOpenSSL",
            dependencies: [
                .product(name: "ZSignApple", package: "zsign-ios")
            ],
            path: "Sources/Dependencies/Modules/OpenSSL"
        ),
    ],
    
    cLanguageStandard: CLanguageStandard.gnu11,
    cxxLanguageStandard: .cxx14
)
