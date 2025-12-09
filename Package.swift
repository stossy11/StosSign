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
            targets: ["StosOpenSSL", "StosSign", "StosSign_CSR"]),
    ],
    dependencies: [
        // .package(url: "https://github.com/stossy11/CoreCrypto-SPM", branch: "master"),
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0" ..< "5.0.0"),
        .package(url: "https://github.com/marmelroy/Zip.git", branch: "master"),
        .package(url: "https://github.com/khcrysalis/Zsign-Package", branch: "package"),
        .package(url: "https://github.com/adam-fowler/swift-srp.git", revision: "ce202c48f8ca68f44b71732f945eb8221d6fe135"),
        .package(url: "https://github.com/krzyzanowskim/OpenSSL", from: "3.3.3001"),
        .package(url: "https://github.com/apple/swift-certificates.git", .upToNextMinor(from: "0.6.0"))
        //https://github.com/marmelroy/Zip
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "StosSign",
            dependencies: [
                .product(name: "ZsignSwift", package: "Zsign-Package"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "SRP", package: "swift-srp"),
                .product(name: "Zip", package: "Zip"),
                .product(name: "OpenSSL", package: "OpenSSL"),
                .product(name: "X509", package: "swift-certificates"),
                "StosOpenSSL",
                "StosSign_CSR"
            ]
        ),
        .target(
            name: "StosSign_CSR",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "SRP", package: "swift-srp"),
                .product(name: "Zip", package: "Zip"),
                .product(name: "X509", package: "swift-certificates")
            ]
        ),
        .target(
            name: "StosOpenSSL",
            dependencies: [
                .product(name: "OpenSSL", package: "OpenSSL"),
            ],
            path: "Sources/Dependencies/Modules/OpenSSL"
        ),
    ],
    
    cLanguageStandard: CLanguageStandard.gnu11,
    cxxLanguageStandard: .cxx14
)
