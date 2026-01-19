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
        .library(
            name: "StosSign",
            targets: ["StosSign", "StosSign_CodeSign", "StosSign_Certificate", "StosOpenSSL", "StosSign_API", "StosSign_Auth"]
        ),
        .library(
            name: "StosSign_API",
            targets: ["StosSign_API"]
        ),
        .library(
            name: "StosSign_Certificate",
            targets: ["StosSign_Certificate"]
        ),
        .library(
            name: "StosSign_Auth",
            targets: ["StosSign_Auth"]
        ),
        .library(
            name: "StosSign_CodeSign",
            targets: ["StosSign_CodeSign"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0" ..< "5.0.0"),
        .package(url: "https://github.com/khcrysalis/Zsign-Package", branch: "package"),
        .package(url: "https://github.com/adam-fowler/swift-srp.git", revision: "ce202c48f8ca68f44b71732f945eb8221d6fe135"),
        .package(url: "https://github.com/krzyzanowskim/OpenSSL", from: "3.3.3001"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "StosSign",
            dependencies: [
                .product(name: "ZsignSwift", package: "Zsign-Package"),
                "StosSign_Certificate",
                "StosSign_Auth",
                "StosSign_API",
                "StosSign_CodeSign",
            ]
        ),
        .target(
            name: "StosSign_Certificate",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "SRP", package: "swift-srp"),
                .product(name: "X509", package: "swift-certificates"),
                .target(
                    name: "StosOpenSSL",
                    condition: .when(platforms: [.iOS, .macOS, .tvOS, .watchOS, .macCatalyst, .visionOS])
                ),
            ]
        ),
        .target(
            name: "StosSign_API",
            dependencies: [
                "StosSign_Certificate"
            ]
        ),
        .target(
            name: "StosSign_Auth",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "SRP", package: "swift-srp"),
                .product(name: "X509", package: "swift-certificates"),
                "StosSign_API",
            ]
        ),
        .target(
            name: "StosOpenSSL",
            dependencies: [
                .product(name: "OpenSSL", package: "OpenSSL"),
            ],
            path: "Sources/Dependencies/Modules/OpenSSL"
        ),
        .target(
            name: "StosSign_CodeSign",
           // path: "Sources/StosSign/StosSign_CodeSign"
        ),
    ],
    cLanguageStandard: .gnu11,
    cxxLanguageStandard: .cxx14
)
