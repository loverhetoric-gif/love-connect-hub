// swift-tools-version:5.9
// LOVE connect HUB のアプリ側の部品（iPhone・iPad・Mac 用。Linux でもテストできる）。
// アプリは署名用・暗号化用の鍵を持たない（規格書 第18章）。下書きを作り、ログインのトークン付きで送るだけ。
import PackageDescription

let package = Package(
    name: "LoveConnectHub",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "LoveConnectHub", targets: ["LoveConnectHub"]),
    ],
    targets: [
        .target(name: "LoveConnectHub"),
        .testTarget(name: "LoveConnectHubTests", dependencies: ["LoveConnectHub"]),
    ]
)
