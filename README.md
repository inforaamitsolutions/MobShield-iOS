# MobShield iOS

Open-source mobile app hardening for iOS: modular RASP detectors, signal aggregation, and per-build native personalization.

**Specification:** [mobshield-spec/MOBSHIELD_SPEC.md](../mobshield-spec/MOBSHIELD_SPEC.md)

## Products

| Product | Purpose |
|---------|---------|
| `MobShieldCore` | Public API facade, aggregator, native bridge (skeleton) |
| `MobShieldDetectJailbreak` | Dopamine, palera1n, unc0ver, checkra1n, rootless |
| `MobShieldDetectHooks` | Frida, Substrate, ElleKit |
| `MobShieldDetectDebugger` | ptrace, sysctl, Mach exceptions |
| `MobShieldDetectEnvironment` | Simulator, automation |
| `MobShieldDetectIntegrity` | SecCode, build anchor |

## Requirements

- Xcode 15+
- iOS 15+
- Swift 5.9+

## Swift Package Manager

```swift
// Package.swift
dependencies: [
    .package(path: "https://github.com/inforaamitsolutions/MobShield-iOS")
]
```

```swift
.target(name: "YourApp", dependencies: [
    .product(name: "MobShieldCore", package: "MobShield"),
])
```

## CocoaPods

```ruby
pod 'MobShield/All', '1.0.1'
```

Add `scripts/mobshield-personalize.sh` as a Run Script build phase (see `MobShieldSampleApp`).

## Build and test

```bash
swift build
swift test
# Or open MobShieldSampleApp/MobShieldSampleApp.xcodeproj
```

## Sample app

`MobShieldSampleApp/` is a SwiftUI demo linking the local package and running the personalization script placeholder.

## Release

Tag `v*.*.*` builds XCFramework zips, uploads them to GitHub Releases, and runs `pod trunk push` when `COCOAPODS_TRUNK_TOKEN` is set.

```bash
./scripts/build-xcframeworks.sh
./scripts/verify-xcframework-reproducibility.sh
```

After release, update SwiftPM binary targets per [docs/versioning.md](../docs/versioning.md) using `scripts/update-spm-binary-checksums.sh`.

## License

- Swift sources and podspec: [Apache-2.0](LICENSE)
- Native core (when implemented): [LICENSE-BSL](LICENSE-BSL), Change Date 2028-05-25
