# MobShield iOS

Open-source mobile app hardening for iOS: modular RASP detectors, signal aggregation, and per-build native personalization.

[![iOS CI](https://github.com/inforaamitsolutions/MobShield-iOS/actions/workflows/ios-ci.yml/badge.svg)](https://github.com/inforaamitsolutions/MobShield-iOS/actions/workflows/ios-ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Platform: iOS 15+](https://img.shields.io/badge/platform-iOS%2015%2B-lightgrey.svg)

MobShield runs a set of detection modules, aggregates their weighted signals into `ThreatEvent`s, and reports your app's runtime posture through a listener — so your app can react to jailbreak, hooking, debugging, and integrity-tampering conditions.

## Products

| Product | Purpose |
|---------|---------|
| `MobShieldCore` | Public API facade, aggregator, validation harness, native bridge (skeleton) |
| `MobShieldDetectJailbreak` | Dopamine, palera1n, unc0ver, checkra1n, rootless |
| `MobShieldDetectHooks` | Frida, Substrate, ElleKit |
| `MobShieldDetectDebugger` | ptrace, sysctl, Mach exceptions |
| `MobShieldDetectEnvironment` | Simulator, automation |
| `MobShieldDetectIntegrity` | SecCode, build anchor |

## Requirements

- Xcode 15+
- iOS 15+
- Swift 5.9+

## Install

### Swift Package Manager

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/inforaamitsolutions/MobShield-iOS", from: "1.0.3"),
]
```

```swift
.target(name: "YourApp", dependencies: [
    .product(name: "MobShieldCore", package: "MobShield"),
    // add the detectors you want:
    .product(name: "MobShieldDetectJailbreak", package: "MobShield"),
    .product(name: "MobShieldDetectHooks", package: "MobShield"),
    .product(name: "MobShieldDetectDebugger", package: "MobShield"),
    .product(name: "MobShieldDetectIntegrity", package: "MobShield"),
])
```

### CocoaPods

```ruby
pod 'MobShield/All', '1.0.3'
```

Add `scripts/mobshield-personalize.sh` as a Run Script build phase (see `MobShieldSampleApp`).

## Quick start

Register the detectors you added, implement a listener, and start MobShield. It runs in **detect-only** mode by default (it reports; it never terminates your process).

```swift
import MobShieldCore
import MobShieldDetectJailbreak
import MobShieldDetectHooks
import MobShieldDetectDebugger
import MobShieldDetectIntegrity

final class MyListener: MobShieldListener {
    func onThreat(_ event: ThreatEvent) {
        print("MobShield threat:", event.type, event.severity, "score:", event.score)
    }
    func onAllChecksFinished(_ events: [ThreatEvent]) {
        print("MobShield scan finished:", events.count, "threat(s)")
    }
}

// Retain the listener for the lifetime of the run (a property on your App/AppDelegate is fine).
let listener = MyListener()

Task {
    let config = MobShieldConfig() // detect-only by default
    await JailbreakDetectionRegistrar.register(config: config)
    await HookDetectionRegistrar.register(config: config)
    await DebuggerDetectionRegistrar.register(config: config)
    await IntegrityDetectionRegistrar.register(config: config)
    MobShield.shared.start(config: config, listener: listener)
}
```

Read the current posture at any time, or stop scanning:

```swift
let state = MobShield.shared.getState()   // riskLevel, activeThreats, running, lastScanMs
MobShield.shared.stop()
```

Common configuration (all optional):

```swift
let config = try MobShieldConfig.builder()
    .periodicIntervalSec(30)                 // rescan every 30s (default: one scan at start)
    .expectedPackageId("com.example.app")    // anchor bundle-id integrity
    .expectedSigners(["<sha256-hex>"])       // anchor code-signing integrity
    .detectOnly(false)                       // opt in to termination
    .terminationPolicy(.exitOnCritical)      // kill the process on a critical threat
    .build()
```

For a signed posture report you can verify on your backend, see `MobShield.shared.currentSignedReport(key:)`.

## Build and test

```bash
swift build
swift test
# Or open MobShieldSampleApp/MobShieldSampleApp.xcodeproj
```

## Sample app

`MobShieldSampleApp/` is a SwiftUI demo linking the local package. Its **Diagnostics → Run validation** screen runs every enabled module and shows which signals fired, aggregated into threats.

## Documentation

- [Detection validation matrix](docs/validation.md) — every signal each module emits and the clean vs compromised baselines.
- [On-device validation runbook](docs/validation-device-runbook.md) — validate against a real jailbreak / Frida / debugger.
- [Xcode integration notes](docs/integration-xcode.md).

## Release

Tag `*.*.*` (e.g. `1.0.3`) on this repo for SwiftPM; optionally build XCFramework zips for GitHub Releases and run `pod trunk push` for CocoaPods.

```bash
./scripts/build-xcframeworks.sh
./scripts/verify-xcframework-reproducibility.sh
```

For binary SwiftPM distribution, update the binary targets with `scripts/update-spm-binary-checksums.sh` after publishing the Release zips.

## License

- Swift sources and podspec: [Apache-2.0](LICENSE)
- Native core (when implemented): [LICENSE-BSL](LICENSE-BSL), Change Date 2028-05-25
