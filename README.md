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

## Why MobShield

- **Fully auditable.** The detection logic is open source under Apache-2.0, so you can review it, fork it, and audit it.
- **No telemetry.** MobShield makes no network calls. Threat events go only to your listener and, if you choose, your backend.
- **Modular.** Add only the products you need.
- **Safe to roll out.** It's detect-only by default and never kills your process unless you opt in.
- **Harder to bypass generically.** A personalization build phase makes each build unique, so one off-the-shelf bypass script doesn't fit every app.
- **Server-verifiable.** Signed posture reports let your backend decide whether to trust a session.

MobShield raises the cost of an attack. Like any client-side protection, it can't make an app unbreakable, so pair it with server-side checks.

## How it compares

| | MobShield | [freeRASP](https://github.com/talsec/Free-RASP-iOS) | [IOSSecuritySuite](https://github.com/securing/IOSSecuritySuite) |
|---|---|---|---|
| License | Apache-2.0 (Swift); native core BSL | MIT wrapper + proprietary binary core, fair-usage policy | Proprietary EULA: free for companies with ≤100 employees, paid plans above |
| Detection logic auditable | ✅ | ❌ (closed binary) | ✅ |
| Sends data to a vendor | ❌ No network calls | Incident data feeds Talsec's weekly Security Report | ❌ |
| Jailbreak (Dopamine, palera1n, rootless) | ✅ | ✅ | ✅ |
| Hooking (Frida, Substrate, ElleKit) | ✅ | ✅ | ✅ (runtime/MSHook detection marked experimental) |
| Debugger | ✅ | ✅ | ✅ |
| Simulator / automation | ✅ | ✅ | ✅ (simulator) |
| Code-signing / tamper integrity | ✅ | ✅ | ✅ |
| Backend-verifiable report | ✅ Signed report, your own key | AppiCrypt (commercial plan) | ❌ |
| Per-build personalization | ✅ | ❌ | ❌ |
| Platforms | iOS + [Android](https://github.com/inforaamitsolutions/MobShield-Android) | iOS, Android, Flutter, RN, Cordova, Capacitor | iOS |

IOSSecuritySuite also offers proxy/VPN and Lockdown Mode detection plus active "deny" APIs, and freeRASP is ahead on cross-platform framework support. If you need those today, they're good choices. *Comparison based on each project's public README and license as of October 2026. Corrections are welcome via PR.*

## OWASP MASVS mapping

| MASVS v2 control | MobShield product |
|---|---|
| MASVS-RESILIENCE-1: platform integrity | `MobShieldDetectJailbreak`, `MobShieldDetectEnvironment` |
| MASVS-RESILIENCE-2: anti-tampering | `MobShieldDetectIntegrity` |
| MASVS-RESILIENCE-4: anti-dynamic analysis | `MobShieldDetectHooks`, `MobShieldDetectDebugger`, `MobShieldDetectEnvironment` |

## Requirements

- Xcode 15+
- iOS 15+
- Swift 5.9+

## Install

### Swift Package Manager

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/inforaamitsolutions/MobShield-iOS", from: "1.1.0"),
]
```

```swift
.target(name: "YourApp", dependencies: [
    .product(name: "MobShieldCore", package: "MobShield"),
    // add the detectors you want:
    .product(name: "MobShieldDetectJailbreak", package: "MobShield"),
    .product(name: "MobShieldDetectHooks", package: "MobShield"),
    .product(name: "MobShieldDetectDebugger", package: "MobShield"),
    .product(name: "MobShieldDetectEnvironment", package: "MobShield"),
    .product(name: "MobShieldDetectIntegrity", package: "MobShield"),
])
```

### CocoaPods

```ruby
pod 'MobShield/All', '1.1.0'
```

Add `scripts/mobshield-personalize.sh` as a Run Script build phase (see `MobShieldSampleApp`).

## Quick start

Register the detectors you added, implement a listener, and start MobShield. It runs in **detect-only** mode by default (it reports; it never terminates your process).

```swift
import MobShieldCore
import MobShieldDetectJailbreak
import MobShieldDetectHooks
import MobShieldDetectDebugger
import MobShieldDetectEnvironment
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
    await EnvironmentDetectionRegistrar.register(config: config)
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

Tag `*.*.*` (e.g. `1.1.0`) on this repo for SwiftPM; optionally build XCFramework zips for GitHub Releases and run `pod trunk push` for CocoaPods.

```bash
./scripts/build-xcframeworks.sh
./scripts/verify-xcframework-reproducibility.sh
```

For binary SwiftPM distribution, update the binary targets with `scripts/update-spm-binary-checksums.sh` after publishing the Release zips.

## License

- Swift sources and podspec: [Apache-2.0](LICENSE)
- Native core (when implemented): [LICENSE-BSL](LICENSE-BSL), Change Date 2028-05-25
