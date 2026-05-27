# MobShield iOS sample app

SwiftUI reference app demonstrating MobShieldCore and all shipped detection modules with Xcode personalization scripts.

## Prerequisites

- macOS with Xcode 15 or newer
- iOS 15+ simulator or device

## Run in under 15 minutes

1. Clone MobShield and open `mobshield-ios/MobShieldSampleApp/MobShieldSampleApp.xcodeproj`.
2. Wait for Swift Package Manager to resolve the local `mobshield-ios` package.
3. Select the **MobShieldSampleApp** scheme and an iOS simulator.
4. Build and run (Cmd+R).
5. On the **Threats** tab, tap **Start**. Open Console.app and filter subsystem `io.mobshield.sample`.
6. Open **Signals** and tap **Refresh signals** for raw probe output.
7. Confirm build phases **MobShield Personalize** (before Sources) and **MobShield Verify** (after link) succeed.

## Personalization

The project includes Run Script phases wired to `../scripts/mobshield-personalize.sh` and `mobshield-verify.sh`. Build settings include:

- `HEADER_SEARCH_PATHS = $(DERIVED_FILE_DIR)` for generated `mobshield_buildinfo.h`
- `MOBSHIELD_EXPECTED_BUNDLE_ID = io.mobshield.sample`
- `MOBSHIELD_AGGRESSIVE_ANTI_DEBUG = NO`

See [integration-xcode.md](../docs/integration-xcode.md) for signing cert SHA-256 and team ID setup.

## Modules demonstrated

- MobShieldCore with default `SignalAggregator` thresholds
- MobShieldDetectJailbreak, Hooks, Debugger, Integrity
- `MobShieldListener` with `os.log` structured logging

## Screens

| Tab | Purpose |
|-----|---------|
| Threats | Live threat event cards |
| Config | Detect-only vs fail-closed, module toggles, ptrace option |
| Signals | Raw `Signal` list from enabled modules |
| About | SDK version, build entropy preview, MASVS summary |
