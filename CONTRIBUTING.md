# Contributing to MobShield

Thank you for your interest in MobShield. This project spans `mobshield-android`, `mobshield-ios`, and `mobshield-spec`.

## Getting started

1. Read [MOBSHIELD_SPEC.md](../mobshield-spec/MOBSHIELD_SPEC.md).
2. Pick a platform directory and build the sample app.
3. Open a draft PR early for architectural changes.

## Pull requests

- Keep changes focused; one concern per PR.
- Add or update tests for Kotlin/Swift logic you change.
- Native detection changes must document new signal names in `mobshield-spec/DETECTION_CATALOG.md`.
- Run local linters before pushing (ktlint/detekt on Android, SwiftLint on iOS).

## Licensing

- Kotlin, Swift, Gradle, and podspec files: **Apache 2.0**.
- Native C/C++ core: **BSL 1.1** until the Change Date, then Apache 2.0. See `LICENSE-BSL`.

## Code of conduct

See [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).
