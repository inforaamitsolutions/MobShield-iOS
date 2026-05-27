# Xcode integration

MobShield personalization runs as a Run Script build phase before native compilation so each app build embeds unique constants in `mobshield_buildinfo.h`.

## Build phase order

1. **MobShield Personalize** (`mobshield-personalize.sh`) before **Compile Sources**
2. Normal compile and link
3. **MobShield Verify** (`mobshield-verify.sh`) after the app binary is produced

## Required xcconfig entries

Add to your app target `.xcconfig` or build settings:

```
MOBSHIELD_EXPECTED_SIGNER_SHA256 = <64-hex-sha256>
MOBSHIELD_EXPECTED_BUNDLE_ID = com.example.app
MOBSHIELD_EXPECTED_TEAM_ID = ABCDE12345
MOBSHIELD_AGGRESSIVE_ANTI_DEBUG = NO
MOBSHIELD_INTEGRITY_RESOURCE_PATHS = Info.plist Main.storyboardc/Info.plist
```

Pass them to the script via **User-Defined** settings or an `.xcconfig` file included by the target.

## Run Script phases

**Personalize (before compile):**

```bash
"${SRCROOT}/../scripts/mobshield-personalize.sh"
```

Add header search path for generated file:

```
HEADER_SEARCH_PATHS = $(inherited) $(DERIVED_FILE_DIR)
```

**Verify (after link):**

```bash
"${SRCROOT}/../scripts/mobshield-verify.sh"
```

## Compute signing certificate SHA-256

Export the certificate from Keychain Access or use:

```bash
security find-identity -v -p codesigning
codesign -d --extract-certificates /path/to/YourApp.app
openssl x509 -inform DER -in codesign0 -outform PEM | openssl x509 -noout -fingerprint -sha256
```

Remove the `sha256 ` prefix and colons, then set `MOBSHIELD_EXPECTED_SIGNER_SHA256` to the 64-character hex value.

## CocoaPods

The `MobShield.podspec` includes a personalize script phase on consumer targets when using the `All` subspec. Override xcconfig values in your app target.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Script does not run every build | Disable "Based on dependency analysis" for the Run Script phase |
| Header not found | Add `$(DERIVED_FILE_DIR)` to **Header Search Paths** |
| Verify fails on entropy | Ensure personalize runs before compile and `mobshield_buildinfo.h` is included by native targets |
| Signing mismatch | Update `MOBSHIELD_EXPECTED_SIGNER_SHA256` for the configuration you build (Debug vs Release) |

## Reproducibility

Personalized binaries are **not** reproducible across builds by design. Only generic MobShield source releases are reproducible from git tags.
