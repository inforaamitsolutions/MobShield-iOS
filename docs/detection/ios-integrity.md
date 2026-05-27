# iOS integrity detection

MobShield integrity detection (`MobShieldDetectIntegrity`) validates code signature, bundle identity, provisioning metadata, anchored resources, and App Store receipts. Signals map to `APP_INTEGRITY` threat events.

## Signals

| Signal | Technique | Default weight | Default confidence |
|--------|-----------|----------------|--------------------|
| `ios.integrity.sec_code` | `SecCodeCopySelf` + `SecCodeCopySigningInformation` | 90 | 95 |
| `ios.integrity.bundle_id` | `Bundle` identifier vs anchor | 85 | 90 |
| `ios.integrity.provisioning` | `embedded.mobileprovision` plist parse | 70 | 80 |
| `ios.integrity.resource` | SHA-256 of anchored bundle files | 80 | 85 |
| `ios.integrity.receipt` | `appStoreReceiptURL` basic PKCS#7 shape | 55 | 65 |

## Re-signing attack model

A repackaged IPA typically changes one or more of:

1. **Code signature** (new certificate digest, team ID, or ad-hoc sign)
2. **Bundle identifier** (different `CFBundleIdentifier`)
3. **Provisioning profile** (enterprise or development profile swapped in)
4. **Resources** (`Info.plist`, storyboards, assets tampered)
5. **App Store receipt** (missing, truncated, or non-PKCS#7 payload on sideload builds)

MobShield compares live runtime values to anchors baked into `MobShieldConfig` at build time via the personalization plugin.

Attackers who strip signatures entirely often fail `SecCodeCopySigningInformation` or present certificates outside the allowlist. Attackers who re-sign with their own developer certificate are caught when `expectedSigners` and `expectedPackageId` do not match.

## Configuration

```swift
let config = try MobShieldConfig.make(
    expectedSigners: ["<sha256-of-signing-cert>"],
    expectedPackageId: "com.example.app",
    expectedResourceHashes: [
        "Info.plist": "<sha256>",
        "Main.storyboardc/Info.plist": "<sha256>",
    ]
)
await IntegrityDetectionRegistrar.register(config: config)
```

- `expectedSigners`: SHA-256 digests of signing certificates (64 hex chars). Empty skips `ios.integrity.sec_code`.
- `expectedPackageId`: Optional; when set enables bundle ID and provisioning checks.
- `expectedResourceHashes`: Relative paths inside the `.app` bundle. Empty skips resource hashing.

## Checks

### Code signature

Uses Security.framework certificate APIs. On iOS, `SecCodeCopySelf` is not exposed in the mobile SDK, so MobShield reads `DeveloperCertificates` from `embedded.mobileprovision` and computes SHA-256 digests with `SecCertificateCreateWithData`. Any expected digest match is treated as success.

### Bundle identifier

Compares `Bundle.main.bundleIdentifier` to `expectedPackageId`.

### Embedded provisioning profile

Reads `embedded.mobileprovision`, extracts the XML plist, and compares `application-identifier` to `TEAMID.expectedPackageId`. Missing profile is ignored on Simulator; on device a missing profile may indicate an App Store distribution build.

### Resource integrity

Hashes files at anchored paths with SHA-256 (CryptoKit). The personalization script should record digests for `Info.plist` and the main storyboard (`UIMainStoryboardFile`).

### App Store receipt

When `appStoreReceiptURL` is present, verifies readability, minimum size, and ASN.1 SEQUENCE prefix (`div 0x30`). Absent receipts on Simulator or developer builds do not emit a signal.

## Bypass notes

| Check | Limitation |
|-------|------------|
| `ios.integrity.sec_code` | Attacker with a stolen enterprise cert matching allowlist |
| `ios.integrity.resource` | Runtime file patching after launch without changing on-disk hash before scan |
| `ios.integrity.receipt` | Does not call Apple's online receipt verification |
| All client checks | Skilled attackers can patch MobShield itself |

## Registration

```swift
await IntegrityDetectionRegistrar.register(config: mobShieldConfig)
```

Module name: `integrity`. Module criticality: `100`.
