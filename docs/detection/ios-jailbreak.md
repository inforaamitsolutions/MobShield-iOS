# iOS Jailbreak Detection (MobShieldDetectJailbreak)

This module implements eight native checks and aggregates signals into `PRIVILEGED_ACCESS` threat events (MASVS-RES-1).

## Signal catalog

| Signal | Technique | Default weight | Default confidence |
|--------|-----------|----------------|-------------------|
| `ios.jb.dyld_image` | `_dyld_get_image_name` suspicious libraries | 80 | 85 |
| `ios.jb.fs_probe` | `stat()` + `access()` on known JB paths | 85 | 90 |
| `ios.jb.sandbox_break` | `fork()` / `vfork()` sandbox escape | 75 | 80 |
| `ios.jb.url_scheme` | `canOpenURL` for package manager schemes | 25 | 40 |
| `ios.jb.sysctl_traced` | `sysctl` `P_TRACED` on self | 70 | 75 |
| `ios.jb.write_test` | write probe outside sandbox | 80 | 85 |
| `ios.jb.symlink` | `lstat` symlink on `/Applications` | 70 | 80 |
| `ios.jb.dyld_header` | Mach-O `MH_DYLIB` suspicious names | 75 | 85 |

Override weights via `MobShieldConfig.detectionTuning`.

## Native checks (`MobShieldDetectJailbreakNative`)

### 1. dyld_image_scan.mm

Iterates `_dyld_image_count` / `_dyld_get_image_name` for Substrate, Substitute, ElleKit, libhooker, Frida, `/var/jb/`, and related markers.

**Survives:** hidden package UI, renamed user apps.

**Bypass:** manual map cleaning, per-process hide plugins.

### 2. filesystem_paths.c

Probes rootful, Sileo, Dopamine, and palera1n paths using both `stat()` and `access(F_OK)`. Additional paths come from `MobShieldConfig.additionalJailbreakPaths`.

**Survives:** most rootless installs that leave `/var/jb` artifacts.

**Bypass:** vnode hooks that patch only one API, path relocation, strong hide lists.

### 3. sandbox_escape.c

Attempts `fork()` and `vfork()`. On a stock device these fail; success suggests a weakened sandbox.

**Survives:** classic sandbox break indicators.

**Bypass:** patched libc that fakes failure while allowing escapes elsewhere.

### 4. url_scheme_probe.mm

Uses public `-[UIApplication canOpenURL:]` for `cydia://`, `sileo://`, `zbra://`, and `filza://`.

**Survives:** installed package managers when declared in Info.plist.

**Bypass:** scheme hiding, missing `LSApplicationQueriesSchemes` entries (probe returns benign).

### 5. sysctl_traced.c

Reads `KERN_PROC_PID` and checks `P_TRACED`. Useful when a debugger is attached during JB testing; can overlap debugger detection.

### 6. write_test.c

Attempts `fopen` on `/private/jailbreak_test.txt`. Non-jailbroken iOS returns `NULL`.

**Survives:** rootless write probes better than bare `/Applications/Cydia.app` alone.

**Bypass:** hooks that fake `fopen` failure without fixing real writes.

### 7. symlink_test.c

`lstat("/Applications")` and related paths for symlink layout common on jailbroken devices.

### 8. dyld_get_image_header_inspect.mm

Walks Mach-O headers for loaded `MH_DYLIB` images with suspicious install names.

## Swift configuration

```swift
let config = MobShieldConfig(
    additionalJailbreakPaths: ["/custom/marker/path"]
)
await JailbreakDetectionRegistrar.register(config: config)
```

`ConfigurableSuspiciousPaths` merges built-in and additional paths before native registration.

## Info.plist requirement (URL schemes)

Add queried schemes to the host app `Info.plist`:

```xml
<key>LSApplicationQueriesSchemes</key>
<array>
    <string>cydia</string>
    <string>sileo</string>
    <string>zbra</string>
    <string>filza</string>
</array>
```

Without this, `canOpenURL` may return false even when a package manager is installed. This is expected App Store behavior, not a MobShield bug.

## Simulator vs real device

Unit tests on the iOS Simulator use mocked filesystem and dyld providers. Integration tests call real native code and expect **no** `PRIVILEGED_ACCESS` on stock Simulator images.

On Simulator builds:

- `sandbox_escape` returns `UNAVAILABLE` because `fork()` is not a reliable jailbreak indicator on Simulator hosts.
- `filesystem_paths` uses a reduced path list (package-manager artifacts only). Generic Unix paths such as `/bin/bash` and bare `/var/jb` are omitted to avoid host filesystem false positives.

`sysctl_traced` may report `P_TRACED` when Xcode attaches a debugger during development or XCTest runs. Treat that signal as a weak hint or tune it down in debug builds.

Validate on physical jailbroken devices (Dopamine, palera1n, unc0ver) before relying on thresholds in production.

## App Store notes

Checks use public APIs (`canOpenURL`, `sysctl`, `stat`, `access`, dyld introspection). Fork-based probes are a grey area: they do not spawn a useful child on stock iOS but are common in JB detectors. Document in your privacy policy if you enable this module. MobShield does not ship exploits or private API calls.

## Registration

```swift
await JailbreakDetectionRegistrar.register(config: mobShieldConfig)
```

Module name: `jailbreak`. Module criticality: `90`.
