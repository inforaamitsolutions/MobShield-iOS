# iOS hook detection

MobShield hook detection (`MobShieldDetectHooks`) implements six native checks and maps signals to `HOOK_FRAMEWORK` threat events.

## Signals

| Signal | Technique | Default weight | Default confidence |
|--------|-----------|----------------|--------------------|
| `ios.hook.mach_region` | `vm_region_recurse_64` RWX anonymous regions | 70 | 75 |
| `common.hook.prologue` | First 16 bytes of native symbols | 80 | 90 |
| `common.hook.frida_maps` | Dyld image names (`FridaGadget`, `gum-js-loop`, etc.) | 75 | 85 |
| `ios.hook.frida_port` | TCP connect to `127.0.0.1:27042` and `:27043` (100ms timeout) | 30 | 50 |
| `ios.hook.dyld_insert` | `DYLD_INSERT_LIBRARIES`, `DYLD_FORCE_FLAT_NAMESPACE` | 65 | 70 |
| `ios.hook.method_swizzle` | `class_getInstanceMethod` IMP comparison | 75 | 85 |

## Techniques

### Mach region inspect

Walks the task address space with `vm_region_recurse_64` and flags anonymous read-write-execute regions. JIT and some Simulator hosts produce false positives, so the check returns `UNAVAILABLE` on `TARGET_OS_SIMULATOR`.

### Function prologue inspect

Reads the first 16 bytes of configured symbols (default: `objc_msgSend`, `open`, `syscall`). When personalization supplies hex baselines, bytes must match. Otherwise MobShield flags ARM64 trampolines (`B` / `LDR`+`BR` patterns).

### Frida artifact scan

Uses `_dyld_get_image_name` to find Frida Gadget, agent, and Gum-related libraries.

### Frida port probe

Non-blocking `connect()` to Frida default ports. Low weight by design because ports are configurable.

### Dyld environment scan

Reads `DYLD_INSERT_LIBRARIES` and `DYLD_FORCE_FLAT_NAMESPACE`. Unavailable on Simulator builds where the variable may be set by the host toolchain.

### Method swizzle detect

Compares IMP pointers for curated Foundation APIs. With personalized baselines, compares against expected IMP hex from the build plugin. Without baselines, compares against the superclass IMP.

## Personalization

Provide baselines via `MobShieldConfig`:

```swift
let config = try MobShieldConfig.make(
    hookPrologueBaselines: [
        HookPrologueBaseline(symbolName: "objc_msgSend", expectedBytesHex: "ff0301d1...")
    ],
    hookSwizzleBaselines: [
        HookSwizzleBaseline(
            className: "NSString",
            selector: "isEqualToString:",
            expectedImplementationHex: "0000000100000000"
        )
    ]
)
```

The Xcode personalize script can inject per-build values into these fields.

## Bypass notes

| Check | Common bypass |
|-------|----------------|
| `common.hook.prologue` | Frida Stalker and inline hooks that avoid rewriting the first 16 bytes |
| `ios.hook.method_swizzle` | Hooks that preserve original IMP or only swizzle app classes |
| `ios.hook.frida_port` | Custom port, host forwarding, or gadget mode without a listener |
| `common.hook.frida_maps` | Renamed dylibs, in-memory modules without dyld registration |
| `ios.hook.mach_region` | Hook frameworks that avoid RWX anonymous mappings |

## App Store notes

`DYLD_INSERT_LIBRARIES` inspection is intended for enterprise or debug builds. App Store binaries should not ship with injection enabled. Port scanning is passive localhost TCP and is generally acceptable, but document it in your privacy policy if enabled.

## Registration

```swift
await HookDetectionRegistrar.register(config: mobShieldConfig)
```

Module name: `hooks`. Module criticality: `85`.
