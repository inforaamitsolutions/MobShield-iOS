# iOS debugger detection

MobShield debugger detection (`MobShieldDetectDebugger`) implements four native checks and maps signals to `DEBUGGER` threat events.

## Signals

| Signal | Technique | Default weight | Default confidence |
|--------|-----------|----------------|--------------------|
| `ios.debug.sysctl_traced` | `sysctl(KERN_PROC_PID)` and `P_TRACED` | 70 | 75 |
| `ios.debug.deny_attach` | `ptrace(PT_DENY_ATTACH)` via `dlsym` | 50 | 60 |
| `ios.debug.mach_exception` | `task_get_exception_ports` | 75 | 80 |
| `ios.debug.timing` | `mach_absolute_time` loop delta | 55 | 65 |

## Techniques

### sysctl traced

Reads `kinfo_proc` for the current PID and tests the `P_TRACED` flag. This is reliable when a debugger is attached, but also triggers under Xcode and XCTest.

### ptrace deny attach

Resolves `ptrace` from `libsystem_kernel.dylib` and calls `PT_DENY_ATTACH`. MobShield only runs this check when `MobShieldConfig.enablePtraceDenyAttach` is `true`. A failure after attach may indicate an active debugger.

`PT_DENY_ATTACH` uses a non-public request constant. It is a common hardening technique but may be questioned during App Review. Keep it disabled for App Store builds unless your legal team approves.

### Mach exception ports

Calls `task_get_exception_ports` and flags non-null ports that are not the task self port. Debuggers and some instrumentation frameworks register exception handlers.

### Timing check

Compares a tight loop duration against an empty baseline using `mach_absolute_time`. Single-stepping under a debugger inflates the loop time.

## Configuration

```swift
let config = try MobShieldConfig.make(
    enablePtraceDenyAttach: false // default; set true only for hardened non-App-Store builds
)
await DebuggerDetectionRegistrar.register(config: config)
```

## Simulator and XCTest behavior

Stock Simulator integration tests expect `HOOK_FRAMEWORK` to stay false. Debugger detection may legitimately emit `DEBUGGER` when Xcode attaches to the test process (`P_TRACED`). Treat `ios.debug.sysctl_traced` as a weak signal during local development.

## Bypass notes

| Check | Common bypass |
|-------|----------------|
| `ios.debug.sysctl_traced` | Kernel patches that clear `P_TRACED` |
| `ios.debug.deny_attach` | Attach before MobShield starts, or kernel bypass |
| `ios.debug.mach_exception` | Restoring default exception ports after hooking |
| `ios.debug.timing` | Debugger without single-stepping, or patched timing APIs |

## App Store notes

`sysctl` and Mach task APIs are public. `ptrace` is public, but `PT_DENY_ATTACH` is a private request number. MobShield does not ship kernel exploits or hidden APIs beyond what many hardening kits already use.

Module name: `debugger`. Module criticality: `80`.
