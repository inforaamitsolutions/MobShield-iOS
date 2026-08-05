# MobShield iOS — Detection validation

This document defines **what each detector is expected to report**, so a run on a real device can
be checked against a known baseline instead of a guess. It is the reference for the validation
harness (`MobShieldValidation`) and the on-device procedure.

## Why this exists

The `*SimulatorIntegration` unit tests run on a **clean** iOS Simulator, which by definition cannot
be jailbroken and has no Frida attached. They prove the detectors do not crash and do not raise
false positives in a clean environment — they do **not** prove a detector fires when the threat is
actually present. Confirming positive detection requires running on a compromised device. This
matrix + the harness make that check repeatable.

## The validation harness

`MobShieldValidation` (in `MobShieldCore`) runs the registered detection modules and returns a
`ValidationReport` exposing both layers:

- **Raw signals** — per module, exactly which `Signal`s fired, with weight/confidence/evidence.
- **Aggregated events** — the `ThreatEvent`s those signals map to, with severity and score.

```swift
// Register the modules you want to validate, then:
let report = await MobShieldValidation.runRegistered()
for module in report.modules {
    print(module.moduleName, module.didFire, module.signals.map(\.name))
}
print("threats:", report.activeThreatTypes, "severity:", report.highestSeverity as Any)
```

`report.firedSignalNames` and `report.activeThreatTypes` are the two things to compare against the
tables below.

## Expected-signal matrix

Weights/confidences are the built-in defaults (overridable via `detectionTuning`). "Signal fires
when…" describes the runtime condition that produces the signal.

### Jailbreak — module `jailbreak`, threat `PRIVILEGED_ACCESS`

| Signal | weight | conf | Signal fires when… |
|---|---|---|---|
| `ios.jb.fs_probe` | 85 | 90 | a known jailbreak path exists (`/Applications/Cydia.app`, `/var/jb`, …) |
| `ios.jb.write_test` | 80 | 85 | a write outside the sandbox (e.g. `/private/…`) succeeds |
| `ios.jb.dyld_image` | 80 | 85 | a loaded image name matches a jailbreak/tweak marker |
| `ios.jb.dyld_header` | 75 | 85 | a loaded dylib header name matches a marker |
| `ios.jb.sandbox_break` | 75 | 80 | `fork()`/`vfork()` succeeds (sandbox escaped) |
| `ios.jb.symlink` | 70 | 80 | a system path is a symlink (rootless remap) |
| `ios.jb.sysctl_traced` | 70 | 75 | the `P_TRACED` process flag is set |
| `ios.jb.url_scheme` | 25 | 40 | a package-manager URL scheme is openable (`cydia://`, `sileo://`, `filza://`) |

### Hooks — module `hooks`, threat `HOOK_FRAMEWORK`

| Signal | weight | conf | Signal fires when… |
|---|---|---|---|
| `common.hook.prologue` | 80 | 90 | a monitored function prologue is patched / trampolined |
| `ios.hook.frida_thread` | 80 | 90 | a running thread is named like a Frida worker (`gum-js-loop`, `gmain`, `gdbus`, `pool-frida`) |
| `ios.hook.frida_symbols` | 80 | 90 | an exported Gum/Frida symbol resolves (`gum_init_embedded`, `frida_agent_main`, …) |
| `common.hook.frida_maps` | 75 | 85 | a loaded image matches a Frida artifact (`FridaGadget`, `frida-agent`, …) |
| `ios.hook.method_swizzle` | 75 | 85 | an Objective-C method IMP differs from its baseline/superclass |
| `ios.hook.mach_region` | 70 | 75 | an anonymous private RWX memory region is present |
| `ios.hook.dyld_insert` | 65 | 70 | `DYLD_INSERT_LIBRARIES` / `DYLD_FORCE_FLAT_NAMESPACE` is set |
| `ios.hook.frida_port` | 30 | 50 | a Frida server port (27042/27043) accepts a connection |

### Debugger — module `debugger`, threat `DEBUGGER`

| Signal | weight | conf | Signal fires when… |
|---|---|---|---|
| `ios.debug.mach_exception` | 75 | 80 | a foreign Mach exception port is registered |
| `ios.debug.sysctl_traced` | 70 | 75 | the `P_TRACED` process flag is set |
| `ios.debug.timing` | 55 | 65 | a timing loop runs anomalously slow (single-stepping) |
| `ios.debug.deny_attach` | 50 | 60 | `ptrace(PT_DENY_ATTACH)` reports an attached tracer (opt-in) |

### Integrity — module `integrity`, threat `APP_INTEGRITY`

| Signal | weight | conf | Signal fires when… |
|---|---|---|---|
| `ios.integrity.sec_code` | 90 | 95 | the signing certificate digest is not in `expectedSigners` |
| `ios.integrity.bundle_id` | 85 | 90 | the bundle id differs from `expectedPackageId` |
| `ios.integrity.resource` | 80 | 85 | a bundle resource hash differs from `expectedResourceHashes` |
| `ios.integrity.provisioning` | 70 | 80 | the embedded profile's app id does not match `expectedPackageId` |
| `ios.integrity.receipt` | 55 | 65 | the App Store receipt is missing/malformed |

> Integrity signals only fire when the corresponding anchor is configured (`expectedSigners`,
> `expectedPackageId`, `expectedResourceHashes`). With a default config they stay silent — except
> `ios.integrity.receipt`, which fires in any build lacking an App Store receipt (see baseline
> note below).

## Environment baselines

### Clean environment (stock device / Simulator, App Store or dev build)

- **Must NOT fire:** any `ios.jb.*`, any `.hook.*` (`common.hook.*` / `ios.hook.*`), any
  `ios.debug.*`. `PRIVILEGED_ACCESS` and `HOOK_FRAMEWORK` must be absent. These are the strong
  false-positive guards.
- **Known benign signal:** `ios.integrity.receipt` fires on any non-App-Store build (Simulator,
  dev, TestFlight sideload) because there is no App Store receipt. This yields at most a
  low/medium `APP_INTEGRITY` event and is expected off the store. Anchor the other integrity
  checks (`expectedSigners`, etc.) for production.
- **Situational:** `ios.debug.*` will fire whenever a debugger is attached (e.g. launching from
  Xcode). Validate the clean debugger baseline from a build launched **without** the debugger.

### Compromised environment (expected positive detections)

| Scenario | Expect fired signals | Expect threat |
|---|---|---|
| Jailbroken (palera1n / Dopamine / unc0ver) | ≥1 of `ios.jb.fs_probe`, `ios.jb.dyld_image`, `ios.jb.symlink`, `ios.jb.sysctl_traced` | `PRIVILEGED_ACCESS` (high/critical) |
| Frida gadget linked / `frida-server` running | ≥1 of `ios.hook.frida_thread`, `ios.hook.frida_symbols`, `common.hook.frida_maps`, `ios.hook.frida_port`, `ios.hook.mach_region` | `HOOK_FRAMEWORK` |
| Debugger attached (lldb) | ≥1 of `ios.debug.mach_exception`, `ios.debug.sysctl_traced` | `DEBUGGER` |
| Re-signed / repackaged app | `ios.integrity.sec_code` and/or `ios.integrity.bundle_id` (with anchors configured) | `APP_INTEGRITY` |

## Status

- **Phase 1 (this doc + `MobShieldValidation` harness):** landed. Harness contract covered by
  `MobShieldValidationTests`; clean-environment behavior documented above.
- **Phase 2 (sample-app Diagnostics screen):** landed. **Diagnostics → Run validation** runs the
  harness on-device and produces a copyable report.
- **Phase 3 (device runbook + results template):** landed — see
  [`validation-device-runbook.md`](validation-device-runbook.md) for the step-by-step procedure to
  validate against a jailbreak / `frida-server` / debugger and record actual fired signals.
