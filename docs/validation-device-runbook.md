# MobShield iOS — on-device validation runbook

This is the manual procedure for confirming the detectors actually fire on a **compromised**
device. It pairs with [`validation.md`](validation.md) (the expected-signal matrix) and the sample
app's **Diagnostics → Run validation** screen (which runs `MobShieldValidation` and produces a
copyable report).

Positive detection cannot be proven on a stock Simulator — it cannot be jailbroken and has no Frida
attached. These steps require a real device you control.

> Use a dedicated **test device**, not a daily driver. Jailbreaking weakens the device's security
> posture; do it only on hardware you own and can wipe. Follow each tool's own official
> instructions for the jailbreak/Frida install itself — this runbook only covers running MobShield
> and recording what fires.

## Prerequisites

- A test iPhone/iPad you can jailbreak and/or attach Frida to.
- Xcode with a signing team. The sample app ships with a placeholder `DEVELOPMENT_TEAM`; set your
  own in **Signing & Capabilities** before installing to a device.
- One or more of the following, per the scenario you want to validate:
  - **Jailbreak:** palera1n (checkm8 / A9–A11), Dopamine (A12–A16, iOS 15–16.x), or unc0ver —
    whichever supports your device/iOS.
  - **Frida:** `frida-server` running on a jailbroken device, **or** the `FridaGadget.dylib`
    fixture bundled in `MobShieldSampleApp/` linked into a build (no jailbreak needed for the
    gadget path).
  - **Debugger:** lldb / launching from Xcode.

## Running a validation pass

1. Open `MobShieldSampleApp/MobShieldSampleApp.xcodeproj`, set your signing team, select the
   physical device, and Run.
2. **Config** tab: confirm all four modules are enabled (Jailbreak, Hooks, Debugger, Integrity).
3. **Diagnostics** tab → **Run validation**.
4. Read the report: each module shows **FIRED / clean** with the signals it emitted, followed by
   the aggregated **threats** (type · severity · score) and the **highest severity**.
5. Tap **Copy report** and paste the text into the results template below.
6. Compare the fired signals against the expected sets in
   [`validation.md`](validation.md#compromised-environment-expected-positive-detections).

### Establish the clean baseline first

Before compromising the device, run one pass on the **stock** device:

- **Expected:** no `PRIVILEGED_ACCESS` and no `HOOK_FRAMEWORK`. `ios.integrity.receipt` will fire
  on a non-App-Store (Xcode) install — this is the documented benign baseline, not a detection.
- **Debugger caveat:** launching from Xcode attaches a debugger, so `ios.debug.*` / `DEBUGGER`
  **will** fire. To capture a clean debugger baseline, launch the app by tapping its icon (not from
  Xcode) and then run validation.

## Scenarios

| # | Setup | Expected fired signals (≥1) | Expected threat |
|---|---|---|---|
| 1 | Stock device, launched from home screen | none of `ios.jb.*` / `.hook.*` / `ios.debug.*` | none (except benign `ios.integrity.receipt`) |
| 2 | Jailbroken (palera1n / Dopamine / unc0ver) | `ios.jb.fs_probe`, `ios.jb.dyld_image`, `ios.jb.symlink`, `ios.jb.sysctl_traced` | `PRIVILEGED_ACCESS` (high/critical) |
| 3 | `frida-server` running on the device | `common.hook.frida_maps`, `ios.hook.frida_port`, `ios.hook.mach_region` | `HOOK_FRAMEWORK` |
| 4 | `FridaGadget.dylib` linked into the build | `common.hook.frida_maps` (and possibly `ios.hook.mach_region`) | `HOOK_FRAMEWORK` |
| 5 | Launched under lldb / from Xcode | `ios.debug.mach_exception`, `ios.debug.sysctl_traced` | `DEBUGGER` |
| 6 | Re-signed / repackaged `.ipa`, anchors configured | `ios.integrity.sec_code` and/or `ios.integrity.bundle_id` | `APP_INTEGRITY` |

Scenario 6 requires anchoring integrity in the config (`expectedSigners`, `expectedPackageId`,
`expectedResourceHashes`) for a legitimate build, then installing a tampered copy.

## Results template

Copy this block per device/OS/tool combination and fill it in.

```
Device:        e.g. iPhone X (A11)
iOS version:   e.g. 16.5
Tool + version: e.g. palera1n 2.0.x  /  frida-server 16.x  /  none
App build:      MobShield.getBuildId() prefix (shown on the About tab)
Date:

Scenario: [1 clean | 2 jailbreak | 3 frida-server | 4 frida-gadget | 5 debugger | 6 re-sign]

--- pasted "Copy report" output ---


--- assessment ---
Fired signals:          <list>
Aggregated threats:     <type / severity / score>
Matches expected table: [ yes / no ]
Notes / anomalies:
```

## Recording outcomes

- Commit filled-in results under `docs/validation-results/` (create as needed), one file per
  device, so the detection matrix has evidence behind it over time.
- A **miss** (expected signal did not fire) is a detector bug or an evasion — open an issue with
  the device/tool details and the pasted report.
- An **unexpected fire on the clean baseline** (scenario 1 raising `PRIVILEGED_ACCESS` or
  `HOOK_FRAMEWORK`) is a false positive — likewise worth an issue.

## Status

Phases 1 (harness + matrix) and 2 (on-device Diagnostics screen) have landed. This runbook is
Phase 3. Actual per-device results are captured by whoever runs the passes above; they cannot be
produced in CI, which only exercises the clean Simulator baseline.
