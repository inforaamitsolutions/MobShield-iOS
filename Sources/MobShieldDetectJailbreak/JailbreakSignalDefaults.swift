/*
 * Copyright 2025 MobShield Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import MobShieldCore

/// Default signal names and tuning for iOS jailbreak detection.
public enum JailbreakSignalDefaults {
    public static let dyldImage = "ios.jb.dyld_image"
    public static let filesystemPaths = "ios.jb.fs_probe"
    public static let sandboxEscape = "ios.jb.sandbox_break"
    public static let urlScheme = "ios.jb.url_scheme"
    public static let sysctlTraced = "ios.jb.sysctl_traced"
    public static let writeTest = "ios.jb.write_test"
    public static let symlinkTest = "ios.jb.symlink"
    public static let dyldHeader = "ios.jb.dyld_header"

    private static let defaults: [String: SignalTuning] = [
        dyldImage: SignalTuning(weight: 80, confidence: 85),
        filesystemPaths: SignalTuning(weight: 85, confidence: 90),
        sandboxEscape: SignalTuning(weight: 75, confidence: 80),
        urlScheme: SignalTuning(weight: 25, confidence: 40),
        sysctlTraced: SignalTuning(weight: 70, confidence: 75),
        writeTest: SignalTuning(weight: 80, confidence: 85),
        symlinkTest: SignalTuning(weight: 70, confidence: 80),
        dyldHeader: SignalTuning(weight: 75, confidence: 85),
    ]

    public static func buildSignal(
        name: String,
        evidence: [String: String],
        tuning: [String: SignalTuning],
        overrideTuning: SignalTuning? = nil
    ) -> Signal {
        let resolved = overrideTuning ?? tuning[name] ?? defaults[name] ?? SignalTuning(weight: 50, confidence: 50)
        return Signal(
            name: name,
            weight: resolved.weight,
            confidence: resolved.confidence,
            evidence: evidence
        )
    }
}
