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

public enum HookSignalDefaults {
    public static let machRegion = "ios.hook.mach_region"
    public static let prologue = "common.hook.prologue"
    public static let fridaMaps = "common.hook.frida_maps"
    public static let fridaPort = "ios.hook.frida_port"
    public static let dyldInsert = "ios.hook.dyld_insert"
    public static let methodSwizzle = "ios.hook.method_swizzle"

    private static let defaults: [String: SignalTuning] = [
        machRegion: SignalTuning(weight: 70, confidence: 75),
        prologue: SignalTuning(weight: 80, confidence: 90),
        fridaMaps: SignalTuning(weight: 75, confidence: 85),
        fridaPort: SignalTuning(weight: 30, confidence: 50),
        dyldInsert: SignalTuning(weight: 65, confidence: 70),
        methodSwizzle: SignalTuning(weight: 75, confidence: 85),
    ]

    public static func buildSignal(
        name: String,
        evidence: [String: String],
        tuning: [String: SignalTuning],
        overrideTuning: SignalTuning? = nil
    ) -> Signal {
        let resolved = overrideTuning ?? tuning[name] ?? defaults[name] ?? SignalTuning(weight: 40, confidence: 50)
        return Signal(
            name: name,
            weight: resolved.weight,
            confidence: resolved.confidence,
            evidence: evidence
        )
    }
}
