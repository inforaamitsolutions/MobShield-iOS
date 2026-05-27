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

public enum DebugSignalDefaults {
    public static let sysctlTraced = "ios.debug.sysctl_traced"
    public static let denyAttach = "ios.debug.deny_attach"
    public static let machException = "ios.debug.mach_exception"
    public static let timing = "ios.debug.timing"

    private static let defaults: [String: SignalTuning] = [
        sysctlTraced: SignalTuning(weight: 70, confidence: 75),
        denyAttach: SignalTuning(weight: 50, confidence: 60),
        machException: SignalTuning(weight: 75, confidence: 80),
        timing: SignalTuning(weight: 55, confidence: 65),
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
