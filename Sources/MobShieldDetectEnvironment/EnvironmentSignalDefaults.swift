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

public enum EnvironmentSignalDefaults {
    /// Running under the iOS Simulator (maps to `EMULATOR`).
    public static let simulator = "ios.env.simulator"
    /// UI/test-automation frameworks injected (maps to `AUTOMATION`).
    public static let automation = "ios.automation.frameworks"

    private static let defaults: [String: SignalTuning] = [
        simulator: SignalTuning(weight: 90, confidence: 95),
        automation: SignalTuning(weight: 75, confidence: 85),
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
