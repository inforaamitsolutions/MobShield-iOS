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

public enum IntegritySignalDefaults {
    public static let secCode = "ios.integrity.sec_code"
    public static let bundleId = "ios.integrity.bundle_id"
    public static let provisioning = "ios.integrity.provisioning"
    public static let resource = "ios.integrity.resource"
    public static let receipt = "ios.integrity.receipt"

    private static let defaults: [String: SignalTuning] = [
        secCode: SignalTuning(weight: 90, confidence: 95),
        bundleId: SignalTuning(weight: 85, confidence: 90),
        provisioning: SignalTuning(weight: 70, confidence: 80),
        resource: SignalTuning(weight: 80, confidence: 85),
        receipt: SignalTuning(weight: 55, confidence: 65),
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
