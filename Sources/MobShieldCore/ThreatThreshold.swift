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

/// Per-threat score cutoffs from MOBSHIELD_SPEC section C.4.
public struct ThreatThreshold: Equatable, Sendable {
    public let warning: Int
    public let critical: Int?

    public init(warning: Int, critical: Int?) throws {
        guard (0...100).contains(warning) else {
            throw ThreatThresholdError.invalidWarning
        }
        if let critical {
            guard (0...100).contains(critical) else {
                throw ThreatThresholdError.invalidCritical
            }
            guard warning <= critical else {
                throw ThreatThresholdError.warningAboveCritical
            }
        }
        self.warning = warning
        self.critical = critical
    }
}

public enum ThreatThresholdError: Error, Equatable {
    case invalidWarning
    case invalidCritical
    case warningAboveCritical
}

public enum DefaultThreatThresholds {
    public static let map: [ThreatType: ThreatThreshold] = {
        func threshold(_ warning: Int, _ critical: Int?) -> ThreatThreshold {
            try! ThreatThreshold(warning: warning, critical: critical)
        }
        return [
            .privilegedAccess: threshold(40, 70),
            .hookFramework: threshold(35, 65),
            .debugger: threshold(30, 60),
            .emulator: threshold(25, 55),
            .automation: threshold(30, 60),
            .appIntegrity: threshold(50, 80),
            .developerMode: threshold(15, nil),
            .adbEnabled: threshold(15, nil),
            .unofficialStore: threshold(20, 50),
        ]
    }()
}
