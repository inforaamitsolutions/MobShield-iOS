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

/// User-visible aggregated threat outcome.
public enum ThreatEvent: Equatable, Sendable {
    case privilegedAccess(
        severity: Severity,
        signals: [String],
        score: Int,
        timestampMs: Int64,
        metadata: [String: String] = [:]
    )
    case hookFramework(
        severity: Severity,
        signals: [String],
        score: Int,
        timestampMs: Int64,
        metadata: [String: String] = [:]
    )
    case debugger(
        severity: Severity,
        signals: [String],
        score: Int,
        timestampMs: Int64,
        metadata: [String: String] = [:]
    )
    case emulator(
        severity: Severity,
        signals: [String],
        score: Int,
        timestampMs: Int64,
        metadata: [String: String] = [:]
    )
    case automation(
        severity: Severity,
        signals: [String],
        score: Int,
        timestampMs: Int64,
        metadata: [String: String] = [:]
    )
    case appIntegrity(
        severity: Severity,
        signals: [String],
        score: Int,
        timestampMs: Int64,
        metadata: [String: String] = [:]
    )
    case developerMode(
        severity: Severity,
        signals: [String],
        score: Int,
        timestampMs: Int64,
        metadata: [String: String] = [:]
    )
    case adbEnabled(
        severity: Severity,
        signals: [String],
        score: Int,
        timestampMs: Int64,
        metadata: [String: String] = [:]
    )
    case unofficialStore(
        severity: Severity,
        signals: [String],
        score: Int,
        timestampMs: Int64,
        metadata: [String: String] = [:]
    )

    public var type: ThreatType {
        switch self {
        case .privilegedAccess: return .privilegedAccess
        case .hookFramework: return .hookFramework
        case .debugger: return .debugger
        case .emulator: return .emulator
        case .automation: return .automation
        case .appIntegrity: return .appIntegrity
        case .developerMode: return .developerMode
        case .adbEnabled: return .adbEnabled
        case .unofficialStore: return .unofficialStore
        }
    }

    public var severity: Severity {
        switch self {
        case .privilegedAccess(let severity, _, _, _, _),
             .hookFramework(let severity, _, _, _, _),
             .debugger(let severity, _, _, _, _),
             .emulator(let severity, _, _, _, _),
             .automation(let severity, _, _, _, _),
             .appIntegrity(let severity, _, _, _, _),
             .developerMode(let severity, _, _, _, _),
             .adbEnabled(let severity, _, _, _, _),
             .unofficialStore(let severity, _, _, _, _):
            return severity
        }
    }

    public var signals: [String] {
        switch self {
        case .privilegedAccess(_, let signals, _, _, _),
             .hookFramework(_, let signals, _, _, _),
             .debugger(_, let signals, _, _, _),
             .emulator(_, let signals, _, _, _),
             .automation(_, let signals, _, _, _),
             .appIntegrity(_, let signals, _, _, _),
             .developerMode(_, let signals, _, _, _),
             .adbEnabled(_, let signals, _, _, _),
             .unofficialStore(_, let signals, _, _, _):
            return signals
        }
    }

    public var score: Int {
        switch self {
        case .privilegedAccess(_, _, let score, _, _),
             .hookFramework(_, _, let score, _, _),
             .debugger(_, _, let score, _, _),
             .emulator(_, _, let score, _, _),
             .automation(_, _, let score, _, _),
             .appIntegrity(_, _, let score, _, _),
             .developerMode(_, _, let score, _, _),
             .adbEnabled(_, _, let score, _, _),
             .unofficialStore(_, _, let score, _, _):
            return score
        }
    }

    public var timestampMs: Int64 {
        switch self {
        case .privilegedAccess(_, _, _, let timestampMs, _),
             .hookFramework(_, _, _, let timestampMs, _),
             .debugger(_, _, _, let timestampMs, _),
             .emulator(_, _, _, let timestampMs, _),
             .automation(_, _, _, let timestampMs, _),
             .appIntegrity(_, _, _, let timestampMs, _),
             .developerMode(_, _, _, let timestampMs, _),
             .adbEnabled(_, _, _, let timestampMs, _),
             .unofficialStore(_, _, _, let timestampMs, _):
            return timestampMs
        }
    }

    public var metadata: [String: String] {
        switch self {
        case .privilegedAccess(_, _, _, _, let metadata),
             .hookFramework(_, _, _, _, let metadata),
             .debugger(_, _, _, _, let metadata),
             .emulator(_, _, _, _, let metadata),
             .automation(_, _, _, _, let metadata),
             .appIntegrity(_, _, _, _, let metadata),
             .developerMode(_, _, _, _, let metadata),
             .adbEnabled(_, _, _, _, let metadata),
             .unofficialStore(_, _, _, _, let metadata):
            return metadata
        }
    }

    public static func create(
        type: ThreatType,
        severity: Severity,
        signals: [String],
        score: Int,
        timestampMs: Int64,
        metadata: [String: String] = [:]
    ) -> ThreatEvent {
        switch type {
        case .privilegedAccess:
            return .privilegedAccess(
                severity: severity,
                signals: signals,
                score: score,
                timestampMs: timestampMs,
                metadata: metadata
            )
        case .hookFramework:
            return .hookFramework(
                severity: severity,
                signals: signals,
                score: score,
                timestampMs: timestampMs,
                metadata: metadata
            )
        case .debugger:
            return .debugger(
                severity: severity,
                signals: signals,
                score: score,
                timestampMs: timestampMs,
                metadata: metadata
            )
        case .emulator:
            return .emulator(
                severity: severity,
                signals: signals,
                score: score,
                timestampMs: timestampMs,
                metadata: metadata
            )
        case .automation:
            return .automation(
                severity: severity,
                signals: signals,
                score: score,
                timestampMs: timestampMs,
                metadata: metadata
            )
        case .appIntegrity:
            return .appIntegrity(
                severity: severity,
                signals: signals,
                score: score,
                timestampMs: timestampMs,
                metadata: metadata
            )
        case .developerMode:
            return .developerMode(
                severity: severity,
                signals: signals,
                score: score,
                timestampMs: timestampMs,
                metadata: metadata
            )
        case .adbEnabled:
            return .adbEnabled(
                severity: severity,
                signals: signals,
                score: score,
                timestampMs: timestampMs,
                metadata: metadata
            )
        case .unofficialStore:
            return .unofficialStore(
                severity: severity,
                signals: signals,
                score: score,
                timestampMs: timestampMs,
                metadata: metadata
            )
        }
    }
}
