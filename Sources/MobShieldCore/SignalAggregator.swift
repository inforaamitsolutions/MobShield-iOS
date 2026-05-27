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

import Foundation

/// Stateless pure aggregator: maps weighted ``Signal`` values to ``ThreatEvent`` list.
///
/// Score formula per threat type T:
/// `score(T) = min(100, sum(weight * confidence / 100))` for signals mapped to T.
public struct SignalAggregator: Sendable {
    private let config: MobShieldConfig

    public init(config: MobShieldConfig) {
        self.config = config
    }

    public func aggregate(signals: [Signal]) -> [ThreatEvent] {
        guard !signals.isEmpty else {
            return []
        }

        var grouped: [ThreatType: [Signal]] = [:]
        for signal in signals {
            guard let type = Self.resolveThreatType(signalName: signal.name) else {
                continue
            }
            if !config.allowDeveloperSignals,
               type == .developerMode || type == .adbEnabled {
                continue
            }
            grouped[type, default: []].append(signal)
        }

        let now = Int64(Date().timeIntervalSince1970 * 1000)
        var events: [ThreatEvent] = []
        for (type, typeSignals) in grouped {
            let score = computeScore(signals: typeSignals)
            if score <= 0 {
                continue
            }
            let threshold = config.thresholds[type] ?? DefaultThreatThresholds.map[type]!
            let severity = mapSeverity(type: type, score: score, threshold: threshold)
            if severity == .info, score < threshold.warning / 2 {
                continue
            }
            let names = typeSignals.map(\.name)
            let metadata = mergeEvidence(signals: typeSignals)
            events.append(
                ThreatEvent.create(
                    type: type,
                    severity: severity,
                    signals: names,
                    score: score,
                    timestampMs: now,
                    metadata: metadata
                )
            )
        }
        return events.sorted { $0.score > $1.score }
    }

    private func computeScore(signals: [Signal]) -> Int {
        var total = 0.0
        for signal in signals {
            total += Double(signal.weight) * (Double(signal.confidence) / 100.0)
        }
        return min(100, max(0, Int(total)))
    }

    private func mapSeverity(type: ThreatType, score: Int, threshold: ThreatThreshold) -> Severity {
        let criticalCap = threshold.critical == nil
        if criticalCap, Self.informationalTypes.contains(type) {
            if score < threshold.warning {
                return .info
            }
            return .high
        }

        if let critical = threshold.critical, score >= critical {
            return .critical
        }
        if score >= threshold.warning {
            return .high
        }
        if score >= threshold.warning / 2 {
            return .medium
        }
        if score >= threshold.warning / 4 {
            return .low
        }
        return .info
    }

    private func mergeEvidence(signals: [Signal]) -> [String: String] {
        var merged: [String: String] = [:]
        for signal in signals {
            for (key, value) in signal.evidence {
                merged["\(signal.name).\(key)"] = value
            }
        }
        return merged
    }

    private static let informationalTypes: Set<ThreatType> = [.developerMode, .adbEnabled]

    public static func resolveThreatType(signalName: String) -> ThreatType? {
        let name = signalName.lowercased()
        if name.hasPrefix("android.root.") || name.hasPrefix("ios.jb.") {
            return .privilegedAccess
        }
        if name.contains(".hook.") || name.hasPrefix("common.hook.") {
            return .hookFramework
        }
        if name.hasPrefix("android.debug.") || name.hasPrefix("ios.debug.") {
            return .debugger
        }
        if name.hasPrefix("android.env.") || name.hasPrefix("ios.env.") {
            return .emulator
        }
        if name.hasPrefix("android.automation.") || name.hasPrefix("ios.automation.") {
            return .automation
        }
        if name.hasPrefix("android.integrity.") || name.hasPrefix("ios.integrity.") {
            return .appIntegrity
        }
        if name.hasPrefix("android.store.") || name.hasPrefix("ios.store.") {
            return .unofficialStore
        }
        if name.hasPrefix("android.dev.") || name.hasSuffix(".developer_mode") {
            return .developerMode
        }
        if name.hasPrefix("android.adb.") || name.hasSuffix(".adb_enabled") {
            return .adbEnabled
        }
        return nil
    }
}
