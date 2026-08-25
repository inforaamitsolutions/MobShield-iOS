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

import CryptoKit
import Foundation

/// Builds and signs ``ThreatReport``s. Pure and side-effect-free: it never performs networking —
/// the host app transmits the signed report to its backend.
public enum MobShieldReporter {
    /// Builds a report from a posture snapshot and the events of the last scan wave.
    public static func makeReport(
        state: MobShieldState,
        events: [ThreatEvent],
        buildId: String,
        schemaVersion: String = ThreatReport.currentSchemaVersion
    ) -> ThreatReport {
        let entries = events
            .sorted { $0.score > $1.score }
            .map { event in
                ThreatReport.Entry(
                    type: event.type,
                    severity: event.severity,
                    score: event.score,
                    signals: event.signals
                )
            }
        return ThreatReport(
            schemaVersion: schemaVersion,
            signalSetVersion: state.signalSetVersion,
            buildId: buildId,
            generatedAtMs: state.lastScanMs,
            riskLevel: state.riskLevel,
            threats: entries
        )
    }

    /// Encodes a report to canonical (deterministic, sorted-key) JSON so a backend can recompute
    /// the signature over identical bytes.
    public static func canonicalJSON(_ report: ThreatReport) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(report)
    }

    /// Produces the canonical JSON and its HMAC-SHA256 signature under `key`.
    public static func sign(_ report: ThreatReport, key: Data) throws -> SignedThreatReport {
        let json = try canonicalJSON(report)
        let code = HMAC<SHA256>.authenticationCode(for: json, using: SymmetricKey(data: key))
        let hex = code.map { String(format: "%02x", $0) }.joined()
        return SignedThreatReport(json: json, signatureHex: hex)
    }
}
