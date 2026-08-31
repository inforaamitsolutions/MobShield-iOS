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

/// A serializable snapshot of the current posture, intended to be sent to a backend for
/// server-side decisioning. Client-side termination is bypassable, so the authoritative decision
/// belongs on a server that receives and verifies this report.
public struct ThreatReport: Codable, Sendable, Equatable {
    public static let currentSchemaVersion = "report-1"

    public let schemaVersion: String
    public let signalSetVersion: String
    public let buildId: String
    public let generatedAtMs: Int64
    public let riskLevel: RiskLevel
    public let threats: [Entry]

    public struct Entry: Codable, Sendable, Equatable {
        public let type: ThreatType
        public let severity: Severity
        public let score: Int
        public let signals: [String]

        public init(type: ThreatType, severity: Severity, score: Int, signals: [String]) {
            self.type = type
            self.severity = severity
            self.score = score
            self.signals = signals
        }
    }

    public init(
        schemaVersion: String,
        signalSetVersion: String,
        buildId: String,
        generatedAtMs: Int64,
        riskLevel: RiskLevel,
        threats: [Entry]
    ) {
        self.schemaVersion = schemaVersion
        self.signalSetVersion = signalSetVersion
        self.buildId = buildId
        self.generatedAtMs = generatedAtMs
        self.riskLevel = riskLevel
        self.threats = threats
    }
}

/// A ``ThreatReport`` serialized to canonical JSON together with an HMAC-SHA256 signature over
/// exactly those bytes. Send `json` and `signatureHex` to the backend; the backend recomputes the
/// HMAC over the received `json` with the shared key and rejects the report if it does not match.
public struct SignedThreatReport: Sendable, Equatable {
    /// Canonical JSON of the report — the exact bytes the signature covers.
    public let json: Data
    /// Lowercase hex HMAC-SHA256 of `json`.
    public let signatureHex: String

    public init(json: Data, signatureHex: String) {
        self.json = json
        self.signatureHex = signatureHex
    }
}
