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

public extension MobShield {
    /// A snapshot report of the latest scan wave's posture, suitable for sending to a backend.
    func currentReport(schemaVersion: String = ThreatReport.currentSchemaVersion) -> ThreatReport {
        MobShieldReporter.makeReport(
            state: getState(),
            events: getLastEvents(),
            buildId: MobShield.getBuildId(),
            schemaVersion: schemaVersion
        )
    }

    /// The current report as canonical JSON plus an HMAC-SHA256 signature under `key`. Transmit
    /// both to your backend; the backend recomputes the HMAC over the received JSON to verify the
    /// report was produced by a build holding the shared key and was not altered in transit.
    func currentSignedReport(key: Data) throws -> SignedThreatReport {
        try MobShieldReporter.sign(currentReport(), key: key)
    }
}
