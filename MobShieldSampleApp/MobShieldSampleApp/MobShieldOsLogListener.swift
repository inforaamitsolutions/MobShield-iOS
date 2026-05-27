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
import os.log
import Foundation

final class MobShieldOsLogListener: MobShieldListener {
    private let log = Logger(subsystem: "io.mobshield.sample", category: "MobShield")
    private let onThreatReceived: (ThreatEvent) -> Void
    private let onScanFinished: ([ThreatEvent]) -> Void

    init(
        onThreatReceived: @escaping (ThreatEvent) -> Void,
        onScanFinished: @escaping ([ThreatEvent]) -> Void
    ) {
        self.onThreatReceived = onThreatReceived
        self.onScanFinished = onScanFinished
    }

    func onThreat(_ event: ThreatEvent) {
        log.info("threat type=\(event.type.rawValue, privacy: .public) severity=\(event.severity.rawValue, privacy: .public) score=\(event.score, privacy: .public)")
        onThreatReceived(event)
    }

    func onAllChecksFinished(_ events: [ThreatEvent]) {
        log.info("scan finished events=\(events.count, privacy: .public)")
        onScanFinished(events)
    }
}
