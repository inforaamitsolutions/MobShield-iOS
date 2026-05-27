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
import SwiftUI

@MainActor
final class SampleViewModel: ObservableObject {
    @Published var prefs = SamplePreferences()
    @Published private(set) var threats: [ThreatRow] = []
    @Published private(set) var signals: [SignalRow] = []
    @Published private(set) var diagnosticsLoading = false
    @Published private(set) var posture = PostureSnapshot.idle

    let sdkVersion = MobShield.getVersion()
    let buildEntropyPreview = SampleMobShieldController.buildEntropyPreview()
    let nativeSelfCheck = MobShield.selfCheck()
    let masvsRows = MasvsCatalog.rows

    private lazy var listener = MobShieldOsLogListener(
        onThreatReceived: { [weak self] event in
            Task { @MainActor in
                self?.threats.insert(ThreatRow(event: event), at: 0)
                self?.refreshPosture()
            }
        },
        onScanFinished: { [weak self] events in
            Task { @MainActor in
                self?.threats = events.map(ThreatRow.init).sorted { $0.score > $1.score }
                self?.refreshPosture()
            }
        }
    )

    func startMobShield() {
        Task {
            await SampleMobShieldController.start(prefs: prefs, listener: listener)
            refreshPosture()
        }
    }

    func stopMobShield() {
        SampleMobShieldController.stop()
        refreshPosture()
    }

    func rescan() {
        Task {
            await SampleMobShieldController.restart(prefs: prefs, listener: listener)
            refreshPosture()
        }
    }

    func clearThreats() {
        threats = []
    }

    func refreshDiagnostics() {
        diagnosticsLoading = true
        Task {
            let collected = await SampleMobShieldController.collectSignals(prefs: prefs)
            signals = collected
                .sorted { ($0.weight * $0.confidence) > ($1.weight * $1.confidence) }
                .map(SignalRow.init)
            diagnosticsLoading = false
        }
    }

    func applyConfigIfRunning() {
        let state = MobShield.shared.getState()
        guard state.running else { return }
        Task {
            await SampleMobShieldController.restart(prefs: prefs, listener: listener)
            refreshPosture()
        }
    }

    private func refreshPosture() {
        let state = MobShield.shared.getState()
        posture = PostureSnapshot(
            riskLevel: state.riskLevel,
            running: state.running,
            activeThreatCount: state.activeThreats.count,
            signalSetVersion: state.signalSetVersion,
            lastScanMs: state.lastScanMs
        )
    }
}

struct PostureSnapshot {
    var riskLevel: RiskLevel
    var running: Bool
    var activeThreatCount: Int
    var signalSetVersion: String
    var lastScanMs: Int64

    static let idle = PostureSnapshot(
        riskLevel: .none,
        running: false,
        activeThreatCount: 0,
        signalSetVersion: MobShield.signalSetVersion,
        lastScanMs: 0
    )
}

struct ThreatRow: Identifiable {
    let id = UUID()
    let typeLabel: String
    let severity: Severity
    let score: Int
    let signalsSummary: String
    let metadataSummary: String

    init(event: ThreatEvent) {
        typeLabel = event.type.rawValue
        severity = event.severity
        score = event.score
        signalsSummary = event.signals.joined(separator: ", ")
        metadataSummary = event.metadata.map { "\($0.key)=\($0.value)" }.joined(separator: ", ")
    }
}

struct SignalRow: Identifiable {
    let id: String
    let name: String
    let weight: Int
    let confidence: Int
    let evidenceSummary: String

    init(signal: Signal) {
        id = signal.name
        name = signal.name
        weight = signal.weight
        confidence = signal.confidence
        evidenceSummary = signal.evidence.map { "\($0.key)=\($0.value)" }.joined(separator: ", ")
    }
}
