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

final class MobShieldEngine: @unchecked Sendable {
    private let config: MobShieldConfig
    private weak var listener: MobShieldListener?
    private let resolveModules: @Sendable () async -> [any DetectionModule]
    private let signalSetVersion: String

    private let stateLock = NSLock()
    private var state: MobShieldState
    private var lastEvents: [ThreatEvent] = []
    private var scanTask: Task<Void, Never>?

    init(
        config: MobShieldConfig,
        listener: MobShieldListener,
        resolveModules: @escaping @Sendable () async -> [any DetectionModule],
        signalSetVersion: String
    ) {
        self.config = config
        self.listener = listener
        self.resolveModules = resolveModules
        self.signalSetVersion = signalSetVersion
        self.state = MobShieldEngine.idleState(signalSetVersion: signalSetVersion)
    }

    func start() {
        scanTask?.cancel()
        scanTask = Task { [weak self] in
            await self?.runScanWave()
        }
    }

    func stop() {
        scanTask?.cancel()
        scanTask = nil
        stateLock.lock()
        state = MobShieldEngine.idleState(signalSetVersion: signalSetVersion)
        lastEvents = []
        stateLock.unlock()
    }

    func getState() -> MobShieldState {
        stateLock.lock()
        defer { stateLock.unlock() }
        return state
    }

    func getLastEvents() -> [ThreatEvent] {
        stateLock.lock()
        defer { stateLock.unlock() }
        return lastEvents
    }

    private func runScanWave() async {
        let modules = await resolveModules()
        if modules.isEmpty {
            let empty: [ThreatEvent] = []
            listener?.onAllChecksFinished(empty)
            updateState(events: empty, running: true)
            return
        }

        let signals = await withTaskGroup(of: [Signal].self) { group in
            for module in modules {
                group.addTask {
                    await module.scan()
                }
            }
            var collected: [Signal] = []
            for await result in group {
                collected.append(contentsOf: result)
            }
            return collected
        }

        let aggregator = SignalAggregator(config: config)
        let events = aggregator.aggregate(signals: signals)
        for event in events {
            listener?.onThreat(event)
        }
        listener?.onAllChecksFinished(events)
        updateState(events: events, running: true)
    }

    private func updateState(events: [ThreatEvent], running: Bool) {
        stateLock.lock()
        lastEvents = events
        state = MobShieldEngine.buildState(
            events: events,
            running: running,
            signalSetVersion: signalSetVersion
        )
        stateLock.unlock()
    }

    private static func buildState(
        events: [ThreatEvent],
        running: Bool,
        signalSetVersion: String
    ) -> MobShieldState {
        let active = Array(Set(events.map(\.type)))
        let maxRank = events.map { severityRank($0.severity) }.max() ?? 0
        let risk: RiskLevel
        switch maxRank {
        case 0:
            risk = .none
        case 1, 2:
            risk = .low
        case 3:
            risk = .medium
        default:
            risk = .high
        }
        return MobShieldState(
            riskLevel: risk,
            activeThreats: active,
            lastScanMs: Int64(Date().timeIntervalSince1970 * 1000),
            signalSetVersion: signalSetVersion,
            running: running
        )
    }

    private static func severityRank(_ severity: Severity) -> Int {
        switch severity {
        case .info: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .critical: return 4
        }
    }

    private static func idleState(signalSetVersion: String) -> MobShieldState {
        MobShieldState(
            riskLevel: .none,
            activeThreats: [],
            lastScanMs: 0,
            signalSetVersion: signalSetVersion,
            running: false
        )
    }
}
