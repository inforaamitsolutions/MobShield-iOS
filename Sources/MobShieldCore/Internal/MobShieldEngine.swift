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
    // Retained strongly for the engine's lifetime so callbacks are delivered even when the
    // caller does not separately hold the listener; released when the engine is torn down
    // (stop()/restart). No retain cycle: the listener has no reference back to the engine.
    private let listener: MobShieldListener
    private let resolveModules: @Sendable () async -> [any DetectionModule]
    private let signalSetVersion: String
    /// Rescan cadence in nanoseconds; nil runs a single scan wave (spec default).
    private let periodicIntervalNanos: UInt64?
    /// Process-exit action invoked when the termination policy is satisfied. Injectable for tests.
    private let terminate: @Sendable () -> Void
    /// Native core integrity probe; a healthy core returns nonzero. Injectable for tests.
    private let selfCheck: @Sendable () -> Int

    private let stateLock = NSLock()
    private var state: MobShieldState
    private var lastEvents: [ThreatEvent] = []
    private var scanTask: Task<Void, Never>?

    init(
        config: MobShieldConfig,
        listener: MobShieldListener,
        resolveModules: @escaping @Sendable () async -> [any DetectionModule],
        signalSetVersion: String,
        periodicIntervalOverrideNanos: UInt64? = nil,
        terminate: @escaping @Sendable () -> Void = MobShieldEngine.defaultTerminate,
        selfCheck: @escaping @Sendable () -> Int = MobShieldEngine.defaultSelfCheck
    ) {
        self.config = config
        self.listener = listener
        self.resolveModules = resolveModules
        self.signalSetVersion = signalSetVersion
        self.periodicIntervalNanos = periodicIntervalOverrideNanos
            ?? config.periodicIntervalSec.map { UInt64($0) * 1_000_000_000 }
        self.terminate = terminate
        self.selfCheck = selfCheck
        self.state = MobShieldEngine.idleState(signalSetVersion: signalSetVersion)
    }

    func start() {
        scanTask?.cancel()
        scanTask = Task { [weak self] in
            await self?.runScanLoop()
        }
    }

    /// Runs one scan wave, then repeats every `periodicIntervalNanos` until cancelled.
    /// When no interval is configured, runs exactly one wave (single-shot).
    /// Terminates the process (and ends the loop) once the configured policy is satisfied.
    private func runScanLoop() async {
        while !Task.isCancelled {
            let events = await runScanWave()
            if MobShieldEngine.shouldTerminate(
                events: events,
                detectOnly: config.detectOnly,
                policy: config.terminationPolicy
            ) {
                terminate()
                return
            }
            guard let periodicIntervalNanos else {
                return
            }
            do {
                try await Task.sleep(nanoseconds: periodicIntervalNanos)
            } catch {
                return
            }
        }
    }

    /// Decides whether the current scan results warrant process termination.
    ///
    /// - `.none` (and any `detectOnly` config): never terminates.
    /// - `.exitOnBypass`: terminates when any threat reaches `.high` or above — a confirmed
    ///   compromise of the protected environment.
    /// - `.exitOnCritical`: terminates only when a threat reaches `.critical`.
    static func shouldTerminate(
        events: [ThreatEvent],
        detectOnly: Bool,
        policy: TerminationPolicy
    ) -> Bool {
        guard !detectOnly else {
            return false
        }
        switch policy {
        case .none:
            return false
        case .exitOnBypass:
            return events.contains { severityRank($0.severity) >= severityRank(.high) }
        case .exitOnCritical:
            return events.contains { $0.severity == .critical }
        }
    }

    static let defaultTerminate: @Sendable () -> Void = {
        exit(EXIT_FAILURE)
    }

    static let defaultSelfCheck: @Sendable () -> Int = {
        NativeBridge.selfCheck()
    }

    /// Signal name for the native core integrity probe; maps to `.appIntegrity`.
    static let selfCheckSignalName = "ios.integrity.native_self_check"

    /// Emits an integrity signal when the native core self-check reports an unhealthy (zero) result,
    /// which indicates the native core was zeroed, swapped, or otherwise tampered with. Per the
    /// documented native contract, a healthy core returns nonzero.
    private func makeSelfCheckSignal() -> Signal? {
        guard selfCheck() == 0 else {
            return nil
        }
        return Signal(
            name: MobShieldEngine.selfCheckSignalName,
            weight: 90,
            confidence: 95,
            evidence: ["reason": "native_self_check_failed"]
        )
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

    @discardableResult
    private func runScanWave() async -> [ThreatEvent] {
        let modules = await resolveModules()

        var signals = await withTaskGroup(of: [Signal].self) { group in
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

        // Native core integrity runs every wave, independent of registered modules.
        if let selfCheckSignal = makeSelfCheckSignal() {
            signals.append(selfCheckSignal)
        }

        let aggregator = SignalAggregator(config: config)
        let events = aggregator.aggregate(signals: signals)
        for event in events {
            listener.onThreat(event)
        }
        listener.onAllChecksFinished(events)
        updateState(events: events, running: true)
        return events
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
