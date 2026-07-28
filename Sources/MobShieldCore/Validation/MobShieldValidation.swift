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

/// A single emitted ``Signal`` flattened for reporting/inspection.
public struct ValidationSignal: Sendable, Equatable {
    public let name: String
    public let weight: Int
    public let confidence: Int
    public let evidence: [String: String]

    public init(_ signal: Signal) {
        self.name = signal.name
        self.weight = signal.weight
        self.confidence = signal.confidence
        self.evidence = signal.evidence
    }
}

/// The outcome of running one ``DetectionModule``'s ``DetectionModule/scan()``.
public struct ModuleValidationResult: Sendable, Equatable {
    public let moduleName: String
    public let criticality: Int
    public let signals: [ValidationSignal]

    /// Whether the module emitted at least one signal this run.
    public var didFire: Bool { !signals.isEmpty }
}

/// Structured result of a validation run: the raw per-module signals *and* the aggregated
/// ``ThreatEvent`` list they map to. Use this to see exactly which detectors fired in a given
/// environment (clean device, jailbroken device, device with Frida attached, …) and how the
/// signals aggregate into threats.
///
/// Unlike ``MobShieldEngine`` (which scans concurrently and only surfaces aggregated events to a
/// listener), this preserves per-module attribution and runs modules in criticality order, so a
/// report reads top-to-bottom from the highest-criticality detector down.
public struct ValidationReport: Sendable {
    public let modules: [ModuleValidationResult]
    public let events: [ThreatEvent]
    public let generatedAtMs: Int64

    public init(modules: [ModuleValidationResult], events: [ThreatEvent], generatedAtMs: Int64) {
        self.modules = modules
        self.events = events
        self.generatedAtMs = generatedAtMs
    }

    /// Every signal emitted across all modules, in module (criticality) order.
    public var rawSignals: [ValidationSignal] { modules.flatMap(\.signals) }

    /// The set of distinct signal names that fired this run.
    public var firedSignalNames: Set<String> { Set(rawSignals.map(\.name)) }

    /// The set of distinct threat types raised after aggregation.
    public var activeThreatTypes: Set<ThreatType> { Set(events.map(\.type)) }

    /// The most severe aggregated threat this run, or `nil` when nothing fired.
    public var highestSeverity: Severity? { events.map(\.severity).max() }
}

/// Runs the SDK's detection modules and reports exactly what fired.
///
/// This is the entry point for on-device and CI validation: register (or hand in) the detection
/// modules, run them against the current environment, and inspect the ``ValidationReport`` to
/// confirm the expected signals appear (on a compromised device) or stay silent (on a clean one).
public enum MobShieldValidation {
    /// Scans `modules` (in descending ``DetectionModule/criticality`` order), aggregates their
    /// signals with `config`, and returns a structured ``ValidationReport``.
    public static func run(
        config: MobShieldConfig = MobShieldConfig(),
        modules: [any DetectionModule]
    ) async -> ValidationReport {
        let ordered = modules.sorted { $0.criticality > $1.criticality }

        var moduleResults: [ModuleValidationResult] = []
        var allSignals: [Signal] = []
        for module in ordered {
            let signals = await module.scan()
            allSignals.append(contentsOf: signals)
            moduleResults.append(
                ModuleValidationResult(
                    moduleName: module.name,
                    criticality: module.criticality,
                    signals: signals.map(ValidationSignal.init)
                )
            )
        }

        let events = SignalAggregator(config: config).aggregate(signals: allSignals)
        return ValidationReport(
            modules: moduleResults,
            events: events,
            generatedAtMs: Int64(Date().timeIntervalSince1970 * 1000)
        )
    }

    /// Convenience: runs whatever modules are currently registered in ``ModuleRegistry/shared``.
    /// Register modules via the per-module registrars (or ``SampleMobShieldController``) first.
    public static func runRegistered(
        config: MobShieldConfig = MobShieldConfig()
    ) async -> ValidationReport {
        let modules = await ModuleRegistry.shared.getAll()
        return await run(config: config, modules: modules)
    }
}
