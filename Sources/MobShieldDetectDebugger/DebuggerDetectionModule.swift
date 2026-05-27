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
import MobShieldCore

/// Detects debuggers via sysctl, Mach exception ports, timing, and optional PT_DENY_ATTACH.
public struct DebuggerDetectionModule: DetectionModule {
    public typealias NativeChecker = DebugNativeChecking.Type

    private let detectionTuning: [String: SignalTuning]
    private let nativeTimeoutNs: UInt64
    private let enablePtraceDenyAttach: Bool
    private let nativeChecker: NativeChecker

    public let name = "debugger"
    public let criticality = 80

    public init(
        config: MobShieldConfig = MobShieldConfig(),
        detectionTuning: [String: SignalTuning]? = nil,
        nativeTimeoutMs: Int = 50,
        enablePtraceDenyAttach: Bool? = nil,
        nativeChecker: NativeChecker = DebugNativeBridge.self
    ) {
        self.detectionTuning = detectionTuning ?? config.detectionTuning
        nativeTimeoutNs = UInt64(nativeTimeoutMs) * 1_000_000
        self.enablePtraceDenyAttach = enablePtraceDenyAttach ?? config.enablePtraceDenyAttach
        self.nativeChecker = nativeChecker
    }

    public func scan() async -> [Signal] {
        await withTaskGroup(of: [Signal].self) { group in
            group.addTask { await self.runCheck(DebugSignalDefaults.sysctlTraced) { self.nativeChecker.sysctlPtraced() } }
            if enablePtraceDenyAttach {
                group.addTask { await self.runCheck(DebugSignalDefaults.denyAttach) { self.nativeChecker.ptraceDenyAttach() } }
            }
            group.addTask { await self.runCheck(DebugSignalDefaults.machException) { self.nativeChecker.machExceptionCheck() } }
            group.addTask { await self.runCheck(DebugSignalDefaults.timing) { self.nativeChecker.timingCheck() } }

            var signals: [Signal] = []
            for await batch in group {
                signals.append(contentsOf: batch)
            }
            return signals
        }
    }

    private func runCheck(
        _ signalName: String,
        block: @escaping @Sendable () -> DebugNativeCheckResult
    ) async -> [Signal] {
        await withTimeout {
            let result = block()
            return Self.toSignals(signalName: signalName, result: result, tuning: detectionTuning)
        }
    }

    private func withTimeout(_ block: @escaping @Sendable () -> [Signal]) async -> [Signal] {
        await withTaskGroup(of: [Signal].self) { group in
            group.addTask { block() }
            group.addTask {
                try? await Task.sleep(nanoseconds: nativeTimeoutNs)
                return []
            }
            let first = await group.next() ?? []
            group.cancelAll()
            return first
        }
    }

    private static func toSignals(
        signalName: String,
        result: DebugNativeCheckResult,
        tuning: [String: SignalTuning]
    ) -> [Signal] {
        guard result.code == DebugNativeBridge.resultDetected else {
            return []
        }
        return [
            DebugSignalDefaults.buildSignal(
                name: signalName,
                evidence: ["detail": result.evidence],
                tuning: tuning
            ),
        ]
    }
}
