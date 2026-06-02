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

/// Detects Frida, Substrate, and related hook frameworks on iOS.
public struct HookDetectionModule: DetectionModule {
    public typealias NativeChecker = HookNativeChecking.Type

    private let detectionTuning: [String: SignalTuning]
    private let nativeTimeoutNs: UInt64
    private let nativeChecker: NativeChecker
    private let configureBaselines: () -> Void

    public let name = "hooks"
    public let criticality = 85

    public init(
        config: MobShieldConfig = MobShieldConfig(),
        detectionTuning: [String: SignalTuning]? = nil,
        nativeTimeoutMs: Int = 50,
        nativeChecker: NativeChecker = HookNativeBridge.self,
        configureBaselines: (() -> Void)? = nil
    ) {
        self.detectionTuning = detectionTuning ?? config.detectionTuning
        nativeTimeoutNs = UInt64(nativeTimeoutMs) * 1_000_000
        self.nativeChecker = nativeChecker
        if let configureBaselines {
            self.configureBaselines = configureBaselines
        } else {
            let prologue = config.hookPrologueBaselines
            let swizzle = config.hookSwizzleBaselines
            self.configureBaselines = {
                nativeChecker.configureBaselines(prologue: prologue, swizzle: swizzle)
            }
        }
    }

    public func scan() async -> [Signal] {
        configureBaselines()
        return await withTaskGroup(of: [Signal].self) { group in
            group.addTask { await self.runCheck(HookSignalDefaults.machRegion) { self.nativeChecker.machRegionInspect() } }
            group.addTask { await self.runCheck(HookSignalDefaults.prologue) { self.nativeChecker.functionPrologueInspect() } }
            group.addTask { await self.runCheck(HookSignalDefaults.fridaMaps) { self.nativeChecker.fridaArtifactScan() } }
            group.addTask { await self.runCheck(HookSignalDefaults.fridaPort) { self.nativeChecker.fridaPortProbe() } }
            group.addTask { await self.runCheck(HookSignalDefaults.dyldInsert) { self.nativeChecker.dyldEnvironmentScan() } }
            group.addTask { await self.runCheck(HookSignalDefaults.methodSwizzle) { self.nativeChecker.methodSwizzleDetect() } }

            var signals: [Signal] = []
            for await batch in group {
                signals.append(contentsOf: batch)
            }
            return signals
        }
    }

    // public func scan() async -> [Signal] {
    //     configureBaselines()

    //     return await withTaskGroup(of: [Signal].self) { group in

    //         group.addTask {
    //             print("machRegion START")
    //             let result = await self.runCheck(HookSignalDefaults.machRegion) {
    //                 self.nativeChecker.machRegionInspect()
    //             }
    //             print("machRegion END")
    //             return result
    //         }

    //         group.addTask {
    //             print("prologue START")
    //             let result = await self.runCheck(HookSignalDefaults.prologue) {
    //                 self.nativeChecker.functionPrologueInspect()
    //             }
    //             print("prologue END")
    //             return result
    //         }

    //         group.addTask {
    //             print("fridaMaps START")
    //             let result = await self.runCheck(HookSignalDefaults.fridaMaps) {
    //                 self.nativeChecker.fridaArtifactScan()
    //             }
    //             print("fridaMaps END")
    //             return result
    //         }

    //         group.addTask {
    //             print("fridaPort START")
    //             let result = await self.runCheck(HookSignalDefaults.fridaPort) {
    //                 self.nativeChecker.fridaPortProbe()
    //             }
    //             print("fridaPort END")
    //             return result
    //         }

    //         group.addTask {
    //             print("dyldInsert START")
    //             let result = await self.runCheck(HookSignalDefaults.dyldInsert) {
    //                 self.nativeChecker.dyldEnvironmentScan()
    //             }
    //             print("dyldInsert END")
    //             return result
    //         }

    //         group.addTask {
    //             print("methodSwizzle START")
    //             let result = await self.runCheck(HookSignalDefaults.methodSwizzle) {
    //                 self.nativeChecker.methodSwizzleDetect()
    //             }
    //             print("methodSwizzle END")
    //             return result
    //         }

    //         var signals: [Signal] = []

    //         for await batch in group {
    //             signals.append(contentsOf: batch)
    //         }

    //         print("HookDetectionModule FINISHED")
    //         return signals
    //     }
    // }

    private func runCheck(
        _ signalName: String,
        block: @escaping @Sendable () -> HookNativeCheckResult
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
        result: HookNativeCheckResult,
        tuning: [String: SignalTuning]
    ) -> [Signal] {
        guard result.code == HookNativeBridge.resultDetected else {
            return []
        }
        return [
            HookSignalDefaults.buildSignal(
                name: signalName,
                evidence: ["detail": result.evidence],
                tuning: tuning
            ),
        ]
    }
}
