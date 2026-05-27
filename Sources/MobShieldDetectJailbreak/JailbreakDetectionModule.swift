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

/// iOS jailbreak detection for Dopamine, palera1n, unc0ver, checkra1n, and rootless variants.
public struct JailbreakDetectionModule: DetectionModule {
    public typealias NativeChecker = JailbreakNativeChecking.Type

    private let detectionTuning: [String: SignalTuning]
    private let nativeTimeoutNs: UInt64
    private let nativeChecker: NativeChecker
    private let configurePaths: () -> Void

    public let name = "jailbreak"
    public let criticality = 90

    public init(
        config: MobShieldConfig = MobShieldConfig(),
        detectionTuning: [String: SignalTuning]? = nil,
        nativeTimeoutMs: Int = 50,
        nativeChecker: NativeChecker = JailbreakNativeBridge.self,
        configurePaths: (() -> Void)? = nil
    ) {
        self.detectionTuning = detectionTuning ?? config.detectionTuning
        nativeTimeoutNs = UInt64(nativeTimeoutMs) * 1_000_000
        self.nativeChecker = nativeChecker
        if let configurePaths {
            self.configurePaths = configurePaths
        } else {
            let paths = ConfigurableSuspiciousPaths(config: config).allPaths()
            self.configurePaths = {
                nativeChecker.configureExtraPaths(paths)
            }
        }
    }

    public func scan() async -> [Signal] {
        configurePaths()
        return await withTaskGroup(of: [Signal].self) { group in
            group.addTask { await self.runCheck(JailbreakSignalDefaults.dyldImage) { self.nativeChecker.dyldImageScan() } }
            group.addTask { await self.runCheck(JailbreakSignalDefaults.filesystemPaths) { self.nativeChecker.filesystemPaths() } }
            group.addTask { await self.runCheck(JailbreakSignalDefaults.sandboxEscape) { self.nativeChecker.sandboxEscape() } }
            group.addTask { await self.runCheck(JailbreakSignalDefaults.urlScheme) { self.nativeChecker.urlSchemeProbe() } }
            group.addTask { await self.runCheck(JailbreakSignalDefaults.sysctlTraced) { self.nativeChecker.sysctlTraced() } }
            group.addTask { await self.runCheck(JailbreakSignalDefaults.writeTest) { self.nativeChecker.writeTest() } }
            group.addTask { await self.runCheck(JailbreakSignalDefaults.symlinkTest) { self.nativeChecker.symlinkTest() } }
            group.addTask { await self.runCheck(JailbreakSignalDefaults.dyldHeader) { self.nativeChecker.dyldHeaderInspect() } }

            var signals: [Signal] = []
            for await batch in group {
                signals.append(contentsOf: batch)
            }
            return signals
        }
    }

    private func runCheck(
        _ signalName: String,
        block: @escaping @Sendable () -> NativeCheckResult
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
        result: NativeCheckResult,
        tuning: [String: SignalTuning]
    ) -> [Signal] {
        guard result.code == JailbreakNativeBridge.resultDetected else {
            return []
        }
        return [
            JailbreakSignalDefaults.buildSignal(
                name: signalName,
                evidence: ["detail": result.evidence],
                tuning: tuning
            ),
        ]
    }
}
