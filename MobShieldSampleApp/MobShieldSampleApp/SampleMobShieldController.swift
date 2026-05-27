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
import MobShieldDetectDebugger
import MobShieldDetectHooks
import MobShieldDetectIntegrity
import MobShieldDetectJailbreak
import Foundation

enum SampleModuleId: String, CaseIterable, Identifiable {
    case jailbreak
    case hooks
    case debugger
    case integrity

    var id: String { rawValue }

    var label: String {
        switch self {
        case .jailbreak: return "Jailbreak / privileged access"
        case .hooks: return "Hooks / instrumentation"
        case .debugger: return "Debugger"
        case .integrity: return "App integrity"
        }
    }
}

struct SamplePreferences: Equatable {
    var detectOnly: Bool = true
    var allowDeveloperSignals: Bool = true
    var enablePtraceDenyAttach: Bool = false
    var enabledModules: Set<SampleModuleId> = Set(SampleModuleId.allCases)
    var expectedPackageId: String = "io.mobshield.sample"
}

enum SampleMobShieldController {
    static func buildConfig(prefs: SamplePreferences) throws -> MobShieldConfig {
        var builder = MobShieldConfig.builder()
            .expectedPackageId(prefs.expectedPackageId)
            .allowDeveloperSignals(prefs.allowDeveloperSignals)
            .enablePtraceDenyAttach(prefs.enablePtraceDenyAttach)

        if prefs.detectOnly {
            builder = builder.detectOnly(true).terminationPolicy(.none)
        } else {
            builder = builder.detectOnly(false).terminationPolicy(.exitOnCritical)
        }
        return try builder.build()
    }

    static func registerModules(config: MobShieldConfig, prefs: SamplePreferences) async {
        await ModuleRegistry.shared.clear()
        if prefs.enabledModules.contains(.jailbreak) {
            await JailbreakDetectionRegistrar.register(config: config)
        }
        if prefs.enabledModules.contains(.hooks) {
            await HookDetectionRegistrar.register(config: config)
        }
        if prefs.enabledModules.contains(.debugger) {
            await DebuggerDetectionRegistrar.register(config: config)
        }
        if prefs.enabledModules.contains(.integrity) {
            await IntegrityDetectionRegistrar.register(config: config)
        }
    }

    static func start(prefs: SamplePreferences, listener: MobShieldListener) async {
        guard let config = try? buildConfig(prefs: prefs) else { return }
        await registerModules(config: config, prefs: prefs)
        MobShield.shared.start(config: config, listener: listener)
    }

    static func stop() {
        MobShield.shared.stop()
    }

    static func restart(prefs: SamplePreferences, listener: MobShieldListener) async {
        stop()
        await start(prefs: prefs, listener: listener)
    }

    static func collectSignals(prefs: SamplePreferences) async -> [Signal] {
        guard let config = try? buildConfig(prefs: prefs) else { return [] }
        await registerModules(config: config, prefs: prefs)
        let modules = await ModuleRegistry.shared.getAll()
        var output: [Signal] = []
        for module in modules {
            let signals = await module.scan()
            output.append(contentsOf: signals)
        }
        return output
    }

    static func buildEntropyPreview() -> String {
        let buildId = MobShield.getBuildId()
        return String(buildId.prefix(8))
    }
}
