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

/// Detects execution environments that a genuine end-user install should never be in: the iOS
/// Simulator (`EMULATOR`) and injected UI/test-automation frameworks (`AUTOMATION`).
public struct EnvironmentDetectionModule: DetectionModule {
    private let detectionTuning: [String: SignalTuning]
    private let probe: EnvironmentProbing

    public let name = "environment"
    public let criticality = 70

    public init(
        config: MobShieldConfig = MobShieldConfig(),
        detectionTuning: [String: SignalTuning]? = nil,
        probe: EnvironmentProbing = LiveEnvironmentProbe()
    ) {
        self.detectionTuning = detectionTuning ?? config.detectionTuning
        self.probe = probe
    }

    public func scan() async -> [Signal] {
        var signals: [Signal] = []
        if let simulator = simulatorSignal() {
            signals.append(simulator)
        }
        if let automation = automationSignal() {
            signals.append(automation)
        }
        return signals
    }

    private func simulatorSignal() -> Signal? {
        if probe.isSimulatorBuild {
            return build(EnvironmentSignalDefaults.simulator, detail: "targetEnvironment=simulator")
        }
        // Simulator processes expose these even in a device-target build running on the simulator.
        let markers = ["SIMULATOR_UDID", "SIMULATOR_DEVICE_NAME", "SIMULATOR_ROOT", "SIMULATOR_HOST_HOME"]
        for marker in markers where probe.environment[marker] != nil {
            return build(EnvironmentSignalDefaults.simulator, detail: "env=\(marker)")
        }
        return nil
    }

    private func automationSignal() -> Signal? {
        if let inserted = probe.environment["DYLD_INSERT_LIBRARIES"] {
            let dylibMarkers = ["libXCTest", "XCTAutomationSupport", "WebDriverAgent", "libAXAutomation"]
            for marker in dylibMarkers where inserted.contains(marker) {
                return build(EnvironmentSignalDefaults.automation, detail: "dyld=\(marker)")
            }
        }
        if probe.environment["XCInjectBundleInto"] != nil {
            return build(EnvironmentSignalDefaults.automation, detail: "env=XCInjectBundleInto")
        }
        // XCUITest and WebDriverAgent load these classes; a shipping app never does.
        let classMarkers = ["XCUIApplication", "FBApplication"]
        for marker in classMarkers where probe.isClassAvailable(marker) {
            return build(EnvironmentSignalDefaults.automation, detail: "class=\(marker)")
        }
        return nil
    }

    private func build(_ name: String, detail: String) -> Signal {
        EnvironmentSignalDefaults.buildSignal(
            name: name,
            evidence: ["detail": detail],
            tuning: detectionTuning
        )
    }
}
