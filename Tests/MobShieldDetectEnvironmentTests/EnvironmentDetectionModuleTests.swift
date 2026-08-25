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
import MobShieldDetectEnvironment
import XCTest

final class EnvironmentDetectionModuleTests: XCTestCase {
    func testSimulatorBuild_emitsEmulatorThreat() async {
        let module = EnvironmentDetectionModule(probe: MockProbe(isSimulatorBuild: true))
        let signals = await module.scan()
        XCTAssertEqual([EnvironmentSignalDefaults.simulator], signals.map(\.name))
        let events = SignalAggregator(config: MobShieldConfig()).aggregate(signals: signals)
        XCTAssertEqual(ThreatType.emulator, events.first?.type)
    }

    func testSimulatorEnvVar_emitsEmulatorSignal() async {
        let module = EnvironmentDetectionModule(
            probe: MockProbe(environment: ["SIMULATOR_DEVICE_NAME": "iPhone 15"])
        )
        let signals = await module.scan()
        XCTAssertEqual([EnvironmentSignalDefaults.simulator], signals.map(\.name))
    }

    func testAutomationDyld_emitsAutomationThreat() async {
        let module = EnvironmentDetectionModule(
            probe: MockProbe(environment: ["DYLD_INSERT_LIBRARIES": "/tmp/WebDriverAgent.dylib"])
        )
        let signals = await module.scan()
        XCTAssertEqual([EnvironmentSignalDefaults.automation], signals.map(\.name))
        let events = SignalAggregator(config: MobShieldConfig()).aggregate(signals: signals)
        XCTAssertEqual(ThreatType.automation, events.first?.type)
    }

    func testAutomationInjectBundle_emitsAutomationSignal() async {
        let module = EnvironmentDetectionModule(
            probe: MockProbe(environment: ["XCInjectBundleInto": "/path/App.app/App"])
        )
        let signals = await module.scan()
        XCTAssertEqual([EnvironmentSignalDefaults.automation], signals.map(\.name))
    }

    func testAutomationClass_emitsAutomationSignal() async {
        let module = EnvironmentDetectionModule(
            probe: MockProbe(availableClasses: ["XCUIApplication"])
        )
        let signals = await module.scan()
        XCTAssertEqual([EnvironmentSignalDefaults.automation], signals.map(\.name))
    }

    func testCleanDevice_emitsNothing() async {
        let module = EnvironmentDetectionModule(probe: MockProbe())
        let signals = await module.scan()
        XCTAssertTrue(signals.isEmpty)
    }

    func testSimulatorAndAutomation_emitsBoth() async {
        let module = EnvironmentDetectionModule(
            probe: MockProbe(
                isSimulatorBuild: true,
                environment: ["XCInjectBundleInto": "x"]
            )
        )
        let signals = await module.scan()
        XCTAssertEqual(
            Set([EnvironmentSignalDefaults.simulator, EnvironmentSignalDefaults.automation]),
            Set(signals.map(\.name))
        )
    }

    private struct MockProbe: EnvironmentProbing {
        var isSimulatorBuild = false
        var environment: [String: String] = [:]
        var availableClasses: Set<String> = []

        func isClassAvailable(_ name: String) -> Bool {
            availableClasses.contains(name)
        }
    }
}
