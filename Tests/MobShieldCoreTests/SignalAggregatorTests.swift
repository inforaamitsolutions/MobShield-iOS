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

import XCTest
@testable import MobShieldCore

final class SignalAggregatorTests: XCTestCase {
    private let defaultConfig = MobShieldConfig()

    func testEmptySignals_returnsEmpty() {
        let result = SignalAggregator(config: defaultConfig).aggregate(signals: [])
        XCTAssertTrue(result.isEmpty)
    }

    func testUnknownSignalName_isIgnored() {
        let result = SignalAggregator(config: defaultConfig).aggregate(
            signals: [signal("unknown.signal", 100, 100)]
        )
        XCTAssertTrue(result.isEmpty)
    }

    func testSingleRootSignal_emitsPrivilegedAccess() {
        let result = SignalAggregator(config: defaultConfig).aggregate(
            signals: [signal("android.root.mount_namespace", 80, 100)]
        )
        XCTAssertEqual(1, result.count)
        XCTAssertEqual(.privilegedAccess, result[0].type)
        XCTAssertEqual(80, result[0].score)
    }

    func testSingleHookSignal_emitsHookFramework() {
        let event = SignalAggregator(config: defaultConfig).aggregate(
            signals: [signal("android.hook.frida_port", 50, 80)]
        ).first!
        XCTAssertEqual(.hookFramework, event.type)
        XCTAssertEqual(40, event.score)
    }

    func testMultiSignalSameType_combinesScore() {
        let events = SignalAggregator(config: defaultConfig).aggregate(
            signals: [
                signal("android.root.mount_namespace", 40, 100),
                signal("android.root.maps_artifact", 40, 100),
            ]
        )
        XCTAssertEqual(80, events.first?.score)
    }

    func testScoreCapsAt100() {
        let events = SignalAggregator(config: defaultConfig).aggregate(
            signals: [
                signal("android.root.a", 60, 100),
                signal("android.root.b", 60, 100),
            ]
        )
        XCTAssertEqual(100, events.first?.score)
    }

    func testZeroWeight_producesNoEvent() {
        let result = SignalAggregator(config: defaultConfig).aggregate(
            signals: [signal("android.root.test", 0, 100)]
        )
        XCTAssertTrue(result.isEmpty)
    }

    func testZeroConfidence_producesNoEvent() {
        let result = SignalAggregator(config: defaultConfig).aggregate(
            signals: [signal("android.root.test", 50, 0)]
        )
        XCTAssertTrue(result.isEmpty)
    }

    func testPrivilegedAccess_criticalSeverity_atHighScore() {
        let event = SignalAggregator(config: defaultConfig).aggregate(
            signals: [signal("android.root.test", 90, 100)]
        ).first!
        XCTAssertEqual(.critical, event.severity)
    }

    func testPrivilegedAccess_warningSeverity_atMediumScore() {
        let event = SignalAggregator(config: defaultConfig).aggregate(
            signals: [signal("android.root.test", 45, 100)]
        ).first!
        XCTAssertEqual(.high, event.severity)
    }

    func testDebugger_mapsCorrectly() {
        let event = SignalAggregator(config: defaultConfig).aggregate(
            signals: [signal("android.debug.tracerpid", 60, 100)]
        ).first!
        XCTAssertEqual(.debugger, event.type)
    }

    func testEmulator_mapsCorrectly() {
        let event = SignalAggregator(config: defaultConfig).aggregate(
            signals: [signal("android.env.qemu_props", 30, 100)]
        ).first!
        XCTAssertEqual(.emulator, event.type)
    }

    func testAutomation_mapsCorrectly() {
        let event = SignalAggregator(config: defaultConfig).aggregate(
            signals: [signal("android.automation.appium", 35, 100)]
        ).first!
        XCTAssertEqual(.automation, event.type)
    }

    func testIntegrity_mapsCorrectly() {
        let event = SignalAggregator(config: defaultConfig).aggregate(
            signals: [signal("android.integrity.signature", 55, 100)]
        ).first!
        XCTAssertEqual(.appIntegrity, event.type)
    }

    func testUnofficialStore_mapsCorrectly() {
        let event = SignalAggregator(config: defaultConfig).aggregate(
            signals: [signal("android.store.installer", 25, 100)]
        ).first!
        XCTAssertEqual(.unofficialStore, event.type)
    }

    func testDeveloperMode_neverCritical() {
        let event = SignalAggregator(config: defaultConfig).aggregate(
            signals: [signal("android.dev.options", 100, 100)]
        ).first!
        XCTAssertEqual(.developerMode, event.type)
        XCTAssertNotEqual(.critical, event.severity)
    }

    func testAdbEnabled_neverCritical() {
        let event = SignalAggregator(config: defaultConfig).aggregate(
            signals: [signal("android.adb.enabled", 100, 100)]
        ).first!
        XCTAssertEqual(.adbEnabled, event.type)
        XCTAssertNotEqual(.critical, event.severity)
    }

    func testSuppressDeveloperSignals_whenDisabled() {
        let config = MobShieldConfig(allowDeveloperSignals: false)
        let result = SignalAggregator(config: config).aggregate(
            signals: [
                signal("android.dev.options", 100, 100),
                signal("android.adb.enabled", 100, 100),
            ]
        )
        XCTAssertTrue(result.isEmpty)
    }

    func testMultipleThreatTypes_returnsMultipleEvents() {
        let events = SignalAggregator(config: defaultConfig).aggregate(
            signals: [
                signal("android.root.test", 80, 100),
                signal("android.hook.frida_port", 70, 100),
            ]
        )
        XCTAssertEqual(2, events.count)
        XCTAssertEqual(
            Set([ThreatType.privilegedAccess, .hookFramework]),
            Set(events.map(\.type))
        )
    }

    func testEvents_sortedByScoreDescending() {
        let events = SignalAggregator(config: defaultConfig).aggregate(
            signals: [
                signal("android.env.qemu_props", 30, 100),
                signal("android.root.test", 90, 100),
            ]
        )
        XCTAssertGreaterThanOrEqual(events.first?.score ?? 0, events.last?.score ?? 0)
    }

    func testEvidence_mergedIntoMetadata() {
        let event = SignalAggregator(config: defaultConfig).aggregate(
            signals: [
                Signal(
                    name: "android.root.test",
                    weight: 80,
                    confidence: 100,
                    evidence: ["detail": "mount"],
                    timestampMs: 1
                ),
            ]
        ).first!
        XCTAssertEqual("mount", event.metadata["android.root.test.detail"])
    }

    func testCustomThresholds_respected() {
        var thresholds = DefaultThreatThresholds.map
        thresholds[.emulator] = try! ThreatThreshold(warning: 10, critical: 15)
        let config = MobShieldConfig(thresholds: thresholds)
        let event = SignalAggregator(config: config).aggregate(
            signals: [signal("android.env.qemu_props", 16, 100)]
        ).first!
        XCTAssertEqual(.critical, event.severity)
    }

    func testCommonHookPrefix_mapsToHookFramework() {
        let event = SignalAggregator(config: defaultConfig).aggregate(
            signals: [signal("common.hook.prologue", 65, 100)]
        ).first!
        XCTAssertEqual(.hookFramework, event.type)
    }

    func testIosJailbreak_mapsToPrivilegedAccess() {
        let event = SignalAggregator(config: defaultConfig).aggregate(
            signals: [signal("ios.jb.dyld_image", 70, 100)]
        ).first!
        XCTAssertEqual(.privilegedAccess, event.type)
    }

    func testLowScoreBelowWarning_emitsInfoOrSkipped() {
        let result = SignalAggregator(config: defaultConfig).aggregate(
            signals: [signal("android.root.test", 5, 50)]
        )
        XCTAssertTrue(result.isEmpty || result.first?.severity == .info)
    }

    func testResolveThreatType_coversKnownPrefixes() {
        XCTAssertEqual(
            .debugger,
            SignalAggregator.resolveThreatType(signalName: "android.debug.ptrace")
        )
        XCTAssertEqual(
            .hookFramework,
            SignalAggregator.resolveThreatType(signalName: "ios.hook.dyld_insert")
        )
    }

    private func signal(_ name: String, _ weight: Int, _ confidence: Int) -> Signal {
        Signal(name: name, weight: weight, confidence: confidence, timestampMs: 1)
    }
}
