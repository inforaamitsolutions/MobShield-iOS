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
import XCTest

final class DebuggerDetectionModuleTests: XCTestCase {
    func testScan_mockSysctlHit_emitsSignal() async {
        MockDebugNative.sysctlDetected = true
        MockDebugNative.sysctlEvidence = "flag=P_TRACED"
        defer { MockDebugNative.reset() }

        let module = DebuggerDetectionModule(nativeChecker: MockDebugNative.self)
        let signals = await module.scan()
        XCTAssertTrue(signals.contains { $0.name == DebugSignalDefaults.sysctlTraced })
    }

    func testScan_ptraceDisabled_skipsDenyAttachCheck() async {
        MockDebugNative.denyAttachDetected = true
        defer { MockDebugNative.reset() }

        let config = try! MobShieldConfig.make(enablePtraceDenyAttach: false)
        let module = DebuggerDetectionModule(config: config, nativeChecker: MockDebugNative.self)
        let signals = await module.scan()
        XCTAssertFalse(signals.contains { $0.name == DebugSignalDefaults.denyAttach })
    }

    func testScan_ptraceEnabled_runsDenyAttachCheck() async {
        MockDebugNative.denyAttachDetected = true
        defer { MockDebugNative.reset() }

        let config = try! MobShieldConfig.make(enablePtraceDenyAttach: true)
        let module = DebuggerDetectionModule(config: config, nativeChecker: MockDebugNative.self)
        let signals = await module.scan()
        XCTAssertTrue(signals.contains { $0.name == DebugSignalDefaults.denyAttach })
    }

    func testAggregated_mockHit_mapsToDebugger() async {
        MockDebugNative.sysctlDetected = true
        defer { MockDebugNative.reset() }

        let module = DebuggerDetectionModule(nativeChecker: MockDebugNative.self)
        let signals = await module.scan()
        let events = SignalAggregator(config: MobShieldConfig()).aggregate(signals: signals)
        XCTAssertEqual(ThreatType.debugger, events.first?.type)
    }
}

enum MockDebugNative: DebugNativeChecking {
    static var sysctlDetected = false
    static var denyAttachDetected = false
    static var machExceptionDetected = false
    static var timingDetected = false
    static var sysctlEvidence = ""
    static var denyAttachEvidence = ""
    static var machExceptionEvidence = ""
    static var timingEvidence = ""

    static func reset() {
        sysctlDetected = false
        denyAttachDetected = false
        machExceptionDetected = false
        timingDetected = false
        sysctlEvidence = ""
        denyAttachEvidence = ""
        machExceptionEvidence = ""
        timingEvidence = ""
    }

    static func sysctlPtraced() -> DebugNativeCheckResult {
        result(detected: sysctlDetected, evidence: sysctlEvidence)
    }

    static func ptraceDenyAttach() -> DebugNativeCheckResult {
        result(detected: denyAttachDetected, evidence: denyAttachEvidence)
    }

    static func machExceptionCheck() -> DebugNativeCheckResult {
        result(detected: machExceptionDetected, evidence: machExceptionEvidence)
    }

    static func timingCheck() -> DebugNativeCheckResult {
        result(detected: timingDetected, evidence: timingEvidence)
    }

    private static func result(detected: Bool, evidence: String) -> DebugNativeCheckResult {
        DebugNativeCheckResult(
            code: detected ? DebugNativeBridge.resultDetected : DebugNativeBridge.resultOk,
            evidence: evidence
        )
    }
}
