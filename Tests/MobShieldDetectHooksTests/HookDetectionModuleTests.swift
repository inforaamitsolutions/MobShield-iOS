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
import MobShieldDetectHooks
import XCTest

final class HookDetectionModuleTests: XCTestCase {
    func testScan_mockFridaMaps_emitsSignal() async {
        MockHookNative.fridaMapsDetected = true
        MockHookNative.fridaMapsEvidence = "image=FridaGadget.dylib"
        defer { MockHookNative.reset() }

        let module = HookDetectionModule(nativeChecker: MockHookNative.self, configureBaselines: {})
        let signals = await module.scan()
        XCTAssertEqual(1, signals.count)
        XCTAssertEqual(HookSignalDefaults.fridaMaps, signals[0].name)
    }

    func testScan_noHits_returnsEmpty() async {
        MockHookNative.reset()
        let module = HookDetectionModule(nativeChecker: MockHookNative.self, configureBaselines: {})
        let signals = await module.scan()
        XCTAssertTrue(signals.isEmpty)
    }

    func testAggregated_mockHit_mapsToHookFramework() async {
        MockHookNative.prologueDetected = true
        MockHookNative.prologueEvidence = "symbol=objc_msgSend"
        defer { MockHookNative.reset() }

        let module = HookDetectionModule(nativeChecker: MockHookNative.self, configureBaselines: {})
        let signals = await module.scan()
        let events = SignalAggregator(config: MobShieldConfig()).aggregate(signals: signals)
        XCTAssertEqual(ThreatType.hookFramework, events.first?.type)
    }
}

enum MockHookNative: HookNativeChecking {
    static var machRegionDetected = false
    static var prologueDetected = false
    static var fridaMapsDetected = false
    static var fridaPortDetected = false
    static var dyldDetected = false
    static var swizzleDetected = false
    static var machRegionEvidence = ""
    static var prologueEvidence = ""
    static var fridaMapsEvidence = ""
    static var fridaPortEvidence = ""
    static var dyldEvidence = ""
    static var swizzleEvidence = ""

    static func reset() {
        machRegionDetected = false
        prologueDetected = false
        fridaMapsDetected = false
        fridaPortDetected = false
        dyldDetected = false
        swizzleDetected = false
        machRegionEvidence = ""
        prologueEvidence = ""
        fridaMapsEvidence = ""
        fridaPortEvidence = ""
        dyldEvidence = ""
        swizzleEvidence = ""
    }

    static func configureBaselines(prologue: [HookPrologueBaseline], swizzle: [HookSwizzleBaseline]) {
        _ = prologue
        _ = swizzle
    }

    static func machRegionInspect() -> HookNativeCheckResult {
        result(detected: machRegionDetected, evidence: machRegionEvidence)
    }

    static func functionPrologueInspect() -> HookNativeCheckResult {
        result(detected: prologueDetected, evidence: prologueEvidence)
    }

    static func fridaArtifactScan() -> HookNativeCheckResult {
        result(detected: fridaMapsDetected, evidence: fridaMapsEvidence)
    }

    static func fridaPortProbe() -> HookNativeCheckResult {
        result(detected: fridaPortDetected, evidence: fridaPortEvidence)
    }

    static func dyldEnvironmentScan() -> HookNativeCheckResult {
        result(detected: dyldDetected, evidence: dyldEvidence)
    }

    static func methodSwizzleDetect() -> HookNativeCheckResult {
        result(detected: swizzleDetected, evidence: swizzleEvidence)
    }

    private static func result(detected: Bool, evidence: String) -> HookNativeCheckResult {
        HookNativeCheckResult(
            code: detected ? HookNativeBridge.resultDetected : HookNativeBridge.resultOk,
            evidence: evidence
        )
    }
}
