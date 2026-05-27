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
import MobShieldDetectJailbreak
import XCTest

final class JailbreakDetectionModuleTests: XCTestCase {
    func testScan_mockFilesystemHit_emitsFsProbeSignal() async {
        let module = JailbreakDetectionModule(
            nativeChecker: MockJailbreakNative.self,
            configurePaths: {}
        )
        MockJailbreakNative.filesystemDetected = true
        MockJailbreakNative.filesystemEvidence = "path=/var/jb"
        defer { MockJailbreakNative.reset() }

        let signals = await module.scan()
        XCTAssertEqual(1, signals.count)
        XCTAssertEqual(JailbreakSignalDefaults.filesystemPaths, signals[0].name)
        XCTAssertEqual("path=/var/jb", signals[0].evidence["detail"])
    }

    func testScan_mockDyldHit_emitsDyldSignal() async {
        MockJailbreakNative.dyldDetected = true
        MockJailbreakNative.dyldEvidence = "image=libhooker.dylib"
        defer { MockJailbreakNative.reset() }

        let module = JailbreakDetectionModule(nativeChecker: MockJailbreakNative.self, configurePaths: {})
        let signals = await module.scan()
        XCTAssertTrue(signals.contains { $0.name == JailbreakSignalDefaults.dyldImage })
    }

    func testScan_noHits_returnsEmpty() async {
        MockJailbreakNative.reset()
        let module = JailbreakDetectionModule(nativeChecker: MockJailbreakNative.self, configurePaths: {})
        let signals = await module.scan()
        XCTAssertTrue(signals.isEmpty)
    }

    func testAggregated_mockHit_mapsToPrivilegedAccess() async {
        MockJailbreakNative.filesystemDetected = true
        MockJailbreakNative.filesystemEvidence = "path=/var/jb"
        defer { MockJailbreakNative.reset() }

        let module = JailbreakDetectionModule(nativeChecker: MockJailbreakNative.self, configurePaths: {})
        let signals = await module.scan()
        let events = SignalAggregator(config: MobShieldConfig()).aggregate(signals: signals)
        XCTAssertEqual(ThreatType.privilegedAccess, events.first?.type)
    }
}

enum MockJailbreakNative: JailbreakNativeChecking {
    static var dyldDetected = false
    static var dyldEvidence = ""
    static var filesystemDetected = false
    static var filesystemEvidence = ""

    static func reset() {
        dyldDetected = false
        dyldEvidence = ""
        filesystemDetected = false
        filesystemEvidence = ""
    }

    static func configureExtraPaths(_ paths: [String]) {
        _ = paths
    }

    static func dyldImageScan() -> NativeCheckResult {
        result(detected: dyldDetected, evidence: dyldEvidence)
    }

    static func filesystemPaths() -> NativeCheckResult {
        result(detected: filesystemDetected, evidence: filesystemEvidence)
    }

    static func sandboxEscape() -> NativeCheckResult {
        result(detected: false, evidence: "")
    }

    static func urlSchemeProbe() -> NativeCheckResult {
        result(detected: false, evidence: "")
    }

    static func sysctlTraced() -> NativeCheckResult {
        result(detected: false, evidence: "")
    }

    static func writeTest() -> NativeCheckResult {
        result(detected: false, evidence: "")
    }

    static func symlinkTest() -> NativeCheckResult {
        result(detected: false, evidence: "")
    }

    static func dyldHeaderInspect() -> NativeCheckResult {
        result(detected: false, evidence: "")
    }

    private static func result(detected: Bool, evidence: String) -> NativeCheckResult {
        NativeCheckResult(
            code: detected ? JailbreakNativeBridge.resultDetected : JailbreakNativeBridge.resultOk,
            evidence: evidence
        )
    }
}
