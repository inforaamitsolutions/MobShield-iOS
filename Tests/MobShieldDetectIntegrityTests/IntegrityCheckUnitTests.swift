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
import MobShieldDetectIntegrity
import XCTest

final class IntegrityCheckUnitTests: XCTestCase {
    func testCodeSignature_mismatch_emitsHit() {
        let check = CodeSignatureCheck(
            expectedSigners: ["a".padding(toLength: 64, withPad: "b", startingAt: 0)],
            secCode: MockSecCodeProvider(
                signingInfo: IntegritySigningInfo(
                    certificateDigests: ["c".padding(toLength: 64, withPad: "d", startingAt: 0)],
                    teamIdentifier: "TEAM",
                    bundleIdentifier: "com.example.app"
                )
            )
        )
        XCTAssertEqual("certificate_mismatch", check.scan()?.reason)
    }

    func testCodeSignature_match_noHit() {
        let digest = "a".padding(toLength: 64, withPad: "0", startingAt: 0)
        let check = CodeSignatureCheck(
            expectedSigners: [digest],
            secCode: MockSecCodeProvider(
                signingInfo: IntegritySigningInfo(
                    certificateDigests: [digest],
                    teamIdentifier: "TEAM",
                    bundleIdentifier: "com.example.app"
                )
            )
        )
        XCTAssertNil(check.scan())
    }

    func testBundleIdentifier_mismatch() {
        let bundle = MockIntegrityBundle(bundleIdentifier: "com.attacker.app")
        let check = BundleIdentifierCheck(expectedPackageId: "com.example.app", bundle: bundle)
        XCTAssertEqual("bundle_id_mismatch", check.scan()?.reason)
    }

    func testResourceIntegrity_hashMismatch() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let infoURL = tempDir.appendingPathComponent("Info.plist")
        try Data("demo".utf8).write(to: infoURL)

        let bundle = MockIntegrityBundle(
            bundleURL: tempDir,
            files: [infoURL.path: Data("demo".utf8)]
        )
        let expected = "f".padding(toLength: 64, withPad: "e", startingAt: 0)
        let check = ResourceIntegrityCheck(expectedHashes: ["Info.plist": expected], bundle: bundle)
        XCTAssertEqual("resource_hash_mismatch", check.scan()?.reason)
    }

    func testAppStoreReceipt_invalidPayload() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let receiptURL = tempDir.appendingPathComponent("receipt")
        try Data([0x00, 0x01]).write(to: receiptURL)

        let bundle = MockIntegrityBundle(
            bundleURL: tempDir,
            appStoreReceiptURL: receiptURL,
            files: [receiptURL.path: Data([0x00, 0x01])]
        )
        XCTAssertEqual("receipt_too_small", AppStoreReceiptCheck(bundle: bundle, minimumReceiptBytes: 128).scan()?.reason)
    }

    func testIntegrityModule_mockedProviders_emitSignal() async {
        let digest = "a".padding(toLength: 64, withPad: "0", startingAt: 0)
        let config = try! MobShieldConfig.make(
            expectedSigners: ["b".padding(toLength: 64, withPad: "1", startingAt: 0)],
            expectedPackageId: "com.example.app"
        )
        let module = IntegrityDetectionModule(
            config: config,
            bundle: MockIntegrityBundle(bundleIdentifier: "com.example.app"),
            secCode: MockSecCodeProvider(
                signingInfo: IntegritySigningInfo(
                    certificateDigests: [digest],
                    teamIdentifier: "TEAM",
                    bundleIdentifier: "com.example.app"
                )
            )
        )
        let signals = await module.scan()
        XCTAssertTrue(signals.contains { $0.name == IntegritySignalDefaults.secCode })
    }
}
