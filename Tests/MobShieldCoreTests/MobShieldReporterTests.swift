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

import CryptoKit
import Foundation
import XCTest
@testable import MobShieldCore

final class MobShieldReporterTests: XCTestCase {
    private let key = Data("test-shared-secret".utf8)

    func testMakeReport_mapsStateAndEvents_sortedByScoreDescending() {
        let report = MobShieldReporter.makeReport(
            state: state(risk: .high, lastScanMs: 1_234),
            events: [
                event(.debugger, .medium, 40),
                event(.privilegedAccess, .critical, 90),
            ],
            buildId: "ios-test-abc"
        )

        XCTAssertEqual(ThreatReport.currentSchemaVersion, report.schemaVersion)
        XCTAssertEqual("ios-test-abc", report.buildId)
        XCTAssertEqual(1_234, report.generatedAtMs)
        XCTAssertEqual(.high, report.riskLevel)
        // Sorted by score descending.
        XCTAssertEqual([.privilegedAccess, .debugger], report.threats.map(\.type))
        XCTAssertEqual(90, report.threats.first?.score)
    }

    func testCanonicalJSON_isDeterministic() throws {
        let report = MobShieldReporter.makeReport(
            state: state(risk: .medium, lastScanMs: 7),
            events: [event(.hookFramework, .high, 70)],
            buildId: "b"
        )
        let a = try MobShieldReporter.canonicalJSON(report)
        let b = try MobShieldReporter.canonicalJSON(report)
        XCTAssertEqual(a, b)
        // Keys are sorted → "buildId" precedes "riskLevel" in the byte stream.
        let text = String(bytes: a, encoding: .utf8) ?? ""
        XCTAssertTrue(text.contains("\"schemaVersion\":\"report-1\""))
    }

    func testSign_matchesIndependentlyComputedHMAC() throws {
        let report = MobShieldReporter.makeReport(
            state: state(risk: .low, lastScanMs: 1),
            events: [],
            buildId: "b"
        )
        let signed = try MobShieldReporter.sign(report, key: key)

        // A backend would recompute the HMAC over the received JSON bytes.
        let expected = HMAC<SHA256>.authenticationCode(for: signed.json, using: SymmetricKey(data: key))
        let expectedHex = expected.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(expectedHex, signed.signatureHex)
    }

    func testSign_tamperedJSON_failsVerification() throws {
        let report = MobShieldReporter.makeReport(
            state: state(risk: .high, lastScanMs: 1),
            events: [event(.privilegedAccess, .critical, 95)],
            buildId: "b"
        )
        let signed = try MobShieldReporter.sign(report, key: key)

        // Flip the risk level in the transmitted JSON; the original signature must not verify.
        let original = String(bytes: signed.json, encoding: .utf8) ?? ""
        let tampered = original.replacingOccurrences(of: "\"HIGH\"", with: "\"NONE\"")
        let tamperedData = Data(tampered.utf8)
        XCTAssertNotEqual(signed.json, tamperedData)

        let recomputed = HMAC<SHA256>.authenticationCode(for: tamperedData, using: SymmetricKey(data: key))
        let recomputedHex = recomputed.map { String(format: "%02x", $0) }.joined()
        XCTAssertNotEqual(signed.signatureHex, recomputedHex)
    }

    func testSign_differentKey_producesDifferentSignature() throws {
        let report = MobShieldReporter.makeReport(
            state: state(risk: .low, lastScanMs: 1),
            events: [],
            buildId: "b"
        )
        let a = try MobShieldReporter.sign(report, key: Data("key-a".utf8))
        let b = try MobShieldReporter.sign(report, key: Data("key-b".utf8))
        XCTAssertEqual(a.json, b.json)
        XCTAssertNotEqual(a.signatureHex, b.signatureHex)
    }

    func testReport_roundTripsThroughCodable() throws {
        let report = MobShieldReporter.makeReport(
            state: state(risk: .high, lastScanMs: 42),
            events: [event(.privilegedAccess, .critical, 90)],
            buildId: "b"
        )
        let data = try MobShieldReporter.canonicalJSON(report)
        let decoded = try JSONDecoder().decode(ThreatReport.self, from: data)
        XCTAssertEqual(report, decoded)
    }

    // MARK: - Helpers

    private func state(risk: RiskLevel, lastScanMs: Int64) -> MobShieldState {
        MobShieldState(
            riskLevel: risk,
            activeThreats: [],
            lastScanMs: lastScanMs,
            signalSetVersion: MobShield.signalSetVersion,
            running: true
        )
    }

    private func event(_ type: ThreatType, _ severity: Severity, _ score: Int) -> ThreatEvent {
        ThreatEvent.create(
            type: type,
            severity: severity,
            signals: ["\(type.rawValue).mock"],
            score: score,
            timestampMs: 0
        )
    }
}
