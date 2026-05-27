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

final class MobShieldConfigTests: XCTestCase {
    func testDefaults_detectOnlyWithNoTermination() {
        let config = MobShieldConfig()
        XCTAssertTrue(config.detectOnly)
        XCTAssertEqual(.none, config.terminationPolicy)
        XCTAssertTrue(config.allowDeveloperSignals)
        XCTAssertEqual(DefaultThreatThresholds.map, config.thresholds)
    }

    func testBuilder_producesEquivalentConfig() throws {
        let signer = String(repeating: "a", count: 64)
        let built = try MobShieldConfig.builder()
            .detectOnly(false)
            .expectedSigners([signer])
            .terminationPolicy(.exitOnCritical)
            .allowDeveloperSignals(false)
            .expectedPackageId("com.example.app")
            .periodicIntervalSec(60)
            .build()
        XCTAssertFalse(built.detectOnly)
        XCTAssertEqual([signer], built.expectedSigners)
        XCTAssertEqual(.exitOnCritical, built.terminationPolicy)
        XCTAssertEqual("com.example.app", built.expectedPackageId)
        XCTAssertEqual(60, built.periodicIntervalSec)
    }

    func testInvalidSigner_rejected() {
        XCTAssertThrowsError(
            try MobShieldConfig.make(expectedSigners: ["not-hex"])
        ) { error in
            XCTAssertEqual(MobShieldConfigError.invalidSigner("expectedSigners must be 64-char SHA-256 hex: not-hex"), error as? MobShieldConfigError)
        }
    }

    func testDetectOnly_withTermination_rejected() {
        XCTAssertThrowsError(
            try MobShieldConfig.make(terminationPolicy: .exitOnCritical)
        ) { error in
            XCTAssertEqual(MobShieldConfigError.detectOnlyRequiresNoTermination, error as? MobShieldConfigError)
        }
    }

    func testPeriodicInterval_mustBePositive() {
        XCTAssertThrowsError(
            try MobShieldConfig.make(periodicIntervalSec: 0)
        ) { error in
            XCTAssertEqual(MobShieldConfigError.invalidPeriodicInterval, error as? MobShieldConfigError)
        }
    }

    func testValidateSigners_acceptsUppercaseHex() throws {
        let signer = String(repeating: "A", count: 64)
        try MobShieldConfig.validateSigners([signer])
    }

    func testThreatThreshold_warningAboveCritical_rejected() {
        XCTAssertThrowsError(try ThreatThreshold(warning: 80, critical: 50)) { error in
            XCTAssertEqual(ThreatThresholdError.warningAboveCritical, error as? ThreatThresholdError)
        }
    }
}
