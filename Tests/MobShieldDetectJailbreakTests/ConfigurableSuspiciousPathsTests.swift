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

final class ConfigurableSuspiciousPathsTests: XCTestCase {
    func testAllPaths_includesBuiltInAndAdditional() {
        let paths = ConfigurableSuspiciousPaths(
            additionalPaths: ["/custom/jb/marker", "/var/jb"]
        ).allPaths()
        XCTAssertTrue(paths.contains("/var/jb"))
        XCTAssertTrue(paths.contains("/custom/jb/marker"))
        XCTAssertTrue(paths.contains("/Applications/Cydia.app"))
    }

    func testAllPaths_deduplicates() {
        let paths = ConfigurableSuspiciousPaths(additionalPaths: ["/var/jb", "  /var/jb  "]).allPaths()
        XCTAssertEqual(paths.filter { $0 == "/var/jb" }.count, 1)
    }

    func testConfig_additionalJailbreakPaths_merged() {
        let config = MobShieldConfig(additionalJailbreakPaths: ["/enterprise/jb/path"])
        let paths = ConfigurableSuspiciousPaths(config: config).allPaths()
        XCTAssertTrue(paths.contains("/enterprise/jb/path"))
    }
}
