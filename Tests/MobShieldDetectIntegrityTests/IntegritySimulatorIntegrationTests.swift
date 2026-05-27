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

/// Uses live Security.framework providers. Anchors are taken from the running test bundle.
final class IntegritySimulatorIntegrationTests: XCTestCase {
    func testNativeModule_matchingAnchors_doesNotEmitAppIntegrity() async throws {
        let bundleId = Bundle.main.bundleIdentifier ?? ""
        let signingInfo = try? LiveSecCodeProvider().copySigningInfo()
        let signers = signingInfo?.certificateDigests ?? []

        let config = try MobShieldConfig.make(
            expectedSigners: signers,
            expectedPackageId: bundleId
        )

        let module = IntegrityDetectionModule(config: config)
        let signals = await module.scan()
        let events = SignalAggregator(config: config).aggregate(signals: signals)

        if events.contains(where: { $0.type == .appIntegrity }) {
            let names = signals.map(\.name).joined(separator: ", ")
            XCTFail("Unexpected APP_INTEGRITY. Signals: [\(names)]")
        }
    }
}
