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

import Foundation

/// Compares `Bundle` identifier to the build-time anchor in `MobShieldConfig.expectedPackageId`.
public struct BundleIdentifierCheck: Sendable {
    private let expectedPackageId: String
    private let bundle: IntegrityBundleProviding

    public init(expectedPackageId: String, bundle: IntegrityBundleProviding) {
        self.expectedPackageId = expectedPackageId
        self.bundle = bundle
    }

    public func scan() -> IntegrityScanHit? {
        guard let actual = bundle.bundleIdentifier else {
            return IntegrityScanHit(
                reason: "bundle_id_missing",
                evidence: ["expected": expectedPackageId]
            )
        }
        if actual != expectedPackageId {
            return IntegrityScanHit(
                reason: "bundle_id_mismatch",
                evidence: [
                    "expected": expectedPackageId,
                    "actual": actual,
                ]
            )
        }
        return nil
    }
}
