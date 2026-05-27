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

/// Compares live code signing certificate digests to `MobShieldConfig.expectedSigners`.
public struct CodeSignatureCheck: Sendable {
    private let expectedSigners: [String]
    private let secCode: IntegritySecCodeProviding

    public init(expectedSigners: [String], secCode: IntegritySecCodeProviding) {
        self.expectedSigners = expectedSigners.map { SHA256Digest.normalize($0) }
        self.secCode = secCode
    }

    public func scan() -> IntegrityScanHit? {
        guard !expectedSigners.isEmpty else {
            return nil
        }

        let signingInfo: IntegritySigningInfo
        do {
            signingInfo = try secCode.copySigningInfo()
        } catch {
            return IntegrityScanHit(
                reason: "sec_code_unavailable",
                evidence: ["detail": "unable_to_read_signing_information"]
            )
        }

        let actual = Set(signingInfo.certificateDigests.map { SHA256Digest.normalize($0) })
        let expected = Set(expectedSigners)
        if actual.isDisjoint(with: expected) {
            return IntegrityScanHit(
                reason: "certificate_mismatch",
                evidence: [
                    "expected": expectedSigners.joined(separator: ","),
                    "actual": signingInfo.certificateDigests.joined(separator: ","),
                    "teamId": signingInfo.teamIdentifier ?? "",
                ]
            )
        }
        return nil
    }
}
