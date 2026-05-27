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

/// Parses `embedded.mobileprovision` and validates application identifier metadata.
public struct EmbeddedProvisioningProfileCheck: Sendable {
    private let expectedPackageId: String?
    private let bundle: IntegrityBundleProviding

    public init(expectedPackageId: String?, bundle: IntegrityBundleProviding) {
        self.expectedPackageId = expectedPackageId
        self.bundle = bundle
    }

    public func scan() -> IntegrityScanHit? {
        guard let bundleURL = bundle.bundleURL else {
            return IntegrityScanHit(reason: "bundle_url_missing")
        }

        let profileURL = bundleURL.appendingPathComponent("embedded.mobileprovision")
        guard bundle.fileExists(atPath: profileURL.path) else {
            #if targetEnvironment(simulator)
            return nil
            #else
            return IntegrityScanHit(
                reason: "provisioning_profile_missing",
                evidence: ["path": profileURL.path]
            )
            #endif
        }

        guard let data = bundle.contents(atPath: profileURL.path) else {
            return IntegrityScanHit(
                reason: "provisioning_profile_unreadable",
                evidence: ["path": profileURL.path]
            )
        }

        guard let plist = ProvisioningProfileParser.parsePlist(from: data) else {
            return IntegrityScanHit(
                reason: "provisioning_profile_parse_failed",
                evidence: ["path": profileURL.path]
            )
        }

        let appIdentifier = ProvisioningProfileParser.applicationIdentifier(from: plist)
        let teamIds = ProvisioningProfileParser.teamIdentifiers(from: plist)

        guard let expectedPackageId, !expectedPackageId.isEmpty else {
            return nil
        }

        if let appIdentifier {
            let suffix = "." + expectedPackageId
            if appIdentifier != expectedPackageId, !appIdentifier.hasSuffix(suffix) {
                return IntegrityScanHit(
                    reason: "provisioning_app_id_mismatch",
                    evidence: [
                        "expected": expectedPackageId,
                        "applicationIdentifier": appIdentifier,
                        "teamIds": teamIds.joined(separator: ","),
                    ]
                )
            }
        }

        return nil
    }
}
