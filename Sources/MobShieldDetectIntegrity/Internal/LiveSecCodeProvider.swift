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
import Security

public enum IntegritySecCodeError: Error, Sendable {
    case apiFailed(OSStatus)
    case missingSigningInfo
}

/// Reads signing metadata from the embedded provisioning profile using Security.framework certificates.
///
/// `SecCodeCopySelf` is unavailable on iOS SDK targets; certificate digests are derived from
/// `DeveloperCertificates` entries in `embedded.mobileprovision` via `SecCertificateCreateWithData`.
public struct LiveSecCodeProvider: IntegritySecCodeProviding {
    private let bundle: IntegrityBundleProviding

    public init(bundle: IntegrityBundleProviding = LiveIntegrityBundleProvider()) {
        self.bundle = bundle
    }

    public func copySigningInfo() throws -> IntegritySigningInfo {
        guard let bundleURL = bundle.bundleURL else {
            throw IntegritySecCodeError.missingSigningInfo
        }
        let profileURL = bundleURL.appendingPathComponent("embedded.mobileprovision")
        guard let data = bundle.contents(atPath: profileURL.path),
              let plist = ProvisioningProfileParser.parsePlist(from: data) else {
            throw IntegritySecCodeError.missingSigningInfo
        }

        let certDataList = plist["DeveloperCertificates"] as? [Data] ?? []
        var digests: [String] = []
        for certData in certDataList {
            guard let certificate = SecCertificateCreateWithData(nil, certData as CFData) else {
                continue
            }
            let digestData = SecCertificateCopyData(certificate) as Data
            digests.append(SHA256Digest.hex(for: digestData))
        }

        let teamIds = ProvisioningProfileParser.teamIdentifiers(from: plist)
        let appId = ProvisioningProfileParser.applicationIdentifier(from: plist)

        if digests.isEmpty {
            throw IntegritySecCodeError.missingSigningInfo
        }

        return IntegritySigningInfo(
            certificateDigests: digests,
            teamIdentifier: teamIds.first,
            bundleIdentifier: appId
        )
    }
}
