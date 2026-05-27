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

/// Hashes curated bundle resources and compares them to build-time anchors.
public struct ResourceIntegrityCheck: Sendable {
    private let expectedHashes: [String: String]
    private let bundle: IntegrityBundleProviding

    public init(expectedHashes: [String: String], bundle: IntegrityBundleProviding) {
        self.expectedHashes = expectedHashes
        self.bundle = bundle
    }

    public func scan() -> IntegrityScanHit? {
        guard !expectedHashes.isEmpty else {
            return nil
        }

        guard let bundleURL = bundle.bundleURL else {
            return IntegrityScanHit(reason: "bundle_url_missing")
        }

        for (relativePath, expectedDigest) in expectedHashes {
            let fileURL = bundleURL.appendingPathComponent(relativePath)
            guard bundle.fileExists(atPath: fileURL.path) else {
                return IntegrityScanHit(
                    reason: "resource_missing",
                    evidence: [
                        "path": relativePath,
                        "expected": SHA256Digest.normalize(expectedDigest),
                    ]
                )
            }
            guard let actualDigest = SHA256Digest.hex(forFileAt: fileURL) else {
                return IntegrityScanHit(
                    reason: "resource_unreadable",
                    evidence: ["path": relativePath]
                )
            }
            if SHA256Digest.normalize(actualDigest) != SHA256Digest.normalize(expectedDigest) {
                return IntegrityScanHit(
                    reason: "resource_hash_mismatch",
                    evidence: [
                        "path": relativePath,
                        "expected": SHA256Digest.normalize(expectedDigest),
                        "actual": SHA256Digest.normalize(actualDigest),
                    ]
                )
            }
        }
        return nil
    }

    /// Paths commonly anchored by the personalization plugin (Info.plist, main storyboard).
    public static func curatedResourcePaths(bundle: IntegrityBundleProviding) -> [String] {
        var paths = ["Info.plist"]
        if let storyboardName = bundle.object(forInfoDictionaryKey: "UIMainStoryboardFile") as? String {
            paths.append("\(storyboardName).storyboardc/Info.plist")
        }
        return paths
    }
}
