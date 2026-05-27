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

/// Validates `Bundle.main.appStoreReceiptURL` when a receipt is present.
public struct AppStoreReceiptCheck: Sendable {
    private let bundle: IntegrityBundleProviding
    private let minimumReceiptBytes: Int

    public init(bundle: IntegrityBundleProviding, minimumReceiptBytes: Int = 128) {
        self.bundle = bundle
        self.minimumReceiptBytes = minimumReceiptBytes
    }

    public func scan() -> IntegrityScanHit? {
        guard let receiptURL = bundle.appStoreReceiptURL else {
            return nil
        }

        guard bundle.fileExists(atPath: receiptURL.path) else {
            return IntegrityScanHit(
                reason: "receipt_url_without_file",
                evidence: ["path": receiptURL.path]
            )
        }

        guard let data = bundle.contents(atPath: receiptURL.path) else {
            return IntegrityScanHit(
                reason: "receipt_unreadable",
                evidence: ["path": receiptURL.path]
            )
        }

        if data.count < minimumReceiptBytes {
            return IntegrityScanHit(
                reason: "receipt_too_small",
                evidence: [
                    "path": receiptURL.path,
                    "bytes": String(data.count),
                ]
            )
        }

        if data.first != 0x30 {
            return IntegrityScanHit(
                reason: "receipt_not_pkcs7",
                evidence: ["path": receiptURL.path]
            )
        }

        return nil
    }
}
