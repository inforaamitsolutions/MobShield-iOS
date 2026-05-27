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
import MobShieldCore

/// App signature, bundle ID, provisioning, resource, and receipt integrity checks.
public struct IntegrityDetectionModule: DetectionModule {
    private let detectionTuning: [String: SignalTuning]
    private let scanTimeoutNs: UInt64
    private let codeSignatureCheck: CodeSignatureCheck
    private let bundleIdentifierCheck: BundleIdentifierCheck?
    private let provisioningCheck: EmbeddedProvisioningProfileCheck
    private let resourceCheck: ResourceIntegrityCheck
    private let receiptCheck: AppStoreReceiptCheck

    public let name = "integrity"
    public let criticality = 100

    public init(
        config: MobShieldConfig = MobShieldConfig(),
        detectionTuning: [String: SignalTuning]? = nil,
        scanTimeoutMs: Int = 100,
        bundle: IntegrityBundleProviding = LiveIntegrityBundleProvider(),
        secCode: IntegritySecCodeProviding = LiveSecCodeProvider()
    ) {
        self.detectionTuning = detectionTuning ?? config.detectionTuning
        scanTimeoutNs = UInt64(scanTimeoutMs) * 1_000_000

        codeSignatureCheck = CodeSignatureCheck(
            expectedSigners: config.expectedSigners,
            secCode: secCode
        )
        if let expectedPackageId = config.expectedPackageId {
            bundleIdentifierCheck = BundleIdentifierCheck(
                expectedPackageId: expectedPackageId,
                bundle: bundle
            )
        } else {
            bundleIdentifierCheck = nil
        }
        provisioningCheck = EmbeddedProvisioningProfileCheck(
            expectedPackageId: config.expectedPackageId,
            bundle: bundle
        )
        resourceCheck = ResourceIntegrityCheck(
            expectedHashes: config.expectedResourceHashes,
            bundle: bundle
        )
        receiptCheck = AppStoreReceiptCheck(bundle: bundle)
    }

    public func scan() async -> [Signal] {
        await withTaskGroup(of: [Signal].self) { group in
            group.addTask { await self.runCheck(IntegritySignalDefaults.secCode) { self.codeSignatureCheck.scan() } }
            group.addTask {
                await self.runCheck(IntegritySignalDefaults.bundleId) {
                    self.bundleIdentifierCheck?.scan()
                }
            }
            group.addTask { await self.runCheck(IntegritySignalDefaults.provisioning) { self.provisioningCheck.scan() } }
            group.addTask { await self.runCheck(IntegritySignalDefaults.resource) { self.resourceCheck.scan() } }
            group.addTask { await self.runCheck(IntegritySignalDefaults.receipt) { self.receiptCheck.scan() } }

            var signals: [Signal] = []
            for await batch in group {
                signals.append(contentsOf: batch)
            }
            return signals
        }
    }

    private func runCheck(
        _ signalName: String,
        block: @escaping @Sendable () -> IntegrityScanHit?
    ) async -> [Signal] {
        await withTimeout {
            guard let hit = block() else {
                return []
            }
            var evidence = hit.evidence
            evidence["reason"] = hit.reason
            return [
                IntegritySignalDefaults.buildSignal(
                    name: signalName,
                    evidence: evidence,
                    tuning: detectionTuning
                ),
            ]
        }
    }

    private func withTimeout(_ block: @escaping @Sendable () -> [Signal]) async -> [Signal] {
        await withTaskGroup(of: [Signal].self) { group in
            group.addTask { block() }
            group.addTask {
                try? await Task.sleep(nanoseconds: scanTimeoutNs)
                return []
            }
            let first = await group.next() ?? []
            group.cancelAll()
            return first
        }
    }
}
