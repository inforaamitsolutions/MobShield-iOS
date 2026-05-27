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

public enum MobShieldConfigError: Error, Equatable {
    case invalidSigner(String)
    case detectOnlyRequiresNoTermination
    case invalidPeriodicInterval
    case blankPackageId
}

/// Runtime configuration for MobShield.
public struct MobShieldConfig: Equatable, Sendable {
    /// When true, never suggests process termination (spec DETECT_ONLY mode).
    public let detectOnly: Bool
    /// SHA-256 certificate digests (hex, lowercase or uppercase).
    public let expectedSigners: [String]
    /// Optional process exit policy.
    public let terminationPolicy: TerminationPolicy
    /// Per-threat score cutoffs overriding spec defaults.
    public let thresholds: [ThreatType: ThreatThreshold]
    /// Emit DEVELOPER_MODE and ADB_ENABLED events when true.
    public let allowDeveloperSignals: Bool
    /// Optional bundle identifier override for integrity checks.
    public let expectedPackageId: String?
    /// Optional rescan interval in seconds; nil disables periodic scans.
    public let periodicIntervalSec: Int?
    /// Per-signal weight/confidence overrides keyed by signal name.
    public let detectionTuning: [String: SignalTuning]
    /// Extra filesystem paths for iOS jailbreak detection modules.
    public let additionalJailbreakPaths: [String]
    /// When true, invokes `ptrace(PT_DENY_ATTACH)` during debugger scans (not App Store safe by default).
    public let enablePtraceDenyAttach: Bool
    /// Personalized native prologue baselines for hook detection.
    public let hookPrologueBaselines: [HookPrologueBaseline]
    /// Personalized ObjC method IMP baselines for swizzle detection.
    public let hookSwizzleBaselines: [HookSwizzleBaseline]
    /// Build-time SHA-256 digests for bundle resources (path relative to .app root).
    public let expectedResourceHashes: [String: String]

    public init(
        detectOnly: Bool = true,
        expectedSigners: [String] = [],
        terminationPolicy: TerminationPolicy = .none,
        thresholds: [ThreatType: ThreatThreshold] = DefaultThreatThresholds.map,
        allowDeveloperSignals: Bool = true,
        expectedPackageId: String? = nil,
        periodicIntervalSec: Int? = nil,
        detectionTuning: [String: SignalTuning] = [:],
        additionalJailbreakPaths: [String] = [],
        enablePtraceDenyAttach: Bool = false,
        hookPrologueBaselines: [HookPrologueBaseline] = [],
        hookSwizzleBaselines: [HookSwizzleBaseline] = [],
        expectedResourceHashes: [String: String] = [:]
    ) {
        self = try! Self.make(
            detectOnly: detectOnly,
            expectedSigners: expectedSigners,
            terminationPolicy: terminationPolicy,
            thresholds: thresholds,
            allowDeveloperSignals: allowDeveloperSignals,
            expectedPackageId: expectedPackageId,
            periodicIntervalSec: periodicIntervalSec,
            detectionTuning: detectionTuning,
            additionalJailbreakPaths: additionalJailbreakPaths,
            enablePtraceDenyAttach: enablePtraceDenyAttach,
            hookPrologueBaselines: hookPrologueBaselines,
            hookSwizzleBaselines: hookSwizzleBaselines,
            expectedResourceHashes: expectedResourceHashes
        )
    }

    public static func make(
        detectOnly: Bool = true,
        expectedSigners: [String] = [],
        terminationPolicy: TerminationPolicy = .none,
        thresholds: [ThreatType: ThreatThreshold] = DefaultThreatThresholds.map,
        allowDeveloperSignals: Bool = true,
        expectedPackageId: String? = nil,
        periodicIntervalSec: Int? = nil,
        detectionTuning: [String: SignalTuning] = [:],
        additionalJailbreakPaths: [String] = [],
        enablePtraceDenyAttach: Bool = false,
        hookPrologueBaselines: [HookPrologueBaseline] = [],
        hookSwizzleBaselines: [HookSwizzleBaseline] = [],
        expectedResourceHashes: [String: String] = [:]
    ) throws -> MobShieldConfig {
        try validateSigners(expectedSigners)
        try validateResourceHashes(expectedResourceHashes)
        if let periodicIntervalSec, periodicIntervalSec <= 0 {
            throw MobShieldConfigError.invalidPeriodicInterval
        }
        if let expectedPackageId, expectedPackageId.isEmpty {
            throw MobShieldConfigError.blankPackageId
        }
        if detectOnly, terminationPolicy != .none {
            throw MobShieldConfigError.detectOnlyRequiresNoTermination
        }
        return MobShieldConfig(
            detectOnly: detectOnly,
            expectedSigners: expectedSigners,
            terminationPolicy: terminationPolicy,
            thresholds: thresholds,
            allowDeveloperSignals: allowDeveloperSignals,
            expectedPackageId: expectedPackageId,
            periodicIntervalSec: periodicIntervalSec,
            detectionTuning: detectionTuning,
            additionalJailbreakPaths: additionalJailbreakPaths,
            enablePtraceDenyAttach: enablePtraceDenyAttach,
            hookPrologueBaselines: hookPrologueBaselines,
            hookSwizzleBaselines: hookSwizzleBaselines,
            expectedResourceHashes: expectedResourceHashes,
            skipValidation: true
        )
    }

    private init(
        detectOnly: Bool,
        expectedSigners: [String],
        terminationPolicy: TerminationPolicy,
        thresholds: [ThreatType: ThreatThreshold],
        allowDeveloperSignals: Bool,
        expectedPackageId: String?,
        periodicIntervalSec: Int?,
        detectionTuning: [String: SignalTuning],
        additionalJailbreakPaths: [String],
        enablePtraceDenyAttach: Bool,
        hookPrologueBaselines: [HookPrologueBaseline],
        hookSwizzleBaselines: [HookSwizzleBaseline],
        expectedResourceHashes: [String: String],
        skipValidation: Bool
    ) {
        _ = skipValidation
        self.detectOnly = detectOnly
        self.expectedSigners = expectedSigners
        self.terminationPolicy = terminationPolicy
        self.thresholds = thresholds
        self.allowDeveloperSignals = allowDeveloperSignals
        self.expectedPackageId = expectedPackageId
        self.periodicIntervalSec = periodicIntervalSec
        self.detectionTuning = detectionTuning
        self.additionalJailbreakPaths = additionalJailbreakPaths
        self.enablePtraceDenyAttach = enablePtraceDenyAttach
        self.hookPrologueBaselines = hookPrologueBaselines
        self.hookSwizzleBaselines = hookSwizzleBaselines
        self.expectedResourceHashes = expectedResourceHashes
    }

    public static func validateResourceHashes(_ hashes: [String: String]) throws {
        for (path, digest) in hashes {
            if path.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                throw MobShieldConfigError.invalidSigner("expectedResourceHashes path must not be blank")
            }
            try validateSha256Hex(field: "expectedResourceHashes[\(path)]", value: digest)
        }
    }

    public static func validateSigners(_ signers: [String]) throws {
        for signer in signers {
            try validateSha256Hex(field: "expectedSigners", value: signer)
        }
    }

    public static func validateSha256Hex(field: String, value: String) throws {
        let pattern = try NSRegularExpression(pattern: "^[0-9a-fA-F]{64}$")
        let range = NSRange(value.startIndex..<value.endIndex, in: value)
        let matches = pattern.firstMatch(in: value, range: range) != nil
        if !matches {
            throw MobShieldConfigError.invalidSigner("\(field) must be 64-char SHA-256 hex: \(value)")
        }
    }
}

public extension MobShieldConfig {
    struct Builder: Sendable {
        private var detectOnly = true
        private var expectedSigners: [String] = []
        private var terminationPolicy: TerminationPolicy = .none
        private var thresholds = DefaultThreatThresholds.map
        private var allowDeveloperSignals = true
        private var expectedPackageId: String?
        private var periodicIntervalSec: Int?
        private var detectionTuning: [String: SignalTuning] = [:]
        private var additionalJailbreakPaths: [String] = []
        private var enablePtraceDenyAttach = false
        private var hookPrologueBaselines: [HookPrologueBaseline] = []
        private var hookSwizzleBaselines: [HookSwizzleBaseline] = []
        private var expectedResourceHashes: [String: String] = [:]

        public init() {}

        public func detectOnly(_ value: Bool) -> Builder {
            var copy = self
            copy.detectOnly = value
            return copy
        }

        public func expectedSigners(_ value: [String]) -> Builder {
            var copy = self
            copy.expectedSigners = value
            return copy
        }

        public func terminationPolicy(_ value: TerminationPolicy) -> Builder {
            var copy = self
            copy.terminationPolicy = value
            return copy
        }

        public func thresholds(_ value: [ThreatType: ThreatThreshold]) -> Builder {
            var copy = self
            copy.thresholds = value
            return copy
        }

        public func allowDeveloperSignals(_ value: Bool) -> Builder {
            var copy = self
            copy.allowDeveloperSignals = value
            return copy
        }

        public func expectedPackageId(_ value: String?) -> Builder {
            var copy = self
            copy.expectedPackageId = value
            return copy
        }

        public func periodicIntervalSec(_ value: Int?) -> Builder {
            var copy = self
            copy.periodicIntervalSec = value
            return copy
        }

        public func detectionTuning(_ value: [String: SignalTuning]) -> Builder {
            var copy = self
            copy.detectionTuning = value
            return copy
        }

        public func additionalJailbreakPaths(_ value: [String]) -> Builder {
            var copy = self
            copy.additionalJailbreakPaths = value
            return copy
        }

        public func enablePtraceDenyAttach(_ value: Bool) -> Builder {
            var copy = self
            copy.enablePtraceDenyAttach = value
            return copy
        }

        public func hookPrologueBaselines(_ value: [HookPrologueBaseline]) -> Builder {
            var copy = self
            copy.hookPrologueBaselines = value
            return copy
        }

        public func hookSwizzleBaselines(_ value: [HookSwizzleBaseline]) -> Builder {
            var copy = self
            copy.hookSwizzleBaselines = value
            return copy
        }

        public func expectedResourceHashes(_ value: [String: String]) -> Builder {
            var copy = self
            copy.expectedResourceHashes = value
            return copy
        }

        public func build() throws -> MobShieldConfig {
            try MobShieldConfig.make(
                detectOnly: detectOnly,
                expectedSigners: expectedSigners,
                terminationPolicy: terminationPolicy,
                thresholds: thresholds,
                allowDeveloperSignals: allowDeveloperSignals,
                expectedPackageId: expectedPackageId,
                periodicIntervalSec: periodicIntervalSec,
                detectionTuning: detectionTuning,
                additionalJailbreakPaths: additionalJailbreakPaths,
                enablePtraceDenyAttach: enablePtraceDenyAttach,
                hookPrologueBaselines: hookPrologueBaselines,
                hookSwizzleBaselines: hookSwizzleBaselines,
                expectedResourceHashes: expectedResourceHashes
            )
        }
    }

    static func builder() -> Builder {
        Builder()
    }
}
