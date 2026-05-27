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

/// Atomic weighted observation from a single detection probe.
public struct Signal: Equatable, Sendable {
    /// Stable dot-notation identifier (for example `ios.jb.dyld_image`).
    public let name: String
    /// Importance if the condition holds, in range 0...100.
    public let weight: Int
    /// Detector certainty in range 0...100.
    public let confidence: Int
    /// Optional non-PII diagnostic key-value pairs.
    public let evidence: [String: String]
    /// Epoch milliseconds when the signal was produced.
    public let timestampMs: Int64

    public init(
        name: String,
        weight: Int,
        confidence: Int,
        evidence: [String: String] = [:],
        timestampMs: Int64 = Int64(Date().timeIntervalSince1970 * 1000)
    ) {
        precondition(!name.isEmpty, "signal name must not be blank")
        precondition((0...100).contains(weight), "weight must be in 0...100")
        precondition((0...100).contains(confidence), "confidence must be in 0...100")
        self.name = name
        self.weight = weight
        self.confidence = confidence
        self.evidence = evidence
        self.timestampMs = timestampMs
    }
}
