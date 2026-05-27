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

/// Expected native function prologue bytes for a symbol (personalization plugin may override).
public struct HookPrologueBaseline: Equatable, Sendable {
    public let symbolName: String
    /// Up to 16 bytes encoded as hex (32 characters). Empty means trampoline heuristic only.
    public let expectedBytesHex: String

    public init(symbolName: String, expectedBytesHex: String = "") {
        self.symbolName = symbolName
        self.expectedBytesHex = expectedBytesHex
    }
}

/// Expected Objective-C method implementation for swizzle detection.
public struct HookSwizzleBaseline: Equatable, Sendable {
    public let className: String
    public let selector: String
    /// Optional IMP pointer as hex (16 characters on 64-bit). Empty uses superclass comparison.
    public let expectedImplementationHex: String

    public init(className: String, selector: String, expectedImplementationHex: String = "") {
        self.className = className
        self.selector = selector
        self.expectedImplementationHex = expectedImplementationHex
    }
}
