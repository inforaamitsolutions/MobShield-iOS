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

/// Abstracts the host facts the environment detector reads, so detection is deterministic and
/// testable regardless of where the tests actually run.
public protocol EnvironmentProbing: Sendable {
    /// True when the binary was compiled for the iOS Simulator.
    var isSimulatorBuild: Bool { get }
    /// The current process environment.
    var environment: [String: String] { get }
    /// Whether an Objective-C class with the given name is loaded in the process.
    func isClassAvailable(_ name: String) -> Bool
}

public struct LiveEnvironmentProbe: EnvironmentProbing {
    public init() {}

    public var isSimulatorBuild: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    public var environment: [String: String] {
        ProcessInfo.processInfo.environment
    }

    public func isClassAvailable(_ name: String) -> Bool {
        NSClassFromString(name) != nil
    }
}
