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

/// Merges built-in and config-supplied jailbreak filesystem paths.
public struct ConfigurableSuspiciousPaths: Sendable {
    #if targetEnvironment(simulator)
    public static let builtInPaths: [String] = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/var/jb/Applications/Sileo.app",
        "/.installed_unc0ver",
    ]
    #else
    public static let builtInPaths: [String] = [
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate",
        "/bin/bash",
        "/etc/apt",
        "/private/var/lib/apt",
        "/Applications/Sileo.app",
        "/var/jb",
        "/var/jb/usr",
        "/var/jb/Library",
        "/var/jb/Applications/Sileo.app",
    ]
    #endif

    private let additionalPaths: [String]

    public init(config: MobShieldConfig = MobShieldConfig()) {
        additionalPaths = config.additionalJailbreakPaths
    }

    public init(additionalPaths: [String]) {
        self.additionalPaths = additionalPaths
    }

    public func allPaths() -> [String] {
        var seen = Set<String>()
        var merged: [String] = []
        for path in Self.builtInPaths + additionalPaths {
            let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty || seen.contains(trimmed) {
                continue
            }
            seen.insert(trimmed)
            merged.append(trimmed)
        }
        return merged
    }
}
