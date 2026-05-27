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

/// Thread-safe registry of ``DetectionModule`` instances.
public actor ModuleRegistry {
    public static let shared = ModuleRegistry()

    private var modules: [any DetectionModule] = []

    private init() {}

    public func register(_ module: any DetectionModule) {
        precondition(!module.name.isEmpty, "module name must not be blank")
        modules.removeAll { $0.name == module.name }
        modules.append(module)
    }

    public func getAll() -> [any DetectionModule] {
        modules.sorted { $0.criticality > $1.criticality }
    }

    public func clear() {
        modules.removeAll()
    }
}
