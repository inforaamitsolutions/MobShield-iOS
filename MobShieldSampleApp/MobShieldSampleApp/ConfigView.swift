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

import SwiftUI

struct ConfigView: View {
    @ObservedObject var model: SampleViewModel

    var body: some View {
        NavigationView {
            Form {
                Section("Response policy") {
                    Toggle("Detect-only (no termination)", isOn: $model.prefs.detectOnly)
                        .onChange(of: model.prefs.detectOnly) { _ in model.applyConfigIfRunning() }
                    Toggle("Allow developer signals", isOn: $model.prefs.allowDeveloperSignals)
                        .onChange(of: model.prefs.allowDeveloperSignals) { _ in model.applyConfigIfRunning() }
                    Toggle("Ptrace deny attach (aggressive)", isOn: $model.prefs.enablePtraceDenyAttach)
                        .onChange(of: model.prefs.enablePtraceDenyAttach) { _ in model.applyConfigIfRunning() }
                    Text("Build-time aggressive mode is set via MOBSHIELD_AGGRESSIVE_ANTI_DEBUG in the personalize Run Script phase.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section("Detection modules") {
                    ForEach(SampleModuleId.allCases) { module in
                        Toggle(
                            module.label,
                            isOn: Binding(
                                get: { model.prefs.enabledModules.contains(module) },
                                set: { enabled in
                                    if enabled {
                                        model.prefs.enabledModules.insert(module)
                                    } else {
                                        model.prefs.enabledModules.remove(module)
                                    }
                                    model.applyConfigIfRunning()
                                }
                            )
                        )
                    }
                }
            }
            .navigationTitle("Configuration")
        }
        .navigationViewStyle(.stack)
    }
}
