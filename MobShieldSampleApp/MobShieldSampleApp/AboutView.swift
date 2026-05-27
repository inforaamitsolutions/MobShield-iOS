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

struct AboutView: View {
    @ObservedObject var model: SampleViewModel

    var body: some View {
        NavigationView {
            List {
                Section("SDK") {
                    HStack { Text("Version"); Spacer(); Text(model.sdkVersion) }
                    HStack { Text("Build entropy"); Spacer(); Text(model.buildEntropyPreview) }
                    HStack { Text("Native self-check"); Spacer(); Text(String(model.nativeSelfCheck)) }
                    Text("Personalized native binaries are not reproducible across builds.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section("MASVS-RESILIENCE coverage") {
                    ForEach(model.masvsRows) { row in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(row.control).font(.system(.caption, design: .monospaced))
                            Text(row.title)
                            Text("Coverage: \(row.coverage)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 4)
                    }
                }
            }
            .navigationTitle("About")
        }
        .navigationViewStyle(.stack)
    }
}
