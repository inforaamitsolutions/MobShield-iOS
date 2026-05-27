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

struct DiagnosticsView: View {
    @ObservedObject var model: SampleViewModel

    var body: some View {
        NavigationView {
            VStack(spacing: 12) {
                Text("Raw signals from enabled modules (pre-aggregation).")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)

                Button("Refresh signals") {
                    model.refreshDiagnostics()
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.diagnosticsLoading)

                if model.diagnosticsLoading {
                    ProgressView()
                } else if model.signals.isEmpty {
                    Text("Tap Refresh to run module scans.")
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List(model.signals) { row in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(row.name).font(.system(.body, design: .monospaced))
                            Text("weight \(row.weight) | confidence \(row.confidence)")
                            Text(row.evidenceSummary)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .listStyle(.plain)
                }
            }
            .padding()
            .navigationTitle("Signal diagnostics")
        }
        .navigationViewStyle(.stack)
    }
}
