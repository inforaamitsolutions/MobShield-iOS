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
import UIKit

struct DiagnosticsView: View {
    @ObservedObject var model: SampleViewModel
    @State private var copied = false

    var body: some View {
        NavigationView {
            List {
                validationSection
                rawSignalsSection
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Diagnostics")
        }
        .navigationViewStyle(.stack)
    }

    @ViewBuilder
    private var validationSection: some View {
        Section("Validation") {
            Button {
                copied = false
                model.runValidation()
            } label: {
                Label("Run validation", systemImage: "checkmark.shield")
            }
            .disabled(model.validationLoading)

            if model.validationLoading {
                ProgressView()
            } else if let validation = model.validation {
                summaryRow(validation)
                ForEach(validation.modules) { moduleRow($0) }
                ForEach(validation.threats) { threatRow($0) }
            } else {
                Text("Runs every enabled module and reports which signals fired, then aggregates "
                    + "them into threats. Compare against docs/validation.md.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private func summaryRow(_ validation: ValidationDisplay) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Highest severity: \(validation.highestSeverityLabel)")
                .font(.headline)
            Text("\(validation.firedSignalCount) signal(s) fired · \(validation.threats.count) threat(s)")
                .font(.caption)
                .foregroundStyle(.secondary)
            Button {
                UIPasteboard.general.string = validation.exportText
                copied = true
            } label: {
                Label(copied ? "Copied report" : "Copy report", systemImage: copied ? "checkmark" : "doc.on.doc")
            }
            .font(.callout)
        }
    }

    @ViewBuilder
    private func moduleRow(_ module: ValidationDisplay.Module) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(module.name).font(.system(.body, design: .monospaced))
                Spacer()
                Text(module.didFire ? "FIRED" : "clean")
                    .font(.caption.bold())
                    .foregroundStyle(module.didFire ? .red : .green)
            }
            ForEach(module.signals) { signal in
                Text("• \(signal.name)  (w\(signal.weight)|c\(signal.confidence))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private func threatRow(_ threat: ThreatRow) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(threat.typeLabel) · \(threat.severity.rawValue)")
                .font(.subheadline.bold())
            Text("score \(threat.score) · \(threat.signalsSummary)")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var rawSignalsSection: some View {
        Section("Raw signals (pre-aggregation)") {
            Button {
                model.refreshDiagnostics()
            } label: {
                Label("Refresh raw signals", systemImage: "arrow.clockwise")
            }
            .disabled(model.diagnosticsLoading)

            if model.diagnosticsLoading {
                ProgressView()
            } else {
                ForEach(model.signals) { row in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(row.name).font(.system(.body, design: .monospaced))
                        Text("weight \(row.weight) | confidence \(row.confidence)")
                        Text(row.evidenceSummary)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }
}
