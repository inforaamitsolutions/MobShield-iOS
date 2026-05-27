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

import MobShieldCore
import SwiftUI

struct HomeView: View {
    @ObservedObject var model: SampleViewModel

    var body: some View {
        NavigationView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Risk \(model.posture.riskLevel.rawValue) | Running \(model.posture.running)")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                HStack {
                    Button("Start") { model.startMobShield() }
                        .buttonStyle(.borderedProminent)
                    Button("Stop") { model.stopMobShield() }
                        .buttonStyle(.bordered)
                    Button("Rescan") { model.rescan() }
                        .buttonStyle(.bordered)
                    Button("Clear") { model.clearThreats() }
                        .buttonStyle(.bordered)
                }

                if model.threats.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "shield")
                            .font(.largeTitle)
                            .foregroundStyle(.secondary)
                        Text("No threats")
                            .font(.headline)
                        Text("Start MobShield to run enabled detection modules.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List(model.threats) { row in
                        ThreatCard(row: row)
                    }
                    .listStyle(.plain)
                }
            }
            .padding()
            .navigationTitle("Threat events")
        }
        .navigationViewStyle(.stack)
    }
}

private struct ThreatCard: View {
    let row: ThreatRow

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(row.typeLabel).font(.headline)
                Spacer()
                Text(row.severity.rawValue)
                    .font(.caption)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(severityColor.opacity(0.2))
                    .foregroundStyle(severityColor)
                    .clipShape(Capsule())
            }
            Text("Score \(row.score)")
            Text(row.signalsSummary)
                .font(.caption)
                .foregroundStyle(.secondary)
            if !row.metadataSummary.isEmpty {
                Text(row.metadataSummary)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }

    private var severityColor: Color {
        switch row.severity {
        case .info: return .gray
        case .low: return .blue
        case .medium: return .yellow
        case .high: return .orange
        case .critical: return .red
        }
    }
}
