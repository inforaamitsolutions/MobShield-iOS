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

import XCTest
@testable import MobShieldCore

final class MobShieldValidationTests: XCTestCase {
    override func tearDown() async throws {
        await MobShield.shared.resetForTests()
    }

    func testRun_capturesPerModuleSignals_inCriticalityOrder() async {
        let report = await MobShieldValidation.run(
            modules: [
                StubModule(name: "debugger", criticality: 80, signals: [signal("ios.debug.timing", 55, 65)]),
                StubModule(name: "jailbreak", criticality: 90, signals: [signal("ios.jb.fs_probe", 85, 90)]),
            ]
        )

        // Highest criticality first, regardless of input order.
        XCTAssertEqual(["jailbreak", "debugger"], report.modules.map(\.moduleName))
        XCTAssertEqual(90, report.modules.first?.criticality)
        XCTAssertTrue(report.modules.allSatisfy(\.didFire))
        XCTAssertEqual(["ios.jb.fs_probe", "ios.debug.timing"], report.rawSignals.map(\.name))
    }

    func testRun_aggregatesSignalsIntoThreatEvents() async {
        let report = await MobShieldValidation.run(
            modules: [
                StubModule(name: "jailbreak", criticality: 90, signals: [signal("ios.jb.fs_probe", 85, 90)]),
                StubModule(name: "hooks", criticality: 85, signals: [signal("common.hook.prologue", 80, 90)]),
            ]
        )

        XCTAssertEqual(Set([.privilegedAccess, .hookFramework]), report.activeThreatTypes)
        XCTAssertEqual(.critical, report.highestSeverity) // fs_probe 85*0.90 = 76 ≥ privilegedAccess critical (70)
        XCTAssertTrue(report.firedSignalNames.contains("ios.jb.fs_probe"))
        XCTAssertTrue(report.firedSignalNames.contains("common.hook.prologue"))
    }

    func testRun_moduleThatEmitsNothing_doesNotFire() async {
        let report = await MobShieldValidation.run(
            modules: [StubModule(name: "jailbreak", criticality: 90, signals: [])]
        )

        XCTAssertEqual(1, report.modules.count)
        XCTAssertFalse(report.modules[0].didFire)
        XCTAssertTrue(report.events.isEmpty)
        XCTAssertNil(report.highestSeverity)
        XCTAssertTrue(report.firedSignalNames.isEmpty)
    }

    func testRun_noModules_producesEmptyReport() async {
        let report = await MobShieldValidation.run(modules: [])

        XCTAssertTrue(report.modules.isEmpty)
        XCTAssertTrue(report.events.isEmpty)
        XCTAssertTrue(report.rawSignals.isEmpty)
        XCTAssertNil(report.highestSeverity)
    }

    func testRunRegistered_usesModulesFromRegistry() async {
        await ModuleRegistry.shared.register(
            StubModule(name: "jailbreak", criticality: 90, signals: [signal("ios.jb.fs_probe", 85, 90)])
        )

        let report = await MobShieldValidation.runRegistered()

        XCTAssertEqual(["jailbreak"], report.modules.map(\.moduleName))
        XCTAssertTrue(report.activeThreatTypes.contains(.privilegedAccess))
    }

    func testRun_preservesEvidenceForInspection() async {
        let report = await MobShieldValidation.run(
            modules: [
                StubModule(
                    name: "jailbreak",
                    criticality: 90,
                    signals: [signal("ios.jb.fs_probe", 85, 90, evidence: ["path": "/Applications/Cydia.app"])]
                ),
            ]
        )

        XCTAssertEqual("/Applications/Cydia.app", report.rawSignals.first?.evidence["path"])
    }

    // MARK: - Helpers

    private func signal(
        _ name: String,
        _ weight: Int,
        _ confidence: Int,
        evidence: [String: String] = [:]
    ) -> Signal {
        Signal(name: name, weight: weight, confidence: confidence, evidence: evidence)
    }

    private struct StubModule: DetectionModule {
        let name: String
        let criticality: Int
        let signals: [Signal]

        func scan() async -> [Signal] { signals }
    }
}
