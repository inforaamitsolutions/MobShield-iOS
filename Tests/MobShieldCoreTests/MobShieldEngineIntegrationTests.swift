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

final class MobShieldEngineIntegrationTests: XCTestCase {
    override func tearDown() async throws {
        await MobShield.shared.resetForTests()
    }

    func testEngine_runsModuleScan_andDeliversCallbacks() async {
        let mockModule = MockDetectionModule()
        await ModuleRegistry.shared.register(mockModule)
        let listener = RecordingListener()
        let engine = MobShieldEngine(
            config: MobShieldConfig(),
            listener: listener,
            resolveModules: {
                await ModuleRegistry.shared.getAll()
            },
            signalSetVersion: MobShield.signalSetVersion
        )

        engine.start()
        try? await Task.sleep(nanoseconds: 200_000_000)

        XCTAssertEqual(1, listener.threats.count)
        XCTAssertEqual(.privilegedAccess, listener.threats[0].type)
        XCTAssertEqual(1, listener.finished.count)
        XCTAssertTrue(engine.getState().running)
        XCTAssertTrue(engine.getState().activeThreats.contains(.privilegedAccess))
        XCTAssertEqual(1, engine.getLastEvents().count)

        engine.stop()
    }

    private struct MockDetectionModule: DetectionModule {
        let name = "mock-root"
        let criticality = 10

        func scan() async -> [Signal] {
            [
                Signal(
                    name: "android.root.mock",
                    weight: 90,
                    confidence: 100
                ),
            ]
        }
    }

    private final class RecordingListener: MobShieldListener {
        var threats: [ThreatEvent] = []
        var finished: [[ThreatEvent]] = []

        func onThreat(_ event: ThreatEvent) {
            threats.append(event)
        }

        func onAllChecksFinished(_ events: [ThreatEvent]) {
            finished.append(events)
        }
    }
}
