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

        XCTAssertEqual(1, listener.threatCount)
        XCTAssertEqual(.privilegedAccess, listener.firstThreatType)
        XCTAssertEqual(1, listener.finishedCount)
        XCTAssertTrue(engine.getState().running)
        XCTAssertTrue(engine.getState().activeThreats.contains(.privilegedAccess))
        XCTAssertEqual(1, engine.getLastEvents().count)

        engine.stop()
    }

    func testEngine_withoutInterval_runsSingleWave() async {
        await ModuleRegistry.shared.register(MockDetectionModule())
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
        try? await Task.sleep(nanoseconds: 250_000_000)

        XCTAssertEqual(1, listener.finishedCount)
        engine.stop()
    }

    func testEngine_periodicInterval_rescansUntilStopped() async {
        await ModuleRegistry.shared.register(MockDetectionModule())
        let listener = RecordingListener()
        let engine = MobShieldEngine(
            config: MobShieldConfig(),
            listener: listener,
            resolveModules: {
                await ModuleRegistry.shared.getAll()
            },
            signalSetVersion: MobShield.signalSetVersion,
            periodicIntervalOverrideNanos: 30_000_000
        )

        engine.start()
        try? await Task.sleep(nanoseconds: 250_000_000)
        engine.stop()

        let wavesAtStop = listener.finishedCount
        XCTAssertGreaterThanOrEqual(wavesAtStop, 2, "periodic interval should trigger repeated scan waves")

        // No further waves should fire once stopped.
        try? await Task.sleep(nanoseconds: 150_000_000)
        XCTAssertEqual(wavesAtStop, listener.finishedCount, "stop() must halt the periodic loop")
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

    private final class RecordingListener: MobShieldListener, @unchecked Sendable {
        private let lock = NSLock()
        private var threats: [ThreatEvent] = []
        private var finished: [[ThreatEvent]] = []

        var threatCount: Int {
            lock.lock(); defer { lock.unlock() }
            return threats.count
        }

        var firstThreatType: ThreatType? {
            lock.lock(); defer { lock.unlock() }
            return threats.first?.type
        }

        var finishedCount: Int {
            lock.lock(); defer { lock.unlock() }
            return finished.count
        }

        func onThreat(_ event: ThreatEvent) {
            lock.lock(); defer { lock.unlock() }
            threats.append(event)
        }

        func onAllChecksFinished(_ events: [ThreatEvent]) {
            lock.lock(); defer { lock.unlock() }
            finished.append(events)
        }
    }
}
