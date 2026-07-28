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
            signalSetVersion: MobShield.signalSetVersion,
            selfCheck: { 1 }
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
            signalSetVersion: MobShield.signalSetVersion,
            selfCheck: { 1 }
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
            periodicIntervalOverrideNanos: 30_000_000,
            selfCheck: { 1 }
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

    // MARK: - Termination policy

    func testShouldTerminate_matrix() {
        let critical = [event(.critical)]
        let high = [event(.high)]
        let medium = [event(.medium)]

        // .none never terminates.
        XCTAssertFalse(MobShieldEngine.shouldTerminate(events: critical, detectOnly: false, policy: .none))

        // detectOnly overrides any policy (defense-in-depth alongside config validation).
        XCTAssertFalse(MobShieldEngine.shouldTerminate(events: critical, detectOnly: true, policy: .exitOnCritical))

        // .exitOnCritical fires only at critical.
        XCTAssertTrue(MobShieldEngine.shouldTerminate(events: critical, detectOnly: false, policy: .exitOnCritical))
        XCTAssertFalse(MobShieldEngine.shouldTerminate(events: high, detectOnly: false, policy: .exitOnCritical))

        // .exitOnBypass fires at high or above.
        XCTAssertTrue(MobShieldEngine.shouldTerminate(events: high, detectOnly: false, policy: .exitOnBypass))
        XCTAssertTrue(MobShieldEngine.shouldTerminate(events: critical, detectOnly: false, policy: .exitOnBypass))
        XCTAssertFalse(MobShieldEngine.shouldTerminate(events: medium, detectOnly: false, policy: .exitOnBypass))

        // No events → never terminate.
        XCTAssertFalse(MobShieldEngine.shouldTerminate(events: [], detectOnly: false, policy: .exitOnBypass))
    }

    func testEngine_exitOnCritical_terminatesOnCriticalThreat() async {
        await ModuleRegistry.shared.register(MockDetectionModule(weight: 90, confidence: 100))
        let config = try! MobShieldConfig.make(detectOnly: false, terminationPolicy: .exitOnCritical)
        let terminated = expectation(description: "terminate invoked")
        let engine = makeEngine(config: config, terminate: { terminated.fulfill() })

        engine.start()
        await fulfillment(of: [terminated], timeout: 1.0)
        engine.stop()
    }

    func testEngine_exitOnBypass_terminatesOnHighSeverity() async {
        // weight 50 * confidence 100% → score 50 → HIGH for privilegedAccess (warning 40, critical 70).
        await ModuleRegistry.shared.register(MockDetectionModule(weight: 50, confidence: 100))
        let config = try! MobShieldConfig.make(detectOnly: false, terminationPolicy: .exitOnBypass)
        let terminated = expectation(description: "terminate invoked")
        let engine = makeEngine(config: config, terminate: { terminated.fulfill() })

        engine.start()
        await fulfillment(of: [terminated], timeout: 1.0)
        engine.stop()
    }

    func testEngine_exitOnCritical_ignoresHighSeverity() async {
        await ModuleRegistry.shared.register(MockDetectionModule(weight: 50, confidence: 100)) // HIGH only
        let config = try! MobShieldConfig.make(detectOnly: false, terminationPolicy: .exitOnCritical)
        let notTerminated = expectation(description: "terminate must not fire on HIGH")
        notTerminated.isInverted = true
        let engine = makeEngine(config: config, terminate: { notTerminated.fulfill() })

        engine.start()
        await fulfillment(of: [notTerminated], timeout: 0.3)
        engine.stop()
    }

    func testEngine_detectOnlyDefault_neverTerminates() async {
        await ModuleRegistry.shared.register(MockDetectionModule(weight: 90, confidence: 100)) // CRITICAL
        let notTerminated = expectation(description: "detect-only must not terminate")
        notTerminated.isInverted = true
        let engine = makeEngine(config: MobShieldConfig(), terminate: { notTerminated.fulfill() })

        engine.start()
        await fulfillment(of: [notTerminated], timeout: 0.3)
        engine.stop()
    }

    // MARK: - Native self-check integrity

    func testEngine_nativeSelfCheckFailure_emitsCriticalIntegrityThreat() async {
        // No modules registered: the self-check must run on its own.
        let listener = RecordingListener()
        let engine = MobShieldEngine(
            config: MobShieldConfig(),
            listener: listener,
            resolveModules: {
                await ModuleRegistry.shared.getAll()
            },
            signalSetVersion: MobShield.signalSetVersion,
            selfCheck: { 0 } // unhealthy / tampered native core
        )

        engine.start()
        try? await Task.sleep(nanoseconds: 200_000_000)

        XCTAssertEqual(1, listener.threatCount)
        XCTAssertEqual(.appIntegrity, listener.firstThreat?.type)
        XCTAssertEqual(.critical, listener.firstThreat?.severity)
        XCTAssertTrue(engine.getState().activeThreats.contains(.appIntegrity))
        engine.stop()
    }

    func testEngine_healthySelfCheck_emitsNoIntegritySignal() async {
        let listener = RecordingListener()
        let engine = MobShieldEngine(
            config: MobShieldConfig(),
            listener: listener,
            resolveModules: {
                await ModuleRegistry.shared.getAll()
            },
            signalSetVersion: MobShield.signalSetVersion,
            selfCheck: { 0x4D534844 } // healthy magic
        )

        engine.start()
        try? await Task.sleep(nanoseconds: 200_000_000)

        XCTAssertEqual(0, listener.threatCount)
        XCTAssertEqual(1, listener.finishedCount)
        engine.stop()
    }

    func testEngine_selfCheckFailure_withExitOnCritical_terminates() async {
        let config = try! MobShieldConfig.make(detectOnly: false, terminationPolicy: .exitOnCritical)
        let terminated = expectation(description: "terminate invoked on tampered core")
        let engine = MobShieldEngine(
            config: config,
            listener: RecordingListener(),
            resolveModules: {
                await ModuleRegistry.shared.getAll()
            },
            signalSetVersion: MobShield.signalSetVersion,
            terminate: { terminated.fulfill() },
            selfCheck: { 0 }
        )

        engine.start()
        await fulfillment(of: [terminated], timeout: 1.0)
        engine.stop()
    }

    // MARK: - Listener retention

    func testEngine_retainsListener_whenCallerDropsReference() async {
        await ModuleRegistry.shared.register(MockDetectionModule(weight: 90, confidence: 100))

        weak var weakListener: RecordingListener?
        // Build the engine in a nested scope so the only strong reference to the listener
        // is the one the engine holds. Under the old `weak` field this would deallocate
        // immediately and callbacks would silently stop.
        func buildEngine() -> MobShieldEngine {
            let listener = RecordingListener()
            weakListener = listener
            return MobShieldEngine(
                config: MobShieldConfig(),
                listener: listener,
                resolveModules: {
                    await ModuleRegistry.shared.getAll()
                },
                signalSetVersion: MobShield.signalSetVersion,
                selfCheck: { 1 }
            )
        }
        let engine = buildEngine()

        XCTAssertNotNil(weakListener, "engine must retain the listener strongly")

        engine.start()
        try? await Task.sleep(nanoseconds: 200_000_000)

        XCTAssertNotNil(weakListener, "listener must stay alive while the engine runs")
        XCTAssertEqual(1, weakListener?.finishedCount, "callbacks must still be delivered")
        engine.stop()
    }

    // MARK: - Helpers

    private func makeEngine(
        config: MobShieldConfig,
        terminate: @escaping @Sendable () -> Void,
        selfCheck: @escaping @Sendable () -> Int = { 1 }
    ) -> MobShieldEngine {
        MobShieldEngine(
            config: config,
            listener: RecordingListener(),
            resolveModules: {
                await ModuleRegistry.shared.getAll()
            },
            signalSetVersion: MobShield.signalSetVersion,
            terminate: terminate,
            selfCheck: selfCheck
        )
    }

    private func event(_ severity: Severity) -> ThreatEvent {
        ThreatEvent.create(
            type: .privilegedAccess,
            severity: severity,
            signals: ["mock"],
            score: 50,
            timestampMs: 0
        )
    }

    private struct MockDetectionModule: DetectionModule {
        let name = "mock-root"
        let criticality = 10
        var weight = 90
        var confidence = 100

        func scan() async -> [Signal] {
            [
                Signal(
                    name: "android.root.mock",
                    weight: weight,
                    confidence: confidence
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

        var firstThreat: ThreatEvent? {
            lock.lock(); defer { lock.unlock() }
            return threats.first
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
