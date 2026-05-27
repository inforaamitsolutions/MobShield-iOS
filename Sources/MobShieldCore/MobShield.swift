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

import Foundation

/// Public entry point for MobShield on iOS.
public final class MobShield: @unchecked Sendable {
    public static let shared = MobShield()

    public static let signalSetVersion = "signals-2026.05.0"

    private let lock = NSLock()
    private var engine: MobShieldEngine?

    private init() {}

    /// Starts MobShield: loads native core, schedules registered ``DetectionModule`` scans,
    /// and delivers callbacks on the listener.
    public func start(config: MobShieldConfig, listener: MobShieldListener) {
        NativeBridge.ensureLoaded()
        stop()
        let newEngine = MobShieldEngine(
            config: config,
            listener: listener,
            resolveModules: {
                await ModuleRegistry.shared.getAll()
            },
            signalSetVersion: Self.signalSetVersion
        )
        lock.lock()
        engine = newEngine
        lock.unlock()
        newEngine.start()
    }

    /// Stops active scans and resets runtime state.
    public func stop() {
        lock.lock()
        let active = engine
        engine = nil
        lock.unlock()
        active?.stop()
    }

    /// Returns the latest posture snapshot.
    public func getState() -> MobShieldState {
        lock.lock()
        let active = engine
        lock.unlock()
        return active?.getState()
            ?? MobShieldState(
                riskLevel: .none,
                activeThreats: [],
                lastScanMs: 0,
                signalSetVersion: Self.signalSetVersion,
                running: false
            )
    }

    /// Returns events from the most recent completed scan wave.
    public func getLastEvents() -> [ThreatEvent] {
        lock.lock()
        let active = engine
        lock.unlock()
        return active?.getLastEvents() ?? []
    }

    /// Native and API version string.
    public static func getVersion() -> String {
        NativeBridge.getVersion()
    }

    /// Native build identifier injected at compile time.
    public static func getBuildId() -> String {
        NativeBridge.getBuildId()
    }

    /// Native integrity self-check; nonzero indicates a healthy core.
    public static func selfCheck() -> Int {
        NativeBridge.selfCheck()
    }

    /// Clears runtime state for unit tests.
    public func resetForTests() async {
        stop()
        await ModuleRegistry.shared.clear()
    }
}
