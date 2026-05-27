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
import MobShieldDetectDebugger
import XCTest

/// Under XCTest/Xcode the process is often traced; DEBUGGER events may be present.
final class DebuggerSimulatorIntegrationTests: XCTestCase {
    func testNativeModule_onSimulator_mayEmitDebuggerWhenTraced() async {
        let module = DebuggerDetectionModule(config: MobShieldConfig())
        let signals = await module.scan()
        let events = SignalAggregator(config: MobShieldConfig()).aggregate(signals: signals)
        if events.contains(where: { $0.type == .debugger }) {
            let debugSignals = Set([
                DebugSignalDefaults.sysctlTraced,
                DebugSignalDefaults.machException,
                DebugSignalDefaults.timing,
            ])
            XCTAssertTrue(
                signals.contains { debugSignals.contains($0.name) },
                "DEBUGGER event should map to a known ios.debug.* signal"
            )
        }
    }
}
