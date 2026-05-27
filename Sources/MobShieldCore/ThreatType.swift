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

/// Normalized threat category aligned with MOBSHIELD_SPEC section C.2.
public enum ThreatType: String, CaseIterable, Sendable {
    case privilegedAccess = "PRIVILEGED_ACCESS"
    case hookFramework = "HOOK_FRAMEWORK"
    case debugger = "DEBUGGER"
    case emulator = "EMULATOR"
    case automation = "AUTOMATION"
    case appIntegrity = "APP_INTEGRITY"
    case developerMode = "DEVELOPER_MODE"
    case adbEnabled = "ADB_ENABLED"
    case unofficialStore = "UNOFFICIAL_STORE"
}
