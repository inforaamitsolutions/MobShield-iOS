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

enum NativeBridge {
    private static let lock = NSLock()
    private static var loaded = false

    static func ensureLoaded() {
        lock.lock()
        defer { lock.unlock() }
        guard !loaded else {
            return
        }
        _ = mobshield_native_init()
        loaded = true
    }

    static func getVersion() -> String {
        ensureLoaded()
        return readString(maxLength: 64) { out, len in
            mobshield_native_get_version(out, len)
        } ?? "0.0.0"
    }

    static func getBuildId() -> String {
        ensureLoaded()
        return readString(maxLength: 128) { out, len in
            mobshield_native_get_build_id(out, len)
        } ?? "unknown"
    }

    static func selfCheck() -> Int {
        ensureLoaded()
        return Int(mobshield_native_self_check())
    }

    private static func readString(
        maxLength: Int,
        block: (UnsafeMutablePointer<CChar>, Int32) -> Int32
    ) -> String? {
        var buffer = [CChar](repeating: 0, count: maxLength)
        let written = buffer.withUnsafeMutableBufferPointer { pointer in
            guard let base = pointer.baseAddress else {
                return Int32(-1)
            }
            return block(base, Int32(maxLength))
        }
        guard written >= 0 else {
            return nil
        }
        return String(cString: buffer)
    }
}

// Link via MobShieldCoreNative target; avoid `import MobShieldCoreNative` so app targets
// (CocoaPods + local SPM) do not need the Clang module on the import MobShieldCore path.
@_silgen_name("mobshield_native_init")
private func mobshield_native_init() -> Int32

@_silgen_name("mobshield_native_get_build_id")
private func mobshield_native_get_build_id(_ out: UnsafeMutablePointer<CChar>?, _ out_len: Int32) -> Int32

@_silgen_name("mobshield_native_get_version")
private func mobshield_native_get_version(_ out: UnsafeMutablePointer<CChar>?, _ out_len: Int32) -> Int32

@_silgen_name("mobshield_native_self_check")
private func mobshield_native_self_check() -> Int32
