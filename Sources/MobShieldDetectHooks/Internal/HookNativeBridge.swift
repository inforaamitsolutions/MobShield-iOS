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
import MobShieldCore

public struct HookNativeCheckResult: Sendable {
    public let code: Int
    public let evidence: String

    public init(code: Int, evidence: String) {
        self.code = code
        self.evidence = evidence
    }
}

public protocol HookNativeChecking: Sendable {
    static func configureBaselines(
        prologue: [HookPrologueBaseline],
        swizzle: [HookSwizzleBaseline]
    )
    static func machRegionInspect() -> HookNativeCheckResult
    static func functionPrologueInspect() -> HookNativeCheckResult
    static func fridaArtifactScan() -> HookNativeCheckResult
    static func fridaPortProbe() -> HookNativeCheckResult
    static func dyldEnvironmentScan() -> HookNativeCheckResult
    static func methodSwizzleDetect() -> HookNativeCheckResult
}

public enum HookNativeBridge: HookNativeChecking {
    public static let resultOk = 0
    public static let resultDetected = 1
    public static let resultUnavailable = 2

    public static func configureBaselines(
        prologue: [HookPrologueBaseline],
        swizzle: [HookSwizzleBaseline]
    ) {
        configureStringArrays(
            prologue: prologue,
            swizzle: swizzle
        )
    }

    public static func machRegionInspect() -> HookNativeCheckResult {
        runCheck(codeFn: mobshield_hook_mach_region_inspect)
    }

    public static func functionPrologueInspect() -> HookNativeCheckResult {
        runCheck(codeFn: mobshield_hook_function_prologue_inspect)
    }

    public static func fridaArtifactScan() -> HookNativeCheckResult {
        runCheck(codeFn: mobshield_hook_frida_artifact_scan)
    }

    public static func fridaPortProbe() -> HookNativeCheckResult {
        runCheck(codeFn: mobshield_hook_frida_port_probe)
    }

    public static func dyldEnvironmentScan() -> HookNativeCheckResult {
        runCheck(codeFn: mobshield_hook_dyld_environment_scan)
    }

    public static func methodSwizzleDetect() -> HookNativeCheckResult {
        runCheck(codeFn: mobshield_hook_method_swizzle_detect)
    }

    private static func configureStringArrays(
        prologue: [HookPrologueBaseline],
        swizzle: [HookSwizzleBaseline]
    ) {
        if prologue.isEmpty {
            _ = mobshield_hook_set_prologue_from_strings(nil, nil, 0)
        } else {
            prologue.withCStringArrays { symbols, hex in
                _ = mobshield_hook_set_prologue_from_strings(symbols, hex, Int32(prologue.count))
            }
        }

        if swizzle.isEmpty {
            _ = mobshield_hook_set_swizzle_from_strings(nil, nil, nil, 0)
        } else {
            swizzle.withCStringArrays { classes, selectors, imps in
                _ = mobshield_hook_set_swizzle_from_strings(
                    classes,
                    selectors,
                    imps,
                    Int32(swizzle.count)
                )
            }
        }
    }

    private static func runCheck(
        codeFn: @convention(c) (UnsafeMutablePointer<CChar>?, Int32) -> Int32
    ) -> HookNativeCheckResult {
        var buffer = [CChar](repeating: 0, count: 256)
        let code = buffer.withUnsafeMutableBufferPointer { pointer -> Int32 in
            guard let base = pointer.baseAddress else {
                return Int32(resultUnavailable)
            }
            return codeFn(base, Int32(pointer.count))
        }
        let evidence = code == resultDetected ? String(cString: buffer) : ""
        return HookNativeCheckResult(code: Int(code), evidence: evidence)
    }
}

private extension Array where Element == HookPrologueBaseline {
    func withCStringArrays(
        _ body: (UnsafePointer<UnsafePointer<CChar>?>?, UnsafePointer<UnsafePointer<CChar>?>?) -> Void
    ) {
        CStringBuffer(strings: map(\.symbolName)).withPointers { symbols in
            CStringBuffer(strings: map(\.expectedBytesHex)).withPointers { hex in
                body(symbols, hex)
            }
        }
    }
}

private extension Array where Element == HookSwizzleBaseline {
    func withCStringArrays(
        _ body: (
            UnsafePointer<UnsafePointer<CChar>?>?,
            UnsafePointer<UnsafePointer<CChar>?>?,
            UnsafePointer<UnsafePointer<CChar>?>?
        ) -> Void
    ) {
        CStringBuffer(strings: map(\.className)).withPointers { classes in
            CStringBuffer(strings: map(\.selector)).withPointers { selectors in
                CStringBuffer(strings: map(\.expectedImplementationHex)).withPointers { imps in
                    body(classes, selectors, imps)
                }
            }
        }
    }
}

private struct CStringBuffer {
    private var owned: [UnsafeMutablePointer<CChar>] = []
    private var pointers: [UnsafePointer<CChar>?] = []

    init(strings: [String]) {
        for string in strings {
            guard let pointer = strdup(string) else {
                continue
            }
            owned.append(pointer)
            pointers.append(UnsafePointer(pointer))
        }
    }

    func withPointers(_ body: (UnsafePointer<UnsafePointer<CChar>?>?) -> Void) {
        defer {
            for pointer in owned {
                free(pointer)
            }
        }
        pointers.withUnsafeBufferPointer { buffer in
            body(buffer.baseAddress)
        }
    }
}

@_silgen_name("mobshield_hook_set_prologue_from_strings")
private func mobshield_hook_set_prologue_from_strings(
    _ symbols: UnsafePointer<UnsafePointer<CChar>?>?,
    _ hex: UnsafePointer<UnsafePointer<CChar>?>?,
    _ count: Int32
) -> Int32

@_silgen_name("mobshield_hook_set_swizzle_from_strings")
private func mobshield_hook_set_swizzle_from_strings(
    _ classes: UnsafePointer<UnsafePointer<CChar>?>?,
    _ selectors: UnsafePointer<UnsafePointer<CChar>?>?,
    _ imps: UnsafePointer<UnsafePointer<CChar>?>?,
    _ count: Int32
) -> Int32

@_silgen_name("mobshield_hook_mach_region_inspect")
private func mobshield_hook_mach_region_inspect(_ evidence: UnsafeMutablePointer<CChar>?, _ evidence_len: Int32) -> Int32

@_silgen_name("mobshield_hook_function_prologue_inspect")
private func mobshield_hook_function_prologue_inspect(_ evidence: UnsafeMutablePointer<CChar>?, _ evidence_len: Int32) -> Int32

@_silgen_name("mobshield_hook_frida_artifact_scan")
private func mobshield_hook_frida_artifact_scan(_ evidence: UnsafeMutablePointer<CChar>?, _ evidence_len: Int32) -> Int32

@_silgen_name("mobshield_hook_frida_port_probe")
private func mobshield_hook_frida_port_probe(_ evidence: UnsafeMutablePointer<CChar>?, _ evidence_len: Int32) -> Int32

@_silgen_name("mobshield_hook_dyld_environment_scan")
private func mobshield_hook_dyld_environment_scan(_ evidence: UnsafeMutablePointer<CChar>?, _ evidence_len: Int32) -> Int32

@_silgen_name("mobshield_hook_method_swizzle_detect")
private func mobshield_hook_method_swizzle_detect(_ evidence: UnsafeMutablePointer<CChar>?, _ evidence_len: Int32) -> Int32
