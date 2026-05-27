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

public struct DebugNativeCheckResult: Sendable {
    public let code: Int
    public let evidence: String

    public init(code: Int, evidence: String) {
        self.code = code
        self.evidence = evidence
    }
}

public protocol DebugNativeChecking: Sendable {
    static func sysctlPtraced() -> DebugNativeCheckResult
    static func ptraceDenyAttach() -> DebugNativeCheckResult
    static func machExceptionCheck() -> DebugNativeCheckResult
    static func timingCheck() -> DebugNativeCheckResult
}

public enum DebugNativeBridge: DebugNativeChecking {
    public static let resultOk = 0
    public static let resultDetected = 1
    public static let resultUnavailable = 2

    public static func sysctlPtraced() -> DebugNativeCheckResult {
        runCheck(codeFn: mobshield_debug_sysctl_ptraced)
    }

    public static func ptraceDenyAttach() -> DebugNativeCheckResult {
        runCheck(codeFn: mobshield_debug_ptrace_deny_attach)
    }

    public static func machExceptionCheck() -> DebugNativeCheckResult {
        runCheck(codeFn: mobshield_debug_mach_exception_check)
    }

    public static func timingCheck() -> DebugNativeCheckResult {
        runCheck(codeFn: mobshield_debug_timing_check)
    }

    private static func runCheck(
        codeFn: @convention(c) (UnsafeMutablePointer<CChar>?, Int32) -> Int32
    ) -> DebugNativeCheckResult {
        var buffer = [CChar](repeating: 0, count: 256)
        let code = buffer.withUnsafeMutableBufferPointer { pointer -> Int32 in
            guard let base = pointer.baseAddress else {
                return Int32(resultUnavailable)
            }
            return codeFn(base, Int32(pointer.count))
        }
        let evidence = code == resultDetected ? String(cString: buffer) : ""
        return DebugNativeCheckResult(code: Int(code), evidence: evidence)
    }
}

@_silgen_name("mobshield_debug_sysctl_ptraced")
private func mobshield_debug_sysctl_ptraced(_ evidence: UnsafeMutablePointer<CChar>?, _ evidence_len: Int32) -> Int32

@_silgen_name("mobshield_debug_ptrace_deny_attach")
private func mobshield_debug_ptrace_deny_attach(_ evidence: UnsafeMutablePointer<CChar>?, _ evidence_len: Int32) -> Int32

@_silgen_name("mobshield_debug_mach_exception_check")
private func mobshield_debug_mach_exception_check(_ evidence: UnsafeMutablePointer<CChar>?, _ evidence_len: Int32) -> Int32

@_silgen_name("mobshield_debug_timing_check")
private func mobshield_debug_timing_check(_ evidence: UnsafeMutablePointer<CChar>?, _ evidence_len: Int32) -> Int32
