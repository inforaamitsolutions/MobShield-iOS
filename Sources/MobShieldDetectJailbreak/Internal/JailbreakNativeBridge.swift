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

public struct NativeCheckResult: Sendable {
    public let code: Int
    public let evidence: String

    public init(code: Int, evidence: String) {
        self.code = code
        self.evidence = evidence
    }
}

public protocol JailbreakNativeChecking: Sendable {
    static func configureExtraPaths(_ paths: [String])
    static func dyldImageScan() -> NativeCheckResult
    static func filesystemPaths() -> NativeCheckResult
    static func sandboxEscape() -> NativeCheckResult
    static func urlSchemeProbe() -> NativeCheckResult
    static func sysctlTraced() -> NativeCheckResult
    static func writeTest() -> NativeCheckResult
    static func symlinkTest() -> NativeCheckResult
    static func dyldHeaderInspect() -> NativeCheckResult
}

public enum JailbreakNativeBridge: JailbreakNativeChecking {
    public static let resultOk = 0
    public static let resultDetected = 1
    public static let resultUnavailable = 2

    public static func configureExtraPaths(_ paths: [String]) {
        paths.withCStringBuffer { buffer, count in
            _ = mobshield_jb_set_extra_paths(buffer, Int32(count))
        }
    }

    public static func dyldImageScan() -> NativeCheckResult {
        runCheck(codeFn: mobshield_jb_dyld_image_scan)
    }

    public static func filesystemPaths() -> NativeCheckResult {
        runCheck(codeFn: mobshield_jb_filesystem_paths)
    }

    public static func sandboxEscape() -> NativeCheckResult {
        runCheck(codeFn: mobshield_jb_sandbox_escape)
    }

    public static func urlSchemeProbe() -> NativeCheckResult {
        runCheck(codeFn: mobshield_jb_url_scheme_probe)
    }

    public static func sysctlTraced() -> NativeCheckResult {
        runCheck(codeFn: mobshield_jb_sysctl_traced)
    }

    public static func writeTest() -> NativeCheckResult {
        runCheck(codeFn: mobshield_jb_write_test)
    }

    public static func symlinkTest() -> NativeCheckResult {
        runCheck(codeFn: mobshield_jb_symlink_test)
    }

    public static func dyldHeaderInspect() -> NativeCheckResult {
        runCheck(codeFn: mobshield_jb_dyld_header_inspect)
    }

    private static func runCheck(
        codeFn: @convention(c) (UnsafeMutablePointer<CChar>?, Int32) -> Int32
    ) -> NativeCheckResult {
        var buffer = [CChar](repeating: 0, count: 256)
        let code = buffer.withUnsafeMutableBufferPointer { pointer -> Int32 in
            guard let base = pointer.baseAddress else {
                return Int32(resultUnavailable)
            }
            return codeFn(base, Int32(pointer.count))
        }
        let evidence: String
        if code == resultDetected {
            evidence = String(cString: buffer)
        } else {
            evidence = ""
        }
        return NativeCheckResult(code: Int(code), evidence: evidence)
    }
}

private extension Array where Element == String {
    func withCStringBuffer(
        _ body: (UnsafePointer<UnsafePointer<CChar>?>?, Int32) -> Void
    ) {
        var owned: [UnsafeMutablePointer<CChar>] = []
        defer {
            for pointer in owned {
                free(pointer)
            }
        }
        var cStrings: [UnsafePointer<CChar>?] = map { string in
            guard let pointer = strdup(string) else {
                return nil
            }
            owned.append(pointer)
            return UnsafePointer(pointer)
        }
        cStrings.withUnsafeBufferPointer { buffer in
            body(buffer.baseAddress, Int32(buffer.count))
        }
    }
}

@_silgen_name("mobshield_jb_set_extra_paths")
private func mobshield_jb_set_extra_paths(_ paths: UnsafePointer<UnsafePointer<CChar>?>?, _ count: Int32) -> Int32

@_silgen_name("mobshield_jb_dyld_image_scan")
private func mobshield_jb_dyld_image_scan(_ evidence: UnsafeMutablePointer<CChar>?, _ evidence_len: Int32) -> Int32

@_silgen_name("mobshield_jb_filesystem_paths")
private func mobshield_jb_filesystem_paths(_ evidence: UnsafeMutablePointer<CChar>?, _ evidence_len: Int32) -> Int32

@_silgen_name("mobshield_jb_sandbox_escape")
private func mobshield_jb_sandbox_escape(_ evidence: UnsafeMutablePointer<CChar>?, _ evidence_len: Int32) -> Int32

@_silgen_name("mobshield_jb_url_scheme_probe")
private func mobshield_jb_url_scheme_probe(_ evidence: UnsafeMutablePointer<CChar>?, _ evidence_len: Int32) -> Int32

@_silgen_name("mobshield_jb_sysctl_traced")
private func mobshield_jb_sysctl_traced(_ evidence: UnsafeMutablePointer<CChar>?, _ evidence_len: Int32) -> Int32

@_silgen_name("mobshield_jb_write_test")
private func mobshield_jb_write_test(_ evidence: UnsafeMutablePointer<CChar>?, _ evidence_len: Int32) -> Int32

@_silgen_name("mobshield_jb_symlink_test")
private func mobshield_jb_symlink_test(_ evidence: UnsafeMutablePointer<CChar>?, _ evidence_len: Int32) -> Int32

@_silgen_name("mobshield_jb_dyld_header_inspect")
private func mobshield_jb_dyld_header_inspect(_ evidence: UnsafeMutablePointer<CChar>?, _ evidence_len: Int32) -> Int32
