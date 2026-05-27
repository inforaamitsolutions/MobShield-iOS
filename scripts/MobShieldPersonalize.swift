#!/usr/bin/env swift
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

import CryptoKit
import Foundation

struct Config {
    let outputHeader: URL
    let fingerprintFile: URL
    let expectedSignerSha256: String
    let expectedBundleId: String
    let expectedTeamId: String
    let aggressiveAntiDebug: Bool
    let resourcePaths: [String]
    let searchPaths: [URL]
}

let internalSymbols = [
    "mobshield_native_self_check",
    "mobshield_jb_dyld_image_scan",
    "mobshield_hook_frida_port_probe",
    "mobshield_debug_sysctl_ptraced",
]

func main() {
    do {
        let config = try parseConfig()
        let fingerprint = try buildFingerprint(config: config)
        if shouldSkip(config: config, fingerprint: fingerprint) {
            fputs("MobShield personalize: up-to-date\n", stderr)
            return
        }
        let seed = try readSeed()
        let header = try generateHeader(config: config, seed: seed)
        try FileManager.default.createDirectory(
            at: config.outputHeader.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try header.write(to: config.outputHeader, atomically: true, encoding: .utf8)
        try fingerprint.write(to: config.fingerprintFile, atomically: true, encoding: .utf8)
        print("MobShield personalize: wrote \(config.outputHeader.path)")
    } catch {
        fputs("MobShield personalize failed: \(error)\n", stderr)
        exit(1)
    }
}

func parseConfig() throws -> Config {
    let env = ProcessInfo.processInfo.environment
    guard let derived = env["DERIVED_FILE_DIR"], !derived.isEmpty else {
        throw NSError(domain: "MobShield", code: 1, userInfo: [NSLocalizedDescriptionKey: "DERIVED_FILE_DIR is not set"])
    }
    let derivedURL = URL(fileURLWithPath: derived, isDirectory: true)
    let resourceList = env["MOBSHIELD_INTEGRITY_RESOURCE_PATHS"] ?? "Info.plist"
    let search = env["MOBSHIELD_FRAMEWORK_SEARCH_PATHS"] ?? env["FRAMEWORK_SEARCH_PATHS"] ?? ""
    let searchPaths = search.split(separator: " ").map { URL(fileURLWithPath: String($0), isDirectory: true) }
    return Config(
        outputHeader: derivedURL.appendingPathComponent("mobshield_buildinfo.h"),
        fingerprintFile: derivedURL.appendingPathComponent("mobshield_inputs.fingerprint"),
        expectedSignerSha256: normalizeHex(env["MOBSHIELD_EXPECTED_SIGNER_SHA256"] ?? ""),
        expectedBundleId: env["MOBSHIELD_EXPECTED_BUNDLE_ID"] ?? env["PRODUCT_BUNDLE_IDENTIFIER"] ?? "",
        expectedTeamId: env["MOBSHIELD_EXPECTED_TEAM_ID"] ?? env["DEVELOPMENT_TEAM"] ?? "",
        aggressiveAntiDebug: (env["MOBSHIELD_AGGRESSIVE_ANTI_DEBUG"] ?? "NO").uppercased() == "YES",
        resourcePaths: resourceList.split(separator: " ").map(String.init).filter { !$0.isEmpty },
        searchPaths: searchPaths
    )
}

func buildFingerprint(config: Config) throws -> String {
    let parts = [
        config.expectedSignerSha256,
        config.expectedBundleId,
        config.expectedTeamId,
        config.aggressiveAntiDebug ? "1" : "0",
        config.resourcePaths.joined(separator: ","),
    ]
    return parts.joined(separator: "|")
}

func shouldSkip(config: Config, fingerprint: String) -> Bool {
    guard let existing = try? String(contentsOf: config.fingerprintFile, encoding: .utf8) else {
        return false
    }
    guard FileManager.default.fileExists(atPath: config.outputHeader.path) else {
        return false
    }
    return existing == fingerprint
}

func readSeed() throws -> Data {
    if let seedHex = ProcessInfo.processInfo.environment["MOBSHIELD_RANDOM_SEED"], !seedHex.isEmpty {
        return try Data(hexString: normalizeHex(seedHex))
    }
    var bytes = [UInt8](repeating: 0, count: 32)
    let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    guard status == errSecSuccess else {
        throw NSError(domain: "MobShield", code: 2, userInfo: [NSLocalizedDescriptionKey: "SecRandomCopyBytes failed"])
    }
    return Data(bytes)
}

func generateHeader(config: Config, seed: Data) throws -> String {
    let entropy = Data(SHA256.hash(data: seed + Data("mobshield-entropy-v1".utf8)).prefix(16))
    let salt = Data(SHA256.hash(data: seed + Data([0x01])).prefix(16))
    let prologuePlain = Data(repeating: 0xFF, count: 64)
    let key = SymmetricKey(data: SHA256.hash(data: entropy + salt))
    let sealed = try AES.GCM.seal(prologuePlain, using: key)
    let nativeNames = ["MobShieldCore", "MobShieldDetectJailbreakNative", "MobShieldDetectHooksNative"]
    let nativePayload = nativeNames.joined(separator: "|").data(using: .utf8) ?? Data()
    let nativeHmac = HMAC<SHA256>.authenticationCode(for: nativePayload + seed, using: SymmetricKey(data: entropy))

    var lines: [String] = []
    lines.append("/* Generated by mobshield-personalize.sh. Not reproducible across builds. */")
    lines.append("#ifndef MOBSHIELD_BUILDINFO_H")
    lines.append("#define MOBSHIELD_BUILDINFO_H")
    lines.append("")
    lines.append("#define MOBSHIELD_VERSION \"0.1.0\"")
    lines.append("#define MOBSHIELD_BUILD_ID \"ios-\(config.expectedBundleId)-\(entropy.hexString().prefix(8))\"")
    lines.append("#define MOBSHIELD_SELF_CHECK_MAGIC 0x4D534844u")
    lines.append("#define MOBSHIELD_BUILD_ENTROPY \"\(entropy.hexString())\"")
    lines.append("#define MOBSHIELD_EXPECTED_SIGNER_SHA256 \"\(config.expectedSignerSha256)\"")
    lines.append("#define MOBSHIELD_EXPECTED_BUNDLE_ID \"\(config.expectedBundleId)\"")
    lines.append("#define MOBSHIELD_EXPECTED_TEAM_ID \"\(config.expectedTeamId)\"")
    lines.append("#define MOBSHIELD_NATIVELIB_HMAC \"\(Data(nativeHmac).hexString())\"")
    lines.append("#define MOBSHIELD_PROLOGUE_KEY_DERIVATION_SALT \"\(salt.hexString())\"")
    lines.append("#define MOBSHIELD_AGGRESSIVE_ANTI_DEBUG \(config.aggressiveAntiDebug ? 1 : 0)")
    let combined = sealed.combined ?? (sealed.nonce + sealed.ciphertext + sealed.tag)
    lines.append("#define MOBSHIELD_FN_PROLOGUE_CIPHERTEXT_LEN \(combined.count)")
    lines.append("static const unsigned char MOBSHIELD_FN_PROLOGUE_NONCE[] = { \(Data(sealed.nonce).hexArray()) };")
    lines.append("static const unsigned char MOBSHIELD_FN_PROLOGUE_CIPHERTEXT[] = { \(Data(combined).hexArray()) };")
    lines.append("")
    for (index, symbol) in internalSymbols.enumerated() {
        let suffix = symbolSuffix(seed: seed, index: index)
        lines.append("#define \(symbol) MOBSHIELD_R_\(suffix)")
    }
    lines.append("")
    lines.append("#endif  // MOBSHIELD_BUILDINFO_H")
    return lines.joined(separator: "\n")
}

func symbolSuffix(seed: Data, index: Int) -> String {
    var payload = seed
    payload.append(UInt8(index))
    payload.append("mobshield-symbol-v1".data(using: .utf8)!)
    return Data(SHA256.hash(data: payload).prefix(4)).hexString()
}

func normalizeHex(_ value: String) -> String {
    value.replacingOccurrences(of: ":", with: "").lowercased()
}

extension Data {
    init(hexString: String) throws {
        let normalized = hexString.replacingOccurrences(of: ":", with: "")
        guard normalized.count % 2 == 0 else {
            throw NSError(domain: "MobShield", code: 3, userInfo: nil)
        }
        var bytes = [UInt8]()
        bytes.reserveCapacity(normalized.count / 2)
        var index = normalized.startIndex
        while index < normalized.endIndex {
            let next = normalized.index(index, offsetBy: 2)
            let byte = UInt8(normalized[index..<next], radix: 16) ?? 0
            bytes.append(byte)
            index = next
        }
        self = Data(bytes)
    }

    func hexString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }

    func hexArray() -> String {
        map { String(format: "0x%02x", $0) }.joined(separator: ", ")
    }
}

extension Digest {
    func hexString() -> String {
        Data(self).hexString()
    }
}

main()
