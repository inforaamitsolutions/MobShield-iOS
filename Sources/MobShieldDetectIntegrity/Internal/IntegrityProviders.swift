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

public struct IntegritySigningInfo: Sendable, Equatable {
    public let certificateDigests: [String]
    public let teamIdentifier: String?
    public let bundleIdentifier: String?

    public init(certificateDigests: [String], teamIdentifier: String?, bundleIdentifier: String?) {
        self.certificateDigests = certificateDigests
        self.teamIdentifier = teamIdentifier
        self.bundleIdentifier = bundleIdentifier
    }
}

public protocol IntegrityBundleProviding: Sendable {
    var bundleIdentifier: String? { get }
    var bundleURL: URL? { get }
    var appStoreReceiptURL: URL? { get }
    func path(forResource name: String, ofType ext: String?) -> String?
    func url(forResource name: String, withExtension ext: String?) -> URL?
    func object(forInfoDictionaryKey key: String) -> Any?
    func fileExists(atPath path: String) -> Bool
    func contents(atPath path: String) -> Data?
}

public protocol IntegritySecCodeProviding: Sendable {
    func copySigningInfo() throws -> IntegritySigningInfo
}

public struct LiveIntegrityBundleProvider: IntegrityBundleProviding {
    private let bundle: Bundle

    public init(bundle: Bundle = .main) {
        self.bundle = bundle
    }

    public var bundleIdentifier: String? { bundle.bundleIdentifier }
    public var bundleURL: URL? { bundle.bundleURL }
    public var appStoreReceiptURL: URL? { bundle.appStoreReceiptURL }

    public func path(forResource name: String, ofType ext: String?) -> String? {
        bundle.path(forResource: name, ofType: ext)
    }

    public func url(forResource name: String, withExtension ext: String?) -> URL? {
        bundle.url(forResource: name, withExtension: ext)
    }

    public func object(forInfoDictionaryKey key: String) -> Any? {
        bundle.object(forInfoDictionaryKey: key)
    }

    public func fileExists(atPath path: String) -> Bool {
        FileManager.default.fileExists(atPath: path)
    }

    public func contents(atPath path: String) -> Data? {
        FileManager.default.contents(atPath: path)
    }
}
