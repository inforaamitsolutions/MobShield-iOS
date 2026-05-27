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

enum ProvisioningProfileParser {
    static func parsePlist(from data: Data) -> [String: Any]? {
        guard let start = data.range(of: Data("<?xml".utf8)),
              let end = data.range(of: Data("</plist>".utf8)) else {
            return nil
        }
        let plistData = data.subdata(in: start.lowerBound..<end.upperBound)
        var format = PropertyListSerialization.PropertyListFormat.xml
        return (try? PropertyListSerialization.propertyList(
            from: plistData,
            options: [],
            format: &format
        )) as? [String: Any]
    }

    static func applicationIdentifier(from plist: [String: Any]) -> String? {
        if let entitlements = plist["Entitlements"] as? [String: Any],
           let appId = entitlements["application-identifier"] as? String {
            return appId
        }
        return plist["AppIDName"] as? String
    }

    static func teamIdentifiers(from plist: [String: Any]) -> [String] {
        if let teamData = plist["TeamIdentifier"] as? [String] {
            return teamData
        }
        if let team = plist["TeamIdentifier"] as? String {
            return [team]
        }
        return []
    }
}
