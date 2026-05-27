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

struct MasvsRow: Identifiable {
    let id: String
    let control: String
    let title: String
    let coverage: String
}

enum MasvsCatalog {
    static let rows: [MasvsRow] = [
        MasvsRow(id: "1", control: "MASVS-RES-1", title: "Untrusted device (root/JB)", coverage: "Yes"),
        MasvsRow(id: "2", control: "MASVS-RES-2", title: "Reverse engineering / tampering", coverage: "Partial"),
        MasvsRow(id: "3", control: "MASVS-RES-3", title: "Runtime process integrity", coverage: "Partial"),
        MasvsRow(id: "4", control: "MASVS-RES-4", title: "Emulator detection", coverage: "Partial"),
        MasvsRow(id: "5", control: "MASVS-RES-5", title: "Platform API integrity", coverage: "Partial"),
        MasvsRow(id: "6", control: "MASVS-RES-6", title: "Obfuscation / anti-tamper", coverage: "No (MVP)"),
        MasvsRow(id: "7", control: "MASVS-RES-7", title: "Anti-debug", coverage: "Yes"),
        MasvsRow(id: "8", control: "MASVS-RES-8", title: "Anti-instrumentation", coverage: "Partial"),
        MasvsRow(id: "9", control: "MASVS-RES-9", title: "Device binding / attestation", coverage: "No (MVP)"),
        MasvsRow(id: "10", control: "MASVS-RES-10", title: "Anti-emulator / automation", coverage: "Partial"),
    ]
}
