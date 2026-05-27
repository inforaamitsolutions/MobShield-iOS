#!/usr/bin/env bash
# Copyright 2025 MobShield Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# MOBSHIELD Personalization
# Add as Xcode Build Phase BEFORE Compile Sources.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SWIFT_TOOL="${SCRIPT_DIR}/MobShieldPersonalize.swift"

if [[ ! -f "${SWIFT_TOOL}" ]]; then
  echo "error: MobShieldPersonalize.swift not found at ${SWIFT_TOOL}" >&2
  exit 1
fi

# Host-side Swift tool: must use the macOS SDK. During iOS app builds Xcode sets
# SDKROOT to iphonesimulator/iphoneos, which breaks `/usr/bin/swift` on Xcode 26+.
MACOS_SDK="$(xcrun --sdk macosx --show-sdk-path)"
export SDKROOT="${MACOS_SDK}"
export DEVELOPER_DIR="${DEVELOPER_DIR:-$(xcode-select -p)}"
xcrun --sdk macosx swift "${SWIFT_TOOL}"
