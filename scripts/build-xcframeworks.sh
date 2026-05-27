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

# Builds XCFrameworks for MobShield SPM library products (device + simulator).
# Requires Xcode 15+ and xcodebuild.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

SCHEMES=(
  "MobShieldCore"
  "MobShieldDetectJailbreak"
  "MobShieldDetectHooks"
  "MobShieldDetectDebugger"
  "MobShieldDetectEnvironment"
  "MobShieldDetectIntegrity"
)

OUT_DIR="${OUT_DIR_OVERRIDE:-${ROOT}/build/xcframeworks}"
ARCHIVE_DIR="${ARCHIVE_DIR_OVERRIDE:-${ROOT}/build/archives}"
rm -rf "${OUT_DIR}" "${ARCHIVE_DIR}"
mkdir -p "${OUT_DIR}" "${ARCHIVE_DIR}"

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1700000000}"

build_scheme() {
  local scheme="$1"
  local ios_archive="${ARCHIVE_DIR}/${scheme}-ios"
  local sim_archive="${ARCHIVE_DIR}/${scheme}-sim"

  echo "Archiving ${scheme} (iOS device)..."
  xcodebuild archive \
    -scheme "${scheme}" \
    -destination "generic/platform=iOS" \
    -archivePath "${ios_archive}" \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
    OTHER_CFLAGS="-DSOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" \
    | xcpretty || true

  echo "Archiving ${scheme} (iOS simulator)..."
  xcodebuild archive \
    -scheme "${scheme}" \
    -destination "generic/platform=iOS Simulator" \
    -archivePath "${sim_archive}" \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
    OTHER_CFLAGS="-DSOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" \
    | xcpretty || true

  local ios_lib sim_lib
  ios_lib="$(find "${ios_archive}.xcarchive/Products" -name "*.framework" -maxdepth 3 | head -1)"
  sim_lib="$(find "${sim_archive}.xcarchive/Products" -name "*.framework" -maxdepth 3 | head -1)"

  if [[ -z "${ios_lib}" || -z "${sim_lib}" ]]; then
    echo "warning: framework not found for ${scheme}; skipping xcframework (SPM-only target?)" >&2
    return 0
  fi

  xcodebuild -create-xcframework \
    -framework "${ios_lib}" \
    -framework "${sim_lib}" \
    -output "${OUT_DIR}/${scheme}.xcframework"

  echo "Created ${OUT_DIR}/${scheme}.xcframework"
}

for scheme in "${SCHEMES[@]}"; do
  build_scheme "${scheme}" || echo "warn: ${scheme} failed" >&2
done

echo "XCFramework output: ${OUT_DIR}"
