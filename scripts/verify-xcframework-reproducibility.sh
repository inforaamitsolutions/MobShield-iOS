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

# Builds XCFrameworks twice and compares binary hashes.
# Allowed differences: codesign blobs, Info.plist timestamps, _CodeSignature.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1700000000}"
WORKDIR="${ROOT}/build/repro-xcf"
rm -rf "${WORKDIR}"
mkdir -p "${WORKDIR}"

hash_tree() {
  local dir="$1"
  local out="$2"
  find "${dir}" -type f \( -name '*.a' -o -name '*.o' -o -path '*/Headers/*' \) | sort | while read -r f; do
    shasum -a 256 "${f}"
  done > "${out}"
}

run_build() {
  local label="$1"
  local dest="${WORKDIR}/${label}"
  mkdir -p "${dest}/xcframeworks" "${dest}/archives"
  OUT_DIR_OVERRIDE="${dest}/xcframeworks" \
    ARCHIVE_DIR_OVERRIDE="${dest}/archives" \
    SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
    ./scripts/build-xcframeworks.sh
  hash_tree "${dest}/xcframeworks" "${dest}/hashes.txt"
}

# build-xcframeworks writes to build/xcframeworks; symlink for second pass
run_build "pass1"
run_build "pass2"

if diff -u "${WORKDIR}/pass1/hashes.txt" "${WORKDIR}/pass2/hashes.txt" > "${WORKDIR}/diff.txt"; then
  echo "PASS: XCFramework content hashes match"
  exit 0
fi

ALLOWED='CodeSignature|\.DS_Store|Info\.plist'
if ! grep -E '^[+-]' "${WORKDIR}/diff.txt" | grep -Ev "${ALLOWED}"; then
  echo "PASS: only codesign/metadata differences"
  exit 0
fi

echo "FAIL: reproducibility differences beyond allowed codesign blobs"
cat "${WORKDIR}/diff.txt"
exit 1
