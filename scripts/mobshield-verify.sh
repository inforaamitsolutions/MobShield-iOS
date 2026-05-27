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

# MOBSHIELD post-build verification. Add AFTER Compile Sources / linking.
set -euo pipefail

if [[ -z "${DERIVED_FILE_DIR:-}" ]]; then
  echo "error: DERIVED_FILE_DIR is not set" >&2
  exit 1
fi

HEADER_PATH="${DERIVED_FILE_DIR}/mobshield_buildinfo.h"
if [[ ! -f "${HEADER_PATH}" ]]; then
  echo "error: mobshield_buildinfo.h not found at ${HEADER_PATH}" >&2
  exit 1
fi

ENTROPY="$(grep MOBSHIELD_BUILD_ENTROPY "${HEADER_PATH}" | sed -E 's/.*\"([0-9a-fA-F]+)\".*/\1/' | head -n1)"
if [[ -z "${ENTROPY}" ]]; then
  echo "error: MOBSHIELD_BUILD_ENTROPY missing in header" >&2
  exit 1
fi

APP_BUNDLE="${TARGET_BUILD_DIR}/${WRAPPER_NAME:-}"
BINARY_PATH="${TARGET_BUILD_DIR}/${EXECUTABLE_PATH:-}"

if [[ -z "${APP_BUNDLE}" || ! -d "${APP_BUNDLE}" ]]; then
  echo "warning: MobShield verify skipped (app bundle not found)" >&2
  exit 0
fi

# Entropy is embedded in MobShield native targets when personalization reaches native code.
if ! grep -a -rq "${ENTROPY}" "${APP_BUNDLE}" 2>/dev/null; then
  if [[ "${CONFIGURATION:-Debug}" == "Debug" ]]; then
    echo "warning: MobShield verify: build entropy not found in app bundle (Debug). Personalize ran; SPM native may use the checked-in stub header until Xcode wires DERIVED_FILE_DIR into package targets." >&2
    exit 0
  fi
  echo "error: MobShield verify failed: app bundle does not contain build entropy ${ENTROPY}" >&2
  echo "  Bundle: ${APP_BUNDLE}" >&2
  [[ -n "${BINARY_PATH}" ]] && echo "  Binary: ${BINARY_PATH}" >&2
  exit 1
fi

VERIFY_BINARY="${BINARY_PATH}"
if [[ -z "${VERIFY_BINARY}" || ! -f "${VERIFY_BINARY}" ]]; then
  VERIFY_BINARY="${APP_BUNDLE}/$(basename "${APP_BUNDLE}" .app)"
fi

EXPECTED_SIGNER="$(echo "${MOBSHIELD_EXPECTED_SIGNER_SHA256:-}" | tr -d ':' | tr '[:upper:]' '[:lower:]')"
if [[ -n "${EXPECTED_SIGNER}" && "${EXPECTED_SIGNER}" != *"0000000000000000"* && -f "${VERIFY_BINARY}" ]]; then
  ACTUAL_SIGNER="$(codesign -d --extract-certificates "${VERIFY_BINARY}" 2>/dev/null | openssl x509 -inform DER -outform PEM 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/sha256 //I' | tr -d ':' | tr '[:upper:]' '[:lower:]' || true)"
  if [[ -n "${ACTUAL_SIGNER}" && "${ACTUAL_SIGNER}" != "${EXPECTED_SIGNER}" ]]; then
    echo "error: MobShield verify failed: signing cert SHA-256 mismatch" >&2
    echo "  Expected: ${EXPECTED_SIGNER}" >&2
    echo "  Actual:   ${ACTUAL_SIGNER}" >&2
    exit 1
  fi
fi

echo "MobShield verify passed for $(basename "${APP_BUNDLE}")"
