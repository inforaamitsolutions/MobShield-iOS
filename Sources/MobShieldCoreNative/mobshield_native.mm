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

#include "mobshield_native.h"

#include <cstring>

#import <Foundation/Foundation.h>

#include "mobshield_buildinfo.h"

namespace {
bool g_initialized = false;
// Baked into .rodata so mobshield-verify can locate entropy in the linked binary.
__attribute__((used)) static const char kMobShieldEntropyAnchor[] =
    "MOBSHIELD_ENTROPY=" MOBSHIELD_BUILD_ENTROPY;
}  // namespace

int mobshield_native_init(void) {
    if (@available(iOS 13.0, *)) {
        (void)[NSProcessInfo processInfo].processName;
    }
    g_initialized = true;
    return 0;
}

static int mobshield_copy_string(const char* value, char* out, int out_len) {
    if (value == nullptr || out == nullptr || out_len <= 0) {
        return -1;
    }
    const int needed = static_cast<int>(std::strlen(value));
    if (needed >= out_len) {
        return -1;
    }
    std::strcpy(out, value);
    return needed;
}

int mobshield_native_get_build_id(char* out, int out_len) {
    return mobshield_copy_string(MOBSHIELD_BUILD_ID, out, out_len);
}

int mobshield_native_get_version(char* out, int out_len) {
    return mobshield_copy_string(MOBSHIELD_VERSION, out, out_len);
}

int mobshield_native_self_check(void) {
    if (!g_initialized) {
        return 0;
    }
    return static_cast<int>(MOBSHIELD_SELF_CHECK_MAGIC);
}
