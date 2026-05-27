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

#include "mobshield_jb_checks.h"

#if __has_include(<TargetConditionals.h>)
#include <TargetConditionals.h>
#endif

#include <cstdio>
#include <cstring>

#include <mach-o/dyld.h>

namespace {
bool contains_marker(const char* haystack, const char* needle) {
    if (haystack == nullptr || needle == nullptr) {
        return false;
    }
    return std::strstr(haystack, needle) != nullptr;
}

bool is_suspicious_image_name(const char* name) {
    if (name == nullptr) {
        return false;
    }
    static const char* kMarkers[] = {
        "MobileSubstrate",
        "Substrate",
        "Substitute",
        "CydiaSubstrate",
        "libhooker",
        "ElleKit",
        "TweakInject",
        "cycript",
        "frida",
        "roothide",
        "/var/jb/",
        "jailbreak",
        nullptr,
    };
    for (int i = 0; kMarkers[i] != nullptr; ++i) {
        if (contains_marker(name, kMarkers[i])) {
            return true;
        }
    }
    return false;
}

void write_evidence(const char* image, char* evidence, int evidence_len) {
    if (evidence == nullptr || evidence_len <= 0) {
        return;
    }
    std::snprintf(evidence, static_cast<size_t>(evidence_len), "image=%s", image != nullptr ? image : "");
}
}  // namespace

int mobshield_jb_dyld_image_scan(char* evidence, int evidence_len) {
#if TARGET_OS_IOS || TARGET_OS_OSX
    const uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        const char* name = _dyld_get_image_name(i);
        if (is_suspicious_image_name(name)) {
            write_evidence(name, evidence, evidence_len);
            return MOBSHIELD_JB_DETECTED;
        }
    }
    return MOBSHIELD_JB_OK;
#else
    (void)evidence;
    (void)evidence_len;
    return MOBSHIELD_JB_UNAVAILABLE;
#endif
}
