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
#include <mach-o/loader.h>

namespace {
bool name_is_suspicious(const char* name) {
    if (name == nullptr) {
        return false;
    }
    static const char* k_markers[] = {
        "substrate",
        "substitute",
        "cycript",
        "frida",
        "ellekit",
        "libhooker",
        "tweakinject",
        "mobilesubstrate",
        "/var/jb/",
        nullptr,
    };
    char lower[256];
    size_t len = std::strlen(name);
    if (len >= sizeof(lower)) {
        len = sizeof(lower) - 1;
    }
    for (size_t i = 0; i < len; ++i) {
        const char ch = name[i];
        lower[i] = (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch - 'A' + 'a') : ch;
    }
    lower[len] = '\0';
    for (int i = 0; k_markers[i] != nullptr; ++i) {
        if (std::strstr(lower, k_markers[i]) != nullptr) {
            return true;
        }
    }
    return false;
}
}  // namespace

int mobshield_jb_dyld_header_inspect(char* evidence, int evidence_len) {
#if TARGET_OS_IOS || TARGET_OS_OSX
    const uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        const struct mach_header* header = _dyld_get_image_header(i);
        const char* name = _dyld_get_image_name(i);
        if (header == nullptr) {
            continue;
        }
        uint32_t filetype = 0;
        if (header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64) {
            const auto* header64 = reinterpret_cast<const mach_header_64*>(header);
            filetype = header64->filetype;
        } else {
            filetype = header->filetype;
        }
        const bool is_dylib = filetype == MH_DYLIB;
        if (!is_dylib) {
            continue;
        }
        if (name_is_suspicious(name)) {
            if (evidence != nullptr && evidence_len > 0) {
                std::snprintf(evidence, static_cast<size_t>(evidence_len), "dylib=%s", name != nullptr ? name : "");
            }
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
