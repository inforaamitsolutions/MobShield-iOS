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

#include "mobshield_hook_checks.h"

#include <stdio.h>
#include <string.h>

#if __has_include(<TargetConditionals.h>)
#include <TargetConditionals.h>
#endif

#if TARGET_OS_IOS || TARGET_OS_OSX
#include <mach-o/dyld.h>
#endif

static int contains_marker(const char* haystack, const char* needle) {
    if (haystack == NULL || needle == NULL) {
        return 0;
    }
    return strstr(haystack, needle) != NULL;
}

static int is_frida_image(const char* name) {
    if (name == NULL) {
        return 0;
    }
    static const char* k_markers[] = {
        "FridaGadget",
        "libgadget",
        "frida-agent",
        "frida-agent.dylib",
        "gum-js-loop",
        "frida-gadget",
        "linjector",
        NULL,
    };
    for (int i = 0; k_markers[i] != NULL; ++i) {
        if (contains_marker(name, k_markers[i])) {
            return 1;
        }
    }
    return 0;
}

int mobshield_hook_frida_artifact_scan(char* evidence, int evidence_len) {
#if TARGET_OS_IOS || TARGET_OS_OSX
    const uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        const char* name = _dyld_get_image_name(i);
        if (is_frida_image(name)) {
            if (evidence != NULL && evidence_len > 0) {
                snprintf(evidence, (size_t)evidence_len, "image=%s", name != NULL ? name : "");
            }
            return MOBSHIELD_HOOK_DETECTED;
        }
    }
    return MOBSHIELD_HOOK_OK;
#else
    (void)evidence;
    (void)evidence_len;
    return MOBSHIELD_HOOK_UNAVAILABLE;
#endif
}
