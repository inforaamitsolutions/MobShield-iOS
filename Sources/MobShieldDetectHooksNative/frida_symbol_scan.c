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

#if __has_include(<TargetConditionals.h>)
#include <TargetConditionals.h>
#endif

#if TARGET_OS_IOS || TARGET_OS_OSX
#include <dlfcn.h>
#endif

// Frida's runtime (Gum) and agent export well-known C symbols. dlsym(RTLD_DEFAULT, ...) resolves
// them across every loaded image, so this fires even when the gadget dylib has been renamed to
// defeat the image-name scan — the exported symbol names cannot change without breaking Frida.
int mobshield_hook_frida_symbol_scan(char* evidence, int evidence_len) {
#if TARGET_OS_IOS || TARGET_OS_OSX
    static const char* k_symbols[] = {
        "gum_init_embedded",
        "gum_script_backend_obtain",
        "gum_interceptor_obtain",
        "frida_agent_main",
        NULL,
    };
    for (int i = 0; k_symbols[i] != NULL; ++i) {
        if (dlsym(RTLD_DEFAULT, k_symbols[i]) != NULL) {
            if (evidence != NULL && evidence_len > 0) {
                snprintf(evidence, (size_t)evidence_len, "symbol=%s", k_symbols[i]);
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
