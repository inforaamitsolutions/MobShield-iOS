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
#include <stdlib.h>
#include <string.h>

#if __has_include(<TargetConditionals.h>)
#include <TargetConditionals.h>
#endif

int mobshield_hook_dyld_environment_scan(char* evidence, int evidence_len) {
#if TARGET_OS_SIMULATOR
    (void)evidence;
    (void)evidence_len;
    return MOBSHIELD_HOOK_UNAVAILABLE;
#else
    const char* insert_libs = getenv("DYLD_INSERT_LIBRARIES");
    if (insert_libs != NULL && insert_libs[0] != '\0') {
        if (evidence != NULL && evidence_len > 0) {
            snprintf(evidence, (size_t)evidence_len, "env=DYLD_INSERT_LIBRARIES");
        }
        return MOBSHIELD_HOOK_DETECTED;
    }
    const char* flat_namespace = getenv("DYLD_FORCE_FLAT_NAMESPACE");
    if (flat_namespace != NULL && flat_namespace[0] != '\0') {
        if (evidence != NULL && evidence_len > 0) {
            snprintf(evidence, (size_t)evidence_len, "env=DYLD_FORCE_FLAT_NAMESPACE");
        }
        return MOBSHIELD_HOOK_DETECTED;
    }
    return MOBSHIELD_HOOK_OK;
#endif
}
