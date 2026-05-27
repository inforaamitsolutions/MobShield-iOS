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

#ifndef MOBSHIELD_HOOK_CHECKS_H
#define MOBSHIELD_HOOK_CHECKS_H

#ifdef __cplusplus
extern "C" {
#endif

#define MOBSHIELD_HOOK_OK 0
#define MOBSHIELD_HOOK_DETECTED 1
#define MOBSHIELD_HOOK_UNAVAILABLE 2
#define MOBSHIELD_HOOK_ERROR -1

#define MOBSHIELD_HOOK_MAX_SYMBOLS 16
#define MOBSHIELD_HOOK_MAX_SWIZZLE 32
#define MOBSHIELD_HOOK_MAX_SYMBOL_LEN 128
#define MOBSHIELD_HOOK_MAX_CLASS_LEN 128
#define MOBSHIELD_HOOK_MAX_SELECTOR_LEN 128
#define MOBSHIELD_HOOK_MAX_PROLOGUE_BYTES 16
#define MOBSHIELD_HOOK_MAX_HEX_LEN 64

typedef struct mobshield_hook_prologue_baseline {
    char symbol[MOBSHIELD_HOOK_MAX_SYMBOL_LEN];
    unsigned char bytes[MOBSHIELD_HOOK_MAX_PROLOGUE_BYTES];
    int byte_count;
} mobshield_hook_prologue_baseline;

typedef struct mobshield_hook_swizzle_baseline {
    char class_name[MOBSHIELD_HOOK_MAX_CLASS_LEN];
    char selector[MOBSHIELD_HOOK_MAX_SELECTOR_LEN];
    unsigned long long expected_imp;
    int has_expected_imp;
} mobshield_hook_swizzle_baseline;

int mobshield_hook_set_prologue_baselines(const mobshield_hook_prologue_baseline* baselines, int count);
int mobshield_hook_set_swizzle_baselines(const mobshield_hook_swizzle_baseline* baselines, int count);

/** Configure prologue baselines from parallel arrays (hex may be NULL for heuristic-only). */
int mobshield_hook_set_prologue_from_strings(
    const char* const* symbols,
    const char* const* prologue_hex,
    int count);

/** Configure swizzle baselines; imp_hex may be NULL to use superclass comparison. */
int mobshield_hook_set_swizzle_from_strings(
    const char* const* class_names,
    const char* const* selectors,
    const char* const* imp_hex,
    int count);

int mobshield_hook_mach_region_inspect(char* evidence, int evidence_len);
int mobshield_hook_function_prologue_inspect(char* evidence, int evidence_len);
int mobshield_hook_frida_artifact_scan(char* evidence, int evidence_len);
int mobshield_hook_frida_port_probe(char* evidence, int evidence_len);
int mobshield_hook_dyld_environment_scan(char* evidence, int evidence_len);
int mobshield_hook_method_swizzle_detect(char* evidence, int evidence_len);

const mobshield_hook_prologue_baseline* mobshield_hook_get_prologue_baselines(int* count);
const mobshield_hook_swizzle_baseline* mobshield_hook_get_swizzle_baselines(int* count);

#ifdef __cplusplus
}
#endif

#endif  // MOBSHIELD_HOOK_CHECKS_H
