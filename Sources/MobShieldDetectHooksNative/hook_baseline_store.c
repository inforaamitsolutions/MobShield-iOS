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

#include <string.h>

static mobshield_hook_prologue_baseline g_prologue[MOBSHIELD_HOOK_MAX_SYMBOLS];
static int g_prologue_count = 0;

static mobshield_hook_swizzle_baseline g_swizzle[MOBSHIELD_HOOK_MAX_SWIZZLE];
static int g_swizzle_count = 0;

int mobshield_hook_set_prologue_baselines(const mobshield_hook_prologue_baseline* baselines, int count) {
    g_prologue_count = 0;
    if (baselines == NULL || count <= 0) {
        return MOBSHIELD_HOOK_OK;
    }
    const int limit = count > MOBSHIELD_HOOK_MAX_SYMBOLS ? MOBSHIELD_HOOK_MAX_SYMBOLS : count;
    for (int i = 0; i < limit; ++i) {
        g_prologue[g_prologue_count] = baselines[i];
        g_prologue[g_prologue_count].symbol[MOBSHIELD_HOOK_MAX_SYMBOL_LEN - 1] = '\0';
        g_prologue_count++;
    }
    return MOBSHIELD_HOOK_OK;
}

int mobshield_hook_set_swizzle_baselines(const mobshield_hook_swizzle_baseline* baselines, int count) {
    g_swizzle_count = 0;
    if (baselines == NULL || count <= 0) {
        return MOBSHIELD_HOOK_OK;
    }
    const int limit = count > MOBSHIELD_HOOK_MAX_SWIZZLE ? MOBSHIELD_HOOK_MAX_SWIZZLE : count;
    for (int i = 0; i < limit; ++i) {
        g_swizzle[g_swizzle_count] = baselines[i];
        g_swizzle[g_swizzle_count].class_name[MOBSHIELD_HOOK_MAX_CLASS_LEN - 1] = '\0';
        g_swizzle[g_swizzle_count].selector[MOBSHIELD_HOOK_MAX_SELECTOR_LEN - 1] = '\0';
        g_swizzle_count++;
    }
    return MOBSHIELD_HOOK_OK;
}

const mobshield_hook_prologue_baseline* mobshield_hook_get_prologue_baselines(int* count) {
    if (count != NULL) {
        *count = g_prologue_count;
    }
    return g_prologue;
}

const mobshield_hook_swizzle_baseline* mobshield_hook_get_swizzle_baselines(int* count) {
    if (count != NULL) {
        *count = g_swizzle_count;
    }
    return g_swizzle;
}

static int hex_nibble(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return 10 + (ch - 'a');
    }
    if (ch >= 'A' && ch <= 'F') {
        return 10 + (ch - 'A');
    }
    return -1;
}

static int decode_hex_bytes(const char* hex, unsigned char* out, int out_cap) {
    if (hex == NULL || out == NULL || out_cap <= 0) {
        return 0;
    }
    int written = 0;
    int hi = -1;
    for (const char* cursor = hex; *cursor != '\0' && written < out_cap; ++cursor) {
        const int nibble = hex_nibble(*cursor);
        if (nibble < 0) {
            continue;
        }
        if (hi < 0) {
            hi = nibble;
        } else {
            out[written++] = (unsigned char)((hi << 4) | nibble);
            hi = -1;
        }
    }
    return written;
}

static unsigned long long decode_pointer_hex(const char* hex) {
    if (hex == NULL || hex[0] == '\0') {
        return 0;
    }
    unsigned long long value = 0;
    for (const char* cursor = hex; *cursor != '\0'; ++cursor) {
        const int nibble = hex_nibble(*cursor);
        if (nibble < 0) {
            continue;
        }
        value = (value << 4) | (unsigned long long)nibble;
    }
    return value;
}

int mobshield_hook_set_prologue_from_strings(
    const char* const* symbols,
    const char* const* prologue_hex,
    int count) {
    g_prologue_count = 0;
    if (symbols == NULL || count <= 0) {
        return MOBSHIELD_HOOK_OK;
    }
    const int limit = count > MOBSHIELD_HOOK_MAX_SYMBOLS ? MOBSHIELD_HOOK_MAX_SYMBOLS : count;
    for (int i = 0; i < limit; ++i) {
        if (symbols[i] == NULL || symbols[i][0] == '\0') {
            continue;
        }
        mobshield_hook_prologue_baseline* entry = &g_prologue[g_prologue_count];
        strncpy(entry->symbol, symbols[i], MOBSHIELD_HOOK_MAX_SYMBOL_LEN - 1);
        entry->symbol[MOBSHIELD_HOOK_MAX_SYMBOL_LEN - 1] = '\0';
        const char* hex = prologue_hex != NULL ? prologue_hex[i] : NULL;
        entry->byte_count = decode_hex_bytes(hex, entry->bytes, MOBSHIELD_HOOK_MAX_PROLOGUE_BYTES);
        g_prologue_count++;
    }
    return MOBSHIELD_HOOK_OK;
}

int mobshield_hook_set_swizzle_from_strings(
    const char* const* class_names,
    const char* const* selectors,
    const char* const* imp_hex,
    int count) {
    g_swizzle_count = 0;
    if (class_names == NULL || selectors == NULL || count <= 0) {
        return MOBSHIELD_HOOK_OK;
    }
    const int limit = count > MOBSHIELD_HOOK_MAX_SWIZZLE ? MOBSHIELD_HOOK_MAX_SWIZZLE : count;
    for (int i = 0; i < limit; ++i) {
        if (class_names[i] == NULL || selectors[i] == NULL) {
            continue;
        }
        mobshield_hook_swizzle_baseline* entry = &g_swizzle[g_swizzle_count];
        strncpy(entry->class_name, class_names[i], MOBSHIELD_HOOK_MAX_CLASS_LEN - 1);
        entry->class_name[MOBSHIELD_HOOK_MAX_CLASS_LEN - 1] = '\0';
        strncpy(entry->selector, selectors[i], MOBSHIELD_HOOK_MAX_SELECTOR_LEN - 1);
        entry->selector[MOBSHIELD_HOOK_MAX_SELECTOR_LEN - 1] = '\0';
        const char* hex = imp_hex != NULL ? imp_hex[i] : NULL;
        if (hex != NULL && hex[0] != '\0') {
            entry->has_expected_imp = 1;
            entry->expected_imp = decode_pointer_hex(hex);
        } else {
            entry->has_expected_imp = 0;
            entry->expected_imp = 0;
        }
        g_swizzle_count++;
    }
    return MOBSHIELD_HOOK_OK;
}
