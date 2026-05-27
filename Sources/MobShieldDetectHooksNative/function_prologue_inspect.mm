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

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>

extern "C" {
const mobshield_hook_prologue_baseline* mobshield_hook_get_prologue_baselines(int* count);
}

namespace {
bool read_prologue(void* address, unsigned char* out, int out_len) {
    if (address == nullptr || out == nullptr || out_len <= 0) {
        return false;
    }
    std::memcpy(out, address, static_cast<size_t>(out_len));
    return true;
}

bool bytes_match(const unsigned char* actual, const unsigned char* expected, int len) {
    if (actual == nullptr || expected == nullptr || len <= 0) {
        return false;
    }
    return std::memcmp(actual, expected, static_cast<size_t>(len)) == 0;
}

bool has_arm64_trampoline(const unsigned char* bytes, int len) {
    if (bytes == nullptr || len < 4) {
        return false;
    }
    const uint32_t word = static_cast<uint32_t>(bytes[0]) | (static_cast<uint32_t>(bytes[1]) << 8) |
                          (static_cast<uint32_t>(bytes[2]) << 16) | (static_cast<uint32_t>(bytes[3]) << 24);
    if ((word & 0xFC000000U) == 0x14000000U) {
        return true;
    }
    if (len >= 8) {
        const uint32_t word2 = static_cast<uint32_t>(bytes[4]) | (static_cast<uint32_t>(bytes[5]) << 8) |
                               (static_cast<uint32_t>(bytes[6]) << 16) |
                               (static_cast<uint32_t>(bytes[7]) << 24);
        if ((word & 0xFF000000U) == 0x58000000U && (word2 & 0xFFFFFC1FU) == 0xD61F0000U) {
            return true;
        }
    }
    return false;
}

void* resolve_symbol(const char* symbol) {
    if (symbol == nullptr) {
        return nullptr;
    }
    void* address = dlsym(RTLD_DEFAULT, symbol);
    if (address != nullptr) {
        return address;
    }
    return dlsym(RTLD_NEXT, symbol);
}

int inspect_symbol(const char* symbol, const unsigned char* expected, int expected_len, char* evidence, int evidence_len) {
    void* address = resolve_symbol(symbol);
    if (address == nullptr) {
        return MOBSHIELD_HOOK_OK;
    }
    unsigned char actual[MOBSHIELD_HOOK_MAX_PROLOGUE_BYTES] = {0};
    if (!read_prologue(address, actual, MOBSHIELD_HOOK_MAX_PROLOGUE_BYTES)) {
        return MOBSHIELD_HOOK_OK;
    }
    if (expected != nullptr && expected_len > 0) {
        if (!bytes_match(actual, expected, expected_len)) {
            if (evidence != nullptr && evidence_len > 0) {
                std::snprintf(evidence, static_cast<size_t>(evidence_len), "symbol=%s", symbol);
            }
            return MOBSHIELD_HOOK_DETECTED;
        }
        return MOBSHIELD_HOOK_OK;
    }
    if (has_arm64_trampoline(actual, MOBSHIELD_HOOK_MAX_PROLOGUE_BYTES)) {
        if (evidence != nullptr && evidence_len > 0) {
            std::snprintf(evidence, static_cast<size_t>(evidence_len), "symbol=%s", symbol);
        }
        return MOBSHIELD_HOOK_DETECTED;
    }
    return MOBSHIELD_HOOK_OK;
}
}  // namespace

int mobshield_hook_function_prologue_inspect(char* evidence, int evidence_len) {
    int count = 0;
    const mobshield_hook_prologue_baseline* baselines = mobshield_hook_get_prologue_baselines(&count);
    if (baselines != nullptr && count > 0) {
        for (int i = 0; i < count; ++i) {
            const int code = inspect_symbol(
                baselines[i].symbol,
                baselines[i].bytes,
                baselines[i].byte_count,
                evidence,
                evidence_len);
            if (code == MOBSHIELD_HOOK_DETECTED) {
                return code;
            }
        }
        return MOBSHIELD_HOOK_OK;
    }

    static const char* k_symbols[] = {"objc_msgSend", "open", "syscall", nullptr};
    for (int i = 0; k_symbols[i] != nullptr; ++i) {
        const int code = inspect_symbol(k_symbols[i], nullptr, 0, evidence, evidence_len);
        if (code == MOBSHIELD_HOOK_DETECTED) {
            return code;
        }
    }
    return MOBSHIELD_HOOK_OK;
}
