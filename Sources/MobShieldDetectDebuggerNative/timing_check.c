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

#include "mobshield_debug_checks.h"

#include <mach/mach_time.h>
#include <stdio.h>

int mobshield_debug_timing_check(char* evidence, int evidence_len) {
#if defined(__APPLE__)
    const uint64_t baseline_start = mach_absolute_time();
    const uint64_t baseline_end = mach_absolute_time();
    const uint64_t baseline_delta = baseline_end - baseline_start;

    volatile uint64_t accumulator = 0;
    const uint64_t loop_start = mach_absolute_time();
    for (int i = 0; i < 50000; ++i) {
        accumulator += (uint64_t)(i * i);
    }
    const uint64_t loop_end = mach_absolute_time();
    const uint64_t loop_delta = loop_end - loop_start;
    (void)accumulator;

    if (loop_delta > baseline_delta * 200 && loop_delta > 500000ULL) {
        if (evidence != NULL && evidence_len > 0) {
            snprintf(evidence, (size_t)evidence_len, "delta=%llu", (unsigned long long)loop_delta);
        }
        return MOBSHIELD_DEBUG_DETECTED;
    }
    return MOBSHIELD_DEBUG_OK;
#else
    (void)evidence;
    (void)evidence_len;
    return MOBSHIELD_DEBUG_UNAVAILABLE;
#endif
}
