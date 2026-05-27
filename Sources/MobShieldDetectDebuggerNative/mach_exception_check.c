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

#include <mach/mach.h>
#include <stdio.h>
#include <string.h>

int mobshield_debug_mach_exception_check(char* evidence, int evidence_len) {
#if defined(__APPLE__)
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;

    const kern_return_t kr = task_get_exception_ports(
        mach_task_self(),
        EXC_MASK_ALL,
        masks,
        &count,
        ports,
        behaviors,
        flavors);
    if (kr != KERN_SUCCESS) {
        return MOBSHIELD_DEBUG_UNAVAILABLE;
    }

    for (mach_msg_type_number_t i = 0; i < count; ++i) {
        if (ports[i] == MACH_PORT_NULL || ports[i] == mach_task_self()) {
            continue;
        }
        if (evidence != NULL && evidence_len > 0) {
            snprintf(
                evidence,
                (size_t)evidence_len,
                "mask=0x%x port=0x%x",
                masks[i],
                ports[i]);
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
