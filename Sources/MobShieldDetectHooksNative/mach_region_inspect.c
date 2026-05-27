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

#include <mach/mach.h>
#include <stdio.h>
#include <string.h>

#if __has_include(<TargetConditionals.h>)
#include <TargetConditionals.h>
#endif

int mobshield_hook_mach_region_inspect(char* evidence, int evidence_len) {
#if TARGET_OS_SIMULATOR
    (void)evidence;
    (void)evidence_len;
    return MOBSHIELD_HOOK_UNAVAILABLE;
#elif TARGET_OS_IOS || TARGET_OS_OSX
    mach_vm_address_t address = 0;
    mach_vm_size_t size = 0;
    natural_t depth = 0;
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;

    while (1) {
        memset(&info, 0, sizeof(info));
        info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
        const kern_return_t kr = vm_region_recurse_64(
            mach_task_self(),
            &address,
            &size,
            &depth,
            (vm_region_info_t)&info,
            &info_count);
        if (kr == KERN_INVALID_ADDRESS) {
            break;
        }
        if (kr != KERN_SUCCESS) {
            return MOBSHIELD_HOOK_UNAVAILABLE;
        }

        if (info.is_submap != 0) {
            depth++;
        } else {
            const vm_prot_t exec_mask = (vm_prot_t)(VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
            const int rwx_anonymous = (info.protection & exec_mask) == exec_mask && info.user_tag == 0 &&
                                      (info.share_mode == SM_PRIVATE || info.share_mode == SM_EMPTY);
            if (rwx_anonymous) {
                if (evidence != NULL && evidence_len > 0) {
                    snprintf(
                        evidence,
                        (size_t)evidence_len,
                        "region=0x%llx size=%llu",
                        (unsigned long long)address,
                        (unsigned long long)size);
                }
                return MOBSHIELD_HOOK_DETECTED;
            }
            address += size;
            depth = 0;
        }
    }
    return MOBSHIELD_HOOK_OK;
#else
    (void)evidence;
    (void)evidence_len;
    return MOBSHIELD_HOOK_UNAVAILABLE;
#endif
}
