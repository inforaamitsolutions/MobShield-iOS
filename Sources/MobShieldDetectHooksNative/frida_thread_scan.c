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
#include <mach/mach.h>
#include <mach/thread_info.h>
#endif

// Frida runs a GLib main loop and JS runtime on named worker threads. These names are a strong,
// hard-to-hide artifact of an in-process Frida agent/gadget: renaming the injected dylib (which
// defeats the image-name scan) does not rename these threads.
static int is_frida_thread(const char* name) {
    if (name == NULL || name[0] == '\0') {
        return 0;
    }
    static const char* k_markers[] = {
        "gum-js-loop",
        "gmain",
        "gdbus",
        "pool-frida",
        "pool-spawner",
        "frida",
        NULL,
    };
    for (int i = 0; k_markers[i] != NULL; ++i) {
        if (strstr(name, k_markers[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

int mobshield_hook_frida_thread_scan(char* evidence, int evidence_len) {
#if TARGET_OS_IOS || TARGET_OS_OSX
    thread_act_array_t threads;
    mach_msg_type_number_t thread_count = 0;
    if (task_threads(mach_task_self(), &threads, &thread_count) != KERN_SUCCESS) {
        return MOBSHIELD_HOOK_UNAVAILABLE;
    }

    int result = MOBSHIELD_HOOK_OK;
    for (mach_msg_type_number_t i = 0; i < thread_count; ++i) {
        thread_extended_info_data_t info;
        mach_msg_type_number_t info_count = THREAD_EXTENDED_INFO_COUNT;
        kern_return_t kr = thread_info(
            threads[i],
            THREAD_EXTENDED_INFO,
            (thread_info_t)&info,
            &info_count);
        if (kr == KERN_SUCCESS && is_frida_thread(info.pth_name)) {
            if (evidence != NULL && evidence_len > 0) {
                snprintf(evidence, (size_t)evidence_len, "thread=%s", info.pth_name);
            }
            result = MOBSHIELD_HOOK_DETECTED;
            break;
        }
    }

    // Release the send rights returned by task_threads and the array allocation itself.
    for (mach_msg_type_number_t i = 0; i < thread_count; ++i) {
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, thread_count * sizeof(thread_act_t));
    return result;
#else
    (void)evidence;
    (void)evidence_len;
    return MOBSHIELD_HOOK_UNAVAILABLE;
#endif
}
