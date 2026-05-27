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

#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <sys/proc.h>
#endif

int mobshield_debug_sysctl_ptraced(char* evidence, int evidence_len) {
#if defined(__APPLE__)
    struct kinfo_proc info;
    memset(&info, 0, sizeof(info));
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    size_t size = sizeof(info);
    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0) {
        return MOBSHIELD_DEBUG_UNAVAILABLE;
    }
#if defined(P_TRACED)
    if ((info.kp_proc.p_flag & P_TRACED) != 0) {
        if (evidence != NULL && evidence_len > 0) {
            snprintf(evidence, (size_t)evidence_len, "flag=P_TRACED");
        }
        return MOBSHIELD_DEBUG_DETECTED;
    }
#endif
    return MOBSHIELD_DEBUG_OK;
#else
    (void)evidence;
    (void)evidence_len;
    return MOBSHIELD_DEBUG_UNAVAILABLE;
#endif
}
