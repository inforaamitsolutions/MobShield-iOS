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

#include "mobshield_jb_checks.h"

#if __has_include(<TargetConditionals.h>)
#include <TargetConditionals.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

int mobshield_jb_sandbox_escape(char* evidence, int evidence_len) {
#if TARGET_OS_SIMULATOR
    (void)evidence;
    (void)evidence_len;
    return MOBSHIELD_JB_UNAVAILABLE;
#elif TARGET_OS_IOS || TARGET_OS_OSX
    errno = 0;
    const pid_t child = fork();
    if (child == 0) {
        _exit(0);
    }
    if (child > 0) {
        int status = 0;
        (void)waitpid(child, &status, 0);
        if (evidence != NULL && evidence_len > 0) {
            snprintf(evidence, (size_t)evidence_len, "probe=%s", "fork");
        }
        return MOBSHIELD_JB_DETECTED;
    }

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
    errno = 0;
    const pid_t vf_child = vfork();
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
    if (vf_child == 0) {
        _exit(0);
    }
    if (vf_child > 0) {
        int status = 0;
        (void)waitpid(vf_child, &status, 0);
        if (evidence != NULL && evidence_len > 0) {
            snprintf(evidence, (size_t)evidence_len, "probe=vfork");
        }
        return MOBSHIELD_JB_DETECTED;
    }
    return MOBSHIELD_JB_OK;
#else
    (void)evidence;
    (void)evidence_len;
    return MOBSHIELD_JB_UNAVAILABLE;
#endif
}
