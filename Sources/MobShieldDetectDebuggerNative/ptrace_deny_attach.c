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

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

typedef int (*mobshield_ptrace_fn)(int request, pid_t pid, caddr_t addr, int data);

int mobshield_debug_ptrace_deny_attach(char* evidence, int evidence_len) {
#if defined(__APPLE__)
    void* handle = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_NOW);
    if (handle == NULL) {
        return MOBSHIELD_DEBUG_UNAVAILABLE;
    }
    mobshield_ptrace_fn ptrace_call = (mobshield_ptrace_fn)dlsym(handle, "ptrace");
    if (ptrace_call == NULL) {
        dlclose(handle);
        return MOBSHIELD_DEBUG_UNAVAILABLE;
    }

    errno = 0;
    const int result = ptrace_call(PT_DENY_ATTACH, 0, 0, 0);
    if (result == -1 && errno != 0) {
        if (evidence != NULL && evidence_len > 0) {
            snprintf(evidence, (size_t)evidence_len, "errno=%d", errno);
        }
        dlclose(handle);
        return MOBSHIELD_DEBUG_DETECTED;
    }
    dlclose(handle);
    return MOBSHIELD_DEBUG_OK;
#else
    (void)evidence;
    (void)evidence_len;
    return MOBSHIELD_DEBUG_UNAVAILABLE;
#endif
}
