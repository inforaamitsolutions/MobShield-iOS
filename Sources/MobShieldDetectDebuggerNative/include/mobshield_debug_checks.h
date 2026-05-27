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

#ifndef MOBSHIELD_DEBUG_CHECKS_H
#define MOBSHIELD_DEBUG_CHECKS_H

#ifdef __cplusplus
extern "C" {
#endif

#define MOBSHIELD_DEBUG_OK 0
#define MOBSHIELD_DEBUG_DETECTED 1
#define MOBSHIELD_DEBUG_UNAVAILABLE 2
#define MOBSHIELD_DEBUG_ERROR -1

int mobshield_debug_sysctl_ptraced(char* evidence, int evidence_len);
int mobshield_debug_ptrace_deny_attach(char* evidence, int evidence_len);
int mobshield_debug_mach_exception_check(char* evidence, int evidence_len);
int mobshield_debug_timing_check(char* evidence, int evidence_len);

#ifdef __cplusplus
}
#endif

#endif  // MOBSHIELD_DEBUG_CHECKS_H
