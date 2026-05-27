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

#ifndef MOBSHIELD_NATIVE_H
#define MOBSHIELD_NATIVE_H

#ifdef __cplusplus
extern "C" {
#endif

/** Initialize native core. Returns 0 on success, negative on failure. */
int mobshield_native_init(void);

/** Copy build id into buffer. Returns bytes written excluding NUL, or -1 on error. */
int mobshield_native_get_build_id(char* out, int out_len);

/** Copy version string into buffer. Returns bytes written excluding NUL, or -1 on error. */
int mobshield_native_get_version(char* out, int out_len);

/** Integrity self-check. Returns nonzero when healthy. */
int mobshield_native_self_check(void);

#ifdef __cplusplus
}
#endif

#endif  // MOBSHIELD_NATIVE_H
