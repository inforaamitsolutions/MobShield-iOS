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

#ifndef MOBSHIELD_JB_CHECKS_H
#define MOBSHIELD_JB_CHECKS_H

#ifdef __cplusplus
extern "C" {
#endif

#define MOBSHIELD_JB_OK 0
#define MOBSHIELD_JB_DETECTED 1
#define MOBSHIELD_JB_UNAVAILABLE 2
#define MOBSHIELD_JB_ERROR -1

#define MOBSHIELD_JB_MAX_EXTRA_PATHS 32
#define MOBSHIELD_JB_MAX_PATH_LEN 512

/** Replace additional filesystem paths scanned by filesystem_paths.c. */
int mobshield_jb_set_extra_paths(const char* const* paths, int count);

int mobshield_jb_dyld_image_scan(char* evidence, int evidence_len);
int mobshield_jb_filesystem_paths(char* evidence, int evidence_len);
int mobshield_jb_sandbox_escape(char* evidence, int evidence_len);
int mobshield_jb_url_scheme_probe(char* evidence, int evidence_len);
int mobshield_jb_sysctl_traced(char* evidence, int evidence_len);
int mobshield_jb_write_test(char* evidence, int evidence_len);
int mobshield_jb_symlink_test(char* evidence, int evidence_len);
int mobshield_jb_dyld_header_inspect(char* evidence, int evidence_len);

#ifdef __cplusplus
}
#endif

#endif  // MOBSHIELD_JB_CHECKS_H
