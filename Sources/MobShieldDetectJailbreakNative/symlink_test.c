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

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int mobshield_jb_symlink_test(char* evidence, int evidence_len) {
    static const char* k_targets[] = {
        "/Applications",
        "/Library/Ringtones",
        NULL,
    };

    for (int i = 0; k_targets[i] != NULL; ++i) {
        struct stat st;
        if (lstat(k_targets[i], &st) != 0) {
            continue;
        }
        if ((st.st_mode & S_IFMT) == S_IFLNK) {
            if (evidence != NULL && evidence_len > 0) {
                snprintf(evidence, (size_t)evidence_len, "symlink=%s", k_targets[i]);
            }
            return MOBSHIELD_JB_DETECTED;
        }
    }
    return MOBSHIELD_JB_OK;
}
