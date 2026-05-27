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
#include <unistd.h>
#include <sys/stat.h>

#if __has_include(<TargetConditionals.h>)
#include <TargetConditionals.h>
#endif

#if TARGET_OS_SIMULATOR
/* Simulator images may expose host-like paths (/bin/bash, /var/jb). Probe package-manager artifacts only. */
static const char* k_default_paths[] = {
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/var/jb/Applications/Sileo.app",
    "/.installed_unc0ver",
    "/private/var/mobile/Library/Preferences/com.saurik.Cydia.plist",
    NULL,
};
#else
static const char* k_default_paths[] = {
    "/Applications/Cydia.app",
    "/Library/MobileSubstrate",
    "/bin/bash",
    "/etc/apt",
    "/private/var/lib/apt",
    "/private/var/stash",
    "/usr/sbin/sshd",
    "/usr/bin/ssh",
    "/Applications/Sileo.app",
    "/var/jb",
    "/var/jb/usr",
    "/var/jb/Library",
    "/var/jb/Applications/Sileo.app",
    "/.installed_unc0ver",
    "/var/binpack",
    "/cores/binpack",
    "/private/var/mobile/Library/Preferences/com.saurik.Cydia.plist",
    NULL,
};
#endif

static char g_extra_paths[MOBSHIELD_JB_MAX_EXTRA_PATHS][MOBSHIELD_JB_MAX_PATH_LEN];
static int g_extra_path_count = 0;

int mobshield_jb_set_extra_paths(const char* const* paths, int count) {
    g_extra_path_count = 0;
    if (paths == NULL || count <= 0) {
        return MOBSHIELD_JB_OK;
    }
    const int limit = count > MOBSHIELD_JB_MAX_EXTRA_PATHS ? MOBSHIELD_JB_MAX_EXTRA_PATHS : count;
    for (int i = 0; i < limit; ++i) {
        if (paths[i] == NULL || paths[i][0] == '\0') {
            continue;
        }
        strncpy(g_extra_paths[g_extra_path_count], paths[i], MOBSHIELD_JB_MAX_PATH_LEN - 1);
        g_extra_paths[g_extra_path_count][MOBSHIELD_JB_MAX_PATH_LEN - 1] = '\0';
        g_extra_path_count++;
    }
    return MOBSHIELD_JB_OK;
}

static int path_exists(const char* path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return 1;
    }
    if (access(path, F_OK) == 0) {
        return 1;
    }
    return 0;
}

static int check_path_list(const char* const* paths, char* evidence, int evidence_len) {
    for (int i = 0; paths[i] != NULL; ++i) {
        if (path_exists(paths[i])) {
            if (evidence != NULL && evidence_len > 0) {
                snprintf(evidence, (size_t)evidence_len, "path=%s", paths[i]);
            }
            return MOBSHIELD_JB_DETECTED;
        }
    }
    return MOBSHIELD_JB_OK;
}

int mobshield_jb_filesystem_paths(char* evidence, int evidence_len) {
    int code = check_path_list(k_default_paths, evidence, evidence_len);
    if (code == MOBSHIELD_JB_DETECTED) {
        return code;
    }
    for (int i = 0; i < g_extra_path_count; ++i) {
        if (path_exists(g_extra_paths[i])) {
            if (evidence != NULL && evidence_len > 0) {
                snprintf(evidence, (size_t)evidence_len, "path=%s", g_extra_paths[i]);
            }
            return MOBSHIELD_JB_DETECTED;
        }
    }
    return MOBSHIELD_JB_OK;
}
