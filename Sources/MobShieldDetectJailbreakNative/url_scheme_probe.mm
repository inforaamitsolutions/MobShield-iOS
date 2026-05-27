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

#include <cstdio>
#include <cstring>

#if __has_include(<TargetConditionals.h>)
#include <TargetConditionals.h>
#endif

#if TARGET_OS_IOS
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#endif

namespace {
void write_scheme(const char* scheme, char* evidence, int evidence_len) {
    if (evidence == nullptr || evidence_len <= 0) {
        return;
    }
    std::snprintf(evidence, static_cast<size_t>(evidence_len), "scheme=%s", scheme != nullptr ? scheme : "");
}

#if TARGET_OS_IOS
bool scheme_openable(UIApplication* app, const char* scheme) {
    if (app == nil || scheme == nullptr) {
        return false;
    }
    NSURL* url = [NSURL URLWithString:[NSString stringWithUTF8String:scheme]];
    if (url == nil) {
        return false;
    }
    return [app canOpenURL:url];
}

int probe_url_schemes(char* evidence, int evidence_len) {
    UIApplication* app = [UIApplication sharedApplication];
    if (app == nil) {
        return MOBSHIELD_JB_UNAVAILABLE;
    }
    if (scheme_openable(app, "cydia://")) {
        write_scheme("cydia://", evidence, evidence_len);
        return MOBSHIELD_JB_DETECTED;
    }
    if (scheme_openable(app, "sileo://")) {
        write_scheme("sileo://", evidence, evidence_len);
        return MOBSHIELD_JB_DETECTED;
    }
    if (scheme_openable(app, "zbra://")) {
        write_scheme("zbra://", evidence, evidence_len);
        return MOBSHIELD_JB_DETECTED;
    }
    if (scheme_openable(app, "filza://")) {
        write_scheme("filza://", evidence, evidence_len);
        return MOBSHIELD_JB_DETECTED;
    }
    return MOBSHIELD_JB_OK;
}
#endif
}  // namespace

int mobshield_jb_url_scheme_probe(char* evidence, int evidence_len) {
#if TARGET_OS_IOS
    if ([NSThread isMainThread]) {
        return probe_url_schemes(evidence, evidence_len);
    }

    __block int result = MOBSHIELD_JB_OK;
    dispatch_sync(dispatch_get_main_queue(), ^{
        result = probe_url_schemes(evidence, evidence_len);
    });
    return result;
#else
    (void)evidence;
    (void)evidence_len;
    return MOBSHIELD_JB_UNAVAILABLE;
#endif
}
