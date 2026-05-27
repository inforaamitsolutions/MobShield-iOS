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

#include <cstdio>
#include <cstring>
#include <objc/runtime.h>

extern "C" {
const mobshield_hook_swizzle_baseline* mobshield_hook_get_swizzle_baselines(int* count);
}

namespace {
int check_method(
    const char* class_name,
    const char* selector_name,
    unsigned long long expected_imp,
    int has_expected_imp,
    char* evidence,
    int evidence_len) {
    if (class_name == nullptr || selector_name == nullptr) {
        return MOBSHIELD_HOOK_OK;
    }
    Class clazz = objc_getClass(class_name);
    if (clazz == nullptr) {
        return MOBSHIELD_HOOK_OK;
    }
    SEL sel = sel_registerName(selector_name);
    Method method = class_getInstanceMethod(clazz, sel);
    if (method == nullptr) {
        method = class_getClassMethod(clazz, sel);
    }
    if (method == nullptr) {
        return MOBSHIELD_HOOK_OK;
    }
    const IMP imp = method_getImplementation(method);
    if (has_expected_imp != 0) {
        if ((unsigned long long)(uintptr_t)imp != expected_imp) {
            if (evidence != nullptr && evidence_len > 0) {
                std::snprintf(
                    evidence,
                    static_cast<size_t>(evidence_len),
                    "class=%s sel=%s",
                    class_name,
                    selector_name);
            }
            return MOBSHIELD_HOOK_DETECTED;
        }
        return MOBSHIELD_HOOK_OK;
    }

    Class super_class = class_getSuperclass(clazz);
    if (super_class == nullptr) {
        return MOBSHIELD_HOOK_OK;
    }
    Method super_method = class_getInstanceMethod(super_class, sel);
    if (super_method == nullptr) {
        super_method = class_getClassMethod(super_class, sel);
    }
    if (super_method == nullptr) {
        return MOBSHIELD_HOOK_OK;
    }
    const IMP super_imp = method_getImplementation(super_method);
    if (imp != super_imp) {
        if (evidence != nullptr && evidence_len > 0) {
            std::snprintf(
                evidence,
                static_cast<size_t>(evidence_len),
                "class=%s sel=%s",
                class_name,
                selector_name);
        }
        return MOBSHIELD_HOOK_DETECTED;
    }
    return MOBSHIELD_HOOK_OK;
}
}  // namespace

int mobshield_hook_method_swizzle_detect(char* evidence, int evidence_len) {
    int count = 0;
    const mobshield_hook_swizzle_baseline* baselines = mobshield_hook_get_swizzle_baselines(&count);
    if (baselines != nullptr && count > 0) {
        for (int i = 0; i < count; ++i) {
            const int code = check_method(
                baselines[i].class_name,
                baselines[i].selector,
                baselines[i].expected_imp,
                baselines[i].has_expected_imp,
                evidence,
                evidence_len);
            if (code == MOBSHIELD_HOOK_DETECTED) {
                return code;
            }
        }
        return MOBSHIELD_HOOK_OK;
    }

    static const mobshield_hook_swizzle_baseline k_defaults[] = {
        {"NSString", "isEqualToString:", 0, 0},
        {"NSArray", "objectAtIndex:", 0, 0},
        {"NSDictionary", "objectForKey:", 0, 0},
        {"NSURL", "initWithString:", 0, 0},
    };
    for (size_t i = 0; i < sizeof(k_defaults) / sizeof(k_defaults[0]); ++i) {
        const int code = check_method(
            k_defaults[i].class_name,
            k_defaults[i].selector,
            k_defaults[i].expected_imp,
            k_defaults[i].has_expected_imp,
            evidence,
            evidence_len);
        if (code == MOBSHIELD_HOOK_DETECTED) {
            return code;
        }
    }
    return MOBSHIELD_HOOK_OK;
}
