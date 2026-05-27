// swift-tools-version: 5.10
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

import PackageDescription

// Binary SwiftPM consumers: after each v*.*.* release, add binaryTarget entries with
// GitHub Release zip URLs and checksums (swift package compute-checksum). See docs/versioning.md.

let package = Package(
    name: "MobShield",
    platforms: [
        .iOS(.v15),
    ],
    products: [
        .library(name: "MobShieldCore", targets: ["MobShieldCore"]),
        .library(name: "MobShieldDetectJailbreak", targets: ["MobShieldDetectJailbreak"]),
        .library(name: "MobShieldDetectHooks", targets: ["MobShieldDetectHooks"]),
        .library(name: "MobShieldDetectDebugger", targets: ["MobShieldDetectDebugger"]),
        .library(name: "MobShieldDetectEnvironment", targets: ["MobShieldDetectEnvironment"]),
        .library(name: "MobShieldDetectIntegrity", targets: ["MobShieldDetectIntegrity"]),
    ],
    targets: [
        .target(
            name: "MobShieldCoreNative",
            path: "Sources/MobShieldCoreNative",
            sources: ["mobshield_native.mm"],
            publicHeadersPath: "include",
            cxxSettings: [
                .headerSearchPath("include"),
            ]
        ),
        .target(
            name: "MobShieldCore",
            dependencies: ["MobShieldCoreNative"],
            path: "Sources/MobShieldCore"
        ),
        .target(
            name: "MobShieldDetectJailbreakNative",
            path: "Sources/MobShieldDetectJailbreakNative",
            sources: [
                "dyld_image_scan.mm",
                "dyld_get_image_header_inspect.mm",
                "url_scheme_probe.mm",
                "filesystem_paths.c",
                "sandbox_escape.c",
                "write_test.c",
                "symlink_test.c",
                "sysctl_traced.c",
            ],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("include"),
                .unsafeFlags(["-Wall", "-Werror"]),
            ],
            cxxSettings: [
                .headerSearchPath("include"),
                .unsafeFlags(["-Wall", "-Werror"]),
            ],
            linkerSettings: [
                .linkedFramework("UIKit", .when(platforms: [.iOS])),
            ]
        ),
        .target(
            name: "MobShieldDetectJailbreak",
            dependencies: ["MobShieldCore", "MobShieldDetectJailbreakNative"],
            path: "Sources/MobShieldDetectJailbreak"
        ),
        .target(
            name: "MobShieldDetectHooksNative",
            path: "Sources/MobShieldDetectHooksNative",
            sources: [
                "mach_region_inspect.c",
                "frida_artifact_scan.c",
                "frida_port_probe.c",
                "dyld_environment_scan.c",
                "hook_baseline_store.c",
                "function_prologue_inspect.mm",
                "method_swizzle_detect.mm",
            ],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("include"),
                .unsafeFlags(["-Wall", "-Werror"]),
            ],
            cxxSettings: [
                .headerSearchPath("include"),
                .unsafeFlags(["-Wall", "-Werror"]),
            ],
            linkerSettings: [
                .linkedLibrary("objc"),
            ]
        ),
        .target(
            name: "MobShieldDetectHooks",
            dependencies: ["MobShieldCore", "MobShieldDetectHooksNative"],
            path: "Sources/MobShieldDetectHooks"
        ),
        .target(
            name: "MobShieldDetectDebuggerNative",
            path: "Sources/MobShieldDetectDebuggerNative",
            sources: [
                "sysctl_ptraced.c",
                "ptrace_deny_attach.c",
                "mach_exception_check.c",
                "timing_check.c",
            ],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("include"),
                .unsafeFlags(["-Wall", "-Werror"]),
            ],
        ),
        .target(
            name: "MobShieldDetectDebugger",
            dependencies: ["MobShieldCore", "MobShieldDetectDebuggerNative"],
            path: "Sources/MobShieldDetectDebugger"
        ),
        .target(
            name: "MobShieldDetectEnvironment",
            dependencies: ["MobShieldCore"],
            path: "Sources/MobShieldDetectEnvironment"
        ),
        .target(
            name: "MobShieldDetectIntegrity",
            dependencies: ["MobShieldCore"],
            path: "Sources/MobShieldDetectIntegrity",
            linkerSettings: [
                .linkedFramework("Security"),
            ]
        ),
        .testTarget(
            name: "MobShieldDetectIntegrityTests",
            dependencies: ["MobShieldDetectIntegrity", "MobShieldCore"]
        ),
        .testTarget(
            name: "MobShieldCoreTests",
            dependencies: ["MobShieldCore"]
        ),
        .testTarget(
            name: "MobShieldDetectJailbreakTests",
            dependencies: ["MobShieldDetectJailbreak", "MobShieldCore"]
        ),
        .testTarget(
            name: "MobShieldDetectHooksTests",
            dependencies: ["MobShieldDetectHooks", "MobShieldCore"]
        ),
        .testTarget(
            name: "MobShieldDetectDebuggerTests",
            dependencies: ["MobShieldDetectDebugger", "MobShieldCore"]
        ),
    ]
)
