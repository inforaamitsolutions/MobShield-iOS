#
# Copyright 2025 MobShield Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

Pod::Spec.new do |s|
  s.name             = 'MobShield'
  s.version          = '1.0.1'
  s.summary          = 'MobShield iOS RASP library suite'
  s.description      = 'Runtime self-protection for iOS. See mobshield-spec/MOBSHIELD_SPEC.md.'
  s.homepage         = 'https://github.com/mobshield/mobshield-ios'
  s.license          = { :type => 'Apache License, Version 2.0', :file => 'LICENSE' }
  s.author           = { 'MobShield Contributors' => 'security@mobshield.dev' }
  s.source           = { :git => 'https://github.com/mobshield/mobshield-ios.git', :tag => s.version.to_s }
  s.ios.deployment_target = '15.0'
  s.swift_version = '5.10'

  s.default_subspec = 'Core'

  s.subspec 'CoreNative' do |native|
    native.source_files = 'Sources/MobShieldCoreNative/**/*.{h,mm}'
    native.public_header_files = 'Sources/MobShieldCoreNative/include/*.h'
    native.module_map = 'Sources/MobShieldCoreNative/include/module.modulemap'
    native.pod_target_xcconfig = {
      'HEADER_SEARCH_PATHS' => '$(PODS_TARGET_SRCROOT)/Sources/MobShieldCoreNative/include',
    }
  end

  s.subspec 'Core' do |core|
    core.source_files = 'Sources/MobShieldCore/**/*.swift'
    core.dependency 'MobShield/CoreNative'
  end

  s.subspec 'JailbreakNative' do |native|
    native.source_files = 'Sources/MobShieldDetectJailbreakNative/**/*.{h,c,mm}'
    native.public_header_files = 'Sources/MobShieldDetectJailbreakNative/include/*.h'
    native.module_map = 'Sources/MobShieldDetectJailbreakNative/include/module.modulemap'
    native.pod_target_xcconfig = {
      'HEADER_SEARCH_PATHS' => '$(PODS_TARGET_SRCROOT)/Sources/MobShieldDetectJailbreakNative/include',
      'OTHER_CFLAGS' => '-Wall -Werror',
      'OTHER_CPLUSPLUSFLAGS' => '-Wall -Werror',
    }
    native.frameworks = 'UIKit'
  end

  s.subspec 'Jailbreak' do |jb|
    jb.source_files = 'Sources/MobShieldDetectJailbreak/**/*.swift'
    jb.dependency 'MobShield/Core'
    jb.dependency 'MobShield/JailbreakNative'
  end

  s.subspec 'HooksNative' do |native|
    native.source_files = 'Sources/MobShieldDetectHooksNative/**/*.{h,c,mm}'
    native.public_header_files = 'Sources/MobShieldDetectHooksNative/include/*.h'
    native.module_map = 'Sources/MobShieldDetectHooksNative/include/module.modulemap'
    native.pod_target_xcconfig = {
      'HEADER_SEARCH_PATHS' => '$(PODS_TARGET_SRCROOT)/Sources/MobShieldDetectHooksNative/include',
      'OTHER_CFLAGS' => '-Wall -Werror',
      'OTHER_CPLUSPLUSFLAGS' => '-Wall -Werror',
    }
  end

  s.subspec 'Hooks' do |hk|
    hk.source_files = 'Sources/MobShieldDetectHooks/**/*.swift'
    hk.dependency 'MobShield/Core'
    hk.dependency 'MobShield/HooksNative'
  end

  s.subspec 'DebuggerNative' do |native|
    native.source_files = 'Sources/MobShieldDetectDebuggerNative/**/*.{h,c}'
    native.public_header_files = 'Sources/MobShieldDetectDebuggerNative/include/*.h'
    native.module_map = 'Sources/MobShieldDetectDebuggerNative/include/module.modulemap'
    native.pod_target_xcconfig = {
      'HEADER_SEARCH_PATHS' => '$(PODS_TARGET_SRCROOT)/Sources/MobShieldDetectDebuggerNative/include',
      'OTHER_CFLAGS' => '-Wall -Werror',
    }
  end

  s.subspec 'Debugger' do |db|
    db.source_files = 'Sources/MobShieldDetectDebugger/**/*.swift'
    db.dependency 'MobShield/Core'
    db.dependency 'MobShield/DebuggerNative'
  end

  s.subspec 'Environment' do |env|
    env.source_files = 'Sources/MobShieldDetectEnvironment/**/*.swift'
    env.dependency 'MobShield/Core'
  end

  s.subspec 'Integrity' do |int|
    int.source_files = 'Sources/MobShieldDetectIntegrity/**/*.swift'
    int.dependency 'MobShield/Core'
  end

  s.subspec 'All' do |all|
    all.dependency 'MobShield/Core'
    all.dependency 'MobShield/Jailbreak'
    all.dependency 'MobShield/Hooks'
    all.dependency 'MobShield/Debugger'
    all.dependency 'MobShield/Environment'
    all.dependency 'MobShield/Integrity'
  end

  s.script_phase = {
    :name => 'MobShield Personalize',
    :script => '"${PODS_TARGET_SRCROOT}/scripts/mobshield-personalize.sh"',
    :execution_position => :before_compile
  }
end
