#!/usr/bin/env python3
"""
framework detector - identifies app frameworks and generates appropriate hooks
supports; React Native, Flutter, Unity, Xamarin, Cordova, and more
"""

import re
import sys
import xml.etree.ElementTree as ET    
from pathlib import Path
from typing import Dict, List, Set, Optional
from dataclasses import dataclass
from enum import Enum

class FrameworkType(Enum):
    NATIVE_JAVA = "native_java"
    NATIVE_KOTLIN = "native_kotlin"
    REACT_NATIVE = "react_native"
    FLUTTER = "flutter"
    UNITY = "unity"
    UNREAL = "unreal"
    XAMARIN = "xamarin"
    CORDOVA = "cordova"
    IONIC = "ionic"
    COCOS2DX = "cocos2dx"
    WEBVIEW_HYBRID = "webview_hybrid"
    NATIVE_CPP = "native_cpp"

@dataclass
class FrameworkSignature:
    name: str
    framework_type: FrameworkType
    indicators: Dict[str, List[str]]  # file_patterns, package_patterns, lib_patterns
    confidence: float = 0.0

class FrameworkDetector:
    FRAMEWORK_SIGNATURES = {
        FrameworkType.REACT_NATIVE: {
            'packages': [
                'com.facebook.react',
                'com.facebook.hermes',
                'com.facebook.jni',
                'com.facebook.soloader'
            ],
            'libraries': [
                'libreactnativejni.so',
                'libhermes.so',
                'libjscexecutor.so',
                'libfb.so',
                'libreact_nativemodule_core.so'
            ],
            'files': [
                'assets/index.android.bundle',
                'assets/index.bundle',
                'res/raw/index.android.bundle'
            ],
            'strings': ['React Native', '__fbBatchedBridge']
        },
        FrameworkType.FLUTTER: {
            'packages': [
                'io.flutter',
                'io.flutter.embedding',
                'io.flutter.plugin'
            ],
            'libraries': [
                'libflutter.so',
                'libapp.so'
            ],
            'files': [
                'assets/flutter_assets',
                'lib/*/libflutter.so'
            ],
            'strings': ['Flutter', 'io.flutter']
        },
        FrameworkType.UNITY: {
            'packages': [
                'com.unity3d',
                'com.unity.purchasing'
            ],
            'libraries': [
                'libunity.so',
                'libmain.so',
                'libil2cpp.so'
            ],
            'files': [
                'assets/bin/Data',
                'lib/*/libunity.so'
            ],
            'strings': ['Unity', 'UnityEngine']
        },
        FrameworkType.XAMARIN: {
            'packages': [
                'mono.android',
                'xamarin.android',
                'mono.MonoRuntimeProvider'
            ],
            'libraries': [
                'libmonodroid.so',
                'libmonosgen-2.0.so',
                'libxamarin-app.so'
            ],
            'files': [
                'assemblies/*.dll'
            ],
            'strings': ['Xamarin', 'Mono.Android']
        },
        FrameworkType.CORDOVA: {
            'packages': [
                'org.apache.cordova',
                'org.apache.cordova.CordovaActivity'
            ],
            'libraries': [],
            'files': [
                'assets/www/cordova.js',
                'assets/www/index.html'
            ],
            'strings': ['cordova', 'Apache Cordova']
        },
        FrameworkType.IONIC: {
            'packages': [
                'org.apache.cordova',
                'io.ionic'
            ],
            'libraries': [],
            'files': [
                'assets/www/index.html',
                'assets/www/build/main.js'
            ],
            'strings': ['ionic', 'Ionic']
        },
        FrameworkType.COCOS2DX: {
            'packages': [
                'org.cocos2dx'
            ],
            'libraries': [
                'libcocos2d.so',
                'libcocos2dcpp.so'
            ],
            'files': [],
            'strings': ['cocos2d', 'Cocos2d-x']
        },
        FrameworkType.UNREAL: {
            'packages': [
                'com.epicgames'
            ],
            'libraries': [
                'libUE4.so',
                'libUnreal.so'
            ],
            'files': [],
            'strings': ['Unreal', 'UE4']
        }
    }
    
    def __init__(self, decompiled_dir: Path):
        self.decompiled_dir = decompiled_dir
        self.detected_frameworks: List[FrameworkSignature] = []
        
    def detect_all(self) -> List[FrameworkSignature]:
        for framework_type, signatures in self.FRAMEWORK_SIGNATURES.items():
            confidence = self._calculate_confidence(framework_type, signatures)
            if confidence > 0.3:
                sig = FrameworkSignature(
                    name=framework_type.value,
                    framework_type=framework_type,
                    indicators=signatures,
                    confidence=confidence
                )
                self.detected_frameworks.append(sig)
        
        if self._has_native_code():
            self.detected_frameworks.append(FrameworkSignature(
                name="native",
                framework_type=FrameworkType.NATIVE_JAVA,
                indicators={},
                confidence=1.0
            ))
        
        # sort by confidence
        self.detected_frameworks.sort(key=lambda x: x.confidence, reverse=True)
        
        return self.detected_frameworks
    
    def _calculate_confidence(self, framework_type: FrameworkType, signatures: Dict) -> float:
        score = 0.0
        max_score = 0.0
        
        if signatures.get('packages'):
            max_score += 0.4
            if self._check_packages(signatures['packages']):
                score += 0.4
        if signatures.get('libraries'):
            max_score += 0.3
            found_libs = self._check_libraries(signatures['libraries'])
            score += 0.3 * (found_libs / len(signatures['libraries']))
        if signatures.get('files'):
            max_score += 0.2
            if self._check_files(signatures['files']):
                score += 0.2
        if signatures.get('strings'):
            max_score += 0.1
            if self._check_strings(signatures['strings']):
                score += 0.1
        return score / max_score if max_score > 0 else 0.0
    
    def _check_packages(self, packages: List[str]) -> bool:
        for smali_dir in self.decompiled_dir.glob('smali*'):
            for package in packages:
                package_path = smali_dir / package.replace('.', '/')
                if package_path.exists():
                    return True
        return False
    
    def _check_libraries(self, libraries: List[str]) -> int:
        lib_dir = self.decompiled_dir / 'lib'
        if not lib_dir.exists():
            return 0
        
        found = 0
        for lib in libraries:
            if list(lib_dir.rglob(lib)):
                found += 1
        return found
    
    def _check_files(self, files: List[str]) -> bool:
        for file_pattern in files:
            if list(self.decompiled_dir.glob(file_pattern)):
                return True
        return False
    
    def _check_strings(self, strings: List[str]) -> bool:
        # simple check - could be enhanced
        for smali_dir in self.decompiled_dir.glob('smali*'):
            for smali_file in list(smali_dir.rglob('*.smali'))[:100]:
                try:
                    content = smali_file.read_text(encoding='utf-8', errors='ignore')
                    if any(s in content for s in strings):
                        return True
                except:
                    continue
        return False
    
    def _has_native_code(self) -> bool:
        for smali_dir in self.decompiled_dir.glob('smali*'):
            if list(smali_dir.rglob('*.smali')):
                return True
        return False

class HookGenerator:
    def __init__(self, frameworks: List[FrameworkSignature]):
        self.frameworks = frameworks
        
    def generate_hooks(self) -> str:
        needs_java = any(f.framework_type != FrameworkType.NATIVE_JAVA for f in self.frameworks)
        
        if needs_java:
            script = """// auto-generated for multiple frameworks
// compatible with Frida 17+

import Java from 'frida-java-bridge';

declare const Module: any;
declare const Interceptor: any;
declare const Process: any;
declare const Memory: any;

console.log('[*] Detected frameworks: """ + ', '.join(f.name for f in self.frameworks) + """');
"""
        else:
            script = """// auto-generated native hooks
// compatible with Frida 17+

console.log('[*] Detected frameworks: """ + ', '.join(f.name for f in self.frameworks) + """');
"""
        
        for framework in self.frameworks:
            if framework.framework_type == FrameworkType.REACT_NATIVE:
                script += self._generate_react_native_hooks()
            elif framework.framework_type == FrameworkType.FLUTTER:
                script += self._generate_flutter_hooks()
            elif framework.framework_type == FrameworkType.UNITY:
                script += self._generate_unity_hooks()
            elif framework.framework_type == FrameworkType.XAMARIN:
                script += self._generate_xamarin_hooks()
            elif framework.framework_type == FrameworkType.CORDOVA:
                script += self._generate_cordova_hooks()
            elif framework.framework_type == FrameworkType.NATIVE_JAVA:
                script += self._generate_native_hooks()
        
        # add native hooks only if not already added
        if not any(f.framework_type == FrameworkType.NATIVE_JAVA for f in self.frameworks):
            script += self._generate_native_hooks()
        
        return script
    
    def _generate_react_native_hooks(self) -> str:
        return """
console.log('[*] Initializing React Native hooks.');
Java.perform(() => {
    try {
        const CatalystInstanceImpl = Java.use('com.facebook.react.bridge.CatalystInstanceImpl');
        CatalystInstanceImpl.jniCallJSFunction.implementation = function(module, method, args) {
            console.log(`[RN] JS Call: ${module}.${method}()`);
            send({type: 'react_native', action: 'js_call', module: module, method: method});
            return this.jniCallJSFunction(module, method, args);
        };
        const NativeModuleRegistry = Java.use('com.facebook.react.bridge.NativeModuleRegistry');
        NativeModuleRegistry.getModule.implementation = function(name) {
            console.log(`[RN] Native Module accessed: ${name}`);
            return this.getModule(name);
        };
        console.log('[✓] React Native hooks');
    } catch (e) {
        console.log(`[-] React Native hooks error: ${e}`);
    }
});

const hermesLib = Module.findExportByName('libhermes.so', '_ZN6hermes2vm7Runtime6createERKNS0_12RuntimeConfigE');
if (hermesLib) {
    Interceptor.attach(hermesLib, {
"""
    
    def _generate_flutter_hooks(self) -> str:
        return """
console.log('[*] Initializing Flutter hooks.');
const flutterLib = Module.findExportByName('libflutter.so', '_ZN7flutter11DartIsolate10InitializeEv');
if (flutterLib) {
    Interceptor.attach(flutterLib, {
        onEnter: function(args) {
            console.log('[Flutter] Dart Isolate initialized');
            send({type: 'flutter', action: 'isolate_init'});
        }
    });
}
console.log('[*] Initializing Flutter hooks.');
Java.perform(() => {
    try {
        const MethodChannel = Java.use('io.flutter.plugin.common.MethodChannel');
        MethodChannel.invokeMethod.overload('java.lang.String', 'java.lang.Object').implementation = function(method, args) {
            console.log(`[Flutter] Method Channel: ${method}`);
            send({type: 'flutter', action: 'method_channel', method: method, args: args});
            return this.invokeMethod(method, args);
        };
        console.log('[✓] Flutter hooks');
    } catch (e) {
        console.log(`[-] Flutter hooks error: ${e}`);
    }
});
"""
    
    def _generate_unity_hooks(self) -> str:
        return """
console.log('[*] Initializing Unity hooks.');
const unityLib = Process.findModuleByName('libunity.so');
if (unityLib) {
    const il2cppInit = Module.findExportByName('libil2cpp.so', 'il2cpp_init');
    if (il2cppInit) {
        Interceptor.attach(il2cppInit, {
            onEnter: function(args) {
                console.log('[Unity] IL2CPP initialized');
                send({type: 'unity', action: 'il2cpp_init'});
            }
        });
    }
    const playerLoop = Module.findExportByName('libunity.so', '_ZN5Unity11PlayerLoop7RunLoopEv');
    if (playerLoop) {
        console.log('[Unity] Player loop hooked');
    }
}
Java.perform(() => {
    try {
        const UnityPlayer = Java.use('com.unity3d.player.UnityPlayer');
        UnityPlayer.UnitySendMessage.implementation = function(gameObject, method, message) {
            console.log(`[Unity] SendMessage: ${gameObject}.${method}(${message})`);
            send({type: 'unity', action: 'send_message', object: gameObject, method: method});
            return this.UnitySendMessage(gameObject, method, message);
        };
        console.log('[✓] Unity hooks');
    } catch (e) {
        console.log(`[-] Unity hooks error: ${e}`);
    }
});
"""
    
    def _generate_xamarin_hooks(self) -> str:
        return """
console.log('[*] Initializing Xamarin hooks.');
Java.perform(() => {
    try {
        const MonoRuntime = Java.use('mono.MonoRuntimeProvider');
        console.log('[Xamarin] Mono runtime detected');

        const Assembly = Java.use('mono.android.Runtime');
        console.log('[✓] Xamarin hooks');
    } catch (e) {
        console.log(`[-] Xamarin hooks error: ${e}`);
    }
});
const monoLib = Module.findExportByName('libmonosgen-2.0.so', 'mono_jit_init_version');
if (monoLib) {
    Interceptor.attach(monoLib, {
        onEnter: function(args) {
            console.log('[Xamarin] Mono JIT initialized');
            send({type: 'xamarin', action: 'mono_init'});
        }
    });
}
"""
    
    def _generate_cordova_hooks(self) -> str:
        return """
console.log('[*] Initializing Cordova hooks.');
Java.perform(() => {
    try {
        const CordovaWebView = Java.use('org.apache.cordova.CordovaWebView');
        const CordovaPlugin = Java.use('org.apache.cordova.CordovaPlugin');
        
        CordovaPlugin.execute.implementation = function(action, args, callbackContext) {
            console.log(`[Cordova] Plugin execute: ${action}`);
            send({type: 'cordova', action: 'plugin_execute', plugin_action: action});
            return this.execute(action, args, callbackContext);
        };
        
        console.log('[✓] Cordova hooks');
    } catch (e) {
        console.log(`[-] Cordova hooks error: ${e}`);
    }
});
"""
    
    
    def _generate_native_hooks(self) -> str:
        return """
console.log('[*] Installing native hooks.');

const libc_functions = ['fopen', 'open', 'read', 'write', 'connect', 'send', 'recv'];
for (const funcName of libc_functions) {
    const funcPtr = (Module as any).findExportByName('libc.so', funcName);
    if (funcPtr) {
        (Interceptor as any).attach(funcPtr, {
            onEnter: function(args: any) {
                if (funcName === 'fopen' || funcName === 'open') {
                    try {
                        const path = args[0].readUtf8String();
                        if (path && !path.includes('/dev/') && !path.includes('/proc/')) {
                            console.log(`[native] ${funcName}(\"${path}\")`);
                            (send as any)({type: 'native', func: funcName, path: path, timestamp: Date.now()});
                        }
                    } catch (e) {
                        // ignore
                    }
                }
            }
        });
    }
}

const ssl_functions = ['SSL_read', 'SSL_write', 'SSL_connect'];
for (const funcName of ssl_functions) {
    const funcPtr = (Module as any).findExportByName('libssl.so', funcName);
    if (funcPtr) {
        (Interceptor as any).attach(funcPtr, {
            onEnter: function(args: any) {
                console.log(`[ssl] ${funcName} called`);
                (send as any)({type: 'ssl', func: funcName, timestamp: Date.now()});
            }
        });
    }
}

console.log('[*] try to interact with the app to see results');
"""


def extract_package_name(decompiled_dir: Path) -> Optional[str]:
    manifest_path = decompiled_dir / 'AndroidManifest.xml'
    if not manifest_path.exists():
        return None
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        return root.get('package')
    except Exception:
        return None
        
if __name__ == '__main__':
    if len(sys.argv) < 2:
        script_dir = Path(__file__).parent.parent
        decompiled_dir = script_dir / 'data' / 'base_decompiled'
        
        if not decompiled_dir.exists():
            print("Usage: python framework_detector.py <decompiled_apk_dir>")
            print("   or: python framework_detector.py  (uses data/base_decompiled)")
            sys.exit(1)
    else:
        decompiled_dir = Path(sys.argv[1])
    
    package_name = extract_package_name(decompiled_dir)
    if package_name:
        print(f"[*] package: {package_name}")
    
    detector = FrameworkDetector(decompiled_dir)
    frameworks = detector.detect_all()
    
    if not frameworks:
        print("[!] no frameworks detected")
        sys.exit(1)
    
    for fw in frameworks:
        bar = "█" * int(fw.confidence * 20)
        print(f"  {fw.name:20} {bar} {fw.confidence:.1%}")
    
    generator = HookGenerator(frameworks)
    script = generator.generate_hooks()
    
    output_file = Path(__file__).parent / 'hooks' / 'generated_hooks.ts'
    output_file.write_text(script)
    
    if package_name:
        print(f"\n[*] compile: npx frida-compile {output_file.name} -o generated_hooks.js")
        print(f"[*] run: frida -U -f {package_name} -l src/hooks/generated_hooks.js")
    
    print()