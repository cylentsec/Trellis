"""
Frida script generator for iOS jailbreak detection hooks.

This module provides specialized hook generation for jailbreak detection techniques
including file system checks, process manipulation detection, and runtime environment
validation. It can optionally include bypass code to hide jailbreak indicators.

Example usage:
    >>> from trellis.generators.frida.jailbreak import generate_jailbreak_script
    >>>
    >>> # Generate detection-only script
    >>> script = generate_jailbreak_script("MyApp", include_bypass=False)
    >>>
    >>> # Generate script with bypass capabilities
    >>> script_with_bypass = generate_jailbreak_script("MyApp", include_bypass=True)
"""

from typing import Optional

from ...signatures import load_category, FunctionSignature
from .base import combine_hooks


# Jailbreak-specific constants and helper functions
JAILBREAK_CONSTANTS = """
// Jailbreak Detection Constants

// Common jailbreak file paths
const JAILBREAK_PATHS = [
    '/Applications/Cydia.app',
    '/Applications/Sileo.app',
    '/Applications/Zebra.app',
    '/Applications/FakeCarrier.app',
    '/Applications/Icy.app',
    '/Applications/blackra1n.app',
    '/Applications/IntelliScreen.app',
    '/Applications/MxTube.app',
    '/Applications/RockApp.app',
    '/Applications/SBSettings.app',
    '/Applications/WinterBoard.app',
    '/Library/MobileSubstrate/MobileSubstrate.dylib',
    '/Library/MobileSubstrate/DynamicLibraries',
    '/bin/bash',
    '/bin/sh',
    '/usr/sbin/sshd',
    '/usr/bin/ssh',
    '/usr/bin/sshd',
    '/usr/libexec/ssh-keysign',
    '/usr/libexec/sftp-server',
    '/etc/apt',
    '/etc/ssh/sshd_config',
    '/private/var/lib/apt',
    '/private/var/lib/cydia',
    '/private/var/mobile/Library/SBSettings/Themes',
    '/private/var/tmp/cydia.log',
    '/private/var/stash',
    '/usr/lib/libsubstrate.dylib',
    '/usr/lib/libhooker.dylib',
    '/usr/lib/libsubstitute.dylib',
    '/usr/lib/substrate',
    '/Library/PreferenceBundles/CydiaSettings.bundle',
    '/System/Library/LaunchDaemons/com.ikey.bbot.plist',
    '/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist',
    '/var/cache/apt',
    '/var/lib/dpkg',
    '/var/lib/apt',
    '/usr/share/jailbreak',
    '/Library/Frameworks/CydiaSubstrate.framework',
    '/.installed_unc0ver',
    '/.bootstrapped_electra',
    '/usr/lib/libjailbreak.dylib',
    '/jb/',
    '/chimera/',
    '/electra/',
    '/private/jailbreak.txt',
    '/private/.cydia_no_stash'
];

// Jailbreak-related dylibs
const JAILBREAK_DYLIBS = [
    'MobileSubstrate',
    'substrate',
    'cycript',
    'frida',
    'libhooker',
    'substitute',
    'SSLKillSwitch',
    'PreferenceLoader',
    'AppList',
    'rocketbootstrap',
    'Shadow',
    'Liberty',
    'FlyJB',
    'Choicy',
    'HideJB'
];

// Jailbreak URL schemes
const JAILBREAK_URL_SCHEMES = [
    'cydia://',
    'sileo://',
    'zbra://',
    'undecimus://',
    'filza://',
    'activator://',
    'installer://',
    'chimera://',
    'electra://',
    'unc0ver://',
    'ifile://',
    'barrel://',
    'appsync://'
];

// Access mode constants
const R_OK = 4;  // Read permission
const W_OK = 2;  // Write permission
const X_OK = 1;  // Execute permission
const F_OK = 0;  // File exists

// Helper: Check if path matches known jailbreak paths
function isJailbreakPath(path) {
    if (!path || path.isNull || path.isNull()) return false;
    var pathStr = (typeof path === 'string') ? path : path.readUtf8String();
    if (!pathStr) return false;

    // Exact match
    for (var i = 0; i < JAILBREAK_PATHS.length; i++) {
        if (pathStr === JAILBREAK_PATHS[i]) return true;
    }

    // Substring match for directories
    var suspiciousSubstrings = [
        '/cydia', '/substrate', '/Library/MobileSubstrate',
        '/Applications/Cydia', '/private/var/lib/apt',
        '/private/var/lib/cydia', '/.bootstrapped'
    ];

    for (var i = 0; i < suspiciousSubstrings.length; i++) {
        if (pathStr.toLowerCase().indexOf(suspiciousSubstrings[i].toLowerCase()) !== -1) {
            return true;
        }
    }

    return false;
}

// Helper: Check if library path indicates jailbreak
function isJailbreakDylib(path) {
    if (!path || path.isNull || path.isNull()) return false;
    var pathStr = (typeof path === 'string') ? path : path.readUtf8String();
    if (!pathStr) return false;

    var pathLower = pathStr.toLowerCase();

    for (var i = 0; i < JAILBREAK_DYLIBS.length; i++) {
        if (pathLower.indexOf(JAILBREAK_DYLIBS[i].toLowerCase()) !== -1) {
            return true;
        }
    }

    return false;
}

// Helper: Extract path string from argument
function getPathString(arg) {
    if (!arg || arg.isNull()) return null;
    try {
        // Try to read as C string
        return arg.readUtf8String();
    } catch (e) {
        // Try to read as ObjC object
        try {
            var obj = new ObjC.Object(arg);
            return obj.toString();
        } catch (e2) {
            return null;
        }
    }
}

// Helper: Check if URL scheme is jailbreak-related
function isJailbreakURLScheme(url) {
    if (!url) return false;
    var urlStr = (typeof url === 'string') ? url : getPathString(url);
    if (!urlStr) return false;

    for (var i = 0; i < JAILBREAK_URL_SCHEMES.length; i++) {
        if (urlStr.indexOf(JAILBREAK_URL_SCHEMES[i]) !== -1) {
            return true;
        }
    }

    return false;
}

// BYPASS HELPERS (only included with include_bypass=True)

// Return failure for file operations
function bypassFileCheck() {
    return -1;  // File not found
}

// Return null for pointer operations
function bypassPointerCheck() {
    return ptr(0);  // NULL pointer
}

// Return empty/safe environment variable
function bypassEnvCheck() {
    return ptr(0);  // NULL (variable not set)
}

// Return safe UID (mobile user)
function bypassUIDCheck() {
    return 501;  // Standard mobile user UID
}
"""


def _generate_file_check_hook(signature: FunctionSignature, include_bypass: bool) -> str:
    """Generate specialized hook for file check functions (stat, lstat, access, fopen, open)."""
    func_name = signature.name
    library = signature.library

    # Find the path parameter (usually first parameter)
    path_param_idx = 0
    for i, param in enumerate(signature.parameters):
        if 'path' in param.name.lower() or 'filename' in param.name.lower() or 'dirname' in param.name.lower():
            path_param_idx = i
            break

    # Determine the bypass return value based on function
    bypass_logic = ""
    if include_bypass:
        if func_name in ['stat', 'lstat', 'access', 'open', 'opendir', 'statfs']:
            bypass_logic = """
                // BYPASS: Return failure for jailbreak paths
                if (isJailbreakPath(pathStr)) {
                    console.log("  [!] BYPASS: Returning -1 (file not found)");
                    retval.replace(-1);
                }"""
        elif func_name == 'fopen':
            bypass_logic = """
                // BYPASS: Return NULL for jailbreak paths
                if (isJailbreakPath(pathStr)) {
                    console.log("  [!] BYPASS: Returning NULL (file not found)");
                    retval.replace(ptr(0));
                }"""

    hook_code = f'''
// Hook: {func_name} (File Check)
(function() {{
    var funcPtr = findExport("{func_name}", "{library}");

    if (funcPtr) {{
        console.log("[*] Hooking {func_name} at", funcPtr);

        Interceptor.attach(funcPtr, {{
            onEnter: function(args) {{
                var pathStr = getPathString(args[{path_param_idx}]);
                this.pathStr = pathStr;
                this.isJailbreakCheck = isJailbreakPath(pathStr);

                if (this.isJailbreakCheck) {{
                    console.log("\\n[!!!] {func_name} - JAILBREAK PATH DETECTED [!!!]");
                    console.log("  [!] Path:", pathStr);
                }} else {{
                    console.log("\\n[+] {func_name} called");
                    console.log("  [0] path:", pathStr);
                }}

                // Log additional parameters
'''

    # Add logging for other parameters
    for i, param in enumerate(signature.parameters):
        if i == path_param_idx:
            continue  # Already logged the path
        if 'path' not in param.name.lower() and 'filename' not in param.name.lower():
            if param.type == 'int':
                hook_code += f'''                console.log("  [{i}] {param.name}:", args[{i}].toInt32());
'''
            elif 'char*' in param.type:
                hook_code += f'''                var param{i} = getPathString(args[{i}]);
                if (param{i}) console.log("  [{i}] {param.name}:", param{i});
'''

    hook_code += '''
                // Backtrace with Ghidra addresses
                if (this.isJailbreakCheck) {
                    var mainModule = getMainAppModule();
                    console.log("  [!] Backtrace (JAILBREAK CHECK, BN = Ghidra offset):");
                    console.log(formatBacktrace(this.context, mainModule, 5));
                }
            },
            onLeave: function(retval) {
                if (this.isJailbreakCheck) {
                    console.log("  [!] Original Return:", retval);
'''

    if bypass_logic:
        hook_code += bypass_logic

    hook_code += '''
                } else {
                    console.log("  => Return:", retval);
                }
            }
        });
    } else {
        console.log("[-] {func_name} not found in {library}");
    }
}})();
'''.replace('{func_name}', func_name).replace('{library}', library)

    return hook_code


def _generate_process_hook(signature: FunctionSignature, include_bypass: bool) -> str:
    """Generate specialized hook for process functions (fork, vfork, system, popen, execve)."""
    func_name = signature.name
    library = signature.library

    # Determine bypass logic
    bypass_logic = ""
    if include_bypass:
        if func_name in ['fork', 'vfork']:
            bypass_logic = """
                // BYPASS: Return -1 (fork not allowed)
                console.log("  [!] BYPASS: Returning -1 (fork failed)");
                retval.replace(-1);"""
        elif func_name == 'system':
            bypass_logic = """
                // BYPASS: Return -1 (command failed)
                console.log("  [!] BYPASS: Returning -1 (command failed)");
                retval.replace(-1);"""
        elif func_name == 'popen':
            bypass_logic = """
                // BYPASS: Return NULL (command failed)
                console.log("  [!] BYPASS: Returning NULL");
                retval.replace(ptr(0));"""
        elif func_name == 'execve':
            bypass_logic = """
                // BYPASS: Return -1 (exec failed)
                console.log("  [!] BYPASS: Returning -1 (exec failed)");
                retval.replace(-1);"""

    hook_code = f'''
// Hook: {func_name} (Process Manipulation - CRITICAL)
(function() {{
    var funcPtr = findExport("{func_name}", "{library}");

    if (funcPtr) {{
        console.log("[*] Hooking {func_name} at", funcPtr);

        Interceptor.attach(funcPtr, {{
            onEnter: function(args) {{
                console.log("\\n[!!!] {func_name} - CRITICAL JAILBREAK CHECK [!!!]");
                console.log("  [!] This should FAIL on non-jailbroken devices!");
'''

    # Add parameter logging
    for i, param in enumerate(signature.parameters):
        if 'char*' in param.type and 'const' in param.type:
            hook_code += f'''                var param{i} = getPathString(args[{i}]);
                if (param{i}) console.log("  [{i}] {param.name}:", param{i});
'''
        elif param.type != 'variadic':
            hook_code += f'''                console.log("  [{i}] {param.name}:", args[{i}]);
'''

    hook_code += '''
                // Backtrace with Ghidra addresses
                var mainModule = getMainAppModule();
                console.log("  [!] Backtrace (BN = Ghidra offset):");
                console.log(formatBacktrace(this.context, mainModule, 5));
            },
            onLeave: function(retval) {
                console.log("  [!] Original Return:", retval);
'''

    if bypass_logic:
        hook_code += bypass_logic

    hook_code += '''
            }
        });
    } else {
        console.log("[-] {func_name} not found in {library}");
    }
}})();
'''.replace('{func_name}', func_name).replace('{library}', library)

    return hook_code


def _generate_dylib_hook(signature: FunctionSignature, include_bypass: bool) -> str:
    """Generate specialized hook for dynamic library functions (dlopen, dyld_get_image_name, _dyld_image_count)."""
    func_name = signature.name
    library = signature.library

    bypass_logic = ""
    if include_bypass and func_name == 'dlopen':
        bypass_logic = """
                // BYPASS: Return NULL for jailbreak libraries
                if (this.isJailbreakLib) {
                    console.log("  [!] BYPASS: Returning NULL (library not found)");
                    retval.replace(ptr(0));
                }"""
    elif include_bypass and func_name == '_dyld_get_image_name':
        bypass_logic = """
                // BYPASS: Return NULL for jailbreak libraries
                if (retval && !retval.isNull()) {
                    var libPath = retval.readUtf8String();
                    if (isJailbreakDylib(libPath)) {
                        console.log("  [!] BYPASS: Hiding jailbreak library:", libPath);
                        retval.replace(ptr(0));
                    }
                }"""

    hook_code = f'''
// Hook: {func_name} (Library Loading)
(function() {{
    var funcPtr = findExport("{func_name}", "{library}");

    if (funcPtr) {{
        console.log("[*] Hooking {func_name} at", funcPtr);

        Interceptor.attach(funcPtr, {{
            onEnter: function(args) {{
'''

    if func_name == 'dlopen':
        hook_code += '''                var libPath = getPathString(args[0]);
                this.libPath = libPath;
                this.isJailbreakLib = isJailbreakDylib(libPath);

                if (this.isJailbreakLib) {
                    console.log("\\n[!!!] dlopen - JAILBREAK LIBRARY DETECTED [!!!]");
                    console.log("  [!] Library:", libPath);
                } else {
                    console.log("\\n[+] dlopen called");
                    console.log("  [0] path:", libPath);
                }
                console.log("  [1] mode:", args[1].toInt32());
'''
    elif func_name == '_dyld_get_image_name':
        hook_code += '''                console.log("\\n[+] _dyld_get_image_name called");
                console.log("  [0] index:", args[0].toInt32());
                this.index = args[0].toInt32();
'''
    else:
        hook_code += f'''                console.log("\\n[+] {func_name} called");
'''

    hook_code += '''            },
            onLeave: function(retval) {
'''

    if func_name == '_dyld_get_image_name':
        hook_code += '''                if (retval && !retval.isNull()) {
                    var libPath = retval.readUtf8String();
                    if (isJailbreakDylib(libPath)) {
                        console.log("  [!!!] JAILBREAK LIBRARY FOUND [!!!]");
                        console.log("  [!] Index:", this.index);
                        console.log("  [!] Library:", libPath);
                    } else {
                        console.log("  => Library:", libPath);
                    }
'''
        if bypass_logic:
            hook_code += bypass_logic
        hook_code += '''                } else {
                    console.log("  => Return: NULL");
                }
'''
    elif func_name == 'dlopen':
        hook_code += '''                if (this.isJailbreakLib) {
                    console.log("  [!] Original Return:", retval);
'''
        if bypass_logic:
            hook_code += bypass_logic
        hook_code += '''                } else {
                    console.log("  => Return:", retval);
                }
'''
    else:
        hook_code += '''                console.log("  => Return:", retval);
'''

    hook_code += '''            }
        });
    } else {
        console.log("[-] {func_name} not found in {library}");
    }
}})();
'''.replace('{func_name}', func_name).replace('{library}', library)

    return hook_code


def _generate_env_hook(signature: FunctionSignature, include_bypass: bool) -> str:
    """Generate specialized hook for environment variable functions (getenv, setenv)."""
    func_name = signature.name
    library = signature.library

    bypass_logic = ""
    if include_bypass and func_name == 'getenv':
        bypass_logic = """
                // BYPASS: Return NULL for DYLD_INSERT_LIBRARIES
                if (this.isSuspicious) {
                    console.log("  [!] BYPASS: Returning NULL (variable not set)");
                    retval.replace(ptr(0));
                }"""

    hook_code = f'''
// Hook: {func_name} (Environment Variables)
(function() {{
    var funcPtr = findExport("{func_name}", "{library}");

    if (funcPtr) {{
        console.log("[*] Hooking {func_name} at", funcPtr);

        Interceptor.attach(funcPtr, {{
            onEnter: function(args) {{
                var varName = getPathString(args[0]);
                this.varName = varName;

                // Check for suspicious environment variables
                var suspicious = ['DYLD_INSERT_LIBRARIES', '_MSSafeMode', '_SafeMode',
                                'DYLD_LIBRARY_PATH', 'DYLD_FRAMEWORK_PATH'];
                this.isSuspicious = false;
                for (var i = 0; i < suspicious.length; i++) {{
                    if (varName === suspicious[i]) {{
                        this.isSuspicious = true;
                        break;
                    }}
                }}

                if (this.isSuspicious) {{
                    console.log("\\n[!!!] {func_name} - JAILBREAK ENV CHECK [!!!]");
                    console.log("  [!] Variable:", varName);
                }} else {{
                    console.log("\\n[+] {func_name} called");
                    console.log("  [0] name:", varName);
                }}
'''

    if func_name == 'setenv':
        hook_code += '''                var value = getPathString(args[1]);
                console.log("  [1] value:", value);
                console.log("  [2] overwrite:", args[2].toInt32());
'''

    hook_code += '''            },
            onLeave: function(retval) {
'''

    if func_name == 'getenv':
        hook_code += '''                if (retval && !retval.isNull()) {
                    var value = retval.readUtf8String();
                    if (this.isSuspicious) {
                        console.log("  [!!!] SUSPICIOUS VALUE FOUND [!!!]");
                        console.log("  [!] " + this.varName + " = " + value);
'''
        if bypass_logic:
            hook_code += bypass_logic
        hook_code += '''                    } else {
                        console.log("  => Value:", value);
                    }
                } else {
                    console.log("  => Return: NULL (not set)");
                }
'''
    else:
        hook_code += '''                console.log("  => Return:", retval.toInt32());
'''

    hook_code += '''            }
        });
    } else {
        console.log("[-] {func_name} not found in {library}");
    }
}})();
'''.replace('{func_name}', func_name).replace('{library}', library)

    return hook_code


def _generate_uid_hook(signature: FunctionSignature, include_bypass: bool) -> str:
    """Generate specialized hook for UID/GID functions (getuid, geteuid, getgid, getegid)."""
    func_name = signature.name
    library = signature.library

    bypass_logic = ""
    if include_bypass:
        if 'uid' in func_name.lower():
            bypass_logic = """
                // BYPASS: Return 501 (mobile user)
                if (uid === 0) {
                    console.log("  [!] BYPASS: Changing UID from 0 (root) to 501 (mobile)");
                    retval.replace(501);
                }"""
        else:
            bypass_logic = """
                // BYPASS: Return 501 (mobile group)
                if (gid === 0) {
                    console.log("  [!] BYPASS: Changing GID from 0 (wheel) to 501 (mobile)");
                    retval.replace(501);
                }"""

    hook_code = f'''
// Hook: {func_name} (User/Group ID Check)
(function() {{
    var funcPtr = findExport("{func_name}", "{library}");

    if (funcPtr) {{
        console.log("[*] Hooking {func_name} at", funcPtr);

        Interceptor.attach(funcPtr, {{
            onEnter: function(args) {{
                console.log("\\n[+] {func_name} called");
            }},
            onLeave: function(retval) {{
'''

    if 'uid' in func_name.lower():
        hook_code += '''                var uid = retval.toInt32();
                if (uid === 0) {
                    console.log("  [!!!] ROOT UID DETECTED (JAILBREAK) [!!!]");
                    console.log("  [!] UID:", uid);
'''
        if bypass_logic:
            hook_code += bypass_logic
        hook_code += '''                } else {
                    console.log("  => UID:", uid);
                }
'''
    else:
        hook_code += '''                var gid = retval.toInt32();
                if (gid === 0) {
                    console.log("  [!!!] ROOT GID DETECTED (JAILBREAK) [!!!]");
                    console.log("  [!] GID:", gid);
'''
        if bypass_logic:
            hook_code += bypass_logic
        hook_code += '''                } else {
                    console.log("  => GID:", gid);
                }
'''

    hook_code += '''            }
        });
    } else {
        console.log("[-] {func_name} not found in {library}");
    }
}})();
'''.replace('{func_name}', func_name).replace('{library}', library)

    return hook_code


def _generate_url_hook(signature: FunctionSignature, include_bypass: bool) -> str:
    """Generate specialized hook for URL scheme functions (UIApplication_canOpenURL)."""
    func_name = signature.name
    library = signature.library

    bypass_logic = ""
    if include_bypass:
        bypass_logic = """
                // BYPASS: Return NO (cannot open URL)
                if (this.isJailbreakScheme) {
                    console.log("  [!] BYPASS: Returning NO (URL cannot be opened)");
                    retval.replace(0);
                }"""

    hook_code = f'''
// Hook: {func_name} (URL Scheme Check)
(function() {{
    if (typeof ObjC === 'undefined' || !ObjC.available) {{
        console.log("[-] Objective-C runtime not available");
        return;
    }}

    var className = "UIApplication";
    var methodName = "- canOpenURL:";

    try {{
        var hook = ObjC.classes[className][methodName];
        if (!hook || !hook.implementation) {{
            console.log("[-] {func_name} not found");
            return;
        }}

        console.log("[*] Hooking {func_name}");

        Interceptor.attach(hook.implementation, {{
            onEnter: function(args) {{
                // args[2] is the URL (args[0] is self, args[1] is selector)
                try {{
                    var url = new ObjC.Object(args[2]);
                    var urlStr = url.toString();
                    this.urlStr = urlStr;
                    this.isJailbreakScheme = isJailbreakURLScheme(urlStr);

                    if (this.isJailbreakScheme) {{
                        console.log("\\n[!!!] canOpenURL: - JAILBREAK URL SCHEME [!!!]");
                        console.log("  [!] URL:", urlStr);
                        var mainModule = getMainAppModule();
                        console.log("  [!] Backtrace (BN = Ghidra offset):");
                        console.log(formatBacktrace(this.context, mainModule, 5));
                    }} else {{
                        console.log("\\n[+] canOpenURL: called");
                        console.log("  [0] URL:", urlStr);
                    }}
                }} catch (e) {{
                    console.log("  [!] Error reading URL:", e);
                }}
            }},
            onLeave: function(retval) {{
                var canOpen = retval ? "YES" : "NO";
                if (this.isJailbreakScheme) {{
                    console.log("  [!] Original Return:", canOpen);
'''

    if bypass_logic:
        hook_code += bypass_logic

    hook_code += '''                } else {
                    console.log("  => Return:", canOpen);
                }
            }
        });
    } catch (e) {
        console.log("[-] Error hooking {func_name}:", e);
    }
}})();
'''.replace('{func_name}', func_name).replace('{library}', library)

    return hook_code


def _generate_syscall_hook(signature: FunctionSignature, include_bypass: bool) -> str:
    """Generate specialized hook for syscall function."""
    func_name = signature.name
    library = signature.library

    hook_code = f'''
// Hook: {func_name} (Direct System Call)
(function() {{
    var funcPtr = findExport("{func_name}", "{library}");

    if (funcPtr) {{
        console.log("[*] Hooking {func_name} at", funcPtr);

        // Common syscall numbers
        var syscallNames = {{
            2: 'SYS_fork',
            5: 'SYS_open',
            33: 'SYS_access',
            59: 'SYS_execve',
            66: 'SYS_vfork',
            188: 'SYS_stat'
        }};

        Interceptor.attach(funcPtr, {{
            onEnter: function(args) {{
                var syscallNum = args[0].toInt32();
                var syscallName = syscallNames[syscallNum] || ("syscall_" + syscallNum);
                this.syscallNum = syscallNum;
                this.syscallName = syscallName;

                // Flag suspicious syscalls
                var suspicious = [2, 5, 33, 59, 66, 188];  // fork, open, access, execve, vfork, stat
                this.isSuspicious = suspicious.indexOf(syscallNum) !== -1;

                if (this.isSuspicious) {{
                    console.log("\\n[!!!] syscall - SUSPICIOUS SYSTEM CALL [!!!]");
                    console.log("  [!] Syscall:", syscallName, "(" + syscallNum + ")");
                    console.log("  [!] Direct syscalls may evade API monitoring");
                    var mainModule = getMainAppModule();
                    console.log("  [!] Backtrace (BN = Ghidra offset):");
                    console.log(formatBacktrace(this.context, mainModule, 5));
                }} else {{
                    console.log("\\n[+] syscall called");
                    console.log("  [0] number:", syscallName, "(" + syscallNum + ")");
                }}
            }},
            onLeave: function(retval) {{
                if (this.isSuspicious) {{
                    console.log("  [!] Return:", retval.toInt32());
                }} else {{
                    console.log("  => Return:", retval.toInt32());
                }}
            }}
        }});
    }} else {{
        console.log("[-] {func_name} not found in {library}");
    }}
}})();
'''.replace('{func_name}', func_name).replace('{library}', library)

    return hook_code


def generate_jailbreak_hook(signature: FunctionSignature, include_bypass: bool = False) -> str:
    """
    Generate a specialized Frida hook for a jailbreak detection function.

    This function creates context-aware hooks that:
    - Highlight when jailbreak-related paths/libraries are being checked
    - Provide detailed logging of detection attempts
    - Optionally include bypass code to hide jailbreak indicators

    Args:
        signature: FunctionSignature object defining the function to hook
        include_bypass: Whether to include bypass code to hide jailbreak

    Returns:
        Complete JavaScript code for the hook
    """
    func_name = signature.name

    # File existence/access checks
    if func_name in ['stat', 'lstat', 'access', 'fopen', 'open', 'opendir', 'statfs']:
        return _generate_file_check_hook(signature, include_bypass)

    # Process manipulation (critical indicators)
    elif func_name in ['fork', 'vfork', 'system', 'popen', 'execve']:
        return _generate_process_hook(signature, include_bypass)

    # Dynamic library checks
    elif func_name in ['dlopen', '_dyld_get_image_name', '_dyld_image_count']:
        return _generate_dylib_hook(signature, include_bypass)

    # Environment variable checks
    elif func_name in ['getenv', 'setenv']:
        return _generate_env_hook(signature, include_bypass)

    # UID/GID checks
    elif func_name in ['getuid', 'geteuid', 'getgid', 'getegid']:
        return _generate_uid_hook(signature, include_bypass)

    # URL scheme checks
    elif 'canOpenURL' in func_name:
        return _generate_url_hook(signature, include_bypass)

    # Direct syscall
    elif func_name == 'syscall':
        return _generate_syscall_hook(signature, include_bypass)

    # Default: use simpler hook for other functions (readdir, etc.)
    else:
        from .base import generate_hook
        return generate_hook(signature)


def generate_jailbreak_script(binary_name: str = "(auto-detected)", include_bypass: bool = False) -> Optional[str]:
    """
    Generate a complete Frida script for jailbreak detection monitoring.

    This function creates a comprehensive script that hooks all jailbreak detection
    functions and provides detailed logging of detection attempts. When include_bypass
    is True, it also includes code to hide jailbreak indicators from the application.

    Args:
        binary_name: Name of the target binary/application
        include_bypass: Whether to include bypass code to hide jailbreak (default: False)

    Returns:
        Complete Frida script as a string, or None if category not found

    Example:
        >>> # Generate detection-only script
        >>> script = generate_jailbreak_script("MyApp", include_bypass=False)
        >>> with open("jailbreak_detection.js", "w") as f:
        ...     f.write(script)
        >>>
        >>> # Generate script with bypass
        >>> bypass_script = generate_jailbreak_script("MyApp", include_bypass=True)
        >>> with open("jailbreak_bypass.js", "w") as f:
        ...     f.write(bypass_script)
    """
    # Load jailbreak category signatures
    db = load_category("jailbreak")
    if db is None:
        return None

    # Generate hooks for all functions
    early_hook_names = {
        "fork",
        "vfork",
        "system",
        "popen",
        "execve",
        "dlopen",
        "dlsym",
        "_dyld_get_image_name",
        "_dyld_image_count",
        "getenv",
    }
    hooks = []
    early_hooks = []
    for func in db.functions.values():
        hook = generate_jailbreak_hook(func, include_bypass)
        if func.name in early_hook_names:
            early_hooks.append(hook)
        else:
            hooks.append(hook)

    # Build the script
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    bypass_note = " (WITH BYPASS)" if include_bypass else ""
    header = f"""// trellis_jailbreak_hooks.js
// Generated by Trellis - JAILBREAK DETECTION{bypass_note}
// Target: {binary_name}
// Generated: {timestamp}
// Frida API: 17.x+ compatible
//
// This script hooks iOS jailbreak detection techniques and provides
// detailed logging of detection attempts.
//
// Features:
// - Ghidra address translation for cross-referencing
// - Jailbreak-safe app module detection
{f'''//
// BYPASS MODE ENABLED: This script will attempt to hide jailbreak
// indicators from the application by returning "safe" values.
''' if include_bypass else ''}"""

    return combine_hooks(
        hooks=hooks,
        category="jailbreak",
        binary_name=binary_name,
        include_constants=False,
        include_runtime_helpers=True,
        early_hooks=early_hooks,
        use_lazy_loading=False,
        timestamp=timestamp,
        header_override=header,
        extra_prelude=JAILBREAK_CONSTANTS,
    )


__all__ = [
    "generate_jailbreak_hook",
    "generate_jailbreak_script",
    "JAILBREAK_CONSTANTS",
]
