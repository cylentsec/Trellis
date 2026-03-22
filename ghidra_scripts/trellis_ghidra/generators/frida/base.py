"""
Base utilities for generating Frida hooks from function signatures.

This module provides the core functionality for transforming Trellis function
signatures into executable Frida JavaScript hooks. It handles type formatting,
parameter logging, backtrace generation, and script composition.

**Frida 17+ Compatibility**: All generated scripts use Frida 17 compatible APIs.
**Ghidra Address Translation**: Backtraces include BN offsets for cross-referencing.

Example usage:
    >>> from trellis.signatures import get_function
    >>> from trellis.generators.frida.base import generate_hook, combine_hooks
    >>>
    >>> # Generate a single hook
    >>> func = get_function("crypto", "CCCrypt")
    >>> hook_code = generate_hook(func)
    >>>
    >>> # Combine multiple hooks into a complete script
    >>> funcs = [get_function("crypto", f) for f in ["CCCrypt", "CCHmac"]]
    >>> hooks = [generate_hook(f) for f in funcs]
    >>> script = combine_hooks(hooks, "crypto", "MyApp")
"""

from datetime import datetime
from typing import Optional, Union

from ...signatures import FunctionSignature, Parameter


# ============================================================================
# Frida 17+ Runtime Helpers
# ============================================================================
# These JavaScript helpers are included in all generated scripts to provide:
# - Ghidra address translation for cross-referencing
# - App module filtering for jailbroken device compatibility
# - Safe ObjC method hooking patterns
# ============================================================================

FRIDA_RUNTIME_HELPERS = """
// ============================================================================
// Trellis Runtime Helpers (Frida 17+ Compatible)
// ============================================================================

// ----------------------------------------------------------------------------
// Ghidra Address Translation
// ----------------------------------------------------------------------------
// Converts Frida runtime addresses to Ghidra offsets for cross-referencing.
// Ghidra uses the __TEXT segment vmaddr directly from the Mach-O header:
//   - Executables: typically 0x100000000
//   - Dylibs with vmaddr=0: stays at 0x0
//   - Dylibs with non-zero vmaddr: uses that vmaddr
//
// Usage: getGhidraOffset(ptr("0x102345678"), targetModule)
// Returns: NativePointer with the Ghidra-compatible address
// ----------------------------------------------------------------------------

function getGhidraOffset(runtimeAddr, module) {
    var offset = runtimeAddr.sub(module.base);
    var header = module.base;
    var magic = header.readU32();

    if (magic === 0xfeedfacf) {  // MH_MAGIC_64
        var filetype = header.add(12).readU32();
        var textVmaddr = ptr(0);
        var ncmds = header.add(16).readU32();
        var cmdPtr = header.add(32);

        for (var i = 0; i < ncmds; i++) {
            var cmd = cmdPtr.readU32();
            var cmdsize = cmdPtr.add(4).readU32();

            if (cmd === 0x19) {  // LC_SEGMENT_64
                var segname = cmdPtr.add(8).readUtf8String();
                // Note: segname is 16-byte null-padded, use startsWith
                if (segname && segname.startsWith('__TEXT')) {
                    textVmaddr = ptr(cmdPtr.add(24).readU64());
                    break;
                }
            }
            cmdPtr = cmdPtr.add(cmdsize);
        }

        // Ghidra uses __TEXT vmaddr as-is — no rebasing for dylibs
        return offset.add(textVmaddr);
    }
    return offset;
}

// ----------------------------------------------------------------------------
// Backtrace Formatting with Ghidra Addresses
// ----------------------------------------------------------------------------
// Formats backtraces to include both runtime and Ghidra addresses.
// This enables direct cross-referencing from Frida output to Ghidra.
//
// Output format: "  0x102345678 (Ghidra: 0x100008d18) symbol_name"
// ----------------------------------------------------------------------------

function formatBacktrace(context, targetModule, maxFrames) {
    maxFrames = maxFrames || 8;
    var bt = Thread.backtrace(context, Backtracer.ACCURATE);
    var lines = [];

    for (var i = 0; i < Math.min(bt.length, maxFrames); i++) {
        var addr = bt[i];
        var sym = DebugSymbol.fromAddress(addr);
        var ghidraAddr = getGhidraOffset(addr, targetModule);
        lines.push('    ' + addr + ' (Ghidra: 0x' + ghidraAddr.toString(16) + ') ' + (sym.name || '<unknown>'));
    }

    return lines.join('\\n');
}

// ----------------------------------------------------------------------------
// App Module Detection (Jailbreak-Safe)
// ----------------------------------------------------------------------------
// On jailbroken devices, jailbreak tweaks may load before the app binary.
// This filters modules to only include those from the app bundle (.app/).
// ----------------------------------------------------------------------------

var _trellisAppModules = null;
var _trellisMainModule = null;

function getAppModules() {
    if (_trellisAppModules === null) {
        _trellisAppModules = Process.enumerateModules().filter(function(m) {
            return m.path.includes('.app/');
        });
    }
    return _trellisAppModules;
}

function getMainAppModule() {
    if (_trellisMainModule === null) {
        var appModules = getAppModules();
        _trellisMainModule = appModules.length > 0 ? appModules[0] : Process.enumerateModules()[0];
    }
    return _trellisMainModule;
}

// ----------------------------------------------------------------------------
// Safe ObjC Method Hooking (Frida 17 Compatible)
// ----------------------------------------------------------------------------
// Frida 17+ requires checking method existence before accessing .implementation.
// These helpers provide safe hooking patterns that won't crash on missing methods.
//
// Usage:
//   hookObjCMethod('NSURLSession', '- dataTaskWithRequest:completionHandler:', function(impl) {
//       Interceptor.attach(impl, { onEnter: function(args) { ... } });
//   });
// ----------------------------------------------------------------------------

function hookObjCMethod(className, methodName, callback) {
    if (typeof ObjC === 'undefined' || !ObjC.available) {
        console.log('[-] ObjC runtime not available, skipping: ' + className + ' ' + methodName);
        return false;
    }

    var clazz = ObjC.classes[className];
    if (!clazz) {
        console.log('[-] Class not found: ' + className);
        return false;
    }

    var method = clazz[methodName];
    if (!method || !method.implementation) {
        console.log('[-] Method not found: ' + className + ' ' + methodName);
        return false;
    }

    console.log('[*] Hooking ' + className + ' ' + methodName);
    callback(method.implementation);
    return true;
}

// Batch hook multiple ObjC methods
function hookObjCMethods(hooks) {
    var successCount = 0;
    hooks.forEach(function(hook) {
        if (hookObjCMethod(hook.className, hook.methodName, hook.callback)) {
            successCount++;
        }
    });
    return successCount;
}

// ----------------------------------------------------------------------------
// Swift Symbol Detection
// ----------------------------------------------------------------------------
// Swift symbols are mangled and may not be safe to hook with Interceptor.attach
// due to calling convention differences. These helpers detect Swift symbols.
// ----------------------------------------------------------------------------

function isSwiftSymbol(symbolName) {
    // Swift symbols start with $s or _$s
    return symbolName && (symbolName.startsWith('$s') || symbolName.startsWith('_$s'));
}

function warnIfSwiftSymbol(symbolName, address) {
    if (isSwiftSymbol(symbolName)) {
        console.log('[!] WARNING: ' + symbolName + ' is a Swift symbol');
        console.log('[!] Hooking Swift functions may cause crashes due to calling conventions');
        console.log('[!] Consider static analysis in Ghidra at: 0x' + address.toString(16));
        return true;
    }
    return false;
}

// ----------------------------------------------------------------------------
// Lazy Loading / Deferred Hook Installation
// ----------------------------------------------------------------------------
// iOS apps must launch within ~20 seconds or the watchdog kills them.
// Installing many hooks at startup can exceed this limit.
// These helpers defer hook installation until after the app has launched.
//
// Usage:
//   deferHooksUntilReady(function() {
//       // Install all your hooks here
//       installCryptoHooks();
//       installNetworkHooks();
//   });
// ----------------------------------------------------------------------------

var _trellisHooksInstalled = false;
var _trellisDeferredHooks = [];

function deferHooksUntilReady(hookInstaller) {
    if (_trellisHooksInstalled) {
        // Already ready, install immediately
        hookInstaller();
        return;
    }

    _trellisDeferredHooks.push(hookInstaller);

    // Only set up the trigger once
    if (_trellisDeferredHooks.length === 1) {
        _setupLaunchTrigger();
    }
}

function _setupLaunchTrigger() {
    if (typeof ObjC !== 'undefined' && ObjC.available) {
        // Method 1: Wait for UIApplicationDidFinishLaunching notification
        var NSNotificationCenter = ObjC.classes.NSNotificationCenter;
        var notificationName = ObjC.classes.NSString.stringWithString_('UIApplicationDidFinishLaunchingNotification');

        var observer = NSNotificationCenter.defaultCenter().addObserverForName_object_queue_usingBlock_(
            notificationName,
            null,
            null,
            new ObjC.Block({
                retType: 'void',
                argTypes: ['object'],
                implementation: function(notification) {
                    console.log('[*] App launched, installing Trellis hooks...');
                    _installDeferredHooks();
                }
            })
        );

        // Fallback: If notification doesn't fire (app already launched), use timeout
        setTimeout(function() {
            if (!_trellisHooksInstalled) {
                console.log('[*] Fallback: Installing Trellis hooks via timeout...');
                _installDeferredHooks();
            }
        }, 2000);

    } else {
        // No ObjC runtime - just use setTimeout
        setTimeout(function() {
            console.log('[*] Installing Trellis hooks (non-ObjC mode)...');
            _installDeferredHooks();
        }, 1000);
    }
}

function _installDeferredHooks() {
    if (_trellisHooksInstalled) return;
    _trellisHooksInstalled = true;

    var startTime = Date.now();

    for (var i = 0; i < _trellisDeferredHooks.length; i++) {
        try {
            _trellisDeferredHooks[i]();
        } catch (e) {
            console.log('[!] Error installing hooks: ' + e);
        }
    }

    var elapsed = Date.now() - startTime;
    console.log('[*] Trellis hooks installed in ' + elapsed + 'ms');
    _trellisDeferredHooks = [];
}

// Force immediate hook installation (use with caution on large hook sets)
function installHooksNow() {
    _trellisHooksInstalled = true;
    // Allow direct hook installation without deferral
}

// ----------------------------------------------------------------------------
// Robust Export Finder (Frida 17+ Compatible)
// ----------------------------------------------------------------------------
// Handles dyld shared cache and various module loading scenarios on iOS.
// Uses global export search first (more reliable), falls back to module-specific.
//
// Usage:
//   var funcPtr = findExport("CCCrypt");  // Global search
//   var funcPtr = findExport("CCCrypt", "libcommonCrypto");  // Module hint
// ----------------------------------------------------------------------------

function findExport(symbolName, moduleHint) {
    var funcPtr = null;

    // Try global export search first (works with dyld shared cache)
    try {
        funcPtr = Module.getGlobalExportByName(symbolName);
        if (funcPtr) return funcPtr;
    } catch (e) {
        // Global search failed, try module-specific
    }

    // Try module-specific search if hint provided
    if (moduleHint) {
        var moduleName = moduleHint.replace('.framework', '').replace('.dylib', '');
        try {
            var mod = Process.getModuleByName(moduleName);
            if (mod) {
                funcPtr = mod.getExportByName(symbolName);
                if (funcPtr) return funcPtr;
            }
        } catch (e) {
            // Module not found
        }

        // Try with full library name variations
        var variations = [
            moduleName,
            moduleName + '.dylib',
            '/usr/lib/' + moduleName + '.dylib',
            '/usr/lib/system/' + moduleName + '.dylib'
        ];
        for (var i = 0; i < variations.length; i++) {
            try {
                var mod = Process.getModuleByName(variations[i]);
                if (mod) {
                    funcPtr = mod.getExportByName(symbolName);
                    if (funcPtr) return funcPtr;
                }
            } catch (e) {
                // Continue trying
            }
        }
    }

    return null;
}
"""


# CommonCrypto enum constants for logging
CC_CONSTANTS = """
// CommonCrypto Constants
const CCOperation = {
    0: 'kCCEncrypt',
    1: 'kCCDecrypt'
};

const CCAlgorithm = {
    0: 'kCCAlgorithmAES128',
    1: 'kCCAlgorithmDES',
    2: 'kCCAlgorithm3DES',
    3: 'kCCAlgorithmCAST',
    4: 'kCCAlgorithmRC4',
    5: 'kCCAlgorithmRC2',
    6: 'kCCAlgorithmBlowfish'
};

const CCOptions = {
    0x0000: 'kCCOptionNone',
    0x0001: 'kCCOptionPKCS7Padding',
    0x0002: 'kCCOptionECBMode'
};

const CCHmacAlgorithm = {
    0: 'kCCHmacAlgSHA1',
    1: 'kCCHmacAlgMD5',
    2: 'kCCHmacAlgSHA256',
    3: 'kCCHmacAlgSHA384',
    4: 'kCCHmacAlgSHA512',
    5: 'kCCHmacAlgSHA224'
};

const CCCryptorStatus = {
    0: 'kCCSuccess',
    '-4300': 'kCCParamError',
    '-4301': 'kCCBufferTooSmall',
    '-4302': 'kCCMemoryFailure',
    '-4303': 'kCCAlignmentError',
    '-4304': 'kCCDecodeError',
    '-4305': 'kCCUnimplemented',
    '-4306': 'kCCOverflow',
    '-4307': 'kCCRNGFailure',
    '-4308': 'kCCUnspecifiedError',
    '-4309': 'kCCCallSequenceError',
    '-4310': 'kCCKeySizeError',
    '-4311': 'kCCInvalidKey'
};

const SecPadding = {
    0: 'kSecPaddingNone',
    1: 'kSecPaddingPKCS1',
    2: 'kSecPaddingOAEP',
    3: 'kSecPaddingSigRaw',
    4: 'kSecPaddingPKCS1MD2',
    5: 'kSecPaddingPKCS1MD5',
    6: 'kSecPaddingPKCS1SHA1',
    7: 'kSecPaddingPKCS1SHA224',
    8: 'kSecPaddingPKCS1SHA256',
    9: 'kSecPaddingPKCS1SHA384',
    10: 'kSecPaddingPKCS1SHA512'
};

const kSecAttrAccessible = {
    'kSecAttrAccessibleWhenUnlocked': 'WhenUnlocked',
    'kSecAttrAccessibleAfterFirstUnlock': 'AfterFirstUnlock',
    'kSecAttrAccessibleAlways': 'Always (INSECURE)',
    'kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly': 'WhenPasscodeSetThisDeviceOnly',
    'kSecAttrAccessibleWhenUnlockedThisDeviceOnly': 'WhenUnlockedThisDeviceOnly',
    'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly': 'AfterFirstUnlockThisDeviceOnly',
    'kSecAttrAccessibleAlwaysThisDeviceOnly': 'AlwaysThisDeviceOnly (INSECURE)'
};

// Helper function to format hexdump
function trellisHexdump(ptr, length, maxBytes) {
    maxBytes = maxBytes || 256;
    if (length > maxBytes) {
        return trellisHexdump(ptr, maxBytes) + '\\n[... truncated ' + (length - maxBytes) + ' bytes ...]';
    }
    try {
        return hexdump(ptr, { length: length, header: false, ansi: false });
    } catch (e) {
        return '<hexdump failed: ' + e + '>';
    }
}

// Helper function to read ObjC object description
function describeObject(ptr) {
    if (ptr.isNull()) return 'nil';
    try {
        var obj = new ObjC.Object(ptr);
        return obj.toString();
    } catch (e) {
        return ptr.toString();
    }
}

// Helper function to format CFDictionary contents
function describeCFDictionary(ptr) {
    if (ptr.isNull()) return 'NULL';
    try {
        var dict = ObjC.Object(ptr);
        return dict.toString();
    } catch (e) {
        return ptr.toString();
    }
}
"""


def get_script_header(category: str, binary_name: str, timestamp: Optional[str] = None) -> str:
    """
    Generate the script header with metadata.

    Args:
        category: Category name (e.g., "crypto", "networking")
        binary_name: Name of the target binary/application
        timestamp: Optional timestamp string (defaults to current time)

    Returns:
        Formatted JavaScript header comment
    """
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""// trellis_{category}_hooks.js
// Generated by Trellis - {category.upper()} category
// Target: {binary_name}
// Generated: {timestamp}
// Frida API: 17.x+ compatible
//
// Features:
// - Lazy loading: Hooks deferred until app launch to prevent watchdog kills
// - Ghidra address translation for cross-referencing
// - Jailbreak-safe app module detection
// - Safe ObjC method hooking patterns
// - Swift symbol detection with warnings
"""


def _is_pointer_type(type_str: str) -> bool:
    """Check if a type is a pointer."""
    return "*" in type_str


def _is_enum_type(type_str: str) -> bool:
    """Check if a type is a CommonCrypto enum."""
    enum_types = {
        "CCOperation",
        "CCAlgorithm",
        "CCOptions",
        "CCHmacAlgorithm",
        "CCCryptorStatus",
        "SecPadding",
        "CCMode",
        "CCPadding",
    }
    return type_str in enum_types


def _is_integer_type(type_str: str) -> bool:
    """Check if a type is an integer."""
    integer_types = {
        "int",
        "uint32_t",
        "int32_t",
        "uint64_t",
        "int64_t",
        "size_t",
        "CC_LONG",
        "unsigned int",
        "unsigned long",
        "long",
        "short",
        "unsigned short",
        "uint8_t",
        "int8_t",
        "uint16_t",
        "int16_t",
    }
    # Remove const and check base type
    base_type = type_str.replace("const", "").strip()
    return base_type in integer_types


def _is_string_type(type_str: str) -> bool:
    """Check if a type is a C string."""
    normalized = type_str.replace("const", "").strip()
    return normalized in ["char*", "char *"]


def _is_cf_type(type_str: str) -> bool:
    """Check if a type is a CoreFoundation type."""
    return (
        type_str.startswith("CF")
        or type_str.startswith("Sec")
        or type_str in ["OSStatus", "bool"]
    )


def get_frida_formatter(param: Parameter, index: int, size_param_map: dict) -> str:
    """
    Generate Frida JavaScript code to format a parameter value for logging.

    Args:
        param: Parameter object with type and name information
        index: Zero-based parameter index in the function signature
        size_param_map: Dictionary mapping parameter names to their size parameter names

    Returns:
        JavaScript expression that formats the parameter value as a string

    Examples:
        >>> param = Parameter(name="data", type="void*", size_param="dataLen")
        >>> get_frida_formatter(param, 0, {"data": "dataLen"})
        "hexdump(args[0], args[1].toInt32())"
    """
    param_type = param.type
    param_name = param.name

    # Handle enum types with constant lookup
    if _is_enum_type(param_type):
        enum_name = param_type
        return f"({enum_name}[args[{index}].toInt32()] || args[{index}].toInt32())"

    # Handle integer types
    if _is_integer_type(param_type):
        return f"args[{index}].toInt32()"

    # Handle string pointers
    if _is_string_type(param_type):
        return f"(args[{index}].isNull() ? 'NULL' : args[{index}].readUtf8String())"

    # Handle void* with size parameter - hexdump the buffer
    if param_type in ["void*", "const void*", "uint8_t*", "const uint8_t*", "unsigned char*"]:
        if param.size_param:
            # Find the index of the size parameter
            size_param_index = None
            for name, size_name in size_param_map.items():
                if name == param_name and size_name == param.size_param:
                    # We need to find the actual index of the size parameter
                    # This will be resolved in generate_hook
                    return f"(args[{index}].isNull() ? 'NULL' : '\\n' + trellisHexdump(args[{index}], {{SIZE_PARAM}}.toInt32(), 128))"
        return f"args[{index}]"

    # Handle CoreFoundation types
    if _is_cf_type(param_type):
        if "Dictionary" in param_type or "CFDictionaryRef" in param_type:
            return f"describeCFDictionary(args[{index}])"
        elif param_type == "bool":
            return f"(args[{index}] ? 'true' : 'false')"
        elif param_type == "OSStatus":
            return f"args[{index}].toInt32()"
        else:
            # Generic CF type - try to describe as ObjC object
            return f"describeObject(args[{index}])"

    # Default: pointer types show address
    if _is_pointer_type(param_type):
        return f"args[{index}]"

    # Fallback: convert to string
    return f"args[{index}]"


def generate_hook(signature: FunctionSignature) -> str:
    """
    Generate a complete Frida hook for a function signature.

    This creates an Interceptor.attach hook with:
    - Robust function lookup using findExport helper (Frida 17+ compatible)
    - Parameter logging in onEnter
    - Return value logging in onLeave
    - Backtrace logging
    - Proper type formatting for all parameters

    Args:
        signature: FunctionSignature object defining the function to hook

    Returns:
        Complete JavaScript code for the hook

    Example:
        >>> from trellis.signatures import get_function
        >>> func = get_function("crypto", "CCCrypt")
        >>> hook = generate_hook(func)
    """
    func_name = signature.name
    library = signature.library

    # Build size parameter mapping
    size_param_map = {}
    param_name_to_index = {}
    for i, param in enumerate(signature.parameters):
        param_name_to_index[param.name] = i
        if param.size_param:
            size_param_map[param.name] = param.size_param

    # Generate parameter logging code
    param_logs = []
    for i, param in enumerate(signature.parameters):
        formatter = get_frida_formatter(param, i, size_param_map)

        # Replace {SIZE_PARAM} placeholder with actual size parameter access
        if "{SIZE_PARAM}" in formatter and param.size_param:
            size_index = param_name_to_index.get(param.size_param, i + 1)
            formatter = formatter.replace("{SIZE_PARAM}", f"args[{size_index}]")

        param_logs.append(f'        console.log("  [{i}] {param.name} ({param.type}):", {formatter});')

    param_logging = "\n".join(param_logs) if param_logs else '        console.log("  (no parameters)");'

    # Generate return value logging
    return_logging = ""
    if signature.return_type and signature.return_type.type != "void":
        ret_type = signature.return_type.type
        if _is_enum_type(ret_type):
            return_logging = f"""
        var retval = {ret_type}[this.context.x0] || this.context.x0;
        console.log("  => Return:", retval);"""
        elif _is_integer_type(ret_type) or ret_type in ["OSStatus", "bool"]:
            return_logging = """
        console.log("  => Return:", this.context.x0.toInt32());"""
        elif _is_pointer_type(ret_type):
            return_logging = """
        console.log("  => Return:", this.context.x0);"""
        else:
            return_logging = """
        console.log("  => Return:", this.context.x0);"""

    # Determine if this is a system library (use global search first)
    is_system_library = any(
        lib in library.lower()
        for lib in ["libcommon", "libsystem", "security", "foundation", "corefoundation"]
    )

    # Generate the hook code with appropriate module resolution strategy
    if is_system_library:
        # System libraries: Use global export search first (more reliable for dyld shared cache)
        hook_code = f'''
// Hook: {func_name}
(function() {{
    var funcPtr = null;

    // System library: Use global export search (works with dyld shared cache)
    try {{
        funcPtr = Module.getGlobalExportByName("{func_name}");
    }} catch (e) {{
        // Fallback: try module-specific search
        try {{
            var moduleName = "{library}".replace(".framework", "").replace(".dylib", "");
            var mod = Process.getModuleByName(moduleName);
            if (mod) {{
                funcPtr = mod.getExportByName("{func_name}");
            }}
        }} catch (e2) {{
            console.log("[-] Could not find {func_name}: " + e2);
        }}
    }}'''
    else:
        # App/third-party libraries: Try module-specific first, then global
        hook_code = f'''
// Hook: {func_name}
(function() {{
    var moduleName = "{library}".replace(".framework", "").replace(".dylib", "");
    var funcPtr = null;

    // Try module-specific search first
    try {{
        var mod = Process.getModuleByName(moduleName);
        if (mod) {{
            funcPtr = mod.getExportByName("{func_name}");
        }}
    }} catch (e) {{
        // Module not found, will try global search
    }}

    // Fallback: global export search (Frida 17+ API)
    if (!funcPtr) {{
        try {{
            funcPtr = Module.getGlobalExportByName("{func_name}");
        }} catch (e2) {{
            console.log("[-] Could not find {func_name}: " + e2);
        }}
    }}'''

    # Common hook attachment code (same for both system and app libraries)
    hook_code += f'''

    if (funcPtr) {{
        console.log("[*] Hooking {func_name} at", funcPtr);

        Interceptor.attach(funcPtr, {{
            onEnter: function(args) {{
                console.log("\\n[+] {func_name} called");
{param_logging}

                // Backtrace with Ghidra addresses
                var mainModule = getMainAppModule();
                console.log("  Backtrace (BN = Ghidra offset):");
                console.log(formatBacktrace(this.context, mainModule, 5));
            }},{("""
            onLeave: function(retval) {{""" + return_logging + """
            }}""") if return_logging else ""}
        }});
    }} else {{
        console.log("[-] {func_name} not found in {library}");
    }}
}})();
'''

    return hook_code


def combine_hooks(
    hooks: list[str],
    category: str,
    binary_name: str,
    include_constants: bool = True,
    include_runtime_helpers: bool = True,
    early_hooks: Optional[list[str]] = None,
    use_lazy_loading: bool = True,
    timestamp: Optional[str] = None,
    header_override: Optional[str] = None,
    extra_prelude: Optional[Union[list[str], str]] = None,
) -> str:
    """
    Combine multiple hooks into a complete Frida script.

    Args:
        hooks: List of hook JavaScript code strings
        category: Category name for the script header
        binary_name: Target binary/application name
        include_constants: Whether to include CC constant definitions
        include_runtime_helpers: Whether to include Frida 17+ runtime helpers
        early_hooks: Optional list of hooks to install immediately when early capture is enabled
        use_lazy_loading: Whether to defer hooks until app has launched (recommended for iOS)
        timestamp: Optional timestamp for header (defaults to current time)

    Returns:
        Complete Frida script with header, helpers, constants, and all hooks

    Example:
        >>> from trellis.signatures import load_category
        >>> from trellis.generators.frida.base import generate_hook, combine_hooks
        >>>
        >>> db = load_category("crypto")
        >>> hooks = [generate_hook(func) for func in db.functions.values()]
        >>> script = combine_hooks(hooks, "crypto", "MyApp")
        >>> # Save or inject script
        >>> with open("hooks.js", "w") as f:
        ...     f.write(script)
    """
    if header_override is not None:
        header = header_override
        if not header.endswith("\n"):
            header += "\n"
    else:
        header = get_script_header(category, binary_name, timestamp)

    script_parts = [header]
    script_parts.append("\n(function() {")
    script_parts.append("    'use strict';\n")

    # Add Frida 17+ runtime helpers (Ghidra address translation, module filtering, etc.)
    if include_runtime_helpers:
        helpers_indented = "\n".join(
            "    " + line if line.strip() else line
            for line in FRIDA_RUNTIME_HELPERS.strip().split("\n")
        )
        script_parts.append(helpers_indented)
        script_parts.append("\n")

    if include_constants:
        # Indent constants
        constants_indented = "\n".join(
            "    " + line if line.strip() else line
            for line in CC_CONSTANTS.strip().split("\n")
        )
        script_parts.append(constants_indented)
        script_parts.append("\n")
    # Add any extra prelude sections (category-specific constants/helpers)
    if extra_prelude:
        sections = [extra_prelude] if isinstance(extra_prelude, str) else extra_prelude
        for section in sections:
            if not section:
                continue
            section_indented = "\n".join(
                "    " + line if line.strip() else line
                for line in section.strip().split("\n")
            )
            script_parts.append(section_indented)
            script_parts.append("\n")

    # Runtime config for lazy loading and early capture
    script_parts.append(
        f"    var TRELLIS_CONFIG = {{ useLazyLoading: {str(use_lazy_loading).lower()}, earlyCapture: false }};"
    )
    script_parts.append("")

    # Swift binary detection warning
    script_parts.append("    // Swift binary detection")
    script_parts.append("    (function() {")
    script_parts.append("        var mainMod = getMainAppModule();")
    script_parts.append("        if (mainMod) {")
    script_parts.append("            var exports = mainMod.enumerateExports();")
    script_parts.append("            var swiftCount = 0;")
    script_parts.append("            for (var i = 0; i < Math.min(exports.length, 500); i++) {")
    script_parts.append("                if (isSwiftSymbol(exports[i].name)) swiftCount++;")
    script_parts.append("            }")
    script_parts.append("            if (swiftCount > 50) {")
    script_parts.append("                console.log('[!] Swift-heavy binary detected (' + swiftCount + '+ Swift symbols)');")
    script_parts.append("                console.log('[!] Hooking Swift functions directly may cause crashes');")
    script_parts.append("                console.log('[!] Recommend: Use Ghidra static analysis for Swift code paths');")
    script_parts.append("            }")
    script_parts.append("        }")
    script_parts.append("    })();")
    script_parts.append("")

    # Optional early capture hooks
    if early_hooks:
        script_parts.append("    if (TRELLIS_CONFIG.earlyCapture) {")
        script_parts.append("")
        for hook in early_hooks:
            hook_lines = hook.split("\n")
            indented_hook = "\n".join(
                "        " + line if line.strip() else line
                for line in hook_lines
            )
            script_parts.append(indented_hook)
        script_parts.append("    }")
        script_parts.append("")

    # Wrap hooks in lazy loading to prevent iOS watchdog kills
    if use_lazy_loading:
        script_parts.append("    if (TRELLIS_CONFIG.useLazyLoading) {")
        script_parts.append("        // Defer hook installation until app has fully launched")
        script_parts.append("        // This prevents iOS watchdog from killing the app during startup")
        script_parts.append("        deferHooksUntilReady(function() {")
        script_parts.append("")

        # Add all hooks (extra indented for the deferred wrapper)
        for hook in hooks:
            hook_lines = hook.split("\n")
            indented_hook = "\n".join(
                "            " + line if line.strip() else line
                for line in hook_lines
            )
            script_parts.append(indented_hook)

        script_parts.append("        });  // end deferHooksUntilReady")
        script_parts.append("    } else {")
        script_parts.append("        // Immediate hook installation (may impact app startup)")
        script_parts.append("")
        for hook in hooks:
            hook_lines = hook.split("\n")
            indented_hook = "\n".join(
                "        " + line if line.strip() else line
                for line in hook_lines
            )
            script_parts.append(indented_hook)
        script_parts.append("    }")
    else:
        # Immediate hook installation (not recommended for iOS with many hooks)
        script_parts.append("    // WARNING: Immediate hook installation - may cause watchdog kills on iOS")
        script_parts.append("    // Consider using lazy loading for production use")
        script_parts.append("")
        for hook in hooks:
            script_parts.append(hook)

    script_parts.append("})();")

    return "\n".join(script_parts)


def generate_category_script(category: str, binary_name: str) -> Optional[str]:
    """
    Generate a complete Frida script for an entire category.

    This is a convenience function that loads a category's signature database
    and generates hooks for all functions in it.

    Args:
        category: Category name (e.g., "crypto", "networking")
        binary_name: Target binary/application name

    Returns:
        Complete Frida script as a string, or None if category not found

    Example:
        >>> script = generate_category_script("crypto", "MyApp")
        >>> if script:
        ...     with open("crypto_hooks.js", "w") as f:
        ...         f.write(script)
    """
    from ...signatures import load_category

    db = load_category(category)
    if db is None:
        return None

    hooks = [generate_hook(func) for func in db.functions.values()]
    return combine_hooks(hooks, category, binary_name)


__all__ = [
    "get_script_header",
    "get_frida_formatter",
    "generate_hook",
    "combine_hooks",
    "generate_category_script",
    "CC_CONSTANTS",
    "FRIDA_RUNTIME_HELPERS",
]
