"""
Frida script generator for iOS Keychain Services hooks.

This module provides specialized hook generation for keychain operations,
including secret storage, retrieval, and security attribute monitoring.
It enhances base hooks with keychain-specific security checks and warnings.

Example usage:
    >>> from trellis.generators.frida.keychain import generate_keychain_script
    >>>
    >>> # Generate hooks for all keychain functions
    >>> script = generate_keychain_script("MyApp")
    >>> with open("keychain_hooks.js", "w") as f:
    ...     f.write(script)
"""

from typing import Optional

from ...signatures import load_category, FunctionSignature
from .base import combine_hooks


# Keychain-specific constants and helper functions
KEYCHAIN_CONSTANTS = """
// Keychain Constants

// kSecClass values
const kSecClass = {
    'kSecClassGenericPassword': 'GenericPassword',
    'kSecClassInternetPassword': 'InternetPassword',
    'kSecClassCertificate': 'Certificate',
    'kSecClassKey': 'Key',
    'kSecClassIdentity': 'Identity'
};

// kSecAttrAccessible values (with security level)
const kSecAttrAccessibleValues = {
    'kSecAttrAccessibleAlways': {
        name: 'Always',
        secure: false,
        description: 'INSECURE: No device lock required'
    },
    'kSecAttrAccessibleAlwaysThisDeviceOnly': {
        name: 'AlwaysThisDeviceOnly',
        secure: false,
        description: 'INSECURE: No device lock, not backed up'
    },
    'kSecAttrAccessibleAfterFirstUnlock': {
        name: 'AfterFirstUnlock',
        secure: true,
        description: 'Accessible after first unlock'
    },
    'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly': {
        name: 'AfterFirstUnlockThisDeviceOnly',
        secure: true,
        description: 'After first unlock, not backed up'
    },
    'kSecAttrAccessibleWhenUnlocked': {
        name: 'WhenUnlocked',
        secure: true,
        description: 'RECOMMENDED: Only when device unlocked'
    },
    'kSecAttrAccessibleWhenUnlockedThisDeviceOnly': {
        name: 'WhenUnlockedThisDeviceOnly',
        secure: true,
        description: 'MOST SECURE: Unlocked, not backed up'
    },
    'kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly': {
        name: 'WhenPasscodeSetThisDeviceOnly',
        secure: true,
        description: 'Requires passcode, not backed up'
    }
};

// SecAccessControlCreateFlags
const SecAccessControlFlags = {
    0x00000001: 'UserPresence',
    0x00000002: 'BiometryAny (DEPRECATED)',
    0x00000004: 'BiometryCurrentSet',
    0x00000008: 'DevicePasscode',
    0x00000010: 'Or',
    0x00000020: 'And',
    0x00000040: 'PrivateKeyUsage',
    0x00000080: 'ApplicationPassword'
};

// OSStatus error codes
const OSStatusCodes = {
    0: 'errSecSuccess',
    [-4]: 'errSecUnimplemented',
    [-25291]: 'errSecNotAvailable',
    [-25292]: 'errSecReadOnly',
    [-25293]: 'errSecAuthFailed',
    [-25299]: 'errSecDuplicateItem',
    [-25300]: 'errSecItemNotFound',
    [-25308]: 'errSecInteractionNotAllowed',
    [-34018]: 'errSecMissingEntitlement'
};

// Helper: Decode keychain attributes from CFDictionary
function decodeKeychainAttributes(dictPtr) {
    if (!dictPtr || dictPtr.isNull() || typeof ObjC === 'undefined' || !ObjC.available) {
        return null;
    }

    try {
        var dict = new ObjC.Object(dictPtr);
        var attributes = {};

        // Extract common attributes
        var keys = ['kSecClass', 'kSecAttrService', 'kSecAttrAccount', 'kSecAttrAccessible',
                    'kSecAttrSynchronizable', 'kSecAttrAccessGroup', 'kSecReturnData',
                    'kSecReturnAttributes', 'kSecValueData'];

        keys.forEach(function(key) {
            try {
                var value = dict.objectForKey_(key);
                if (value) {
                    attributes[key] = value.toString();
                }
            } catch (e) {}
        });

        return attributes;
    } catch (e) {
        return null;
    }
}

// Helper: Check if accessibility level is insecure
function checkInsecureAccessibility(accessible) {
    var insecure = ['kSecAttrAccessibleAlways', 'kSecAttrAccessibleAlwaysThisDeviceOnly'];
    return insecure.indexOf(accessible) !== -1;
}

// Helper: Decode OSStatus
function decodeOSStatus(status) {
    return OSStatusCodes[status] || ('OSStatus: ' + status);
}

// Helper: Flag private key export
function flagPrivateKeyExport(keyPtr, functionName) {
    console.log("  [!!!] CRITICAL: Private key being exported via " + functionName);
    console.log("  [!] This may indicate insecure key storage or transmission");
}

// Helper: Decode SecAccessControl flags
function decodeAccessControlFlags(flags) {
    var flagsArray = [];
    for (var flag in SecAccessControlFlags) {
        if ((flags & parseInt(flag)) !== 0) {
            flagsArray.push(SecAccessControlFlags[flag]);
        }
    }
    return flagsArray.length > 0 ? flagsArray.join(' | ') : 'None';
}
"""


def generate_keychain_hook(signature: FunctionSignature) -> str:
    """
    Generate a specialized Frida hook for a keychain function.

    Enhances the base hook with keychain-specific security checks:
    - Decodes kSecAttr* constants to readable strings
    - Warns about insecure accessibility levels (Always, AlwaysThisDeviceOnly)
    - Flags iCloud synchronization settings
    - Monitors private key exports
    - Decodes OSStatus return values

    Args:
        signature: FunctionSignature object defining the function to hook

    Returns:
        Complete JavaScript code for the hook
    """
    func_name = signature.name
    library = signature.library

    # Use findExport helper for Frida 17+ compatibility with dyld shared cache
    hook_code = f'''
// Hook: {func_name}
(function() {{
    var funcPtr = findExport("{func_name}", "{library}");

    if (funcPtr) {{
        console.log("[*] Hooking {func_name} at", funcPtr);

        Interceptor.attach(funcPtr, {{
            onEnter: function(args) {{
                console.log("\\n[+] {func_name} called");
'''

    # Add keychain-specific parameter handling
    if func_name in ['SecItemAdd', 'SecItemUpdate', 'SecItemCopyMatching', 'SecItemDelete']:
        hook_code += '''
                // Decode keychain query dictionary
                var queryDict = args[0];
                if (queryDict && !queryDict.isNull()) {
                    console.log("  [0] query dictionary:");
                    var attrs = decodeKeychainAttributes(queryDict);
                    if (attrs) {
                        for (var key in attrs) {
                            console.log("      " + key + ": " + attrs[key]);

                            // Security checks
                            if (key === 'kSecAttrAccessible') {
                                if (checkInsecureAccessibility(attrs[key])) {
                                    console.log("      [!!!] INSECURE: Always accessible (no device lock)");
                                }
                            }
                            if (key === 'kSecAttrSynchronizable' && attrs[key] === 'true') {
                                console.log("      [!] WARNING: Item will sync to iCloud Keychain");
                            }
                        }
                    }
                }
'''

    elif 'SecKey' in func_name:
        # Security.framework key operations
        for i, param in enumerate(signature.parameters):
            param_name = param.name
            if 'key' in param_name.lower():
                hook_code += f'''                console.log("  [{i}] {param_name}: " + args[{i}]);
                if ("{func_name}".indexOf("Export") !== -1) {{
                    flagPrivateKeyExport(args[{i}], "{func_name}");
                }}
'''
            elif 'CFData' in param.type or 'NSData' in param.type:
                hook_code += f'''                var data = args[{i}];
                if (data && !data.isNull() && typeof ObjC !== 'undefined') {{
                    try {{
                        var nsdata = new ObjC.Object(data);
                        console.log("  [{i}] {param_name}: <" + nsdata.length() + " bytes>");
                    }} catch (e) {{
                        console.log("  [{i}] {param_name}: " + data);
                    }}
                }} else {{
                    console.log("  [{i}] {param_name}: " + data);
                }}
'''
            else:
                hook_code += f'''                console.log("  [{i}] {param_name}: " + args[{i}]);
'''

    elif func_name == 'SecAccessControlCreateWithFlags':
        hook_code += '''
                console.log("  [0] allocator: " + args[0]);

                var protection = args[1];
                if (protection && !protection.isNull() && typeof ObjC !== 'undefined') {
                    try {
                        var protStr = new ObjC.Object(protection).toString();
                        console.log("  [1] protection: " + protStr);
                        if (checkInsecureAccessibility(protStr)) {
                            console.log("      [!!!] INSECURE: Always accessible");
                        }
                    } catch (e) {
                        console.log("  [1] protection: " + protection);
                    }
                }

                var flags = args[2].toInt32();
                console.log("  [2] flags: 0x" + flags.toString(16) + " (" + decodeAccessControlFlags(flags) + ")");

                console.log("  [3] error: " + args[3]);
'''

    else:
        # Generic parameter logging
        for i, param in enumerate(signature.parameters):
            param_name = param.name
            param_type = param.type

            if 'CFDictionary' in param_type or 'NSDictionary' in param_type:
                hook_code += f'''                console.log("  [{i}] {param_name}: <dictionary>");
'''
            elif 'CFData' in param_type or 'NSData' in param_type:
                hook_code += f'''                console.log("  [{i}] {param_name}: <data>");
'''
            elif param_type in ['OSStatus', 'int']:
                hook_code += f'''                console.log("  [{i}] {param_name}: " + args[{i}].toInt32());
'''
            else:
                hook_code += f'''                console.log("  [{i}] {param_name}: " + args[{i}]);
'''

    hook_code += '''
                // Backtrace with Ghidra addresses
                var mainModule = getMainAppModule();
                console.log("  [!] Backtrace (BN = Ghidra offset):");
                console.log(formatBacktrace(this.context, mainModule, 5));
            },
            onLeave: function(retval) {
'''

    # Handle OSStatus return values
    if signature.return_type and signature.return_type.type == 'OSStatus':
        hook_code += '''                var status = retval.toInt32();
                var statusStr = decodeOSStatus(status);
                console.log("  => Return: " + statusStr + " (" + status + ")");

                if (status !== 0) {
                    console.log("  [!] Operation failed with error: " + statusStr);
                }
'''
    else:
        hook_code += '''                console.log("  => Return: " + retval);
'''

    hook_code += '''            }
        });
    } else {
        console.log("[-] {func_name} not found in {library}");
    }
}})();
'''.replace('{func_name}', func_name).replace('{library}', library)

    return hook_code


def generate_keychain_script(binary_name: str = "(auto-detected)", timestamp: Optional[str] = None) -> Optional[str]:
    """
    Generate a complete Frida script for keychain operation monitoring.

    This function creates a comprehensive script that hooks all iOS Keychain
    Services functions, providing detailed logging with security warnings for:
    - Insecure accessibility levels (Always, AlwaysThisDeviceOnly)
    - iCloud Keychain synchronization
    - Private key exports
    - Access control flags

    Args:
        binary_name: Name of the target binary/application
        timestamp: Optional timestamp string for the header comment

    Returns:
        Complete Frida script as a string, or None if category not found

    Example:
        >>> script = generate_keychain_script("MyApp")
        >>> with open("keychain_hooks.js", "w") as f:
        ...     f.write(script)
    """
    # Load keychain category signatures
    db = load_category("keychain")
    if db is None:
        return None

    # Generate hooks for all functions
    hooks = []
    for func in db.functions.values():
        hook = generate_keychain_hook(func)
        hooks.append(hook)

    # Build the script
    from datetime import datetime
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    header = f"""// trellis_keychain_hooks.js
// Generated by Trellis - KEYCHAIN category
// Target: {binary_name}
// Generated: {timestamp}
// Frida API: 17.x+ compatible
//
// This script hooks iOS Keychain Services operations, providing detailed
// logging of secret storage and retrieval with security warnings for:
// - Insecure accessibility levels (Always, AlwaysThisDeviceOnly)
// - iCloud Keychain synchronization
// - Private key exports
// - Access control flags
//
// Features:
// - Ghidra address translation for cross-referencing
// - Jailbreak-safe app module detection
"""

    return combine_hooks(
        hooks=hooks,
        category="keychain",
        binary_name=binary_name,
        include_constants=False,
        include_runtime_helpers=True,
        early_hooks=None,
        use_lazy_loading=True,
        timestamp=timestamp,
        header_override=header,
        extra_prelude=KEYCHAIN_CONSTANTS,
    )


__all__ = [
    "generate_keychain_hook",
    "generate_keychain_script",
    "KEYCHAIN_CONSTANTS",
]
