"""
Frida script generator for cryptographic operation hooks.

This module provides specialized hook generation for cryptographic functions,
including CommonCrypto, Security.framework, and other crypto APIs. It enhances
base hooks with crypto-specific security checks and warnings.

Example usage:
    >>> from trellis.generators.frida.crypto import generate_crypto_script
    >>>
    >>> # Generate hooks for all crypto functions
    >>> script = generate_crypto_script("MyApp")
    >>> with open("crypto_hooks.js", "w") as f:
    ...     f.write(script)
"""

from typing import Optional

from ...signatures import load_category, FunctionSignature
from .base import combine_hooks


# Crypto-specific constants and helper functions
CRYPTO_CONSTANTS = """
// Crypto Constants

// Helper: Safe hexdump wrapper
function trellisHexdump(ptr, length, maxBytes) {
    maxBytes = maxBytes || 256;
    if (length > maxBytes) {
        return trellisHexdump(ptr, maxBytes) + '\n[... truncated ' + (length - maxBytes) + ' bytes ...]';
    }
    try {
        return hexdump(ptr, { length: length, header: false, ansi: false });
    } catch (e) {
        return '<hexdump failed: ' + e + '>';
    }
}

// CCAlgorithm enumeration
const CCAlgorithm = {
    0: 'AES',
    1: 'DES (INSECURE)',
    2: '3DES (DEPRECATED)',
    3: 'CAST',
    4: 'RC4 (INSECURE)',
    5: 'RC2'
};

// CCOperation enumeration
const CCOperation = {
    0: 'Encrypt',
    1: 'Decrypt'
};

// CCOptions flags
const CCOptions = {
    0x0000: 'None',
    0x0001: 'PKCS7Padding',
    0x0002: 'ECBMode (INSECURE)'
};

// CCHmacAlgorithm enumeration
const CCHmacAlgorithm = {
    0: 'SHA1 (BROKEN)',
    1: 'MD5 (BROKEN)',
    2: 'SHA256',
    3: 'SHA384',
    4: 'SHA512',
    5: 'SHA224'
};

// CCDigestAlgorithm enumeration
const CCDigestAlgorithm = {
    8: 'SHA1 (BROKEN)',
    9: 'SHA224',
    10: 'SHA256',
    11: 'SHA384',
    12: 'SHA512'
};

// CCPBKDFAlgorithm enumeration
const CCPBKDFAlgorithm = {
    2: 'PBKDF2'
};

// CCPseudoRandomAlgorithm enumeration (PRF for PBKDF2)
const CCPseudoRandomAlgorithm = {
    1: 'HMAC-SHA1 (WEAK)',
    2: 'HMAC-SHA224',
    3: 'HMAC-SHA256',
    4: 'HMAC-SHA384',
    5: 'HMAC-SHA512'
};

// Helper: Check if PRF algorithm is weak
function checkWeakPRF(prf) {
    return prf === 1; // HMAC-SHA1
}

// Helper: Check if PBKDF2 rounds are insufficient
function checkWeakRounds(rounds) {
    if (rounds < 10000) return 'CRITICALLY_WEAK';
    if (rounds < 100000) return 'WEAK';
    return null;
}

// Helper: Log password (for PBKDF2)
function logPassword(passwordPtr, passwordLen) {
    if (passwordPtr && !passwordPtr.isNull() && passwordLen > 0) {
        try {
            var password = passwordPtr.readUtf8String(passwordLen);
            console.log("  [!!!] PASSWORD CAPTURED: '" + password + "'");
        } catch (e) {
            console.log("  [!] Password (hex):");
            console.log(trellisHexdump(passwordPtr, Math.min(passwordLen, 64), 64));
        }
    }
}

// Helper: Check if ECB mode is being used (insecure)
function checkECBMode(options) {
    return (options & 0x0002) !== 0;
}

// Helper: Check if algorithm is weak
function checkWeakAlgorithm(algorithm) {
    const weakAlgorithms = [1, 2, 4]; // DES, 3DES, RC4
    return weakAlgorithms.indexOf(algorithm) !== -1;
}

// Helper: Check if hash algorithm is weak
function checkWeakHashAlgorithm(algorithm) {
    const weakHashes = [0, 1]; // SHA1, MD5
    return weakHashes.indexOf(algorithm) !== -1;
}

// Helper: Log key material as hexdump
function logKeyMaterial(keyPtr, keyLength, label) {
    if (keyPtr && keyLength > 0) {
        console.log("  [!] " + label + " (" + keyLength + " bytes):");
        console.log(trellisHexdump(keyPtr, keyLength, keyLength));
    }
}
"""


def generate_crypto_hook(signature: FunctionSignature) -> str:
    """
    Generate a specialized Frida hook for a cryptographic function.

    Enhances the base hook with crypto-specific security checks:
    - Warns about ECB mode usage (no IV)
    - Flags weak algorithms (DES, 3DES, RC4)
    - Flags weak hash algorithms (MD5, SHA1)
    - Logs key material as hexdump
    - Decodes crypto enums to readable strings

    Args:
        signature: FunctionSignature object defining the function to hook

    Returns:
        Complete JavaScript code for the hook
    """
    func_name = signature.name
    library = signature.library

    # Crypto functions are always in system libraries - use global export search first
    # This is more reliable for dyld shared cache on iOS
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
    }}

    if (funcPtr) {{
        console.log("[*] Hooking {func_name} at", funcPtr);

        Interceptor.attach(funcPtr, {{
            onEnter: function(args) {{
                console.log("\\n[+] {func_name} called");
'''

    # Add parameter logging with crypto-specific formatting
    for i, param in enumerate(signature.parameters):
        param_name = param.name
        param_type = param.type

        # Handle CCOperation enum
        if 'op' in param_name.lower() and 'operation' in param_type.lower():
            hook_code += f'''                this.op = args[{i}].toInt32();
                console.log("  [{i}] {param_name}: " + (CCOperation[this.op] || this.op));
'''

        # Handle CCPBKDFAlgorithm (for CCKeyDerivationPBKDF) - check BEFORE generic CCAlgorithm
        elif param_type == 'CCPBKDFAlgorithm':
            hook_code += f'''                var pbkdfAlg = args[{i}].toInt32();
                console.log("  [{i}] {param_name}: " + (CCPBKDFAlgorithm[pbkdfAlg] || pbkdfAlg));
'''

        # Handle CCPseudoRandomAlgorithm (PRF for PBKDF2) - check BEFORE generic CCAlgorithm
        elif param_type == 'CCPseudoRandomAlgorithm':
            hook_code += f'''                this.prf = args[{i}].toInt32();
                var prfStr = CCPseudoRandomAlgorithm[this.prf] || this.prf;
                console.log("  [{i}] {param_name}: " + prfStr);
                if (checkWeakPRF(this.prf)) {{
                    console.log("  [!] WARNING: Weak PRF (HMAC-SHA1) - prefer SHA256+");
                }}
'''

        # Handle CCAlgorithm enum (generic - after specific algorithm types)
        elif 'alg' in param_name.lower() or 'algorithm' in param_type.lower():
            if 'hmac' in func_name.lower():
                hook_code += f'''                this.algorithm = args[{i}].toInt32();
                var algStr = CCHmacAlgorithm[this.algorithm] || this.algorithm;
                console.log("  [{i}] {param_name}: " + algStr);
                if (checkWeakHashAlgorithm(this.algorithm)) {{
                    console.log("  [!] WARNING: Weak hash algorithm detected!");
                }}
'''
            elif 'digest' in func_name.lower() or 'sha' in func_name.lower() or 'md5' in func_name.lower():
                hook_code += f'''                this.algorithm = args[{i}].toInt32();
                var algStr = CCDigestAlgorithm[this.algorithm] || this.algorithm;
                console.log("  [{i}] {param_name}: " + algStr);
'''
            else:
                hook_code += f'''                this.algorithm = args[{i}].toInt32();
                var algStr = CCAlgorithm[this.algorithm] || this.algorithm;
                console.log("  [{i}] {param_name}: " + algStr);
                if (checkWeakAlgorithm(this.algorithm)) {{
                    console.log("  [!] WARNING: Weak encryption algorithm!");
                }}
'''

        # Handle CCOptions flags
        elif 'option' in param_name.lower():
            hook_code += f'''                this.options = args[{i}].toInt32();
                console.log("  [{i}] {param_name}: 0x" + this.options.toString(16));
                if (checkECBMode(this.options)) {{
                    console.log("  [!!!] CRITICAL: ECB mode is INSECURE!");
                }}
'''

        # Handle password parameter (const char* in PBKDF)
        elif param_name.lower() == 'password' and 'char*' in param_type:
            # Find the passwordLen parameter
            for j, size_param in enumerate(signature.parameters):
                if size_param.name.lower() == 'passwordlen':
                    hook_code += f'''                this.password = args[{i}];
                this.passwordLen = args[{j}].toInt32();
                console.log("  [{i}] {param_name}: <" + this.passwordLen + " bytes>");
                logPassword(this.password, this.passwordLen);
'''
                    break
            else:
                hook_code += f'''                this.password = args[{i}];
                console.log("  [{i}] {param_name}: " + this.password.readUtf8String());
'''

        # Handle rounds parameter (for PBKDF2)
        elif param_name.lower() == 'rounds':
            hook_code += f'''                this.rounds = args[{i}].toInt32();
                console.log("  [{i}] {param_name}: " + this.rounds);
                var roundsWarning = checkWeakRounds(this.rounds);
                if (roundsWarning === 'CRITICALLY_WEAK') {{
                    console.log("  [!!!] CRITICAL: Iteration count < 10000 is INSECURE!");
                }} else if (roundsWarning === 'WEAK') {{
                    console.log("  [!] WARNING: Iteration count < 100000 is weak");
                }}
'''

        # Handle salt parameter (for PBKDF2)
        elif param_name.lower() == 'salt':
            # Find the saltLen parameter
            for j, size_param in enumerate(signature.parameters):
                if size_param.name.lower() == 'saltlen':
                    hook_code += f'''                this.salt = args[{i}];
                this.saltLen = args[{j}].toInt32();
                console.log("  [{i}] {param_name}: <" + this.saltLen + " bytes>");
                if (this.saltLen < 8) {{
                    console.log("  [!] WARNING: Salt too short (< 8 bytes)");
                }}
                if (!this.salt.isNull() && this.saltLen > 0) {{
                    console.log(trellisHexdump(this.salt, Math.min(this.saltLen, 32), 32));
                }}
'''
                    break
            else:
                hook_code += f'''                console.log("  [{i}] {param_name}: " + args[{i}]);
'''

        # Handle key material
        elif 'key' in param_name.lower() and param_type in ['void*', 'const void*', 'uint8_t*']:
            hook_code += f'''                this.key = args[{i}];
'''
            # If there's a keyLength parameter, store it
            for j, size_param in enumerate(signature.parameters):
                if 'length' in size_param.name.lower() and 'key' in size_param.name.lower():
                    hook_code += f'''                this.keyLength = args[{j}].toInt32();
                console.log("  [{i}] {param_name}: <pointer> (length: " + this.keyLength + " bytes)");
'''
                    break
            else:
                hook_code += f'''                console.log("  [{i}] {param_name}: " + this.key);
'''

        # Handle IV (initialization vector)
        elif 'iv' in param_name.lower():
            hook_code += f'''                this.iv = args[{i}];
                if (this.iv.isNull()) {{
                    console.log("  [{i}] {param_name}: NULL");
                    console.log("  [!] WARNING: No IV provided (ECB mode?)");
                }} else {{
                    console.log("  [{i}] {param_name}: <pointer>");
                }}
'''

        # Handle size_t and numeric parameters
        elif param_type in ['size_t', 'int', 'uint32_t', 'CCCryptorStatus']:
            hook_code += f'''                console.log("  [{i}] {param_name}: " + args[{i}].toInt32());
'''

        # Handle pointer parameters
        elif '*' in param_type:
            hook_code += f'''                console.log("  [{i}] {param_name}: " + args[{i}]);
'''

    hook_code += '''
                // Backtrace with Ghidra addresses
                var mainModule = getMainAppModule();
                console.log("  [!] Backtrace (BN = Ghidra offset):");
                console.log(formatBacktrace(this.context, mainModule, 5));

                // Log key material if available
                if (this.key && this.keyLength) {
                    logKeyMaterial(this.key, this.keyLength, "Key Material");
                }
            },
            onLeave: function(retval) {
                console.log("  => Return: " + retval);
            }
        });
    } else {
        console.log("[-] {func_name} not found in {library}");
    }
})();
'''.replace('{func_name}', func_name).replace('{library}', library)

    return hook_code


def generate_crypto_script(binary_name: str = "(auto-detected)", timestamp: Optional[str] = None) -> Optional[str]:
    """
    Generate a complete Frida script for cryptographic function monitoring.

    This function creates a comprehensive script that hooks all cryptographic
    functions and provides detailed logging with security warnings for weak
    algorithms, ECB mode usage, and key material exposure.

    Args:
        binary_name: Name of the target binary/application
        timestamp: Optional timestamp string for the header comment

    Returns:
        Complete Frida script as a string, or None if category not found

    Example:
        >>> script = generate_crypto_script("MyApp")
        >>> with open("crypto_hooks.js", "w") as f:
        ...     f.write(script)
    """
    # Load crypto category signatures
    db = load_category("crypto")
    if db is None:
        return None

    # Generate hooks for all functions
    hooks = []
    for func in db.functions.values():
        hook = generate_crypto_hook(func)
        hooks.append(hook)

    # Build the script
    from datetime import datetime
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    header = f"""// trellis_crypto_hooks.js
// Generated by Trellis - CRYPTO category
// Target: {binary_name}
// Generated: {timestamp}
// Frida API: 17.x+ compatible
//
// This script hooks iOS cryptographic operations and provides detailed
// logging of encryption/decryption calls, including security warnings for:
// - ECB mode usage (no IV)
// - Weak algorithms (DES, 3DES, RC4)
// - Weak hash functions (MD5, SHA1)
// - Key material exposure
//
// Features:
// - Ghidra address translation for cross-referencing
// - Jailbreak-safe app module detection
"""

    return combine_hooks(
        hooks=hooks,
        category="crypto",
        binary_name=binary_name,
        include_constants=False,
        include_runtime_helpers=True,
        early_hooks=None,
        use_lazy_loading=True,
        timestamp=timestamp,
        header_override=header,
        extra_prelude=CRYPTO_CONSTANTS,
    )


__all__ = [
    "generate_crypto_hook",
    "generate_crypto_script",
    "CRYPTO_CONSTANTS",
]
