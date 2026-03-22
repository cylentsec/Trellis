"""
Frida script generator for networking and TLS security hooks.

This module provides specialized hook generation for network security functions,
including TLS/SSL operations, certificate validation, and connection security.
It enhances base hooks with TLS-specific security checks and warnings.

Example usage:
    >>> from trellis.generators.frida.networking import generate_networking_script
    >>>
    >>> # Generate hooks for all networking functions
    >>> script = generate_networking_script("MyApp")
    >>> with open("networking_hooks.js", "w") as f:
    ...     f.write(script)
"""

from typing import Optional

from ...signatures import load_category, FunctionSignature
from .base import combine_hooks


# Networking-specific constants and helper functions
NETWORKING_CONSTANTS = """
// Networking/TLS Constants

// TLS Protocol Versions
const TLSVersion = {
    0x0301: 'TLS 1.0 (INSECURE)',
    0x0302: 'TLS 1.1 (DEPRECATED)',
    0x0303: 'TLS 1.2',
    0x0304: 'TLS 1.3'
};

// SSL/TLS Connection States
const SSLSessionState = {
    0: 'kSSLIdle',
    1: 'kSSLHandshake',
    2: 'kSSLConnected',
    3: 'kSSLClosed',
    4: 'kSSLAborted'
};

// SecTrustResultType enumeration
const SecTrustResult = {
    0: 'kSecTrustResultInvalid',
    1: 'kSecTrustResultProceed',
    2: 'kSecTrustResultConfirm',
    3: 'kSecTrustResultDeny',
    4: 'kSecTrustResultUnspecified',
    5: 'kSecTrustResultRecoverableTrustFailure',
    6: 'kSecTrustResultFatalTrustFailure',
    7: 'kSecTrustResultOtherError'
};

// Helper: Decode TLS version
function decodeTLSVersion(version) {
    if (typeof version === 'number') {
        return TLSVersion[version] || ('0x' + version.toString(16));
    }
    return version;
}

// Helper: Check if TLS version is secure
function isTLSVersionSecure(version) {
    // TLS 1.2 (0x0303) and TLS 1.3 (0x0304) are secure
    return version === 0x0303 || version === 0x0304;
}

// Helper: Describe certificate (if available via ObjC runtime)
function describeCertificate(certRef) {
    if (typeof ObjC !== 'undefined' && ObjC.available) {
        try {
            var cert = new ObjC.Object(certRef);
            return cert.toString();
        } catch (e) {
            return "<certificate>";
        }
    }
    return "<certificate>";
}

// Helper: Decode trust result
function decodeTrustResult(result) {
    return SecTrustResult[result] || result;
}

// Helper: Check if trust result indicates failure
function isTrustResultFailure(result) {
    // 0 (Invalid), 3 (Deny), 5 (Recoverable), 6 (Fatal), 7 (Other) are failures
    return [0, 3, 5, 6, 7].indexOf(result) !== -1;
}
"""


def _enhance_ssl_set_peer_domain_name(hook_code: str) -> str:
    """Add hostname verification check to SSLSetPeerDomainName hook."""
    # Insert warning if hostname is NULL
    enhancement = '''
                if (args[1].isNull()) {
                    console.log("  [!!!] CRITICAL: Hostname is NULL - peer verification disabled!");
                } else {'''

    # Find the logging section and add our check
    return hook_code.replace(
        '                console.log("  [1] peerName:',
        enhancement + '\n                console.log("  [1] peerName:'
    ).replace(
        '            },\n            onLeave:',
        '''                }
            },
            onLeave:'''
    )


def _enhance_ssl_set_session_option(hook_code: str) -> str:
    """Add warning for kSSLSessionOptionBreakOnServerAuth option."""
    enhancement = '''
                // Check for security-relevant options
                var option = args[1].toInt32();
                var value = args[2].toInt32();

                // kSSLSessionOptionBreakOnServerAuth = 0
                if (option === 0 && value === 1) {
                    console.log("  [!] WARNING: Breaking on server auth (manual validation)");
                }

                // kSSLSessionOptionBreakOnCertRequested = 1
                if (option === 1) {
                    console.log("  [!] Client certificate requested");
                }
'''

    return hook_code.replace(
        '            onEnter: function(args) {',
        '            onEnter: function(args) {\n' + enhancement
    )


def _enhance_ssl_set_peer_id(hook_code: str) -> str:
    """Add peer ID logging enhancement."""
    # Just return the hook as-is, base implementation is sufficient
    return hook_code


def _enhance_sec_trust_evaluate(hook_code: str) -> str:
    """Add trust evaluation result checking."""
    enhancement = '''
                // Check trust evaluation result
                var resultPtr = args[1];
                if (resultPtr && !resultPtr.isNull()) {
                    var result = resultPtr.readU32();
                    var resultStr = decodeTrustResult(result);
                    console.log("  [!] Trust Result: " + resultStr);

                    if (isTrustResultFailure(result)) {
                        console.log("  [!!!] CRITICAL: Certificate validation FAILED!");
                    } else if (result === 1) {
                        console.log("  [!] Trust explicitly granted (check if cert pinning in place)");
                    }
                }
'''

    return hook_code.replace(
        '            onLeave: function(retval) {',
        '            onLeave: function(retval) {\n' + enhancement
    )


def _enhance_sec_trust_set_anchor_certificates(hook_code: str) -> str:
    """Add anchor certificate warning."""
    enhancement = '''
                // Setting custom anchor certificates
                var certsArray = args[1];
                if (certsArray && !certsArray.isNull() && typeof ObjC !== 'undefined') {
                    try {
                        var arr = new ObjC.Object(certsArray);
                        var count = arr.count();
                        console.log("  [!] Setting " + count + " custom anchor certificate(s)");
                        console.log("  [!] This may indicate certificate pinning");
                    } catch (e) {
                        console.log("  [!] Custom anchor certificates set");
                    }
                }
'''

    return hook_code.replace(
        '            onEnter: function(args) {',
        '            onEnter: function(args) {\n' + enhancement
    )


def _enhance_sec_trust_set_policies(hook_code: str) -> str:
    """Add trust policy logging."""
    enhancement = '''
                // Setting trust policies
                console.log("  [!] Custom trust policies being set");
                console.log("  [!] May affect certificate validation behavior");
'''

    return hook_code.replace(
        '            onEnter: function(args) {',
        '            onEnter: function(args) {\n' + enhancement
    )


def _enhance_nw_connection_create(hook_code: str) -> str:
    """Add network connection parameter extraction."""
    # Network.framework hooks need ObjC runtime
    enhancement = '''
                // Network connection being created
                if (typeof ObjC !== 'undefined' && ObjC.available) {
                    try {
                        var endpoint = new ObjC.Object(args[0]);
                        console.log("  [!] Endpoint: " + endpoint.toString());
                    } catch (e) {
                        console.log("  [!] Endpoint: <unavailable>");
                    }
                }
'''

    return hook_code.replace(
        '            onEnter: function(args) {',
        '            onEnter: function(args) {\n' + enhancement
    )


def _enhance_ssl_set_protocol_version_min(hook_code: str) -> str:
    """Add TLS version security check."""
    enhancement = '''
                var version = args[1].toInt32();
                var versionStr = decodeTLSVersion(version);
                console.log("  [!] Minimum TLS version: " + versionStr);

                if (!isTLSVersionSecure(version)) {
                    console.log("  [!!!] CRITICAL: Allowing insecure TLS version!");
                }
'''

    return hook_code.replace(
        '            onEnter: function(args) {',
        '            onEnter: function(args) {\n' + enhancement
    )


def _enhance_ssl_handshake(hook_code: str) -> str:
    """Add SSL handshake state logging."""
    enhancement = '''
                console.log("  [!] SSL handshake initiated");
                console.log("  [!] Check for certificate validation bypass");
'''

    return hook_code.replace(
        '            onEnter: function(args) {',
        '            onEnter: function(args) {\n' + enhancement
    )


def generate_networking_hook(signature: FunctionSignature) -> str:
    """
    Generate a specialized Frida hook for a networking/TLS function.

    Enhances the base hook with networking-specific security checks:
    - Warns about insecure TLS versions (< TLS 1.2)
    - Flags missing hostname verification
    - Monitors certificate validation results
    - Detects certificate pinning implementations
    - Logs trust policy modifications

    Args:
        signature: FunctionSignature object defining the function to hook

    Returns:
        Complete JavaScript code for the hook
    """
    func_name = signature.name
    library = signature.library

    # Start with base hook structure - use findExport helper for Frida 17+ compatibility
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

    # Add parameter logging
    for i, param in enumerate(signature.parameters):
        param_name = param.name
        param_type = param.type

        if 'char*' in param_type or 'string' in param_type.lower():
            hook_code += f'''                var {param_name} = args[{i}];
                if ({param_name} && !{param_name}.isNull()) {{
                    console.log("  [{i}] {param_name}: " + {param_name}.readUtf8String());
                }} else {{
                    console.log("  [{i}] {param_name}: NULL");
                }}
'''
        elif param_type in ['int', 'uint32_t', 'size_t', 'OSStatus']:
            hook_code += f'''                console.log("  [{i}] {param_name}: " + args[{i}].toInt32());
'''
        elif 'bool' in param_type.lower():
            hook_code += f'''                console.log("  [{i}] {param_name}: " + (args[{i}].toInt32() ? "true" : "false"));
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
                console.log("  => Return: " + retval);
            }
        });
    } else {
        console.log("[-] {func_name} not found in {library}");
    }
}})();
'''.replace('{func_name}', func_name).replace('{library}', library)

    # Apply function-specific enhancements
    if func_name == 'SSLSetPeerDomainName':
        hook_code = _enhance_ssl_set_peer_domain_name(hook_code)
    elif func_name == 'SSLSetSessionOption':
        hook_code = _enhance_ssl_set_session_option(hook_code)
    elif func_name == 'SecTrustEvaluate' or func_name == 'SecTrustEvaluateWithError':
        hook_code = _enhance_sec_trust_evaluate(hook_code)
    elif func_name == 'SecTrustSetAnchorCertificates':
        hook_code = _enhance_sec_trust_set_anchor_certificates(hook_code)
    elif func_name == 'SecTrustSetPolicies':
        hook_code = _enhance_sec_trust_set_policies(hook_code)
    elif func_name == 'nw_connection_create':
        hook_code = _enhance_nw_connection_create(hook_code)
    elif func_name == 'SSLSetProtocolVersionMin':
        hook_code = _enhance_ssl_set_protocol_version_min(hook_code)
    elif func_name == 'SSLHandshake':
        hook_code = _enhance_ssl_handshake(hook_code)

    return hook_code


def generate_networking_script(binary_name: str = "(auto-detected)", timestamp: Optional[str] = None) -> Optional[str]:
    """
    Generate a complete Frida script for networking/TLS security monitoring.

    This function creates a comprehensive script that hooks all networking
    and TLS functions, providing detailed logging with security warnings for:
    - Insecure TLS versions
    - Missing hostname verification
    - Certificate validation failures
    - Custom trust policies
    - Certificate pinning detection

    Args:
        binary_name: Name of the target binary/application
        timestamp: Optional timestamp string for the header comment

    Returns:
        Complete Frida script as a string, or None if category not found

    Example:
        >>> script = generate_networking_script("MyApp")
        >>> with open("networking_hooks.js", "w") as f:
        ...     f.write(script)
    """
    # Load networking category signatures
    db = load_category("networking")
    if db is None:
        return None

    # Generate hooks for all functions
    early_hook_names = {
        "SSLSetProtocolVersionMin",
        "SSLSetProtocolVersionMax",
        "SSLSetPeerDomainName",
        "SecTrustEvaluate",
        "SecTrustEvaluateWithError",
        "SecTrustSetAnchorCertificates",
        "nw_parameters_set_tls_enabled",
    }
    hooks = []
    early_hooks = []
    for func in db.functions.values():
        hook = generate_networking_hook(func)
        if func.name in early_hook_names:
            early_hooks.append(hook)
        else:
            hooks.append(hook)

    # Build the script
    from datetime import datetime
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    header = f"""// trellis_networking_hooks.js
// Generated by Trellis - NETWORKING category
// Target: {binary_name}
// Generated: {timestamp}
// Frida API: 17.x+ compatible
//
// This script hooks iOS networking and TLS operations, providing detailed
// logging of connection security including warnings for:
// - Insecure TLS versions (< TLS 1.2)
// - Missing hostname verification
// - Certificate validation failures
// - Custom trust policies and certificate pinning
//
// Features:
// - Ghidra address translation for cross-referencing
// - Jailbreak-safe app module detection
"""

    return combine_hooks(
        hooks=hooks,
        category="networking",
        binary_name=binary_name,
        include_constants=False,
        include_runtime_helpers=True,
        early_hooks=early_hooks,
        use_lazy_loading=True,
        timestamp=timestamp,
        header_override=header,
        extra_prelude=NETWORKING_CONSTANTS,
    )


__all__ = [
    "generate_networking_hook",
    "generate_networking_script",
    "NETWORKING_CONSTANTS",
]
