"""
Frida script generator for anti-debugging detection hooks.

This module provides specialized hook generation for anti-debugging techniques,
including ptrace, sysctl, exception ports, and other debugger detection methods.
It can optionally include bypass code to circumvent anti-debugging protections.

Example usage:
    >>> from trellis.generators.frida.antidebug import generate_antidebug_script
    >>>
    >>> # Generate detection-only script
    >>> script = generate_antidebug_script("MyApp", include_bypass=False)
    >>>
    >>> # Generate script with bypass capabilities
    >>> script_with_bypass = generate_antidebug_script("MyApp", include_bypass=True)
"""

from typing import Optional

from ...signatures import load_category, FunctionSignature
from .base import combine_hooks


# Anti-debug-specific constants and helper functions
ANTIDEBUG_CONSTANTS = """
// Anti-Debug Constants

// ptrace request types
const PtraceRequest = {
    0: 'PT_TRACE_ME',
    1: 'PT_READ_I',
    2: 'PT_READ_D',
    3: 'PT_READ_U',
    4: 'PT_WRITE_I',
    5: 'PT_WRITE_D',
    6: 'PT_WRITE_U',
    7: 'PT_CONTINUE',
    8: 'PT_KILL',
    9: 'PT_STEP',
    10: 'PT_ATTACH',
    11: 'PT_DETACH',
    12: 'PT_SIGEXC',
    13: 'PT_THUPDATE',
    14: 'PT_ATTACHEXC',
    31: 'PT_DENY_ATTACH'
};

// sysctl MIB names
const SysctlMIB = {
    '1.14': 'KERN_PROC',
    '1.14.1': 'KERN_PROC_ALL',
    '1.14.12': 'KERN_PROC_PID'
};

// Process flags (P_* constants)
const ProcessFlags = {
    0x00000800: 'P_TRACED'
};

// Helper: Decode ptrace request
function decodePtraceRequest(request) {
    return PtraceRequest[request] || ('UNKNOWN_' + request);
}

// Helper: Format sysctl MIB
function formatSysctlMIB(mibPtr, mibLen) {
    if (!mibPtr || mibPtr.isNull() || mibLen === 0) {
        return 'NULL';
    }

    try {
        var mib = [];
        for (var i = 0; i < mibLen; i++) {
            mib.push(mibPtr.add(i * 4).readU32());
        }
        var mibStr = mib.join('.');
        return SysctlMIB[mibStr] || mibStr;
    } catch (e) {
        return 'ERROR';
    }
}

// Helper: Check if P_TRACED flag is set
function checkPTracedFlag(flags) {
    return (flags & 0x00000800) !== 0;
}

// Helper: Decode exception mask
function decodeExceptionMask(mask) {
    var exceptions = [];
    if (mask & 0x01) exceptions.push('EXC_BAD_ACCESS');
    if (mask & 0x02) exceptions.push('EXC_BAD_INSTRUCTION');
    if (mask & 0x04) exceptions.push('EXC_ARITHMETIC');
    if (mask & 0x08) exceptions.push('EXC_EMULATION');
    if (mask & 0x10) exceptions.push('EXC_SOFTWARE');
    if (mask & 0x20) exceptions.push('EXC_BREAKPOINT');
    if (mask & 0x40) exceptions.push('EXC_SYSCALL');
    if (mask & 0x80) exceptions.push('EXC_MACH_SYSCALL');
    return exceptions.length > 0 ? exceptions.join(' | ') : 'NONE';
}
"""

# Bypass helper functions (only included when include_bypass=True)
BYPASS_HELPERS = """
// Bypass Helpers

// Bypass ptrace PT_DENY_ATTACH
function bypassPtrace(args, retval) {
    var request = args[0].toInt32();
    if (request === 31) { // PT_DENY_ATTACH
        console.log("  [!] BYPASS: Forcing ptrace PT_DENY_ATTACH to return 0");
        retval.replace(0);
        return true;
    }
    return false;
}

// Bypass sysctl P_TRACED flag
function bypassSysctl(args, retval, oldpPtr) {
    if (!oldpPtr || oldpPtr.isNull()) {
        return false;
    }

    try {
        // Read kinfo_proc structure
        // The p_flag field is at offset 8 in kinfo_proc.kp_proc
        var flagsPtr = oldpPtr.add(32); // offset to p_flag in kp_proc
        var flags = flagsPtr.readU32();

        if (checkPTracedFlag(flags)) {
            console.log("  [!] BYPASS: Clearing P_TRACED flag");
            flagsPtr.writeU32(flags & ~0x00000800);
            return true;
        }
    } catch (e) {
        console.log("  [!] BYPASS ERROR: " + e);
    }
    return false;
}

// Bypass getppid (return 1 instead of debugger's PID)
function bypassGetppid(retval) {
    var ppid = retval.toInt32();
    if (ppid !== 1) {
        console.log("  [!] BYPASS: Changing parent PID from " + ppid + " to 1");
        retval.replace(1);
        return true;
    }
    return false;
}

// Bypass isatty (always return 0 - not a terminal)
function bypassIsatty(retval) {
    var result = retval.toInt32();
    if (result !== 0) {
        console.log("  [!] BYPASS: Changing isatty result from " + result + " to 0");
        retval.replace(0);
        return true;
    }
    return false;
}
"""


def generate_antidebug_hook(signature: FunctionSignature, include_bypass: bool = False) -> str:
    """
    Generate a specialized Frida hook for an anti-debugging function.

    Creates hooks that detect anti-debugging checks and optionally bypass them:
    - ptrace PT_DENY_ATTACH detection
    - sysctl P_TRACED flag monitoring
    - Exception port manipulation
    - getppid and isatty checks
    - Optional bypass code to circumvent protections

    Args:
        signature: FunctionSignature object defining the function to hook
        include_bypass: Whether to include bypass code (default: False)

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
'''

    # Function-specific logging
    if func_name == 'ptrace':
        hook_code += '''                var request = args[0].toInt32();
                var requestStr = decodePtraceRequest(request);
                this.request = request;

                console.log("\\n[+] ptrace called");
                console.log("  [0] request: " + requestStr + " (" + request + ")");

                if (request === 31) {
                    console.log("  [!!!] PT_DENY_ATTACH detected - attempting to block debugging!");
                }

                console.log("  [1] pid: " + args[1].toInt32());
                console.log("  [2] addr: " + args[2]);
                console.log("  [3] data: " + args[3].toInt32());
'''

    elif func_name == 'sysctl':
        hook_code += '''                var mibPtr = args[0];
                var mibLen = args[1].toInt32();
                var mibStr = formatSysctlMIB(mibPtr, mibLen);
                this.mibStr = mibStr;
                this.oldpPtr = args[2];

                console.log("\\n[+] sysctl called");
                console.log("  [0] mib: " + mibStr);
                console.log("  [1] miblen: " + mibLen);
                console.log("  [2] oldp: " + this.oldpPtr);
                console.log("  [3] oldlenp: " + args[3]);

                if (mibStr.indexOf('KERN_PROC') !== -1) {
                    console.log("  [!] WARNING: Process info query (may check P_TRACED flag)");
                }
'''

    elif func_name == 'syscall':
        hook_code += '''                var syscallNum = args[0].toInt32();
                this.syscallNum = syscallNum;

                console.log("\\n[+] syscall called");
                console.log("  [0] number: " + syscallNum);

                // SYS_ptrace = 26
                if (syscallNum === 26) {
                    var request = args[1].toInt32();
                    console.log("  [!!!] Direct ptrace syscall: " + decodePtraceRequest(request));
                }
'''

    elif func_name == 'getppid':
        hook_code += '''                console.log("\\n[+] getppid called");
                console.log("  [!] May be checking if parent is debugger");
'''

    elif func_name == 'isatty':
        hook_code += '''                console.log("\\n[+] isatty called");
                console.log("  [0] fd: " + args[0].toInt32());
                console.log("  [!] May be checking if running in terminal (debugger)");
'''

    elif func_name == 'task_get_exception_ports':
        hook_code += '''                console.log("\\n[+] task_get_exception_ports called");
                console.log("  [0] task: " + args[0]);
                console.log("  [1] exception_mask: 0x" + args[1].toInt32().toString(16));
                console.log("  [!] Querying exception ports (may detect debugger)");
'''

    else:
        # Generic logging
        hook_code += f'''                console.log("\\n[+] {func_name} called");
'''
        for i, param in enumerate(signature.parameters):
            if param.type in ['int', 'pid_t', 'uint32_t']:
                hook_code += f'''                console.log("  [{i}] {param.name}: " + args[{i}].toInt32());
'''
            else:
                hook_code += f'''                console.log("  [{i}] {param.name}: " + args[{i}]);
'''

    hook_code += '''
                // Backtrace with Ghidra addresses
                var mainModule = getMainAppModule();
                console.log("  [!] Backtrace (BN = Ghidra offset):");
                console.log(formatBacktrace(this.context, mainModule, 5));
            },
            onLeave: function(retval) {
                console.log("  => Return: " + retval);
'''

    # Add bypass logic if requested
    if include_bypass:
        if func_name == 'ptrace':
            hook_code += '''
                // BYPASS: Force PT_DENY_ATTACH to succeed
                if (bypassPtrace([ptr(this.request)], retval)) {
                    console.log("  [!] Successfully bypassed PT_DENY_ATTACH");
                }
'''
        elif func_name == 'sysctl':
            hook_code += '''
                // BYPASS: Clear P_TRACED flag
                if (this.mibStr.indexOf('KERN_PROC') !== -1) {
                    if (bypassSysctl([], retval, this.oldpPtr)) {
                        console.log("  [!] Successfully cleared P_TRACED flag");
                    }
                }
'''
        elif func_name == 'getppid':
            hook_code += '''
                // BYPASS: Return init PID (1) instead of debugger PID
                if (bypassGetppid(retval)) {
                    console.log("  [!] Successfully spoofed parent PID");
                }
'''
        elif func_name == 'isatty':
            hook_code += '''
                // BYPASS: Always return 0 (not a TTY)
                if (bypassIsatty(retval)) {
                    console.log("  [!] Successfully spoofed isatty result");
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


def generate_antidebug_script(binary_name: str = "(auto-detected)", include_bypass: bool = False) -> Optional[str]:
    """
    Generate a complete Frida script for anti-debugging detection monitoring.

    This function creates a comprehensive script that hooks all anti-debugging
    functions and provides detailed logging of detection attempts. When include_bypass
    is True, it also includes code to circumvent anti-debugging protections.

    Args:
        binary_name: Name of the target binary/application
        include_bypass: Whether to include bypass code (default: False)

    Returns:
        Complete Frida script as a string, or None if category not found

    Example:
        >>> # Generate detection-only script
        >>> script = generate_antidebug_script("MyApp", include_bypass=False)
        >>> with open("antidebug_detection.js", "w") as f:
        ...     f.write(script)
        >>>
        >>> # Generate script with bypass
        >>> bypass_script = generate_antidebug_script("MyApp", include_bypass=True)
        >>> with open("antidebug_bypass.js", "w") as f:
        ...     f.write(bypass_script)
    """
    # Load antidebug category signatures
    db = load_category("antidebug")
    if db is None:
        return None

    # Generate hooks for all functions
    early_hook_names = {
        "ptrace",
        "sysctl",
        "sysctlbyname",
        "getppid",
        "task_get_exception_ports",
    }
    hooks = []
    early_hooks = []
    for func in db.functions.values():
        hook = generate_antidebug_hook(func, include_bypass)
        if func.name in early_hook_names:
            early_hooks.append(hook)
        else:
            hooks.append(hook)

    # Build the script
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    bypass_note = " (WITH BYPASS)" if include_bypass else ""
    header = f"""// trellis_antidebug_hooks.js
// Generated by Trellis - ANTI-DEBUG category{bypass_note}
// Target: {binary_name}
// Generated: {timestamp}
// Frida API: 17.x+ compatible
//
// This script hooks iOS anti-debugging techniques and provides detailed
// logging of debugger detection attempts.
//
// Features:
// - Ghidra address translation for cross-referencing
// - Jailbreak-safe app module detection
{f'''//
// BYPASS MODE ENABLED: This script will attempt to circumvent anti-debugging
// protections by modifying return values and clearing debugging flags.
''' if include_bypass else ''}"""

    extra_sections = [ANTIDEBUG_CONSTANTS]
    if include_bypass:
        extra_sections.append(BYPASS_HELPERS)

    return combine_hooks(
        hooks=hooks,
        category="antidebug",
        binary_name=binary_name,
        include_constants=False,
        include_runtime_helpers=True,
        early_hooks=early_hooks,
        use_lazy_loading=False,
        timestamp=timestamp,
        header_override=header,
        extra_prelude=extra_sections,
    )


__all__ = [
    "generate_antidebug_hook",
    "generate_antidebug_script",
    "ANTIDEBUG_CONSTANTS",
    "BYPASS_HELPERS",
]
