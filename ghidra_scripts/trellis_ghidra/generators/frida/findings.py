"""
Findings-driven Frida script generator.

This module enhances traditional API-level hooking by generating targeted hooks
for specific security findings identified during static analysis. Each hook
corresponds to a finding in the Markdown report, enabling direct verification
of static analysis results at runtime.

Key Features:
- Address-specific hooks for verified findings
- Cross-references between static analysis and dynamic instrumentation
- Severity-based prioritization
- Finding verification workflow

Example usage:
    >>> from trellis.analysis import run_security_analysis
    >>> from trellis.generators.frida.findings import generate_findings_script
    >>>
    >>> # Run static analysis
    >>> findings = run_security_analysis(program, "keychain")
    >>>
    >>> # Generate targeted Frida script
    >>> script = generate_findings_script(findings, program.filename)
"""

from typing import List, Dict, Optional
from datetime import datetime

from ...analysis.security_checks import SecurityFinding, Severity


def _escape_js_string(value: str) -> str:
    """Escape a string for safe embedding inside a JavaScript double-quoted string literal."""
    s = str(value)
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    s = s.replace("\t", "\\t")
    return s


def _escape_js_comment(value: str) -> str:
    """Sanitise a string for use inside a JavaScript single-line comment.

    Newlines would start a new line outside the comment, so they are replaced
    with spaces.
    """
    return str(value).replace("\n", " ").replace("\r", " ")


def generate_finding_hook(finding: SecurityFinding, finding_index: int, image_base: int = 0, module_base_expr: str = "mainModule.base") -> str:
    """
    Generate a targeted Frida hook for a specific security finding.
    
    This creates an address-specific hook that monitors the exact call site
    identified during static analysis, providing verification that the finding
    occurs at runtime.
    
    Args:
        finding: SecurityFinding object from static analysis
        finding_index: 1-based finding number for reporting
        image_base: Ghidra image base address (subtracted to get runtime offset)
        module_base_expr: JavaScript expression for module base address
    
    Returns:
        JavaScript code for the finding-specific hook
    """
    severity_emoji = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
    }
    emoji = severity_emoji.get(finding.severity, "⚪")
    severity_str = finding.severity.name
    
    # Format the evidence dictionary for JavaScript
    evidence_js = "{\n"
    for key, value in finding.evidence.items():
        # Escape strings properly for JavaScript
        escaped_key = _escape_js_string(str(key))
        if isinstance(value, str):
            value_js = f'"{_escape_js_string(value)}"'
        elif isinstance(value, bool):
            value_js = str(value).lower()
        elif value is None:
            value_js = "null"
        else:
            value_js = f'"{_escape_js_string(str(value))}"'
        evidence_js += f'        "{escaped_key}": {value_js},\n'
    evidence_js += "    }"
    
    # Compute the runtime offset by subtracting the image base from the Ghidra VA
    offset = finding.location - image_base if image_base else finding.location
    
    # Escape all finding fields for safe JavaScript embedding
    esc_issue = _escape_js_string(finding.issue_type)
    esc_desc = _escape_js_string(finding.description)
    esc_func = _escape_js_string(finding.function_name)
    esc_impact = _escape_js_string(finding.impact)
    esc_rec = _escape_js_string(finding.recommendation)
    # Comment-safe versions (no newlines)
    cmt_issue = _escape_js_comment(finding.issue_type)
    cmt_desc = _escape_js_comment(finding.description)
    cmt_func = _escape_js_comment(finding.function_name)
    cmt_impact = _escape_js_comment(finding.impact)
    cmt_rec = _escape_js_comment(finding.recommendation)

    hook_code = f'''
// ====================================================================
// FINDING #{finding_index}: {severity_str} - {cmt_issue}
// ====================================================================
// Ghidra Address: 0x{finding.location:x}
// Runtime Offset: 0x{offset:x}
// Function: {cmt_func}
// Description: {cmt_desc}
// Impact: {cmt_impact}
// Recommendation: {cmt_rec}
// ====================================================================

(function() {{
    try {{
        var callSite = {module_base_expr}.add(0x{offset:x});
        
        console.log("[*] Installing hook for Finding #{finding_index} at", callSite);
        
        Interceptor.attach(callSite, {{
            onEnter: function(args) {{
                console.log("\\n{emoji} [FINDING #{finding_index} TRIGGERED] {emoji}");
                console.log("  Severity: {severity_str}");
                console.log("  Issue: {esc_issue}");
                console.log("  Function: {esc_func}");
                console.log("  Ghidra: 0x{finding.location:x}");
                console.log("  Description: {esc_desc}");
                console.log("  Evidence (from static analysis):");
                var evidence = {evidence_js};
                for (var key in evidence) {{
                    console.log("    " + key + ": " + evidence[key]);
                }}
                
                // Function-specific runtime verification
'''
    
    # Add function-specific verification based on finding type
    if finding.issue_type == "Missing Keychain Accessibility Attribute":
        hook_code += '''
                // Verify: Check if kSecAttrAccessible is actually missing at runtime
                if (typeof ObjC !== 'undefined' && ObjC.available) {
                    try {
                        var queryDict = args[0];  // SecItemAdd first argument
                        if (queryDict && !queryDict.isNull()) {
                            var dict = new ObjC.Object(queryDict);
                            var accessible = dict.objectForKey_("kSecAttrAccessible");
                            if (accessible && !accessible.isNull()) {
                                console.log("  [!] RUNTIME VERIFICATION: kSecAttrAccessible IS set to:", accessible.toString());
                                console.log("  [!] Finding may be FALSE POSITIVE or app behavior changed");
                            } else {
                                console.log("  [✓] FINDING CONFIRMED: kSecAttrAccessible NOT set at runtime");
                            }
                        }
                    } catch (e) {
                        console.log("  [!] Could not verify dict: " + e);
                    }
                }
'''
    elif finding.issue_type == "Insecure Keychain Accessibility":
        hook_code += f'''
                // Verify: Check actual accessibility level at runtime
                if (typeof ObjC !== 'undefined' && ObjC.available) {{
                    try {{
                        var queryDict = args[0];
                        if (queryDict && !queryDict.isNull()) {{
                            var dict = new ObjC.Object(queryDict);
                            var accessible = dict.objectForKey_("kSecAttrAccessible");
                            if (accessible && !accessible.isNull()) {{
                                var accessibleStr = accessible.toString();
                                console.log("  [✓] FINDING CONFIRMED: Runtime accessibility = " + accessibleStr);
                                if (accessibleStr.indexOf("Always") !== -1) {{
                                    console.log("  [!!!] CRITICAL: Device lock bypass possible!");
                                }}
                            }} else {{
                                console.log("  [!] ANOMALY: No accessibility set at runtime (expected: {_escape_js_string(finding.evidence.get('kSecAttrAccessible', 'unknown'))})");
                            }}
                        }}
                    }} catch (e) {{
                        console.log("  [!] Could not verify: " + e);
                    }}
                }}
'''
    elif "sysctl" in finding.function_name:
        hook_code += '''
                // Verify: Check if this is P_TRACED flag check (anti-debug)
                var mibPtr = args[0];
                var mibLen = args[1].toInt32();
                if (mibPtr && !mibPtr.isNull()) {
                    try {
                        var mib = [];
                        for (var i = 0; i < mibLen; i++) {
                            mib.push(mibPtr.add(i * 4).readU32());
                        }
                        var mibStr = mib.join('.');
                        console.log("  Runtime MIB: " + mibStr);
                        
                        if (mibStr === '1.14.12') {
                            console.log("  [✓] FINDING CONFIRMED: KERN_PROC_PID query (likely P_TRACED check)");
                        } else {
                            console.log("  [!] Different MIB at runtime: " + mibStr);
                        }
                    } catch (e) {
                        console.log("  [!] Could not read MIB: " + e);
                    }
                }
'''
    elif "ptrace" in finding.function_name:
        hook_code += '''
                // Verify: Check ptrace request type and offer bypass
                var request = args[0].toInt32();
                var requestNames = {0: "PT_TRACE_ME", 31: "PT_DENY_ATTACH"};
                var requestName = requestNames[request] || "Unknown(" + request + ")";
                console.log("  ptrace request: " + requestName);
                if (request === 31) {
                    console.log("  [✓] CONFIRMED: PT_DENY_ATTACH — this prevents debugger attachment");
                    console.log("  [*] To bypass: set retval to 0 in onLeave");
                }
'''
    elif "getppid" in finding.function_name:
        hook_code += '''
                // Verify: getppid — normal apps return 1 (launchd), debugged apps return debugger PID
                console.log("  [*] getppid called — will check return value in onLeave");
                this._isGetppid = true;
'''
    elif "isatty" in finding.function_name:
        hook_code += '''
                // Verify: isatty — check which file descriptor is being tested
                var fd = args[0].toInt32();
                var fdNames = {0: "stdin", 1: "stdout", 2: "stderr"};
                console.log("  fd: " + (fdNames[fd] || fd) + " (" + fd + ")");
                console.log("  [*] Debugger consoles may cause isatty to return 1");
'''
    elif "task_get_exception_ports" in finding.function_name:
        hook_code += '''
                // Verify: Exception port query — debuggers register exception handlers
                try {
                    var mask = args[1].toInt32();
                    var exceptions = [];
                    if (mask & 0x20) exceptions.push("EXC_BREAKPOINT");
                    if (mask & 0x10) exceptions.push("EXC_SOFTWARE");
                    if (mask & 0x01) exceptions.push("EXC_BAD_ACCESS");
                    console.log("  Exception mask: 0x" + mask.toString(16) + " (" + (exceptions.join(" | ") || "other") + ")");
                    if (mask & 0x20) {
                        console.log("  [✓] CONFIRMED: Checking EXC_BREAKPOINT — detects debugger");
                    }
                } catch (e) {
                    console.log("  [!] Could not read exception mask: " + e);
                }
'''
    elif "_dyld_get_image_name" in finding.function_name:
        hook_code += '''
                // Verify: Check which image index is being queried and what path is returned
                var imageIndex = args[0].toInt32();
                console.log("  Image index: " + imageIndex);
                this._dyldImageIndex = imageIndex;
'''
    elif "_dyld_image_count" in finding.function_name:
        hook_code += '''
                // Verify: Image count enumeration — used to iterate loaded libraries
                console.log("  [*] _dyld_image_count called — app is enumerating loaded libraries");
                this._isDyldCount = true;
'''
    elif "dladdr" in finding.function_name:
        hook_code += '''
                // Verify: Check what address is being validated
                try {
                    var addr = args[0];
                    console.log("  Address being looked up: " + addr);
                    var sym = DebugSymbol.fromAddress(addr);
                    if (sym && sym.name) {
                        console.log("  Symbol at address: " + sym.name + " (" + sym.moduleName + ")");
                    }
                } catch (e) {
                    console.log("  [!] Could not resolve address: " + e);
                }
'''
    elif "dlsym" in finding.function_name:
        hook_code += '''
                // Verify: Check which symbol is being dynamically resolved
                try {
                    var symbolName = args[1].readCString();
                    console.log("  Resolving symbol: " + symbolName);
                    var antiDebugSymbols = ["ptrace", "sysctl", "syscall", "getppid", "isatty",
                                            "task_get_exception_ports", "dladdr"];
                    for (var i = 0; i < antiDebugSymbols.length; i++) {
                        if (symbolName && symbolName.indexOf(antiDebugSymbols[i]) !== -1) {
                            console.log("  [✓] CONFIRMED: Dynamically resolving anti-debug API: " + symbolName);
                            break;
                        }
                    }
                } catch (e) {
                    console.log("  [!] Could not read symbol name: " + e);
                }
'''
    elif "syscall" in finding.function_name and "sysctl" not in finding.function_name:
        hook_code += '''
                // Verify: Direct syscall — check syscall number for anti-debug calls
                var sysNum = args[0].toInt32();
                var sysNames = {1: "exit", 20: "getpid", 26: "ptrace", 39: "getppid", 202: "sysctl"};
                var sysName = sysNames[sysNum] || "syscall_" + sysNum;
                console.log("  Syscall number: " + sysNum + " (" + sysName + ")");
                if (sysNum === 26) {
                    var request = args[1].toInt32();
                    console.log("  [✓] CONFIRMED: Direct ptrace syscall, request=" + request);
                    if (request === 31) console.log("  [!!!] PT_DENY_ATTACH via direct syscall — bypasses library hooks!");
                } else if (sysNum === 202) {
                    console.log("  [✓] CONFIRMED: Direct sysctl syscall — bypasses library hooks!");
                }
'''
    elif finding.function_name in ("exit", "abort"):
        hook_code += f'''
                // Verify: Defensive termination — this may kill the process
                console.log("  [!!!] {_escape_js_string(finding.function_name)} called — app may be terminating due to tamper detection");
'''
        if finding.function_name == "exit":
            hook_code += '''
                try {
                    var exitCode = args[0].toInt32();
                    console.log("  Exit code: " + exitCode);
                } catch (e) {}
'''
    elif "task_info" in finding.function_name:
        hook_code += '''
                // Verify: Check task_info flavor for TASK_DYLD_INFO
                try {
                    var flavor = args[1].toInt32();
                    var flavorNames = {17: "TASK_DYLD_INFO", 20: "MACH_TASK_BASIC_INFO", 5: "TASK_BASIC_INFO"};
                    var flavorName = flavorNames[flavor] || "flavor_" + flavor;
                    console.log("  task_info flavor: " + flavorName + " (" + flavor + ")");
                    if (flavor === 17) {
                        console.log("  [✓] CONFIRMED: TASK_DYLD_INFO — enumerating loaded libraries");
                    }
                } catch (e) {
                    console.log("  [!] Could not read flavor: " + e);
                }
'''
    elif "Crypto Call" in finding.issue_type:
        hook_code += '''
                // Verify: Log actual crypto parameters at runtime
                // Note: Frida's InvocationArguments has no .length — use fixed count
                console.log("  [*] Crypto function called — logging parameters:");
                for (var i = 0; i < 8; i++) {
                    try {
                        var argVal = args[i];
                        if (argVal.isNull && argVal.isNull()) {
                            console.log("    arg[" + i + "] = NULL");
                        } else {
                            console.log("    arg[" + i + "] = " + argVal);
                            // Try to read as int for algorithm/rounds
                            try {
                                var asInt = argVal.toInt32();
                                if (asInt >= 0 && asInt < 100000) {
                                    console.log("      (as int: " + asInt + ")");
                                }
                            } catch(e) {}
                            // Try to read as string for key/salt
                            try {
                                var asStr = argVal.readCString();
                                if (asStr && asStr.length > 0 && asStr.length < 256) {
                                    console.log('      (as string: "' + asStr + '")');
                                }
                            } catch(e) {}
                        }
                    } catch(e) { break; }
                }
'''
    elif "Hardcoded Authentication" in finding.issue_type or "Client-Side Auth" in finding.issue_type:
        hook_code += '''
                // Verify: Log the comparison value and offer bypass
                if (typeof ObjC !== 'undefined' && ObjC.available) {
                    try {
                        // For isEqualToString: first arg is self (receiver), arg[1] is SEL, arg[2] is string
                        var compareStr = new ObjC.Object(args[2]);
                        console.log("  [✓] Comparing against: " + compareStr.toString());
                        console.log("  [*] To bypass: hook to always return 1 (YES)");
                    } catch(e) {
                        console.log("  [!] Could not read comparison string: " + e);
                    }
                }
'''
    elif "Jailbreak Detection" in finding.issue_type:
        hook_code += '''
                // Verify: Log the file path or argument being checked
                try {
                    var pathArg = args[0];
                    if (pathArg && !pathArg.isNull()) {
                        var path = pathArg.readCString();
                        if (path) {
                            console.log("  [*] Checking path: " + path);
                            if (path.indexOf("Cydia") !== -1 || path.indexOf("substrate") !== -1 ||
                                path.indexOf("frida") !== -1 || path.indexOf("/bin/bash") !== -1) {
                                console.log("  [✓] CONFIRMED: Jailbreak detection path check");
                            }
                        }
                    }
                } catch (e) {
                    console.log("  [!] Could not read path arg: " + e);
                }
'''
    elif "Hardcoded Password Used in Crypto" in finding.issue_type:
        hook_code += '''
                // Verify: This string is being used as a crypto key/password
                console.log("  [✓] CRITICAL: Hardcoded password referenced in crypto context");
                console.log("  [*] All installations of this app use the same encryption password");
                console.log("  [*] Attackers can extract this from the binary to decrypt any user data");
'''
    
    # Generic parameter logging for all findings
    hook_code += '''
                // Runtime arguments (for manual inspection)
                console.log("  Runtime arguments:");
                for (var i = 0; i < 4; i++) {
                    try {
                        console.log("    [" + i + "] = " + args[i]);
                    } catch(e) { break; }
                }
                
                // Backtrace with Ghidra addresses
                var mainModule = getMainAppModule();
                console.log("  Backtrace:");
                console.log(formatBacktrace(this.context, mainModule, 5));
'''
    
    hook_code += f'''
            }},
            onLeave: function(retval) {{
                console.log("  => Return: " + retval);
            }}
        }});
        
    }} catch (e) {{
        console.log("[-] Failed to hook Finding #{finding_index} (Ghidra 0x{finding.location:x}, offset 0x{offset:x}): " + e);
    }}
}})();
'''
    
    return hook_code


def generate_findings_summary(findings: List[SecurityFinding]) -> str:
    """
    Generate JavaScript code that prints a summary of all findings at startup.
    
    Args:
        findings: List of SecurityFinding objects
    
    Returns:
        JavaScript code for summary display
    """
    severity_counts = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 0,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
    }
    
    # Only count actionable findings (INFO is excluded from hooks)
    for finding in findings:
        if finding.severity != Severity.INFO:
            severity_counts[finding.severity] += 1
    
    summary_code = '''
console.log("\\n" + "=".repeat(70));
console.log("TRELLIS FINDINGS-DRIVEN INSTRUMENTATION");
console.log("=".repeat(70));
'''
    
    summary_code += f'''
console.log("Total Findings: {len(findings)}");
'''
    
    if severity_counts[Severity.CRITICAL] > 0:
        summary_code += f'console.log("  🔴 Critical: {severity_counts[Severity.CRITICAL]}");\n'
    if severity_counts[Severity.HIGH] > 0:
        summary_code += f'console.log("  🟠 High: {severity_counts[Severity.HIGH]}");\n'
    if severity_counts[Severity.MEDIUM] > 0:
        summary_code += f'console.log("  🟡 Medium: {severity_counts[Severity.MEDIUM]}");\n'
    if severity_counts[Severity.LOW] > 0:
        summary_code += f'console.log("  🔵 Low: {severity_counts[Severity.LOW]}");\n'
    
    summary_code += '''
console.log("\\nThese hooks monitor specific call sites identified during static analysis.");
console.log("When triggered, you'll see runtime verification of the static findings.");
console.log("=".repeat(70) + "\\n");
'''
    
    return summary_code


def group_findings_by_function(findings: List[SecurityFinding]) -> Dict[str, List[SecurityFinding]]:
    """
    Group findings by the function they occur in.
    
    Args:
        findings: List of SecurityFinding objects
    
    Returns:
        Dictionary mapping function names to lists of findings
    """
    grouped = {}
    for finding in findings:
        func_name = finding.function_name
        if func_name not in grouped:
            grouped[func_name] = []
        grouped[func_name].append(finding)
    return grouped


# Categories where global fallback hooks should be included when findings
# coverage is low.  Mapping: category -> minimum actionable findings before
# fallbacks are suppressed.  If the number of actionable findings is *below*
# this threshold the fallback hooks will be appended.
_GLOBAL_FALLBACK_CATEGORIES: Dict[str, int] = {
    "antidebug": 5,
}


def _generate_antidebug_global_fallbacks() -> str:
    """Generate global API hooks that cover common anti-debug/anti-hook patterns.

    These are appended to findings-driven scripts when the static analysis
    produced too few actionable findings (e.g. because the target uses
    ``always_inline`` functions or resolves APIs dynamically via ``dlsym``).

    All hooks use Frida 17+ APIs and include Ghidra-translated backtraces.
    """
    return '''
// ====================================================================
// GLOBAL FALLBACK HOOKS — Anti-Debug / Anti-Hook
// ====================================================================
// Appended because static analysis produced few actionable findings.
// These cover common anti-debug APIs that may have been inlined or
// resolved dynamically at runtime (e.g. via dlsym).
// ====================================================================

(function _trellisAntidebugFallbacks() {
    var mainModule = getMainAppModule();
    var hookCount = 0;

    // --- ptrace (PT_DENY_ATTACH bypass) --------------------------------
    try {
        var ptracePtr = Module.getGlobalExportByName("ptrace");
        if (ptracePtr) {
            Interceptor.attach(ptracePtr, {
                onEnter: function(args) {
                    this._request = args[0].toInt32();
                    var requestNames = {0: "PT_TRACE_ME", 31: "PT_DENY_ATTACH"};
                    var name = requestNames[this._request] || "request_" + this._request;
                    console.log("\\n[GLOBAL] ptrace(" + name + ")");
                    if (this._request === 31) {
                        console.log("  [!!!] PT_DENY_ATTACH detected — bypassing");
                    }
                    console.log("  Backtrace:");
                    console.log(formatBacktrace(this.context, mainModule, 5));
                },
                onLeave: function(retval) {
                    if (this._request === 31) {
                        retval.replace(ptr(0));
                        console.log("  => Return replaced with 0 (bypass applied)");
                    }
                }
            });
            hookCount++;
            console.log("[+] Hooked ptrace (PT_DENY_ATTACH bypass)");
        }
    } catch (e) {
        console.log("[-] Could not hook ptrace: " + e);
    }

    // --- sysctl (P_TRACED flag clearing) --------------------------------
    try {
        var sysctlPtr = Module.getGlobalExportByName("sysctl");
        if (sysctlPtr) {
            Interceptor.attach(sysctlPtr, {
                onEnter: function(args) {
                    this._mibPtr = args[0];
                    this._mibLen = args[1].toInt32();
                    this._oldp = args[2];
                    this._oldlenp = args[3];
                    // Detect KERN_PROC_PID anti-debug pattern (MIB len 4)
                    this._isAntiDebug = false;
                    if (this._mibLen === 4 && this._mibPtr && !this._mibPtr.isNull()) {
                        try {
                            var m0 = this._mibPtr.readU32();
                            var m1 = this._mibPtr.add(4).readU32();
                            if (m0 === 1 && m1 === 14) {
                                this._isAntiDebug = true;
                            }
                        } catch (e) {}
                    }
                },
                onLeave: function(retval) {
                    if (this._isAntiDebug && this._oldp && !this._oldp.isNull()) {
                        try {
                            // kinfo_proc.kp_proc.p_flag is at offset 32 in the struct
                            var flagPtr = this._oldp.add(32);
                            var flags = flagPtr.readU32();
                            if (flags & 0x800) {
                                flagPtr.writeU32(flags & ~0x800);
                                console.log("\\n[GLOBAL] sysctl: Cleared P_TRACED flag (0x800)");
                                console.log("  Backtrace:");
                                console.log(formatBacktrace(this.context, mainModule, 5));
                            }
                        } catch (e) {
                            console.log("[-] Could not clear P_TRACED: " + e);
                        }
                    }
                }
            });
            hookCount++;
            console.log("[+] Hooked sysctl (P_TRACED bypass)");
        }
    } catch (e) {
        console.log("[-] Could not hook sysctl: " + e);
    }

    // --- _dyld_get_image_name (hide injected libraries) -----------------
    var suspiciousLibs = ["FridaGadget", "frida", "MobileSubstrate", "cycript",
                          "SSLKillSwitch", "SSLKillSwitch2", "libcycript",
                          "SubstrateInserter", "SubstrateLoader", "SubstrateBootstrap"];
    try {
        var dyldNamePtr = Module.getGlobalExportByName("_dyld_get_image_name");
        if (dyldNamePtr) {
            Interceptor.attach(dyldNamePtr, {
                onEnter: function(args) {
                    this._index = args[0].toInt32();
                },
                onLeave: function(retval) {
                    if (retval && !retval.isNull()) {
                        try {
                            var path = retval.readCString();
                            if (path) {
                                for (var i = 0; i < suspiciousLibs.length; i++) {
                                    if (path.indexOf(suspiciousLibs[i]) !== -1) {
                                        console.log("\\n[GLOBAL] _dyld_get_image_name: Hiding " + path);
                                        // Return empty string to hide the library
                                        var fakeStr = Memory.allocUtf8String("/usr/lib/system/libsystem_c.dylib");
                                        retval.replace(fakeStr);
                                        break;
                                    }
                                }
                            }
                        } catch (e) {}
                    }
                }
            });
            hookCount++;
            console.log("[+] Hooked _dyld_get_image_name (library hiding)");
        }
    } catch (e) {
        console.log("[-] Could not hook _dyld_get_image_name: " + e);
    }

    // --- exit / abort (prevent defensive termination) -------------------
    try {
        var exitPtr = Module.getGlobalExportByName("exit");
        if (exitPtr) {
            Interceptor.attach(exitPtr, {
                onEnter: function(args) {
                    var code = args[0].toInt32();
                    console.log("\\n[GLOBAL] exit(" + code + ") called — blocking termination");
                    console.log("  Backtrace:");
                    console.log(formatBacktrace(this.context, mainModule, 5));
                    // Replace exit code with loop to prevent termination
                    // This keeps the process alive for further analysis
                    args[0] = ptr(0);
                }
            });
            hookCount++;
            console.log("[+] Hooked exit (termination prevention)");
        }
    } catch (e) {
        console.log("[-] Could not hook exit: " + e);
    }

    // --- dlsym (monitor dynamic symbol resolution) ----------------------
    try {
        var dlsymPtr = Module.getGlobalExportByName("dlsym");
        if (dlsymPtr) {
            var antiDebugSymbols = ["ptrace", "sysctl", "syscall", "getppid",
                                    "isatty", "task_get_exception_ports", "dladdr"];
            Interceptor.attach(dlsymPtr, {
                onEnter: function(args) {
                    this._symbol = null;
                    try {
                        this._symbol = args[1].readCString();
                    } catch (e) {}
                },
                onLeave: function(retval) {
                    if (this._symbol) {
                        for (var i = 0; i < antiDebugSymbols.length; i++) {
                            if (this._symbol === antiDebugSymbols[i]) {
                                console.log("\\n[GLOBAL] dlsym resolving anti-debug API: " + this._symbol + " => " + retval);
                                console.log("  Backtrace:");
                                console.log(formatBacktrace(this.context, mainModule, 5));
                                break;
                            }
                        }
                    }
                }
            });
            hookCount++;
            console.log("[+] Hooked dlsym (dynamic resolution monitoring)");
        }
    } catch (e) {
        console.log("[-] Could not hook dlsym: " + e);
    }

    console.log("[*] Installed " + hookCount + " global anti-debug fallback hooks");
})();
'''


def generate_findings_script(
    findings: List[SecurityFinding],
    binary_name: str,
    category: str = "findings",
    include_generic_hooks: bool = False,
    timestamp: Optional[str] = None,
    image_base: int = 0,
    lazy_loading: bool = True,
    include_global_fallbacks: bool = False
) -> str:
    """
    Generate a complete findings-driven Frida script.
    
    This creates a script with:
    - Targeted hooks for each specific finding
    - Runtime verification logic
    - Cross-references to static analysis
    - Severity-based organization
    - Optional global API fallback hooks for categories with low detection
    
    Args:
        findings: List of SecurityFinding objects from static analysis
        binary_name: Name of the target binary
        category: Category name for the script
        include_generic_hooks: Whether to also include generic API hooks (default: False)
        timestamp: Optional timestamp for header
        image_base: Ghidra image base address (subtracted from finding addresses
            to compute runtime offsets). For iOS executables this is typically
            0x100000000.
        lazy_loading: Whether to defer hook installation until after app launch
            (default: True). Set to False for antidebug scripts that need to
            catch startup checks.
        include_global_fallbacks: Whether to append global API hooks as fallbacks
            when findings coverage is low (default: False). Automatically enabled
            for categories listed in _GLOBAL_FALLBACK_CATEGORIES.
    
    Returns:
        Complete Frida script as a string
    
    Example:
        >>> findings = analyze_keychain_security(program)
        >>> script = generate_findings_script(findings, "MyApp", "keychain", image_base=0x100000000)
        >>> with open("keychain_findings.js", "w") as f:
        ...     f.write(script)
    """
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Filter out INFO-level findings (not actionable for pentesting/bug bounty)
    actionable_findings = [f for f in findings if f.severity != Severity.INFO]
    
    # Sort findings by severity (Critical first)
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    sorted_findings = sorted(actionable_findings, key=lambda f: (severity_order[f.severity], f.location))
    
    # Build script
    from .base import FRIDA_RUNTIME_HELPERS
    
    header = f"""// trellis_{category}_findings.js
// Generated by Trellis - FINDINGS-DRIVEN INSTRUMENTATION
// Target: {binary_name}
// Generated: {timestamp}
// Frida API: 17.x+ compatible
//
// ⚠️  FINDINGS-DRIVEN MODE ⚠️
//
// This script hooks SPECIFIC call sites identified during static analysis.
// Each hook corresponds to a finding in the Markdown report, enabling:
//   - Runtime verification of static analysis results
//   - Direct cross-referencing between Ghidra and Frida
//   - Severity-based prioritization
//   - False positive elimination
//
// Actionable Findings: {len(sorted_findings)} (INFO-level findings excluded)
//   🔴 Critical: {sum(1 for f in sorted_findings if f.severity == Severity.CRITICAL)}
//   🟠 High: {sum(1 for f in sorted_findings if f.severity == Severity.HIGH)}
//   🟡 Medium: {sum(1 for f in sorted_findings if f.severity == Severity.MEDIUM)}
//   🔵 Low: {sum(1 for f in sorted_findings if f.severity == Severity.LOW)}
//
// Features:
// - Address-specific hooks (not generic API hooks)
// - Runtime verification logic per finding
// - Ghidra address translation for cross-referencing
// - Finding metadata embedded in hooks
"""

    script_parts = [header]
    script_parts.append("\n(function() {")
    script_parts.append("    'use strict';\n")
    
    # Add runtime helpers
    helpers_indented = "\n".join(
        "    " + line if line.strip() else line
        for line in FRIDA_RUNTIME_HELPERS.strip().split("\n")
    )
    script_parts.append(helpers_indented)
    script_parts.append("\n")
    
    # Add findings summary
    summary = generate_findings_summary(sorted_findings)
    summary_indented = "\n".join(
        "    " + line if line.strip() else line
        for line in summary.strip().split("\n")
    )
    script_parts.append(summary_indented)
    script_parts.append("\n")
    
    # Determine whether to add global fallback hooks.
    # Auto-enable if the category is known to benefit from fallbacks and
    # the number of actionable findings is below the threshold.
    use_fallbacks = include_global_fallbacks
    if not use_fallbacks and category in _GLOBAL_FALLBACK_CATEGORIES:
        threshold = _GLOBAL_FALLBACK_CATEGORIES[category]
        if len(sorted_findings) < threshold:
            use_fallbacks = True

    # Configuration
    lazy_js = "true" if lazy_loading else "false"
    script_parts.append("    var TRELLIS_CONFIG = {")
    script_parts.append(f"        useLazyLoading: {lazy_js},")
    script_parts.append("        verifyFindings: true,")
    script_parts.append(f"        totalFindings: {len(sorted_findings)}")
    script_parts.append("    };\n")

    # --------------- hook body (shared between lazy / immediate) --------
    hook_body_lines = []
    total_hook_label = str(len(sorted_findings))
    if use_fallbacks:
        total_hook_label += " finding-specific + global fallback"
    hook_body_lines.append(
        "console.log('[*] Installing " + total_hook_label + " hooks...');"
    )
    hook_body_lines.append("var mainModule = getMainAppModule();")
    hook_body_lines.append("")

    for i, finding in enumerate(sorted_findings, start=1):
        hook = generate_finding_hook(finding, i, image_base=image_base)
        for line in hook.strip().split("\n"):
            hook_body_lines.append(line)
        hook_body_lines.append("")

    hook_body_lines.append(
        "console.log('[*] All finding hooks installed. Monitoring for security issues...');"
    )

    # --------------- emit hooks (lazy or immediate) --------------------
    if lazy_loading:
        script_parts.append("    if (TRELLIS_CONFIG.useLazyLoading) {")
        script_parts.append("        deferHooksUntilReady(function() {")
        for line in hook_body_lines:
            script_parts.append(("            " + line) if line.strip() else line)
        script_parts.append("        });")
        script_parts.append("    }")
    else:
        # Install hooks immediately (before app resumes from spawn)
        script_parts.append("    // Immediate hook installation (lazy loading disabled)")
        script_parts.append("    (function() {")
        for line in hook_body_lines:
            script_parts.append(("        " + line) if line.strip() else line)
        script_parts.append("    })();")

    # --------------- global fallback hooks -----------------------------
    if use_fallbacks:
        script_parts.append("")
        # Fallback hooks are self-contained IIFEs — indent inside outer IIFE
        fallback_code = _generate_antidebug_global_fallbacks()
        for line in fallback_code.strip().split("\n"):
            script_parts.append(("    " + line) if line.strip() else line)

    script_parts.append("})();")

    return "\n".join(script_parts)


def generate_hybrid_script(
    findings: List[SecurityFinding],
    generic_hooks: List[str],
    binary_name: str,
    category: str,
    timestamp: Optional[str] = None
) -> str:
    """
    Generate a hybrid script with both finding-specific and generic hooks.
    
    This provides:
    - Targeted monitoring of known issues (findings)
    - Comprehensive API coverage (generic hooks)
    - Best of both worlds for thorough analysis
    
    Args:
        findings: List of SecurityFinding objects
        generic_hooks: List of generic hook JavaScript code strings
        binary_name: Target binary name
        category: Category name
        timestamp: Optional timestamp
    
    Returns:
        Complete hybrid Frida script
    """
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Generate findings section
    findings_script = generate_findings_script(findings, binary_name, category, timestamp=timestamp)
    
    # Modify the findings script to not close the IIFE
    # (we'll add generic hooks after)
    findings_lines = findings_script.split("\n")
    
    # Remove the closing })(); from findings script
    while findings_lines and findings_lines[-1].strip() in ["", "})();"]:
        findings_lines.pop()
    
    script_parts = findings_lines
    
    # Add separator
    script_parts.append("")
    script_parts.append("    // ====================================================================")
    script_parts.append("    // GENERIC API HOOKS (Comprehensive Coverage)")
    script_parts.append("    // ====================================================================")
    script_parts.append("    // The following hooks provide generic monitoring of all API calls,")
    script_parts.append("    // complementing the finding-specific hooks above.")
    script_parts.append("    // ====================================================================")
    script_parts.append("")
    
    # Add generic hooks
    for hook in generic_hooks:
        hook_indented = "\n".join(
            "            " + line if line.strip() else line
            for line in hook.strip().split("\n")
        )
        script_parts.append(hook_indented)
    
    # Close the script
    script_parts.append("})();")
    
    return "\n".join(script_parts)


__all__ = [
    "generate_finding_hook",
    "generate_findings_script",
    "generate_hybrid_script",
    "group_findings_by_function",
]
