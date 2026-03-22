"""
Anti-debugging security checks for Trellis (Ghidra Port).

This module implements detection of anti-debugging techniques in iOS binaries,
identifying ptrace, sysctl, and other debugging prevention mechanisms.

These checks report the PRESENCE of anti-debugging, which is informational
for security analysis - it indicates the app is trying to detect tampering.
"""

from typing import Optional, List, TYPE_CHECKING

from .security_checks import SecurityChecker, SecurityFinding, Severity

if TYPE_CHECKING:
    from ..signatures import FunctionSignature
    from .calltree import CallSite
    from .extractor import ExtractedCallInfo


# ptrace request constants
PT_TRACE_ME = 0       # Tracing by parent
PT_READ_I = 1         # Read word from instruction space
PT_READ_D = 2         # Read word from data space
PT_READ_U = 3         # Read from user structure
PT_WRITE_I = 4        # Write word to instruction space
PT_WRITE_D = 5        # Write word to data space
PT_WRITE_U = 6        # Write to user structure
PT_CONTINUE = 7       # Continue process
PT_KILL = 8           # Kill process
PT_STEP = 9           # Single step
PT_ATTACH = 10        # Attach to process
PT_DETACH = 11        # Detach from process
PT_DENY_ATTACH = 31   # Prevent debugging (iOS specific)

PTRACE_REQUESTS = {
    PT_TRACE_ME: "PT_TRACE_ME",
    PT_READ_I: "PT_READ_I",
    PT_READ_D: "PT_READ_D",
    PT_READ_U: "PT_READ_U",
    PT_WRITE_I: "PT_WRITE_I",
    PT_WRITE_D: "PT_WRITE_D",
    PT_WRITE_U: "PT_WRITE_U",
    PT_CONTINUE: "PT_CONTINUE",
    PT_KILL: "PT_KILL",
    PT_STEP: "PT_STEP",
    PT_ATTACH: "PT_ATTACH",
    PT_DETACH: "PT_DETACH",
    PT_DENY_ATTACH: "PT_DENY_ATTACH",
}

# sysctl CTL types
CTL_KERN = 1
KERN_PROC = 14
KERN_PROC_PID = 1

# P_TRACED flag (kinfo_proc.kp_proc.p_flag)
P_TRACED = 0x00000800


# Caller name patterns that indicate confirmed anti-debug / anti-tamper context
_ANTIDEBUG_CALLER_PATTERNS = {
    # (keyword_lower, severity, technique_label)
    "isdebugged": (Severity.MEDIUM, "Debugger detection function"),
    "debugger": (Severity.MEDIUM, "Debugger detection function"),
    "antiDebug": (Severity.MEDIUM, "Anti-debug function"),
    "disable_gdb": (Severity.HIGH, "GDB/debugger disabling function"),
    "detect_injected_dylds": (Severity.MEDIUM, "Injected dylib detection"),
    "amidebugged": (Severity.MEDIUM, "Debugger detection function"),
    "denyattach": (Severity.HIGH, "Debugger attachment prevention"),
    "antitamper": (Severity.MEDIUM, "Anti-tamper function"),
    "integritycheck": (Severity.MEDIUM, "Integrity check function"),
}


def _get_caller_antidebug_context(caller_name):
    """
    Check if the caller function name indicates anti-debug/anti-tamper context.

    Returns:
        Tuple of (Severity, technique_label) if matched, or None.
    """
    if not caller_name:
        return None
    lower = caller_name.lower()
    for keyword, (severity, label) in _ANTIDEBUG_CALLER_PATTERNS.items():
        if keyword.lower() in lower:
            return (severity, label)
    return None


class AntiDebugSecurityChecker(SecurityChecker):
    """Security checker for anti-debugging techniques."""

    def check_call_site(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check for anti-debugging function usage."""
        findings = []

        func_name = function_sig.name

        # ptrace checks
        if func_name == "ptrace":
            findings.extend(self._check_ptrace(
                function_sig, call_site, extracted_info
            ))

        # sysctl checks (checking P_TRACED flag)
        elif func_name == "sysctl":
            findings.extend(self._check_sysctl(
                function_sig, call_site, extracted_info
            ))

        # sysctlbyname checks
        elif func_name == "sysctlbyname":
            findings.extend(self._check_sysctlbyname(
                function_sig, call_site, extracted_info
            ))

        # getppid (parent process ID check)
        elif func_name == "getppid":
            findings.extend(self._check_getppid(
                function_sig, call_site, extracted_info
            ))

        # isatty (terminal check)
        elif func_name == "isatty":
            findings.extend(self._check_isatty(
                function_sig, call_site, extracted_info
            ))

        # task_get_exception_ports (exception handler check)
        elif func_name == "task_get_exception_ports":
            findings.extend(self._check_exception_ports(
                function_sig, call_site, extracted_info
            ))

        # sysctl/kern.boottime timing check
        elif func_name == "gettimeofday":
            findings.extend(self._check_timing(
                function_sig, call_site, extracted_info
            ))
            
        # syscall checks (can bypass hooks)
        elif func_name == "syscall":
            findings.extend(self._check_syscall(
                function_sig, call_site, extracted_info
            ))

        # Injection detection: dyld image enumeration
        elif func_name == "_dyld_get_image_name":
            findings.extend(self._check_dyld_get_image_name(
                function_sig, call_site, extracted_info
            ))

        elif func_name == "_dyld_image_count":
            findings.extend(self._check_dyld_image_count(
                function_sig, call_site, extracted_info
            ))

        # Hook/caller validation
        elif func_name == "dladdr":
            findings.extend(self._check_dladdr(
                function_sig, call_site, extracted_info
            ))

        # Dynamic symbol resolution (may resolve anti-debug APIs at runtime)
        elif func_name == "dlsym":
            findings.extend(self._check_dlsym(
                function_sig, call_site, extracted_info
            ))

        # Task info (library enumeration via TASK_DYLD_INFO)
        elif func_name == "task_info":
            findings.extend(self._check_task_info(
                function_sig, call_site, extracted_info
            ))

        # Defensive termination
        elif func_name in ("exit", "abort"):
            findings.extend(self._check_defensive_exit(
                function_sig, call_site, extracted_info
            ))

        # Elevate severity based on caller name context
        findings = self._elevate_by_caller_name(findings, call_site)

        return findings

    def _elevate_by_caller_name(
        self,
        findings: List[SecurityFinding],
        call_site: "CallSite"
    ) -> List[SecurityFinding]:
        """
        Elevate finding severity when caller function name confirms anti-debug intent.

        For example, a sysctl call from '_isDebugged' is clearly anti-debug
        (not just general sysctl usage), so we elevate from LOW/INFO to MEDIUM
        and add a targeted bypass recommendation.
        """
        caller_name = call_site.caller_name if call_site else None
        context = _get_caller_antidebug_context(caller_name)

        if context is None or not findings:
            return findings

        caller_severity, technique_label = context

        display_caller = caller_name
        if display_caller and len(display_caller) > 80:
            display_caller = display_caller[:77] + "..."

        elevated = []
        for finding in findings:
            # Only elevate if caller context provides higher severity
            if self._severity_rank(caller_severity) > self._severity_rank(finding.severity):
                new_severity = caller_severity
            else:
                new_severity = finding.severity

            # Enrich evidence with caller context
            evidence = dict(finding.evidence) if finding.evidence else {}
            evidence["caller"] = display_caller
            evidence["caller_context"] = technique_label

            # Provide targeted bypass recommendation
            bypass_rec = self._get_bypass_recommendation(caller_name, finding.function_name)

            elevated.append(SecurityFinding(
                severity=new_severity,
                issue_type=finding.issue_type,
                description=finding.description,
                location=finding.location,
                function_name=finding.function_name,
                evidence=evidence,
                impact=finding.impact,
                recommendation=bypass_rec or finding.recommendation
            ))

        return elevated

    @staticmethod
    def _severity_rank(severity):
        """Numeric rank for severity comparison."""
        ranks = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return ranks.get(severity, 0)

    @staticmethod
    def _get_bypass_recommendation(caller_name, api_name):
        """Generate a targeted bypass recommendation based on caller context."""
        if not caller_name:
            return None
        lower = caller_name.lower()

        if "disable_gdb" in lower:
            return ("Hook ptrace in '{}' and return 0 to prevent debugger denial; "
                    "alternatively NOP the call instruction".format(caller_name))
        elif "isdebugged" in lower:
            return ("Hook '{}' to always return false/0 to bypass debugger detection; "
                    "or hook {} to return benign values".format(caller_name, api_name))
        elif "detect_injected_dylds" in lower or "injected" in lower:
            return ("Hook _dyld_image_count/_dyld_get_image_name to hide injected "
                    "libraries, or hook '{}' to return false/0".format(caller_name))
        elif "jailbreak" in lower:
            return ("Hook '{}' to return false/0 to bypass jailbreak detection; "
                    "or hook individual API calls within it".format(caller_name))
        return None

    def _check_ptrace(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check ptrace calls for anti-debugging."""
        findings = []
        params_by_name = {}
        if extracted_info and extracted_info.parameters:
            params_by_name = {p.name: p for p in extracted_info.parameters}

        # Get request parameter (first param)
        request_param = params_by_name.get("request") or params_by_name.get("req")
        if request_param is None and extracted_info and len(extracted_info.parameters) > 0:
            request_param = extracted_info.parameters[0]

        if request_param:
            request_value = self._get_constant_int(request_param)

        if request_value is not None:
                if request_value == PT_DENY_ATTACH:
                    findings.append(SecurityFinding(
                        severity=Severity.HIGH,
                        issue_type="Anti-Debug: ptrace PT_DENY_ATTACH",
                        description="ptrace with PT_DENY_ATTACH detected (prevents debugger attachment)",
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={
                            "request": "PT_DENY_ATTACH (31)",
                            "technique": "Kernel-level debugger prevention"
                        },
                        impact="Debuggers cannot attach to this process after this call",
                        recommendation="For security testing, hook ptrace and return 0 to bypass"
                    ))
                else:
                    request_name = PTRACE_REQUESTS.get(request_value, "Unknown ({})".format(request_value))
                    findings.append(SecurityFinding(
                        severity=Severity.LOW,
                        issue_type="Anti-Debug: ptrace",
                        description="ptrace call with request {}".format(request_name),
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={"request": request_name},
                        impact="May be used for debugging detection or process tracing",
                        recommendation=None
                    ))
        else:
            # Can't determine request, report generic ptrace usage
            findings.append(SecurityFinding(
                severity=Severity.LOW,
                issue_type="Anti-Debug: ptrace",
                description="ptrace call detected (possible anti-debugging)",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"function": "ptrace"},
                impact="May be used to prevent or detect debugger attachment",
                recommendation="Analyze to determine if PT_DENY_ATTACH is used"
            ))

        return findings

    def _check_sysctl(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check sysctl calls for P_TRACED flag checking."""
        findings = []

        # sysctl is commonly used to check kinfo_proc.kp_proc.p_flag for P_TRACED
        # The MIB array for anti-debug is: {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()}
        # Try to determine if this is actually an anti-debug check

        is_anti_debug = None  # None = unknown
        mib_len = None

        if extracted_info and extracted_info.parameters:
            params_by_name = {p.name: p for p in extracted_info.parameters}

            # Check mib_len parameter (second param) - anti-debug uses 4
            mib_len_param = params_by_name.get("namelen") or params_by_name.get("mib_len")
            if mib_len_param is None and len(extracted_info.parameters) > 1:
                mib_len_param = extracted_info.parameters[1]

            if mib_len_param:
                mib_len = self._get_constant_int(mib_len_param)
                if mib_len == 4:
                    # 4-element MIB is consistent with KERN_PROC anti-debug check
                    is_anti_debug = True
                elif mib_len == 2:
                    # 2-element MIB is typically for simple queries like KERN_BOOTTIME
                    is_anti_debug = False

        # Report based on analysis confidence
        if is_anti_debug is True:
            # Confirmed anti-debug pattern
            findings.append(SecurityFinding(
                severity=Severity.MEDIUM,
                issue_type="Anti-Debug: sysctl",
                description="sysctl call detected checking P_TRACED flag",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={
                    "technique": "kinfo_proc P_TRACED flag check",
                    "mib_pattern": "{CTL_KERN, KERN_PROC, KERN_PROC_PID, pid}",
                    "mib_len": str(mib_len) if mib_len else "unknown"
                },
                impact="Can detect if process is being traced by a debugger",
                recommendation="Hook sysctl to clear P_TRACED flag (0x800) in response"
            ))
        elif is_anti_debug is None:
            # Could not determine - report as potential anti-debug
            findings.append(SecurityFinding(
                severity=Severity.LOW,
                issue_type="Potential Anti-Debug: sysctl",
                description="sysctl call detected (could not determine MIB pattern)",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={
                    "technique": "Unknown - manual analysis required",
                    "mib_len": str(mib_len) if mib_len else "unknown",
                    "note": "Check if MIB is {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid}"
                },
                impact="May be checking P_TRACED flag for debugger detection",
                recommendation="Manually verify MIB pattern to confirm anti-debug usage"
            ))
        # If is_anti_debug is False, we confirmed it's NOT anti-debug, so don't report

        return findings

    def _check_sysctlbyname(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check sysctlbyname calls for debug-related queries."""
        findings = []

        # sysctlbyname("kern.proc.pid", ...) is another way to check P_TRACED
        findings.append(SecurityFinding(
            severity=Severity.LOW,
            issue_type="Anti-Debug: sysctlbyname",
            description="sysctlbyname call detected (may check process info)",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={
                "function": "sysctlbyname",
                "possible_names": "kern.proc.pid, hw.machine, etc."
            },
            impact="Can query system info including debugger attachment status",
            recommendation="Hook and monitor the name parameter for debug checks"
        ))

        return findings

    def _check_getppid(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check getppid for parent process ID verification."""
        findings = []

        # getppid() returns 1 (launchd) for normal apps, but different for debugged apps
        findings.append(SecurityFinding(
            severity=Severity.LOW,
            issue_type="Anti-Debug: getppid",
            description="getppid call detected (parent process check)",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={
                "technique": "Parent process ID verification",
                "normal_ppid": "1 (launchd)",
                "debug_ppid": "Different (debugger process)"
            },
            impact="Can detect if app was launched by debugger instead of launchd",
            recommendation="Hook getppid to always return 1"
        ))

        return findings

    def _check_isatty(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check isatty for terminal detection."""
        findings = []

        # isatty() on stdin/stdout can detect terminal attachment (debugger consoles)
        findings.append(SecurityFinding(
            severity=Severity.LOW,
            issue_type="Anti-Debug: isatty",
            description="isatty call detected (terminal/console check)",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={
                "technique": "Terminal attachment detection",
                "checked_fds": "0 (stdin), 1 (stdout), 2 (stderr)"
            },
            impact="Can detect if standard I/O is attached to a terminal (debugger console)",
            recommendation="Hook isatty to return 0 (not a terminal)"
        ))

        return findings

    def _check_exception_ports(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check task_get_exception_ports for debugger detection."""
        findings = []

        # Debuggers register exception handlers on the target process
        # Checking exception ports can reveal debugger presence
        findings.append(SecurityFinding(
            severity=Severity.MEDIUM,
            issue_type="Anti-Debug: Exception Ports",
            description="task_get_exception_ports call detected (debugger handler check)",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={
                "technique": "Exception handler enumeration",
                "target": "mach_task_self() or target task"
            },
            impact="Debuggers register exception handlers - checking ports reveals them",
            recommendation="Hook to return empty exception port list"
        ))

        return findings

    def _check_timing(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check gettimeofday for timing-based anti-debug."""
        findings = []

        # Timing checks measure execution time - breakpoints cause delays
        findings.append(SecurityFinding(
            severity=Severity.LOW,
            issue_type="Potential Anti-Debug: Timing",
            description="gettimeofday call detected (possible timing check)",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={
                "technique": "Execution timing measurement",
                "detection": "Breakpoints/single-stepping cause delays"
            },
            impact="May be used to detect debugger-induced delays (or legitimate timing)",
            recommendation="Look for multiple calls and elapsed time comparisons"
        ))

        return findings

    def _check_syscall(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check direct syscalls (bypass hooks)."""
        findings = []
        
        # Check syscall number if available
        # syscall(number, ...)
        
        sys_num = None
        sys_name = "Unknown"
        
        if extracted_info and len(extracted_info.parameters) > 0:
            sys_num_param = extracted_info.parameters[0]
            sys_num = self._get_constant_int(sys_num_param)
            
            if sys_num is not None:
                # Common anti-debug syscalls
                if sys_num == 26: sys_name = "ptrace"
                elif sys_num == 202: sys_name = "sysctl"
                elif sys_num == 1: sys_name = "exit"
                elif sys_num == 20: sys_name = "getpid"
                elif sys_num == 39: sys_name = "getppid"
                else: sys_name = "syscall_{}".format(sys_num)
        
        findings.append(SecurityFinding(
            severity=Severity.HIGH,
            issue_type="Anti-Debug: Direct Syscall",
            description="Direct syscall detected (bypasses library hooks)",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={
                "technique": "Direct syscall invocation",
                "syscall_number": sys_num if sys_num is not None else "Dynamic",
                "syscall_name": sys_name
            },
            impact="Bypasses standard user-mode hooks (Frida Interceptor)",
            recommendation="Use kernel-level monitoring or instruction rewriting"
        ))
        
        return findings


    def _check_dyld_get_image_name(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check _dyld_get_image_name for injected library detection."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.MEDIUM,
            issue_type="Anti-Injection: _dyld_get_image_name",
            description="_dyld_get_image_name call detected (enumerates loaded library paths)",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={
                "technique": "Loaded library path enumeration",
                "detects": "Frida, Cydia Substrate, injected dylibs"
            },
            impact="Can detect injected libraries by checking image paths for known hooking frameworks",
            recommendation="Hook _dyld_get_image_name to hide injected library paths"
        ))

        return findings

    def _check_dyld_image_count(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check _dyld_image_count for injection detection."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.LOW,
            issue_type="Anti-Injection: _dyld_image_count",
            description="_dyld_image_count call detected (counts loaded images)",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={
                "technique": "Loaded image count check",
                "note": "Typically used with _dyld_get_image_name to enumerate libraries"
            },
            impact="Can detect unexpected libraries by monitoring loaded image count",
            recommendation="Hook _dyld_image_count to return expected baseline count"
        ))

        return findings

    def _check_dladdr(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check dladdr for hook/caller validation."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.LOW,
            issue_type="Anti-Hook: dladdr",
            description="dladdr call detected (validates caller address or detects function hooking)",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={
                "technique": "Address-to-symbol resolution",
                "detects": "Function hooks, injected code, unexpected callers"
            },
            impact="Can detect if functions have been hooked by checking if return addresses are in expected libraries",
            recommendation="Hook dladdr to return expected Dl_info values"
        ))

        return findings

    def _check_dlsym(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check dlsym for dynamic resolution of anti-debug APIs."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.LOW,
            issue_type="Anti-Debug: dlsym",
            description="dlsym call detected (dynamic symbol resolution, may resolve anti-debug APIs at runtime)",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={
                "technique": "Dynamic symbol resolution",
                "note": "May resolve ptrace, sysctl, or other anti-debug functions to evade static analysis"
            },
            impact="Can dynamically resolve security-sensitive functions to bypass static analysis detection",
            recommendation="Hook dlsym to monitor which symbols are being resolved"
        ))

        return findings

    def _check_task_info(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check task_info for library enumeration via TASK_DYLD_INFO."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.MEDIUM,
            issue_type="Anti-Injection: task_info",
            description="task_info call detected (may enumerate loaded libraries via TASK_DYLD_INFO)",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={
                "technique": "Mach task library enumeration",
                "detects": "Injected dylibs, hooking frameworks"
            },
            impact="TASK_DYLD_INFO can enumerate all loaded libraries to detect injection",
            recommendation="Hook task_info to filter injected libraries from results"
        ))

        return findings

    def _check_defensive_exit(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check exit/abort for defensive termination."""
        findings = []
        func_name = function_sig.name

        # Check exit status if available
        exit_code = None
        if func_name == "exit" and extracted_info and extracted_info.parameters:
            exit_code = self._get_constant_int(extracted_info.parameters[0])

        findings.append(SecurityFinding(
            severity=Severity.LOW,
            issue_type="Anti-Debug: Defensive {}".format(func_name),
            description="{} call detected (possible defensive termination after tampering detection)".format(func_name),
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={
                "technique": "Defensive process termination",
                "function": func_name,
                "exit_code": str(exit_code) if exit_code is not None else "unknown"
            },
            impact="May terminate the process when debugging or tampering is detected",
            recommendation="Hook {} to prevent termination; investigate caller for detection logic".format(func_name)
        ))

        return findings


__all__ = ["AntiDebugSecurityChecker"]
