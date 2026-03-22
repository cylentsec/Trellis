"""
Logging security checks for Trellis (Ghidra Port).

This module implements security analysis for iOS logging operations,
detecting potential sensitive data leakage through logging APIs.
"""

from typing import Optional, List, TYPE_CHECKING

from .security_checks import SecurityChecker, SecurityFinding, Severity

if TYPE_CHECKING:
    from ..signatures import FunctionSignature
    from .calltree import CallSite
    from .extractor import ExtractedCallInfo


# Keywords that suggest sensitive data in log messages
SENSITIVE_KEYWORDS = [
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "auth", "credential", "credit", "card", "cvv", "ssn", "social",
    "private", "key", "session", "cookie", "bearer", "jwt", "oauth",
    "pin", "otp", "passcode", "biometric", "fingerprint", "face_id",
    "account", "user", "email", "phone", "address", "dob", "birth",
    "encrypt", "decrypt", "cipher", "hash", "salt", "nonce", "iv"
]


class LoggingSecurityChecker(SecurityChecker):
    """Security checker for logging operations."""

    def check_call_site(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check a logging function call site for security issues."""
        findings = []

        if not extracted_info:
            return findings

        func_name = function_sig.name

        # NSLog (Objective-C)
        if "NSLog" in func_name:
            findings.extend(self._check_nslog(function_sig, call_site, extracted_info))

        # os_log (Unified logging)
        elif "os_log" in func_name or "_os_log" in func_name:
            findings.extend(self._check_os_log(function_sig, call_site, extracted_info))

        # Swift print/debugPrint
        elif func_name in ["print", "debugPrint", "dump"] or "Swift.print" in func_name:
            findings.extend(self._check_swift_print(function_sig, call_site, extracted_info))

        # CocoaLumberjack
        elif "DDLog" in func_name:
            findings.extend(self._check_cocoalumberjack(function_sig, call_site, extracted_info))

        # OSLog Logger (iOS 14+)
        elif "Logger" in func_name and ("log" in func_name.lower() or "info" in func_name.lower()):
            findings.extend(self._check_logger(function_sig, call_site, extracted_info))

        # printf/fprintf (C)
        elif func_name in ["print", "fprint", "sprint", "snprint"]:
            findings.extend(self._check_printf(function_sig, call_site, extracted_info))

        # syslog
        elif "syslog" in func_name:
            findings.extend(self._check_syslog(function_sig, call_site, extracted_info))

        # asl_log (Apple System Logger - deprecated but may exist)
        elif "asl_log" in func_name:
            findings.extend(self._check_asl(function_sig, call_site, extracted_info))

        return findings

    def _check_nslog(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check NSLog for sensitive data."""
        findings = []

        # NSLog in production — base severity is INFO to reduce noise.
        # Promoted to HIGH only when sensitive keywords are detected in content.
        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="NSLog in Production",
            description="NSLog call detected - logs are visible in device console",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api": "NSLog"},
            impact="NSLog output can be read by any app or attacker with device access",
            recommendation="Use os_log with privacy modifiers or remove in production builds"
        ))

        # Check for sensitive keywords in format string
        self._check_sensitive_content(function_sig, call_site, extracted_info, findings)

        return findings

    def _check_os_log(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check os_log for sensitive data."""
        findings = []

        # os_log is better but still needs review
        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="Unified Logging (os_log)",
            description="os_log call detected - check privacy modifiers",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api": "os_log"},
            impact="os_log can redact sensitive data with %{private} modifier",
            recommendation="Use %{private} for sensitive data, %{public} only for non-sensitive"
        ))

        # Check for sensitive keywords
        self._check_sensitive_content(function_sig, call_site, extracted_info, findings)

        return findings

    def _check_swift_print(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check Swift print/debugPrint for sensitive data."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.MEDIUM,
            issue_type="Swift Print Statement",
            description="{}() call detected - should not be in production".format(function_sig.name),
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api": function_sig.name},
            impact="Print statements expose data in device logs",
            recommendation="Remove print statements or use logging framework with build flags"
        ))

        # Check for sensitive keywords
        self._check_sensitive_content(function_sig, call_site, extracted_info, findings)

        return findings

    def _check_cocoalumberjack(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check CocoaLumberjack logging."""
        findings = []

        # Determine log level from function name
        log_level = "unknown"
        if "Verbose" in function_sig.name:
            log_level = "verbose"
        elif "Debug" in function_sig.name:
            log_level = "debug"
        elif "Info" in function_sig.name:
            log_level = "info"
        elif "Warn" in function_sig.name:
            log_level = "warning"
        elif "Error" in function_sig.name:
            log_level = "error"

        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="CocoaLumberjack Logging",
            description="DDLog{} call detected".format(log_level.capitalize()),
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api": function_sig.name, "level": log_level},
            impact="Logging frameworks can leak data if misconfigured",
            recommendation="Ensure log levels are appropriate for production"
        ))

        # Check for sensitive keywords
        self._check_sensitive_content(function_sig, call_site, extracted_info, findings)

        return findings

    def _check_logger(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check OSLog Logger usage."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="OSLog Logger",
            description="OSLog Logger call detected",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api": "Logger"},
            impact="OSLog Logger supports privacy modifiers",
            recommendation="Use privacy modifiers for sensitive data"
        ))

        # Check for sensitive keywords
        self._check_sensitive_content(function_sig, call_site, extracted_info, findings)

        return findings

    def _check_printf(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check printf family functions."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.MEDIUM,
            issue_type="C Printf Logging",
            description="{} call detected - low-level logging".format(function_sig.name),
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api": function_sig.name},
            impact="Printf output goes to stdout/stderr which may be captured",
            recommendation="Use structured logging with privacy controls"
        ))

        # Check for sensitive keywords
        self._check_sensitive_content(function_sig, call_site, extracted_info, findings)

        return findings

    def _check_syslog(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check syslog usage."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.MEDIUM,
            issue_type="Syslog Usage",
            description="syslog call detected - system-level logging",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api": "syslog"},
            impact="Syslog messages are persistent and accessible",
            recommendation="Use os_log with privacy modifiers instead"
        ))

        # Check for sensitive keywords
        self._check_sensitive_content(function_sig, call_site, extracted_info, findings)

        return findings

    def _check_asl(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check Apple System Logger (deprecated)."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.MEDIUM,
            issue_type="Deprecated ASL Logging",
            description="asl_log call detected - deprecated API",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api": "asl_log"},
            impact="ASL is deprecated; logs may have inconsistent behavior",
            recommendation="Migrate to os_log unified logging"
        ))

        # Check for sensitive keywords
        self._check_sensitive_content(function_sig, call_site, extracted_info, findings)

        return findings

    def _check_sensitive_content(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo",
        findings: List[SecurityFinding]
    ) -> None:
        """Check log message for sensitive keywords."""
        if not extracted_info.parameters:
            return

        for param in extracted_info.parameters:
            if param.value_as_string:
                log_content = param.value_as_string.lower()
                
                for keyword in SENSITIVE_KEYWORDS:
                    if keyword in log_content:
                        findings.append(SecurityFinding(
                            severity=Severity.HIGH,
                            issue_type="Sensitive Data in Log",
                            description="Potential sensitive data '{}' found in log message".format(keyword),
                            location=call_site.call_instruction_address,
                            function_name=function_sig.name,
                            evidence={
                                "keyword": keyword,
                                "context": param.value_as_string[:100]
                            },
                            impact="'{}' related data may be leaked to device logs".format(keyword),
                            recommendation="Remove sensitive data from logs or use privacy modifiers"
                        ))
                        break  # One finding per parameter is enough


__all__ = ["LoggingSecurityChecker"]
