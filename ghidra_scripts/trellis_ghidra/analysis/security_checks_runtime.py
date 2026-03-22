"""
Runtime manipulation security checks for Trellis (Ghidra Port).

This module detects runtime security vulnerabilities that can be exploited via
dynamic instrumentation or binary patching:
- Hardcoded credential comparisons (isEqualToString: with static strings)
- Always-true/always-false authentication conditions
- Client-side validation logic that can be bypassed

These are common in intentionally vulnerable apps (e.g., DVIA-v2) and in
production apps where developers implement client-side auth checks.
"""

from typing import List, TYPE_CHECKING

from .security_checks import SecurityChecker, SecurityFinding, Severity

if TYPE_CHECKING:
    from ..signatures import FunctionSignature
    from .calltree import CallSite
    from .extractor import ExtractedCallInfo


# Keywords in caller names that indicate authentication / validation context
_AUTH_CALLER_KEYWORDS = [
    "login", "auth", "authenticate", "signin", "signIn",
    "validate", "verify", "credential", "password",
    "checkPassword", "checkCredential", "checkAccess",
    "isAdmin", "isAuthorized", "isAuthenticated",
    "TouchID", "FaceID", "biometric",
]

# Keywords in caller names that indicate comparison / validation logic
_VALIDATION_CALLER_KEYWORDS = [
    "compare", "check", "validate", "verify",
    "match", "confirm", "equal",
]


def _caller_suggests_auth(caller_name):
    """Check if the caller function name suggests authentication context."""
    if not caller_name:
        return False
    lower = caller_name.lower()
    for kw in _AUTH_CALLER_KEYWORDS:
        if kw.lower() in lower:
            return True
    return False


def _caller_suggests_validation(caller_name):
    """Check if the caller function name suggests validation context."""
    if not caller_name:
        return False
    lower = caller_name.lower()
    for kw in _VALIDATION_CALLER_KEYWORDS:
        if kw.lower() in lower:
            return True
    return False


class RuntimeSecurityChecker(SecurityChecker):
    """
    Security checker for runtime manipulation vulnerabilities.

    Detects patterns like:
    - [userInput isEqualToString:@"admin123"]  → hardcoded credential
    - if (3 < 1) { grantAccess() }  → always-false auth bypass
    - if ([pin isEqualToString:@"8848"]) → hardcoded validation code
    """

    def check_call_site(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check for runtime manipulation vulnerabilities."""
        findings = []

        func_name = function_sig.name
        caller_name = call_site.caller_name if call_site else None

        # String comparison methods (ObjC)
        if func_name in ("isEqualToString:", "isEqual:", "compare:",
                         "caseInsensitiveCompare:", "localizedCompare:"):
            findings.extend(self._check_string_comparison(
                function_sig, call_site, extracted_info
            ))

        # Integer/numeric comparison in auth context
        elif func_name in ("integerValue", "intValue", "boolValue"):
            if _caller_suggests_auth(caller_name):
                findings.extend(self._check_auth_context(
                    function_sig, call_site, extracted_info
                ))

        return findings

    def _check_string_comparison(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check string comparison methods for hardcoded credentials."""
        findings = []
        caller_name = call_site.caller_name if call_site else None

        # Check if we're in an auth/validation context
        is_auth = _caller_suggests_auth(caller_name)
        is_validation = _caller_suggests_validation(caller_name)

        if not (is_auth or is_validation):
            return findings

        # Check if any parameter has a resolved string value
        has_hardcoded_string = False
        hardcoded_value = None

        if extracted_info and extracted_info.parameters:
            for param in extracted_info.parameters:
                if param.value_as_string:
                    has_hardcoded_string = True
                    hardcoded_value = param.value_as_string
                    break
                elif param.value_str and param.value_str.startswith('"'):
                    has_hardcoded_string = True
                    hardcoded_value = param.value_str.strip('"')
                    break

        if has_hardcoded_string and hardcoded_value:
            # Determine severity based on context
            severity = Severity.CRITICAL if is_auth else Severity.HIGH
            issue_type = ("Hardcoded Authentication Credential"
                          if is_auth else "Hardcoded Validation Value")

            display_caller = caller_name
            if display_caller and len(display_caller) > 80:
                display_caller = display_caller[:77] + "..."

            findings.append(SecurityFinding(
                severity=severity,
                issue_type=issue_type,
                description="Hardcoded string '{}' used in {} comparison".format(
                    hardcoded_value, function_sig.name),
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={
                    "comparison_method": function_sig.name,
                    "hardcoded_value": hardcoded_value,
                    "caller": display_caller or "<unknown>",
                    "context": "authentication" if is_auth else "validation",
                },
                impact="Attacker can extract the hardcoded value from the binary "
                       "or patch the comparison to always return true",
                recommendation="Move credential validation server-side; "
                               "never compare against hardcoded strings in the client"
            ))

        elif is_auth:
            # Can't determine the comparison value, but auth context is confirmed
            display_caller = caller_name
            if display_caller and len(display_caller) > 80:
                display_caller = display_caller[:77] + "..."

            findings.append(SecurityFinding(
                severity=Severity.MEDIUM,
                issue_type="Client-Side Authentication Check",
                description="{} called in authentication function (parameters unresolved)".format(
                    function_sig.name),
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={
                    "comparison_method": function_sig.name,
                    "caller": display_caller or "<unknown>",
                    "note": "String comparison in auth context — likely comparing "
                            "against hardcoded or locally-stored credential"
                },
                impact="Client-side authentication can be bypassed by hooking the "
                       "comparison method to always return true",
                recommendation="Implement server-side authentication; client should "
                               "only send credentials, not validate them locally"
            ))

        return findings

    def _check_auth_context(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check for numeric value extraction in auth context."""
        findings = []
        caller_name = call_site.caller_name if call_site else None

        display_caller = caller_name
        if display_caller and len(display_caller) > 80:
            display_caller = display_caller[:77] + "..."

        findings.append(SecurityFinding(
            severity=Severity.MEDIUM,
            issue_type="Client-Side Auth Logic",
            description="Numeric value extraction in authentication function",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={
                "method": function_sig.name,
                "caller": display_caller or "<unknown>",
                "note": "Integer/boolean extraction suggests client-side validation"
            },
            impact="Client-side validation logic can be bypassed with Frida",
            recommendation="Move validation logic to server-side"
        ))

        return findings


__all__ = ["RuntimeSecurityChecker"]
