"""
Biometric authentication security checks for Trellis (Ghidra Port).

Detects LAContext biometric authentication usage and flags insecure
client-side-only biometric checks that can be trivially bypassed.
The secure pattern binds biometric to Keychain via SecAccessControl;
using evaluatePolicy alone is a HIGH severity issue.
"""

from typing import List, TYPE_CHECKING

from .security_checks import SecurityChecker, SecurityFinding, Severity

if TYPE_CHECKING:
    from ..signatures import FunctionSignature
    from .calltree import CallSite
    from .extractor import ExtractedCallInfo


class BiometricSecurityChecker(SecurityChecker):
    """Security checker for biometric authentication (Touch ID / Face ID)."""

    def check_call_site(self, function_sig, call_site, extracted_info):
        """Check a biometric function call site for security issues."""
        findings = []
        func_name = function_sig.name

        if "evaluatePolicy" in func_name and "localizedReason" in func_name:
            findings.extend(self._check_evaluate_policy(
                function_sig, call_site, extracted_info
            ))

        elif func_name == "canEvaluatePolicy:error:":
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="Biometric Availability Check",
                description="Application checks biometric availability via canEvaluatePolicy",
                location=call_site.call_instruction_address,
                function_name=func_name,
                evidence={"api": "canEvaluatePolicy:error:"},
                impact="Biometric authentication is available in this app",
                recommendation="Verify biometric is combined with Keychain access control"
            ))

        elif "evaluateAccessControl" in func_name:
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="Biometric Access Control",
                description="LAContext evaluateAccessControl used (more secure pattern)",
                location=call_site.call_instruction_address,
                function_name=func_name,
                evidence={"api": func_name},
                impact="Using SecAccessControl with LAContext is more secure than evaluatePolicy alone",
                recommendation="Verify SecAccessControl uses kSecAccessControlBiometryAny or BiometryCurrentSet"
            ))

        return findings

    def _check_evaluate_policy(self, function_sig, call_site, extracted_info):
        """Check evaluatePolicy:localizedReason:reply: for client-side bypass risk."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.HIGH,
            issue_type="Client-Side Biometric Authentication",
            description="LAContext.evaluatePolicy used for biometric auth - trivially bypassable",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={
                "api": "evaluatePolicy:localizedReason:reply:",
                "bypass_methods": "Frida hook, binary patch, ObjC swizzle",
            },
            impact="Client-side biometric check returns a simple BOOL that can be hooked to always return true",
            recommendation="Bind biometric to Keychain with SecAccessControlCreateWithFlags + kSecAccessControlBiometryAny"
        ))

        return findings


    def scan_for_biometric(self):
        """
        Standalone string-table scan for biometric authentication usage.

        Searches the binary's string table for evaluatePolicy:localizedReason:reply:
        selectors and flags them as client-side biometric if no corresponding
        evaluateAccessControl usage is found (the secure Keychain-bound pattern).

        Returns:
            List of SecurityFinding objects
        """
        findings = []
        has_evaluate_policy = False
        has_evaluate_access_control = False
        evaluate_policy_addresses = []

        for address, string_value in self.program.get_defined_strings():
            if not string_value:
                continue
            if "evaluatePolicy" in string_value and "localizedReason" in string_value:
                has_evaluate_policy = True
                evaluate_policy_addresses.append(address)
            if "evaluateAccessControl" in string_value:
                has_evaluate_access_control = True

        if has_evaluate_policy and not has_evaluate_access_control:
            for addr in evaluate_policy_addresses:
                findings.append(SecurityFinding(
                    severity=Severity.HIGH,
                    issue_type="Client-Side Biometric Authentication (String Scan)",
                    description="evaluatePolicy:localizedReason:reply: found without "
                                "evaluateAccessControl — biometric is not bound to Keychain",
                    location=addr,
                    function_name="evaluatePolicy:localizedReason:reply:",
                    evidence={
                        "selector": "evaluatePolicy:localizedReason:reply:",
                        "secure_alternative_present": "No",
                        "detection_method": "string_table_scan",
                    },
                    impact="Client-side biometric check returns a simple BOOL that can be "
                           "hooked to always return true via Frida or binary patch",
                    recommendation="Bind biometric to Keychain with "
                                   "SecAccessControlCreateWithFlags + kSecAccessControlBiometryAny"
                ))
        elif has_evaluate_policy and has_evaluate_access_control:
            for addr in evaluate_policy_addresses:
                findings.append(SecurityFinding(
                    severity=Severity.INFO,
                    issue_type="Biometric Authentication Present",
                    description="evaluatePolicy:localizedReason:reply: found; "
                                "evaluateAccessControl also present (potentially secure)",
                    location=addr,
                    function_name="evaluatePolicy:localizedReason:reply:",
                    evidence={
                        "selector": "evaluatePolicy:localizedReason:reply:",
                        "secure_alternative_present": "Yes",
                        "detection_method": "string_table_scan",
                    },
                    impact="Biometric authentication detected; verify evaluateAccessControl "
                           "is used for the sensitive path",
                    recommendation="Confirm that sensitive operations use Keychain-bound "
                                   "biometric, not just evaluatePolicy"
                ))

        return findings


__all__ = ["BiometricSecurityChecker"]
