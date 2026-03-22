"""
Deserialization security checks for Trellis (Ghidra Port).

This module implements security analysis for NSKeyedArchiver/NSKeyedUnarchiver and
NSCoding operations, detecting insecure deserialization patterns that could lead
to object injection or remote code execution.
"""

from typing import Optional, List, TYPE_CHECKING

from .security_checks import SecurityChecker, SecurityFinding, Severity

if TYPE_CHECKING:
    from ..signatures import FunctionSignature
    from .calltree import CallSite
    from .extractor import ExtractedCallInfo


class DeserializationSecurityChecker(SecurityChecker):
    """Security checker for deserialization operations."""

    def check_call_site(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check a deserialization function call site for security issues."""
        findings = []

        if not function_sig:
            return findings

        func_name = function_sig.name

        # Route to specific checkers based on function name
        if func_name == "unarchiveObjectWithData:":
            findings.extend(self._check_insecure_unarchive(function_sig, call_site, extracted_info))

        elif func_name == "unarchiveTopLevelObjectWithData:error:":
            findings.extend(self._check_insecure_unarchive_toplevel(function_sig, call_site, extracted_info))

        elif func_name in ["unarchivedObjectOfClass:fromData:error:",
                           "unarchivedObjectOfClasses:fromData:error:"]:
            findings.extend(self._check_secure_unarchive(function_sig, call_site, extracted_info))

        elif func_name == "decodeObjectForKey:":
            findings.extend(self._check_insecure_decode(function_sig, call_site, extracted_info))

        elif func_name == "decodeObjectOfClass:forKey:":
            findings.extend(self._check_secure_decode(function_sig, call_site, extracted_info))

        elif func_name == "setRequiresSecureCoding:":
            findings.extend(self._check_requires_secure_coding(function_sig, call_site, extracted_info))

        elif func_name == "initForReadingFromData:error:":
            findings.extend(self._check_unarchiver_init(function_sig, call_site, extracted_info))

        return findings

    def _check_insecure_unarchive(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check deprecated unarchiveObjectWithData usage."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.HIGH,
            issue_type="Insecure Deserialization",
            description="Use of deprecated unarchiveObjectWithData: allows arbitrary object instantiation",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={
                "api": "NSKeyedUnarchiver +unarchiveObjectWithData:",
                "risk": "No class validation - can instantiate any NSCoding class"
            },
            impact="Potential Remote Code Execution (RCE) if data comes from untrusted source",
            recommendation="Use unarchivedObjectOfClass:fromData:error: with specific allowed classes"
        ))

        # Try to determine data source if possible
        if extracted_info and extracted_info.parameters:
            data_param = extracted_info.parameters[0] if len(extracted_info.parameters) > 0 else None
            if data_param:
                findings.append(SecurityFinding(
                    severity=Severity.INFO,
                    issue_type="Deserialization Data Source",
                    description="Check source of deserialized data",
                    location=call_site.call_instruction_address,
                    function_name=function_sig.name,
                    evidence={"data_param": str(data_param.name) if hasattr(data_param, 'name') else "data"},
                    impact="Network data increases risk to CRITICAL",
                    recommendation="Trace data source - network/file/user input requires validation"
                ))

        return findings

    def _check_insecure_unarchive_toplevel(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check deprecated unarchiveTopLevelObjectWithData:error: usage."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.HIGH,
            issue_type="Insecure Deserialization",
            description="Use of deprecated unarchiveTopLevelObjectWithData:error: - no class validation",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={
                "api": "NSKeyedUnarchiver +unarchiveTopLevelObjectWithData:error:",
                "risk": "Allows arbitrary NSCoding object instantiation"
            },
            impact="Object injection vulnerability - potential RCE with crafted archives",
            recommendation="Use unarchivedObjectOfClass:fromData:error: with allowed class list"
        ))

        return findings

    def _check_secure_unarchive(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check modern secure unarchiving APIs."""
        findings = []

        # These are the secure APIs, but still log INFO for awareness
        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="Secure Deserialization API",
            description="Using secure unarchiving API: {}".format(function_sig.name),
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api": function_sig.name},
            impact="Class validation prevents arbitrary object instantiation",
            recommendation="Verify allowed classes are minimal and trusted"
        ))

        # Check if class parameter looks suspicious
        if extracted_info and extracted_info.parameters:
            class_param = extracted_info.parameters[0] if len(extracted_info.parameters) > 0 else None
            if class_param and class_param.value_if_constant is not None:
                class_value = str(class_param.value_if_constant)
                # Check for overly permissive classes
                if class_value in ["NSObject", "NSArray", "NSDictionary"]:
                    findings.append(SecurityFinding(
                        severity=Severity.MEDIUM,
                        issue_type="Permissive Deserialization Classes",
                        description="Allowing broad Foundation classes in deserialization",
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={"allowed_class": class_value},
                        impact="Foundation containers can hold arbitrary objects",
                        recommendation="Use specific application classes, not generic containers"
                    ))

        return findings

    def _check_insecure_decode(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check insecure decodeObjectForKey usage."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.MEDIUM,
            issue_type="Insecure NSCoder Decode",
            description="Use of decodeObjectForKey: without class validation",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={
                "api": "NSCoder -decodeObjectForKey:",
                "risk": "No class validation during decode"
            },
            impact="Can instantiate unexpected objects during deserialization",
            recommendation="Use decodeObjectOfClass:forKey: with specific class"
        ))

        return findings

    def _check_secure_decode(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check secure decodeObjectOfClass:forKey: usage."""
        findings = []

        # This is the secure API, just log INFO
        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="Secure NSCoder Decode",
            description="Using secure decode API with class validation",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api": "NSCoder -decodeObjectOfClass:forKey:"},
            impact="Class validation prevents unexpected object types",
            recommendation="Verify specified class is appropriate"
        ))

        return findings

    def _check_requires_secure_coding(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check setRequiresSecureCoding: value."""
        findings = []

        if extracted_info and extracted_info.parameters:
            value_param = extracted_info.parameters[0] if len(extracted_info.parameters) > 0 else None
            if value_param and self._is_constant_value(value_param):
                value = self._get_constant_int(value_param)
                # Check if setting to NO/false/0
                if value == 0:
                    findings.append(SecurityFinding(
                        severity=Severity.CRITICAL,
                        issue_type="Secure Coding Disabled",
                        description="Explicitly disabling secure coding on NSKeyedUnarchiver",
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={
                            "value": "NO (0)",
                            "api": "NSKeyedUnarchiver -setRequiresSecureCoding:"
                        },
                        impact="Disables all deserialization security checks - allows object injection",
                        recommendation="Always use setRequiresSecureCoding:YES for untrusted data"
                    ))
                elif value == 1:
                    findings.append(SecurityFinding(
                        severity=Severity.INFO,
                        issue_type="Secure Coding Enabled",
                        description="Secure coding enabled on NSKeyedUnarchiver",
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={"value": "YES (1)"},
                        impact="Enforces class validation during deserialization",
                        recommendation="Good practice - secure coding is enabled"
                    ))
        else:
            # Can't determine value
            findings.append(SecurityFinding(
                severity=Severity.MEDIUM,
                issue_type="Secure Coding Configuration",
                description="Setting requiresSecureCoding - verify value is YES",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"api": "NSKeyedUnarchiver -setRequiresSecureCoding:"},
                impact="If set to NO, disables deserialization security",
                recommendation="Ensure this is always set to YES for untrusted data"
            ))

        return findings

    def _check_unarchiver_init(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check NSKeyedUnarchiver initialization."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="NSKeyedUnarchiver Initialization",
            description="NSKeyedUnarchiver initialized - check for requiresSecureCoding",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api": "NSKeyedUnarchiver -initForReadingFromData:error:"},
            impact="Must call setRequiresSecureCoding:YES after init",
            recommendation="Verify setRequiresSecureCoding:YES is called immediately after"
        ))

        return findings


__all__ = ["DeserializationSecurityChecker"]
