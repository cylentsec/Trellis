"""
Networking security checks for Trellis (Ghidra Port).

This module implements security analysis for iOS networking operations,
detecting insecure TLS/SSL configurations and certificate validation issues.
"""

from typing import Optional, List, TYPE_CHECKING

from .security_checks import SecurityChecker, SecurityFinding, Severity

if TYPE_CHECKING:
    from ..signatures import FunctionSignature
    from .calltree import CallSite
    from .extractor import ExtractedCallInfo


class NetworkingSecurityChecker(SecurityChecker):
    """Security checker for networking operations."""

    def check_call_site(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check a networking function call site for security issues."""
        findings = []

        if not extracted_info:
            return findings

        func_name = function_sig.name

        # NSURLSession configuration
        if "NSURLSessionConfiguration" in func_name:
            findings.extend(self._check_session_config(function_sig, call_site, extracted_info))

        # TLS minimum version
        elif "TLSMinimumSupportedProtocol" in func_name or "minimumTLSProtocol" in func_name.lower():
            findings.extend(self._check_tls_version(function_sig, call_site, extracted_info))

        # ATS (App Transport Security) bypass
        elif "allowsArbitraryLoads" in func_name or "NSAllowsArbitraryLoads" in func_name:
            findings.extend(self._check_ats_bypass(function_sig, call_site, extracted_info))

        # Certificate validation
        elif "SecTrustEvaluate" in func_name or "SecTrustEvaluateWithError" in func_name:
            findings.extend(self._check_cert_validation(function_sig, call_site, extracted_info))

        # URLSession delegate methods
        elif "didReceiveChallenge" in func_name or "willPerformHTTPRedirection" in func_name:
            findings.extend(self._check_url_session_delegate(function_sig, call_site, extracted_info))

        # SSL/TLS context settings
        elif "SSLSetProtocolVersionMin" in func_name or "SSLSetProtocolVersionMax" in func_name:
            findings.extend(self._check_ssl_protocol_version(function_sig, call_site, extracted_info))

        # SSL handshake
        elif "SSLHandshake" in func_name:
            findings.extend(self._check_ssl_handshake(function_sig, call_site, extracted_info))

        # Network reachability
        elif "SCNetworkReachability" in func_name:
            findings.extend(self._check_network_reachability(function_sig, call_site, extracted_info))

        # CFNetwork stream properties
        elif "CFStreamPropertySSL" in func_name or "kCFStreamSSL" in func_name:
            findings.extend(self._check_cfstream_ssl(function_sig, call_site, extracted_info))

        # HTTP (non-HTTPS) URLs
        elif "NSURL" in func_name or "URLWithString" in func_name:
            findings.extend(self._check_url_scheme(function_sig, call_site, extracted_info))

        return findings

    def _check_session_config(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check NSURLSessionConfiguration settings."""
        findings = []

        # Check for ephemeral vs default configuration
        if "ephemeralSessionConfiguration" in function_sig.name:
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="Ephemeral Session Configuration",
                description="NSURLSession using ephemeral configuration (no persistent storage)",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"config_type": "ephemeral"},
                impact="Session data not persisted to disk",
                recommendation="Appropriate for sensitive data transfers"
            ))
        elif "defaultSessionConfiguration" in function_sig.name:
            findings.append(SecurityFinding(
                severity=Severity.LOW,
                issue_type="Default Session Configuration",
                description="NSURLSession using default configuration (may cache to disk)",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"config_type": "default"},
                impact="Response data may be cached to disk",
                recommendation="Consider ephemeral configuration for sensitive data"
            ))

        return findings

    def _check_tls_version(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check TLS minimum version settings."""
        findings = []

        if not extracted_info.parameters:
            return findings

        params_by_name = {p.name: p for p in extracted_info.parameters}

        # Known weak TLS version constants
        weak_versions = {
            0: "SSL 3.0",  # kSSLProtocol3
            1: "TLS 1.0",  # kTLSProtocol1
            2: "TLS 1.1",  # kTLSProtocol11
        }

        for param in extracted_info.parameters:
            if self._is_constant_value(param):
                version_val = self._get_constant_int(param)
                if version_val in weak_versions:
                    findings.append(SecurityFinding(
                        severity=Severity.HIGH,
                        issue_type="Weak TLS Version",
                        description="Minimum TLS version set to {}".format(weak_versions[version_val]),
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={"tls_version": weak_versions[version_val], "constant": version_val},
                        impact="Weak TLS versions are vulnerable to known attacks (POODLE, BEAST)",
                        recommendation="Set minimum TLS version to 1.2 or higher"
                    ))
                    break

        if not findings:
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="TLS Version Configuration",
                description="TLS minimum version being configured",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={},
                impact="TLS version affects connection security",
                recommendation="Ensure TLS 1.2+ is required"
            ))

        return findings

    def _check_ats_bypass(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check for App Transport Security bypass."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.HIGH,
            issue_type="ATS Bypass Detected",
            description="App Transport Security may be disabled (NSAllowsArbitraryLoads)",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"setting": "NSAllowsArbitraryLoads"},
            impact="Allows insecure HTTP connections and weak TLS",
            recommendation="Enable ATS and configure exceptions only for specific domains"
        ))

        return findings

    def _check_cert_validation(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check certificate validation calls."""
        findings = []

        # SecTrustEvaluate is the critical point for cert validation
        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="Certificate Trust Evaluation",
            description="SecTrust certificate validation detected",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api": function_sig.name},
            impact="Certificate validation is a critical security control",
            recommendation="Verify the result is properly checked (not ignored)"
        ))

        return findings

    def _check_url_session_delegate(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check URLSession delegate method implementations."""
        findings = []

        if "didReceiveChallenge" in function_sig.name:
            findings.append(SecurityFinding(
                severity=Severity.MEDIUM,
                issue_type="Authentication Challenge Handler",
                description="URLSession authentication challenge handler implemented",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"delegate_method": "didReceiveChallenge"},
                impact="Custom challenge handling may bypass certificate validation",
                recommendation="Review handler to ensure it doesn't blindly accept certificates"
            ))
        elif "willPerformHTTPRedirection" in function_sig.name:
            findings.append(SecurityFinding(
                severity=Severity.LOW,
                issue_type="HTTP Redirection Handler",
                description="URLSession redirect handler implemented",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"delegate_method": "willPerformHTTPRedirection"},
                impact="Redirects to HTTP or malicious URLs may be allowed",
                recommendation="Validate redirect URLs maintain HTTPS"
            ))

        return findings

    def _check_ssl_protocol_version(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check SSLSetProtocolVersion calls."""
        findings = []

        if not extracted_info.parameters:
            return findings

        # Check for weak protocol versions
        weak_protocols = {
            0x0300: "SSL 3.0",
            0x0301: "TLS 1.0",
            0x0302: "TLS 1.1",
        }

        for param in extracted_info.parameters:
            if self._is_constant_value(param):
                proto_val = self._get_constant_int(param)
                if proto_val in weak_protocols:
                    findings.append(SecurityFinding(
                        severity=Severity.HIGH,
                        issue_type="Weak SSL/TLS Protocol",
                        description="SSL protocol version set to {}".format(weak_protocols[proto_val]),
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={"protocol": weak_protocols[proto_val], "value": hex(proto_val)},
                        impact="Weak protocols are vulnerable to downgrade attacks",
                        recommendation="Use TLS 1.2 (0x0303) or TLS 1.3 (0x0304) minimum"
                    ))
                    break

        if not findings:
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="SSL Protocol Configuration",
                description="SSL protocol version being configured",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={},
                impact="Protocol version affects connection security",
                recommendation="Verify TLS 1.2+ is enforced"
            ))

        return findings

    def _check_ssl_handshake(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check SSLHandshake usage."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="SSL Handshake",
            description="SSLHandshake API usage detected",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api": "SSLHandshake"},
            impact="Custom SSL implementation",
            recommendation="Verify proper error handling and certificate validation"
        ))

        return findings

    def _check_network_reachability(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check network reachability usage."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="Network Reachability Check",
            description="SCNetworkReachability API usage",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api": "SCNetworkReachability"},
            impact="Network status checking",
            recommendation="Ensure fallback behavior is secure when offline"
        ))

        return findings

    def _check_cfstream_ssl(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check CFStream SSL properties."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.MEDIUM,
            issue_type="CFStream SSL Configuration",
            description="CFStream SSL properties being configured",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api": "CFStream SSL"},
            impact="Low-level SSL configuration may have security implications",
            recommendation="Review SSL settings for proper certificate validation"
        ))

        return findings

    def _check_url_scheme(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check URL creation for insecure schemes."""
        findings = []

        if not extracted_info.parameters:
            return findings

        for param in extracted_info.parameters:
            if param.value_as_string:
                url_string = param.value_as_string.lower()
                if url_string.startswith("http://") and not url_string.startswith("http://localhost"):
                    findings.append(SecurityFinding(
                        severity=Severity.MEDIUM,
                        issue_type="Insecure HTTP URL",
                        description="Hardcoded HTTP (non-HTTPS) URL detected",
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={"url": param.value_as_string},
                        impact="Data transmitted over HTTP is not encrypted",
                        recommendation="Use HTTPS for all network communications"
                    ))

        return findings


__all__ = ["NetworkingSecurityChecker"]
