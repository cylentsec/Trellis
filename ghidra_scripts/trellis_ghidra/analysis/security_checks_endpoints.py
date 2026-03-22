"""
Endpoints security checks for Trellis (Ghidra Port).

This module implements security analysis for API endpoints and URLs,
extracting and analyzing network endpoints used by the application.
"""

import re
from typing import Optional, List, Set, TYPE_CHECKING

from .security_checks import SecurityChecker, SecurityFinding, Severity

if TYPE_CHECKING:
    from ..signatures import FunctionSignature
    from .calltree import CallSite
    from .extractor import ExtractedCallInfo


# Patterns that indicate debug/test endpoints
DEBUG_ENDPOINT_PATTERNS = [
    r"/debug",
    r"/test",
    r"/dev",
    r"/staging",
    r"/sandbox",
    r"/mock",
    r"/local",
    r"/internal",
    r"localhost",
    r"127\.0\.0\.1",
    r"10\.\d+\.\d+\.\d+",
    r"192\.168\.\d+\.\d+",
    r"172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+",
]

# Sensitive endpoint patterns
SENSITIVE_ENDPOINT_PATTERNS = [
    r"/auth",
    r"/login",
    r"/token",
    r"/oauth",
    r"/password",
    r"/reset",
    r"/admin",
    r"/payment",
    r"/checkout",
    r"/card",
    r"/billing",
    r"/api/v\d+/users?",
    r"/api/v\d+/accounts?",
    r"/graphql",
]


class EndpointsSecurityChecker(SecurityChecker):
    """Security checker for API endpoints."""

    def __init__(self, program):
        """Initialize the checker."""
        super().__init__(program)
        self._discovered_endpoints: Set[str] = set()

    def check_call_site(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check a function call site for endpoint information."""
        findings = []

        if not extracted_info:
            return findings

        func_name = function_sig.name

        # URL creation
        if "NSURL" in func_name or "URLWithString" in func_name or "URL" in func_name:
            findings.extend(self._check_url_creation(function_sig, call_site, extracted_info))

        # NSURLRequest/URLRequest
        elif "URLRequest" in func_name or "NSURLRequest" in func_name:
            findings.extend(self._check_url_request(function_sig, call_site, extracted_info))

        # Alamofire/AFNetworking
        elif "AF" in func_name and ("request" in func_name.lower() or "get" in func_name.lower() or "post" in func_name.lower()):
            findings.extend(self._check_alamofire(function_sig, call_site, extracted_info))

        # URLSession dataTask
        elif "dataTask" in func_name or "downloadTask" in func_name or "uploadTask" in func_name:
            findings.extend(self._check_url_session_task(function_sig, call_site, extracted_info))

        # GraphQL
        elif "graphql" in func_name.lower() or "query" in func_name.lower():
            findings.extend(self._check_graphql(function_sig, call_site, extracted_info))

        # REST/API path building
        elif "appendPathComponent" in func_name or "appendingPathComponent" in func_name:
            findings.extend(self._check_path_component(function_sig, call_site, extracted_info))

        # WebSocket
        elif "WebSocket" in func_name or "wss://" in str(extracted_info):
            findings.extend(self._check_websocket(function_sig, call_site, extracted_info))

        return findings

    def _check_url_creation(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check URL creation for endpoints."""
        findings = []

        if not extracted_info.parameters:
            return findings

        for param in extracted_info.parameters:
            if param.value_as_string:
                url = param.value_as_string
                findings.extend(self._analyze_url(url, function_sig, call_site))

        return findings

    def _check_url_request(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check URLRequest for endpoint information."""
        findings = []

        if not extracted_info.parameters:
            return findings

        for param in extracted_info.parameters:
            if param.value_as_string:
                url = param.value_as_string
                findings.extend(self._analyze_url(url, function_sig, call_site))

        return findings

    def _check_alamofire(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check Alamofire/AFNetworking requests."""
        findings = []

        if not extracted_info.parameters:
            return findings

        for param in extracted_info.parameters:
            if param.value_as_string:
                url = param.value_as_string
                findings.extend(self._analyze_url(url, function_sig, call_site))

        # Note the networking library usage
        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="Networking Library Detected",
            description="Alamofire/AFNetworking request detected",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"library": "Alamofire/AFNetworking"},
            impact="Third-party networking library in use",
            recommendation="Ensure library is up-to-date and TLS properly configured"
        ))

        return findings

    def _check_url_session_task(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check URLSession task creation."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="URLSession Task",
            description="{} network request detected".format(function_sig.name),
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api": function_sig.name},
            impact="Network request being made",
            recommendation="Review request URL and data handling"
        ))

        return findings

    def _check_graphql(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check GraphQL usage."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="GraphQL Endpoint",
            description="GraphQL API usage detected",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api_type": "GraphQL"},
            impact="GraphQL APIs may expose more data than intended",
            recommendation="Review GraphQL schema for data exposure"
        ))

        # Check for query strings
        if extracted_info.parameters:
            for param in extracted_info.parameters:
                if param.value_as_string and ("query" in param.value_as_string.lower() or "mutation" in param.value_as_string.lower()):
                    findings.append(SecurityFinding(
                        severity=Severity.LOW,
                        issue_type="GraphQL Query Pattern",
                        description="GraphQL query/mutation detected",
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={"query_fragment": param.value_as_string[:100]},
                        impact="Query structure visible in binary",
                        recommendation="Review for sensitive field exposure"
                    ))

        return findings

    def _check_path_component(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check URL path component appending."""
        findings = []

        if not extracted_info.parameters:
            return findings

        for param in extracted_info.parameters:
            if param.value_as_string:
                path = param.value_as_string
                
                # Check for API versioning
                if re.match(r"v\d+", path) or re.match(r"api", path.lower()):
                    findings.append(SecurityFinding(
                        severity=Severity.INFO,
                        issue_type="API Path Component",
                        description="API path component: {}".format(path),
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={"path": path},
                        impact="API structure visible",
                        recommendation="Document for API mapping"
                    ))

        return findings

    def _check_websocket(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check WebSocket usage."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="WebSocket Connection",
            description="WebSocket connection detected",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"protocol": "WebSocket"},
            impact="Real-time data channel",
            recommendation="Ensure wss:// (secure) is used instead of ws://"
        ))

        # Check for ws:// (insecure)
        if extracted_info.parameters:
            for param in extracted_info.parameters:
                if param.value_as_string and "ws://" in param.value_as_string.lower():
                    findings.append(SecurityFinding(
                        severity=Severity.HIGH,
                        issue_type="Insecure WebSocket",
                        description="Unencrypted WebSocket (ws://) detected",
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={"url": param.value_as_string},
                        impact="WebSocket traffic is not encrypted",
                        recommendation="Use wss:// for encrypted WebSocket connections"
                    ))

        return findings

    def _analyze_url(
        self,
        url: str,
        function_sig: "FunctionSignature",
        call_site: "CallSite"
    ) -> List[SecurityFinding]:
        """Analyze a URL string for security issues."""
        findings = []

        # Skip if already discovered
        if url in self._discovered_endpoints:
            return findings
        self._discovered_endpoints.add(url)

        # Check for HTTP (non-HTTPS)
        if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
            findings.append(SecurityFinding(
                severity=Severity.MEDIUM,
                issue_type="Insecure HTTP Endpoint",
                description="Unencrypted HTTP endpoint detected",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"url": url},
                impact="Data transmitted without encryption",
                recommendation="Use HTTPS for all network communications"
            ))

        # Check for debug/test endpoints
        for pattern in DEBUG_ENDPOINT_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                findings.append(SecurityFinding(
                    severity=Severity.HIGH,
                    issue_type="Debug/Test Endpoint",
                    description="Debug or test endpoint detected: {}".format(url),
                    location=call_site.call_instruction_address,
                    function_name=function_sig.name,
                    evidence={"url": url, "pattern": pattern},
                    impact="Debug endpoints may be accessible in production",
                    recommendation="Remove or disable debug endpoints in production builds"
                ))
                break

        # Check for sensitive endpoints
        for pattern in SENSITIVE_ENDPOINT_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                findings.append(SecurityFinding(
                    severity=Severity.INFO,
                    issue_type="Sensitive Endpoint",
                    description="Sensitive endpoint detected: {}".format(url),
                    location=call_site.call_instruction_address,
                    function_name=function_sig.name,
                    evidence={"url": url, "type": pattern},
                    impact="Endpoint handles sensitive operations",
                    recommendation="Ensure proper authentication and authorization"
                ))
                break

        # Check for hardcoded API keys in URL
        if "api_key=" in url.lower() or "apikey=" in url.lower() or "key=" in url.lower():
            findings.append(SecurityFinding(
                severity=Severity.CRITICAL,
                issue_type="API Key in URL",
                description="API key embedded in URL",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"url": url[:100]},
                impact="API key visible in binary and network logs",
                recommendation="Move API keys to headers or secure storage"
            ))

        # Check for credentials in URL
        if "@" in url and "://" in url:
            # URL might have credentials (http://user:pass@host)
            match = re.search(r"://([^:]+):([^@]+)@", url)
            if match:
                findings.append(SecurityFinding(
                    severity=Severity.CRITICAL,
                    issue_type="Credentials in URL",
                    description="Username/password embedded in URL",
                    location=call_site.call_instruction_address,
                    function_name=function_sig.name,
                    evidence={"url_pattern": "://user:pass@host"},
                    impact="Credentials visible in binary and logs",
                    recommendation="Use secure authentication methods"
                ))

        # Record the endpoint for reporting
        if url.startswith("http"):
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="API Endpoint",
                description="Network endpoint: {}".format(url),
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"url": url},
                impact="Endpoint used by application",
                recommendation="Document for API surface mapping"
            ))

        return findings


__all__ = ["EndpointsSecurityChecker"]
