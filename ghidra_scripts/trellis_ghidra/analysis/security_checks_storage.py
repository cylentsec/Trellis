"""
Storage security checks for Trellis (Ghidra Port).

This module implements security analysis for data storage operations,
detecting insecure storage of sensitive data in NSUserDefaults, plist files,
SQLite databases, and archived objects.
"""

from typing import Optional, List, TYPE_CHECKING

from .security_checks import SecurityChecker, SecurityFinding, Severity

if TYPE_CHECKING:
    from ..signatures import FunctionSignature
    from .calltree import CallSite
    from .extractor import ExtractedCallInfo


# Key name patterns that indicate security-sensitive data
SENSITIVE_KEY_PATTERNS = {
    # Authentication
    "token", "auth", "password", "credential", "secret", "apikey", "api_key",
    "access_token", "refresh_token", "session", "jwt", "bearer",
    # Cryptographic
    "key", "encryption", "decrypt", "private_key", "public_key", "certificate",
    "cert", "pin", "hmac",
    # Security policy
    "trusted", "allowed", "whitelist", "allowlist", "blocklist", "blacklist",
    "domain", "host", "endpoint", "url",
    # Personal data
    "ssn", "social_security", "credit_card", "card_number", "cvv", "account",
}

# High-sensitivity patterns (should NEVER be in UserDefaults)
CRITICAL_KEY_PATTERNS = {
    "password", "secret", "private_key", "apikey", "api_key",
    "access_token", "refresh_token", "bearer", "jwt",
    "credit_card", "card_number", "cvv", "ssn",
}

# Security policy patterns that could lead to bypasses
SECURITY_POLICY_PATTERNS = {
    "trusted", "allowed", "whitelist", "allowlist", "verified",
    "domain", "host", "endpoint", "url", "skip", "bypass",
    "jailbreak", "rooted", "debug", "admin", "privileged",
}


class StorageSecurityChecker(SecurityChecker):
    """Security checker for data storage operations."""

    def check_call_site(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check a storage function call site for security issues."""
        findings = []

        if not extracted_info:
            return findings

        func_name = function_sig.name

        # Check NSUserDefaults methods
        if func_name in ["setObject:forKey:", "objectForKey:", "setBool:forKey:",
                         "setInteger:forKey:", "stringForKey:", "arrayForKey:",
                         "boolForKey:"]:
            findings.extend(self._check_userdefaults(function_sig, call_site, extracted_info))

        # Check deprecated synchronize
        elif func_name == "synchronize":
            findings.append(SecurityFinding(
                severity=Severity.LOW,
                issue_type="Deprecated API",
                description="Using deprecated NSUserDefaults synchronize",
                location=call_site.call_instruction_address,
                function_name=func_name,
                evidence={},
                impact="synchronize is deprecated since iOS 12 and indicates legacy code",
                recommendation="Remove synchronize calls - NSUserDefaults auto-saves"
            ))

        # Check file write operations
        elif func_name == "writeToFile:atomically:":
            findings.extend(self._check_file_write(function_sig, call_site, extracted_info))

        # Check file read operations
        elif func_name == "initWithContentsOfFile:":
            findings.extend(self._check_file_read(function_sig, call_site, extracted_info))

        # Check NSKeyedArchiver
        elif func_name == "archivedDataWithRootObject:":
            findings.append(SecurityFinding(
                severity=Severity.MEDIUM,
                issue_type="Insecure Archiving",
                description="Using deprecated archiver without secure coding",
                location=call_site.call_instruction_address,
                function_name=func_name,
                evidence={},
                impact="No protection against deserialization attacks",
                recommendation="Use archivedDataWithRootObject:requiringSecureCoding:error: with secure coding enabled"
            ))

        elif func_name == "archivedDataWithRootObject:requiringSecureCoding:error:":
            findings.extend(self._check_archiver(function_sig, call_site, extracted_info))

        # Check SQLite operations
        elif func_name == "sqlite3_open":
            findings.extend(self._check_sqlite_open(function_sig, call_site, extracted_info))

        elif func_name == "sqlite3_exec":
            findings.append(SecurityFinding(
                severity=Severity.HIGH,
                issue_type="SQL Injection Risk",
                description="Using sqlite3_exec with direct SQL execution",
                location=call_site.call_instruction_address,
                function_name=func_name,
                evidence={},
                impact="High risk of SQL injection if queries use string concatenation",
                recommendation="Use sqlite3_prepare_v2 with parameterized queries"
            ))

        elif func_name == "sqlite3_prepare_v2":
            findings.extend(self._check_sqlite_prepare(function_sig, call_site, extracted_info))

        return findings

    def _check_userdefaults(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check NSUserDefaults operations for sensitive data storage."""
        findings = []
        params_by_name = {p.name: p for p in extracted_info.parameters}

        # Try to get the key name
        key_param = None
        if "defaultName" in params_by_name:
            key_param = params_by_name["defaultName"]
        elif "forKey" in params_by_name:
            key_param = params_by_name["forKey"]

        # Check if key has a string value we can analyze
        key_value = None
        if key_param and key_param.value_as_string:
            key_value = key_param.value_as_string
        elif key_param and key_param.value_if_constant is not None:
            key_value = str(key_param.value_if_constant)
        elif key_param and key_param.variable_name:
            key_value = key_param.variable_name

        if key_value:
            key_name = key_value.lower()

            # Check for critical sensitive data
            for pattern in CRITICAL_KEY_PATTERNS:
                if pattern in key_name:
                    findings.append(SecurityFinding(
                        severity=Severity.CRITICAL,
                        issue_type="Critical Data in UserDefaults",
                        description="Storing highly sensitive data '{}' in NSUserDefaults".format(key_value),
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={"key": key_value},
                        impact="NSUserDefaults stores data in plaintext plist files accessible in backups",
                        recommendation="Use Keychain Services for sensitive data storage"
                    ))
                    return findings  # Critical finding supersedes others

            # Check for security policy patterns
            if any(p in key_name for p in SECURITY_POLICY_PATTERNS):
                findings.append(SecurityFinding(
                    severity=Severity.HIGH,
                    issue_type="Security Policy in UserDefaults",
                    description="Storing security policy '{}' in NSUserDefaults".format(key_value),
                    location=call_site.call_instruction_address,
                    function_name=function_sig.name,
                    evidence={"key": key_value},
                    impact="Security policies in UserDefaults can be tampered with",
                    recommendation="Store security policies in code or encrypted storage"
                ))
                return findings

            # Check for other sensitive data
            for pattern in SENSITIVE_KEY_PATTERNS:
                if pattern in key_name:
                    findings.append(SecurityFinding(
                        severity=Severity.HIGH,
                        issue_type="Sensitive Data in UserDefaults",
                        description="Storing sensitive data '{}' in NSUserDefaults".format(key_value),
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={"key": key_value},
                        impact="Sensitive data stored in plaintext plist files",
                        recommendation="Use Keychain Services or encrypted storage"
                    ))
                    break

        # If we can't determine the key, still warn about the pattern
        elif function_sig.name.startswith("set"):
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="UserDefaults Storage",
                description="Storing data in NSUserDefaults (key unknown)",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={},
                impact="NSUserDefaults is not suitable for sensitive data",
                recommendation="Verify no sensitive data is stored"
            ))

        return findings

    def _check_file_write(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check file write operations for security issues."""
        findings = []
        params_by_name = {p.name: p for p in extracted_info.parameters}

        path_param = params_by_name.get("path")
        path_value = None
        if path_param and path_param.value_if_constant is not None:
            path_value = str(path_param.value_if_constant)

        if path_value:
            # Check for world-readable locations
            if "/Documents" in path_value or "/tmp" in path_value or "/Library/Caches" in path_value:
                findings.append(SecurityFinding(
                    severity=Severity.MEDIUM,
                    issue_type="Insecure File Location",
                    description="Writing to potentially accessible location: {}".format(path_value),
                    location=call_site.call_instruction_address,
                    function_name=function_sig.name,
                    evidence={"path": path_value},
                    impact="Files in Documents and Caches are included in backups and may be accessible",
                    recommendation="Use iOS Data Protection and consider encryption"
                ))
            else:
                findings.append(SecurityFinding(
                    severity=Severity.INFO,
                    issue_type="File Write",
                    description="Writing plist file to: {}".format(path_value),
                    location=call_site.call_instruction_address,
                    function_name=function_sig.name,
                    evidence={"path": path_value},
                    impact="Plist files are unencrypted XML/binary format",
                    recommendation="Consider encryption for sensitive data"
                ))

        return findings

    def _check_file_read(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check file read operations for security issues."""
        findings = []
        params_by_name = {p.name: p for p in extracted_info.parameters}

        path_param = params_by_name.get("path")
        path_value = None
        if path_param and path_param.value_if_constant is not None:
            path_value = str(path_param.value_if_constant)

        if path_value:
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="File Read",
                description="Reading from file: {}".format(path_value),
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"path": path_value},
                impact="No integrity verification on file contents",
                recommendation="Verify file integrity if containing sensitive configuration"
            ))

        return findings

    def _check_archiver(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check NSKeyedArchiver secure coding usage."""
        findings = []
        params_by_name = {p.name: p for p in extracted_info.parameters}

        secure_param = params_by_name.get("requiresSecureCoding")
        if secure_param:
            secure_value = self._get_constant_int(secure_param)
            if secure_value == 0:  # NO/false
                findings.append(SecurityFinding(
                    severity=Severity.MEDIUM,
                    issue_type="Insecure Coding Disabled",
                    description="NSKeyedArchiver called with secure coding disabled",
                    location=call_site.call_instruction_address,
                    function_name=function_sig.name,
                    evidence={"requiresSecureCoding": "NO"},
                    impact="Vulnerable to object substitution attacks during deserialization",
                    recommendation="Set requiresSecureCoding to YES"
                ))

        return findings

    def _check_sqlite_open(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check SQLite database operations."""
        findings = []
        params_by_name = {p.name: p for p in extracted_info.parameters}

        filename_param = params_by_name.get("filename")
        path_value = None
        if filename_param and filename_param.value_if_constant is not None:
            path_value = str(filename_param.value_if_constant)

        if path_value:
            # Check for accessible locations
            if "/Documents" in path_value or "/Library/Caches" in path_value:
                findings.append(SecurityFinding(
                    severity=Severity.HIGH,
                    issue_type="Unencrypted Database",
                    description="SQLite database in accessible location: {}".format(path_value),
                    location=call_site.call_instruction_address,
                    function_name=function_sig.name,
                    evidence={"path": path_value},
                    impact="SQLite databases are unencrypted and included in backups",
                    recommendation="Use SQLCipher or Core Data with encryption"
                ))
            else:
                findings.append(SecurityFinding(
                    severity=Severity.MEDIUM,
                    issue_type="Unencrypted Database",
                    description="Opening SQLite database: {}".format(path_value),
                    location=call_site.call_instruction_address,
                    function_name=function_sig.name,
                    evidence={"path": path_value},
                    impact="SQLite stores data unencrypted by default",
                    recommendation="Consider SQLCipher for sensitive data"
                ))

        return findings

    def _check_sqlite_prepare(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check SQLite prepared statement usage."""
        findings = []
        params_by_name = {p.name: p for p in extracted_info.parameters}

        sql_param = params_by_name.get("zSql")
        sql_value = None
        if sql_param and sql_param.value_if_constant is not None:
            sql_value = str(sql_param.value_if_constant)

        if sql_value:
            # Look for string concatenation patterns
            if "||" in sql_value or "+" in sql_value or "%" in sql_value:
                findings.append(SecurityFinding(
                    severity=Severity.HIGH,
                    issue_type="SQL Injection Risk",
                    description="SQL query appears to use string concatenation",
                    location=call_site.call_instruction_address,
                    function_name=function_sig.name,
                    evidence={"sql": sql_value[:200]},  # Truncate long queries
                    impact="String concatenation in SQL queries enables injection attacks",
                    recommendation="Use parameter binding with sqlite3_bind_* functions"
                ))

            # Check for sensitive data references in queries
            sql_lower = sql_value.lower()
            for pattern in CRITICAL_KEY_PATTERNS:
                if pattern in sql_lower:
                    findings.append(SecurityFinding(
                        severity=Severity.MEDIUM,
                        issue_type="Sensitive Data in SQL",
                        description="SQL query references sensitive data: {}".format(pattern),
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={"pattern": pattern},
                        impact="Sensitive data being stored in unencrypted SQLite database",
                        recommendation="Use encrypted storage for sensitive data"
                    ))
                    break

        return findings


__all__ = ["StorageSecurityChecker", "SENSITIVE_KEY_PATTERNS", "CRITICAL_KEY_PATTERNS"]
