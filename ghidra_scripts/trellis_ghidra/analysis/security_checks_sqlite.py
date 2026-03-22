"""
SQLite security checks for Trellis (Ghidra Port).

This module implements security analysis for SQLite database operations,
detecting SQL injection vulnerabilities and unencrypted database usage.
"""

from typing import Optional, List, TYPE_CHECKING

from .security_checks import SecurityChecker, SecurityFinding, Severity

if TYPE_CHECKING:
    from ..signatures import FunctionSignature
    from .calltree import CallSite
    from .extractor import ExtractedCallInfo


class SQLiteSecurityChecker(SecurityChecker):
    """Security checker for SQLite operations."""

    def check_call_site(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check a SQLite function call site for security issues."""
        findings = []

        if not extracted_info:
            return findings

        func_name = function_sig.name

        # SQLite3 C API
        if "sqlite3_exec" in func_name:
            findings.extend(self._check_sqlite_exec(function_sig, call_site, extracted_info))

        elif "sqlite3_prepare" in func_name or "sqlite3_prepare_v2" in func_name:
            findings.extend(self._check_sqlite_prepare(function_sig, call_site, extracted_info))

        elif "sqlite3_open" in func_name or "sqlite3_open_v2" in func_name:
            findings.extend(self._check_sqlite_open(function_sig, call_site, extracted_info))

        elif "sqlite3_bind" in func_name:
            findings.extend(self._check_sqlite_bind(function_sig, call_site, extracted_info))

        # FMDB (Objective-C wrapper)
        elif "executeQuery" in func_name or "FMDatabase" in func_name and "Query" in func_name:
            findings.extend(self._check_fmdb_query(function_sig, call_site, extracted_info))

        elif "executeUpdate" in func_name or "FMDatabase" in func_name and "Update" in func_name:
            findings.extend(self._check_fmdb_update(function_sig, call_site, extracted_info))

        # Core Data (which uses SQLite)
        elif "NSPersistentStoreCoordinator" in func_name:
            findings.extend(self._check_core_data(function_sig, call_site, extracted_info))

        # SQLCipher (encrypted SQLite)
        elif "sqlite3_key" in func_name or "sqlcipher" in func_name.lower():
            findings.extend(self._check_sqlcipher(function_sig, call_site, extracted_info))

        # GRDB Swift
        elif "DatabaseQueue" in func_name or "DatabasePool" in func_name:
            findings.extend(self._check_grdb(function_sig, call_site, extracted_info))

        return findings

    def _check_sqlite_exec(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check sqlite3_exec for SQL injection."""
        findings = []

        # sqlite3_exec is dangerous because it executes arbitrary SQL
        findings.append(SecurityFinding(
            severity=Severity.HIGH,
            issue_type="SQLite Direct Execution",
            description="sqlite3_exec used - high risk of SQL injection if query is dynamic",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api": "sqlite3_exec"},
            impact="SQL injection can lead to data theft, modification, or deletion",
            recommendation="Use sqlite3_prepare_v2 with parameterized queries instead"
        ))

        # Check if SQL string is hardcoded vs dynamic
        if extracted_info.parameters and len(extracted_info.parameters) > 1:
            sql_param = extracted_info.parameters[1]  # Second param is SQL string
            if sql_param.value_as_string:
                sql_lower = sql_param.value_as_string.lower()
                if "select" in sql_lower or "insert" in sql_lower or "update" in sql_lower:
                    findings.append(SecurityFinding(
                        severity=Severity.MEDIUM,
                        issue_type="SQL Query Pattern",
                        description="SQL query detected in sqlite3_exec",
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={"sql_fragment": sql_param.value_as_string[:100]},
                        impact="Verify this query doesn't include user input",
                        recommendation="Review query for concatenated user input"
                    ))

        return findings

    def _check_sqlite_prepare(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check sqlite3_prepare for proper usage."""
        findings = []

        # Prepared statements are good, but need to verify bind usage
        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="SQLite Prepared Statement",
            description="sqlite3_prepare_v2 used (safer than sqlite3_exec)",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api": function_sig.name},
            impact="Prepared statements prevent SQL injection when used correctly",
            recommendation="Ensure all dynamic values use sqlite3_bind_* functions"
        ))

        return findings

    def _check_sqlite_open(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check sqlite3_open for database location and encryption."""
        findings = []

        # Check database path
        if extracted_info.parameters:
            path_param = extracted_info.parameters[0]
            if path_param.value_as_string:
                db_path = path_param.value_as_string
                
                # Check for world-readable locations
                if "/tmp" in db_path or "Caches" in db_path:
                    findings.append(SecurityFinding(
                        severity=Severity.MEDIUM,
                        issue_type="SQLite Database in Temp Location",
                        description="Database opened in potentially insecure location",
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={"db_path": db_path},
                        impact="Databases in temp/cache may be accessible to other apps or backed up",
                        recommendation="Store sensitive databases in Documents with proper encryption"
                    ))
                
                # Unencrypted database warning
                findings.append(SecurityFinding(
                    severity=Severity.MEDIUM,
                    issue_type="Unencrypted SQLite Database",
                    description="Standard SQLite database opened (unencrypted)",
                    location=call_site.call_instruction_address,
                    function_name=function_sig.name,
                    evidence={"db_path": db_path},
                    impact="Database contents are readable if device is compromised",
                    recommendation="Consider using SQLCipher for sensitive data"
                ))

        return findings

    def _check_sqlite_bind(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check sqlite3_bind usage."""
        findings = []

        # Bind functions are good - they indicate parameterized queries
        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="SQLite Parameter Binding",
            description="sqlite3_bind_* used for query parameterization",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"api": function_sig.name},
            impact="Parameterized queries prevent SQL injection",
            recommendation="Good practice - continue using parameterized queries"
        ))

        return findings

    def _check_fmdb_query(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check FMDB executeQuery for SQL injection."""
        findings = []

        # Check if using format string (dangerous) vs parameterized
        if extracted_info.parameters:
            for param in extracted_info.parameters:
                if param.value_as_string:
                    sql = param.value_as_string
                    # Look for format specifiers that indicate string interpolation
                    if "%@" in sql or "%s" in sql or "%d" in sql:
                        findings.append(SecurityFinding(
                            severity=Severity.HIGH,
                            issue_type="FMDB Format String Query",
                            description="FMDB query using format specifiers (potential SQL injection)",
                            location=call_site.call_instruction_address,
                            function_name=function_sig.name,
                            evidence={"sql_pattern": sql[:100]},
                            impact="Format string queries can be vulnerable to SQL injection",
                            recommendation="Use executeQuery:withArgumentsInArray: instead"
                        ))
                    # Check for question mark placeholders (good)
                    elif "?" in sql:
                        findings.append(SecurityFinding(
                            severity=Severity.INFO,
                            issue_type="FMDB Parameterized Query",
                            description="FMDB query using ? placeholders (safe)",
                            location=call_site.call_instruction_address,
                            function_name=function_sig.name,
                            evidence={"sql_pattern": sql[:100]},
                            impact="Parameterized queries prevent SQL injection",
                            recommendation="Good practice"
                        ))

        return findings

    def _check_fmdb_update(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check FMDB executeUpdate for SQL injection."""
        findings = []

        if extracted_info.parameters:
            for param in extracted_info.parameters:
                if param.value_as_string:
                    sql = param.value_as_string
                    # Format specifiers in UPDATE/INSERT/DELETE are especially dangerous
                    if "%@" in sql or "%s" in sql:
                        findings.append(SecurityFinding(
                            severity=Severity.CRITICAL,
                            issue_type="FMDB Unsafe Update Statement",
                            description="FMDB update using format specifiers (SQL injection risk)",
                            location=call_site.call_instruction_address,
                            function_name=function_sig.name,
                            evidence={"sql_pattern": sql[:100]},
                            impact="SQL injection in UPDATE/INSERT/DELETE can modify or destroy data",
                            recommendation="Use executeUpdate:withArgumentsInArray: with ? placeholders"
                        ))

        return findings

    def _check_core_data(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check Core Data configuration."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="Core Data Usage",
            description="Core Data persistent store coordinator detected",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"framework": "Core Data"},
            impact="Core Data uses SQLite by default (unencrypted)",
            recommendation="Consider NSFileProtection or encrypted persistent store"
        ))

        return findings

    def _check_sqlcipher(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check SQLCipher usage."""
        findings = []

        # Check for hardcoded encryption key
        if "sqlite3_key" in function_sig.name and extracted_info.parameters:
            for param in extracted_info.parameters:
                if param.value_as_string:
                    findings.append(SecurityFinding(
                        severity=Severity.CRITICAL,
                        issue_type="Hardcoded SQLCipher Key",
                        description="SQLCipher encryption key appears to be hardcoded",
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={"key_visible": True},
                        impact="Hardcoded keys can be extracted from the binary",
                        recommendation="Derive encryption key from Keychain or user input"
                    ))
                    break

        if not findings:
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="SQLCipher Encryption",
                description="SQLCipher encrypted database detected",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"encryption": "SQLCipher"},
                impact="Database contents are encrypted at rest",
                recommendation="Ensure key is derived securely (not hardcoded)"
            ))

        return findings

    def _check_grdb(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check GRDB Swift SQLite wrapper."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="GRDB Swift SQLite",
            description="GRDB Swift SQLite library detected",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"library": "GRDB"},
            impact="GRDB provides type-safe query building",
            recommendation="Verify encryption is enabled for sensitive data"
        ))

        return findings


__all__ = ["SQLiteSecurityChecker"]
