"""
Deep link security checks for Trellis (Ghidra Port).

This module implements security analysis for deep link handling and URL schemes,
detecting potential injection vulnerabilities, missing source validation, and
dangerous URL destinations like WebViews or file operations.
"""

from typing import Optional, List, TYPE_CHECKING

from .security_checks import SecurityChecker, SecurityFinding, Severity

if TYPE_CHECKING:
    from ..signatures import FunctionSignature
    from .calltree import CallSite
    from .extractor import ExtractedCallInfo


# Deep link delegate method patterns
DEEPLINK_DELEGATE_PATTERNS = [
    "application:openURL:options:",
    "application:handleOpenURL:",
    "application:continueUserActivity:restorationHandler:",
    "scene:openURLContexts:",
    "scene:continueUserActivity:",
]

# Functions that could be dangerous if URL data flows into them
DANGEROUS_URL_DESTINATIONS = {
    # WebView loading functions
    "loadRequest:", "loadHTMLString:baseURL:", "loadFileURL:",
    "loadFileURL:allowingReadAccessToURL:", "loadData:MIMEType:textEncodingName:baseURL:",
    # JavaScript execution
    "evaluateJavaScript:", "evaluateJavaScript:completionHandler:",
    "stringByEvaluatingJavaScriptFromString:",
}

# File access functions that could be abused with file:// URLs
FILE_ACCESS_FUNCTIONS = {
    # NSFileManager
    "contentsOfFile:", "fileExistsAtPath:", "contentsAtPath:",
    "createFileAtPath:contents:attributes:", "removeItemAtPath:",
    "copyItemAtPath:toPath:", "moveItemAtPath:toPath:",
    # NSData
    "dataWithContentsOfFile:", "initWithContentsOfFile:",
    "writeToFile:atomically:", "writeToFile:options:error:",
    # NSString
    "stringWithContentsOfFile:", "initWithContentsOfFile:",
    "writeToFile:atomically:encoding:error:",
    # C functions
    "fopen", "open", "access", "stat", "unlink",
}

# Database/query functions that could lead to SQL injection
DATABASE_FUNCTIONS = {
    # SQLite
    "sqlite3_prepare", "sqlite3_prepare_v2", "sqlite3_prepare_v3",
    "sqlite3_exec", "sqlite3_get_table",
    # NSPredicate
    "predicateWithFormat:", "predicateWithFormat:arguments:",
}


class DeepLinkSecurityChecker(SecurityChecker):
    """Security checker for deep link and URL scheme handling."""

    def check_call_site(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check a deep link function call site for security issues."""
        findings = []

        func_name = function_sig.name

        # Check for deep link entry points
        if func_name in ["application:openURL:options:", "scene:openURLContexts:"]:
            findings.append(SecurityFinding(
                severity=Severity.MEDIUM,
                issue_type="Deep Link Entry Point",
                description="Deep link handler found: {}".format(func_name),
                location=call_site.call_instruction_address,
                function_name=func_name,
                evidence={
                    "handler": func_name,
                    "modern_api": True,
                    "dangerous_destinations": ", ".join(sorted(DANGEROUS_URL_DESTINATIONS)[:5]) + "...",
                },
                impact="Deep link handlers receive untrusted URL input from other apps. "
                       "If URL data flows into WebView loading, JavaScript execution, or file operations, "
                       "it can lead to XSS, local file access, or code injection.",
                recommendation="Validate URL scheme, host, and all parameters. Never pass URL data directly "
                               "to loadHTMLString, evaluateJavaScript, or file I/O functions."
            ))

        elif func_name == "application:handleOpenURL:":
            findings.append(SecurityFinding(
                severity=Severity.MEDIUM,
                issue_type="Deprecated Deep Link Handler",
                description="Using deprecated deep link handler without source validation",
                location=call_site.call_instruction_address,
                function_name=func_name,
                evidence={
                    "handler": func_name,
                    "deprecated": True,
                    "dangerous_destinations": ", ".join(sorted(DANGEROUS_URL_DESTINATIONS)[:5]) + "...",
                },
                impact="Cannot validate source application with this deprecated API. "
                       "URL data may flow into dangerous functions like WebView or file operations.",
                recommendation="Migrate to application:openURL:options: for source validation. "
                               "Never pass URL parameters to loadHTMLString or evaluateJavaScript."
            ))

        elif func_name in ["application:continueUserActivity:restorationHandler:", "scene:continueUserActivity:"]:
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="Universal Links Handler",
                description="Universal Links handler found: {}".format(func_name),
                location=call_site.call_instruction_address,
                function_name=func_name,
                evidence={
                    "handler": func_name,
                    "type": "Universal Links",
                },
                impact="Handles Universal Links. Ensure domain validation.",
                recommendation="Verify userActivity.webpageURL matches expected domains."
            ))

        # Check for URL scheme checking
        elif func_name == "canOpenURL:":
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="URL Scheme Check",
                description="App checks if URL schemes are available",
                location=call_site.call_instruction_address,
                function_name=func_name,
                evidence={
                    "function": func_name,
                    "purpose": "scheme_detection",
                },
                impact="Can be used for app detection or jailbreak checks.",
                recommendation="Ensure LSApplicationQueriesSchemes is properly configured."
            ))

        # Check for opening external URLs
        elif func_name in ["openURL:options:completionHandler:", "openURL:"]:
            findings.append(SecurityFinding(
                severity=Severity.MEDIUM,
                issue_type="External URL Opening",
                description="App opens external URLs",
                location=call_site.call_instruction_address,
                function_name=func_name,
                evidence={
                    "function": func_name,
                    "can_launch_apps": True,
                },
                impact="Can launch other apps or open web content.",
                recommendation="Validate URL schemes before opening. Consider user confirmation."
            ))

        # Check for SwiftUI onOpenURL
        elif "onOpenURL" in func_name:
            findings.append(SecurityFinding(
                severity=Severity.MEDIUM,
                issue_type="SwiftUI Deep Link Handler",
                description="SwiftUI onOpenURL modifier found - URL input is untrusted",
                location=call_site.call_instruction_address,
                function_name=func_name,
                evidence={
                    "handler": func_name,
                    "framework": "SwiftUI",
                    "dangerous_destinations": ", ".join(sorted(DANGEROUS_URL_DESTINATIONS)[:5]) + "...",
                },
                impact="SwiftUI deep link handlers receive untrusted URL data. "
                       "If URL components flow into WebView, JavaScript, or file operations, "
                       "it enables XSS or local file access attacks.",
                recommendation="Validate URL scheme, host, and parameters before use. "
                               "Do not pass URL data directly to loadHTMLString, evaluateJavaScript, or file I/O."
            ))

        return findings


__all__ = ["DeepLinkSecurityChecker"]
