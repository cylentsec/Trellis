"""
WebView JavaScript bridge security checks for Trellis (Ghidra Port).

Detects WKScriptMessageHandler implementations that expose native APIs
to JavaScript, WKURLSchemeHandler implementations that may allow file
access, and evaluateJavaScript calls that inject code into web content.
"""

from typing import Optional, List, TYPE_CHECKING

from .security_checks import SecurityChecker, SecurityFinding, Severity

if TYPE_CHECKING:
    from ..signatures import FunctionSignature
    from .calltree import CallSite
    from .extractor import ExtractedCallInfo


# Functions indicating sensitive operations within a JS bridge handler
SENSITIVE_URL_FUNCTIONS = {
    "openURL:", "openURL:options:completionHandler:",
    "loadRequest:", "loadHTMLString:baseURL:",
    "loadFileURL:allowingReadAccessToURL:",
}

SENSITIVE_FILE_FUNCTIONS = {
    "contentsOfFile:", "contentsAtPath:", "fileExistsAtPath:",
    "createFileAtPath:", "moveItemAtPath:", "copyItemAtPath:",
    "fopen", "open", "NSData initWithContentsOfFile:",
    "NSString initWithContentsOfFile:",
    "stringWithContentsOfFile:encoding:error:",
    "dataWithContentsOfFile:",
}

SENSITIVE_AUTH_FUNCTIONS = {
    "SecItemAdd", "SecItemCopyMatching", "SecItemUpdate",
    "SecItemDelete",
    "initWithUser:password:", "credentialWithUser:password:",
}

SENSITIVE_NETWORK_FUNCTIONS = {
    "dataTaskWithRequest:", "dataTaskWithURL:",
    "downloadTaskWithRequest:", "uploadTaskWithRequest:",
    "sendSynchronousRequest:", "sendAsynchronousRequest:",
}

# Known patterns for path traversal protection
PATH_SANITIZATION_FUNCTIONS = {
    "stringByStandardizingPath",
    "stringByResolvingSymlinksInPath",
    "hasPrefix:",
    "pathComponents",
    "lastPathComponent",
    "URLByStandardizingPath",
    "standardizedURL",
}


# User input selectors that indicate taint sources
_USER_INPUT_SELECTORS = {
    'text', 'getText', 'textField', 'nameTextField',
    'passwordTextField', 'inputTextField', 'searchTextField',
    'UITextField', 'UITextView', 'editingChanged',
}


class WebViewSecurityChecker(SecurityChecker):
    """Security checker for WebView JavaScript bridge attack surface."""

    def check_call_site(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check a WebView-related function call site."""
        findings = []
        func_name = function_sig.name

        if "addScriptMessageHandler" in func_name and "name:" in func_name:
            findings.extend(self._check_handler_registration(
                function_sig, call_site, extracted_info
            ))
        elif func_name == "evaluateJavaScript:completionHandler:":
            findings.extend(self._check_evaluate_javascript(
                function_sig, call_site, extracted_info
            ))
        elif "callAsyncJavaScript" in func_name:
            findings.extend(self._check_async_javascript(
                function_sig, call_site, extracted_info
            ))
        elif func_name == "addUserScript:":
            findings.extend(self._check_user_script(
                function_sig, call_site, extracted_info
            ))
        elif "startURLSchemeTask" in func_name:
            findings.extend(self._check_url_scheme_task(
                function_sig, call_site, extracted_info
            ))
        elif "decidePolicyForNavigationAction" in func_name:
            findings.extend(self._check_navigation_policy(
                function_sig, call_site, extracted_info
            ))
        # Check for handler implementation methods
        elif "userContentController" in func_name and "didReceiveScriptMessage" in func_name:
            findings.extend(self._check_message_handler_impl(
                function_sig, call_site, extracted_info
            ))
        # loadHTMLString:baseURL: (XSS risk with nil baseURL)
        elif "loadHTMLString" in func_name:
            findings.extend(self._check_load_html_string(
                function_sig, call_site, extracted_info
            ))
        # loadRequest: (WebView loading external content)
        elif func_name == "loadRequest:":
            findings.extend(self._check_load_request(
                function_sig, call_site, extracted_info
            ))

        return findings

    def _check_handler_registration(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check addScriptMessageHandler:name: registration."""
        findings = []
        handler_name = None

        # Try to extract the handler name from parameters
        if extracted_info and extracted_info.parameters:
            for param in extracted_info.parameters:
                if param.value_if_constant is not None:
                    # Could be the handler name
                    handler_name = str(param.value_if_constant)
                    break

        desc = "JavaScript message handler registered"
        if handler_name:
            desc = "JavaScript message handler '{}' registered".format(handler_name)

        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="JS Bridge Handler Registration",
            description=desc,
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={
                "handler_name": handler_name or "<unknown>",
                "method": function_sig.name,
            },
            impact="Exposes native functionality to JavaScript via window.webkit.messageHandlers",
            recommendation="Review handler implementation for sensitive operations"
        ))

        return findings

    def _check_evaluate_javascript(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check evaluateJavaScript:completionHandler: calls."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.MEDIUM,
            issue_type="Native-to-JS Code Injection",
            description="evaluateJavaScript called from native code",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"method": "evaluateJavaScript:completionHandler:"},
            impact="Native code injects JavaScript into web content - verify input is sanitized",
            recommendation="Ensure JavaScript strings are not constructed from untrusted input"
        ))

        return findings

    def _check_async_javascript(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check callAsyncJavaScript calls."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.MEDIUM,
            issue_type="Native-to-JS Async Execution",
            description="callAsyncJavaScript called from native code",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"method": function_sig.name},
            impact="Native code executes async JavaScript in web content",
            recommendation="Verify arguments parameter doesn't contain sensitive data"
        ))

        return findings

    def _check_user_script(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check addUserScript: calls."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="WebView Script Injection",
            description="User script injected into WKWebView content",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"method": "addUserScript:"},
            impact="Script runs in all loaded web pages - check if it exposes sensitive APIs",
            recommendation="Review injected script content for security implications"
        ))

        return findings

    def _check_url_scheme_task(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check webView:startURLSchemeTask: call sites."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.HIGH,
            issue_type="Custom URL Scheme Handler",
            description="WKURLSchemeHandler processes custom URL scheme requests",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"method": "webView:startURLSchemeTask:"},
            impact="Custom scheme handler may allow file access or data exfiltration from JS",
            recommendation="Verify URL path is sanitized against path traversal (../ attacks)"
        ))

        return findings

    def _check_navigation_policy(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check decidePolicyForNavigationAction delegate."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="WebView Navigation Policy",
            description="Navigation policy delegate implemented",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"method": function_sig.name},
            impact="Controls which URLs the WebView can navigate to",
            recommendation="Verify allowlist prevents navigation to malicious URLs"
        ))

        return findings

    def _check_message_handler_impl(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check WKScriptMessageHandler implementation."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.HIGH,
            issue_type="JS Bridge Handler Implementation",
            description="WebView message handler implementation found",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={
                "handler_type": "WKScriptMessageHandler",
                "method": function_sig.name,
            },
            impact="JavaScript in WebView can call this native method",
            recommendation="Review for sensitive operations (URL opening, file access, auth)"
        ))

        return findings

    def _check_load_html_string(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check loadHTMLString:baseURL: for XSS risk."""
        findings = []

        # Try to detect nil baseURL (second method parameter)
        base_url_is_nil = False
        if extracted_info and extracted_info.parameters:
            params = extracted_info.parameters
            if len(params) > 1:
                try:
                    if self._is_null_pointer(params[1]):
                        base_url_is_nil = True
                except (AttributeError, TypeError):
                    pass

        # Check for user-input taint: does the caller also reference UITextField?
        has_user_input = self._caller_has_user_input_ref(call_site)

        if has_user_input:
            findings.append(SecurityFinding(
                severity=Severity.HIGH,
                issue_type="XSS via User Input in loadHTMLString",
                description="loadHTMLString:baseURL: caller also references user input "
                            "(UITextField/UITextView) — XSS likely",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={
                    "method": "loadHTMLString:baseURL:",
                    "baseURL": "nil" if base_url_is_nil else "unknown",
                    "taint_source": "UITextField/UITextView reference in caller",
                },
                impact="User input flows to WebView HTML rendering without sanitization — "
                       "attacker can inject JavaScript via text fields",
                recommendation="Sanitize all user input before HTML rendering; "
                               "use textContent instead of innerHTML equivalents"
            ))
        elif base_url_is_nil:
            findings.append(SecurityFinding(
                severity=Severity.HIGH,
                issue_type="loadHTMLString with nil baseURL",
                description="loadHTMLString:baseURL: called with nil baseURL - XSS risk",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"method": "loadHTMLString:baseURL:", "baseURL": "nil"},
                impact="Loading HTML with nil baseURL allows JavaScript to access local resources",
                recommendation="Provide a restrictive baseURL or sanitize all HTML input"
            ))
        else:
            findings.append(SecurityFinding(
                severity=Severity.MEDIUM,
                issue_type="Dynamic HTML Loading",
                description="loadHTMLString:baseURL: loading HTML content dynamically",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"method": "loadHTMLString:baseURL:"},
                impact="If HTML content includes untrusted input, XSS is possible",
                recommendation="Sanitize HTML input and set a restrictive baseURL"
            ))

        return findings

    def _caller_has_user_input_ref(self, call_site):
        """
        Check if the caller function references UITextField/UITextView
        or other user-input selectors, indicating a taint source.
        """
        if not call_site:
            return False

        caller_name = call_site.caller_name or ""

        # Check caller name for text field references
        lower = caller_name.lower()
        for sel in _USER_INPUT_SELECTORS:
            if sel.lower() in lower:
                return True

        # Try decompiling the caller to look for UITextField references
        try:
            func = self.program.get_function_containing(
                call_site.call_instruction_address
            )
            if func:
                decomp = self.program.get_decompiled_code(func)
                if decomp:
                    for sel in ('UITextField', 'UITextView', 'textField',
                                'nameTextField', 'text()'):
                        if sel in decomp:
                            return True
        except Exception:
            pass

        return False

    def _check_load_request(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check loadRequest: for potential issues."""
        findings = []

        findings.append(SecurityFinding(
            severity=Severity.MEDIUM,
            issue_type="WebView Load Request",
            description="WebView loading URL request via loadRequest:",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"method": "loadRequest:"},
            impact="WebView loading external content - verify HTTPS and content validation",
            recommendation="Use HTTPS for all loaded URLs and implement WKNavigationDelegate"
        ))

        return findings


    def scan_uiwebview_deprecation(self):
        """
        Standalone scan for deprecated UIWebView usage.

        Searches the binary's string table and symbol table for UIWebView
        class references. UIWebView is deprecated since iOS 12 and has
        severe security limitations (no JS disable, no same-origin policy).

        Returns:
            List of SecurityFinding objects.
        """
        findings = []
        seen = False

        for address, string_value in self.program.get_defined_strings():
            if 'UIWebView' in string_value and not seen:
                seen = True
                findings.append(SecurityFinding(
                    severity=Severity.HIGH,
                    issue_type="Deprecated UIWebView Usage",
                    description="UIWebView class reference found — deprecated since iOS 12",
                    location=address,
                    function_name="<string_table>",
                    evidence={
                        "class": "UIWebView",
                        "string_context": string_value[:80],
                    },
                    impact="UIWebView cannot disable JavaScript, has no same-origin policy, "
                           "and no out-of-process rendering. Memory corruption bugs in "
                           "JavaScriptCore affect the main app process.",
                    recommendation="Migrate to WKWebView or SFSafariViewController"
                ))

        return findings


__all__ = ["WebViewSecurityChecker"]
