# -*- coding: utf-8 -*-
"""
TLS delegate security checks for Trellis (Ghidra port).

Detects insecure URLSession delegate implementations that bypass
certificate validation, unconditionally accept all TLS challenges,
or fail to properly evaluate server trust.
"""

from .security_checks import SecurityChecker, SecurityFinding, Severity

# NSURLSessionAuthChallengeDisposition values
AUTH_CHALLENGE_USE_CREDENTIAL = 0       # Accept the credential (DANGEROUS if unconditional)
AUTH_CHALLENGE_PERFORM_DEFAULT = 1      # Use default handling (safe)
AUTH_CHALLENGE_CANCEL = 2               # Cancel authentication (safe)
AUTH_CHALLENGE_REJECT_PROTECTION = 3    # Reject and try next method

DISPOSITION_NAMES = {
    0: "UseCredential (ACCEPT)",
    1: "PerformDefaultHandling (SAFE)",
    2: "CancelAuthenticationChallenge",
    3: "RejectProtectionSpace",
}

# ObjC method name patterns for TLS delegates
TLS_DELEGATE_PATTERNS = [
    "URLSession:didReceiveChallenge:completionHandler:",
    "URLSession:task:didReceiveChallenge:completionHandler:",
    "connection:willSendRequestForAuthenticationChallenge:",
]

# Functions that should be called for proper trust evaluation
TRUST_EVALUATION_FUNCTIONS = {
    "SecTrustEvaluate",
    "SecTrustEvaluateWithError",
    "SecTrustEvaluateAsync",
    "SecTrustEvaluateAsyncWithError",
}

# Functions indicating certificate pinning
CERT_PINNING_FUNCTIONS = {
    "SecCertificateCopyData",
    "SecTrustCopyCertificateChain",
    "SecTrustGetCertificateAtIndex",
    "SecCertificateCopySubjectSummary",
}

# Patterns indicating debug/development build conditional checks.
# These are RUNTIME checks that return different values in debug vs release builds.
# If the certificate bypass is guarded by these, the code path may be unreachable in release.
#
# IMPORTANT: The code still EXISTS in the release binary, but won't EXECUTE because
# these runtime checks return false in release builds.
DEBUG_CONDITIONAL_PATTERNS = [
    # Swift debug configuration - returns false in release builds
    # This is the most reliable indicator of a debug-only code path
    "_isDebugAssertConfiguration",
    "isDebugAssertConfiguration",
    
    # Common runtime debug flag checks
    "isDebug",
    "debugMode",
    "debug_mode",
    "isDebugBuild",
    "debugEnabled",
    
    # Build configuration property checks
    "buildConfiguration",
    "BuildConfiguration.debug",
    
    # Preprocessor-style that may appear as string literals
    "DEBUG",
    "_DEBUG",
]


class TLSDelegateSecurityChecker(SecurityChecker):
    """Security checker for URLSession/NSURLConnection TLS delegate implementations."""

    def check_call_site(self, function_sig, call_site, extracted_info):
        """Standard call site check - delegates to specific checks."""
        findings = []
        func_name = function_sig.name

        # For delegate methods found as symbols, analyze their implementation
        for pattern in TLS_DELEGATE_PATTERNS:
            if pattern in func_name:
                findings.extend(self._analyze_delegate_implementation(
                    function_sig, call_site
                ))
                break

        # Also check for trust evaluation functions being called
        if func_name in TRUST_EVALUATION_FUNCTIONS:
            findings.extend(self._check_trust_evaluation_call(
                function_sig, call_site, extracted_info
            ))

        return findings

    def check_delegate_implementations(self):
        """
        Scan the entire binary for TLS delegate implementations.

        This is the primary analysis method - it searches for all ObjC methods
        matching delegate patterns and analyzes their implementations.

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        # Search all functions for delegate method patterns
        for func in self.program.get_all_functions():
            func_name = func.name

            # Skip block_invoke functions - they're analyzed as part of their parent delegate
            # via decompilation which includes dispatched blocks
            if '_block_invoke' in func_name:
                continue

            # Check if function name matches any delegate pattern
            for pattern in TLS_DELEGATE_PATTERNS:
                if pattern in func_name:
                    findings.extend(self._analyze_delegate_method(func, pattern))
                    break

        return findings

    def _analyze_delegate_implementation(self, function_sig, call_site):
        """Analyze a delegate implementation from call site."""
        findings = []

        # Try to get the function containing or at the call site.
        # For ObjC selector matches, call_site.caller_address is the
        # containing function; for regular imports, the call instruction
        # references the delegate implementation.
        func = None
        if call_site:
            func = self.program.get_function_at(call_site.caller_address)
            if func is None:
                func = self.program.get_function_containing(
                    call_site.call_instruction_address
                )
        if func is None:
            return findings

        for pattern in TLS_DELEGATE_PATTERNS:
            if pattern in func.name:
                findings.extend(self._analyze_delegate_method(func, pattern))
                break

        return findings

    def _analyze_delegate_method(self, func, pattern):
        """
        Analyze a delegate method implementation for security issues.

        Args:
            func: GhidraFunction object
            pattern: The delegate pattern that matched
        """
        findings = []
        func_name = func.name

        # Check if this is a legacy NSURLConnection delegate
        if "willSendRequestForAuthenticationChallenge" in pattern:
            findings.append(SecurityFinding(
                severity=Severity.MEDIUM,
                issue_type="Legacy NSURLConnection Delegate",
                description="Legacy NSURLConnection authentication delegate found",
                location=func.address,
                function_name=func_name,
                evidence={
                    "method": func_name,
                    "pattern": pattern,
                },
                impact="NSURLConnection is deprecated; legacy delegates may lack modern security",
                recommendation="Migrate to URLSession with proper delegate implementation"
            ))

        # Try to decompile and analyze
        try:
            decomp_text = self.program.get_decompiled_code(func)
            if decomp_text is None:
                findings.append(SecurityFinding(
                    severity=Severity.HIGH,
                    issue_type="TLS Delegate (Unanalyzable)",
                    description="TLS delegate method found but decompilation unavailable",
                    location=func.address,
                    function_name=func_name,
                    evidence={"method": func_name, "reason": "Decompilation not available"},
                    impact="Cannot verify if certificate validation is performed correctly",
                    recommendation="Manual review required"
                ))
                return findings
        except Exception:
            return findings

        # Analyze decompiled code for key patterns
        
        calls_trust_eval = False
        calls_cert_pinning = False
        has_conditional_logic = False
        uses_deprecated_api = False
        has_debug_guard = False
        debug_guard_evidence = []

        # Check for trust evaluation calls
        if "SecTrustEvaluateWithError" in decomp_text:
            calls_trust_eval = True
        elif "SecTrustEvaluateAsync" in decomp_text:
            calls_trust_eval = True
        elif "SecTrustEvaluate" in decomp_text:
            calls_trust_eval = True
            uses_deprecated_api = True

        # Check for cert pinning calls
        for pin_func in CERT_PINNING_FUNCTIONS:
            if pin_func in decomp_text:
                calls_cert_pinning = True

        # Check for conditional logic
        if " if " in decomp_text or " if(" in decomp_text:
            has_conditional_logic = True
        if "switch" in decomp_text:
            has_conditional_logic = True

        # Check for debug conditional guards in the code
        # If the bypass is behind a debug-conditional branch, the code path
        # may be unreachable in release builds (even though the code exists)
        for debug_pattern in DEBUG_CONDITIONAL_PATTERNS:
            if debug_pattern in decomp_text or debug_pattern.lower() in decomp_text.lower():
                has_debug_guard = True
                debug_guard_evidence.append(debug_pattern)
        
        # Follow block_invoke dispatches from this delegate
        # iOS TLS delegates often dispatch validation to block_invoke functions
        analyzed_blocks = set()
        result = self._analyze_dispatched_blocks(
            func, func_name, analyzed_blocks
        )
        if result:
            # Update flags based on what we found in dispatched blocks
            calls_trust_eval = calls_trust_eval or result['calls_trust_eval']
            calls_cert_pinning = calls_cert_pinning or result['calls_cert_pinning']
            has_conditional_logic = has_conditional_logic or result['has_conditional']
            uses_deprecated_api = uses_deprecated_api or result['uses_deprecated']

        # If uses deprecated SecTrustEvaluate instead of SecTrustEvaluateWithError
        if uses_deprecated_api:
            findings.append(SecurityFinding(
                severity=Severity.MEDIUM,
                issue_type="Deprecated Trust Evaluation API",
                description="TLS delegate uses deprecated SecTrustEvaluate instead of SecTrustEvaluateWithError",
                location=func.address,
                function_name=func_name,
                evidence={
                    "method": func_name,
                    "deprecated_api": "SecTrustEvaluate",
                    "recommended": "SecTrustEvaluateWithError"
                },
                impact="Deprecated API may lack modern security features",
                recommendation="Use SecTrustEvaluateWithError for better error handling"
            ))

        # If no certificate pinning
        if not calls_cert_pinning:
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="No Certificate Pinning in TLS Delegate",
                description="TLS delegate does not perform certificate pinning",
                location=func.address,
                function_name=func_name,
                evidence={
                    "method": func_name,
                    "missing": "SecCertificateCopyData / certificate comparison",
                },
                impact="Without pinning, a CA-issued rogue certificate could be accepted",
                recommendation="Consider implementing certificate pinning for sensitive connections"
            ))

        # Check for unconditional trust
        if not has_conditional_logic and not calls_trust_eval:
            # No conditionals at all - always accepts certificates
            findings.append(SecurityFinding(
                severity=Severity.CRITICAL,
                issue_type="Unconditional TLS Trust",
                description="TLS delegate unconditionally accepts all certificates without any conditional checks",
                location=func.address,
                function_name=func_name,
                evidence={
                    "method": func_name,
                    "trust_evaluation": "NONE",
                    "conditional_logic": "NONE",
                },
                impact="All TLS certificates are accepted without validation - trivial MitM",
                recommendation="Implement proper SecTrustEvaluateWithError and check result"
            ))
        elif has_conditional_logic and not calls_trust_eval:
            # Has conditionals but no trust evaluation - check if debug-guarded
            if has_debug_guard:
                # Code path appears guarded by debug conditionals
                # The bypass code EXISTS in the binary but may not EXECUTE in release
                findings.append(SecurityFinding(
                    severity=Severity.LOW,
                    issue_type="Debug-Guarded TLS Trust Bypass",
                    description="TLS delegate bypasses validation but code path appears guarded by debug conditional",
                    location=func.address,
                    function_name=func_name,
                    evidence={
                        "method": func_name,
                        "trust_evaluation": "NONE",
                        "debug_conditionals_found": debug_guard_evidence[:5],
                        "note": "Code exists in binary but may not execute in release builds",
                    },
                    impact="Bypass code is present but likely unreachable in release builds due to debug conditional",
                    recommendation="Verify with runtime testing that bypass is not reachable in release; prefer compile-time #if DEBUG to exclude code entirely"
                ))
            else:
                # Has conditionals but they don't appear to be debug-related
                findings.append(SecurityFinding(
                    severity=Severity.HIGH,
                    issue_type="Conditional TLS Trust Bypass",
                    description="TLS delegate has conditional logic but no trust evaluation - bypass may be reachable",
                    location=func.address,
                    function_name=func_name,
                    evidence={
                        "method": func_name,
                        "trust_evaluation": "NONE",
                        "has_conditional": True,
                        "debug_guard": "NOT DETECTED",
                    },
                    impact="Certificate validation bypass may be reachable under certain conditions",
                    recommendation="Review the conditional logic; implement proper SecTrustEvaluateWithError"
                ))

        return findings

    def _check_trust_evaluation_call(self, function_sig, call_site, extracted_info):
        """Check calls to trust evaluation functions."""
        findings = []
        func_name = function_sig.name

        # Check if using deprecated API
        if func_name == "SecTrustEvaluate":
            findings.append(SecurityFinding(
                severity=Severity.LOW,
                issue_type="Deprecated Trust Evaluation",
                description="Using deprecated SecTrustEvaluate API",
                location=call_site.call_instruction_address,
                function_name=func_name,
                evidence={
                    "api": "SecTrustEvaluate",
                    "recommended": "SecTrustEvaluateWithError"
                },
                impact="Deprecated API may lack modern security features",
                recommendation="Use SecTrustEvaluateWithError (iOS 12+) for better error handling"
            ))

        return findings
    
    def _analyze_dispatched_blocks(self, func, func_name, analyzed_blocks):
        """
        Follow block callbacks dispatched from this delegate method.
        
        iOS TLS delegates often dispatch validation to block_invoke functions:
          URLSession:didReceiveChallenge:completionHandler: (delegate)
            └─> ___78-[Class URLSession:...]_block_invoke
                └─> SecTrustEvaluate (actual validation here)
        
        This method searches for block_invoke functions whose names reference
        the delegate method and analyzes them for trust evaluation calls.
        
        Args:
            func: GhidraFunction of the delegate
            func_name: Name of the delegate function
            analyzed_blocks: Set of already-analyzed block addresses
            
        Returns:
            Dictionary with keys: calls_trust_eval, calls_cert_pinning, 
            has_conditional, uses_deprecated (all booleans), or None if no blocks found
        """
        # Extract the class and method name components for matching
        # e.g., "-[GULNetworkURLSession URLSession:task:didReceiveChallenge:completionHandler:]"
        # would match "GULNetworkURLSession" and "didReceiveChallenge"
        class_name = None
        method_keywords = []
        
        if func_name.startswith('-[') or func_name.startswith('+['):
            # Parse Objective-C method name
            bracket_end = func_name.find(']')
            if bracket_end > 2:
                inner = func_name[2:bracket_end]
                space_idx = inner.find(' ')
                if space_idx > 0:
                    class_name = inner[:space_idx]
                    method_part = inner[space_idx+1:]
                    # Extract keywords from selector
                    for part in method_part.split(':'):
                        if part and len(part) > 3:  # Skip short parts
                            method_keywords.append(part)
        
        if not class_name and not method_keywords:
            return None
        
        # Build search patterns
        block_patterns = []
        if class_name:
            block_patterns.append(class_name)
        for kw in method_keywords:
            if kw.lower() not in ('urlsession', 'task', 'completionhandler'):
                block_patterns.append(kw)
        
        # Track what we find in blocks
        block_calls_trust_eval = False
        block_calls_cert_pinning = False
        block_has_conditional = False
        block_uses_deprecated = False
        found_any_blocks = False
        
        # Search all functions for matching block_invoke patterns
        for block_func in self.program.get_all_functions():
            block_name = block_func.name
            
            # Skip if not a block invoke
            if '_block_invoke' not in block_name:
                continue
            
            # Skip already analyzed blocks (prevent infinite recursion)
            if block_func.address in analyzed_blocks:
                continue
            
            # Check if block name matches our delegate
            matches = False
            for pattern in block_patterns:
                if pattern in block_name:
                    matches = True
                    break
            
            if not matches:
                continue
            
            # Mark as analyzed
            analyzed_blocks.add(block_func.address)
            found_any_blocks = True
            
            # Decompile and analyze this block
            try:
                block_decomp = self.program.get_decompiled_code(block_func)
                if block_decomp is None:
                    continue
                
                # Check for trust evaluation in the block
                if "SecTrustEvaluateWithError" in block_decomp:
                    block_calls_trust_eval = True
                elif "SecTrustEvaluateAsync" in block_decomp:
                    block_calls_trust_eval = True
                elif "SecTrustEvaluate" in block_decomp:
                    block_calls_trust_eval = True
                    block_uses_deprecated = True
                
                # Check for cert pinning in the block
                for pin_func in CERT_PINNING_FUNCTIONS:
                    if pin_func in block_decomp:
                        block_calls_cert_pinning = True
                
                # Check for conditionals in the block
                if " if " in block_decomp or " if(" in block_decomp:
                    block_has_conditional = True
                if "switch" in block_decomp:
                    block_has_conditional = True
                
                # Recursively check blocks dispatched from this block
                nested_result = self._analyze_dispatched_blocks(
                    block_func, block_name, analyzed_blocks
                )
                if nested_result:
                    block_calls_trust_eval = block_calls_trust_eval or nested_result['calls_trust_eval']
                    block_calls_cert_pinning = block_calls_cert_pinning or nested_result['calls_cert_pinning']
                    block_has_conditional = block_has_conditional or nested_result['has_conditional']
                    block_uses_deprecated = block_uses_deprecated or nested_result['uses_deprecated']
                
            except Exception:
                continue
        
        # Return aggregated results
        if found_any_blocks:
            return {
                'calls_trust_eval': block_calls_trust_eval,
                'calls_cert_pinning': block_calls_cert_pinning,
                'has_conditional': block_has_conditional,
                'uses_deprecated': block_uses_deprecated,
            }
        return None

__all__ = ["TLSDelegateSecurityChecker"]
