"""
String-table security checks for Trellis (Ghidra Port).

This module performs a pass over the binary's defined string table to find
hardcoded credentials, API keys, HTTP URLs, and other sensitive string
literals. Unlike call-site checkers, this module does NOT require
decompiler/parameter extraction — it works purely on string data, making
it effective for Swift binaries where parameter extraction often fails.
"""

import re
from typing import List, Set, TYPE_CHECKING

from .security_checks import SecurityChecker, SecurityFinding, Severity

if TYPE_CHECKING:
    from ..ghidra_api import GhidraProgram
    from ..signatures import FunctionSignature
    from .calltree import CallSite
    from .extractor import ExtractedCallInfo


# =========================================================================
# Patterns for hardcoded credentials and secrets
# =========================================================================

# Regex patterns for API key formats (high-entropy hex/base64 strings)
API_KEY_PATTERNS = [
    # Generic API key in key=value format
    re.compile(r'(?:api[_-]?key|apikey|api[_-]?secret|app[_-]?key|app[_-]?secret|auth[_-]?token|access[_-]?token|client[_-]?secret)\s*[:=]\s*["\']?([A-Za-z0-9+/=_-]{16,})', re.IGNORECASE),
    # AWS-style keys
    re.compile(r'AKIA[0-9A-Z]{16}'),
    # Generic long hex strings that look like keys (32+ hex chars)
    re.compile(r'^[0-9a-fA-F]{32,}$'),
]

# Keywords that suggest a string IS a password or secret value
# (vs. just containing the word "password" in a UI label)
SECRET_VALUE_INDICATORS = [
    # Strings that look like they're actual password values (not labels)
    re.compile(r'^[@#$%^&*!a-zA-Z0-9]{8,}$'),  # Looks like a password
]

# String patterns that indicate hardcoded credentials near crypto operations
HARDCODED_PASSWORD_PATTERNS = [
    # Strings used as encryption passwords (high entropy, special chars)
    re.compile(r'^[@#$%&!][a-zA-Z0-9@#$%&!]{10,}$'),
]

# HTTP URL patterns (non-HTTPS)
HTTP_URL_PATTERN = re.compile(r'^https?://', re.IGNORECASE)
HTTP_ONLY_PATTERN = re.compile(r'^http://', re.IGNORECASE)

# Sensitive URL path patterns
SENSITIVE_URL_PATHS = [
    '/api/', '/auth/', '/login/', '/token/', '/oauth/',
    '/password/', '/payment/', '/checkout/', '/card/',
    '/billing/', '/account/', '/admin/', '/user/',
    '/register/', '/signup/', '/session/',
]

# Strings that are likely UI labels, not secrets (false positive filters)
UI_LABEL_INDICATORS = [
    'enter your', 'please enter', 'forgot', 'reset', 'change',
    'confirm', 'new password', 'old password', 'current password',
    'password:', 'password field', 'password is', 'password must',
    'enter password', 'type password', 'invalid password',
    'password strength', 'password hint', 'password requirements',
    'sign in', 'log in', 'sign up',
]

# Known benign string patterns to skip
SKIP_PATTERNS = [
    'localhost', '127.0.0.1', '0.0.0.0',
    'example.com/placeholder', 'schema.org',
    'apple.com/DTDs', 'w3.org/',
    'xmlns', '<!DOCTYPE', '<?xml',
]

# Swift/ObjC compiler-generated metadata prefixes — never credentials
_METADATA_PREFIXES = (
    '$s', '$S',           # Swift mangled symbols
    '_$s', '_$S',         # Swift mangled symbols (underscore-prefixed)
    '@objc_',             # ObjC interop stubs
    '_OBJC_',             # ObjC metadata symbols
    '__swift_',           # Swift runtime metadata
    '_swift_',            # Swift runtime metadata
)

# Keywords in function names that indicate crypto usage
_CRYPTO_FUNCTION_KEYWORDS = [
    'encrypt', 'decrypt', 'crypto', 'cryptography', 'cipher',
    'pbkdf', 'derive', 'hash', 'hmac', 'aes', 'des', 'blowfish',
    'RNEncryptor', 'RNDecryptor', 'SymmetricKey',
    'CCCrypt', 'CCKeyDerivation',
]

# Keywords in function names that indicate auth/credential usage
_AUTH_FUNCTION_KEYWORDS = [
    'login', 'auth', 'authenticate', 'credential', 'password',
    'token', 'session', 'signin', 'signup', 'register',
    'validate', 'verify',
    'oauth', 'sso', 'saml', 'mfa', '2fa', 'totp', 'otp', 'pincode',
]

# Keywords that indicate PCI/payment context
_PAYMENT_FUNCTION_KEYWORDS = [
    'payment', 'card', 'credit', 'billing', 'checkout',
    'purchase', 'transaction', 'stripe', 'braintree',
    'storekit', 'apple_pay', 'applepay', 'in_app_purchase',
    'iap', 'subscription', 'receipt',
]


class StringTableSecurityChecker(SecurityChecker):
    """
    Security checker that scans the binary's string table for
    hardcoded credentials, API keys, HTTP URLs, and sensitive literals.

    This checker is unique: it does NOT operate on call sites. Instead,
    it performs a standalone scan of all defined strings in the binary.
    The check_call_site method is a no-op; use scan_strings() directly.
    """

    def __init__(self, program):
        """Initialize the checker."""
        super().__init__(program)
        self._scanned = False
        self._findings = []

    def check_call_site(self, function_sig, call_site, extracted_info):
        """No-op for string scanner — use scan_strings() instead."""
        return []

    def scan_strings(self):
        """
        Scan all defined strings in the binary for security issues.

        Returns:
            List of SecurityFinding objects
        """
        if self._scanned:
            return self._findings

        findings = []
        seen_strings = set()  # Deduplicate

        for address, string_value in self.program.get_defined_strings():
            if not string_value or len(string_value) < 4:
                continue

            # Skip duplicates
            if string_value in seen_strings:
                continue
            seen_strings.add(string_value)

            # Skip known benign patterns
            if self._is_skip_pattern(string_value):
                continue

            # Check for HTTP cleartext URLs
            findings.extend(self._check_http_url(address, string_value))

            # Check for API key patterns
            findings.extend(self._check_api_key(address, string_value))

            # Check for hardcoded password patterns
            findings.extend(self._check_hardcoded_password(address, string_value))

        self._scanned = True
        self._findings = findings
        return findings

    def _is_skip_pattern(self, value):
        """Check if a string matches known benign patterns."""
        # Skip Swift/ObjC compiler-generated metadata strings
        if value.startswith(_METADATA_PREFIXES):
            return True
        lower = value.lower()
        for skip in SKIP_PATTERNS:
            if skip in lower:
                return True
        return False

    def _is_ui_label(self, value):
        """Check if a string looks like a UI label rather than a secret."""
        lower = value.lower()
        for indicator in UI_LABEL_INDICATORS:
            if indicator in lower:
                return True
        # Strings with spaces are usually UI text, not secrets
        if value.count(' ') > 3:
            return True
        return False

    def _check_http_url(self, address, value):
        """Check for HTTP (non-HTTPS) URL strings."""
        findings = []

        if not HTTP_URL_PATTERN.match(value):
            return findings

        # Check for HTTP (not HTTPS)
        if HTTP_ONLY_PATTERN.match(value):
            # Check for sensitive URL paths
            value_lower = value.lower()
            is_sensitive = any(path in value_lower for path in SENSITIVE_URL_PATHS)

            if is_sensitive:
                findings.append(SecurityFinding(
                    severity=Severity.HIGH,
                    issue_type="HTTP Cleartext with Sensitive Path",
                    description="Sensitive data sent over unencrypted HTTP: {}".format(
                        value[:120]),
                    location=address,
                    function_name="<string_table>",
                    evidence={"url": value[:200], "protocol": "HTTP (cleartext)"},
                    impact="Credentials or sensitive data transmitted without encryption (MITM attack)",
                    recommendation="Use HTTPS for all network communication, especially authentication and payment endpoints"
                ))
            else:
                findings.append(SecurityFinding(
                    severity=Severity.MEDIUM,
                    issue_type="HTTP Cleartext URL",
                    description="Unencrypted HTTP URL found: {}".format(value[:120]),
                    location=address,
                    function_name="<string_table>",
                    evidence={"url": value[:200], "protocol": "HTTP (cleartext)"},
                    impact="Data transmitted without encryption, vulnerable to interception",
                    recommendation="Use HTTPS instead of HTTP for all network requests"
                ))

        return findings

    def _check_api_key(self, address, value):
        """Check for hardcoded API keys and tokens."""
        findings = []

        for pattern in API_KEY_PATTERNS:
            match = pattern.search(value)
            if match:
                # Extra filter: skip short matches and obvious non-keys
                matched = match.group(0)
                if len(matched) < 16:
                    continue

                findings.append(SecurityFinding(
                    severity=Severity.HIGH,
                    issue_type="Hardcoded API Key/Token",
                    description="Potential hardcoded API key or token found in binary",
                    location=address,
                    function_name="<string_table>",
                    evidence={
                        "value_preview": value[:40] + ("..." if len(value) > 40 else ""),
                        "pattern": "API key format",
                    },
                    impact="Hardcoded API keys can be extracted and abused by attackers",
                    recommendation="Store API keys in server-side config or iOS Keychain, not in the binary"
                ))
                break  # One finding per string

        return findings

    def _check_hardcoded_password(self, address, value):
        """Check for strings that look like hardcoded passwords."""
        findings = []

        # Skip UI labels
        if self._is_ui_label(value):
            return findings

        # Check for password-like strings (high entropy, special chars, no spaces)
        for pattern in HARDCODED_PASSWORD_PATTERNS:
            if pattern.match(value):
                findings.append(SecurityFinding(
                    severity=Severity.CRITICAL,
                    issue_type="Potential Hardcoded Password",
                    description="String with password-like characteristics found in binary",
                    location=address,
                    function_name="<string_table>",
                    evidence={
                        "value": value,
                        "length": str(len(value)),
                        "pattern": "High-entropy string with special characters",
                    },
                    impact="Hardcoded passwords can be extracted from the binary by any attacker",
                    recommendation="Never hardcode passwords — derive from user input or fetch from secure storage"
                ))
                break

        return findings

    def cross_reference_findings(self):
        """
        Enrich existing string findings with cross-reference analysis.

        Uses Ghidra's xrefs to determine WHICH FUNCTIONS reference each
        suspicious string. This links hardcoded passwords to crypto call sites,
        HTTP URLs to auth functions, etc.

        Must be called after scan_strings(). Returns new findings generated
        by the cross-referencing (the original findings are unmodified).
        """
        if not self._scanned:
            self.scan_strings()

        xref_findings = []

        for finding in self._findings:
            # Only cross-reference CRITICAL and HIGH findings
            if finding.severity not in (Severity.CRITICAL, Severity.HIGH):
                continue

            # Get xrefs to the string address
            try:
                refs = self.program.get_references_to(finding.location)
            except Exception:
                continue

            if not refs:
                continue

            # Collect referencing function names
            referencing_functions = []
            for ref in refs:
                try:
                    func = self.program.get_function_containing(ref.from_address)
                    if func:
                        referencing_functions.append(func.name)
                except Exception:
                    continue

            if not referencing_functions:
                continue

            # Check if any referencing function is crypto-related
            crypto_callers = self._match_function_keywords(
                referencing_functions, _CRYPTO_FUNCTION_KEYWORDS
            )
            auth_callers = self._match_function_keywords(
                referencing_functions, _AUTH_FUNCTION_KEYWORDS
            )
            payment_callers = self._match_function_keywords(
                referencing_functions, _PAYMENT_FUNCTION_KEYWORDS
            )

            # Generate cross-reference findings
            if crypto_callers and "Hardcoded Password" in finding.issue_type:
                display_callers = [c[:80] for c in crypto_callers[:3]]
                xref_findings.append(SecurityFinding(
                    severity=Severity.CRITICAL,
                    issue_type="Hardcoded Password Used in Crypto Operation",
                    description="Hardcoded password string is referenced by crypto function(s)",
                    location=finding.location,
                    function_name="<string_xref>",
                    evidence={
                        "string_value": finding.evidence.get("value", "<unknown>"),
                        "crypto_functions": ", ".join(display_callers),
                        "total_references": str(len(referencing_functions)),
                    },
                    impact="Hardcoded encryption password means all installations share the "
                           "same key — data encrypted by one user can be decrypted by any "
                           "attacker who extracts this string from the binary",
                    recommendation="Derive encryption keys from user-provided passwords at "
                                   "runtime using PBKDF2 with a random salt, or use iOS Keychain"
                ))

            if auth_callers and "Hardcoded Password" in finding.issue_type:
                display_callers = [c[:80] for c in auth_callers[:3]]
                xref_findings.append(SecurityFinding(
                    severity=Severity.CRITICAL,
                    issue_type="Hardcoded Credential in Auth Function",
                    description="Hardcoded credential string is referenced by authentication function(s)",
                    location=finding.location,
                    function_name="<string_xref>",
                    evidence={
                        "string_value": finding.evidence.get("value", "<unknown>"),
                        "auth_functions": ", ".join(display_callers),
                        "total_references": str(len(referencing_functions)),
                    },
                    impact="Hardcoded credentials in authentication functions allow bypass — "
                           "attacker can extract credentials from the binary",
                    recommendation="Never hardcode authentication credentials; use secure "
                                   "server-side authentication"
                ))

            if payment_callers and "HTTP" in finding.issue_type:
                display_callers = [c[:80] for c in payment_callers[:3]]
                xref_findings.append(SecurityFinding(
                    severity=Severity.CRITICAL,
                    issue_type="Cleartext HTTP in Payment Flow",
                    description="HTTP URL referenced by payment/billing function(s)",
                    location=finding.location,
                    function_name="<string_xref>",
                    evidence={
                        "url": finding.evidence.get("url", "<unknown>"),
                        "payment_functions": ", ".join(display_callers),
                    },
                    impact="Payment data (credit cards, account info) transmitted over "
                           "cleartext HTTP — trivially interceptable via MITM",
                    recommendation="Use HTTPS for ALL payment-related communication; "
                                   "implement certificate pinning for payment endpoints"
                ))

            # Always record the referencing context for any CRITICAL/HIGH finding
            if referencing_functions and not (crypto_callers or auth_callers or payment_callers):
                # Just add context about which functions reference this string
                display_funcs = [f[:80] for f in referencing_functions[:5]]
                finding.evidence["referenced_by"] = ", ".join(display_funcs)
                if len(referencing_functions) > 5:
                    finding.evidence["referenced_by"] += " (+{} more)".format(
                        len(referencing_functions) - 5
                    )

        return xref_findings

    @staticmethod
    def _match_function_keywords(func_names, keywords):
        """Return function names that contain any of the given keywords."""
        matched = []
        for name in func_names:
            lower = name.lower()
            for kw in keywords:
                if kw.lower() in lower:
                    matched.append(name)
                    break
        return matched


__all__ = ["StringTableSecurityChecker"]
