"""
String-table security checks for Trellis (Ghidra Port).

This module performs a pass over the binary's defined string table to find
hardcoded credentials, API keys, HTTP URLs, and other sensitive string
literals. Unlike call-site checkers, this module does NOT require
decompiler/parameter extraction — it works purely on string data, making
it effective for Swift binaries where parameter extraction often fails.
"""

import base64
import math
import re
from typing import List, Set, Tuple, TYPE_CHECKING

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
    # Original: Strings starting with special char (encryption passwords)
    re.compile(r'^[@#$%&!][a-zA-Z0-9@#$%&!]{10,}$'),
    # Mixed-case alphanumeric with embedded special characters (e.g., This!sA5Ecret)
    re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9@#$%^&*!]{5,}$'),
]

# Format string patterns — these are NOT passwords (false positive filter)
_FORMAT_STRING_RE = re.compile(r'%[@dDuUfFeEgGsSiIlLcCpPxXo]|%[0-9]*l[udxo]')

# Template marker patterns — NOT passwords (e.g., @@TEMPVIEW@@)
_TEMPLATE_MARKER_RE = re.compile(r'^@@[A-Z_]+@@$')

# ObjC type encoding patterns — runtime metadata, NOT passwords
# Examples: v32@?0q8@"NSString"16^B24, @"NSString", v24@0:8@16
_OBJC_TYPE_ENCODING_RE = re.compile(
    r'@\?'          # block type
    r'|@"[A-Z]'     # ObjC object type @"ClassName"
    r'|\^[A-Z]'     # pointer type ^B, ^v, etc.
    r'|^[vVBbcCsSiIlLqQfd@#:?]+\d'  # type string starting with type codes + offset
)

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

# Valid Base64 string pattern — requires characteristics that distinguish
# intentionally-encoded strings from normal identifiers:
#  - Must be 20+ chars (shorter strings have too many false positives)
#  - Must contain at least one of: +, /, or trailing = (Base64 specific chars)
#    OR be a multiple-of-4 length AND contain mixed case + digits
_BASE64_RE = re.compile(r'^[A-Za-z0-9+/]{19,}={0,3}$')


def _looks_like_base64(value: str) -> bool:
    """Check if a string looks intentionally Base64-encoded vs a normal identifier."""
    if not _BASE64_RE.match(value):
        return False

    # Strings with +, /, or = are almost certainly Base64 (these chars don't
    # appear in identifiers, paths, or natural language)
    if '+' in value or '/' in value or value.endswith('='):
        return True

    # For pure-alphanumeric strings, require multiple signals:
    # 1. Length is a multiple of 4 (Base64 output characteristic)
    # 2. Contains mixed case AND digits (identifiers rarely mix all three)
    # 3. Does NOT look like a camelCase/PascalCase identifier
    if len(value) % 4 != 0:
        return False

    has_upper = bool(re.search(r'[A-Z]', value))
    has_lower = bool(re.search(r'[a-z]', value))
    has_digit = bool(re.search(r'[0-9]', value))

    if not (has_upper and has_lower and has_digit):
        return False

    # Reject camelCase identifiers: if the string has a lowercase letter
    # immediately followed by an uppercase letter, it's likely an identifier
    # like "passwordResetToken" not Base64 like "cGFzc3dvcmQ="
    camel_transitions = len(re.findall(r'[a-z][A-Z]', value))
    if camel_transitions >= 2:
        return False

    return True

# Keywords that indicate a decoded Base64 value is sensitive
_DECODED_SECRET_KEYWORDS = [
    'password', 'passwd', 'secret', 'token', 'api_key', 'apikey',
    'api-key', 'auth', 'credential', 'private_key', 'privatekey',
    'access_key', 'accesskey', 'client_secret', 'bearer',
]

# Maximum address gap (bytes) for credential-pair proximity detection
_CREDENTIAL_PAIR_MAX_GAP = 64

# Entropy threshold for password-like strings (Shannon entropy in bits/char)
_ENTROPY_THRESHOLD = 3.5

# Min/max lengths for entropy-based password detection
_ENTROPY_MIN_LEN = 8
_ENTROPY_MAX_LEN = 64

# Swift/ObjC compiler-generated metadata prefixes — never credentials
_METADATA_PREFIXES = (
    '$s', '$S',           # Swift mangled symbols
    '_$s', '_$S',         # Swift mangled symbols (underscore-prefixed)
    '$__',                # Swift lazy storage ivars ($__lazy_storage_$_...)
    '@objc_',             # ObjC interop stubs
    '_OBJC_',             # ObjC metadata symbols
    '__swift_',           # Swift runtime metadata
    '_swift_',            # Swift runtime metadata
    '_TtC',              # Swift class type metadata (_TtC7Module...)
    '_TtGC',             # Swift generic class metadata
    '_TtV',              # Swift value type metadata
    '_TtO',              # Swift enum type metadata
    'T@,',               # ObjC property type encoding (T@,C,N,V_...)
    'T@"',               # ObjC property type with class (T@"NSString",...)
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

            # Check for Base64-encoded secrets
            findings.extend(self._check_base64_encoded_secret(address, string_value))

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

    def _is_format_string(self, value):
        """Check if a string is a format specifier, template, or ObjC type encoding."""
        if _FORMAT_STRING_RE.search(value):
            return True
        if _TEMPLATE_MARKER_RE.match(value):
            return True
        if _OBJC_TYPE_ENCODING_RE.search(value):
            return True
        # Strings containing double-quotes are type encodings or code, not passwords
        if '"' in value:
            return True
        return False

    @staticmethod
    def _shannon_entropy(s):
        """Calculate Shannon entropy of a string in bits per character."""
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = float(len(s))
        return -sum((count / length) * math.log2(count / length)
                     for count in freq.values())

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

    def _check_base64_encoded_secret(self, address, value):
        """Check if a string is a Base64-encoded secret."""
        findings = []

        # Must look like an intentionally Base64-encoded string (not a normal
        # identifier that happens to use only Base64-safe characters)
        if not _looks_like_base64(value):
            return findings

        # Skip very long strings (likely binary blobs, not encoded secrets)
        if len(value) > 256:
            return findings

        # Attempt decode
        try:
            decoded_bytes = base64.b64decode(value, validate=True)
        except Exception:
            return findings

        # Must decode to valid UTF-8 text
        try:
            decoded_str = decoded_bytes.decode('utf-8')
        except (UnicodeDecodeError, ValueError):
            return findings

        # Skip if decoded result is empty or too short
        if len(decoded_str) < 4:
            return findings

        # Check if decoded value matches secret patterns
        decoded_lower = decoded_str.lower()

        # Strategy 1: Decoded text contains sensitive keywords
        keyword_hit = None
        for kw in _DECODED_SECRET_KEYWORDS:
            if kw in decoded_lower:
                keyword_hit = kw
                break

        # Strategy 2: Decoded text matches API key patterns
        api_key_hit = False
        if not keyword_hit:
            for pattern in API_KEY_PATTERNS:
                if pattern.search(decoded_str):
                    api_key_hit = True
                    break

        # Strategy 3: Decoded text is high-entropy (password-like)
        entropy_hit = False
        if not keyword_hit and not api_key_hit:
            if (len(decoded_str) >= _ENTROPY_MIN_LEN and
                    len(decoded_str) <= _ENTROPY_MAX_LEN and
                    ' ' not in decoded_str):
                entropy = self._shannon_entropy(decoded_str)
                has_alpha = bool(re.search(r'[a-zA-Z]', decoded_str))
                has_digit = bool(re.search(r'[0-9]', decoded_str))
                has_special = bool(re.search(r'[@#$%^&*!]', decoded_str))
                mixed = sum([has_alpha, has_digit, has_special])
                if entropy >= _ENTROPY_THRESHOLD and mixed >= 2:
                    entropy_hit = True

        if not (keyword_hit or api_key_hit or entropy_hit):
            return findings

        # Determine detection method for evidence
        if keyword_hit:
            method = "keyword '{}' in decoded value".format(keyword_hit)
        elif api_key_hit:
            method = "API key pattern in decoded value"
        else:
            method = "high-entropy decoded value ({:.2f} bits/char)".format(
                self._shannon_entropy(decoded_str))

        # Collect xrefs to show where this encoded string is used
        referencing_functions = []
        try:
            refs = self.program.get_references_to(address)
            for ref in refs:
                func = self.program.get_function_containing(ref.from_address)
                if func:
                    referencing_functions.append(func.name)
        except Exception:
            pass

        evidence = {
            "encoded_value": value[:60] + ("..." if len(value) > 60 else ""),
            "decoded_preview": decoded_str[:60] + (
                "..." if len(decoded_str) > 60 else ""),
            "detection_method": method,
        }
        if referencing_functions:
            display_funcs = [f[:80] for f in referencing_functions[:5]]
            evidence["used_by"] = ", ".join(display_funcs)
            if len(referencing_functions) > 5:
                evidence["used_by"] += " (+{} more)".format(
                    len(referencing_functions) - 5)

        findings.append(SecurityFinding(
            severity=Severity.HIGH,
            issue_type="Base64-Encoded Secret in String Table",
            description="Base64 string decodes to a value matching secret patterns",
            location=address,
            function_name="<string_table>",
            evidence=evidence,
            impact="Encoded secret can be trivially decoded by any attacker "
                   "who extracts the string from the binary",
            recommendation="Do not store secrets in the binary even if encoded; "
                          "use iOS Keychain or server-side configuration"
        ))

        return findings

    def _check_hardcoded_password(self, address, value):
        """Check for strings that look like hardcoded passwords."""
        findings = []

        # Skip UI labels
        if self._is_ui_label(value):
            return findings

        # Skip format strings and template markers (false positive filter)
        if self._is_format_string(value):
            return findings

        # Check for password-like strings (high entropy, special chars, no spaces)
        for pattern in HARDCODED_PASSWORD_PATTERNS:
            if pattern.match(value):
                # Secondary filter: require at least one special char
                # AND at least one alphanumeric to avoid template markers
                has_special = bool(re.search(r'[@#$%^&*!]', value))
                has_alpha = bool(re.search(r'[a-zA-Z]', value))
                has_digit = bool(re.search(r'[0-9]', value))

                if has_special and has_alpha:
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

        # Entropy-based detection for strings that don't match regex patterns
        # Catches passwords like 'ev8848@1953', 'tenzinnorgay', etc.
        if not findings:
            findings.extend(self._check_entropy_password(address, value))

        return findings

    def _check_entropy_password(self, address, value):
        """Detect passwords via Shannon entropy analysis."""
        findings = []

        # Length filter
        if len(value) < _ENTROPY_MIN_LEN or len(value) > _ENTROPY_MAX_LEN:
            return findings

        # Must not contain spaces (passwords don't have spaces)
        if ' ' in value:
            return findings

        # Must not look like a path, URL, selector, or source filename
        if any(c in value for c in ('/', ':', '[', ']', '{', '}', '(', ')')):
            return findings

        # Skip format strings, ObjC type encodings, and template markers
        if self._is_format_string(value):
            return findings

        # Skip source filenames (e.g., YapDatabaseTransaction.m)
        if '.' in value and value.rsplit('.', 1)[-1] in (
            'm', 'h', 'c', 'mm', 'cpp', 'swift', 'py', 'js', 'json',
            'plist', 'xib', 'storyboard', 'strings', 'dat', 'db',
            'sqlite', 'der', 'pem', 'cer', 'enc', 'png', 'jpg',
        ):
            return findings

        # Must not be all lowercase alpha (too many common words would match)
        if value.isalpha() and value.islower():
            return findings

        # Calculate entropy
        entropy = self._shannon_entropy(value)
        if entropy < _ENTROPY_THRESHOLD:
            return findings

        # Require mixed character classes (letters+digits, or letters+password-special)
        # IMPORTANT: only count password-typical special chars (@#$%^&*!), NOT
        # identifier separators (- _ . ,) which are normal in ObjC/Swift strings
        has_alpha = bool(re.search(r'[a-zA-Z]', value))
        has_digit = bool(re.search(r'[0-9]', value))
        has_password_special = bool(re.search(r'[@#$%^&*!]', value))
        mixed_classes = sum([has_alpha, has_digit, has_password_special])

        if mixed_classes >= 2:
            findings.append(SecurityFinding(
                severity=Severity.HIGH,
                issue_type="Potential Hardcoded Credential (Entropy)",
                description="High-entropy string detected (possible password or token)",
                location=address,
                function_name="<string_table>",
                evidence={
                    "value": value,
                    "length": str(len(value)),
                    "entropy": "{:.2f}".format(entropy),
                    "pattern": "Entropy-based detection (>{:.1f} bits/char)".format(
                        _ENTROPY_THRESHOLD),
                },
                impact="Hardcoded credentials can be extracted from the binary by any attacker",
                recommendation="Never hardcode credentials — use secure storage or server-side validation"
            ))

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

    def detect_credential_pairs(self):
        """
        Detect credential pairs by proximity in the string table.

        When two strings at adjacent addresses look like a username+password
        pair (e.g., 'edhillary' at 0x100386310 followed by 'ev8848@1953' at
        0x10038631a), flag as CRITICAL.

        Must be called after scan_strings().

        Returns:
            List of SecurityFinding objects for detected credential pairs.
        """
        if not self._scanned:
            self.scan_strings()

        pair_findings = []

        # Collect high-entropy / password-like strings with their addresses
        # Re-scan string table for candidates (lightweight — no decompilation)
        candidates = []  # list of (address, string_value)
        seen = set()

        for address, string_value in self.program.get_defined_strings():
            if not string_value or len(string_value) < 4:
                continue
            if string_value in seen:
                continue
            seen.add(string_value)

            # Skip known benign
            if self._is_skip_pattern(string_value):
                continue
            if self._is_ui_label(string_value):
                continue
            if self._is_format_string(string_value):
                continue
            if ' ' in string_value:
                continue
            # Skip long strings (paths, URLs, selectors, sentences)
            if len(string_value) > _ENTROPY_MAX_LEN:
                continue
            if any(c in string_value for c in ('/', ':', '[', ']', '{', '}')):
                continue
            # Skip query-string fragments
            if string_value.startswith('&') or string_value.startswith('?'):
                continue

            # Must be short-ish, no spaces — plausible credential
            if _ENTROPY_MIN_LEN <= len(string_value) <= 40:
                candidates.append((address, string_value))

        # Sort by address for proximity scanning
        candidates.sort(key=lambda x: x[0])

        # Slide a window over adjacent strings
        for i in range(len(candidates) - 1):
            addr_a, val_a = candidates[i]
            addr_b, val_b = candidates[i + 1]

            # Check proximity
            gap = addr_b - addr_a
            if gap > _CREDENTIAL_PAIR_MAX_GAP or gap < 0:
                continue

            # One should look like a username, the other like a password
            entropy_a = self._shannon_entropy(val_a)
            entropy_b = self._shannon_entropy(val_b)

            # A credential pair: one lower-entropy (username) + one higher-entropy (password)
            # Use password-typical special chars only (not _ - . which are identifier separators)
            has_special_a = bool(re.search(r'[@#$%^&*!]', val_a))
            has_special_b = bool(re.search(r'[@#$%^&*!]', val_b))

            # Heuristic: if one has password-special chars and the other doesn't,
            # they look like a credential pair (username + password)
            is_pair = False
            username_val = None
            password_val = None

            if has_special_b and not has_special_a and entropy_b > 3.0:
                is_pair = True
                username_val = val_a
                password_val = val_b
            elif has_special_a and not has_special_b and entropy_a > 3.0:
                is_pair = True
                username_val = val_b
                password_val = val_a

            if is_pair:
                pair_findings.append(SecurityFinding(
                    severity=Severity.CRITICAL,
                    issue_type="Hardcoded Credential Pair",
                    description="Adjacent strings appear to be a username/password pair",
                    location=addr_a,
                    function_name="<string_table>",
                    evidence={
                        "username_candidate": username_val,
                        "password_candidate": password_val,
                        "username_address": hex(addr_a if username_val == val_a else addr_b),
                        "password_address": hex(addr_b if password_val == val_b else addr_a),
                        "gap_bytes": str(gap),
                    },
                    impact="Hardcoded username/password pair can be extracted from binary",
                    recommendation="Remove hardcoded credentials; use server-side authentication"
                ))

        return pair_findings


__all__ = ["StringTableSecurityChecker"]
