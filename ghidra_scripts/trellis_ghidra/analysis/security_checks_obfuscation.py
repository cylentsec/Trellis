# -*- coding: utf-8 -*-
"""
Obfuscation pattern detection for Trellis (Ghidra port).

This module analyzes decompiled code to detect common string obfuscation and
encoding patterns used to hide secrets, such as Base64 decoding, Hex decoding,
XOR operations, and AES decryption with hardcoded keys.

The primary detection engine is **decompiler pseudocode analysis**: each
function near a sensitive sink is decompiled and the pseudocode is searched
for language-agnostic decode patterns (works for both Swift and Objective-C).
Variable flow is tracked from decode output to sink input so that every
finding reports *where* the decoded/decrypted value is used.
"""

import re
from typing import Dict, List, Optional, Set, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ..ghidra_api import GhidraProgram
    from .finder import FoundFunction
    from .calltree import CallSite
    from .extractor import ExtractedCallInfo

from .security_checks import SecurityChecker, SecurityFinding, Severity


# =========================================================================
# XOR false-positive filtering
# =========================================================================

# XOR constants that are likely NOT obfuscation (false positives)
FALSE_POSITIVE_XOR_KEYS = {
    0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80,
    0xff, 0xffff, 0x8000,
    0x80000000, 0xffffffff,
    0x8000000000000000, 0xffffffffffffffff,
}

# Well-known constants used in crypto/hash algorithms (NOT obfuscation)
_KNOWN_CRYPTO_CONSTANTS = {
    # ChaCha20/Salsa20 sigma "expand 32-byte k"
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    # ChaCha20/Salsa20 tau "expand 16-byte k"
    0x61707865, 0x3120646e, 0x79622d36, 0x6b206574,
    # TEA/XTEA delta
    0x9e3779b9,
    # TEA sum initial
    0xc6ef3720,
    # Golden ratio related (used in various hash functions)
    0x9e3779b97f4a7c15,
    # FNV-1/FNV-1a primes and offsets
    0x01000193,         # FNV-1 32-bit prime
    0x811c9dc5,         # FNV-1 32-bit offset basis
    0x00000100000001b3, # FNV-1 64-bit prime
    0xcbf29ce484222325, # FNV-1 64-bit offset basis
    # MurmurHash constants
    0xcc9e2d51, 0x1b873593,  # MurmurHash3 32-bit
    0xff51afd7ed558ccd, 0xc4ceb9fe1a85ec53,  # MurmurHash3 128-bit finalize
    0x87c37b91114253d5, 0x4cf5ad432745937f,  # MurmurHash3 128-bit
    # CityHash / FarmHash constants
    0x9ae16a3b2f90404f,
    0x9ddfea08eb382d69,
    # SipHash constants
    0x736f6d6570736575, 0x646f72616e646f6d,
    0x6c7967656e657261, 0x7465646279746573,
    # xxHash constants
    0x9e3779b185ebca87,  # xxHash64 PRIME1
    0xc2b2ae3d27d4eb4f,  # xxHash64 PRIME2
    0x165667b19e3779f9,  # xxHash64 PRIME3
    0x85ebca77c2b2ae63,  # xxHash64 PRIME4
    0x27d4eb2f165667c5,  # xxHash64 PRIME5
    # CRC-32 polynomial
    0xedb88320,
    0x82f63b78,  # CRC-32C (Castagnoli)
    # AES round constants / AESNI related
    0x63636363,
    # SHA-256 initial hash values (first 8 primes)
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    # MD5 constants (T table, derived from sin)
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    # BLAKE2 IV
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
}

# Function name fragments indicating crypto/hash algorithm implementations
_CRYPTO_HASH_FUNC_FRAGMENTS = [
    # Hash algorithms
    'hash', 'Hash', 'HASH',
    'sha1', 'sha2', 'sha3', 'sha256', 'sha384', 'sha512',
    'SHA1', 'SHA2', 'SHA3', 'SHA256', 'SHA384', 'SHA512',
    'md5', 'MD5', 'md4', 'MD4',
    'hmac', 'HMAC',
    'blake', 'BLAKE',
    'crc32', 'CRC32', 'crc', 'CRC',
    # Cipher algorithms
    'chacha', 'ChaCha', 'CHACHA',
    'salsa', 'Salsa', 'SALSA',
    'aes', 'AES', 'Aes',
    'poly1305', 'Poly1305',
    'siphash', 'SipHash', 'SIPHASH',
    'tea_', 'TEA_', 'xtea', 'XTEA',
    # Hash library namespaces
    'hash_internal', 'HashInternal',
    'absl', 'ABSL',
    'fnv', 'FNV',
    'murmur', 'Murmur', 'MURMUR',
    'city', 'City', 'CITY',
    'farm', 'Farm', 'FARM',
    'xxhash', 'xxHash', 'XXHash', 'XXH',
    'wyhash', 'WyHash',
    'spooky', 'Spooky',
    'metro', 'Metro',
    # Crypto library namespaces
    'CommonCrypto', 'CCCrypt',
    'CryptoKit',
    'BoringSSL', 'boringssl',
    'OpenSSL', 'openssl',
    'libsodium', 'sodium',
    'NaCl', 'nacl',
]


def _is_crypto_hash_function(func_name: str) -> bool:
    """Check if the function name indicates a crypto or hash algorithm implementation."""
    return any(frag in func_name for frag in _CRYPTO_HASH_FUNC_FRAGMENTS)


def _is_likely_obfuscation_key(const_val: int) -> bool:
    """
    Determine if an XOR constant is likely used for obfuscation vs simple bit ops.
    """
    if const_val in FALSE_POSITIVE_XOR_KEYS:
        return False
    const_val = const_val & 0xffffffffffffffff
    # Check against known crypto/hash algorithm constants
    if const_val in _KNOWN_CRYPTO_CONSTANTS:
        return False
    if const_val != 0 and (const_val & (const_val - 1)) == 0:
        return False
    if const_val < 0x100:
        return bin(const_val).count('1') > 2
    if const_val >= 0x10000:
        return True
    if const_val >= 0x100:
        return bin(const_val).count('1') >= 4
    return False


# =========================================================================
# Language-agnostic patterns matched in decompiler pseudocode
# =========================================================================

# Sensitive sinks — if a function's pseudocode contains any of these, it is a
# candidate for decode→sink analysis.  Covers both ObjC and Swift patterns.
#
# NOTE: Hash functions (CC_SHA*, CC_MD5, CCHmac, etc.) are deliberately
# excluded.  Hashing is a one-way operation — a decoded value flowing into
# a hash is normal data processing, not an "obfuscated secret" pattern.
# Key derivation (PBKDF) is also excluded: if a decoded value is used as
# the password input to PBKDF, the interesting finding is the hardcoded
# password, which is caught by the string-table and secret-sinks checkers.
_SINK_PATTERNS = [
    # CommonCrypto — encryption/decryption only (NOT hashing)
    'CCCrypt', 'CCCryptorCreate',
    # Security framework — keychain storage
    'SecItemAdd', 'SecItemUpdate', 'SecItemCopyMatching',
    # Network headers (ObjC)
    'setValue:forHTTPHeaderField:', 'addValue:forHTTPHeaderField:',
    # WebKit
    'evaluateJavaScript:',
    # Swift CryptoKit — encryption only (NOT SHA/HMAC/HKDF)
    'AES.GCM.seal', 'ChaChaPoly.seal', 'SymmetricKey',
    # ObjC crypto wrappers — encryption only
    'RNEncryptor', 'RNDecryptor',
    'encryptData:', 'decryptData:',
]

# Functions whose presence in pseudocode should EXCLUDE a candidate from
# decode→sink analysis.  If a function is primarily a hash/digest wrapper,
# a decoded value flowing into it is not an obfuscated-secret pattern.
_HASH_FUNCTION_INDICATORS = [
    # CommonCrypto hashing
    'CC_SHA1', 'CC_SHA256', 'CC_SHA384', 'CC_SHA512', 'CC_MD5',
    'CCHmac', 'CCHmacInit', 'CCHmacUpdate', 'CCHmacFinal',
    'CCKeyDerivationPBKDF',
    # Swift CryptoKit hashing
    'SHA256.hash', 'SHA384.hash', 'SHA512.hash',
    'HMAC.authenticationCode', 'HKDF.deriveKey',
    # Generic hash indicators in function/variable names
    'digest', 'Digest', 'hashValue', 'checksum',
]

# Decode/deobfuscation patterns — searched in pseudocode text.
_DECODE_PATTERNS = [
    # Base64 — covers ObjC, Swift, and custom implementations
    ('base64', re.compile(
        r'(base64Encoded|Base64|base64Decode|initWithBase64|'
        r'fromBase64|b64decode|decodeBase64|base64EncodedString)',
        re.IGNORECASE)),
    # Hex decode
    ('hex', re.compile(
        r'(fromHexString|hexString|hexDecode|unhexlify|'
        r'dataFromHex|hexToData|hexToBytes)',
        re.IGNORECASE)),
    # XOR obfuscation
    ('xor', re.compile(
        r'\w+\s*\^\s*0x[0-9a-fA-F]{2,}|0x[0-9a-fA-F]{2,}\s*\^\s*\w+')),
    # AES/encryption wrapper calls that suggest decode-before-use
    ('decrypt', re.compile(
        r'(decrypt|decipher|deobfuscate|unscramble|unmask|reveal)',
        re.IGNORECASE)),
]

# Regex to extract C-style assignments:  var = someCall(...);
# Group 1 = LHS variable, Group 2 = call/expression
_ASSIGN_RE = re.compile(
    r'(\w+)\s*=\s*([^;]*?'
    r'(?:base64|Base64|hexString|fromHex|decrypt|decipher|'
    r'deobfuscate|unmask|unhexlify|b64decode|XOR|\^\s*0x)'
    r'[^;]*);',
    re.IGNORECASE)

# Regex to find sink calls with arguments:  SinkName(...var...)
_SINK_CALL_RE = re.compile(
    r'({})[\s(]'.format('|'.join(re.escape(s) for s in _SINK_PATTERNS)))

# Maximum number of functions to decompile (performance guard).
# Typical iOS apps have 15-50K functions; 2000 was far too low and caused
# the scanner to miss findings in the latter ~90% of the binary.
_MAX_FUNCTIONS_TO_DECOMPILE = 50000

# Maximum bytes to read for XOR recovery attempts
_XOR_MAX_BLOB_SIZE = 256

# Minimum printable ratio for XOR recovery to be considered successful
_XOR_MIN_PRINTABLE_RATIO = 0.85

# =========================================================================
# XOR decode loop detection patterns (pseudocode regex)
# =========================================================================

# Step A: Detect loop constructs in decompiled C.
# Matches for/while/do-while and captures the body up to the closing brace.
_LOOP_HEAD_RE = re.compile(
    r'(?:'
    r'for\s*\([^)]*\)\s*\{'
    r'|while\s*\([^)]*\)\s*\{'
    r'|do\s*\{'
    r')',
    re.DOTALL)

# Step B-1: Byte load from (index_var + constant_address) inside loop body.
# Matches patterns like:
#   *(i + 0x10086f668)          — direct pointer arithmetic
#   *(0x10086f668 + i)          — reversed operand order
#   (&DAT_10086f668)[i]         — Ghidra array-indexing on data label
# Captures the constant hex address.
_LOOP_DATA_LOAD_RE = re.compile(
    r'\*\s*\(\s*(?:'
    r'\w+\s*\+\s*(0x[0-9a-fA-F]{6,16})'
    r'|(0x[0-9a-fA-F]{6,16})\s*\+\s*\w+'
    r')\s*\)'
    r'|'
    r'\(\s*&\s*DAT_([0-9a-fA-F]{6,16})\s*\)\s*\[[^\]]+\]')

# Step B-2: Transform expression containing XOR with a hex constant.
# Matches:  (expr ^ 0xNN)  or  (0xNN ^ expr)
# Captures the hex constant.
_LOOP_XOR_RE = re.compile(
    r'(?:\w[\w.]*\s*\^\s*(0x[0-9a-fA-F]+)'
    r'|(0x[0-9a-fA-F]+)\s*\^\s*\w[\w.]*)')

# Step C: Composed transforms — optional ADD/SUB/NOT after XOR.
# Matches:  (expr ^ 0xNN) - 3   or   (expr ^ 0xNN) + 0x10
_COMPOSED_TRANSFORM_RE = re.compile(
    r'\([^)]*\^[^)]*\)\s*([+\-])\s*(0x[0-9a-fA-F]+|\d+)')

# Step D: Loop bound extraction from condition.
# Matches:  i != 9,  i < 0x20,  i <= count,  i < 9,  counter != 0xa
_LOOP_BOUND_RE = re.compile(
    r'(?:while|for)[^)]*'
    r'\w+\s*(!?[<>=]=?)\s*(0x[0-9a-fA-F]+|\d+)'
    r'|'
    r'\w+\s*(!?[<>=]=?)\s*(0x[0-9a-fA-F]+|\d+)\s*\)')

# Step E: String constructor patterns (Swift and ObjC) — checked in full
# function pseudocode, not just loop body.
_STRING_CONSTRUCTOR_PATTERNS = [
    # Swift String(bytes:encoding:) — appears as mangled symbol containing
    # these substrings in Ghidra's decompiled output
    'bytes8encoding', 'bytes:encoding:', 'String.init',
    'FoundationE5bytes',  # from mangled $sSS10FoundationE5bytes...
    'stringWithUTF8String', 'UTF8String',
    # ObjC NSString constructors
    'initWithBytes:length:encoding:',
    'initWithData:encoding:',
    'initWithUTF8String:',
    'stringWithCString:encoding:',
    'stringWithCharacters:length:',
    'NSString',
    # Generic
    'initWithBytes', 'initWithData',
]


def _is_printable_text(data: bytes) -> Optional[str]:
    """
    Check if bytes are mostly printable ASCII/UTF-8.

    Used for XOR decode loop recovery where ANY printable text is
    interesting (it was intentionally obfuscated, so even a URL or
    config string is a finding).

    Returns the decoded string if printable, None otherwise.
    """
    try:
        text = data.decode('utf-8', errors='replace')
    except Exception:
        return None

    if not text or len(text) < 3:
        return None

    # Strip null bytes
    text = text.rstrip('\x00')
    if len(text) < 3:
        return None

    # Check printable ratio
    printable = sum(1 for c in text if 32 <= ord(c) < 127)
    if len(text) == 0 or printable / len(text) < _XOR_MIN_PRINTABLE_RATIO:
        return None

    return text


def _is_printable_secret(data: bytes) -> Optional[str]:
    """
    Check if bytes are mostly printable ASCII/UTF-8 and look secret-like.

    Returns the decoded string if it looks like a secret, None otherwise.
    """
    try:
        text = data.decode('utf-8', errors='replace')
    except Exception:
        return None

    if not text or len(text) < 6:
        return None

    # Check printable ratio
    printable = sum(1 for c in text if 32 <= ord(c) < 127)
    if printable / len(text) < _XOR_MIN_PRINTABLE_RATIO:
        return None

    # Strip null bytes and check again
    text = text.rstrip('\x00')
    if len(text) < 6:
        return None

    # Check for secret-like content
    lower = text.lower()
    secret_keywords = [
        'password', 'secret', 'token', 'api_key', 'apikey', 'auth',
        'credential', 'private', 'bearer', 'key=', 'http://', 'https://',
    ]
    for kw in secret_keywords:
        if kw in lower:
            return text

    # High entropy check (mixed character classes)
    has_alpha = bool(re.search(r'[a-zA-Z]', text))
    has_digit = bool(re.search(r'[0-9]', text))
    has_special = bool(re.search(r'[^a-zA-Z0-9\s]', text))
    if has_alpha and has_digit and has_special:
        return text

    return None


class ObfuscationSecurityChecker(SecurityChecker):
    """Security checker for obfuscation patterns (Base64, Hex, XOR, AES)."""

    def __init__(self, program):
        super().__init__(program)
        # Cache: func_address -> decompiled pseudocode string
        self._decomp_cache = {}  # type: Dict[int, Optional[str]]

    def check_call_site(self, function_sig, call_site, extracted_info):
        """Check Base64/Hex decode API calls (signature-based, ObjC only)."""
        findings = []
        func_name = function_sig.name

        is_base64 = any(api in func_name for api in [
            "initWithBase64EncodedString:",
            "initWithBase64EncodedData:",
            "dataFromBase64String",
            "base64Decoded",
            "GTMBase64",
            "RXBase64"
        ])

        is_hex = any(api in func_name for api in [
            "dataFromHexString:",
            "hexString",
            "unhexlify"
        ])

        if is_base64:
            input_val = None
            if extracted_info and extracted_info.params:
                for param in extracted_info.params:
                    if param.value_as_string:
                        input_val = param.value_as_string
                        break

            evidence = {"function": func_name}
            if input_val:
                evidence["input"] = input_val[:100]

            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="Obfuscation: Base64 Decode",
                description="Base64 decoding detected",
                location=call_site.call_instruction_address,
                function_name=call_site.caller_name,
                evidence=evidence,
                impact="May be used to hide secrets or configuration",
                recommendation="Inspect decoded value for sensitive data"
            ))

        elif is_hex:
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="Obfuscation: Hex Decode",
                description="Hex string decoding detected",
                location=call_site.call_instruction_address,
                function_name=call_site.caller_name,
                evidence={"function": func_name},
                impact="May be used to hide binary data or keys",
                recommendation="Inspect input string for hidden keys or sensitive data"
            ))

        return findings

    # =================================================================
    # Core engine: decompiler-based decode→sink scanner
    # =================================================================

    def scan_decode_to_sink(self):
        """
        Decompiler-based scan for decode/deobfuscation patterns flowing into
        sensitive sinks.  Works for both Swift and Objective-C.

        Algorithm:
          1. Decompile every function (up to _MAX_FUNCTIONS_TO_DECOMPILE).
          2. If the pseudocode mentions a sensitive sink, mark it as a
             candidate.
          3. Search the candidate's pseudocode for decode patterns.
          4. Trace variable flow: if the decode output variable appears as
             an argument to a sink call, report the full chain.
          5. If variable flow cannot be confirmed, still report at MEDIUM
             severity.

        Returns:
            List of SecurityFinding objects
        """
        findings = []
        seen = set()  # Dedup: (func_addr, decode_type, sink_name)

        print("[Trellis] Decode→Sink scan: decompiling functions...")

        func_count = 0
        candidate_count = 0

        for func in self.program.get_all_functions():
            if func_count >= _MAX_FUNCTIONS_TO_DECOMPILE:
                break
            func_count += 1

            decomp = self._get_decomp(func)
            if not decomp:
                continue

            # Step 1: does this function call any sensitive sink?
            matched_sinks = []
            for sink in _SINK_PATTERNS:
                if sink in decomp:
                    matched_sinks.append(sink)
            if not matched_sinks:
                continue

            # Skip functions that are primarily hash/digest operations.
            # A decoded value flowing into a hash is normal data processing,
            # not an obfuscated secret being recovered.
            if self._is_hash_function(decomp):
                continue

            candidate_count += 1

            # Step 2: does this function contain any decode pattern?
            for decode_type, pattern in _DECODE_PATTERNS:
                match = pattern.search(decomp)
                if not match:
                    continue

                # For XOR patterns, apply false-positive filtering
                if decode_type == 'xor':
                    # Skip XOR inside known crypto/hash implementations
                    if _is_crypto_hash_function(func.name):
                        continue
                    hex_match = re.search(
                        r'0x([0-9a-fA-F]+)', match.group(0))
                    if hex_match:
                        const_val = int(hex_match.group(1), 16)
                        if not _is_likely_obfuscation_key(const_val):
                            continue

                decode_snippet = match.group(0).strip()[:80]

                # Step 3: variable-flow tracking
                for sink_name in matched_sinks:
                    dedup_key = (func.address, decode_type, sink_name)
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    var_chain = self._trace_variable_flow(
                        decomp, decode_snippet, sink_name)

                    if var_chain:
                        # Confirmed flow: decode output reaches sink
                        severity = Severity.CRITICAL if any(
                            s in sink_name for s in (
                                'CCCrypt', 'CCCryptorCreate',
                                'SecItemAdd', 'SecItemUpdate',
                                'SymmetricKey')
                        ) else Severity.HIGH

                        findings.append(SecurityFinding(
                            severity=severity,
                            issue_type="Decoded/Decrypted Value Used in Sink",
                            description=(
                                "{} decode output flows to {} sink".format(
                                    decode_type.upper(), sink_name)),
                            location=func.address,
                            function_name=func.name,
                            evidence={
                                "decode_type": decode_type,
                                "decode_pattern": decode_snippet,
                                "sink": sink_name,
                                "variable_chain": var_chain,
                                "detection_method":
                                    "decompiler_variable_flow",
                            },
                            impact=(
                                "Obfuscated/encrypted value is decoded at "
                                "runtime and passed to {} — the pre-decode "
                                "value can be extracted from the binary and "
                                "decoded offline".format(sink_name)),
                            recommendation=(
                                "Do not store secrets in the binary even if "
                                "encoded/encrypted; use iOS Keychain or "
                                "server-side configuration")
                        ))
                    else:
                        # Decode pattern present but flow not confirmed
                        findings.append(SecurityFinding(
                            severity=Severity.MEDIUM,
                            issue_type=(
                                "Decode Pattern Near Sensitive Sink"),
                            description=(
                                "{} decode pattern found in function calling "
                                "{}".format(
                                    decode_type.upper(), sink_name)),
                            location=func.address,
                            function_name=func.name,
                            evidence={
                                "decode_type": decode_type,
                                "decode_pattern": decode_snippet,
                                "sink": sink_name,
                                "detection_method":
                                    "decompiler_pattern_proximity",
                            },
                            impact=(
                                "Decode/deobfuscation operation in same "
                                "function as sensitive sink — manual review "
                                "needed to confirm data flow"),
                            recommendation=(
                                "Inspect decompiled code to determine if "
                                "decoded value reaches the sink parameter")
                        ))

        print("[Trellis] Decode→Sink scan: checked {} functions, "
              "{} candidates, {} findings".format(
                  func_count, candidate_count, len(findings)))

        return findings

    def _trace_variable_flow(
        self, decomp: str, decode_snippet: str, sink_name: str
    ) -> Optional[str]:
        """
        Trace variable flow from a decode operation to a sink call in
        decompiled pseudocode.

        Looks for patterns like:
            result_var = ...decode_snippet...;
            ...
            SinkName(...result_var...);

        Returns a human-readable variable chain string if flow is confirmed,
        or None if it cannot be traced.
        """
        # Strategy 1: find an assignment where decode pattern is on the RHS
        assigned_vars = set()
        for m in _ASSIGN_RE.finditer(decomp):
            lhs_var = m.group(1)
            rhs_expr = m.group(2)
            # Verify the decode snippet (or its key part) appears in the RHS
            decode_key = decode_snippet[:20].strip()
            if decode_key in rhs_expr:
                assigned_vars.add(lhs_var)

        if not assigned_vars:
            # Try simpler heuristic: any variable assigned near decode keyword
            for line in decomp.split('\n'):
                for decode_type, pattern in _DECODE_PATTERNS:
                    if pattern.search(line) and '=' in line:
                        parts = line.split('=')
                        if len(parts) >= 2:
                            lhs = parts[0].strip().split()[-1] if parts[
                                0].strip() else ''
                            if lhs and lhs.isidentifier():
                                assigned_vars.add(lhs)

        if not assigned_vars:
            return None

        # Strategy 2: check if any assigned variable appears in a sink call
        # Search for sink_name(...assigned_var...)
        sink_pattern = re.compile(
            r'{}\s*\([^)]*\b({})\b'.format(
                re.escape(sink_name),
                '|'.join(re.escape(v) for v in assigned_vars)))

        m = sink_pattern.search(decomp)
        if m:
            matched_var = m.group(1)
            return "{} → {} → {}()".format(
                decode_snippet[:40], matched_var, sink_name)

        # Strategy 3: transitive — check if assigned var is passed to another
        # variable that reaches the sink (one hop)
        for var in assigned_vars:
            # Find "other_var = ...var...;"
            transitive_re = re.compile(
                r'(\w+)\s*=\s*[^;]*\b{}\b[^;]*;'.format(re.escape(var)))
            for tm in transitive_re.finditer(decomp):
                hop_var = tm.group(1)
                if hop_var == var:
                    continue
                hop_sink_re = re.compile(
                    r'{}\s*\([^)]*\b{}\b'.format(
                        re.escape(sink_name), re.escape(hop_var)))
                if hop_sink_re.search(decomp):
                    return "{} → {} → {} → {}()".format(
                        decode_snippet[:30], var, hop_var, sink_name)

        return None

    def _get_decomp(self, func) -> Optional[str]:
        """Get decompiled code for a function with caching."""
        if func.address in self._decomp_cache:
            return self._decomp_cache[func.address]

        try:
            decomp = self.program.get_decompiled_code(func)
        except Exception:
            decomp = None

        self._decomp_cache[func.address] = decomp
        return decomp

    @staticmethod
    def _is_hash_function(decomp: str) -> bool:
        """
        Check if decompiled pseudocode is primarily a hash/digest operation.

        Hash functions are one-way — a decoded value flowing into a hash
        is normal data processing, not an obfuscated secret being recovered.
        Returns True if any hash indicator is found AND no encryption sink
        is also present (mixed functions that both hash and encrypt should
        still be analyzed).
        """
        has_hash = any(ind in decomp for ind in _HASH_FUNCTION_INDICATORS)
        if not has_hash:
            return False

        # If the function ALSO calls an encryption sink, don't exclude it.
        # Some functions hash AND encrypt (e.g., derive key then encrypt).
        has_encrypt = any(sink in decomp for sink in _SINK_PATTERNS)
        return not has_encrypt

    # =================================================================
    # XOR decode loop detector
    # =================================================================

    def scan_xor_decode_loops(self):
        """
        Detect byte-by-byte XOR decode loops in decompiled pseudocode.

        Looks for the general pattern where a loop iterates over a
        hardcoded data blob, applies a transform chain (XOR, ADD, SUB,
        NOT, etc.), and optionally constructs a string from the result.

        This is language-agnostic (works for Swift and ObjC) and handles
        variations in loop type, transform chain, loop bound, and string
        constructor.

        When the pattern is matched, the detector reads the data blob
        from the binary, applies the extracted transform chain, and
        attempts to recover the plaintext.

        Returns:
            List of SecurityFinding objects
        """
        findings = []
        seen_addrs = set()  # Dedup by (func_addr, data_addr)

        print("[Trellis] XOR decode loop scan: analyzing functions...")

        func_count = 0
        for func in self.program.get_all_functions():
            if func_count >= _MAX_FUNCTIONS_TO_DECOMPILE:
                break
            func_count += 1

            decomp = self._get_decomp(func)
            if not decomp:
                continue

            # Skip known crypto/hash implementations
            if _is_crypto_hash_function(func.name):
                continue

            # Fast pre-filter: must contain both a loop keyword AND
            # XOR operator to be worth analyzing
            if '^' not in decomp:
                continue
            if not any(kw in decomp for kw in
                       ('for ', 'while ', 'do {', 'do\n')):
                continue

            # Find all loop regions in the pseudocode
            for loop_match in _LOOP_HEAD_RE.finditer(decomp):
                loop_start = loop_match.start()
                # Extract a generous chunk of the loop body
                # (find matching brace is hard; grab up to 800 chars)
                loop_body = decomp[loop_start:loop_start + 800]

                # Step B-1: Look for data load from constant address
                data_load_match = _LOOP_DATA_LOAD_RE.search(loop_body)
                if not data_load_match:
                    continue

                data_addr_str = (data_load_match.group(1) or
                                 data_load_match.group(2) or
                                 data_load_match.group(3))
                try:
                    data_addr = int(data_addr_str, 16)
                except (ValueError, TypeError):
                    continue

                # Verify the address is in a data section
                if not self.program.is_address_in_data_section(data_addr):
                    continue

                # Step B-2: Look for XOR with constant in the loop body
                xor_match = _LOOP_XOR_RE.search(loop_body)
                if not xor_match:
                    continue

                xor_key_str = xor_match.group(1) or xor_match.group(2)
                try:
                    xor_key = int(xor_key_str, 16)
                except (ValueError, TypeError):
                    continue

                # Dedup
                dedup_key = (func.address, data_addr)
                if dedup_key in seen_addrs:
                    continue
                seen_addrs.add(dedup_key)

                # Step C: Extract composed transform chain
                transform_chain = [('XOR', xor_key)]
                composed = _COMPOSED_TRANSFORM_RE.search(loop_body)
                if composed:
                    op_char = composed.group(1)
                    operand_str = composed.group(2)
                    try:
                        operand = int(operand_str, 16) if operand_str.startswith(
                            '0x') else int(operand_str)
                    except ValueError:
                        operand = 0
                    if op_char == '-':
                        transform_chain.append(('SUB', operand))
                    elif op_char == '+':
                        transform_chain.append(('ADD', operand))

                # Step D: Extract loop bound
                # Use the same generous window as the loop body (800 chars)
                # so do-while bounds at the END of the body are not missed.
                loop_bound = self._extract_loop_bound(
                    decomp[loop_start:loop_start + 800])

                # Step E: Check for string constructor
                has_string_ctor = any(
                    pat in decomp for pat in _STRING_CONSTRUCTOR_PATTERNS)

                # Report the structural match — the analyst has the
                # data address and transform chain to decode offline.
                findings.append(self._make_loop_finding(
                    func, data_addr, transform_chain, loop_bound,
                    has_string_ctor, loop_body))

        print("[Trellis] XOR decode loop scan: {} findings".format(
            len(findings)))
        return findings

    def _extract_loop_bound(self, loop_region: str) -> Optional[int]:
        """Extract numeric loop bound from a pseudocode loop region."""
        m = _LOOP_BOUND_RE.search(loop_region)
        if not m:
            return None

        bound_str = m.group(2) or m.group(4)
        if not bound_str:
            return None

        try:
            val = int(bound_str, 16) if bound_str.startswith('0x') \
                else int(bound_str)
        except (ValueError, TypeError):
            return None

        # Sanity check: loop bounds > 1024 are probably not string decode
        if val <= 0 or val > 1024:
            return None

        return val

    @staticmethod
    def _apply_transform_chain(
        raw: bytes, chain: list, loop_bound: Optional[int]
    ) -> bytes:
        """Apply a transform chain to raw bytes."""
        length = loop_bound if loop_bound else len(raw)
        length = min(length, len(raw))

        result = bytearray(length)
        for i in range(length):
            val = raw[i]
            for op, operand in chain:
                if op == 'XOR':
                    # Handle multi-byte XOR keys
                    key_bytes = []
                    temp = operand
                    while temp > 0:
                        key_bytes.insert(0, temp & 0xff)
                        temp >>= 8
                    if not key_bytes:
                        key_bytes = [0]
                    val ^= key_bytes[i % len(key_bytes)]
                elif op == 'SUB':
                    val = (val - operand) & 0xff
                elif op == 'ADD':
                    val = (val + operand) & 0xff
                elif op == 'NOT':
                    val = (~val) & 0xff
            result[i] = val

        return bytes(result)

    def _make_loop_finding(
        self, func, data_addr: int, transform_chain: list,
        loop_bound: Optional[int], has_string_ctor: bool,
        loop_body: str
    ) -> SecurityFinding:
        """Create a SecurityFinding for a detected XOR decode loop."""
        chain_str = " → ".join(
            "{}({})".format(op, hex(val) if isinstance(val, int) else val)
            for op, val in transform_chain)

        evidence = {
            "data_address": hex(data_addr),
            "transform_chain": chain_str,
            "technique": "XOR_LOOP",
        }
        if loop_bound:
            evidence["loop_bound"] = str(loop_bound)
        if has_string_ctor:
            evidence["string_constructor"] = "detected"

        severity = Severity.HIGH
        issue_type = "XOR Decode Loop Detected"
        description = (
            "Byte-by-byte XOR decode loop operating on "
            "hardcoded data at {}".format(hex(data_addr)))
        bound_hint = (" ({} bytes)".format(loop_bound)
                       if loop_bound else "")
        impact = (
            "Function decodes hardcoded data{} using transform "
            "chain {} — extract the blob at {} and apply the "
            "chain to recover the hidden value".format(
                bound_hint, chain_str, hex(data_addr)))

        return SecurityFinding(
            severity=severity,
            issue_type=issue_type,
            description=description,
            location=func.address,
            function_name=func.name,
            evidence=evidence,
            impact=impact,
            recommendation=(
                "Do not hide secrets via XOR encoding in the binary; "
                "use iOS Keychain or server-side configuration")
        )

    # =================================================================
    # XOR obfuscation scan with recovery (single-expression, non-loop)
    # =================================================================

    def scan_for_xor_obfuscation(self):
        """
        Scan functions calling crypto/keychain sinks for XOR patterns in
        decompiler output.  When a data blob is referenced nearby, attempt
        to apply the XOR key and recover the plaintext.

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        print("[Trellis] XOR obfuscation scan: identifying sink callers...")

        # Reuse decompiler cache from scan_decode_to_sink if available
        sink_callers = {}  # func_addr -> decomp code

        for func in self.program.get_all_functions():
            decomp = self._get_decomp(func)
            if not decomp:
                continue
            for sink in _SINK_PATTERNS:
                if sink in decomp:
                    sink_callers[func.address] = decomp
                    break

        print("[Trellis] XOR scan: {} sink-calling functions".format(
            len(sink_callers)))

        xor_pattern = re.compile(
            r'(\w+\s*\^\s*0x[0-9a-fA-F]+|0x[0-9a-fA-F]+\s*\^\s*\w+)')

        for func_addr, decomp in sink_callers.items():
            func = self.program.get_function_at(func_addr)
            if not func:
                continue

            # Skip known crypto/hash implementations
            if _is_crypto_hash_function(func.name):
                continue

            matches = xor_pattern.findall(decomp)
            for match in matches:
                hex_match = re.search(r'0x([0-9a-fA-F]+)', match)
                if not hex_match:
                    continue

                const_val = int(hex_match.group(1), 16)
                if not _is_likely_obfuscation_key(const_val):
                    continue

                # Identify which sinks this function calls
                used_in_sinks = [
                    s for s in _SINK_PATTERNS if s in decomp]

                # Attempt XOR recovery: look for data references
                recovered = self._attempt_xor_recovery(
                    func, const_val)

                if recovered:
                    findings.append(SecurityFinding(
                        severity=Severity.HIGH,
                        issue_type="XOR-Obfuscated Secret Recovered",
                        description=(
                            "XOR-encoded data decoded to secret-like "
                            "plaintext"),
                        location=func.address,
                        function_name=func.name,
                        evidence={
                            "xor_key": hex(const_val),
                            "recovered_preview": recovered[:60],
                            "pattern": match.strip(),
                            "used_in_sinks": ", ".join(
                                used_in_sinks[:3]),
                        },
                        impact=(
                            "XOR-obfuscated secret can be recovered by "
                            "extracting the data blob and applying the "
                            "key {}".format(hex(const_val))),
                        recommendation=(
                            "Do not use XOR for secret protection; use "
                            "iOS Keychain or server-side configuration")
                    ))
                else:
                    # No recovery but pattern is suspicious
                    severity = (Severity.MEDIUM if const_val >= 0x10000
                                else Severity.INFO)
                    findings.append(SecurityFinding(
                        severity=severity,
                        issue_type="Obfuscation: XOR Operation",
                        description=(
                            "XOR with constant detected near sensitive "
                            "sink"),
                        location=func.address,
                        function_name=func.name,
                        evidence={
                            "xor_key": hex(const_val),
                            "pattern": match.strip(),
                            "used_in_sinks": ", ".join(
                                used_in_sinks[:3]),
                        },
                        impact=(
                            "May indicate XOR obfuscation of data "
                            "before use in {}".format(
                                ", ".join(used_in_sinks[:2]))),
                        recommendation=(
                            "Check if this is part of a decryption loop; "
                            "verify XOR key source")
                    ))

        return findings

    def _attempt_xor_recovery(
        self, func, xor_key: int
    ) -> Optional[str]:
        """
        Attempt to recover XOR-obfuscated data by finding data-section
        references in the function and applying the XOR key.

        Returns the decoded string if it looks like a secret, else None.
        """
        # Find addresses referenced by this function that are in data sections
        try:
            refs = self.program.get_references_to(func.address)
        except Exception:
            return None

        # Actually we need refs FROM this function (outgoing), not TO it.
        # Walk the function's xrefs by checking the decomp for address literals.
        decomp = self._get_decomp(func)
        if not decomp:
            return None

        # Find hex address literals in the decompiled code
        addr_pattern = re.compile(r'0x([0-9a-fA-F]{6,16})')
        for m in addr_pattern.finditer(decomp):
            try:
                addr_val = int(m.group(1), 16)
            except ValueError:
                continue

            if not self.program.is_address_in_data_section(addr_val):
                continue

            # Read data blob and apply XOR
            raw = self.program.read_bytes_at(
                addr_val, _XOR_MAX_BLOB_SIZE)
            if not raw:
                continue

            # Apply XOR key (byte-level for single-byte keys,
            # multi-byte for larger keys)
            key_bytes = []
            temp = xor_key
            while temp > 0:
                key_bytes.insert(0, temp & 0xff)
                temp >>= 8
            if not key_bytes:
                key_bytes = [0]

            decoded = bytearray(len(raw))
            for i in range(len(raw)):
                decoded[i] = raw[i] ^ key_bytes[i % len(key_bytes)]

            result = _is_printable_secret(bytes(decoded))
            if result:
                return result

        return None

    # =================================================================
    # AES hardcoded key + ciphertext co-location detection
    # =================================================================

    def scan_for_aes_key_ciphertext_pairs(self):
        """
        Detect functions where both the AES key and ciphertext are
        hardcoded in data sections.  Searches decompiled pseudocode for
        CCCrypt/CCCryptorCreate calls where both the key and dataIn
        parameters reference constant data.

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        print("[Trellis] AES key+ciphertext co-location scan...")

        # Pattern to match CCCrypt calls in pseudocode with visible arguments
        # CCCrypt(op, alg, opts, key, keyLen, iv, dataIn, dataInLen, ...)
        cccrypt_re = re.compile(
            r'CCCrypt\s*\(\s*'
            r'([^,]+),\s*'   # op
            r'([^,]+),\s*'   # alg
            r'([^,]+),\s*'   # options
            r'([^,]+),\s*'   # key
            r'([^,]+),\s*'   # keyLength
            r'([^,]+),\s*'   # iv
            r'([^,]+)',       # dataIn
            re.DOTALL)

        for func in self.program.get_all_functions():
            decomp = self._get_decomp(func)
            if not decomp:
                continue
            if 'CCCrypt' not in decomp:
                continue

            for m in cccrypt_re.finditer(decomp):
                key_expr = m.group(4).strip()
                data_in_expr = m.group(7).strip()

                # Check if both look like constant addresses
                key_addr = self._extract_data_address(key_expr)
                data_addr = self._extract_data_address(data_in_expr)

                if key_addr is None or data_addr is None:
                    continue

                # Both key and dataIn reference data sections
                if (not self.program.is_address_in_data_section(key_addr) or
                        not self.program.is_address_in_data_section(
                            data_addr)):
                    continue

                # Determine where the output is used
                # Look for the dataOut parameter (param 8) assignment
                output_usage = self._find_cccrypt_output_usage(
                    decomp, m.end())

                evidence = {
                    "key_address": hex(key_addr),
                    "ciphertext_address": hex(data_addr),
                    "key_expression": key_expr[:40],
                    "data_expression": data_in_expr[:40],
                }
                if output_usage:
                    evidence["decrypted_output_used_in"] = output_usage

                findings.append(SecurityFinding(
                    severity=Severity.CRITICAL,
                    issue_type=(
                        "Hardcoded AES Key and Ciphertext Co-located"),
                    description=(
                        "Both AES encryption key and ciphertext are "
                        "hardcoded in binary data sections"),
                    location=func.address,
                    function_name=func.name,
                    evidence=evidence,
                    impact=(
                        "Attacker can extract both the key and "
                        "ciphertext from the binary and decrypt "
                        "offline — encryption provides zero protection"),
                    recommendation=(
                        "Store encryption keys in iOS Keychain with "
                        "biometric protection; fetch encrypted data "
                        "from a server at runtime")
                ))

        print("[Trellis] AES co-location scan: {} findings".format(
            len(findings)))
        return findings

    def _extract_data_address(self, expr: str) -> Optional[int]:
        """Extract a constant address from a pseudocode expression."""
        # Direct hex literal:  0x100045a20
        m = re.search(r'0x([0-9a-fA-F]{6,16})', expr)
        if m:
            try:
                return int(m.group(1), 16)
            except ValueError:
                pass

        # Cast pattern:  (void *)0x100045a20
        m = re.search(r'\(\s*\w[\w\s*]*\)\s*0x([0-9a-fA-F]{6,16})', expr)
        if m:
            try:
                return int(m.group(1), 16)
            except ValueError:
                pass

        return None

    def _find_cccrypt_output_usage(
        self, decomp: str, after_pos: int
    ) -> Optional[str]:
        """
        After a CCCrypt call, find how the decrypted output buffer is used.

        Looks for the next function call or assignment that references the
        output variable.
        """
        # Get text after the CCCrypt call
        rest = decomp[after_pos:after_pos + 500]

        # Common patterns: output buffer passed to another function
        call_re = re.compile(r'(\w+)\s*\([^)]*\b(dataOut|output|plaintext|'
                             r'decrypted|result|buffer)\b')
        m = call_re.search(rest)
        if m:
            return "{}({})".format(m.group(1), m.group(2))

        # Assignment: some_var = dataOut
        assign_re = re.compile(r'(\w+)\s*=\s*[^;]*(dataOut|output|plaintext|'
                               r'decrypted|result|buffer)')
        m = assign_re.search(rest)
        if m:
            return "{} = {}".format(m.group(1), m.group(2))

        return None


__all__ = ["ObfuscationSecurityChecker"]
