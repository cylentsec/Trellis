"""
Cryptography security checks for Trellis (Ghidra Port).

This module implements security analysis for cryptographic operations,
detecting weak algorithms, ECB mode, hardcoded keys, and other crypto issues.
"""

from typing import Optional, List, TYPE_CHECKING

from .security_checks import SecurityChecker, SecurityFinding, Severity

if TYPE_CHECKING:
    from ..signatures import FunctionSignature
    from .calltree import CallSite
    from .extractor import ExtractedCallInfo


# CommonCrypto algorithm constants
CC_ALGORITHM_AES = 0
CC_ALGORITHM_DES = 1
CC_ALGORITHM_3DES = 2
CC_ALGORITHM_CAST = 3
CC_ALGORITHM_RC4 = 4
CC_ALGORITHM_RC2 = 5
CC_ALGORITHM_BLOWFISH = 6

# CommonCrypto options
CC_OPTION_ECB_MODE = 0x0002
CC_OPTION_PKCS7_PADDING = 0x0001

# CCKeyDerivationPBKDF PRF algorithm constants
CC_PRF_HMAC_SHA1 = 1
CC_PRF_HMAC_SHA224 = 2
CC_PRF_HMAC_SHA256 = 3
CC_PRF_HMAC_SHA384 = 4
CC_PRF_HMAC_SHA512 = 5

# PRF algorithm names
PRF_NAMES = {
    CC_PRF_HMAC_SHA1: "HMAC-SHA1",
    CC_PRF_HMAC_SHA224: "HMAC-SHA224",
    CC_PRF_HMAC_SHA256: "HMAC-SHA256",
    CC_PRF_HMAC_SHA384: "HMAC-SHA384",
    CC_PRF_HMAC_SHA512: "HMAC-SHA512",
}

# Weak PRF algorithms for PBKDF2
WEAK_PRF_ALGORITHMS = {
    CC_PRF_HMAC_SHA1: "HMAC-SHA1",
}

# PBKDF2 thresholds
PBKDF2_ROUNDS_CRITICAL = 10000    # Below this is critically weak
PBKDF2_ROUNDS_HIGH = 100000       # Below this is weak for modern usage
PBKDF2_MIN_SALT_LEN = 8           # Minimum acceptable salt length
PBKDF2_MIN_KEY_LEN = 16           # Minimum derived key length (128 bits)

# Weak algorithms
WEAK_ALGORITHMS = {
    CC_ALGORITHM_DES: "DES",
    CC_ALGORITHM_3DES: "3DES",
    CC_ALGORITHM_RC4: "RC4",
    CC_ALGORITHM_RC2: "RC2",
}

# Algorithm names
ALGORITHM_NAMES = {
    CC_ALGORITHM_AES: "AES",
    CC_ALGORITHM_DES: "DES",
    CC_ALGORITHM_3DES: "3DES",
    CC_ALGORITHM_CAST: "CAST",
    CC_ALGORITHM_RC4: "RC4",
    CC_ALGORITHM_RC2: "RC2",
    CC_ALGORITHM_BLOWFISH: "Blowfish",
}


# Caller name patterns that indicate crypto-related context
_CRYPTO_CALLER_KEYWORDS = [
    "encrypt", "decrypt", "crypto", "cryptography", "cipher",
    "pbkdf", "derive", "hash", "digest",
    "RNEncryptor", "RNDecryptor", "SymmetricKey",
    "AES", "DES", "Blowfish", "RC4",
]


def _caller_suggests_crypto(caller_name):
    """Check if the caller function name suggests crypto context."""
    if not caller_name:
        return False
    lower = caller_name.lower()
    for kw in _CRYPTO_CALLER_KEYWORDS:
        if kw.lower() in lower:
            return True
    return False


class CryptoSecurityChecker(SecurityChecker):
    """Security checker for cryptographic operations."""
    
    def check_call_site(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check a crypto function call site for security issues."""
        findings = []
        
        has_params = extracted_info and extracted_info.parameters
        func_name = function_sig.name
        
        # Check CCCrypt / CCCryptorCreate
        if func_name in ["CCCrypt", "CCCryptorCreate", "CCCryptorCreateWithMode"]:
            if has_params:
                findings.extend(self._check_cccrypt(function_sig, call_site, extracted_info))
            # Caller-name heuristic fallback when params couldn't be extracted
            if not findings:
                findings.extend(self._check_crypto_caller_heuristic(
                    function_sig, call_site, extracted_info, "symmetric encryption"
                ))
        
        # Check CCKeyDerivationPBKDF
        elif func_name == "CCKeyDerivationPBKDF":
            if has_params:
                findings.extend(self._check_pbkdf2(function_sig, call_site, extracted_info))
            # Caller-name heuristic fallback
            if not findings:
                findings.extend(self._check_crypto_caller_heuristic(
                    function_sig, call_site, extracted_info, "key derivation"
                ))
        
        # Check weak hash functions
        elif func_name in ["CC_MD5", "CC_SHA1"]:
            if has_params:
                findings.extend(self._check_weak_hash(function_sig, call_site, extracted_info))
            # Weak hash is always reportable regardless of params
            if not findings:
                findings.extend(self._check_weak_hash(function_sig, call_site, extracted_info))
        
        return findings
    
    def _check_cccrypt(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check CCCrypt/CCCryptorCreate for security issues."""
        findings = []
        params_by_name = {p.name: p for p in extracted_info.parameters}
        
        # Check for weak algorithm
        if "alg" in params_by_name or "algorithm" in params_by_name:
            alg_param = params_by_name.get("alg") or params_by_name.get("algorithm")
            alg_value = self._get_constant_int(alg_param)
            
            if alg_value is not None and alg_value in WEAK_ALGORITHMS:
                alg_name = WEAK_ALGORITHMS[alg_value]
                findings.append(SecurityFinding(
                    severity=Severity.CRITICAL,
                    issue_type="Weak Encryption Algorithm",
                    description="Weak algorithm {} used".format(alg_name),
                    location=call_site.call_instruction_address,
                    function_name=function_sig.name,
                    evidence={"algorithm": "{} ({})".format(alg_name, alg_value)},
                    impact="{} is cryptographically broken and can be attacked".format(alg_name),
                    recommendation="Use AES-256 instead of {}".format(alg_name)
                ))
        
        # Check for ECB mode
        if "options" in params_by_name:
            options_param = params_by_name["options"]
            options_value = self._get_constant_int(options_param)
            
            if options_value is not None and (options_value & CC_OPTION_ECB_MODE):
                findings.append(SecurityFinding(
                    severity=Severity.HIGH,
                    issue_type="ECB Mode",
                    description="ECB mode encryption detected",
                    location=call_site.call_instruction_address,
                    function_name=function_sig.name,
                    evidence={"options": "0x{:x} (kCCOptionECBMode set)".format(options_value)},
                    impact="ECB mode reveals patterns in plaintext, enabling cryptanalysis",
                    recommendation="Use CBC, CTR, or GCM mode with a random IV"
                ))
        
        # Check for NULL IV in non-ECB mode
        if "iv" in params_by_name and "options" in params_by_name:
            iv_param = params_by_name["iv"]
            options_param = params_by_name["options"]
            options_value = self._get_constant_int(options_param)
            
            # If not ECB mode and IV is NULL
            if options_value is not None and not (options_value & CC_OPTION_ECB_MODE):
                if self._is_null_pointer(iv_param):
                    findings.append(SecurityFinding(
                        severity=Severity.HIGH,
                        issue_type="NULL IV",
                        description="NULL initialization vector with CBC mode",
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={"iv": "NULL", "mode": "CBC (non-ECB)"},
                        impact="NULL IV makes encryption deterministic and predictable",
                        recommendation="Generate a random IV for each encryption operation"
                    ))
        
        # Check for hardcoded key
        if "key" in params_by_name:
            key_param = params_by_name["key"]
            key_finding = self._check_hardcoded_key(
                function_sig, call_site, key_param, extracted_info
            )
            if key_finding:
                findings.append(key_finding)
        
        return findings
    
    def _check_hardcoded_key(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        key_param,
        extracted_info: "ExtractedCallInfo"
    ) -> Optional[SecurityFinding]:
        """Check if encryption key is hardcoded."""
        # If key is a constant pointer value
        key_value = self._get_constant_int(key_param)
        if key_value is not None and key_value != 0:
            # Check if it points to a data section
            if self._is_data_section(key_value):
                return SecurityFinding(
                    severity=Severity.CRITICAL,
                    issue_type="Hardcoded Encryption Key",
                    description="Encryption key loaded from hardcoded data",
                    location=call_site.call_instruction_address,
                    function_name=function_sig.name,
                    evidence={
                        "key_address": "0x{:x}".format(key_value),
                        "key_source": "Data section (hardcoded)"
                    },
                    impact="All app installations share the same key, no forward secrecy",
                    recommendation="Derive keys from user credentials or use iOS keychain"
                )
        
        return None
    
    def _check_pbkdf2(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check CCKeyDerivationPBKDF for weak parameters."""
        findings = []
        params_by_name = {p.name: p for p in extracted_info.parameters}

        # Check iteration count (rounds)
        if "rounds" in params_by_name:
            rounds_param = params_by_name["rounds"]
            rounds_value = self._get_constant_int(rounds_param)

            if rounds_value is not None:
                if rounds_value < PBKDF2_ROUNDS_CRITICAL:
                    findings.append(SecurityFinding(
                        severity=Severity.CRITICAL,
                        issue_type="Critically Low PBKDF2 Iterations",
                        description="PBKDF2 using only {} iterations (minimum {} recommended)".format(
                            rounds_value, PBKDF2_ROUNDS_CRITICAL),
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={"rounds": str(rounds_value), "minimum_recommended": str(PBKDF2_ROUNDS_HIGH)},
                        impact="Low iteration count allows brute-force key recovery in seconds",
                        recommendation="Use at least {} iterations (OWASP recommends {}+)".format(
                            PBKDF2_ROUNDS_CRITICAL, PBKDF2_ROUNDS_HIGH)
                    ))
                elif rounds_value < PBKDF2_ROUNDS_HIGH:
                    findings.append(SecurityFinding(
                        severity=Severity.HIGH,
                        issue_type="Low PBKDF2 Iterations",
                        description="PBKDF2 using {} iterations ({}+ recommended)".format(
                            rounds_value, PBKDF2_ROUNDS_HIGH),
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={"rounds": str(rounds_value), "recommended": str(PBKDF2_ROUNDS_HIGH)},
                        impact="Moderate iteration count may be brute-forceable with GPU hardware",
                        recommendation="Use at least {} iterations for PBKDF2".format(PBKDF2_ROUNDS_HIGH)
                    ))

        # Check PRF algorithm
        if "prf" in params_by_name:
            prf_param = params_by_name["prf"]
            prf_value = self._get_constant_int(prf_param)

            if prf_value is not None and prf_value in WEAK_PRF_ALGORITHMS:
                prf_name = WEAK_PRF_ALGORITHMS[prf_value]
                findings.append(SecurityFinding(
                    severity=Severity.MEDIUM,
                    issue_type="Weak PBKDF2 PRF Algorithm",
                    description="PBKDF2 using weak PRF: {}".format(prf_name),
                    location=call_site.call_instruction_address,
                    function_name=function_sig.name,
                    evidence={"prf": "{} ({})".format(prf_name, prf_value)},
                    impact="SHA-1 based PRF provides less security margin than SHA-256+",
                    recommendation="Use kCCPRFHmacAlgSHA256 or kCCPRFHmacAlgSHA512"
                ))

        # Check for hardcoded salt
        if "salt" in params_by_name:
            salt_param = params_by_name["salt"]
            salt_value = self._get_constant_int(salt_param)

            if salt_value is not None and salt_value != 0:
                if self._is_data_section(salt_value):
                    findings.append(SecurityFinding(
                        severity=Severity.HIGH,
                        issue_type="Hardcoded PBKDF2 Salt",
                        description="PBKDF2 salt loaded from hardcoded data",
                        location=call_site.call_instruction_address,
                        function_name=function_sig.name,
                        evidence={"salt_address": "0x{:x}".format(salt_value), "salt_source": "Data section (hardcoded)"},
                        impact="All users share the same salt, enabling precomputed rainbow table attacks",
                        recommendation="Generate a random salt per user/password and store alongside the derived key"
                    ))

        # Check derived key length
        if "derivedKeyLen" in params_by_name:
            keylen_param = params_by_name["derivedKeyLen"]
            keylen_value = self._get_constant_int(keylen_param)

            if keylen_value is not None and keylen_value < PBKDF2_MIN_KEY_LEN:
                findings.append(SecurityFinding(
                    severity=Severity.MEDIUM,
                    issue_type="Short PBKDF2 Derived Key",
                    description="PBKDF2 derived key is only {} bytes ({} bits)".format(
                        keylen_value, keylen_value * 8),
                    location=call_site.call_instruction_address,
                    function_name=function_sig.name,
                    evidence={"derivedKeyLen": str(keylen_value), "minimum_recommended": str(PBKDF2_MIN_KEY_LEN)},
                    impact="Short derived keys reduce the effective security of encryption",
                    recommendation="Use at least {} bytes ({} bits) for the derived key".format(
                        PBKDF2_MIN_KEY_LEN, PBKDF2_MIN_KEY_LEN * 8)
                ))

        return findings

    def _check_weak_hash(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check for weak hash algorithm usage."""
        findings = []
        func_name = function_sig.name
        
        if func_name == "CC_MD5":
            findings.append(SecurityFinding(
                severity=Severity.MEDIUM,
                issue_type="MD5 Usage",
                description="MD5 hash function used",
                location=call_site.call_instruction_address,
                function_name=func_name,
                evidence={"algorithm": "MD5"},
                impact="MD5 is cryptographically broken (acceptable for non-crypto hashing)",
                recommendation="Use SHA-256/SHA-512 for security purposes"
            ))
        elif func_name == "CC_SHA1":
            findings.append(SecurityFinding(
                severity=Severity.LOW,
                issue_type="SHA-1 Usage",
                description="SHA-1 hash function used",
                location=call_site.call_instruction_address,
                function_name=func_name,
                evidence={"algorithm": "SHA-1"},
                impact="SHA-1 is deprecated for digital signatures",
                recommendation="Use SHA-256/SHA-512 for security purposes"
            ))
        
        return findings

    def _check_crypto_caller_heuristic(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo",
        crypto_context: str
    ) -> List[SecurityFinding]:
        """
        Fallback check using caller function name when parameter extraction fails.

        When the decompiler can't resolve parameter values (common with Swift-to-C
        bridged calls), the caller function name often reveals the security context.
        For example, a caller named 'BrokenCryptographyPinDetailsViewController...pbkdf2'
        clearly indicates a crypto operation that needs manual review.
        """
        findings = []
        caller_name = call_site.caller_name if call_site else None

        if not caller_name:
            return findings

        if _caller_suggests_crypto(caller_name):
            # Demangle Swift symbol for readable evidence
            display_caller = caller_name
            if len(display_caller) > 80:
                display_caller = display_caller[:77] + "..."

            findings.append(SecurityFinding(
                severity=Severity.MEDIUM,
                issue_type="Crypto Call — Manual Review Required",
                description="{} call in crypto-related function (parameters unresolved)".format(
                    function_sig.name),
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={
                    "caller": display_caller,
                    "crypto_context": crypto_context,
                    "note": "Parameter values could not be extracted from decompiler; "
                            "manual review needed to determine algorithm, key, rounds, etc."
                },
                impact="Crypto implementation may use weak parameters (algorithm, key size, "
                       "iteration count) but static analysis could not confirm",
                recommendation="Use Frida to hook {} at runtime and inspect actual parameters, "
                               "or analyze the caller function in Ghidra decompiler".format(
                                   function_sig.name)
            ))

        return findings


__all__ = ["CryptoSecurityChecker"]
