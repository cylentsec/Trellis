"""
CryptoKit security checks for Trellis (Ghidra Port).

This module implements security analysis for Apple's CryptoKit framework operations,
detecting insecure configurations in Swift-native cryptography.
"""

from typing import Optional, List, TYPE_CHECKING

from .security_checks import SecurityChecker, SecurityFinding, Severity

if TYPE_CHECKING:
    from ..signatures import FunctionSignature
    from .calltree import CallSite
    from .extractor import ExtractedCallInfo


class CryptoKitSecurityChecker(SecurityChecker):
    """Security checker for CryptoKit operations."""

    def check_call_site(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check a CryptoKit function call site for security issues."""
        findings = []

        if not extracted_info or not extracted_info.parameters:
            return findings

        func_name = function_sig.name

        # Hashing
        if func_name == "SHA256.hash" or "SHA256" in func_name and "hash" in func_name:
            findings.extend(self._check_sha256_usage(function_sig, call_site, extracted_info))

        # Encryption (AES-GCM)
        elif "AES.GCM.seal" in func_name or ("AES" in func_name and "GCM" in func_name and "seal" in func_name):
            findings.extend(self._check_aes_gcm(function_sig, call_site, extracted_info))

        # Encryption (ChaChaPoly)
        elif "ChaChaPoly.seal" in func_name or ("ChaChaPoly" in func_name and "seal" in func_name):
            findings.extend(self._check_chacha_poly(function_sig, call_site, extracted_info))

        # Key Agreement
        elif "Curve25519" in func_name and "KeyAgreement" in func_name and "PrivateKey" in func_name:
            findings.extend(self._check_key_agreement(function_sig, call_site, extracted_info))

        # Signatures
        elif "P256" in func_name and "Signing" in func_name and "PrivateKey" in func_name:
            findings.extend(self._check_signing_key(function_sig, call_site, extracted_info))

        # Key Derivation
        elif "HKDF" in func_name and "deriveKey" in func_name:
            findings.extend(self._check_hkdf(function_sig, call_site, extracted_info))

        # Symmetric key creation
        elif "SymmetricKey" in func_name:
            findings.extend(self._check_symmetric_key(function_sig, call_site, extracted_info))

        return findings

    def _check_sha256_usage(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check SHA256 usage."""
        findings = []
        # SHA256 is secure for general hashing, just log INFO
        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="CryptoKit Hashing",
            description="SHA256 hash operation via CryptoKit",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"algorithm": "SHA256"},
            impact="SHA256 is secure for general hashing but not for password storage",
            recommendation="For passwords, use PBKDF2 or Argon2 instead"
        ))
        return findings

    def _check_aes_gcm(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check AES.GCM.seal usage."""
        findings = []
        params_by_name = {p.name: p for p in extracted_info.parameters}

        # Check for hardcoded key
        key_param = params_by_name.get("key") or params_by_name.get("using")
        if key_param and self._is_constant_value(key_param):
            findings.append(SecurityFinding(
                severity=Severity.CRITICAL,
                issue_type="Hardcoded CryptoKit Key",
                description="AES-GCM key appears to be hardcoded",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"key_param": str(key_param.value_if_constant)},
                impact="Hardcoded keys allow attackers to decrypt all data",
                recommendation="Use Keychain or Secure Enclave for key storage"
            ))

        # Check for hardcoded nonce (IV)
        nonce_param = params_by_name.get("nonce")
        if nonce_param and self._is_constant_value(nonce_param):
            findings.append(SecurityFinding(
                severity=Severity.CRITICAL,
                issue_type="Hardcoded AES-GCM Nonce",
                description="AES-GCM nonce (IV) appears to be hardcoded",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"nonce_param": str(nonce_param.value_if_constant)},
                impact="Nonce reuse in GCM mode is catastrophic (leaks key stream)",
                recommendation="Generate a random unique nonce for every encryption"
            ))

        # If no issues found, report INFO about AES-GCM usage
        if not findings:
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="CryptoKit AES-GCM Encryption",
                description="AES-GCM authenticated encryption via CryptoKit",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"algorithm": "AES-GCM"},
                impact="AES-GCM provides authenticated encryption",
                recommendation="Ensure unique nonces and secure key storage"
            ))

        return findings

    def _check_chacha_poly(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check ChaChaPoly.seal usage."""
        findings = []
        params_by_name = {p.name: p for p in extracted_info.parameters}

        # Check for hardcoded key
        key_param = params_by_name.get("key") or params_by_name.get("using")
        if key_param and self._is_constant_value(key_param):
            findings.append(SecurityFinding(
                severity=Severity.CRITICAL,
                issue_type="Hardcoded CryptoKit Key",
                description="ChaChaPoly key appears to be hardcoded",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"key_param": str(key_param.value_if_constant)},
                impact="Hardcoded keys allow attackers to decrypt all data",
                recommendation="Use Keychain or Secure Enclave for key storage"
            ))

        # Check for hardcoded nonce
        nonce_param = params_by_name.get("nonce")
        if nonce_param and self._is_constant_value(nonce_param):
            findings.append(SecurityFinding(
                severity=Severity.CRITICAL,
                issue_type="Hardcoded ChaChaPoly Nonce",
                description="ChaChaPoly nonce (IV) appears to be hardcoded",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"nonce_param": str(nonce_param.value_if_constant)},
                impact="Nonce reuse destroys security guarantees",
                recommendation="Generate a random unique nonce for every encryption"
            ))

        # If no issues found, report INFO
        if not findings:
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="CryptoKit ChaChaPoly Encryption",
                description="ChaCha20-Poly1305 authenticated encryption via CryptoKit",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"algorithm": "ChaCha20-Poly1305"},
                impact="ChaCha20-Poly1305 provides authenticated encryption",
                recommendation="Ensure unique nonces and secure key storage"
            ))

        return findings

    def _check_key_agreement(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check KeyAgreement private key usage."""
        findings = []
        
        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="CryptoKit Key Agreement",
            description="Curve25519 key agreement operation",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"algorithm": "Curve25519 ECDH"},
            impact="Key agreement used for secure key exchange",
            recommendation="Ensure private keys are stored securely (Keychain/Secure Enclave)"
        ))
        
        return findings

    def _check_signing_key(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check Signing private key usage."""
        findings = []
        
        findings.append(SecurityFinding(
            severity=Severity.INFO,
            issue_type="CryptoKit Signing Key",
            description="P-256 ECDSA signing key operation",
            location=call_site.call_instruction_address,
            function_name=function_sig.name,
            evidence={"algorithm": "P-256 ECDSA"},
            impact="Digital signatures for authenticity verification",
            recommendation="Ensure private keys are stored in Secure Enclave"
        ))
        
        return findings

    def _check_hkdf(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check HKDF usage."""
        findings = []
        params_by_name = {p.name: p for p in extracted_info.parameters}

        # Check for weak/empty salt
        salt_param = params_by_name.get("salt")
        if salt_param and self._is_constant_value(salt_param):
            salt_value = self._get_constant_int(salt_param)
            if salt_value == 0:
                findings.append(SecurityFinding(
                    severity=Severity.MEDIUM,
                    issue_type="Weak HKDF Salt",
                    description="HKDF using empty or zero salt",
                    location=call_site.call_instruction_address,
                    function_name=function_sig.name,
                    evidence={"salt": "empty/zero"},
                    impact="Empty salt reduces key derivation security",
                    recommendation="Use a random salt for each key derivation"
                ))

        if not findings:
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="CryptoKit Key Derivation",
                description="HKDF key derivation operation",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"algorithm": "HKDF"},
                impact="Key derivation from input keying material",
                recommendation="Ensure unique salt per derivation"
            ))

        return findings

    def _check_symmetric_key(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """Check SymmetricKey creation."""
        findings = []
        params_by_name = {p.name: p for p in extracted_info.parameters}

        # Check for hardcoded key data
        data_param = params_by_name.get("data")
        if data_param and self._is_constant_value(data_param):
            findings.append(SecurityFinding(
                severity=Severity.CRITICAL,
                issue_type="Hardcoded Symmetric Key",
                description="SymmetricKey created from hardcoded data",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"data_source": "constant"},
                impact="Hardcoded keys can be extracted from the binary",
                recommendation="Generate keys randomly or derive from secure sources"
            ))

        if not findings:
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="CryptoKit Symmetric Key",
                description="SymmetricKey creation",
                location=call_site.call_instruction_address,
                function_name=function_sig.name,
                evidence={"type": "SymmetricKey"},
                impact="Symmetric key for encryption/HMAC operations",
                recommendation="Store keys securely in Keychain"
            ))

        return findings


__all__ = ["CryptoKitSecurityChecker"]
