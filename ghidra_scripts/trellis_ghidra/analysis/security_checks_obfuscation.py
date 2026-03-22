# -*- coding: utf-8 -*-
"""
Obfuscation pattern detection for Trellis (Ghidra port).

This module analyzes decompiled code to detect common string obfuscation and
encoding patterns used to hide secrets, such as Base64 decoding, Hex decoding,
and XOR operations.
"""

import re
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from ..ghidra_api import GhidraProgram
    from .finder import FoundFunction
    from .calltree import CallSite
    from .extractor import ExtractedCallInfo

from .security_checks import SecurityChecker, SecurityFinding, Severity


# XOR constants that are likely NOT obfuscation (false positives)
# These are common patterns for boolean/bit manipulation, not string decryption
FALSE_POSITIVE_XOR_KEYS = {
    0x1,            # Boolean negation (! operator)
    0x2,            # Bit 1 toggle
    0x4,            # Bit 2 toggle
    0x8,            # Bit 3 toggle
    0x10,           # Bit 4 toggle
    0x20,           # Bit 5 toggle
    0x40,           # Bit 6 toggle
    0x80,           # Sign bit for bytes / bit 7 toggle
    0xff,           # Byte inversion (~x for uint8)
    0xffff,         # 16-bit inversion
    0x8000,         # Sign bit for 16-bit
    0x80000000,     # Sign bit for 32-bit integers
    0xffffffff,     # 32-bit inversion (~x for uint32)
    0x8000000000000000,  # Sign bit for 64-bit
    0xffffffffffffffff,  # 64-bit inversion
}


def _is_likely_obfuscation_key(const_val: int) -> bool:
    """
    Determine if an XOR constant is likely used for obfuscation vs simple bit ops.

    True obfuscation keys typically:
    - Are larger than single-byte values
    - Have multiple bits set (not power of 2)
    - Are not common bit manipulation patterns
    """
    if const_val in FALSE_POSITIVE_XOR_KEYS:
        return False

    # Mask to 64-bit for consistent handling
    const_val = const_val & 0xffffffffffffffff

    # Single bit set = likely bit flag manipulation, not obfuscation
    if const_val != 0 and (const_val & (const_val - 1)) == 0:
        return False

    # Very small values (< 256) with few bits are usually not obfuscation
    if const_val < 0x100:
        bit_count = bin(const_val).count('1')
        if bit_count <= 2:
            return False

    # Values >= 0x10000 (16-bit+) with multiple bits are likely obfuscation
    if const_val >= 0x10000:
        return True

    # 8-16 bit values: only flag if they have 4+ bits set (looks more like a key)
    if const_val >= 0x100:
        bit_count = bin(const_val).count('1')
        return bit_count >= 4

    return False


class ObfuscationSecurityChecker(SecurityChecker):
    """Security checker for obfuscation patterns (Base64, Hex, XOR)."""

    def check_call_site(self, function_sig, call_site, extracted_info):
        """Check Base64/Hex decode API calls."""
        findings = []
        func_name = function_sig.name

        # Determine obfuscation type
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
            # Try to extract input string from extracted_info
            input_val = None
            if extracted_info and extracted_info.params:
                for param in extracted_info.params:
                    if param.value_as_string:
                        input_val = param.value_as_string
                        break

            evidence = {"function": func_name}
            if input_val:
                evidence["input"] = input_val[:100]  # Truncate long inputs

            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="Obfuscation: Base64 Decode",
                description="Base64 decoding detected",
                location=call_site.call_instruction_address,
                function_name=call_site.caller_name,
                evidence=evidence,
                impact="May be used to hide secrets or configuration",
                recommendation="Inspect decoded value for sensitive data (API keys, passwords, URLs)"
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

    def scan_for_xor_obfuscation(self):
        """
        Scan functions calling crypto/keychain sinks for XOR patterns in decompiler output.

        This is a standalone scan that looks for XOR operations with constants
        in functions that handle sensitive data.

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        # Get functions that call sensitive sinks (crypto, keychain, network)
        sensitive_sinks = {
            "CCCrypt", "CCCryptorCreate", "SecItemAdd", "SecItemUpdate",
            "NSURLSession", "URLSession", "CFHTTPMessage"
        }

        sink_callers = set()
        for func in self.program.get_all_functions():
            try:
                decomp = self.program.get_decompiled_code(func)
                if decomp:
                    for sink in sensitive_sinks:
                        if sink in decomp:
                            sink_callers.add(func.address)
                            break
            except Exception:
                continue

        # Analyze sink callers for XOR patterns
        for func_addr in sink_callers:
            func = self.program.get_function_at(func_addr)
            if not func:
                continue

            try:
                decomp = self.program.get_decompiled_code(func)
                if not decomp:
                    continue

                # Search for XOR patterns: variable ^ 0x<hex constant>
                # Pattern: matches "var ^ 0x1234" or "0x1234 ^ var"
                xor_pattern = re.compile(r'(\w+\s*\^\s*0x[0-9a-fA-F]+|0x[0-9a-fA-F]+\s*\^\s*\w+)')
                matches = xor_pattern.findall(decomp)

                for match in matches:
                    # Extract the hex constant
                    hex_match = re.search(r'0x([0-9a-fA-F]+)', match)
                    if not hex_match:
                        continue

                    const_val = int(hex_match.group(1), 16)

                    # Filter false positives
                    if not _is_likely_obfuscation_key(const_val):
                        continue

                    # Determine severity based on key size
                    if const_val >= 0x10000:
                        severity = Severity.MEDIUM
                        description = "XOR with large constant detected (likely obfuscation)"
                    else:
                        severity = Severity.INFO
                        description = "XOR operation with constant detected"

                    findings.append(SecurityFinding(
                        severity=severity,
                        issue_type="Obfuscation: XOR Operation",
                        description=description,
                        location=func.address,
                        function_name=func.name,
                        evidence={
                            "xor_key": hex(const_val),
                            "pattern": match.strip()
                        },
                        impact="May indicate simple XOR obfuscation of strings/data before crypto/keychain",
                        recommendation="Check if this is part of a decryption loop; verify XOR key source"
                    ))

            except Exception:
                continue

        return findings


__all__ = ["ObfuscationSecurityChecker"]
