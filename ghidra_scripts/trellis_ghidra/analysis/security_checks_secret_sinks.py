# -*- coding: utf-8 -*-
"""
Sensitive sink analysis for Trellis (Ghidra port).

This module traces data flow from hardcoded/obfuscated sources to sensitive 
security sinks, such as crypto functions, keychain operations, and network requests.
"""

from typing import List, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from ..ghidra_api import GhidraProgram
    from .finder import FoundFunction
    from .calltree import CallSite
    from .extractor import ExtractedCallInfo

from .security_checks import SecurityChecker, SecurityFinding, Severity


# Definition of sensitive sinks
# Maps function name to parameter indices and descriptions
SENSITIVE_SINKS = {
    # Crypto Sinks
    "CCCrypt": {"indices": [3], "desc": "Encryption Key"},  # param 3 is key
    "CCCryptorCreate": {"indices": [3], "desc": "Encryption Key"},
    "CCHmac": {"indices": [1], "desc": "HMAC Key"},
    "CCKeyDerivationPBKDF": {"indices": [1], "desc": "Password for Key Derivation"},
    
    # Keychain Sinks
    "SecItemAdd": {"indices": [0], "desc": "Keychain Item Dictionary"},
    "SecItemUpdate": {"indices": [1], "desc": "Keychain Update Attributes"},
    
    # Network Header Sinks (ObjC selectors - checked via string matching)
    "setValue:forHTTPHeaderField:": {"indices": [0], "desc": "HTTP Header Value"},
    "addValue:forHTTPHeaderField:": {"indices": [0], "desc": "HTTP Header Value"},
}


class SecretSinkSecurityChecker(SecurityChecker):
    """Analyzes data flow from hardcoded strings to sensitive sinks."""

    def check_call_site(self, function_sig, call_site, extracted_info):
        """Check if hardcoded strings flow into sensitive sinks."""
        findings = []
        func_name = function_sig.name

        # Check if this is a sensitive sink
        config = None
        for sink_name, sink_config in SENSITIVE_SINKS.items():
            if sink_name in func_name:
                config = sink_config
                break

        if not config:
            return findings

        # Check parameters for hardcoded values
        if not extracted_info or not extracted_info.parameters:
            return findings

        for idx in config.get("indices", []):
            if idx >= len(extracted_info.parameters):
                continue

            param = extracted_info.parameters[idx]

            # Check if parameter is a string constant
            if param.value_as_string:
                # Hardcoded string directly passed to sink
                findings.append(SecurityFinding(
                    severity=Severity.HIGH,
                    issue_type="Hardcoded Secret in Sink",
                    description=f"Hardcoded string passed to {config['desc']} sink",
                    location=call_site.call_instruction_address,
                    function_name=call_site.caller_name,
                    evidence={
                        "sink": func_name,
                        "value": param.value_as_string[:50],  # Truncate
                        "param_index": idx,
                        "full_value_length": len(param.value_as_string)
                    },
                    impact="Secret is hardcoded and easily extractable from binary",
                    recommendation="Store secrets in Keychain with proper access control, or load from secure configuration"
                ))

            # Check if parameter is a constant from data section
            elif param.value_if_constant is not None:
                addr = param.value_if_constant
                if self.program.is_address_in_data_section(addr):
                    # Constant data address (possible obfuscated key/data)
                    findings.append(SecurityFinding(
                        severity=Severity.MEDIUM,
                        issue_type="Constant Data in Sink",
                        description=f"Constant data passed to {config['desc']} sink",
                        location=call_site.call_instruction_address,
                        function_name=call_site.caller_name,
                        evidence={
                            "sink": func_name,
                            "data_address": hex(addr),
                            "param_index": idx,
                        },
                        impact="Data may be easily extracted; check if obfuscated or encrypted",
                        recommendation="Verify data is properly encrypted/obfuscated before use"
                    ))

        return findings


__all__ = ["SecretSinkSecurityChecker"]
