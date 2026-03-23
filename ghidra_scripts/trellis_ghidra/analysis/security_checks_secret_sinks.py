# -*- coding: utf-8 -*-
"""
Sensitive sink analysis for Trellis (Ghidra port).

This module traces data flow from hardcoded/obfuscated sources to sensitive 
security sinks, such as crypto functions, keychain operations, and network requests.
"""

import re
from typing import List, Dict, Set, Optional, TYPE_CHECKING

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


# Patterns for identifying secret-like strings in decompiled output
_DECOMPILER_STRING_RE = re.compile(r'"([^"]{8,80})"')

# Crypto/encryption related function name keywords
_CRYPTO_SINK_KEYWORDS = [
    'encrypt', 'decrypt', 'crypto', 'cipher', 'aes', 'des',
    'RNEncryptor', 'RNDecryptor', 'CCCrypt', 'CCKey',
    'SymmetricKey', 'hmac', 'pbkdf', 'derive',
]

# Maximum call-chain depth for interprocedural xref analysis
_MAX_CALL_CHAIN_DEPTH = 3

# Crypto/encryption ObjC selectors that indicate a function calls crypto code.
# Used by the forward-search strategy to bridge objc_msgSend dispatch.
_CRYPTO_SELECTORS = [
    'encryptData:', 'decryptData:', 'encryptData:with', 'decryptData:with',
    'RNEncryptor', 'RNDecryptor',
    'initWithOperation:settings:key:', 'initWithPassword:',
    'CCCrypt', 'CCCryptorCreate', 'CCKeyDerivation',
    'SecItemAdd', 'SecItemUpdate',
    'evaluateJavaScript:',
]


class SecretSinkSecurityChecker(SecurityChecker):
    """Analyzes data flow from hardcoded strings to sensitive sinks."""

    def __init__(self, program):
        super().__init__(program)
        self._secret_strings = None  # Lazy: set of (address, value) from StringScan
        self._reported_forward_matches = set()  # Dedup: (func_addr, secret_addr, sel_name)

    def set_secret_strings(self, secret_findings):
        """
        Accept CRITICAL/HIGH string findings from StringTableSecurityChecker
        to enable cross-reference fallback when parameter extraction fails.

        Args:
            secret_findings: List of SecurityFinding from string scan
        """
        self._secret_strings = {}
        for f in secret_findings:
            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                addr = f.location
                val = f.evidence.get("value", f.evidence.get(
                    "value_preview", f.evidence.get("string_value", "")))
                if val:
                    self._secret_strings[addr] = val
        print("[Trellis] SecretSinkChecker: loaded {} secret strings for xref".format(
            len(self._secret_strings)))
        for addr, val in list(self._secret_strings.items())[:5]:
            print("[Trellis]   {} = {}".format(hex(addr), val[:40]))

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

        # --- Primary path: parameter extraction succeeded ---
        if extracted_info and extracted_info.parameters:
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
                        description="Hardcoded string passed to {} sink".format(
                            config['desc']),
                        location=call_site.call_instruction_address,
                        function_name=call_site.caller_name,
                        evidence={
                            "sink": func_name,
                            "value": param.value_as_string[:50],
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
                        findings.append(SecurityFinding(
                            severity=Severity.MEDIUM,
                            issue_type="Constant Data in Sink",
                            description="Constant data passed to {} sink".format(
                                config['desc']),
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

        # --- Fallback path: parameter extraction failed ---
        # Use string-table cross-reference to find secrets in the caller
        if not findings:
            findings.extend(self._xref_fallback(
                function_sig, call_site, config
            ))

        return findings

    def _xref_fallback(self, function_sig, call_site, config):
        """
        Fallback: when parameter extraction fails, walk up the call chain
        to find functions that reference known secret strings.

        Uses interprocedural BFS: starting from the sink's direct caller,
        walk callers-of-callers up to _MAX_CALL_CHAIN_DEPTH hops. At each
        hop, check if the function references any known secret string.

        This catches patterns like:
          textFieldShouldReturn (has secret) → RNEncryptor.encryptData → CCCrypt (sink)
        """
        findings = []

        if not self._secret_strings:
            return findings

        caller_name = call_site.caller_name if call_site else None
        if not caller_name:
            return findings

        # Get the direct caller function
        caller_func = None
        try:
            caller_func = self.program.get_function_containing(
                call_site.call_instruction_address
            )
        except Exception:
            return findings

        if not caller_func:
            return findings

        # --- Interprocedural BFS up the call chain ---
        matched = self._find_secret_in_call_chain(caller_func)

        for secret_addr, secret_value, chain in matched:
            chain_display = " → ".join(n[:40] for n in chain)
            findings.append(SecurityFinding(
                severity=Severity.CRITICAL,
                issue_type="Hardcoded Secret Flows to Crypto Sink",
                description="Hardcoded secret reaches {} sink via call chain".format(
                    function_sig.name),
                location=call_site.call_instruction_address,
                function_name=caller_name,
                evidence={
                    "sink": function_sig.name,
                    "sink_type": config["desc"],
                    "secret_value": secret_value[:50],
                    "secret_address": hex(secret_addr),
                    "call_chain": chain_display,
                    "chain_depth": str(len(chain)),
                    "detection_method": "interprocedural_xref",
                },
                impact="Hardcoded secret is used in {} — all app installations "
                       "share the same key/password".format(config["desc"]),
                recommendation="Derive keys from user input at runtime or use "
                               "iOS Keychain for secret storage"
            ))

        # Strategy 2: Forward search — check if any secret-holding function
        # also references crypto selectors (bridges objc_msgSend dispatch)
        if not findings:
            findings.extend(self._forward_selector_search(
                function_sig, call_site, config
            ))

        # Strategy 3: Decompile the direct caller and search for string literals
        if not findings:
            findings.extend(self._decompiler_string_scan(
                function_sig, call_site, config, caller_func
            ))

        return findings

    def _find_secret_in_call_chain(self, start_func):
        """
        BFS up the call chain from start_func, checking each function
        for references to known secret strings.

        Args:
            start_func: GhidraFunction to start traversal from

        Returns:
            List of (secret_addr, secret_value, call_chain_names) tuples.
            call_chain_names is the list of function names from the secret
            source down to start_func.
        """
        if not self._secret_strings:
            return []

        # Build a cache of which functions reference which secrets
        # (avoids re-querying xrefs at every hop)
        if not hasattr(self, '_secret_ref_cache'):
            self._secret_ref_cache = self._build_secret_ref_cache()

        results = []
        # BFS queue: (function_address, depth, chain_names)
        visited = set()
        queue = [(start_func.address, 0, [start_func.name])]
        visited.add(start_func.address)

        while queue:
            func_addr, depth, chain = queue.pop(0)

            # Check if this function references any secret
            if func_addr in self._secret_ref_cache:
                for secret_addr, secret_value in self._secret_ref_cache[func_addr]:
                    # chain is ordered from sink-caller outward; reverse for display
                    display_chain = list(reversed(chain))
                    results.append((secret_addr, secret_value, display_chain))

            # Stop expanding if we've hit max depth
            if depth >= _MAX_CALL_CHAIN_DEPTH:
                continue

            # Find callers of this function and add to queue
            try:
                callers = self.program.get_callers(func_addr)
                for ref in callers:
                    caller_func = self.program.get_function_containing(ref.from_address)
                    if caller_func and caller_func.address not in visited:
                        visited.add(caller_func.address)
                        queue.append((
                            caller_func.address,
                            depth + 1,
                            chain + [caller_func.name]
                        ))
            except Exception:
                continue

        return results

    def _forward_selector_search(self, function_sig, call_site, config):
        """
        Forward search: for each function that references a known secret,
        check if that function also references crypto-related ObjC selectors.

        This bridges the objc_msgSend gap. In ObjC, the call from
        textFieldShouldReturn to RNEncryptor.encryptData goes through
        objc_msgSend — invisible to get_callers(). But the caller function
        DOES reference the selector string 'encryptData:withSettings:password:error:'.
        If a function references both a secret AND a crypto selector, the
        secret flows to crypto code.
        """
        findings = []

        if not self._secret_strings:
            return findings

        # Build the secret-ref cache if not already done
        if not hasattr(self, '_secret_ref_cache'):
            self._secret_ref_cache = self._build_secret_ref_cache()

        # Build crypto-selector address cache (once)
        if not hasattr(self, '_crypto_selector_addrs'):
            self._crypto_selector_addrs = self._build_crypto_selector_cache()

        if not self._crypto_selector_addrs:
            return findings

        # For each function that references a secret, check if it also
        # references a crypto selector
        for func_addr, secrets in self._secret_ref_cache.items():
            # Get all strings referenced by this function by checking
            # if any crypto selector address is also referenced from here
            for sel_addr, sel_name in self._crypto_selector_addrs:
                try:
                    refs = self.program.get_references_to(sel_addr)
                    for ref in refs:
                        ref_func = self.program.get_function_containing(ref.from_address)
                        if ref_func and ref_func.address == func_addr:
                            # This function references BOTH a secret AND a crypto selector
                            for secret_addr, secret_value in secrets:
                                # Deduplicate across multiple check_call_site invocations
                                dedup_key = (func_addr, secret_addr, sel_name)
                                if dedup_key in self._reported_forward_matches:
                                    continue
                                self._reported_forward_matches.add(dedup_key)

                                func_obj = self.program.get_function_at(func_addr)
                                func_name = func_obj.name if func_obj else hex(func_addr)
                                findings.append(SecurityFinding(
                                    severity=Severity.CRITICAL,
                                    issue_type="Hardcoded Secret Flows to Crypto Sink",
                                    description="Function references both hardcoded secret "
                                                "and crypto selector '{}'".format(sel_name),
                                    location=func_addr,
                                    function_name=func_name,
                                    evidence={
                                        "sink": sel_name,
                                        "sink_type": "Crypto operation (ObjC dispatch)",
                                        "secret_value": secret_value[:50],
                                        "secret_address": hex(secret_addr),
                                        "crypto_selector": sel_name,
                                        "detection_method": "forward_selector_search",
                                    },
                                    impact="Hardcoded secret is passed to crypto operation "
                                           "via ObjC message dispatch",
                                    recommendation="Derive keys from user input at runtime "
                                                   "or use iOS Keychain for secret storage"
                                ))
                            # Found a match for this function, stop checking selectors
                            raise StopIteration
                except StopIteration:
                    break
                except Exception:
                    continue

        return findings

    def _build_crypto_selector_cache(self):
        """
        Find addresses of crypto-related ObjC selector strings in the binary.

        Returns list of (address, selector_name) tuples.
        """
        results = []
        for address, string_value in self.program.get_defined_strings():
            if not string_value:
                continue
            for sel in _CRYPTO_SELECTORS:
                if sel in string_value and ':' in string_value:
                    results.append((address, string_value))
                    break

        print("[Trellis] SecretSinkChecker: found {} crypto selector strings".format(
            len(results)))
        return results

    def _build_secret_ref_cache(self):
        """
        Build a lookup: function_address → [(secret_addr, secret_value), ...]

        Queries xrefs for every known secret string once and caches the
        result for reuse across all call-chain traversals.
        """
        cache = {}  # func_addr -> list of (secret_addr, secret_value)

        for secret_addr, secret_value in self._secret_strings.items():
            try:
                refs = self.program.get_references_to(secret_addr)
                for ref in refs:
                    func = self.program.get_function_containing(ref.from_address)
                    if func:
                        if func.address not in cache:
                            cache[func.address] = []
                        cache[func.address].append((secret_addr, secret_value))
            except Exception:
                continue

        print("[Trellis] SecretSinkChecker: built secret-ref cache with {} functions".format(
            len(cache)))
        for func_addr, secrets in list(cache.items())[:5]:
            print("[Trellis]   func {} refs {} secrets".format(
                hex(func_addr), len(secrets)))

        return cache

    def _decompiler_string_scan(self, function_sig, call_site, config, caller_func):
        """
        Decompile the caller function and search for string literals
        that look like secrets (high entropy, special chars).

        This catches cases where backward-slice fails but the decompiler
        still shows the string in the pseudocode.
        """
        findings = []

        try:
            decomp_code = self.program.get_decompiled_code(caller_func)
        except Exception:
            return findings

        if not decomp_code:
            return findings

        # Check if the sink function is called in this decompiled code
        if function_sig.name not in decomp_code:
            return findings

        # Extract string literals from decompiled code
        for match in _DECOMPILER_STRING_RE.finditer(decomp_code):
            literal = match.group(1)
            # Check if it looks like a secret (has special chars + alpha)
            has_special = bool(re.search(r'[@#$%^&*!]', literal))
            has_alpha = bool(re.search(r'[a-zA-Z]', literal))
            if has_special and has_alpha and len(literal) >= 10:
                findings.append(SecurityFinding(
                    severity=Severity.HIGH,
                    issue_type="Hardcoded Secret in Decompiled Sink Caller",
                    description="String literal in function calling {} sink".format(
                        function_sig.name),
                    location=call_site.call_instruction_address,
                    function_name=call_site.caller_name or "<unknown>",
                    evidence={
                        "sink": function_sig.name,
                        "sink_type": config["desc"],
                        "string_literal": literal[:50],
                        "detection_method": "decompiler_string_scan",
                    },
                    impact="String literal found in decompiled code near crypto "
                           "sink — likely a hardcoded key or password",
                    recommendation="Replace hardcoded secret with runtime-derived "
                                   "key or iOS Keychain"
                ))

        return findings


__all__ = ["SecretSinkSecurityChecker"]
