# -*- coding: utf-8 -*-
"""
PCI data flow security checks for Trellis (Ghidra Port).

This module detects when payment card data (credit card numbers, CVV, cardholder
names) is transmitted over cleartext HTTP connections. It cross-references
PCI-related string literals with HTTP URL strings within the same function scope.

This catches patterns like TransportLayerProtectionViewController posting
card_number, card_name, card_cvv to http://example.com/ — a CRITICAL finding
that pure URL-based scanning rates as only MEDIUM because the URL path doesn't
contain sensitive keywords like /payment/.
"""

import re
from typing import List, TYPE_CHECKING

from .security_checks import SecurityChecker, SecurityFinding, Severity

if TYPE_CHECKING:
    from ..ghidra_api import GhidraProgram


# PCI/payment-related string patterns in field names and dictionary keys
_PCI_FIELD_PATTERNS = [
    re.compile(r'card[_\-\s]?number', re.IGNORECASE),
    re.compile(r'card[_\-\s]?num', re.IGNORECASE),
    re.compile(r'card[_\-\s]?cvv', re.IGNORECASE),
    re.compile(r'card[_\-\s]?cvc', re.IGNORECASE),
    re.compile(r'card[_\-\s]?name', re.IGNORECASE),
    re.compile(r'card[_\-\s]?holder', re.IGNORECASE),
    re.compile(r'credit[_\-\s]?card', re.IGNORECASE),
    re.compile(r'card[_\-\s]?expir', re.IGNORECASE),
    re.compile(r'\bCVV\b'),
    re.compile(r'\bCVC\b'),
    re.compile(r'\bPAN\b'),
    re.compile(r'account[_\-\s]?number', re.IGNORECASE),
]

# HTTP cleartext URL pattern
_HTTP_URL_RE = re.compile(r'^http://', re.IGNORECASE)


class PCIDataFlowChecker(SecurityChecker):
    """
    Detects PCI data (credit card info) sent over cleartext HTTP.

    Strategy:
    1. Scan the string table for PCI field names (card_number, cvv, etc.)
    2. For each PCI string, find which functions reference it
    3. Check if those same functions also reference an http:// URL
    4. If both are in the same function, flag as CRITICAL
    """

    def check_call_site(self, function_sig, call_site, extracted_info):
        """No-op — this checker uses scan_pci_data_flow() instead."""
        return []

    def scan_pci_data_flow(self):
        """
        Scan for PCI data flowing to cleartext HTTP endpoints.

        Returns:
            List of SecurityFinding objects.
        """
        findings = []

        # Step 1: Collect PCI field strings and HTTP URLs from string table
        pci_strings = []   # (address, value)
        http_strings = []  # (address, value)

        for address, string_value in self.program.get_defined_strings():
            if not string_value:
                continue

            # Check for PCI field names
            for pattern in _PCI_FIELD_PATTERNS:
                if pattern.search(string_value):
                    pci_strings.append((address, string_value))
                    break

            # Check for HTTP URLs
            if _HTTP_URL_RE.match(string_value):
                http_strings.append((address, string_value))

        if not pci_strings or not http_strings:
            return findings

        # Step 2: For each PCI string, find referencing functions
        pci_func_map = {}  # func_address -> list of (pci_addr, pci_value)
        for pci_addr, pci_value in pci_strings:
            try:
                refs = self.program.get_references_to(pci_addr)
                for ref in refs:
                    func = self.program.get_function_containing(ref.from_address)
                    if func:
                        if func.address not in pci_func_map:
                            pci_func_map[func.address] = []
                        pci_func_map[func.address].append((pci_addr, pci_value))
            except Exception:
                continue

        # Step 3: For each HTTP URL, check if its referencing functions overlap
        for http_addr, http_value in http_strings:
            try:
                refs = self.program.get_references_to(http_addr)
            except Exception:
                continue

            for ref in refs:
                try:
                    func = self.program.get_function_containing(ref.from_address)
                except Exception:
                    continue

                if func and func.address in pci_func_map:
                    pci_fields = pci_func_map[func.address]
                    field_names = ", ".join(
                        v[:30] for _, v in pci_fields[:5]
                    )

                    findings.append(SecurityFinding(
                        severity=Severity.CRITICAL,
                        issue_type="PCI Data Over Cleartext HTTP",
                        description="Payment card data fields sent via cleartext HTTP",
                        location=func.address,
                        function_name=func.name,
                        evidence={
                            "http_url": http_value[:100],
                            "http_url_address": hex(http_addr),
                            "pci_fields": field_names,
                            "pci_field_count": str(len(pci_fields)),
                            "function": func.name[:80],
                        },
                        impact="Credit card data (PAN, CVV, cardholder name) transmitted "
                               "without encryption — trivially interceptable via MITM. "
                               "Violates PCI DSS Requirement 4.1.",
                        recommendation="Use HTTPS for ALL payment-related communication; "
                                       "implement certificate pinning for payment endpoints"
                    ))
                    # One finding per function
                    break

        return findings


__all__ = ["PCIDataFlowChecker"]
