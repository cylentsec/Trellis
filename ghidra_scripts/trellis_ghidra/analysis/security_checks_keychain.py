# -*- coding: utf-8 -*-
"""
Keychain security checks for Trellis (Ghidra port).

This module implements security analysis for iOS Keychain Services operations,
detecting insecure accessibility levels, iCloud sync issues, and missing protections.
"""

from .security_checks import SecurityChecker, SecurityFinding, Severity

# Keychain accessibility constants
INSECURE_ACCESSIBILITY = {
    "kSecAttrAccessibleAlways": "Always accessible (even when device is locked)",
    "kSecAttrAccessibleAlwaysThisDeviceOnly": "Always accessible on this device (even when locked)",
}

SECURE_ACCESSIBILITY = {
    "kSecAttrAccessibleWhenUnlocked": "Accessible only when device is unlocked",
    "kSecAttrAccessibleAfterFirstUnlock": "Accessible after first unlock (ok for background tasks)",
    "kSecAttrAccessibleWhenUnlockedThisDeviceOnly": "Accessible when unlocked (this device only)",
    "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly": "Accessible after first unlock (this device only)",
    "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly": "Accessible when passcode set (this device only)",
}

# Severity mapping for accessibility levels
ACCESSIBILITY_SEVERITY = {
    "kSecAttrAccessibleWhenUnlocked": Severity.LOW,
    "kSecAttrAccessibleAfterFirstUnlock": Severity.MEDIUM,
    "kSecAttrAccessibleAlways": Severity.CRITICAL,
    "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly": Severity.LOW,
    "kSecAttrAccessibleWhenUnlockedThisDeviceOnly": Severity.LOW,
    "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly": Severity.MEDIUM,
    "kSecAttrAccessibleAlwaysThisDeviceOnly": Severity.HIGH,
    # Raw values
    "ak": Severity.LOW,
    "ck": Severity.MEDIUM,
    "dk": Severity.CRITICAL,
    "akpu": Severity.LOW,
    "aku": Severity.LOW,
    "cku": Severity.MEDIUM,
    "dku": Severity.HIGH,
}

# Known keychain attributes
KEYCHAIN_ATTRIBUTES = {
    "kSecAttrAccessible",
    "kSecAttrAccessControl",
    "kSecAttrSynchronizable",
    "kSecAttrAccount",
    "kSecAttrService",
    "kSecClass",
    "kSecValueData",
    "kSecAttrAccessGroup",
    "kSecReturnData",
    "kSecReturnAttributes",
    "kSecReturnRe",
    "kSecReturnPersistentRe",
    "kSecMatchLimit",
}

# Debug patterns
DEBUG_PATTERNS = {"Dump", "Debug", "Test", "Mock", "Fake", "Stub", "dump", "debug", "test"}


class KeychainSecurityChecker(SecurityChecker):
    """Security checker for iOS Keychain operations."""

    def check_call_site(self, function_sig, call_site, extracted_info):
        """Check a keychain function call site for security issues."""
        findings = []
        func_name = function_sig.name

        # Check SecItemAdd for insecure storage
        if func_name == "SecItemAdd":
            findings.extend(self._check_sec_item_add(function_sig, call_site, extracted_info))

        # Check SecItemUpdate for security downgrades
        elif func_name == "SecItemUpdate":
            findings.extend(self._check_sec_item_update(function_sig, call_site, extracted_info))

        # Check SecItemCopyMatching for data exposure
        elif func_name == "SecItemCopyMatching":
            findings.extend(self._check_sec_item_copy(function_sig, call_site, extracted_info))

        # Check for debug utilities
        findings.extend(self._check_debug_utilities(call_site))

        return findings

    def _check_sec_item_add(self, function_sig, call_site, extracted_info):
        """Check SecItemAdd for insecure accessibility and synchronization."""
        findings = []
        address = call_site.call_instruction_address if call_site else 0

        # Try to extract accessibility from parameters
        accessibility = self._extract_accessibility(extracted_info)
        sync_enabled = self._extract_sync_setting(extracted_info)

        if accessibility:
            severity = ACCESSIBILITY_SEVERITY.get(accessibility, Severity.HIGH)
            
            if accessibility in INSECURE_ACCESSIBILITY or severity >= Severity.HIGH:
                protection_desc = INSECURE_ACCESSIBILITY.get(
                    accessibility, 
                    SECURE_ACCESSIBILITY.get(accessibility, "Unknown protection level")
                )
                findings.append(SecurityFinding(
                    severity=severity,
                    issue_type="Insecure Keychain Accessibility",
                    description="Keychain item stored with insecure accessibility: {}".format(accessibility),
                    location=address,
                    function_name=function_sig.name,
                    evidence={
                        "kSecAttrAccessible": accessibility,
                        "protection": protection_desc,
                    },
                    impact="Item is accessible even when device is locked, vulnerable to physical attacks",
                    recommendation="Use kSecAttrAccessibleWhenUnlocked or kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly"
                ))
        else:
            # No accessibility attribute found - report as potential issue
            findings.append(SecurityFinding(
                severity=Severity.MEDIUM,
                issue_type="Missing Keychain Accessibility Attribute",
                description="Keychain item stored without explicit accessibility level",
                location=address,
                function_name=function_sig.name,
                evidence={
                    "kSecAttrAccessible": "not set (defaults to kSecAttrAccessibleWhenUnlocked)",
                },
                impact="Developer may be unaware of keychain protection levels, using defaults",
                recommendation="Explicitly set kSecAttrAccessible to an appropriate protection level"
            ))

        # Check for iCloud sync
        if sync_enabled:
            findings.append(SecurityFinding(
                severity=Severity.MEDIUM,
                issue_type="Keychain iCloud Sync Enabled",
                description="Keychain item configured for iCloud synchronization",
                location=address,
                function_name=function_sig.name,
                evidence={"kSecAttrSynchronizable": True},
                impact="Item will be synced to iCloud, potentially exposing it to additional attack surface",
                recommendation="Disable sync for sensitive items by setting kSecAttrSynchronizable to false"
            ))

        return findings

    def _check_sec_item_update(self, function_sig, call_site, extracted_info):
        """Check SecItemUpdate for security downgrades."""
        findings = []
        address = call_site.call_instruction_address if call_site else 0

        accessibility = self._extract_accessibility(extracted_info)
        
        if accessibility:
            severity = ACCESSIBILITY_SEVERITY.get(accessibility, Severity.MEDIUM)
            
            if severity >= Severity.HIGH:
                findings.append(SecurityFinding(
                    severity=Severity.CRITICAL if severity == Severity.CRITICAL else Severity.HIGH,
                    issue_type="Keychain Accessibility Downgrade",
                    description="Keychain item accessibility being changed to insecure level: {}".format(accessibility),
                    location=address,
                    function_name=function_sig.name,
                    evidence={
                        "new_kSecAttrAccessible": accessibility,
                    },
                    impact="Existing secure keychain item is being made more accessible",
                    recommendation="Do not downgrade accessibility to weaker protection levels"
                ))

        # Check if sync is being enabled
        sync_enabled = self._extract_sync_setting(extracted_info)
        if sync_enabled:
            findings.append(SecurityFinding(
                severity=Severity.HIGH,
                issue_type="Enabling iCloud Sync on Existing Item",
                description="iCloud synchronization being enabled on existing keychain item",
                location=address,
                function_name=function_sig.name,
                evidence={"kSecAttrSynchronizable": True},
                impact="Previously local-only item will now sync to iCloud",
                recommendation="Avoid enabling sync on items that were originally stored locally"
            ))

        return findings

    def _check_sec_item_copy(self, function_sig, call_site, extracted_info):
        """Check SecItemCopyMatching for data exposure."""
        findings = []
        address = call_site.call_instruction_address if call_site else 0

        return_data = self._extract_return_data(extracted_info)
        match_limit_all = self._extract_match_limit_all(extracted_info)

        if return_data:
            findings.append(SecurityFinding(
                severity=Severity.MEDIUM,
                issue_type="Keychain Data Extraction",
                description="SecItemCopyMatching returns decrypted keychain data",
                location=address,
                function_name=function_sig.name,
                evidence={
                    "kSecReturnData": True,
                    "risk": "Returns decrypted secret material as NSData",
                },
                impact="Raw secret data (passwords, keys, tokens) is returned to the caller in plaintext",
                recommendation="Ensure returned data is zeroized after use; verify caller handles data securely"
            ))

        if match_limit_all:
            findings.append(SecurityFinding(
                severity=Severity.HIGH,
                issue_type="Overly Broad Keychain Query",
                description="SecItemCopyMatching queries all matching keychain items",
                location=address,
                function_name=function_sig.name,
                evidence={
                    "kSecMatchLimit": "kSecMatchLimitAll",
                    "risk": "Returns ALL matching keychain items",
                },
                impact="Bulk extraction of keychain items; if exploited, attacker retrieves all matching secrets",
                recommendation="Use kSecMatchLimitOne unless bulk retrieval is specifically needed"
            ))

        return findings

    def _check_debug_utilities(self, call_site):
        """Check if the calling function appears to be a debug/test utility."""
        findings = []
        
        if not call_site:
            return findings
            
        caller_name = call_site.caller_name or ""
        
        for pattern in DEBUG_PATTERNS:
            if pattern in caller_name:
                findings.append(SecurityFinding(
                    severity=Severity.HIGH,
                    issue_type="Debug/Test Keychain Utility in Production",
                    description="Keychain operations in debug/test function: {}".format(caller_name),
                    location=call_site.call_instruction_address,
                    function_name=caller_name,
                    evidence={
                        "function_name": caller_name,
                        "debug_pattern": pattern,
                        "keychain_api": "SecItem*"
                    },
                    impact="Debug or test code accessing keychain may expose sensitive data or bypass security",
                    recommendation="Remove debug/test keychain utilities from production builds"
                ))
                break

        return findings

    @staticmethod
    def _get_param_string_values(param):
        """Get all string representations of a parameter value for matching."""
        values = []
        if not param:
            return values
        if hasattr(param, 'value_as_string') and param.value_as_string:
            values.append(param.value_as_string)
        if hasattr(param, 'value_str') and param.value_str:
            values.append(param.value_str)
        if hasattr(param, 'variable_name') and param.variable_name:
            values.append(param.variable_name)
        return values

    def _extract_accessibility(self, extracted_info):
        """Extract accessibility value from extracted parameters."""
        if not extracted_info or not hasattr(extracted_info, 'parameters'):
            return None

        for param in extracted_info.parameters:
            for val in self._get_param_string_values(param):
                # Check for known accessibility constants
                for acc in list(INSECURE_ACCESSIBILITY.keys()) + list(SECURE_ACCESSIBILITY.keys()):
                    if acc in val:
                        return acc

                # Check for raw values
                for raw_val in ["ak", "ck", "dk", "akpu", "aku", "cku", "dku"]:
                    if val == raw_val:
                        return raw_val

        return None

    def _extract_sync_setting(self, extracted_info):
        """Extract synchronization setting from parameters."""
        if not extracted_info or not hasattr(extracted_info, 'parameters'):
            return False

        for param in extracted_info.parameters:
            for val in self._get_param_string_values(param):
                if "kSecAttrSynchronizable" in val:
                    if "True" in val or "true" in val or "YES" in val:
                        return True

        return False

    def _extract_return_data(self, extracted_info):
        """Check if kSecReturnData is set to true."""
        if not extracted_info or not hasattr(extracted_info, 'parameters'):
            return False

        for param in extracted_info.parameters:
            for val in self._get_param_string_values(param):
                if "kSecReturnData" in val:
                    if "True" in val or "true" in val or "YES" in val:
                        return True

        return False

    def _extract_match_limit_all(self, extracted_info):
        """Check if kSecMatchLimitAll is used."""
        if not extracted_info or not hasattr(extracted_info, 'parameters'):
            return False

        for param in extracted_info.parameters:
            for val in self._get_param_string_values(param):
                if "kSecMatchLimitAll" in val:
                    return True

        return False


__all__ = ["KeychainSecurityChecker"]
