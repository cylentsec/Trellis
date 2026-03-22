# -*- coding: utf-8 -*-
"""
Jailbreak detection security checks for Trellis (Ghidra port).

This module implements detection of jailbreak detection techniques in iOS binaries,
identifying file path checks, fork detection, dylib enumeration, and other
jailbreak detection mechanisms.
"""

from .security_checks import SecurityChecker, SecurityFinding, Severity

# Known jailbreak-related paths
JAILBREAK_PATHS = {
    # Cydia and package managers
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/Installer.app",
    "/Applications/Icy.app",
    "/Applications/blackra1n.app",

    # Common jailbreak files
    "/bin/bash",
    "/bin/sh",
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/usr/libexec/sftp-server",
    "/etc/apt",
    "/etc/ssh/sshd_config",

    # Cydia files
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/tmp/cydia.log",
    "/var/lib/dpkg/info",

    # Jailbreak tools
    "/private/var/stash",
    "/private/var/mobile/Library/SBSettings/Themes",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Library/MobileSubstrate/DynamicLibraries",
    "/var/cache/apt",
    "/var/lib/apt",

    # Substrate and hooking
    "/usr/lib/TweakInject",
    "/Library/TweakInject",
    "/usr/lib/libcycript.dylib",
    "/usr/lib/libhooker.dylib",
    "/usr/lib/libsubstitute.dylib",

    # Other indicators
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/private/var/mobile/Library/Caches/com.saurik.Cydia",

    # Frida and dynamic instrumentation
    "/usr/lib/frida",
    "/usr/local/bin/frida-server",

    # Checkra1n and modern jailbreaks
    "/.bootstrapped_electra",
    "/.installed_unc0ver",
    "/jb",
}

# Known jailbreak-related dylibs
JAILBREAK_DYLIBS = {
    "MobileSubstrate",
    "libsubstitute",
    "libhooker",
    "SubstrateInserter",
    "SubstrateBootstrap",
    "SubstrateLoader",
    "TweakInject",
    "CydiaSubstrate",
    "cycript",
    "libcycript",
    "frida",
    "FridaGadget",
    "SSLKillSwitch",
}

# Known jailbreak-related environment variables
JAILBREAK_ENVVARS = {
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "_MSSafeMode",
    "MOBILE_SUBSTRATE",
}

# Known jailbreak URL schemes
JAILBREAK_URL_SCHEMES = {
    "cydia://",
    "sileo://",
    "zebra://",
    "filza://",
    "activator://",
    "undecimus://",
}

# Jailbreak-related symbol names
JAILBREAK_SYMBOLS = {
    "MSHookFunction",
    "MSHookMessageEx",
    "MSGetImageByName",
    "substrate_",
    "SubstrateHookFunction",
    "LHHookFunction",
}

# Caller name keywords that indicate jailbreak detection context.
# These are intentionally broad single-word tokens because the heuristic
# only fires AFTER the checker already matched on a jailbreak-relevant API
# (dlopen, _dyld_image_count, stat, etc.) AND parameter extraction failed,
# so the false-positive risk is low.
_JAILBREAK_CALLER_KEYWORDS = [
    # Compound patterns (high confidence)
    "jailbreak", "jailbroken", "JailbreakDetection",
    "rootDetect", "deviceIntegrity", "isCompromised",
    "checkJailbreak", "detectJailbreak",
    "isJailbroken", "jbDetect",
    # Broader single-word patterns (match real-world function names like
    # _detect_injected_dylds, _disable_gdb, checkTamper, etc.)
    "detect", "injected", "dyld", "dylib",
    "disable", "gdb", "debugger",
    "tamper", "integrity", "sandbox",
    "pirate", "piracy",
    "hook", "tweak", "substrate",
    "cydia", "frida", "cycript",
]


def _caller_suggests_jailbreak(caller_name):
    """Check if the caller function name suggests jailbreak detection context."""
    if not caller_name:
        return False
    lower = caller_name.lower()
    for kw in _JAILBREAK_CALLER_KEYWORDS:
        if kw.lower() in lower:
            return True
    return False

# Known library prefixes (to filter false positives)
KNOWN_LIBRARY_PREFIXES = {
    "_CRYPTO_", "_SSL_", "_EVP_", "_RSA_", "_EC_", "_BIO_", "_X509_",
    "_ASN1_", "_PEM_", "_DH_", "_DSA_", "_HMAC_", "_SHA", "_MD5_",
    "_AES_", "_DES_", "_OPENSSL_", "_ERR_", "_BN_", "_PKCS",
    "_u_", "_icu_", "_ucol_", "_udat_", "_unum_", "_uloc_", "_ures_",
    "_mg_", "_mongoose_",
    "_FIR", "_CLSLog", "_Crashlytics", "_firebase_",
    "_sqlite3_", "_sqlite_",
    "_inflate", "_deflate", "_compress", "_uncompress", "_gz",
    "_xml", "_XML_", "_xslt",
    "_curl_", "_Curl_",
}


def _caller_is_known_library(caller_name):
    """Check if the calling function belongs to a known third-party library."""
    if not caller_name:
        return False

    for prefix in KNOWN_LIBRARY_PREFIXES:
        if caller_name.startswith(prefix):
            return True

    return False


def _get_param_string_values(param):
    """Get all string representations of a parameter value for matching."""
    values = []
    if not param:
        return values
    # Check value_as_string first (populated by backward slice for ADRP+ADD addresses)
    if hasattr(param, 'value_as_string') and param.value_as_string:
        values.append(param.value_as_string)
    # Check value_str (the display representation)
    if hasattr(param, 'value_str') and param.value_str:
        values.append(param.value_str)
    # Check variable_name (sometimes contains meaningful strings)
    if hasattr(param, 'variable_name') and param.variable_name:
        values.append(param.variable_name)
    return values


def _argument_contains_jailbreak_path(extracted_info):
    """Check if any parameter value contains a known jailbreak path."""
    if not extracted_info or not hasattr(extracted_info, 'parameters'):
        return None

    for param in extracted_info.parameters:
        for val in _get_param_string_values(param):
            if not val:
                continue

            # Direct match against known paths
            for jb_path in JAILBREAK_PATHS:
                if jb_path in val:
                    return jb_path

            # Partial path indicators
            jb_indicators = [
                "Cydia", "cydia", "Sileo", "sileo", "Zebra",
                "Substrate", "substrate", "TweakInject", "tweakinject",
                "libhooker", "libcycript", "frida", "Frida",
                "unc0ver", "electra", "checkra1n",
                "sshd", "MobileSubstrate",
            ]
            for indicator in jb_indicators:
                if indicator in val:
                    return "<contains '{}'>".format(indicator)

    return None


def _argument_contains_jailbreak_envvar(extracted_info):
    """Check if any parameter value contains a known jailbreak env var."""
    if not extracted_info or not hasattr(extracted_info, 'parameters'):
        return None

    for param in extracted_info.parameters:
        for val in _get_param_string_values(param):
            for envvar in JAILBREAK_ENVVARS:
                if envvar in val:
                    return envvar
    return None


def _argument_contains_jailbreak_dylib(extracted_info):
    """Check if any parameter value contains a known jailbreak dylib name."""
    if not extracted_info or not hasattr(extracted_info, 'parameters'):
        return None

    for param in extracted_info.parameters:
        for val in _get_param_string_values(param):
            for dylib in JAILBREAK_DYLIBS:
                if dylib in val:
                    return dylib
    return None


class JailbreakSecurityChecker(SecurityChecker):
    """Security checker for jailbreak detection techniques."""

    def check_call_site(self, function_sig, call_site, extracted_info):
        """Check a call site for jailbreak detection indicators."""
        findings = []
        func_name = function_sig.name
        caller_name = call_site.caller_name if call_site else None

        # Skip if caller is in a known library
        if _caller_is_known_library(caller_name):
            return findings

        # File existence checks
        if func_name in ("stat", "stat64", "lstat", "lstat64", "access", 
                         "fopen", "open", "fileExistsAtPath:", 
                         "NSFileManager", "contentsOfDirectoryAtPath:error:"):
            jb_path = _argument_contains_jailbreak_path(extracted_info)
            if jb_path:
                findings.append(SecurityFinding(
                    severity=Severity.INFO,
                    issue_type="Jailbreak Detection - File Path Check",
                    description="Checking for jailbreak-related file path: {}".format(jb_path),
                    location=call_site.call_instruction_address if call_site else 0,
                    function_name=func_name,
                    evidence={
                        "api": func_name,
                        "path_checked": jb_path,
                        "caller": caller_name or "<unknown>",
                    },
                    impact="Application is detecting jailbroken devices",
                    recommendation="This is a security control; verify it cannot be bypassed"
                ))

        # Fork detection (common jailbreak detection technique)
        if func_name == "fork":
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="Jailbreak Detection - Fork Check",
                description="fork() called - may be checking for jailbreak sandbox escape",
                location=call_site.call_instruction_address if call_site else 0,
                function_name=func_name,
                evidence={
                    "api": "fork",
                    "technique": "Jailbroken devices allow forking",
                    "caller": caller_name or "<unknown>",
                },
                impact="Application is detecting jailbroken devices via fork",
                recommendation="This is a security control; verify it cannot be bypassed"
            ))

        # Environment variable checks
        if func_name == "getenv":
            envvar = _argument_contains_jailbreak_envvar(extracted_info)
            if envvar:
                findings.append(SecurityFinding(
                    severity=Severity.INFO,
                    issue_type="Jailbreak Detection - Environment Check",
                    description="Checking for jailbreak-related environment variable: {}".format(envvar),
                    location=call_site.call_instruction_address if call_site else 0,
                    function_name=func_name,
                    evidence={
                        "api": "getenv",
                        "envvar_checked": envvar,
                        "caller": caller_name or "<unknown>",
                    },
                    impact="Application is detecting jailbroken devices via environment",
                    recommendation="This is a security control; verify it cannot be bypassed"
                ))

        # Dylib enumeration
        if func_name in ("_dyld_image_count", "_dyld_get_image_name", 
                         "dlsym", "dlopen", "dladdr"):
            dylib = _argument_contains_jailbreak_dylib(extracted_info)
            if dylib:
                findings.append(SecurityFinding(
                    severity=Severity.INFO,
                    issue_type="Jailbreak Detection - Dylib Check",
                    description="Checking for jailbreak-related dylib: {}".format(dylib),
                    location=call_site.call_instruction_address if call_site else 0,
                    function_name=func_name,
                    evidence={
                        "api": func_name,
                        "dylib_checked": dylib,
                        "caller": caller_name or "<unknown>",
                    },
                    impact="Application is detecting jailbroken devices via loaded libraries",
                    recommendation="This is a security control; verify it cannot be bypassed"
                ))

        # Symbolic link checks (sandbox escape detection)
        if func_name in ("readlink", "lstat", "lstat64"):
            jb_path = _argument_contains_jailbreak_path(extracted_info)
            if jb_path:
                findings.append(SecurityFinding(
                    severity=Severity.INFO,
                    issue_type="Jailbreak Detection - Symlink Check",
                    description="Checking symlink status of jailbreak path: {}".format(jb_path),
                    location=call_site.call_instruction_address if call_site else 0,
                    function_name=func_name,
                    evidence={
                        "api": func_name,
                        "path_checked": jb_path,
                        "caller": caller_name or "<unknown>",
                    },
                    impact="Application is detecting jailbroken devices via filesystem",
                    recommendation="This is a security control; verify it cannot be bypassed"
                ))

        # URL scheme checks (canOpenURL for Cydia, etc.)
        if func_name in ("canOpenURL:", "openURL:"):
            if extracted_info and hasattr(extracted_info, 'parameters'):
                for param in extracted_info.parameters:
                    if param and hasattr(param, 'value'):
                        val = str(param.value) if param.value else ""
                        for scheme in JAILBREAK_URL_SCHEMES:
                            if scheme in val:
                                findings.append(SecurityFinding(
                                    severity=Severity.INFO,
                                    issue_type="Jailbreak Detection - URL Scheme Check",
                                    description="Checking for jailbreak URL scheme: {}".format(scheme),
                                    location=call_site.call_instruction_address if call_site else 0,
                                    function_name=func_name,
                                    evidence={
                                        "api": func_name,
                                        "scheme_checked": scheme,
                                        "caller": caller_name or "<unknown>",
                                    },
                                    impact="Application is detecting jailbroken devices via URL schemes",
                                    recommendation="This is a security control; verify it cannot be bypassed"
                                ))

        # System call checks (ptrace anti-debugging often combined with JB detection)
        if func_name == "ptrace":
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="Anti-Debug / Jailbreak Detection - ptrace",
                description="ptrace called - may be anti-debugging or jailbreak detection",
                location=call_site.call_instruction_address if call_site else 0,
                function_name=func_name,
                evidence={
                    "api": "ptrace",
                    "technique": "PT_DENY_ATTACH prevents debugger attachment",
                    "caller": caller_name or "<unknown>",
                },
                impact="Application has anti-debugging protection",
                recommendation="This is a security control; verify it cannot be bypassed"
            ))

        # sysctl checks (process flags inspection)
        if func_name == "sysctl":
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="Anti-Debug / Jailbreak Detection - sysctl",
                description="sysctl called - may be checking for debugger or jailbreak",
                location=call_site.call_instruction_address if call_site else 0,
                function_name=func_name,
                evidence={
                    "api": "sysctl",
                    "technique": "Can check P_TRACED flag or system info",
                    "caller": caller_name or "<unknown>",
                },
                impact="Application may be detecting debugging or jailbreak",
                recommendation="This is a security control; verify it cannot be bypassed"
            ))

        # Caller-name heuristic: when parameter extraction fails but the
        # caller function name clearly indicates jailbreak detection context,
        # report it even without resolved parameter values.
        if not findings and _caller_suggests_jailbreak(caller_name):
            # Determine which kind of check this likely is based on the API
            technique = "Unknown"
            if func_name in ("stat", "stat64", "lstat", "lstat64", "access",
                             "fopen", "open", "fileExistsAtPath:",
                             "NSFileManager", "contentsOfDirectoryAtPath:error:"):
                technique = "File path existence check"
            elif func_name in ("dlsym", "dlopen", "dladdr",
                               "_dyld_image_count", "_dyld_get_image_name"):
                technique = "Dynamic library enumeration"
            elif func_name == "getenv":
                technique = "Environment variable check"
            elif func_name in ("canOpenURL:", "openURL:"):
                technique = "URL scheme check"
            elif func_name == "fork":
                technique = "Fork sandbox escape test"
            elif func_name in ("ptrace", "sysctl"):
                technique = "Anti-debug / process inspection"
            else:
                technique = "{} call".format(func_name)

            display_caller = caller_name
            if len(display_caller) > 80:
                display_caller = display_caller[:77] + "..."

            findings.append(SecurityFinding(
                severity=Severity.INFO,
                issue_type="Jailbreak Detection — Caller Heuristic",
                description="{} called from jailbreak detection function (parameters unresolved)".format(
                    func_name),
                location=call_site.call_instruction_address if call_site else 0,
                function_name=func_name,
                evidence={
                    "api": func_name,
                    "technique": technique,
                    "caller": display_caller,
                    "note": "Parameter values could not be extracted; caller name indicates "
                            "jailbreak detection context"
                },
                impact="Application is performing jailbreak detection checks",
                recommendation="Hook {} in Frida to inspect runtime parameters and verify "
                               "jailbreak detection behavior".format(func_name)
            ))

        return findings

    def scan_string_table(self):
        """
        Scan the binary string table for jailbreak-related paths and URLs.

        Fallback for when parameter extraction fails (common with Swift).
        Instead of relying on call-site parameter values, scan all defined
        strings for known jailbreak indicators.

        Returns:
            List of SecurityFinding objects
        """
        findings = []
        seen = set()

        for address, string_value in self.program.get_defined_strings():
            if not string_value or len(string_value) < 4:
                continue
            if string_value in seen:
                continue
            seen.add(string_value)

            # Check known jailbreak file paths
            for jb_path in JAILBREAK_PATHS:
                if jb_path == string_value or string_value.endswith(jb_path):
                    findings.append(SecurityFinding(
                        severity=Severity.INFO,
                        issue_type="Jailbreak Detection - Path String",
                        description="Jailbreak-related path in string table: {}".format(jb_path),
                        location=address,
                        function_name="<string_table>",
                        evidence={
                            "path": jb_path,
                            "detection_method": "string_table_scan",
                        },
                        impact="Application includes jailbreak detection path checks",
                        recommendation="Verify jailbreak detection cannot be trivially bypassed"
                    ))
                    break

            # Check jailbreak URL schemes
            for scheme in JAILBREAK_URL_SCHEMES:
                if scheme in string_value:
                    findings.append(SecurityFinding(
                        severity=Severity.INFO,
                        issue_type="Jailbreak Detection - URL Scheme",
                        description="Jailbreak URL scheme in string table: {}".format(scheme),
                        location=address,
                        function_name="<string_table>",
                        evidence={
                            "scheme": scheme,
                            "detection_method": "string_table_scan",
                        },
                        impact="Application checks for jailbreak app URL schemes",
                        recommendation="Verify jailbreak detection cannot be trivially bypassed"
                    ))
                    break

            # Check jailbreak dylib names
            for dylib in JAILBREAK_DYLIBS:
                if dylib in string_value:
                    findings.append(SecurityFinding(
                        severity=Severity.INFO,
                        issue_type="Jailbreak Detection - Dylib String",
                        description="Jailbreak-related dylib in string table: {}".format(dylib),
                        location=address,
                        function_name="<string_table>",
                        evidence={
                            "dylib": dylib,
                            "detection_method": "string_table_scan",
                        },
                        impact="Application includes jailbreak detection library checks",
                        recommendation="Verify jailbreak detection cannot be trivially bypassed"
                    ))
                    break

        return findings


__all__ = ["JailbreakSecurityChecker"]
