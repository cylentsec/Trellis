# @category iOS Security
# @menupath Tools.Trellis.Analyze All
# @toolbar python.png
# @description iOS Security Analysis - Analyze for crypto, networking, keychain, and other security-relevant functions

"""
Trellis for Ghidra - iOS Security Analysis Toolkit

This script analyzes iOS binaries for security-relevant function usage
and generates detailed security reports.

Usage:
    1. Open an iOS binary in Ghidra
    2. Run this script via Script Manager or Tools menu
    3. Select which categories to analyze
    4. Choose an output directory when prompted
    5. Reports are saved to the selected directory

Categories available:
    - crypto: CommonCrypto functions (CCCrypt, CCHmac, etc.)
    - networking: TLS/SSL configuration
    - keychain: Keychain Services
    - antidebug: Anti-debugging techniques
    - jailbreak: Jailbreak detection
"""

import os
import sys
from datetime import datetime
from pathlib import Path

# Add the script directory to the path so we can import trellis_ghidra
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

# Import Trellis modules
try:
    from trellis_ghidra.ghidra_api import GhidraProgram
    from trellis_ghidra.signatures import (
        load_category,
        load_all,
        get_available_categories,
    )
    from trellis_ghidra.analysis.finder import find_functions, FoundFunction
    from trellis_ghidra.analysis.calltree import build_call_tree, CallSite
    from trellis_ghidra.analysis.extractor import extract_call_info
    from trellis_ghidra.analysis.security_checks import (
        Severity,
        SecurityFinding,
        SEVERITY_EMOJI,
    )
    from trellis_ghidra.analysis.findings_storage import save_findings
    from trellis_ghidra.analysis.security_checks_crypto import CryptoSecurityChecker
    from trellis_ghidra.analysis.security_checks_tls import (
        TLSDelegateSecurityChecker,
        TLS_DELEGATE_PATTERNS,
    )
    from trellis_ghidra.analysis.security_checks_keychain import KeychainSecurityChecker
    from trellis_ghidra.analysis.security_checks_jailbreak import (
        JailbreakSecurityChecker,
    )
    from trellis_ghidra.analysis.security_checks_storage import StorageSecurityChecker
    from trellis_ghidra.analysis.security_checks_deserialization import (
        DeserializationSecurityChecker,
    )
    from trellis_ghidra.analysis.security_checks_antidebug import (
        AntiDebugSecurityChecker,
    )
    from trellis_ghidra.analysis.security_checks_webview import WebViewSecurityChecker
    from trellis_ghidra.analysis.security_checks_deeplinks import (
        DeepLinkSecurityChecker,
        DEEPLINK_DELEGATE_PATTERNS,
    )
    from trellis_ghidra.analysis.security_checks_cryptokit import (
        CryptoKitSecurityChecker,
    )
    from trellis_ghidra.analysis.security_checks_networking import (
        NetworkingSecurityChecker,
    )
    from trellis_ghidra.analysis.security_checks_sqlite import SQLiteSecurityChecker
    from trellis_ghidra.analysis.security_checks_logging import LoggingSecurityChecker
    from trellis_ghidra.analysis.security_checks_endpoints import (
        EndpointsSecurityChecker,
    )
    from trellis_ghidra.analysis.security_checks_strings import (
        StringTableSecurityChecker,
    )
    from trellis_ghidra.analysis.security_checks_biometric import (
        BiometricSecurityChecker,
    )
    from trellis_ghidra.analysis.security_checks_runtime import RuntimeSecurityChecker
    from trellis_ghidra.analysis.security_checks_obfuscation import (
        ObfuscationSecurityChecker,
    )
    from trellis_ghidra.analysis.security_checks_secret_sinks import (
        SecretSinkSecurityChecker,
    )
    from trellis_ghidra.analysis.security_checks_pci import PCIDataFlowChecker
    from trellis_ghidra.analysis.url_handlers import (
        find_url_handlers,
        find_ui_entry_points,
        extract_url_schemes,
        cross_reference_schemes_with_handlers,
        generate_url_handler_frida_script,
        format_url_handlers_report,
        format_url_schemes_report,
    )
    from trellis_ghidra.analysis.swift_demangle import demangle, is_swift_symbol

    TRELLIS_AVAILABLE = True
except ImportError as e:
    print("[Trellis] Error importing Trellis modules: {}".format(e))
    print(
        "[Trellis] Make sure trellis_ghidra package is in the same directory as this script"
    )
    TRELLIS_AVAILABLE = False

# Ghidra imports
from ghidra.util.task import TaskMonitor


def get_security_checker(category, program):
    """Get the appropriate security checker for a category."""
    checkers = {
        "crypto": CryptoSecurityChecker,
        "cryptokit": CryptoKitSecurityChecker,
        "tls": TLSDelegateSecurityChecker,
        "tls_delegate": TLSDelegateSecurityChecker,
        "networking": NetworkingSecurityChecker,
        "keychain": KeychainSecurityChecker,
        "jailbreak": JailbreakSecurityChecker,
        "antidebug": AntiDebugSecurityChecker,
        "storage": StorageSecurityChecker,
        "deserialization": DeserializationSecurityChecker,
        "webview": WebViewSecurityChecker,
        "deeplinks": DeepLinkSecurityChecker,
        "sqlite": SQLiteSecurityChecker,
        "logging": LoggingSecurityChecker,
        "endpoints": EndpointsSecurityChecker,
        "privacy": StorageSecurityChecker,  # Privacy uses storage checks
        "integrity": JailbreakSecurityChecker,  # Integrity uses jailbreak checks
        "secrets": KeychainSecurityChecker,  # Secrets uses keychain checks
        "insecure_storage": StorageSecurityChecker,  # Insecure storage uses storage checks
        "biometric": BiometricSecurityChecker,
        "runtime": RuntimeSecurityChecker,
        "obfuscation": ObfuscationSecurityChecker,
        "secret_sinks": SecretSinkSecurityChecker,
    }

    checker_class = checkers.get(category)
    if checker_class:
        return checker_class(program)
    return None


def format_report(category, binary_name, results, program):
    """
    Format analysis results into a Markdown report.

    Args:
        category: Category name
        binary_name: Name of the analyzed binary
        results: List of (found_func, refs, call_tree, findings) tuples
        program: GhidraProgram for context

    Returns:
        Markdown formatted report string
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Collect all findings
    all_findings = []
    for _, _, _, findings in results:
        if findings:
            all_findings.extend(findings)

    # Count by severity
    severity_counts = {s: 0 for s in Severity}
    for finding in all_findings:
        severity_counts[finding.severity] += 1

    category_descriptions = {
        "crypto": "Cryptographic function usage and potential vulnerabilities",
        "cryptokit": "Swift CryptoKit framework usage and security analysis",
        "keychain": "Keychain/secrets storage patterns and security issues",
        "networking": "Network/TLS configuration and security concerns",
        "tls": "TLS delegate implementation and certificate validation",
        "tls_delegate": "TLS delegate implementation and certificate validation",
        "antidebug": "Anti-debugging techniques detected in the binary",
        "jailbreak": "Jailbreak detection methods found in the binary",
        "storage": "Data storage patterns (NSUserDefaults, file writes, etc.)",
        "deserialization": "Object deserialization vulnerabilities (NSCoding, etc.)",
        "webview": "WebView security (JavaScript bridges, content loading)",
        "deeplinks": "Deep link and URL scheme handling security",
        "sqlite": "SQLite database security (SQL injection, encryption)",
        "logging": "Sensitive data logging detection (NSLog, os_log, etc.)",
        "endpoints": "API endpoint discovery and security analysis",
        "privacy": "Privacy-sensitive data handling",
        "integrity": "Application integrity checks",
        "secrets": "Secrets and credentials management",
        "biometric": "Biometric authentication (Touch ID/Face ID) security analysis",
        "runtime": "Runtime manipulation vulnerabilities (client-side auth, hardcoded comparisons)",
        "insecure_storage": "Insecure data storage patterns (NSUserDefaults, plist files, etc.)",
        "obfuscation": "Obfuscation patterns (Base64/Hex decode, XOR operations)",
        "secret_sinks": "Hardcoded secrets flowing into crypto/keychain/network sinks",
    }

    report = """# Trellis {category} Analysis Report

**Binary**: `{binary_name}`
**Generated**: {timestamp}
**Category**: {description}
**Tool**: Trellis for Ghidra

---

## Summary

| Metric | Value |
|--------|-------|
| Functions Analyzed | {func_count} |
| Total Findings | {finding_count} |
| Critical | {critical} |
| High | {high} |
| Medium | {medium} |
| Low | {low} |
| Info | {info} |

---

## Security Findings

""".format(
        category=category.title(),
        binary_name=binary_name,
        timestamp=timestamp,
        description=category_descriptions.get(category, category),
        func_count=len(results),
        finding_count=len(all_findings),
        critical=severity_counts[Severity.CRITICAL],
        high=severity_counts[Severity.HIGH],
        medium=severity_counts[Severity.MEDIUM],
        low=severity_counts[Severity.LOW],
        info=severity_counts[Severity.INFO],
    )

    if all_findings:
        # Group findings by severity
        for severity in [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]:
            severity_findings = [f for f in all_findings if f.severity == severity]
            if severity_findings:
                emoji = SEVERITY_EMOJI.get(severity, "")
                report += "### {} {} ({})\n\n".format(
                    emoji, severity.value, len(severity_findings)
                )

                for finding in severity_findings:
                    report += "#### {}\n\n".format(finding.issue_type)
                    report += "**Description**: {}\n\n".format(finding.description)

                    # Calculate offset
                    offset_str = ""
                    try:
                        offset = finding.location - program.image_base
                        offset_str = " (Offset: `{}`)".format(hex(offset))
                    except:
                        pass

                    # Demangle function name
                    display_name = finding.function_name
                    if is_swift_symbol(finding.function_name):
                        demangled = demangle(finding.function_name)
                        if demangled != finding.function_name:
                            display_name = demangled

                    report += "**Location**: `{}`{}\n\n".format(
                        hex(finding.location), offset_str
                    )
                    report += "**Function**: `{}`\n\n".format(display_name)

                    if finding.evidence:
                        report += "**Evidence**:\n"
                        for key, value in finding.evidence.items():
                            report += "- {}: `{}`\n".format(key, value)
                        report += "\n"

                    report += "**Impact**: {}\n\n".format(finding.impact)

                    if finding.recommendation:
                        report += "**Recommendation**: {}\n\n".format(
                            finding.recommendation
                        )

                    report += "---\n\n"
    else:
        report += "*No security issues detected.*\n\n---\n\n"

    # Functions analyzed section
    report += "## Functions Analyzed\n\n"

    for found_func, refs, call_tree, findings in results:
        report += "### `{}`\n\n".format(found_func.name)
        report += "- **Library**: {}\n".format(found_func.signature.library)
        report += "- **Address**: `{}`\n".format(hex(found_func.address))
        report += "- **Type**: {}\n".format(found_func.symbol_type)

        if refs:
            report += "- **Call Sites**: {}\n".format(len(refs))
            report += "\n| Caller | Address |\n|--------|--------|\n"
            for ref in refs[:20]:
                caller_func = program.get_function_containing(ref.from_address)
                caller_name = caller_func.name if caller_func else "<unknown>"
                report += "| `{}` | `{}` |\n".format(caller_name, hex(ref.from_address))
            if len(refs) > 20:
                report += "\n*...and {} more call sites*\n".format(len(refs) - 20)

        if findings:
            report += "- **Findings**: {} issue(s)\n".format(len(findings))

        report += "\n"

    report += """---

## Next Steps

1. Review each finding and assess its impact
2. Use Frida scripts for runtime validation (generate with Trellis CLI)
3. Address critical and high severity issues first
4. Consider security notes for functions without specific findings

---

*Generated by [Trellis](https://github.com/cylentsec/Trellis) - iOS Security Analysis Toolkit for Ghidra*
"""

    return report


def format_standalone_findings_report(
    binary_name, category_title, description, findings, program
):
    """
    Format standalone security findings (not from call-site analysis) into a report.
    Used for string-table scans and other non-signature-based checks.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    severity_counts = {s: 0 for s in Severity}
    for f in findings:
        severity_counts[f.severity] += 1

    report = "# Trellis {} Report\n\n".format(category_title)
    report += "**Binary**: `{}`\n".format(binary_name)
    report += "**Generated**: {}\n".format(timestamp)
    report += "**Category**: {}\n".format(description)
    report += "**Tool**: Trellis for Ghidra\n\n---\n\n"

    report += "## Summary\n\n"
    report += "| Metric | Value |\n|--------|-------|\n"
    report += "| Total Findings | {} |\n".format(len(findings))
    report += "| Critical | {} |\n".format(severity_counts[Severity.CRITICAL])
    report += "| High | {} |\n".format(severity_counts[Severity.HIGH])
    report += "| Medium | {} |\n".format(severity_counts[Severity.MEDIUM])
    report += "| Low | {} |\n".format(severity_counts[Severity.LOW])
    report += "| Info | {} |\n\n---\n\n".format(severity_counts[Severity.INFO])

    report += "## Security Findings\n\n"

    if findings:
        for severity in [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]:
            sev_findings = [f for f in findings if f.severity == severity]
            if sev_findings:
                emoji = SEVERITY_EMOJI.get(severity, "")
                report += "### {} {} ({})\n\n".format(
                    emoji, severity.value, len(sev_findings)
                )

                for finding in sev_findings:
                    report += "#### {}\n\n".format(finding.issue_type)
                    report += "**Description**: {}\n\n".format(finding.description)

                    offset_str = ""
                    try:
                        offset = finding.location - program.image_base
                        offset_str = " (Offset: `{}`)".format(hex(offset))
                    except Exception:
                        pass

                    report += "**Location**: `{}`{}\n\n".format(
                        hex(finding.location), offset_str
                    )

                    if finding.evidence:
                        report += "**Evidence**:\n"
                        for key, value in finding.evidence.items():
                            report += "- {}: `{}`\n".format(key, value)
                        report += "\n"

                    report += "**Impact**: {}\n\n".format(finding.impact)

                    if finding.recommendation:
                        report += "**Recommendation**: {}\n\n".format(
                            finding.recommendation
                        )

                    report += "---\n\n"
    else:
        report += "*No security issues detected.*\n\n---\n\n"

    report += (
        "---\n\n*Generated by Trellis - iOS Security Analysis Toolkit for Ghidra*\n"
    )
    return report


def analyze_category(
    program, category, monitor, output_dir, secret_string_findings=None
):
    """
    Run analysis for a single security category.

    Args:
        program: GhidraProgram wrapper
        category: Category name
        monitor: Ghidra TaskMonitor
        output_dir: Path to save the report
        secret_string_findings: Optional list of string findings to pass to
            SecretSinkSecurityChecker for cross-reference fallback

    Returns:
        Dict with findings, functions, report_path keys
    """
    print("[Trellis] Analyzing {}...".format(category))
    monitor.setMessage("Loading {} signatures...".format(category))

    # Load signature database
    db = load_category(category)
    if db is None:
        print("[Trellis] Failed to load {} signatures".format(category))
        return None

    print(
        "[Trellis] Loaded {} function signatures for {}".format(
            len(db.functions), category
        )
    )

    # Find matching functions
    monitor.setMessage("Finding {} functions...".format(category))
    found = find_functions(program, db)

    if not found:
        print("[Trellis] No {} functions found in binary".format(category))
        return {
            "findings": 0,
            "functions": 0,
            "report_path": None,
            "category": category,
        }

    print("[Trellis] Found {} {} functions".format(len(found), category))

    # Initialize security checker
    security_checker = get_security_checker(category, program)

    # If this is secret_sinks and we have string findings, inject them
    if (
        category == "secret_sinks"
        and secret_string_findings
        and security_checker
        and hasattr(security_checker, "set_secret_strings")
    ):
        security_checker.set_secret_strings(secret_string_findings)
        print(
            "[Trellis] Injected {} string findings into secret_sinks checker".format(
                len(secret_string_findings)
            )
        )

    # Analyze each function
    results = []
    for idx, found_func in enumerate(found):
        if monitor.isCancelled():
            break

        monitor.setMessage(
            "Analyzing {} ({}/{}): {}...".format(
                category, idx + 1, len(found), found_func.name[:40]
            )
        )

        all_findings = []
        call_refs = []

        # ObjC selectors (found via string-table search) already carry their
        # call-site info: found_func.address is the instruction that references
        # the selector string, and found_func.ghidra_function is the containing
        # caller.  Searching get_references_to() on that instruction address
        # returns nothing useful, so we synthesize the CallSite directly.
        if found_func.symbol_type == "objc_selector" and security_checker:
            if found_func.ghidra_function:
                call_site = CallSite(
                    caller_address=found_func.ghidra_function.address,
                    caller_name=found_func.ghidra_function.name,
                    call_instruction_address=found_func.address,
                    callee_name=found_func.name,
                )

                extracted = extract_call_info(program, call_site, found_func.signature)

                findings = security_checker.check_call_site(
                    found_func.signature, call_site, extracted
                )
                all_findings.extend(findings)
                # Synthetic single-element list so the report shows "Call Sites: 1"
                call_refs = [
                    type(
                        "Ref",
                        (),
                        {
                            "from_address": found_func.address,
                            "to_address": found_func.address,
                            "is_call": True,
                        },
                    )()
                ]
        else:
            # Standard path: imports and internal symbols — look up xrefs
            refs = program.get_references_to(found_func.address)
            call_refs = [r for r in refs if r.is_call]

            if call_refs and security_checker:
                for ref in call_refs:
                    caller_func = program.get_function_containing(ref.from_address)
                    caller_name = caller_func.name if caller_func else "<unknown>"

                    call_site = CallSite(
                        caller_address=caller_func.address
                        if caller_func
                        else ref.from_address,
                        caller_name=caller_name,
                        call_instruction_address=ref.from_address,
                        callee_name=found_func.name,
                    )

                    extracted = extract_call_info(
                        program, call_site, found_func.signature
                    )

                    findings = security_checker.check_call_site(
                        found_func.signature, call_site, extracted
                    )
                    all_findings.extend(findings)

            # Delegate fallback: delegate methods (e.g. application:openURL:options:,
            # URLSession:didReceiveChallenge:completionHandler:) are called by the
            # iOS runtime — not by other code in the binary — so they have no
            # inbound xrefs.  When a found function matches a known delegate
            # pattern and has no call_refs, synthesize a self-referencing
            # CallSite so the checker can still analyze the entry point.
            if not call_refs and security_checker:
                _DELEGATE_PATTERNS = DEEPLINK_DELEGATE_PATTERNS + TLS_DELEGATE_PATTERNS
                is_delegate = any(pat in found_func.name for pat in _DELEGATE_PATTERNS)
                if is_delegate:
                    # The delegate function IS the entry point — use its own
                    # address so the checker can look up and decompile it.
                    func_at = program.get_function_at(found_func.address)
                    delegate_addr = func_at.address if func_at else found_func.address
                    delegate_name = func_at.name if func_at else found_func.name

                    call_site = CallSite(
                        caller_address=delegate_addr,
                        caller_name=delegate_name,
                        call_instruction_address=found_func.address,
                        callee_name=found_func.name,
                    )

                    extracted = extract_call_info(
                        program, call_site, found_func.signature
                    )

                    findings = security_checker.check_call_site(
                        found_func.signature, call_site, extracted
                    )
                    all_findings.extend(findings)
                    # Synthetic ref so the report shows this function was analyzed
                    call_refs = [
                        type(
                            "Ref",
                            (),
                            {
                                "from_address": found_func.address,
                                "to_address": found_func.address,
                                "is_call": True,
                            },
                        )()
                    ]

        results.append((found_func, call_refs, None, all_findings))

    # Count findings and collect all findings
    all_findings_list = []
    for _, _, _, findings in results:
        if findings:
            all_findings_list.extend(findings)

    total_findings = len(all_findings_list)

    # Generate report
    monitor.setMessage("Generating {} report...".format(category))
    binary_name = program.filename
    timestamp = datetime.now().strftime("%y-%m-%d-%H%M%S")

    report = format_report(category, binary_name, results, program)
    report_filename = "Trellis-{}-{}.md".format(category.title(), timestamp)
    report_path = output_dir / report_filename

    try:
        with open(str(report_path), "w") as f:
            f.write(report)
        print("[Trellis] Saved report to: {}".format(report_path))
    except Exception as e:
        print("[Trellis] Failed to save report: {}".format(e))
        report_path = None

    # Save findings JSON for Frida generator
    findings_json_path = None
    if all_findings_list:
        try:
            findings_json_path = save_findings(
                all_findings_list,
                str(output_dir),
                category,
                binary_name,
                timestamp,
                image_base=program.image_base,
            )
            print("[Trellis] Saved findings JSON: {}".format(findings_json_path))
        except Exception as e:
            print("[Trellis] Failed to save findings JSON: {}".format(e))

    return {
        "findings": total_findings,
        "functions": len(results),
        "report_path": str(report_path) if report_path else None,
        "findings_json_path": findings_json_path,
        "category": category,
    }


def run_string_table_scan(program, monitor, output_dir):
    """
    Run standalone string-table based security scans.

    Args:
        program: GhidraProgram wrapper
        monitor: Ghidra TaskMonitor
        output_dir: Path to save the report

    Includes:
    - Credential/secret scanner (hardcoded passwords, API keys, HTTP URLs)
    - Jailbreak detection string-table fallback
    - Biometric authentication string-table fallback
    """
    print("[Trellis] Running string-table scans...")
    monitor.setMessage("Scanning string table for secrets and indicators...")

    # String-table credential/secret scanner
    string_checker = StringTableSecurityChecker(program)
    string_findings = string_checker.scan_strings()

    # Cross-reference string findings with function context (xrefs)
    monitor.setMessage("Cross-referencing string findings with function context...")
    xref_findings = string_checker.cross_reference_findings()
    if xref_findings:
        print(
            "[Trellis] String xref analysis produced {} additional findings".format(
                len(xref_findings)
            )
        )

    # Jailbreak string-table fallback
    jb_checker = JailbreakSecurityChecker(program)
    jb_findings = jb_checker.scan_string_table()

    # Biometric string-table fallback
    monitor.setMessage("Scanning for biometric authentication usage...")
    bio_checker = BiometricSecurityChecker(program)
    bio_findings = bio_checker.scan_for_biometric()
    if bio_findings:
        print("[Trellis] Biometric scan produced {} findings".format(len(bio_findings)))

    # Credential-pair proximity detection
    monitor.setMessage("Detecting credential pairs by proximity...")
    pair_findings = string_checker.detect_credential_pairs()
    if pair_findings:
        print(
            "[Trellis] Credential pair detection produced {} findings".format(
                len(pair_findings)
            )
        )

    # UIWebView deprecation scan
    monitor.setMessage("Scanning for deprecated UIWebView usage...")
    webview_checker = WebViewSecurityChecker(program)
    uiwebview_findings = webview_checker.scan_uiwebview_deprecation()
    if uiwebview_findings:
        print(
            "[Trellis] UIWebView deprecation scan produced {} findings".format(
                len(uiwebview_findings)
            )
        )

    # PCI data flow scan
    monitor.setMessage("Scanning for PCI data over cleartext HTTP...")
    pci_checker = PCIDataFlowChecker(program)
    pci_findings = pci_checker.scan_pci_data_flow()
    if pci_findings:
        print(
            "[Trellis] PCI data flow scan produced {} findings".format(
                len(pci_findings)
            )
        )

    # Runtime hardcoded comparison constant scan
    monitor.setMessage("Scanning for hardcoded validation constants...")
    runtime_checker = RuntimeSecurityChecker(program)
    runtime_const_findings = runtime_checker.scan_hardcoded_comparison_constants()
    if runtime_const_findings:
        print(
            "[Trellis] Runtime constant scan produced {} findings".format(
                len(runtime_const_findings)
            )
        )

    all_findings = (
        string_findings
        + xref_findings
        + pair_findings
        + jb_findings
        + bio_findings
        + uiwebview_findings
        + pci_findings
        + runtime_const_findings
    )

    if not all_findings:
        print("[Trellis] No string-table findings")
        return {
            "findings": 0,
            "functions": 0,
            "report_path": None,
            "category": "string_scan",
        }

    print("[Trellis] Found {} string-table findings".format(len(all_findings)))

    # Generate report
    binary_name = program.filename
    report = format_standalone_findings_report(
        binary_name,
        "String-Table Scan",
        "String-table analysis (hardcoded credentials, API keys, HTTP URLs, jailbreak paths)",
        all_findings,
        program,
    )

    timestamp = datetime.now().strftime("%y-%m-%d-%H%M%S")
    report_path = output_dir / "Trellis-StringScan-{}.md".format(timestamp)

    try:
        with open(str(report_path), "w") as f:
            f.write(report)
        print("[Trellis] String scan report: {}".format(report_path))
    except Exception as e:
        print("[Trellis] Failed to save string scan report: {}".format(e))
        report_path = None

    return {
        "findings": len(all_findings),
        "functions": 0,
        "report_path": str(report_path) if report_path else None,
        "category": "string_scan",
        "_string_findings": string_findings + xref_findings,
    }


def run_obfuscated_secrets_scan(program, monitor, output_dir):
    """
    Run decompiler-based obfuscated secret detection scans.

    Includes:
    - Decode→Sink flow analysis (Base64, Hex, XOR, decrypt patterns)
    - XOR obfuscation scan with plaintext recovery
    - AES hardcoded key + ciphertext co-location detection

    All scans use decompiler pseudocode and work for both Swift and ObjC.

    Args:
        program: GhidraProgram wrapper
        monitor: Ghidra TaskMonitor
        output_dir: Path to save the report
    """
    print("[Trellis] Running obfuscated secrets scan...")

    checker = ObfuscationSecurityChecker(program)
    all_findings = []

    # 1. Decompiler-based decode→sink flow analysis (core engine)
    if not monitor.isCancelled():
        monitor.setMessage("Scanning for decode→sink data flow...")
        decode_sink_findings = checker.scan_decode_to_sink()
        if decode_sink_findings:
            print(
                "[Trellis] Decode→Sink scan: {} findings".format(
                    len(decode_sink_findings)
                )
            )
            all_findings.extend(decode_sink_findings)

    # 2. XOR decode loop detector (byte-by-byte decode with transform chain)
    if not monitor.isCancelled():
        monitor.setMessage("Scanning for XOR decode loops...")
        loop_findings = checker.scan_xor_decode_loops()
        if loop_findings:
            print(
                "[Trellis] XOR decode loop scan: {} findings".format(len(loop_findings))
            )
            all_findings.extend(loop_findings)

    # 3. XOR obfuscation with recovery (single-expression, non-loop)
    if not monitor.isCancelled():
        monitor.setMessage("Scanning for XOR-obfuscated secrets...")
        xor_findings = checker.scan_for_xor_obfuscation()
        if xor_findings:
            print("[Trellis] XOR scan: {} findings".format(len(xor_findings)))
            all_findings.extend(xor_findings)

    # 4. AES key + ciphertext co-location
    if not monitor.isCancelled():
        monitor.setMessage("Scanning for hardcoded AES key+ciphertext pairs...")
        aes_findings = checker.scan_for_aes_key_ciphertext_pairs()
        if aes_findings:
            print("[Trellis] AES co-location: {} findings".format(len(aes_findings)))
            all_findings.extend(aes_findings)

    if not all_findings:
        print("[Trellis] No obfuscated secret findings")
        return {
            "findings": 0,
            "functions": 0,
            "report_path": None,
            "category": "obfuscated_secrets",
        }

    print("[Trellis] Total obfuscated secret findings: {}".format(len(all_findings)))

    # Generate report
    binary_name = program.filename
    report = format_standalone_findings_report(
        binary_name,
        "Obfuscated Secrets",
        "Decompiler-based detection of encoded/encrypted secrets "
        "(Base64, Hex, XOR, AES) flowing into sensitive sinks",
        all_findings,
        program,
    )

    timestamp = datetime.now().strftime("%y-%m-%d-%H%M%S")
    report_path = output_dir / "Trellis-ObfuscatedSecrets-{}.md".format(timestamp)

    try:
        with open(str(report_path), "w") as f:
            f.write(report)
        print("[Trellis] Obfuscated secrets report: {}".format(report_path))
    except Exception as e:
        print("[Trellis] Failed to save report: {}".format(e))
        report_path = None

    # Save findings JSON for Frida generator
    findings_json_path = None
    try:
        findings_json_path = save_findings(
            all_findings,
            str(output_dir),
            "obfuscated_secrets",
            binary_name,
            timestamp,
            image_base=program.image_base,
        )
        print("[Trellis] Saved findings JSON: {}".format(findings_json_path))
    except Exception as e:
        print("[Trellis] Failed to save findings JSON: {}".format(e))

    return {
        "findings": len(all_findings),
        "functions": 0,
        "report_path": str(report_path) if report_path else None,
        "findings_json_path": findings_json_path,
        "category": "obfuscated_secrets",
    }


def run_url_handler_analysis(program, monitor, output_dir):
    """
    Run URL handler detection and analysis.

    Args:
        program: GhidraProgram wrapper
        monitor: Ghidra TaskMonitor
        output_dir: Path to save the report

    Includes:
    - SwiftUI/UIKit URL handlers
    - Custom URL schemes
    - Cross-referencing schemes with handlers
    - UI entry points
    """
    print("[Trellis] Running URL handler analysis...")
    monitor.setMessage("Detecting URL handlers and schemes...")

    # Find URL handlers
    handlers = find_url_handlers(program)
    if handlers:
        print("[Trellis] Found {} URL handlers".format(len(handlers)))
    else:
        print("[Trellis] No URL handlers detected")

    # Extract URL schemes from strings
    monitor.setMessage("Extracting URL schemes from binary strings...")
    schemes = extract_url_schemes(program)
    if schemes:
        print("[Trellis] Found {} custom URL schemes".format(len(schemes)))
    else:
        print("[Trellis] No custom URL schemes detected")

    # Cross-reference schemes with handlers
    if handlers and schemes:
        monitor.setMessage("Cross-referencing schemes with handlers...")
        schemes = cross_reference_schemes_with_handlers(schemes, handlers, program)
        linked = sum(1 for s in schemes if s.handler_address)
        print("[Trellis] Linked {} schemes to handlers".format(linked))

    # Find UI entry points
    monitor.setMessage("Finding UI entry points...")
    entry_points = find_ui_entry_points(program)
    if entry_points:
        print("[Trellis] Found {} UI entry points".format(len(entry_points)))
    else:
        print("[Trellis] No UI entry points detected")

    if not handlers and not schemes and not entry_points:
        print("[Trellis] No URL handlers, schemes, or UI entry points found")
        return {
            "findings": 0,
            "functions": 0,
            "report_path": None,
            "category": "url_handlers",
        }

    # Generate reports
    binary_name = program.filename
    timestamp = datetime.now().strftime("%y-%m-%d-%H%M%S")

    # Handler report
    handler_report = ""
    if handlers:
        handler_report = format_url_handlers_report(handlers, binary_name)

    # Scheme report
    scheme_report = ""
    if schemes:
        scheme_report = format_url_schemes_report(schemes, binary_name)

    # UI entry points report
    entry_report = ""
    if entry_points:
        entry_report = """### UI Entry Points Detected ({})\n\n""".format(
            len(entry_points)
        )
        entry_report += "| Address | Type | Class | Symbol |\n"
        entry_report += "|---------|------|-------|--------|\n"
        for e in entry_points:
            class_info = e.class_name if e.class_name else "—"
            symbol_display = (
                e.demangled_name[:50] + "..."
                if len(e.demangled_name) > 50
                else e.demangled_name
            )
            entry_report += "| `{}` | {} | `{}` | `{}` |\n".format(
                hex(e.address), e.entry_type, class_info, symbol_display
            )
        entry_report += "\n"

    # Combine reports
    full_report = handler_report + "\n" + scheme_report + "\n" + entry_report

    report_path = output_dir / "Trellis-URLHandlers-{}.md".format(timestamp)
    try:
        with open(str(report_path), "w") as f:
            f.write(full_report)
        print("[Trellis] URL handler report: {}".format(report_path))
    except Exception as e:
        print("[Trellis] Failed to save URL handler report: {}".format(e))
        report_path = None

    # Generate Frida script if handlers were found
    if handlers:
        frida_script = generate_url_handler_frida_script(handlers, binary_name)
        frida_path = output_dir / "trellis-url-handlers-{}.js".format(timestamp)
        try:
            with open(str(frida_path), "w") as f:
                f.write(frida_script)
            print("[Trellis] URL handler Frida script: {}".format(frida_path))
        except Exception as e:
            print("[Trellis] Failed to save Frida script: {}".format(e))

    return {
        "findings": len(handlers) + len(schemes),
        "functions": len(handlers) + len(entry_points),
        "report_path": str(report_path) if report_path else None,
        "category": "url_handlers",
    }


def run_analysis(program, output_dir, monitor):
    """
    Core analysis logic — runs all security categories and saves reports.

    This function is decoupled from the Ghidra GUI and can be called from
    both the interactive Ghidra script (main) and the headless CLI.

    Args:
        program: GhidraProgram wrapper
        output_dir: pathlib.Path for report output
        monitor: Ghidra TaskMonitor (use TaskMonitor.DUMMY for headless)

    Returns:
        List of result dicts (keys: category, findings, functions, report_path)
    """
    print("[Trellis] Starting analysis of: {}".format(program.filename))
    print("[Trellis] Image base: {}".format(hex(program.image_base)))
    print("[Trellis] Reports will be saved to: {}".format(output_dir))

    # Get available categories
    categories = get_available_categories()
    print("[Trellis] Available categories: {}".format(", ".join(categories)))

    # Analyze key security categories (must match available YAML signature files)
    # NOTE: secret_sinks is excluded here — it runs after the string scan so it
    # can receive string findings for cross-reference fallback.
    categories_to_analyze = [
        "crypto",
        "cryptokit",
        "keychain",
        "networking",
        "tls_delegate",
        "jailbreak",
        "antidebug",
        "storage",
        "deserialization",
        "webview",
        "deeplinks",
        "sqlite",
        "logging",
        "endpoints",
        "privacy",
        "integrity",
        "biometric",
        "runtime",
        "insecure_storage",
        "obfuscation",
    ]

    all_results = []
    for category in categories_to_analyze:
        if monitor.isCancelled():
            break
        result = analyze_category(program, category, monitor, output_dir)
        if result:
            all_results.append(result)

    # Standalone string-table scans (credentials, HTTP URLs, jailbreak fallback)
    # Must run BEFORE secret_sinks so we can pass string findings for xref fallback.
    string_scan_findings = []  # Will hold string findings for secret_sinks
    if not monitor.isCancelled():
        string_result = run_string_table_scan(program, monitor, output_dir)
        if string_result:
            all_results.append(string_result)
            # Collect the string findings for secret_sinks xref fallback
            if string_result.get("_string_findings"):
                string_scan_findings = string_result["_string_findings"]

    # Secret sinks analysis — runs after string scan to enable xref fallback
    if not monitor.isCancelled():
        print(
            "[Trellis] Passing {} string findings to secret_sinks".format(
                len(string_scan_findings)
            )
        )
        result = analyze_category(
            program,
            "secret_sinks",
            monitor,
            output_dir,
            secret_string_findings=string_scan_findings,
        )
        if result:
            all_results.append(result)

    # Obfuscated secrets analysis — decompiler-based decode→sink scan,
    # XOR recovery, and AES key+ciphertext co-location detection.
    if not monitor.isCancelled():
        obfuscated_result = run_obfuscated_secrets_scan(program, monitor, output_dir)
        if obfuscated_result:
            all_results.append(obfuscated_result)

    # URL handler analysis (SwiftUI/UIKit handlers, custom schemes, UI entry points)
    if not monitor.isCancelled():
        url_result = run_url_handler_analysis(program, monitor, output_dir)
        if url_result:
            all_results.append(url_result)

    # Print summary
    print("\n" + "=" * 60)
    print("[Trellis] ANALYSIS COMPLETE")
    print("=" * 60)

    total_findings = sum(r.get("findings", 0) for r in all_results)
    total_functions = sum(r.get("functions", 0) for r in all_results)

    for result in all_results:
        print(
            "  {}: {} findings in {} functions".format(
                result["category"],
                result.get("findings", 0),
                result.get("functions", 0),
            )
        )
        if result.get("report_path"):
            print("    Report: {}".format(result["report_path"]))

    print(
        "\nTotal: {} security issues across {} functions".format(
            total_findings, total_functions
        )
    )

    return all_results


def main():
    """Ghidra GUI entry point for the Trellis analysis script."""
    if not TRELLIS_AVAILABLE:
        print("[Trellis] ERROR: Trellis modules not available")
        return

    # Get Ghidra globals (injected by the Ghidra script runtime)
    try:
        program = GhidraProgram(currentProgram, monitor)  # noqa: F821
    except Exception as e:
        print("[Trellis] Error initializing: {}".format(e))
        return

    # Prompt user for output directory
    try:
        output_java_file = askDirectory(  # noqa: F821
            "Trellis: Choose Report Output Directory", "Save Reports"
        )
        output_dir = Path(str(output_java_file))
    except Exception:
        output_dir = Path.home() / "Documents"
        print("[Trellis] No directory selected, defaulting to: {}".format(output_dir))

    run_analysis(program, output_dir, monitor)  # noqa: F821


# Run the script
if __name__ == "__main__":
    main()
