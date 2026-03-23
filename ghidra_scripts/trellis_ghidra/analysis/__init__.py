"""
Binary analysis modules for Trellis (Ghidra Port).

This package provides tools for analyzing iOS binaries with Ghidra,
focusing on security-relevant functionality and patterns.

Modules:
    finder: Find security-relevant functions by matching against signature databases
    calltree: Build call trees showing all paths to security-relevant functions
    extractor: Extract parameter types, values, and return value usage at call sites
    security_checks: Base classes for security analysis
    security_checks_*: Category-specific security checkers

Usage:
    from trellis_ghidra.ghidra_api import get_program
    from trellis_ghidra.analysis import find_functions, build_call_tree
    from trellis_ghidra.signatures import load_category
    
    # In Ghidra script
    program = get_program(currentProgram)
    
    # Find crypto functions
    crypto_db = load_category("crypto")
    crypto_funcs = find_functions(program, crypto_db)
    
    # Build call tree for a found function
    func = crypto_funcs[0]
    tree = build_call_tree(program, func.address, max_depth=5)
"""

# Import main analysis functions
from .finder import (
    FoundFunction,
    find_functions,
    find_all_categories,
)

from .calltree import (
    CallSite,
    CallTreeNode,
    build_call_tree,
    flatten_call_tree,
    print_call_tree,
    count_paths,
    get_call_depth,
)

from .extractor import (
    ExtractedParam,
    ExtractedCallInfo,
    extract_call_info,
    format_extracted_info,
)

from .security_checks import (
    Severity,
    SecurityFinding,
    SecurityChecker,
    SEVERITY_EMOJI,
)

from .findings_storage import (
    save_findings,
    load_findings,
    load_findings_with_metadata,
    save_findings_json,
    load_findings_json,
    find_latest_findings,
    get_findings_summary,
)

# Security checkers
from .security_checks_crypto import CryptoSecurityChecker
from .security_checks_tls import TLSDelegateSecurityChecker
from .security_checks_keychain import KeychainSecurityChecker
from .security_checks_jailbreak import JailbreakSecurityChecker
from .security_checks_storage import StorageSecurityChecker
from .security_checks_deserialization import DeserializationSecurityChecker
from .security_checks_antidebug import AntiDebugSecurityChecker
from .security_checks_webview import WebViewSecurityChecker
from .security_checks_deeplinks import DeepLinkSecurityChecker
from .security_checks_cryptokit import CryptoKitSecurityChecker
from .security_checks_networking import NetworkingSecurityChecker
from .security_checks_sqlite import SQLiteSecurityChecker
from .security_checks_logging import LoggingSecurityChecker
from .security_checks_endpoints import EndpointsSecurityChecker
from .security_checks_strings import StringTableSecurityChecker
from .security_checks_biometric import BiometricSecurityChecker
from .security_checks_runtime import RuntimeSecurityChecker
from .security_checks_obfuscation import ObfuscationSecurityChecker
from .security_checks_secret_sinks import SecretSinkSecurityChecker
from .security_checks_pci import PCIDataFlowChecker

# URL handlers and UI entry points
from .url_handlers import (
    URLHandler,
    URLScheme,
    UIEntryPoint,
    find_url_handlers,
    find_ui_entry_points,
    extract_url_schemes,
    cross_reference_schemes_with_handlers,
    generate_url_handler_frida_script,
    format_url_handlers_report,
    format_url_schemes_report,
)

# Swift demangling (reused from original)
from .swift_demangle import (
    is_swift_symbol,
    demangle,
    demangle_many,
)

__all__ = [
    # Finder
    "FoundFunction",
    "find_functions",
    "find_all_categories",
    # Call tree
    "CallSite",
    "CallTreeNode",
    "build_call_tree",
    "flatten_call_tree",
    "print_call_tree",
    "count_paths",
    "get_call_depth",
    # Extractor
    "ExtractedParam",
    "ExtractedCallInfo",
    "extract_call_info",
    "format_extracted_info",
    # Security checks base
    "Severity",
    "SecurityFinding",
    "SecurityChecker",
    "SEVERITY_EMOJI",
    # Findings storage
    "save_findings",
    "load_findings",
    "load_findings_with_metadata",
    "save_findings_json",
    "load_findings_json",
    "find_latest_findings",
    "get_findings_summary",
    # Security checkers
    "CryptoSecurityChecker",
    "TLSDelegateSecurityChecker",
    "KeychainSecurityChecker",
    "JailbreakSecurityChecker",
    "StorageSecurityChecker",
    "DeserializationSecurityChecker",
    "AntiDebugSecurityChecker",
    "WebViewSecurityChecker",
    "DeepLinkSecurityChecker",
    "CryptoKitSecurityChecker",
    "NetworkingSecurityChecker",
    "SQLiteSecurityChecker",
    "LoggingSecurityChecker",
    "EndpointsSecurityChecker",
    "StringTableSecurityChecker",
    "BiometricSecurityChecker",
    "RuntimeSecurityChecker",
    "ObfuscationSecurityChecker",
    "SecretSinkSecurityChecker",
    "PCIDataFlowChecker",
    # URL handlers
    "URLHandler",
    "URLScheme",
    "UIEntryPoint",
    "find_url_handlers",
    "find_ui_entry_points",
    "extract_url_schemes",
    "cross_reference_schemes_with_handlers",
    "generate_url_handler_frida_script",
    "format_url_handlers_report",
    "format_url_schemes_report",
    # Swift demangling
    "is_swift_symbol",
    "demangle",
    "demangle_many",
]
