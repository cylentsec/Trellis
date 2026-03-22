# -*- coding: utf-8 -*-
"""
Frida script generators for Trellis (Ghidra port).

This module re-exports the Frida script generators from the frida/ subpackage,
which provides comprehensive instrumentation scripts for iOS security analysis.

All generated scripts use Frida 17+ APIs exclusively.

Features:
    - Frida 17+ compatible (Module.getGlobalExportByName, ptr.readU32(), etc.)
    - Ghidra address translation for cross-referencing
    - Lazy loading to prevent iOS watchdog kills during startup
    - Jailbreak-safe app module detection
    - Safe ObjC method hooking patterns
    - Optional bypass modes for anti-debug and jailbreak detection
"""

# Import from the frida subpackage
from .frida import (
    # Base utilities
    generate_hook,
    combine_hooks,
    generate_category_script,
    get_script_header,
    get_frida_formatter,
    CC_CONSTANTS,
    # Category-specific generators
    generate_crypto_script,
    generate_networking_script,
    generate_keychain_script,
    generate_antidebug_script,
    generate_jailbreak_script,
    generate_secrets_script,
    generate_tls_delegate_script,
    generate_webview_bridge_script,
    generate_deeplinks_script,
    generate_storage_script,
    generate_deserialization_script,
)

# Import findings-driven generators
from .frida.findings import (
    generate_findings_script,
    generate_hybrid_script,
    generate_finding_hook,
    group_findings_by_function,
)

# Backward-compatible alias
generate_hook_for_function = generate_hook


def generate_crypto_tracer(found_functions):
    """
    Generate a comprehensive Frida script to trace crypto functions.

    Args:
        found_functions: List of FoundFunction objects, or None for full tracer

    Returns:
        String containing complete Frida script
    """
    if found_functions:
        hooks = [generate_hook(func.signature) for func in found_functions]
        return combine_hooks(hooks, "crypto", "(auto-detected)")
    return generate_crypto_script("(auto-detected)")


def generate_keychain_tracer(found_functions):
    """
    Generate Frida script to trace keychain operations.

    Args:
        found_functions: List of FoundFunction objects, or None for full tracer

    Returns:
        String containing complete Frida script
    """
    if found_functions:
        hooks = [generate_hook(func.signature) for func in found_functions]
        return combine_hooks(hooks, "keychain", "(auto-detected)")
    return generate_keychain_script("(auto-detected)")


def generate_tls_tracer():
    """
    Generate Frida script to trace TLS validation.

    Returns:
        String containing complete Frida script
    """
    return generate_tls_delegate_script("(auto-detected)")


def save_frida_script(script_content, output_path):
    """
    Save a generated Frida script to a file.

    Args:
        script_content: JavaScript code string
        output_path: Path to save the script

    Returns:
        True if saved successfully, False otherwise
    """
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(script_content)
        return True
    except Exception as e:
        print("[Trellis] Failed to save Frida script: {}".format(e))
        return False


__all__ = [
    # Base
    "generate_hook",
    "generate_hook_for_function",
    "combine_hooks",
    "generate_category_script",
    "get_script_header",
    "get_frida_formatter",
    "CC_CONSTANTS",
    # Category generators
    "generate_crypto_script",
    "generate_networking_script",
    "generate_keychain_script",
    "generate_antidebug_script",
    "generate_jailbreak_script",
    "generate_secrets_script",
    "generate_tls_delegate_script",
    "generate_webview_bridge_script",
    "generate_deeplinks_script",
    "generate_storage_script",
    "generate_deserialization_script",
    # Findings-driven generators
    "generate_findings_script",
    "generate_hybrid_script",
    "generate_finding_hook",
    "group_findings_by_function",
    # Backward-compatible wrappers
    "generate_crypto_tracer",
    "generate_keychain_tracer",
    "generate_tls_tracer",
    "save_frida_script",
]
