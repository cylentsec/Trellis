# @category iOS Security
# @menupath Tools.Trellis.Generate Frida Scripts
# @toolbar python.png
# @description Generate Frida instrumentation scripts for functions found in the binary

"""
Trellis for Ghidra - Frida Script Generator

This script generates ready-to-use Frida instrumentation scripts based on
security-relevant functions found in the currently loaded binary.

Usage:
    1. Open an iOS binary in Ghidra
    2. Run this script via Tools > Trellis > Generate Frida Scripts
    3. Choose which tracer type(s) to generate
    4. Choose an output directory when prompted
    5. Scripts are saved as .js files to the selected directory
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
    from trellis_ghidra.signatures import load_category
    from trellis_ghidra.analysis.finder import find_functions, find_all_categories
    from trellis_ghidra.analysis.findings_storage import (
        load_findings,
        load_findings_with_metadata,
    )
    from trellis_ghidra.generators import (
        generate_hook_for_function,
        generate_crypto_tracer,
        generate_keychain_tracer,
        generate_tls_tracer,
        generate_networking_script,
        generate_antidebug_script,
        generate_jailbreak_script,
        generate_webview_bridge_script,
        generate_deeplinks_script,
        generate_storage_script,
        generate_deserialization_script,
        save_frida_script,
        generate_findings_script,
        generate_hybrid_script,
    )

    TRELLIS_AVAILABLE = True
except ImportError as e:
    print("[Trellis] Error importing Trellis modules: {}".format(e))
    print(
        "[Trellis] Make sure trellis_ghidra package is in the same directory as this script"
    )
    TRELLIS_AVAILABLE = False

# Ghidra imports
from ghidra.util.task import TaskMonitor

# JPype Java imports (PyGhidra uses jpype for Java interop)
try:
    from java.util import ArrayList as JArrayList
except ImportError:
    # Fallback if import fails
    JArrayList = None


# Categories that need immediate hook installation (no lazy loading)
# and global fallback hooks to cover inlined/dynamic-resolved APIs.
_ANTIDEBUG_CATEGORIES = {"antidebug"}

# Maps user-facing tracer names to the categories they scan and their generator
TRACER_OPTIONS = [
    "All Tracers",
    "All Tracers (Findings-Driven)",
    "Crypto Tracer",
    "Crypto Findings",
    "Keychain Tracer",
    "Keychain Findings",
    "TLS/Networking Tracer",
    "TLS Findings",
    "Anti-Debug Tracer",
    "Anti-Debug Findings",
    "Anti-Debug Bypass",
    "Jailbreak Detection Tracer",
    "Jailbreak Findings",
    "Jailbreak Detection Bypass",
    "WebView Bridge Tracer",
    "WebView Findings",
    "Deep Link Tracer",
    "Deeplinks Findings",
    "Storage Tracer",
    "Storage Findings",
    "Deserialization Tracer",
    "Deserialization Findings",
    "Custom — All Found Functions",
]


def generate_findings_for_category(category, output_dir, binary_name, monitor):
    """
    Generate a findings-driven Frida script for a single category.

    This function is decoupled from the Ghidra GUI and can be called from
    both the interactive script and the headless CLI.

    Args:
        category:    Analysis category name (e.g. "crypto", "keychain")
        output_dir:  Directory that contains the findings JSON files (Path or str)
        binary_name: Binary filename (as returned by program.filename)
        monitor:     Ghidra TaskMonitor

    Returns:
        Frida script string, or None if no actionable findings exist
    """
    monitor.setMessage("Loading {} findings...".format(category))
    result = load_findings_with_metadata(str(output_dir), category, binary_name)

    if not result or not result["findings"]:
        print(
            "[Trellis] No {} findings found. Run TrellisAnalyze first.".format(category)
        )
        return None

    findings = result["findings"]
    metadata = result["metadata"]
    image_base = metadata.get("image_base", 0)

    if not image_base:
        print("[Trellis] WARNING: No image_base in {} findings JSON.".format(category))
        print(
            "[Trellis]   Re-run TrellisAnalyze to regenerate findings with image_base."
        )
        print(
            "[Trellis]   Frida hooks will use raw Ghidra addresses (likely wrong at runtime)."
        )

    print(
        "[Trellis] Loaded {} {} findings (image_base=0x{:x})".format(
            len(findings), category, image_base
        )
    )
    monitor.setMessage("Generating findings-driven script for {}...".format(category))

    is_antidebug = category in _ANTIDEBUG_CATEGORIES
    script = generate_findings_script(
        findings,
        binary_name,
        category,
        image_base=image_base,
        lazy_loading=not is_antidebug,
        include_global_fallbacks=is_antidebug,
    )

    from trellis_ghidra.analysis.security_checks import Severity

    actionable_count = sum(1 for f in findings if f.severity != Severity.INFO)
    if actionable_count == 0 and not is_antidebug:
        print(
            "[Trellis] Skipping {} findings script: all {} findings are INFO-level".format(
                category, len(findings)
            )
        )
        return None

    if is_antidebug and actionable_count == 0:
        print(
            "[Trellis] Note: all {} findings are INFO-level, "
            "but global fallback hooks will provide coverage.".format(category)
        )

    return script


def run_frida_generation(program, output_dir, monitor):
    """
    Generate all Frida scripts (generic tracers + findings-driven) and save them.

    This function is decoupled from the Ghidra GUI and can be called from
    both the interactive Ghidra script and the headless CLI.

    Args:
        program:    GhidraProgram wrapper
        output_dir: pathlib.Path for script output (also used to find findings JSON)
        monitor:    Ghidra TaskMonitor (use TaskMonitor.DUMMY for headless)

    Returns:
        List of saved script file paths
    """
    binary_name = program.filename
    timestamp = datetime.now().strftime("%y-%m-%d-%H%M%S")
    saved_scripts = []

    def _save(script, name):
        if script:
            path = output_dir / "trellis-{}-{}.js".format(name, timestamp)
            if save_frida_script(script, str(path)):
                saved_scripts.append(str(path))
                print("[Trellis] Saved: {}".format(path))
                return True
        return False

    # --- Generic tracers ---
    monitor.setMessage("Finding crypto functions...")
    crypto_db = load_category("crypto")
    if crypto_db:
        found = find_functions(program, crypto_db)
        if found:
            print("[Trellis] Found {} crypto functions".format(len(found)))
            _save(generate_crypto_tracer(found), "crypto")
        else:
            print("[Trellis] No crypto functions found in binary")
    else:
        print("[Trellis] Failed to load crypto signatures")

    monitor.setMessage("Generating keychain tracer...")
    _save(generate_keychain_tracer(None), "keychain")

    monitor.setMessage("Generating TLS/networking tracer...")
    _save(generate_tls_tracer(), "tls")
    _save(generate_networking_script(binary_name), "networking")

    monitor.setMessage("Generating anti-debug tracer...")
    _save(generate_antidebug_script(binary_name, include_bypass=False), "antidebug")

    monitor.setMessage("Generating jailbreak detection tracer...")
    _save(generate_jailbreak_script(binary_name, include_bypass=False), "jailbreak")

    monitor.setMessage("Generating WebView bridge tracer...")
    _save(generate_webview_bridge_script(binary_name), "webview")

    monitor.setMessage("Generating deep link tracer...")
    _save(generate_deeplinks_script(binary_name), "deeplinks")

    monitor.setMessage("Generating storage tracer...")
    _save(generate_storage_script(binary_name), "storage")

    monitor.setMessage("Generating deserialization tracer...")
    _save(generate_deserialization_script(binary_name), "deserialization")

    # --- Findings-driven scripts (require prior TrellisAnalyze run) ---
    for category, script_name in [
        ("crypto", "crypto-findings"),
        ("keychain", "keychain-findings"),
        ("tls_delegate", "tls-findings"),
        ("antidebug", "antidebug-findings"),
        ("jailbreak", "jailbreak-findings"),
        ("webview", "webview-findings"),
        ("deeplinks", "deeplinks-findings"),
        ("storage", "storage-findings"),
        ("deserialization", "deserialization-findings"),
    ]:
        script = generate_findings_for_category(
            category, output_dir, binary_name, monitor
        )
        _save(script, script_name)

    # Summary
    print("\n" + "=" * 60)
    print("[Trellis] FRIDA SCRIPT GENERATION COMPLETE")
    print("=" * 60)
    if saved_scripts:
        for s in saved_scripts:
            print("  {}".format(s))
        print("\nRun with:")
        print("  frida -U -f <bundle_id> -l <script.js>")
    else:
        print("  No scripts were generated.")

    return saved_scripts


def generate_custom_tracer(program, monitor):
    """
    Generate a combined Frida script with hooks for every security-relevant
    function found across all signature categories.

    Args:
        program: GhidraProgram wrapper
        monitor: Ghidra TaskMonitor

    Returns:
        String containing complete Frida script, or None if no functions found
    """
    monitor.setMessage("Scanning all categories for functions...")
    all_found = find_all_categories(program)

    if not all_found:
        return None

    parts = [
        "// Trellis Custom Tracer",
        "// Generated for: {}".format(program.filename),
        "// Date: {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "// Frida 17+ compatible",
        "",
        'console.log("[Trellis] Loading custom tracer...");',
        "",
    ]

    total_hooks = 0
    for category, found_functions in sorted(all_found.items()):
        if monitor.isCancelled():
            break
        monitor.setMessage("Generating hooks for {}...".format(category))

        parts.append(
            "// === {} ({} functions) ===".format(
                category.upper(), len(found_functions)
            )
        )

        for func in found_functions:
            parts.append(generate_hook_for_function(func.signature))
            total_hooks += 1

        parts.append("")

    parts.append(
        'console.log("[Trellis] Custom tracer loaded. {} hooks generated.");'.format(
            total_hooks
        )
    )

    return "\n".join(parts)


def main():
    """Main entry point for the Trellis Frida script generator."""
    if not TRELLIS_AVAILABLE:
        print("[Trellis] ERROR: Trellis modules not available")
        return

    # Get Ghidra globals
    try:
        program = GhidraProgram(currentProgram, monitor)
    except Exception as e:
        print("[Trellis] Error initializing: {}".format(e))
        return

    print("[Trellis] Frida Script Generator")
    print("[Trellis] Binary: {}".format(program.filename))

    # Ask which tracer to generate
    # PyGhidra requires Java List object for askChoice
    if JArrayList:
        tracer_list = JArrayList()
        for option in TRACER_OPTIONS:
            tracer_list.add(option)
    else:
        # Fallback to Python list (may fail)
        tracer_list = TRACER_OPTIONS

    choice = askChoice(
        "Trellis: Generate Frida Scripts",
        "Select which Frida tracer to generate:",
        tracer_list,
        TRACER_OPTIONS[0],
    )

    if not choice:
        print("[Trellis] Cancelled.")
        return

    # Prompt for output directory
    try:
        output_java_file = askDirectory(
            "Trellis: Choose Frida Script Output Directory", "Save Scripts"
        )
        output_dir = Path(str(output_java_file))
    except Exception:
        output_dir = Path.home() / "Documents"
        print("[Trellis] No directory selected, defaulting to: {}".format(output_dir))

    print("[Trellis] Scripts will be saved to: {}".format(output_dir))

    timestamp = datetime.now().strftime("%y-%m-%d-%H%M%S")
    saved_scripts = []

    generate_all = choice == "All Tracers"
    generate_all_findings = choice == "All Tracers (Findings-Driven)"
    binary_name = program.filename

    def _save(script, name):
        """Helper to save a script and track it."""
        if script:
            path = output_dir / "trellis-{}-{}.js".format(name, timestamp)
            if save_frida_script(script, str(path)):
                saved_scripts.append(str(path))
                print("[Trellis] Saved: {}".format(path))
                return True
        return False

    def _generate_findings(category):
        """Helper to generate findings-driven script for a category."""
        monitor.setMessage("Loading {} findings...".format(category))
        result = load_findings_with_metadata(str(output_dir), category, binary_name)

        if not result or not result["findings"]:
            print(
                "[Trellis] No {} findings found. Run TrellisAnalyze first.".format(
                    category
                )
            )
            return None

        findings = result["findings"]
        metadata = result["metadata"]
        image_base = metadata.get("image_base", 0)

        if not image_base:
            print(
                "[Trellis] WARNING: No image_base in {} findings JSON.".format(category)
            )
            print(
                "[Trellis]   Re-run TrellisAnalyze to regenerate findings with image_base."
            )
            print(
                "[Trellis]   Frida hooks will use raw Ghidra addresses (likely wrong at runtime)."
            )

        print(
            "[Trellis] Loaded {} {} findings (image_base=0x{:x})".format(
                len(findings), category, image_base
            )
        )
        monitor.setMessage(
            "Generating findings-driven script for {}...".format(category)
        )

        # Anti-debug scripts: disable lazy loading so hooks catch startup
        # checks, and enable global fallback hooks to cover inlined or
        # dynamically-resolved APIs (e.g. always_inline + dlsym patterns).
        is_antidebug = category in _ANTIDEBUG_CATEGORIES
        script = generate_findings_script(
            findings,
            binary_name,
            category,
            image_base=image_base,
            lazy_loading=not is_antidebug,
            include_global_fallbacks=is_antidebug,
        )

        # Check if script has any actionable hooks (INFO-only = 0 hooks)
        # For antidebug, global fallback hooks provide coverage even when
        # all findings are INFO, so don't skip.
        from trellis_ghidra.analysis.security_checks import Severity

        actionable_count = sum(1 for f in findings if f.severity != Severity.INFO)
        if actionable_count == 0 and not is_antidebug:
            print(
                "[Trellis] Skipping {} findings script: all {} findings are INFO-level (no actionable hooks)".format(
                    category, len(findings)
                )
            )
            return None

        if is_antidebug and actionable_count == 0:
            print(
                "[Trellis] Note: all {} findings are INFO-level, but global fallback hooks will provide coverage.".format(
                    category
                )
            )

        return script

    # --- Crypto Tracer ---
    if choice == "Crypto Tracer" or generate_all:
        monitor.setMessage("Finding crypto functions...")
        crypto_db = load_category("crypto")
        if crypto_db:
            found = find_functions(program, crypto_db)
            if found:
                print("[Trellis] Found {} crypto functions".format(len(found)))
                _save(generate_crypto_tracer(found), "crypto")
            else:
                print("[Trellis] No crypto functions found in binary")
        else:
            print("[Trellis] Failed to load crypto signatures")

    # --- Keychain Tracer ---
    if choice == "Keychain Tracer" or generate_all:
        monitor.setMessage("Generating keychain tracer...")
        _save(generate_keychain_tracer(None), "keychain")

    # --- TLS/Networking Tracer ---
    if choice == "TLS/Networking Tracer" or generate_all:
        monitor.setMessage("Generating TLS/networking tracer...")
        _save(generate_tls_tracer(), "tls")
        _save(generate_networking_script(binary_name), "networking")

    # --- Anti-Debug Tracer ---
    if choice == "Anti-Debug Tracer" or generate_all:
        monitor.setMessage("Generating anti-debug tracer...")
        _save(generate_antidebug_script(binary_name, include_bypass=False), "antidebug")

    # --- Anti-Debug Bypass ---
    if choice == "Anti-Debug Bypass":
        monitor.setMessage("Generating anti-debug bypass...")
        _save(
            generate_antidebug_script(binary_name, include_bypass=True),
            "antidebug-bypass",
        )

    # --- Jailbreak Detection Tracer ---
    if choice == "Jailbreak Detection Tracer" or generate_all:
        monitor.setMessage("Generating jailbreak detection tracer...")
        _save(generate_jailbreak_script(binary_name, include_bypass=False), "jailbreak")

    # --- Jailbreak Detection Bypass ---
    if choice == "Jailbreak Detection Bypass":
        monitor.setMessage("Generating jailbreak detection bypass...")
        _save(
            generate_jailbreak_script(binary_name, include_bypass=True),
            "jailbreak-bypass",
        )

    # --- WebView Bridge Tracer ---
    if choice == "WebView Bridge Tracer" or generate_all:
        monitor.setMessage("Generating WebView bridge tracer...")
        _save(generate_webview_bridge_script(binary_name), "webview")

    # --- Deep Link Tracer ---
    if choice == "Deep Link Tracer" or generate_all:
        monitor.setMessage("Generating deep link tracer...")
        _save(generate_deeplinks_script(binary_name), "deeplinks")

    # --- Storage Tracer ---
    if choice == "Storage Tracer" or generate_all:
        monitor.setMessage("Generating storage tracer...")
        _save(generate_storage_script(binary_name), "storage")

    # --- Deserialization Tracer ---
    if choice == "Deserialization Tracer" or generate_all:
        monitor.setMessage("Generating deserialization tracer...")
        _save(generate_deserialization_script(binary_name), "deserialization")

    # --- Custom: all found functions ---
    if choice == "Custom — All Found Functions":
        script = generate_custom_tracer(program, monitor)
        _save(script, "custom")
        if not script:
            print("[Trellis] No security-relevant functions found in binary")

    # --- FINDINGS-DRIVEN MODES ---

    # Crypto Findings
    if choice == "Crypto Findings" or generate_all_findings:
        _save(_generate_findings("crypto"), "crypto-findings")

    # Keychain Findings
    if choice == "Keychain Findings" or generate_all_findings:
        _save(_generate_findings("keychain"), "keychain-findings")

    # TLS Findings
    if choice == "TLS Findings" or generate_all_findings:
        _save(_generate_findings("tls_delegate"), "tls-findings")

    # Anti-Debug Findings
    if choice == "Anti-Debug Findings" or generate_all_findings:
        _save(_generate_findings("antidebug"), "antidebug-findings")

    # Jailbreak Findings
    if choice == "Jailbreak Findings" or generate_all_findings:
        _save(_generate_findings("jailbreak"), "jailbreak-findings")

    # WebView Findings
    if choice == "WebView Findings" or generate_all_findings:
        _save(_generate_findings("webview"), "webview-findings")

    # Deeplinks Findings
    if choice == "Deeplinks Findings" or generate_all_findings:
        _save(_generate_findings("deeplinks"), "deeplinks-findings")

    # Storage Findings
    if choice == "Storage Findings" or generate_all_findings:
        _save(_generate_findings("storage"), "storage-findings")

    # Deserialization Findings
    if choice == "Deserialization Findings" or generate_all_findings:
        _save(_generate_findings("deserialization"), "deserialization-findings")

    # Summary
    print("\n" + "=" * 60)
    print("[Trellis] FRIDA SCRIPT GENERATION COMPLETE")
    print("=" * 60)

    if saved_scripts:
        for s in saved_scripts:
            print("  {}".format(s))
        print("\nRun with:")
        print("  frida -U -f <bundle_id> -l <script.js>")
    else:
        print("  No scripts were generated.")


# Run the script
if __name__ == "__main__":
    main()
