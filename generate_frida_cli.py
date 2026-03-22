#!/usr/bin/env python3
"""
Trellis-Ghidra Frida Script Generator CLI

Generate Frida instrumentation scripts for iOS security analysis without
requiring Ghidra. Scripts can be used directly with frida-tools.

Usage:
    ./generate_frida_cli.py --help
    ./generate_frida_cli.py -m crypto -o crypto_hooks.js
    ./generate_frida_cli.py -m all -o all_hooks.js
    ./generate_frida_cli.py -m antidebug,jailbreak --bypass -o bypass.js
"""

import argparse
import sys
from pathlib import Path

# Add ghidra_scripts to path for standalone usage
script_dir = Path(__file__).parent / "ghidra_scripts"
sys.path.insert(0, str(script_dir))

# Import Frida generators directly (they don't require Ghidra runtime)
from trellis_ghidra.generators.frida.crypto import generate_crypto_script
from trellis_ghidra.generators.frida.networking import generate_networking_script
from trellis_ghidra.generators.frida.keychain import generate_keychain_script
from trellis_ghidra.generators.frida.antidebug import generate_antidebug_script
from trellis_ghidra.generators.frida.jailbreak import generate_jailbreak_script

# Paths to static hook scripts
FRIDA_DIR = script_dir / "trellis_ghidra" / "generators" / "frida"
UI_HOOKS_PATH = FRIDA_DIR / "ui_hooks.js"
WEBVIEW_HOOKS_PATH = FRIDA_DIR / "webview_hooks.js"
TELEPORT_HOOKS_PATH = FRIDA_DIR / "teleport_hooks.js"


def generate_ui_script(_binary_name: str = None, **kwargs) -> str:
    """Load the static UI interaction hooks script."""
    if UI_HOOKS_PATH.exists():
        return UI_HOOKS_PATH.read_text()
    return "// UI hooks not available\n"


def generate_webview_script(_binary_name: str = None, **kwargs) -> str:
    """Load the static WebView security scanner script."""
    if WEBVIEW_HOOKS_PATH.exists():
        return WEBVIEW_HOOKS_PATH.read_text()
    return "// WebView hooks not available\n"


def generate_teleport_script(_binary_name: str = None, **kwargs) -> str:
    """Load the static GPS teleporter script."""
    if TELEPORT_HOOKS_PATH.exists():
        return TELEPORT_HOOKS_PATH.read_text()
    return "// GPS teleport hooks not available\n"


AVAILABLE_MODULES = {
    "ui": {
        "generator": generate_ui_script,
        "description": "UI interaction hooks (UIControl, gestures, SwiftUI buttons)",
        "supports_bypass": False,
    },
    "webview": {
        "generator": generate_webview_script,
        "description": "WebView security scanner (JS bridges, URL loading, UIWebView detection)",
        "supports_bypass": False,
    },
    "teleport": {
        "generator": generate_teleport_script,
        "description": "GPS location spoofing (CLLocation hooks with move() function)",
        "supports_bypass": False,
    },
    "crypto": {
        "generator": generate_crypto_script,
        "description": "Cryptographic APIs (CommonCrypto, Security.framework)",
        "supports_bypass": False,
    },
    "networking": {
        "generator": generate_networking_script,
        "description": "Network/TLS APIs (URLSession, SecureTransport)",
        "supports_bypass": False,
    },
    "keychain": {
        "generator": generate_keychain_script,
        "description": "Keychain Services (SecItem* functions)",
        "supports_bypass": False,
    },
    "antidebug": {
        "generator": generate_antidebug_script,
        "description": "Anti-debugging techniques (ptrace, sysctl, etc.)",
        "supports_bypass": True,
    },
    "jailbreak": {
        "generator": generate_jailbreak_script,
        "description": "Jailbreak detection methods (file checks, dlopen, etc.)",
        "supports_bypass": True,
    },
}


def list_modules():
    """Print available modules and their descriptions."""
    print("\nAvailable Modules:")
    print("-" * 60)
    for name, info in AVAILABLE_MODULES.items():
        bypass_note = " [supports --bypass]" if info["supports_bypass"] else ""
        print(f"  {name:12} - {info['description']}{bypass_note}")
    print("-" * 60)
    print("\nUse 'all' to generate scripts for all modules.")
    print("Use comma-separated values for multiple modules: -m crypto,networking")


def generate_combined_script(modules: list, include_bypass: bool) -> str:
    """Generate a combined script with multiple modules."""
    scripts = []
    header = f"""// Trellis-Ghidra Combined Frida Script
// Modules: {', '.join(modules)}
// Frida API: 17.x+ compatible
//
// Usage: frida -U -f <bundle_id> -l <script.js>

"""
    scripts.append(header)

    for module in modules:
        if module not in AVAILABLE_MODULES:
            print(f"Warning: Unknown module '{module}', skipping.", file=sys.stderr)
            continue

        info = AVAILABLE_MODULES[module]
        generator = info["generator"]

        scripts.append(f"\n// {'=' * 60}")
        scripts.append(f"// Module: {module.upper()}")
        scripts.append(f"// {'=' * 60}\n")

        if info["supports_bypass"]:
            script = generator(include_bypass=include_bypass)
        else:
            script = generator()

        # Remove duplicate headers from individual scripts when combining
        lines = script.split('\n')
        in_header = True
        filtered_lines = []
        for line in lines:
            if in_header and (line.startswith('//') or line.strip() == ''):
                continue
            else:
                in_header = False
                filtered_lines.append(line)

        scripts.append('\n'.join(filtered_lines))

    return '\n'.join(scripts)


def main():
    parser = argparse.ArgumentParser(
        description="Trellis-Ghidra Frida Script Generator - Generate iOS instrumentation scripts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -m crypto -o crypto.js
      Generate crypto hooks, save to crypto.js

  %(prog)s -m all
      Generate all module hooks, print to stdout

  %(prog)s -m antidebug,jailbreak --bypass -o bypass.js
      Generate anti-debug and jailbreak hooks with bypass code

  %(prog)s --list
      Show available modules

For more information, see the Trellis-Ghidra documentation.
        """,
    )

    parser.add_argument(
        "-m", "--modules",
        type=str,
        help="Module(s) to generate: ui, webview, teleport, crypto, networking, keychain, antidebug, jailbreak, or 'all'",
    )

    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Output file path (default: print to stdout)",
    )

    parser.add_argument(
        "--bypass",
        action="store_true",
        help="Include bypass code for antidebug and jailbreak modules",
    )

    parser.add_argument(
        "--list",
        action="store_true",
        help="List available modules and exit",
    )

    parser.add_argument(
        "--separate",
        action="store_true",
        help="Generate separate files for each module (requires -o as directory)",
    )

    args = parser.parse_args()

    # Handle --list
    if args.list:
        list_modules()
        return 0

    # Validate required arguments
    if not args.modules:
        parser.print_help()
        print("\nError: -m/--modules is required. Use --list to see available modules.")
        return 1

    # Parse modules
    if args.modules.lower() == "all":
        modules = list(AVAILABLE_MODULES.keys())
    else:
        modules = [m.strip().lower() for m in args.modules.split(",")]

    # Validate modules
    invalid_modules = [m for m in modules if m not in AVAILABLE_MODULES]
    if invalid_modules:
        print(f"Error: Unknown module(s): {', '.join(invalid_modules)}")
        list_modules()
        return 1

    # Generate scripts
    if args.separate:
        # Generate separate files for each module
        if not args.output:
            print("Error: --separate requires -o/--output to specify output directory")
            return 1

        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)

        for module in modules:
            info = AVAILABLE_MODULES[module]
            generator = info["generator"]

            if info["supports_bypass"]:
                script = generator(include_bypass=args.bypass)
            else:
                script = generator()

            output_file = output_dir / f"{module}_hooks.js"
            output_file.write_text(script)
            print(f"Generated: {output_file}")

        print(f"\nAll scripts saved to: {output_dir}/")

    else:
        # Generate combined or single script
        if len(modules) == 1:
            module = modules[0]
            info = AVAILABLE_MODULES[module]
            generator = info["generator"]

            if info["supports_bypass"]:
                script = generator(include_bypass=args.bypass)
            else:
                script = generator()
        else:
            script = generate_combined_script(modules, args.bypass)

        # Output
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(script)
            print(f"Generated: {args.output}")
        else:
            print(script)

    return 0


if __name__ == "__main__":
    sys.exit(main())
