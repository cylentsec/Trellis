#!/usr/bin/env python3
"""
Trellis Headless CLI
====================
Run the full Trellis analysis pipeline from the command line — no Ghidra GUI required.

Workflow:
  1. Uses PyGhidra to open the binary and run Ghidra auto-analysis headlessly.
  2. Runs all Trellis security checks and saves per-category Markdown reports.
  3. Generates generic and findings-driven Frida instrumentation scripts.

Usage:
    python trellis_headless.py --binary /path/to/MyApp --output /tmp/results
    python trellis_headless.py -b /path/to/MyApp -o /tmp/results --skip-frida
    python trellis_headless.py -b /path/to/MyApp -o /tmp/results --skip-analysis

Requirements:
    - PyGhidra must be importable (the same venv used by 'ghidra' / pyghidraRun).
    - The binary must be a decrypted iOS Mach-O file.
      See https://github.com/cylentsec/frida-decrypt if you need a decryption tool.
"""

import argparse
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup — make ghidra_scripts importable before PyGhidra starts
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).parent
_GHIDRA_SCRIPTS = _REPO_ROOT / "ghidra_scripts"
if str(_GHIDRA_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_GHIDRA_SCRIPTS))


def parse_args():
    parser = argparse.ArgumentParser(
        prog="trellis_headless.py",
        description="Trellis Headless — iOS binary security analysis without the Ghidra GUI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python trellis_headless.py -b MyApp -o /tmp/trellis-results
      Full pipeline: Ghidra analysis + Markdown reports + Frida scripts

  python trellis_headless.py -b MyApp -o /tmp/results --skip-frida
      Analysis and reports only (no Frida scripts)

  python trellis_headless.py -b MyApp -o /tmp/results --skip-analysis
      Frida script generation only (requires findings JSON from a prior run)

  python trellis_headless.py -b MyApp -o /tmp/results --project-dir /tmp/ghidra-proj
      Use a persistent Ghidra project directory (avoids re-analysis on repeat runs)
""",
    )

    parser.add_argument(
        "-b", "--binary",
        required=True,
        metavar="PATH",
        help="Path to the decrypted iOS Mach-O binary to analyze",
    )
    parser.add_argument(
        "-o", "--output",
        required=True,
        metavar="DIR",
        help="Output directory for Markdown reports and Frida scripts (created if needed)",
    )
    parser.add_argument(
        "--project-dir",
        metavar="DIR",
        default=None,
        help="Ghidra project directory (default: temporary directory). "
             "Use a persistent path to reuse analysis across runs.",
    )
    parser.add_argument(
        "--skip-analysis",
        action="store_true",
        help="Skip Markdown report generation. Useful when re-generating Frida scripts "
             "from existing findings JSON produced by a prior run.",
    )
    parser.add_argument(
        "--skip-frida",
        action="store_true",
        help="Skip Frida script generation.",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    binary_path = Path(args.binary).resolve()
    output_dir = Path(args.output).resolve()

    # Validate binary
    if not binary_path.exists():
        print("[Trellis] ERROR: Binary not found: {}".format(binary_path))
        sys.exit(1)

    if args.skip_analysis and args.skip_frida:
        print("[Trellis] ERROR: --skip-analysis and --skip-frida both set — nothing to do.")
        sys.exit(1)

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    print("[Trellis] Output directory: {}".format(output_dir))

    # -----------------------------------------------------------------------
    # Import PyGhidra — must happen before any Ghidra Java classes are used
    # -----------------------------------------------------------------------
    try:
        import pyghidra
    except ImportError:
        print(
            "[Trellis] ERROR: pyghidra is not importable.\n"
            "  Make sure you are running this script with the Python interpreter\n"
            "  from Ghidra's virtual environment, e.g.:\n"
            "    ~/.config/ghidra/<version>/venv/bin/python trellis_headless.py ...\n"
            "  Or install pyghidra: pip install pyghidra"
        )
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Determine Ghidra project directory
    # -----------------------------------------------------------------------
    _tmp_dir = None  # keep reference to avoid premature cleanup
    if args.project_dir:
        project_dir = Path(args.project_dir).resolve()
        project_dir.mkdir(parents=True, exist_ok=True)
    else:
        _tmp_dir = tempfile.TemporaryDirectory(prefix="trellis-ghidra-")
        project_dir = Path(_tmp_dir.name)

    print("[Trellis] Ghidra project directory: {}".format(project_dir))
    print("[Trellis] Opening binary with Ghidra (auto-analysis will run) ...")
    print("[Trellis] This may take several minutes for large binaries.\n")

    # -----------------------------------------------------------------------
    # Open binary with PyGhidra — imports of Ghidra Java APIs happen INSIDE
    # the context manager after the JVM is initialised.
    # -----------------------------------------------------------------------
    try:
        with pyghidra.open_program(
            str(binary_path),
            project_location=str(project_dir),
            project_name=binary_path.name,
            analyze=True,
        ) as flat_api:
            _run_trellis(flat_api, output_dir, args)
    finally:
        if _tmp_dir is not None:
            _tmp_dir.cleanup()

    print("\n[Trellis] Done. Results saved to: {}".format(output_dir))


def _run_trellis(flat_api, output_dir, args):
    """
    Inner function called once PyGhidra has initialised the JVM.
    All Ghidra Java class imports live here so they only execute
    after pyghidra.open_program() has set up the class loader.
    """
    # Ghidra Java imports (safe now that the JVM is running)
    from ghidra.util.task import TaskMonitor  # noqa: PLC0415

    # Trellis modules (ghidra_scripts/ is on sys.path from module-level setup)
    from trellis_ghidra.ghidra_api import GhidraProgram  # noqa: PLC0415
    from TrellisAnalyze import run_analysis              # noqa: PLC0415
    from TrellisFrida import run_frida_generation        # noqa: PLC0415

    monitor = TaskMonitor.DUMMY
    program = GhidraProgram(flat_api.currentProgram, monitor)

    print("[Trellis] Binary loaded: {}".format(program.filename))
    print("[Trellis] Image base:    {}".format(hex(program.image_base)))

    # --- Step 1: Security analysis → Markdown reports + findings JSON ---
    if not args.skip_analysis:
        print("\n[Trellis] === STEP 1: Security Analysis ===")
        run_analysis(program, output_dir, monitor)
    else:
        print("[Trellis] Skipping analysis (--skip-analysis)")

    # --- Step 2: Frida script generation ---
    if not args.skip_frida:
        print("\n[Trellis] === STEP 2: Frida Script Generation ===")
        run_frida_generation(program, output_dir, monitor)
    else:
        print("[Trellis] Skipping Frida generation (--skip-frida)")


if __name__ == "__main__":
    main()
