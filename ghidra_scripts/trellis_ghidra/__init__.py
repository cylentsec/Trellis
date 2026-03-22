"""
Trellis for Ghidra - iOS Security Analysis Toolkit

This package provides iOS binary security analysis modules for Ghidra.
It analyzes iOS binaries for security-relevant function usage and
generates Frida scripts for dynamic instrumentation.

Modules:
    ghidra_api: Ghidra API abstraction layer
    analysis: Binary analysis (finder, calltree, extractor, security checks)
    signatures: Function signature database loading
    generators: Frida script generation (reused from original)
"""

__version__ = "0.1.0"
__author__ = "Trellis Contributors"
__description__ = "iOS Security Analysis Toolkit for Ghidra + Frida"

# When running in Ghidra, these will be available
# When running outside Ghidra (syntax check), we use stubs
try:
    from ghidra.program.model.listing import Program
    from ghidra.program.model.symbol import SymbolType
    GHIDRA_AVAILABLE = True
except ImportError:
    GHIDRA_AVAILABLE = False

__all__ = [
    "__version__",
    "__author__",
    "__description__",
    "GHIDRA_AVAILABLE",
]
