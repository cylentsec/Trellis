"""
Swift symbol demangling utilities.

This module provides functions for detecting and demangling Swift symbols.
It uses the `swift demangle` command-line tool which is available on macOS
with Xcode or Swift toolchain installed.

Usage:
    from trellis_ghidra.analysis.swift_demangle import is_swift_symbol, demangle
    
    symbol = "$s9MyModule10SomeClassC6methodyyF"
    if is_swift_symbol(symbol):
        readable = demangle(symbol)
        print(readable)  # "MyModule.SomeClass.method() -> ()"
"""

import subprocess
from typing import Dict, List, Optional
from functools import lru_cache


def is_swift_symbol(name: str) -> bool:
    """
    Check if a symbol name is a Swift mangled symbol.
    
    Swift symbols start with '$s' or '_$s' (with C underscore prefix).
    
    Args:
        name: Symbol name to check
        
    Returns:
        True if the symbol appears to be Swift mangled
    """
    if not name:
        return False
    return name.startswith('$s') or name.startswith('_$s')


@lru_cache(maxsize=1024)
def demangle(symbol: str) -> str:
    """
    Demangle a single Swift symbol.
    
    Uses the `swift demangle` command-line tool. Falls back to returning
    the original symbol if demangling fails.
    
    Results are cached to avoid repeated subprocess calls.
    
    Args:
        symbol: Mangled Swift symbol
        
    Returns:
        Demangled symbol name, or original if demangling failed
    """
    if not is_swift_symbol(symbol):
        return symbol
    
    try:
        result = subprocess.run(
            ['swift', 'demangle', symbol],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        # swift command not available or timed out
        pass
    
    return symbol


def demangle_many(symbols: List[str]) -> Dict[str, str]:
    """
    Demangle multiple Swift symbols in a single batch.
    
    More efficient than calling demangle() for each symbol when
    processing many symbols at once.
    
    Args:
        symbols: List of mangled Swift symbols
        
    Returns:
        Dictionary mapping mangled names to demangled names
    """
    if not symbols:
        return {}
    
    # Filter to only Swift symbols
    swift_symbols = [s for s in symbols if is_swift_symbol(s)]
    if not swift_symbols:
        return {s: s for s in symbols}
    
    # Check cache first
    result = {}
    uncached = []
    
    for sym in symbols:
        cached = demangle.cache_info()  # Check if in cache
        # Try individual lookup
        if is_swift_symbol(sym):
            try:
                # Will use cache if available
                result[sym] = demangle(sym)
            except:
                uncached.append(sym)
        else:
            result[sym] = sym
    
    # For any remaining symbols, try batch demangling
    if uncached:
        try:
            # Batch demangle using stdin
            proc = subprocess.Popen(
                ['swift', 'demangle'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, _ = proc.communicate(
                input='\n'.join(uncached),
                timeout=30
            )
            
            if proc.returncode == 0 and stdout:
                lines = stdout.strip().split('\n')
                for mangled, demangled in zip(uncached, lines):
                    result[mangled] = demangled.strip()
                    # Update cache
                    demangle.cache_clear()  # Clear and repopulate
                    
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            # Fall back to original names
            for sym in uncached:
                result[sym] = sym
    
    return result


def extract_swift_components(demangled: str) -> Dict[str, str]:
    """
    Extract components from a demangled Swift symbol.
    
    Args:
        demangled: Demangled Swift symbol string
        
    Returns:
        Dictionary with extracted components:
        - module: Module name
        - type: Type/class name  
        - member: Method/property name
        - full: Full demangled string
    """
    components = {
        'module': '',
        'type': '',
        'member': '',
        'full': demangled
    }
    
    # Try to extract module.Type.member pattern
    parts = demangled.split('.')
    if len(parts) >= 3:
        components['module'] = parts[0]
        components['type'] = parts[1]
        # Member might include signature
        member_part = '.'.join(parts[2:])
        # Strip signature info after first (
        if '(' in member_part:
            member_part = member_part.split('(')[0]
        components['member'] = member_part
    elif len(parts) == 2:
        components['module'] = parts[0]
        components['type'] = parts[1].split('(')[0] if '(' in parts[1] else parts[1]
    elif len(parts) == 1:
        components['type'] = demangled.split('(')[0] if '(' in demangled else demangled
    
    return components


def format_symbol(symbol: str, max_length: int = 80) -> str:
    """
    Format a symbol for display, demangling if necessary and truncating.
    
    Args:
        symbol: Symbol name (mangled or not)
        max_length: Maximum length before truncation
        
    Returns:
        Formatted symbol string
    """
    display = demangle(symbol) if is_swift_symbol(symbol) else symbol
    
    if len(display) > max_length:
        return display[:max_length - 3] + "..."
    
    return display


__all__ = [
    "is_swift_symbol",
    "demangle",
    "demangle_many",
    "extract_swift_components",
    "format_symbol",
]
