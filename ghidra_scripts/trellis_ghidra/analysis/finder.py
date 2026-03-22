"""
Function finder module for Ghidra.

This module finds security-relevant functions in a Ghidra program
by matching against signature databases. It can locate both imported
(external) functions and internal symbol references.

Usage:
    from trellis_ghidra.ghidra_api import get_program
    from trellis_ghidra.signatures import load_category
    from trellis_ghidra.analysis.finder import find_functions
    
    program = get_program(currentProgram)
    crypto_db = load_category("crypto")
    found = find_functions(program, crypto_db)
    
    for func in found:
        print("{} @ {} ({})".format(func.name, hex(func.address), func.symbol_type))
"""

from typing import Optional, List, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from ..ghidra_api import GhidraProgram, GhidraFunction
    from ..signatures import SignatureDatabase, FunctionSignature

from .swift_demangle import is_swift_symbol, demangle_many, demangle


class FoundFunction(object):
    """
    Represents a security-relevant function found in a binary.
    
    Attributes:
        name: Function name as it appears in the binary
        address: Virtual address of the function
        signature: The FunctionSignature from the signature database
        symbol_type: Type of symbol ("import", "symbol", "reference")
        ghidra_function: Ghidra Function object if available
        demangled_name: Demangled name if Swift symbol
    """
    
    def __init__(self, name, address, signature, symbol_type, 
                 ghidra_function=None, demangled_name=None):
        self.name = name
        self.address = address
        self.signature = signature
        self.symbol_type = symbol_type
        self.ghidra_function = ghidra_function
        self.demangled_name = demangled_name


def _find_imported_functions(
    program: "GhidraProgram",
    db: "SignatureDatabase"
) -> List[FoundFunction]:
    """
    Find imported/external functions that match signatures in the database.
    
    Args:
        program: GhidraProgram wrapper
        db: SignatureDatabase to match against
        
    Returns:
        List of FoundFunction objects for matching imports
    """
    found = []
    
    # Iterate through external symbols
    for sym in program.get_external_symbols():
        sym_name = sym.name
        
        # 1. Exact match
        signature = db.get_function(sym_name)
        
        # 2. Try with/without leading underscore (C name mangling)
        if signature is None and sym_name.startswith('_'):
            signature = db.get_function(sym_name[1:])
        if signature is None and not sym_name.startswith('_'):
            signature = db.get_function('_' + sym_name)
        
        if signature is not None:
            found.append(FoundFunction(
                name=signature.name,
                address=sym.address,
                signature=signature,
                symbol_type="import",
                ghidra_function=None,
            ))
            continue
        
        # 3. Check for Swift mangled name
        if is_swift_symbol(sym_name):
            demangled = demangle(sym_name)
            
            # Check if any Swift signature name appears in demangled name
            # IMPORTANT: Only match Swift signatures (those with dots like "SHA256.hash")
            # against Swift symbols. C function names like "system" would incorrectly
            # match Swift names like "SwiftUI.Image.init(systemName:)"
            for func_sig in db.functions.values():
                # Skip C function signatures (no dots) - they shouldn't match Swift symbols
                if "." not in func_sig.name:
                    continue
                if func_sig.name in demangled:
                    found.append(FoundFunction(
                        name=sym_name,
                        address=sym.address,
                        signature=func_sig,
                        symbol_type="import",
                        ghidra_function=None,
                        demangled_name=demangled,
                    ))
                    break
    
    return found


def _find_internal_functions(
    program: "GhidraProgram",
    db: "SignatureDatabase"
) -> List[FoundFunction]:
    """
    Find internal function symbols that match signatures in the database.
    
    Args:
        program: GhidraProgram wrapper
        db: SignatureDatabase to match against
        
    Returns:
        List of FoundFunction objects for matching internal functions
    """
    found = []
    swift_symbols = []
    swift_symbol_funcs = {}  # mangled_name -> GhidraFunction
    
    # Iterate through all internal functions
    for func in program.get_all_functions():
        func_name = func.name
        
        # 1. Check for direct match (including underscore variants)
        signature = db.get_function(func_name)
        if signature is None and func_name.startswith('_'):
            signature = db.get_function(func_name[1:])
        if signature is None and not func_name.startswith('_'):
            signature = db.get_function('_' + func_name)
        
        if signature is not None:
            found.append(FoundFunction(
                name=signature.name,
                address=func.address,
                signature=signature,
                symbol_type="symbol",
                ghidra_function=func,
            ))
        elif is_swift_symbol(func_name):
            # Collect Swift symbols for batch processing
            swift_symbols.append(func_name)
            swift_symbol_funcs[func_name] = func
    
    # 2. Batch demangle Swift symbols
    if swift_symbols:
        demangled_map = demangle_many(swift_symbols)
        
        # Find signatures that match in demangled names
        # Optimization: only check signatures that look like Swift (contain dots)
        swift_signatures = [
            sig for sig in db.functions.values()
            if "." in sig.name
        ]
        
        if swift_signatures:
            for mangled, demangled in demangled_map.items():
                for sig in swift_signatures:
                    if sig.name in demangled:
                        func = swift_symbol_funcs[mangled]
                        found.append(FoundFunction(
                            name=mangled,
                            address=func.address,
                            signature=sig,
                            symbol_type="symbol",
                            ghidra_function=func,
                            demangled_name=demangled,
                        ))
                        break
    
    return found


def _find_objc_selectors(
    program: "GhidraProgram",
    db: "SignatureDatabase",
    already_found_addresses: set
) -> List[FoundFunction]:
    """
    Find ObjC selectors dispatched via objc_msgSend by string-table search.

    ObjC methods like `evaluatePolicy:localizedReason:reply:` are not standalone
    functions — they're dispatched via objc_msgSend with the selector as a
    string argument. This function searches the binary's string table for
    selector strings matching our signatures, then finds xrefs to locate
    the actual call sites.

    Args:
        program: GhidraProgram wrapper
        db: SignatureDatabase to match against
        already_found_addresses: Set of addresses already found (to avoid dupes)

    Returns:
        List of FoundFunction objects for matching ObjC selectors
    """
    found = []

    # Only search for signatures that look like ObjC selectors (contain ':')
    objc_signatures = {
        sig.name: sig for sig in db.functions.values()
        if ':' in sig.name
    }

    if not objc_signatures:
        return found

    # Search the string table for selector strings
    for address, string_value in program.get_defined_strings():
        if not string_value or ':' not in string_value:
            continue

        # Check for exact match against our signatures
        if string_value in objc_signatures:
            signature = objc_signatures[string_value]

            # Find xrefs to this string — these are objc_msgSend call sites
            try:
                refs = program.get_references_to(address)
            except Exception:
                continue

            for ref in refs:
                if ref.from_address in already_found_addresses:
                    continue

                # Get the containing function for context
                try:
                    func = program.get_function_containing(ref.from_address)
                except Exception:
                    func = None

                found.append(FoundFunction(
                    name=signature.name,
                    address=ref.from_address,
                    signature=signature,
                    symbol_type="objc_selector",
                    ghidra_function=func,
                ))
                already_found_addresses.add(ref.from_address)

    return found


def find_functions(
    program: "GhidraProgram",
    db: "SignatureDatabase"
) -> List[FoundFunction]:
    """
    Find all security-relevant functions in a binary that match a signature database.
    
    This function searches for both imported functions and internal symbol references
    that match the signatures in the provided database.
    
    Args:
        program: GhidraProgram wrapper
        db: SignatureDatabase containing function signatures to match against
        
    Returns:
        List of FoundFunction objects, sorted by address
        
    Example:
        from trellis_ghidra.ghidra_api import get_program
        from trellis_ghidra.signatures import load_category
        
        program = get_program(currentProgram)
        crypto_db = load_category("crypto")
        found = find_functions(program, crypto_db)
        
        print("Found {} crypto functions".format(len(found)))
        for func in found:
            print("  {} @ {}".format(func.name, hex(func.address)))
    """
    # Find imported functions
    imports = _find_imported_functions(program, db)
    
    # Find internal functions
    internals = _find_internal_functions(program, db)
    
    # Track already-found addresses to avoid duplicates
    found_addresses = set(f.address for f in imports + internals)
    
    # Find ObjC selectors via string-table search
    objc_found = _find_objc_selectors(program, db, found_addresses)
    
    # Combine and sort by address
    all_found = imports + internals + objc_found
    all_found.sort(key=lambda f: f.address)
    
    return all_found


def find_all_categories(program: "GhidraProgram") -> Dict[str, List[FoundFunction]]:
    """
    Find all security-relevant functions across all signature categories.
    
    Args:
        program: GhidraProgram wrapper
        
    Returns:
        Dictionary mapping category names to lists of FoundFunction objects
        
    Example:
        results = find_all_categories(program)
        for category, functions in results.items():
            print("{}: {} functions".format(category, len(functions)))
    """
    from ..signatures import load_all
    
    all_databases = load_all()
    results = {}
    
    for category, db in all_databases.items():
        found = find_functions(program, db)
        if found:
            results[category] = found
    
    return results


__all__ = [
    "FoundFunction",
    "find_functions",
    "find_all_categories",
]
