"""
Call tree construction for Ghidra.

This module builds complete call trees showing all code paths leading to a target
function. This is particularly useful for understanding how security-relevant
functions are reached in an iOS binary.

Usage:
    from trellis_ghidra.ghidra_api import get_program
    from trellis_ghidra.analysis.calltree import build_call_tree, flatten_call_tree
    
    program = get_program(currentProgram)
    
    # Build the call tree for a target function
    tree = build_call_tree(program, target_address, max_depth=10)
    
    # Get all paths as a list
    paths = flatten_call_tree(tree)
    for path in paths:
        print(" -> ".join(path))
"""

from typing import Optional, List, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from ..ghidra_api import GhidraProgram


class CallSite(object):
    """
    Represents a specific location where a function is called.
    
    Attributes:
        caller_address: Address of the calling function's entry point
        caller_name: Name of the calling function
        call_instruction_address: Address of the actual call instruction
        callee_name: Name or address of what's being called
    """
    
    def __init__(self, caller_address, caller_name, call_instruction_address, callee_name):
        self.caller_address = caller_address
        self.caller_name = caller_name
        self.call_instruction_address = call_instruction_address
        self.callee_name = callee_name
    
    def __str__(self):
        return "{}@0x{:x} calls {} at 0x{:x}".format(
            self.caller_name, self.caller_address,
            self.callee_name, self.call_instruction_address
        )


class CallTreeNode(object):
    """
    Represents a node in the call tree.
    
    The tree is built "upward" from a target function toward entry points,
    showing all functions that call the target (directly or indirectly).
    
    Attributes:
        function_name: Name of this function
        function_address: Entry point address of this function
        callers: List of functions that call this one (recursive)
        call_sites: Specific locations where calls occur
        depth: Depth in the tree (0 = target, higher = farther from target)
    """
    
    def __init__(self, function_name, function_address, callers=None, call_sites=None, depth=0):
        self.function_name = function_name
        self.function_address = function_address
        self.callers = callers if callers is not None else []
        self.call_sites = call_sites if call_sites is not None else []
        self.depth = depth
    
    def __str__(self):
        indent = "  " * self.depth
        return "{}{}@0x{:x} (depth={}, callers={})".format(
            indent, self.function_name, self.function_address,
            self.depth, len(self.callers)
        )


def _collect_call_sites(
    program: "GhidraProgram",
    target_address: int
) -> List[CallSite]:
    """
    Collect all call sites that reference a target function.
    
    Args:
        program: GhidraProgram wrapper
        target_address: Address of the target function
        
    Returns:
        List of CallSite objects for each call to the target
    """
    call_sites = []
    
    # Get the target function info
    target_func = program.get_function_at(target_address)
    target_name = target_func.name if target_func else "sub_{:x}".format(target_address)
    
    # Get all call references to this address
    callers = program.get_callers(target_address)
    
    for ref in callers:
        # Get the calling function
        caller_func = program.get_function_containing(ref.from_address)
        
        if caller_func is None:
            continue
        
        call_site = CallSite(
            caller_address=caller_func.address,
            caller_name=caller_func.name,
            call_instruction_address=ref.from_address,
            callee_name=target_name,
        )
        call_sites.append(call_site)
    
    return call_sites


def build_call_tree(
    program: "GhidraProgram",
    target_address: int,
    max_depth: int = 10,
    _visited: Optional[Set[int]] = None,
    _current_depth: int = 0,
) -> Optional[CallTreeNode]:
    """
    Build a complete call tree starting from a target function.
    
    The tree is constructed "upward" - starting from the target function and
    recursively finding all functions that call it, up to entry points.
    
    Args:
        program: GhidraProgram wrapper
        target_address: Address of the target function
        max_depth: Maximum depth to traverse (prevents infinite recursion)
        _visited: Internal - tracks visited functions for cycle detection
        _current_depth: Internal - tracks current depth
        
    Returns:
        CallTreeNode representing the root, or None if target doesn't exist
        
    Example:
        tree = build_call_tree(program, cccrypt_address, max_depth=5)
        print("Found {:x} direct callers".format(len(tree.callers)))
    """
    # Initialize visited set on first call
    if _visited is None:
        _visited = set()
    
    # Check depth limit
    if _current_depth > max_depth:
        return None
    
    # Cycle detection
    if target_address in _visited:
        return None
    
    # Get the target function
    target_func = program.get_function_at(target_address)
    if target_func is None:
        # Try to get function containing this address
        target_func = program.get_function_containing(target_address)
        if target_func is None:
            return None
    
    # Mark as visited
    _visited.add(target_address)
    
    # Create the node for this function
    node = CallTreeNode(
        function_name=target_func.name,
        function_address=target_func.address,
        depth=_current_depth,
    )
    
    # Collect all call sites
    node.call_sites = _collect_call_sites(program, target_address)
    
    # Recursively build tree for each caller
    for call_site in node.call_sites:
        caller_node = build_call_tree(
            program,
            call_site.caller_address,
            max_depth=max_depth,
            _visited=_visited.copy(),  # Copy to allow different paths
            _current_depth=_current_depth + 1,
        )
        
        if caller_node is not None:
            node.callers.append(caller_node)
    
    return node


def flatten_call_tree(node: CallTreeNode) -> List[List[str]]:
    """
    Convert a call tree into a flat list of call paths.
    
    Each path is a list of function names, ordered from entry point to target.
    
    Args:
        node: Root node of the call tree
        
    Returns:
        List of paths, where each path is a list of function names
        
    Example:
        paths = flatten_call_tree(tree)
        for path in paths:
            print(" -> ".join(path))
    """
    paths = []
    
    def _traverse(current_node: CallTreeNode, current_path: List[str]) -> None:
        # Add current function to the path
        path_with_current = [current_node.function_name] + current_path
        
        if not current_node.callers:
            # Leaf node (entry point)
            paths.append(path_with_current)
        else:
            # Recursively process callers
            for caller in current_node.callers:
                _traverse(caller, path_with_current)
    
    _traverse(node, [])
    return paths


def print_call_tree(node: CallTreeNode, indent: int = 0) -> None:
    """
    Print a call tree in human-readable format.
    
    Args:
        node: Root node to print
        indent: Current indentation level
    """
    prefix = "  " * indent
    print("{}{}@0x{:x} (depth={})".format(prefix, node.function_name, node.function_address, node.depth))
    
    if node.call_sites:
        for call_site in node.call_sites:
            print("{}  called at 0x{:x}".format(prefix, call_site.call_instruction_address))
    
    for caller in node.callers:
        print_call_tree(caller, indent + 1)


def get_call_depth(node: CallTreeNode) -> int:
    """
    Get the maximum depth of the call tree.
    
    Args:
        node: Root node
        
    Returns:
        Maximum depth (levels from target to farthest entry point)
    """
    if not node.callers:
        return node.depth
    
    return max(get_call_depth(caller) for caller in node.callers)


def count_paths(node: CallTreeNode) -> int:
    """
    Count total unique paths in the call tree.
    
    Args:
        node: Root node
        
    Returns:
        Total number of unique paths from entry points to target
    """
    if not node.callers:
        return 1
    
    return sum(count_paths(caller) for caller in node.callers)


__all__ = [
    "CallSite",
    "CallTreeNode",
    "build_call_tree",
    "flatten_call_tree",
    "print_call_tree",
    "get_call_depth",
    "count_paths",
]
