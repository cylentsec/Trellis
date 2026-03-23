"""
Parameter extraction for Ghidra call sites.

This module extracts detailed information about function calls, including
parameter values, types, and return value usage. It uses Ghidra's Decompiler
API to provide meaningful variable names and expressions through the
HighFunction and Pcode APIs.

Usage:
    from trellis_ghidra.ghidra_api import get_program
    from trellis_ghidra.analysis.extractor import extract_call_info
    from trellis_ghidra.analysis.calltree import build_call_tree
    
    program = get_program(currentProgram)
    tree = build_call_tree(program, target_address)
    
    for call_site in tree.call_sites:
        info = extract_call_info(program, call_site, signature)
        print("Call at 0x{:x}"".format(info.call_address))
        for param in info.parameters:
            print("  {:x}: {}".format(param.name, param.value_str))
"""

from typing import Optional, List, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..ghidra_api import GhidraProgram
    from ..signatures import FunctionSignature
    from .calltree import CallSite


class ExtractedParam(object):
    """
    Represents extracted information about a function parameter.
    
    Attributes:
        index: Zero-based parameter index
        name: Parameter name from signature
        expected_type: C type from signature
        value_str: String representation of the argument
        value_if_constant: Actual value if constant
        variable_name: Variable name if a variable reference
        value_as_string: String value if the parameter is a string
    """
    
    def __init__(self, index, name, expected_type, value_str=None, 
                 value_if_constant=None, variable_name=None, value_as_string=None):
        self.index = index
        self.name = name
        self.expected_type = expected_type
        self.value_str = value_str
        self.value_if_constant = value_if_constant
        self.variable_name = variable_name
        self.value_as_string = value_as_string
    
    def __str__(self):
        parts = ["{:x}: {}".format(self.name, self.expected_type)]
        
        if self.value_if_constant is not None:
            parts.append("= {:x}".format(self.value_if_constant))
        elif self.variable_name:
            parts.append("= {:x}".format(self.variable_name))
        elif self.value_str:
            parts.append("= {:x}".format(self.value_str))
        
        return " ".join(parts)


class ExtractedCallInfo(object):
    """
    Represents complete extracted information about a function call.
    
    Attributes:
        call_address: Address of the call instruction
        caller_function: Name of the calling function
        target_function: Name of the called function
        parameters: List of extracted parameter information
        return_usage: Description of how return value is used
        decompiler_available: Whether decompiler was available
    """
    
    def __init__(self, call_address, caller_function, target_function,
                 parameters=None, return_usage=None, decompiler_available=False):
        self.call_address = call_address
        self.caller_function = caller_function
        self.target_function = target_function
        self.parameters = parameters if parameters is not None else []
        self.return_usage = return_usage
        self.decompiler_available = decompiler_available
    
    def __str__(self):
        decompiler_status = 'Available' if self.decompiler_available else 'Not available'
        lines = [
            "Call to {:x} at 0x{:x}".format(self.target_function, self.call_address),
            "  Caller: {:x}".format(self.caller_function),
            "  Decompiler: {:x}".format(decompiler_status),
        ]
        
        if self.parameters:
            lines.append("  Parameters:")
            for param in self.parameters:
                lines.append("    {:x}".format(param))
        
        if self.return_usage:
            lines.append("  Return: {:x}".format(self.return_usage))
        
        return "\n".join(lines)


# ARM64 calling convention: x0-x7 for first 8 arguments
_ARM64_ARG_REGISTERS = {
    "x0": 0, "x1": 1, "x2": 2, "x3": 3,
    "x4": 4, "x5": 5, "x6": 6, "x7": 7,
    # 32-bit variants (lower half of x registers)
    "w0": 0, "w1": 1, "w2": 2, "w3": 3,
    "w4": 4, "w5": 5, "w6": 6, "w7": 7,
}

# Maximum number of instructions to scan backward from call site
_BACKWARD_SLICE_DEPTH = 20

# Branch mnemonics that mark basic-block boundaries — scanning past these
# would attribute values from a different execution path to the call site.
_BRANCH_MNEMONICS = frozenset({
    "b", "b.eq", "b.ne", "b.lt", "b.gt", "b.le", "b.ge",
    "b.hi", "b.lo", "b.hs", "b.ls", "b.cs", "b.cc",
    "cbz", "cbnz", "tbz", "tbnz", "ret",
})


def _backward_slice_arm64(program, call_address, num_params):
    """
    ARM64 backward slice: extract parameter values by scanning instructions
    before the call site.

    When the decompiler can't resolve parameter values (common with Swift-to-C
    bridged calls), this scans backward from the call instruction looking for
    MOV/MOVZ/MOVK/ADRP+ADD patterns that load values into argument registers.

    Args:
        program: GhidraProgram wrapper
        call_address: Address of the call instruction
        num_params: Number of parameters to extract

    Returns:
        Dict mapping parameter index to (value, value_type) tuples.
        value_type is 'int' for immediates or 'string_addr' for addresses.
    """
    results = {}  # param_index -> (value, value_type)

    # Track register state: reg_name -> (value, pending_shifts)
    # We process instructions newest-first, so we see the final write first
    resolved_regs = set()  # Registers we've already resolved
    reg_values = {}  # reg_name -> int value
    adrp_pending = {}  # canonical x-reg -> page_base or ADD offset (waiting for pair)
    movk_pending = {}  # canonical x-reg -> list of (imm, shift) from MOVK insns

    instructions = program.get_instructions_before(call_address, _BACKWARD_SLICE_DEPTH)

    for insn in instructions:
        try:
            mnemonic = insn.getMnemonicString().lower()
            num_ops = insn.getNumOperands()
        except Exception:
            continue

        # Stop at basic-block boundaries — a branch means the preceding
        # instructions belong to a different execution path
        if mnemonic in _BRANCH_MNEMONICS:
            break

        # Skip non-relevant instructions
        if num_ops < 2:
            continue

        # Get destination register name
        try:
            dest_reg = insn.getRegister(0)
            if dest_reg is None:
                continue
            dest_name = dest_reg.getName().lower()
        except Exception:
            continue

        # Canonical x-form for cross-width lookups (w1 <-> x1)
        canon_name = "x" + dest_name[1:]

        # Only care about argument registers
        if dest_name not in _ARM64_ARG_REGISTERS:
            continue

        param_idx = _ARM64_ARG_REGISTERS[dest_name]

        # Skip if we only need num_params parameters
        if param_idx >= num_params:
            continue

        # Skip if already resolved (we scan backwards, first write wins)
        if dest_name in resolved_regs:
            continue

        # Also skip if we resolved the x-variant of a w-register or vice versa
        if canon_name in resolved_regs or ("w" + dest_name[1:]) in resolved_regs:
            continue

        # Pattern: MOV Xn, #imm / MOVZ Xn, #imm
        if mnemonic in ("mov", "movz", "orr"):
            try:
                # Try to get scalar value from second operand
                scalars = insn.getOpObjects(1)
                if scalars:
                    for obj in scalars:
                        val = _try_get_scalar_value(obj)
                        if val is not None:
                            # Combine with any pending MOVK instructions
                            if mnemonic == "movz" and canon_name in movk_pending:
                                for movk_imm, movk_shift in movk_pending[canon_name]:
                                    val = val | (movk_imm << movk_shift)
                                del movk_pending[canon_name]
                            reg_values[dest_name] = val
                            resolved_regs.add(dest_name)
                            results[param_idx] = (val, 'int')
                            break
            except Exception:
                pass

        # Pattern: MOVK Xn, #imm, LSL #shift
        # Scanning backward, we see MOVK before its paired MOVZ.
        # Store the (imm, shift) and combine when MOVZ is found.
        elif mnemonic == "movk":
            try:
                scalars = insn.getOpObjects(1)
                if scalars:
                    for obj in scalars:
                        imm = _try_get_scalar_value(obj)
                        if imm is not None:
                            shift = 0
                            if num_ops >= 3:
                                shift_ops = insn.getOpObjects(2)
                                if shift_ops:
                                    for sobj in shift_ops:
                                        sval = _try_get_scalar_value(sobj)
                                        if sval is not None:
                                            shift = sval
                                            break
                            if canon_name not in movk_pending:
                                movk_pending[canon_name] = []
                            movk_pending[canon_name].append((imm, shift))
                            break
            except Exception:
                pass

        # Pattern: ADRP Xn, #page_addr
        elif mnemonic == "adrp":
            try:
                scalars = insn.getOpObjects(1)
                if scalars:
                    for obj in scalars:
                        val = _try_get_scalar_value(obj)
                        if val is not None:
                            # Check if we already have an ADD for this reg
                            if canon_name in adrp_pending:
                                # This is the ADRP part of ADRP+ADD
                                full_addr = val + adrp_pending[canon_name]
                                reg_values[dest_name] = full_addr
                                resolved_regs.add(dest_name)
                                # Try to read string at this address
                                results[param_idx] = (full_addr, 'string_addr')
                                del adrp_pending[canon_name]
                            else:
                                # Just store the page base
                                adrp_pending[canon_name] = val
                            break
            except Exception:
                pass

        # Pattern: ADD Xn, Xn, #offset (completes ADRP+ADD)
        elif mnemonic == "add":
            try:
                # Check source register matches destination (ADD Xn, Xn, #imm)
                src_reg = insn.getRegister(1)
                if src_reg and src_reg.getName().lower() in (dest_name, canon_name):
                    scalars = insn.getOpObjects(2)
                    if scalars:
                        for obj in scalars:
                            val = _try_get_scalar_value(obj)
                            if val is not None:
                                if canon_name in adrp_pending:
                                    # We have both ADRP base and ADD offset
                                    # But wait — we're scanning backward,
                                    # so we see ADD before ADRP
                                    # Store the ADD offset, wait for ADRP
                                    pass
                                # Store offset for when we find the ADRP
                                adrp_pending[canon_name] = val
                                break
            except Exception:
                pass

        # If destination register is written by any other instruction,
        # mark it as resolved (clobbered) so we don't look further back
        elif dest_name not in resolved_regs:
            if mnemonic in ("ldr", "ldp", "ldur", "ldar", "str", "stp",
                            "bl", "blr", "svc"):
                # Register was loaded from memory or clobbered by call
                resolved_regs.add(dest_name)

    return results


def _try_get_scalar_value(obj):
    """Try to extract a scalar integer value from a Ghidra operand object."""
    try:
        # Ghidra Scalar objects have getValue()
        if hasattr(obj, 'getValue'):
            return int(obj.getValue())
        # Address objects have getOffset()
        if hasattr(obj, 'getOffset'):
            return int(obj.getOffset())
        # Try direct conversion
        return int(obj)
    except Exception:
        return None


def _extract_pcode_constant(varnode) -> Optional[int]:
    """
    Extract a constant value from a Pcode Varnode if it's a constant.
    
    Args:
        varnode: Ghidra Varnode object
        
    Returns:
        Integer constant value or None
    """
    try:
        if varnode.isConstant():
            return varnode.getOffset()
    except:
        pass
    return None


def _find_call_pcode(program: "GhidraProgram", call_address: int):
    """
    Find the Pcode CALL operation at or near a call address.
    
    Args:
        program: GhidraProgram wrapper
        call_address: Address of the call instruction
        
    Returns:
        Tuple of (HighFunction, PcodeOp) or (None, None)
    """
    # Get the function containing this call
    caller_func = program.get_function_containing(call_address)
    if caller_func is None:
        return None, None
    
    # Decompile the function
    high_func = program.decompile_function(caller_func)
    if high_func is None:
        return None, None
    
    # Search for CALL pcode at or near the address
    try:
        pcode_ops = high_func.getPcodeOps()
        
        # First pass: exact address match
        for op in pcode_ops:
            if op.getOpcode() == 4:  # PcodeOp.CALL = 4
                seq_addr = op.getSeqnum().getTarget()
                if seq_addr and seq_addr.getOffset() == call_address:
                    return high_func, op
        
        # Second pass: closest CALL within range
        pcode_ops = high_func.getPcodeOps()  # Reset iterator
        closest_op = None
        closest_dist = float('inf')
        
        for op in pcode_ops:
            if op.getOpcode() == 4:  # CALL
                seq_addr = op.getSeqnum().getTarget()
                if seq_addr:
                    dist = abs(seq_addr.getOffset() - call_address)
                    if dist < closest_dist and dist < 32:  # Within 32 bytes
                        closest_dist = dist
                        closest_op = op
        
        if closest_op:
            return high_func, closest_op
            
    except Exception as e:
        print("[Trellis] Error finding call pcode: {}".format(e))
    
    return high_func, None


def extract_call_info(
    program: "GhidraProgram",
    call_site: "CallSite",
    signature: "FunctionSignature"
) -> ExtractedCallInfo:
    """
    Extract detailed information about a function call site.
    
    Uses Ghidra's decompiler to extract parameter values and types.
    
    Args:
        program: GhidraProgram wrapper
        call_site: CallSite object representing the call
        signature: Function signature with parameter info
        
    Returns:
        ExtractedCallInfo with all available information
    """
    info = ExtractedCallInfo(
        call_address=call_site.call_instruction_address,
        caller_function=call_site.caller_name,
        target_function=call_site.callee_name,
    )
    
    # Try to get decompiler info
    high_func, call_pcode = _find_call_pcode(program, call_site.call_instruction_address)
    
    if high_func is not None:
        info.decompiler_available = True
    
    # Create parameter entries from signature
    for i, param in enumerate(signature.parameters):
        extracted = ExtractedParam(
            index=i,
            name=param.name,
            expected_type=param.type,
        )
        
        # If we have the call Pcode, try to extract parameter values
        if call_pcode is not None:
            try:
                inputs = call_pcode.getInputs()
                # Input 0 is typically the call target, params start at 1
                if i + 1 < len(inputs):
                    varnode = inputs[i + 1]
                    
                    # Try to get constant value
                    const_val = _extract_pcode_constant(varnode)
                    if const_val is not None:
                        extracted.value_if_constant = const_val
                        extracted.value_str = "0x{:x}".format(const_val) if const_val > 15 else str(const_val)
                    else:
                        # Try to get variable name
                        high_var = varnode.getHigh()
                        if high_var:
                            extracted.variable_name = high_var.getName()
                            extracted.value_str = high_var.getName()
                        else:
                            extracted.value_str = str(varnode)
            except Exception as e:
                extracted.value_str = "<error: {}>".format(e)
        
        info.parameters.append(extracted)
    
    # Fallback: ARM64 backward slice for unresolved parameters
    # When the decompiler couldn't resolve parameter values (common with
    # Swift-to-C bridged calls), scan raw ARM64 instructions for patterns
    # that load immediate values or addresses into argument registers.
    unresolved_count = sum(
        1 for p in info.parameters if p.value_if_constant is None and not p.variable_name
    )
    if unresolved_count > 0:
        try:
            slice_results = _backward_slice_arm64(
                program, call_site.call_instruction_address, len(signature.parameters)
            )
            for param_idx, (value, value_type) in slice_results.items():
                if param_idx < len(info.parameters):
                    param = info.parameters[param_idx]
                    # Only fill in if decompiler didn't resolve this one
                    if param.value_if_constant is None and not param.variable_name:
                        if value_type == 'int':
                            param.value_if_constant = value
                            param.value_str = "0x{:x}".format(value) if value > 15 else str(value)
                        elif value_type == 'string_addr':
                            # Try to read string at the address
                            string_val = program.read_string_at(value)
                            if string_val:
                                param.value_as_string = string_val
                                param.value_str = '"{}"'.format(string_val[:80])
                            else:
                                param.value_if_constant = value
                                param.value_str = "0x{:x} (addr)".format(value)
        except Exception as e:
            # Backward slice is best-effort; don't fail the extraction
            pass
    
    return info


def format_extracted_info(info: ExtractedCallInfo, include_addresses: bool = True) -> str:
    """
    Format extracted call information as a human-readable string.
    
    Args:
        info: ExtractedCallInfo to format
        include_addresses: Whether to include hex addresses
        
    Returns:
        Formatted string representation
    """
    lines = []
    
    if include_addresses:
        lines.append("Call to {} at 0x{:x}".format(info.target_function, info.call_address))
        lines.append("  From: {}".format(info.caller_function))
    else:
        lines.append("Call to {}".format(info.target_function))
        lines.append("  From: {}".format(info.caller_function))
    
    if info.decompiler_available:
        lines.append("  Decompiler: Available")
    else:
        lines.append("  Decompiler: Not available (limited information)")
    
    if info.parameters:
        lines.append("  Parameters:")
        for param in info.parameters:
            param_line = "    [{}] {} ({})".format(param.index, param.name, param.expected_type)
            
            if param.value_if_constant is not None:
                param_line += " = {}".format(param.value_if_constant)
            elif param.variable_name:
                param_line += " = {}".format(param.variable_name)
            elif param.value_str:
                param_line += " = {}".format(param.value_str)
            else:
                param_line += " = <unknown>"
            
            lines.append(param_line)
    
    if info.return_usage:
        lines.append("  Return: {}".format(info.return_usage))
    
    return "\n".join(lines)


__all__ = [
    "ExtractedParam",
    "ExtractedCallInfo",
    "extract_call_info",
    "format_extracted_info",
]
