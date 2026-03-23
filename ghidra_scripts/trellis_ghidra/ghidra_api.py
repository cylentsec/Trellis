"""
Ghidra API Abstraction Layer for Trellis

This module provides a compatibility layer that wraps Ghidra's Java APIs
in Python-friendly functions. It also provides stub implementations for
syntax checking when Ghidra is not available.

Key Ghidra API mappings:
    Program (currentProgram) - Main binary representation
    SymbolTable.getAllSymbols() - Get all symbols
    FunctionManager.getFunctionAt() - Get function at address
    ReferenceManager.getReferencesTo() - Get cross-references
    DecompInterface.decompileFunction() - Decompile to high-level representation

Usage in Ghidra scripts:
    from trellis_ghidra.ghidra_api import GhidraProgram
    
    program = GhidraProgram(currentProgram)
    for symbol in program.get_symbols():
        if symbol.is_external:
            print(symbol.name)
"""

from dataclasses import dataclass
from typing import Optional, List, Iterator, Any
from enum import Enum

# Try to import Ghidra APIs
try:
    from ghidra.program.model.listing import Program, Function
    from ghidra.program.model.symbol import Symbol, SymbolType, SymbolTable
    from ghidra.program.model.address import Address, AddressFactory
    from ghidra.program.model.mem import MemoryBlock
    from ghidra.program.model.pcode import PcodeOp, Varnode
    from ghidra.app.decompiler import DecompInterface, DecompileResults
    from ghidra.util.task import TaskMonitor
    from ghidra.program.flatapi import FlatProgramAPI
    GHIDRA_AVAILABLE = True
except ImportError:
    GHIDRA_AVAILABLE = False
    # Define stubs for type hints
    Program = Any
    Function = Any
    Symbol = Any
    Address = Any


class GhidraSymbolType(Enum):
    """Enumeration of Ghidra symbol types."""
    IMPORT = "import"           # External/imported function
    FUNCTION = "function"       # Internal function  
    LABEL = "label"            # Code label
    DATA = "data"              # Data symbol
    UNKNOWN = "unknown"        # Other


@dataclass
class GhidraSymbol:
    """
    Wrapper for Ghidra Symbol objects.
    
    Provides a Python-friendly interface for symbol access.
    """
    name: str
    address: int
    symbol_type: GhidraSymbolType
    is_external: bool
    _ghidra_symbol: Any = None
    
    @classmethod
    def from_ghidra(cls, symbol) -> "GhidraSymbol":
        """Create from a Ghidra Symbol object."""
        if not GHIDRA_AVAILABLE:
            raise RuntimeError("Ghidra not available")
        
        # Determine symbol type
        sym_type = symbol.getSymbolType()
        if symbol.isExternal():
            gs_type = GhidraSymbolType.IMPORT
        elif sym_type == SymbolType.FUNCTION:
            gs_type = GhidraSymbolType.FUNCTION
        elif sym_type == SymbolType.LABEL:
            gs_type = GhidraSymbolType.LABEL
        else:
            gs_type = GhidraSymbolType.UNKNOWN
            
        return cls(
            name=symbol.getName(),
            address=symbol.getAddress().getOffset(),
            symbol_type=gs_type,
            is_external=symbol.isExternal(),
            _ghidra_symbol=symbol
        )


@dataclass
class GhidraFunction:
    """
    Wrapper for Ghidra Function objects.
    
    Provides consistent interface for function analysis.
    """
    name: str
    address: int  # Entry point address
    _ghidra_function: Any = None
    
    @property
    def start(self) -> int:
        """Entry point address (alias for address)."""
        return self.address
    
    @classmethod
    def from_ghidra(cls, func) -> "GhidraFunction":
        """Create from a Ghidra Function object."""
        if not GHIDRA_AVAILABLE:
            raise RuntimeError("Ghidra not available")
            
        return cls(
            name=func.getName(),
            address=func.getEntryPoint().getOffset(),
            _ghidra_function=func
        )


@dataclass
class GhidraReference:
    """
    Wrapper for Ghidra Reference objects.
    
    Represents a cross-reference (xref) in the binary.
    """
    from_address: int      # Where the reference originates
    to_address: int        # What is being referenced
    is_call: bool          # Is this a function call?
    _ghidra_ref: Any = None


@dataclass  
class GhidraMemoryBlock:
    """
    Wrapper for Ghidra MemoryBlock objects.
    
    Represents a memory segment/section.
    """
    name: str
    start: int
    end: int
    is_executable: bool
    is_writable: bool
    is_readable: bool


class GhidraProgram:
    """
    Main interface to a Ghidra Program.
    
    This class wraps a Ghidra Program object and provides Python-friendly
    methods for binary analysis.
    
    Usage:
        # In a Ghidra script
        from trellis_ghidra.ghidra_api import GhidraProgram
        
        program = GhidraProgram(currentProgram)
        
        # Find imported functions
        for sym in program.get_external_symbols():
            print(f"Import: {sym.name} @ {hex(sym.address)}")
        
        # Get callers of a function
        callers = program.get_callers(0x100001234)
        
        # Get function at address
        func = program.get_function_at(0x100001234)
    """
    
    def __init__(self, program, monitor=None):
        """
        Initialize with a Ghidra Program object.
        
        Args:
            program: Ghidra Program (currentProgram in scripts)
            monitor: Optional TaskMonitor for progress updates
        """
        if not GHIDRA_AVAILABLE:
            raise RuntimeError("Ghidra not available - this must run inside Ghidra")
            
        self._program = program
        self._monitor = monitor or TaskMonitor.DUMMY
        self._flat_api = FlatProgramAPI(program)
        self._decompiler = None  # Lazy initialization
        
    @property
    def filename(self) -> str:
        """Get the binary filename."""
        return self._program.getName()
    
    @property
    def image_base(self) -> int:
        """Get the image base address."""
        return self._program.getImageBase().getOffset()
    
    def get_address(self, offset: int):
        """Convert an integer offset to a Ghidra Address object."""
        return self._program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
    
    # =========================================================================
    # Symbol Operations
    # =========================================================================
    
    def get_all_symbols(self) -> Iterator[GhidraSymbol]:
        """
        Iterate all symbols in the binary.
        """
        symbol_table = self._program.getSymbolTable()
        symbol_iter = symbol_table.getAllSymbols(True)
        
        while symbol_iter.hasNext():
            sym = symbol_iter.next()
            yield GhidraSymbol.from_ghidra(sym)
    
    def get_external_symbols(self) -> Iterator[GhidraSymbol]:
        """
        Get only external/imported symbols.
        """
        for sym in self.get_all_symbols():
            if sym.is_external:
                yield sym
    
    def get_function_symbols(self) -> Iterator[GhidraSymbol]:
        """Get all function symbols (both internal and external)."""
        func_manager = self._program.getFunctionManager()
        
        # External functions — iterate the symbol table filtered to externals,
        # since ExternalManager.getExternalLocations() has no zero-arg overload.
        for sym in self.get_external_symbols():
            yield sym
        
        # Internal functions
        func_iter = func_manager.getFunctions(True)
        while func_iter.hasNext():
            func = func_iter.next()
            yield GhidraSymbol(
                name=func.getName(),
                address=func.getEntryPoint().getOffset(),
                symbol_type=GhidraSymbolType.FUNCTION,
                is_external=False
            )
    
    def get_symbol_by_name(self, name: str) -> Optional[GhidraSymbol]:
        """Find a symbol by name."""
        symbol_table = self._program.getSymbolTable()
        symbols = symbol_table.getSymbols(name)
        
        for sym in symbols:
            return GhidraSymbol.from_ghidra(sym)
        return None
    
    # =========================================================================
    # Function Operations
    # =========================================================================
    
    def get_function_at(self, address: int) -> Optional[GhidraFunction]:
        """
        Get the function at an exact address.
        """
        func_manager = self._program.getFunctionManager()
        addr = self.get_address(address)
        func = func_manager.getFunctionAt(addr)
        
        if func:
            return GhidraFunction.from_ghidra(func)
        return None
    
    def get_function_containing(self, address: int) -> Optional[GhidraFunction]:
        """
        Get the function containing an address.
        """
        func_manager = self._program.getFunctionManager()
        addr = self.get_address(address)
        func = func_manager.getFunctionContaining(addr)
        
        if func:
            return GhidraFunction.from_ghidra(func)
        return None
    
    def get_all_functions(self) -> Iterator[GhidraFunction]:
        """
        Iterate all functions in the binary.
        """
        func_manager = self._program.getFunctionManager()
        func_iter = func_manager.getFunctions(True)
        
        while func_iter.hasNext():
            func = func_iter.next()
            yield GhidraFunction.from_ghidra(func)
    
    def get_function_count(self) -> int:
        """Get total number of functions."""
        return self._program.getFunctionManager().getFunctionCount()
    
    # =========================================================================
    # Reference/Cross-reference Operations
    # =========================================================================
    
    def get_references_to(self, address: int) -> List[GhidraReference]:
        """
        Get all references TO an address.
        """
        ref_manager = self._program.getReferenceManager()
        addr = self.get_address(address)
        refs = []
        
        ref_iter = ref_manager.getReferencesTo(addr)
        while ref_iter.hasNext():
            ref = ref_iter.next()
            from_addr = ref.getFromAddress()
            
            # Check if this is a call reference
            is_call = ref.getReferenceType().isCall()
            
            refs.append(GhidraReference(
                from_address=from_addr.getOffset(),
                to_address=address,
                is_call=is_call,
                _ghidra_ref=ref
            ))
        
        return refs
    
    def get_callers(self, address: int) -> List[GhidraReference]:
        """
        Get all CALL references to an address.
        """
        all_refs = self.get_references_to(address)
        return [ref for ref in all_refs if ref.is_call]
    
    # =========================================================================
    # Memory/Segment Operations
    # =========================================================================
    
    def get_memory_blocks(self) -> List[GhidraMemoryBlock]:
        """
        Get all memory blocks/segments.
        """
        memory = self._program.getMemory()
        blocks = []
        
        for block in memory.getBlocks():
            blocks.append(GhidraMemoryBlock(
                name=block.getName(),
                start=block.getStart().getOffset(),
                end=block.getEnd().getOffset(),
                is_executable=block.isExecute(),
                is_writable=block.isWrite(),
                is_readable=block.isRead()
            ))
        
        return blocks
    
    def is_address_in_data_section(self, address: int) -> bool:
        """Check if address is in a non-executable (data) section."""
        for block in self.get_memory_blocks():
            if block.start <= address <= block.end:
                return not block.is_executable
        return False
    
    # =========================================================================
    # Decompiler Operations
    # =========================================================================
    
    def _init_decompiler(self):
        """Initialize the decompiler (lazy)."""
        if self._decompiler is None:
            self._decompiler = DecompInterface()
            self._decompiler.openProgram(self._program)
    
    def decompile_function(self, func: GhidraFunction, timeout: int = 60) -> Optional[Any]:
        """
        Decompile a function and return the HighFunction.
        
        Args:
            func: GhidraFunction to decompile
            timeout: Decompilation timeout in seconds
            
        Returns:
            Ghidra HighFunction object or None if decompilation fails
        """
        self._init_decompiler()
        
        ghidra_func = func._ghidra_function
        if ghidra_func is None:
            # Need to look up the function
            ghidra_func = self._program.getFunctionManager().getFunctionAt(
                self.get_address(func.address)
            )
            if ghidra_func is None:
                return None
        
        results = self._decompiler.decompileFunction(ghidra_func, timeout, self._monitor)
        
        if results and results.decompileCompleted():
            return results.getHighFunction()
        return None
    
    def get_decompiled_code(self, func: GhidraFunction, timeout: int = 60) -> Optional[str]:
        """
        Get the decompiled C code for a function.
        
        Args:
            func: GhidraFunction to decompile
            timeout: Decompilation timeout in seconds
            
        Returns:
            Decompiled C code as string, or None if failed
        """
        self._init_decompiler()
        
        ghidra_func = func._ghidra_function
        if ghidra_func is None:
            ghidra_func = self._program.getFunctionManager().getFunctionAt(
                self.get_address(func.address)
            )
            if ghidra_func is None:
                return None
        
        results = self._decompiler.decompileFunction(ghidra_func, timeout, self._monitor)
        
        if results and results.decompileCompleted():
            return results.getDecompiledFunction().getC()
        return None
    
    # =========================================================================
    # String Operations
    # =========================================================================
    
    def get_defined_strings(self) -> Iterator[tuple]:
        """
        Get all defined strings in the binary.
        
        Yields:
            Tuples of (address, string_value)
        """
        data_iter = self._program.getListing().getDefinedData(True)
        
        while data_iter.hasNext():
            data = data_iter.next()
            if data.hasStringValue():
                try:
                    value = data.getValue()
                    if value:
                        yield (data.getAddress().getOffset(), str(value))
                except:
                    pass
    
    def read_string_at(self, address: int, max_len: int = 1024) -> Optional[str]:
        """Read a null-terminated string at an address."""
        try:
            addr = self.get_address(address)
            data = self._program.getListing().getDataAt(addr)
            if data and data.hasStringValue():
                return str(data.getValue())
        except:
            pass
        return None

    # =========================================================================
    # Instruction Operations
    # =========================================================================

    def get_instruction_at(self, address: int):
        """
        Get the instruction at an exact address.

        Returns:
            Ghidra Instruction object or None
        """
        try:
            addr = self.get_address(address)
            return self._program.getListing().getInstructionAt(addr)
        except Exception:
            return None

    def get_instruction_before(self, address: int):
        """
        Get the instruction immediately before an address.

        Returns:
            Ghidra Instruction object or None
        """
        try:
            addr = self.get_address(address)
            return self._program.getListing().getInstructionBefore(addr)
        except Exception:
            return None

    def get_instructions_before(self, address: int, count: int) -> list:
        """
        Get N instructions before an address, ordered newest-first.

        Args:
            address: Start address (exclusive)
            count: Number of instructions to retrieve

        Returns:
            List of Ghidra Instruction objects (most recent first)
        """
        instructions = []
        try:
            addr = self.get_address(address)
            insn = self._program.getListing().getInstructionBefore(addr)
            while insn and len(instructions) < count:
                instructions.append(insn)
                insn = insn.getPrevious()
        except Exception:
            pass
        return instructions


# Convenience function for scripts
def get_program(current_program, monitor=None) -> GhidraProgram:
    """
    Create a GhidraProgram wrapper from currentProgram.
    
    Usage in Ghidra script:
        from trellis_ghidra.ghidra_api import get_program
        program = get_program(currentProgram)
    """
    return GhidraProgram(current_program, monitor)


__all__ = [
    "GHIDRA_AVAILABLE",
    "GhidraSymbolType",
    "GhidraSymbol", 
    "GhidraFunction",
    "GhidraReference",
    "GhidraMemoryBlock",
    "GhidraProgram",
    "get_program",
]
