"""
Signature database loader for Trellis (Ghidra Port).

This module loads and parses YAML signature files that define security-relevant
iOS functions. The signature files are platform-independent and define function
names, parameters, and security notes.

Usage:
    from trellis_ghidra.signatures import load_category, load_all, get_function
    
    # Load a specific category
    crypto_db = load_category("crypto")
    
    # Load all categories
    all_dbs = load_all()
    
    # Get a specific function signature
    func = get_function("crypto", "CCCrypt")
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict

# Try to import yaml
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError as e:
    YAML_AVAILABLE = False
    import sys
    print("[Trellis] PyYAML import failed: {}".format(e))
    print("[Trellis] Python path: {}".format(sys.path))
    print("[Trellis] Python executable: {}".format(sys.executable))


@dataclass
class Parameter:
    """
    Represents a function parameter in a signature.
    
    Attributes:
        name: Parameter name
        type: C type (e.g., "void*", "size_t", "CCOperation")
        description: Human-readable description
        size_param: Optional name of parameter that specifies buffer size
    """
    name: str
    type: str
    description: str = ""
    size_param: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: dict) -> "Parameter":
        """Create a Parameter from a dictionary."""
        return cls(
            name=data["name"],
            type=data["type"],
            description=data.get("description", ""),
            size_param=data.get("size_param"),
        )


@dataclass
class ReturnType:
    """
    Represents a function return type.
    
    Attributes:
        type: C type of the return value
        description: Human-readable description
    """
    type: str
    description: str = ""
    
    @classmethod
    def from_dict(cls, data: dict) -> "ReturnType":
        """Create a ReturnType from a dictionary."""
        return cls(
            type=data["type"],
            description=data.get("description", ""),
        )


@dataclass
class FunctionSignature:
    """
    Represents a complete function signature.
    
    Attributes:
        name: Function name as it appears in the binary
        library: Library/dylib that exports this function
        parameters: List of function parameters
        return_type: Return type information
        security_notes: List of security considerations
    """
    name: str
    library: str
    parameters: List[Parameter] = field(default_factory=list)
    return_type: Optional[ReturnType] = None
    security_notes: List[str] = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data: dict) -> "FunctionSignature":
        """Create a FunctionSignature from a dictionary."""
        parameters = [
            Parameter.from_dict(p) for p in data.get("parameters", [])
        ]
        
        return_data = data.get("return")
        return_type = ReturnType.from_dict(return_data) if return_data else None
        
        return cls(
            name=data["name"],
            library=data["library"],
            parameters=parameters,
            return_type=return_type,
            security_notes=data.get("security_notes", []),
        )


@dataclass
class SignatureDatabase:
    """
    Represents a complete signature database for a category.
    
    Attributes:
        category: Category name (e.g., "crypto", "networking")
        description: Human-readable description
        functions: Dictionary mapping function names to signatures
        source_file: Path to the YAML file
    """
    category: str
    description: str
    functions: Dict[str, FunctionSignature] = field(default_factory=dict)
    source_file: Optional[Path] = None
    
    def get_function(self, name: str) -> Optional[FunctionSignature]:
        """Get a function signature by name."""
        return self.functions.get(name)
    
    def list_functions(self) -> List[str]:
        """Get sorted list of function names."""
        return sorted(self.functions.keys())
    
    @classmethod
    def from_dict(cls, data: dict, source_file: Optional[Path] = None) -> "SignatureDatabase":
        """Create a SignatureDatabase from a dictionary."""
        functions = {}
        for func_data in data.get("functions", []):
            func_sig = FunctionSignature.from_dict(func_data)
            functions[func_sig.name] = func_sig
        
        return cls(
            category=data["category"],
            description=data.get("description", ""),
            functions=functions,
            source_file=source_file,
        )


def _get_signatures_dir() -> Path:
    """
    Get the path to the signatures directory.
    
    The YAML signature files are located in the same directory as this module.
    """
    return Path(__file__).parent


def _load_yaml_file(file_path: Path) -> Optional[dict]:
    """
    Load and parse a YAML file.
    
    Args:
        file_path: Path to the YAML file
        
    Returns:
        Parsed YAML data as dictionary, or None if file doesn't exist
    """
    if not YAML_AVAILABLE:
        raise ImportError(
            "PyYAML is required for signature loading. "
            "Install with: pip install pyyaml"
        )
    
    if not file_path.exists():
        return None
    
    with open(file_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_category(name: str) -> Optional[SignatureDatabase]:
    """
    Load a single signature category from a YAML file.
    
    Args:
        name: Category name (e.g., "crypto", "networking")
        
    Returns:
        SignatureDatabase if found, None otherwise
        
    Example:
        >>> crypto_db = load_category("crypto")
        >>> if crypto_db:
        ...     print(f"Loaded {len(crypto_db.functions)} functions")
    """
    signatures_dir = _get_signatures_dir()
    
    # Try both .yaml and .yml extensions
    for ext in [".yaml", ".yml"]:
        file_path = signatures_dir / f"{name}{ext}"
        data = _load_yaml_file(file_path)
        
        if data is not None:
            return SignatureDatabase.from_dict(data, source_file=file_path)
    
    return None


def load_all() -> Dict[str, SignatureDatabase]:
    """
    Load all signature categories.
    
    Returns:
        Dictionary mapping category names to SignatureDatabase objects
        
    Example:
        >>> all_dbs = load_all()
        >>> for category, db in all_dbs.items():
        ...     print(f"{category}: {len(db.functions)} functions")
    """
    signatures_dir = _get_signatures_dir()
    databases = {}
    
    if not signatures_dir.exists():
        print(f"[Trellis] Warning: Signatures directory not found: {signatures_dir}")
        return databases
    
    # Find all YAML files
    yaml_files = list(signatures_dir.glob("*.yaml")) + list(signatures_dir.glob("*.yml"))
    
    for file_path in yaml_files:
        try:
            data = _load_yaml_file(file_path)
            if data is None:
                continue
            
            db = SignatureDatabase.from_dict(data, source_file=file_path)
            databases[db.category] = db
            
        except Exception as e:
            print(f"[Trellis] Warning: Failed to load {file_path}: {e}")
            continue
    
    return databases


def get_function(category: str, name: str) -> Optional[FunctionSignature]:
    """
    Get a specific function signature from a category.
    
    Args:
        category: Category name (e.g., "crypto")
        name: Function name (e.g., "CCCrypt")
        
    Returns:
        FunctionSignature if found, None otherwise
        
    Example:
        >>> func = get_function("crypto", "CCCrypt")
        >>> if func:
        ...     print(f"{func.name} has {len(func.parameters)} parameters")
    """
    db = load_category(category)
    if db is None:
        return None
    
    return db.get_function(name)


def get_available_categories() -> List[str]:
    """
    Get list of available signature categories.
    
    Returns:
        Sorted list of category names
    """
    signatures_dir = _get_signatures_dir()
    categories = []
    
    if not signatures_dir.exists():
        return categories
    
    yaml_files = list(signatures_dir.glob("*.yaml")) + list(signatures_dir.glob("*.yml"))
    
    for file_path in yaml_files:
        # Extract category name from filename
        cat_name = file_path.stem
        categories.append(cat_name)
    
    return sorted(categories)


__all__ = [
    "Parameter",
    "ReturnType",
    "FunctionSignature",
    "SignatureDatabase",
    "load_category",
    "load_all",
    "get_function",
    "get_available_categories",
]
