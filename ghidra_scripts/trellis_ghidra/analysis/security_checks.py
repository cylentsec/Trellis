"""
Security checking framework for Trellis (Ghidra Port).

This module provides the base infrastructure for automated security analysis,
including finding definitions, severity levels, and base checker classes.
"""

from enum import Enum
from typing import Optional, Any, Dict, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ..ghidra_api import GhidraProgram
    from .calltree import CallSite
    from ..signatures import FunctionSignature
    from .extractor import ExtractedCallInfo


class Severity(Enum):
    """Security finding severity levels."""
    CRITICAL = "CRITICAL"  # Immediate security risk, easily exploitable
    HIGH = "HIGH"          # Significant security risk
    MEDIUM = "MEDIUM"      # Notable security concern
    LOW = "LOW"            # Minor security issue
    INFO = "INFO"          # Informational, not necessarily a vulnerability


# Emoji indicators for severity levels
SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


class SecurityFinding(object):
    """
    Represents a specific security issue found at a call site.
    
    Attributes:
        severity: How serious this issue is
        issue_type: Short name (e.g., "ECB Mode", "Weak Algorithm")
        description: Human-readable description
        location: Address where the issue was found
        function_name: Name of the security function being called
        evidence: Supporting evidence (parameter values, etc.)
        impact: Why this is a security concern
        recommendation: How to fix (optional)
    """
    
    def __init__(self, severity, issue_type, description, location, 
                 function_name, evidence, impact, recommendation=None):
        self.severity = severity
        self.issue_type = issue_type
        self.description = description
        self.location = location
        self.function_name = function_name
        self.evidence = evidence
        self.impact = impact
        self.recommendation = recommendation
    
    def __str__(self):
        return self.format_str()
    
    def format_str(self, program=None):
        """
        Format finding for display.
        
        Args:
            program: Optional GhidraProgram for offset calculation and demangling
        """
        emoji = SEVERITY_EMOJI.get(self.severity, "")
        
        # Resolve function name (demangle if Swift)
        display_name = self.function_name
        offset_str = ""
        
        if program is not None:
            # Demangle Swift symbols
            try:
                from .swift_demangle import demangle
                demangled = demangle(self.function_name)
                if demangled != self.function_name:
                    display_name = demangled
            except Exception:
                pass
            
            # Calculate offset from image base
            try:
                image_base = program.image_base
                if image_base and self.location >= image_base:
                    offset = self.location - image_base
                    offset_str = " (Offset: {})".format(hex(offset))
            except Exception:
                pass
        
        lines = [
            "{} {}: {}".format(emoji, self.severity.value, self.description),
            "   Location: {}{}".format(hex(self.location), offset_str),
            "   Function: {}".format(display_name),
        ]
        
        # Add evidence if available
        if self.evidence:
            lines.append("   Evidence:")
            for key, value in self.evidence.items():
                lines.append("      {}: {}".format(key, value))
        
        # Add impact
        lines.append("   Impact: {}".format(self.impact))
        
        # Add recommendation if available
        if self.recommendation:
            lines.append("   Fix: {}".format(self.recommendation))
        
        return "\n".join(lines)


class SecurityChecker:
    """
    Base class for category-specific security checkers.
    
    Subclasses implement specific security checks for each category
    (crypto, keychain, networking, etc.).
    
    Usage:
        class CryptoChecker(SecurityChecker):
            def check_call_site(self, function_sig, call_ref, extracted_info):
                findings = []
                # ... check for issues ...
                return findings
    """
    
    def __init__(self, program: "GhidraProgram"):
        """
        Initialize the security checker.
        
        Args:
            program: GhidraProgram wrapper for analysis context
        """
        self.program = program
    
    def check_call_site(
        self,
        function_sig: "FunctionSignature",
        call_site: "CallSite",
        extracted_info: "ExtractedCallInfo"
    ) -> List[SecurityFinding]:
        """
        Check a single call site for security issues.
        
        Args:
            function_sig: FunctionSignature of the security function
            call_site: CallSite representing the call location
            extracted_info: ExtractedCallInfo with parameter values
            
        Returns:
            List of SecurityFinding objects (empty if no issues found)
        """
        raise NotImplementedError("Subclasses must implement check_call_site")
    
    def _is_constant_value(self, param) -> bool:
        """Check if a parameter has a constant value."""
        return param.value_if_constant is not None
    
    def _is_null_pointer(self, param) -> bool:
        """Check if a parameter is a NULL pointer."""
        return self._is_constant_value(param) and param.value_if_constant == 0
    
    def _get_constant_int(self, param) -> Optional[int]:
        """Get the constant integer value if available."""
        if self._is_constant_value(param) and isinstance(param.value_if_constant, int):
            return param.value_if_constant
        return None
    
    def _is_data_section(self, address: int) -> bool:
        """Check if an address is in a data (non-executable) section."""
        return self.program.is_address_in_data_section(address)


__all__ = [
    "Severity",
    "SecurityFinding",
    "SecurityChecker",
    "SEVERITY_EMOJI",
]
