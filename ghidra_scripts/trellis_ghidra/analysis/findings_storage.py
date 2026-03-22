# -*- coding: utf-8 -*-
"""
Findings storage and serialization for Trellis.

This module provides functionality to save and load security findings
between TrellisAnalyze (static analysis) and TrellisFrida (dynamic instrumentation).

The findings are stored in JSON format for:
- Human readability
- Easy inspection and debugging
- Cross-tool compatibility
- Version control friendliness

Example usage:
    >>> from trellis.analysis import run_security_analysis
    >>> from trellis.analysis.findings_storage import save_findings, load_findings
    >>>
    >>> # In TrellisAnalyze
    >>> findings = run_security_analysis(program, "keychain")
    >>> save_findings(findings, "/path/to/output", "keychain", "MyApp")
    >>>
    >>> # In TrellisFrida
    >>> findings = load_findings("/path/to/output", "keychain", "MyApp")
    >>> script = generate_findings_script(findings, "MyApp", "keychain")
"""

import json
import os
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime

from .security_checks import SecurityFinding, Severity


def severity_to_string(severity: Severity) -> str:
    """Convert Severity enum to string."""
    return severity.name


def string_to_severity(severity_str: str) -> Severity:
    """Convert string to Severity enum."""
    return Severity[severity_str]


def finding_to_dict(finding: SecurityFinding) -> Dict[str, Any]:
    """
    Convert a SecurityFinding object to a JSON-serializable dictionary.
    
    Args:
        finding: SecurityFinding object
    
    Returns:
        Dictionary representation of the finding
    """
    return {
        "severity": severity_to_string(finding.severity),
        "issue_type": finding.issue_type,
        "description": finding.description,
        "location": finding.location,
        "function_name": finding.function_name,
        "evidence": finding.evidence,
        "impact": finding.impact,
        "recommendation": finding.recommendation,
    }


def dict_to_finding(finding_dict: Dict[str, Any]) -> SecurityFinding:
    """
    Convert a dictionary to a SecurityFinding object.
    
    Args:
        finding_dict: Dictionary representation of a finding
    
    Returns:
        SecurityFinding object
    """
    return SecurityFinding(
        severity=string_to_severity(finding_dict["severity"]),
        issue_type=finding_dict["issue_type"],
        description=finding_dict["description"],
        location=finding_dict["location"],
        function_name=finding_dict["function_name"],
        evidence=finding_dict.get("evidence", {}),
        impact=finding_dict.get("impact", ""),
        recommendation=finding_dict.get("recommendation", ""),
    )


def save_findings_json(
    findings: List[SecurityFinding],
    output_path: str,
    category: str,
    binary_name: str,
    timestamp: Optional[str] = None,
    image_base: Optional[int] = None
) -> str:
    """
    Save findings to a JSON file.
    
    The file is named: trellis-{category}-findings-{timestamp}.json
    
    Args:
        findings: List of SecurityFinding objects
        output_path: Directory to save the file
        category: Category name (e.g., "keychain", "crypto")
        binary_name: Name of the analyzed binary
        timestamp: Optional timestamp string (defaults to current time)
        image_base: Ghidra image base address (needed for Frida offset calculation)
    
    Returns:
        Path to the saved JSON file
    
    Example:
        >>> save_findings_json(findings, "/tmp", "keychain", "DVIA-v2", image_base=0x100000000)
        '/tmp/trellis-keychain-findings-26-02-25-101154.json'
    """
    if timestamp is None:
        timestamp = datetime.now().strftime("%y-%m-%d-%H%M%S")
    
    # Build the JSON structure
    metadata = {
        "category": category,
        "binary_name": binary_name,
        "timestamp": timestamp,
        "total_findings": len(findings),
        "severity_counts": {
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in findings if f.severity == Severity.LOW),
        },
        "format_version": "1.1",
    }
    if image_base is not None:
        metadata["image_base"] = image_base
    
    findings_data = {
        "metadata": metadata,
        "findings": [finding_to_dict(f) for f in findings],
    }
    
    # Create output directory if it doesn't exist
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate filename
    filename = f"trellis-{category}-findings-{timestamp}.json"
    filepath = output_dir / filename
    
    # Write JSON file
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(findings_data, f, indent=2, ensure_ascii=False)
    
    return str(filepath)


def load_findings_json(filepath: str) -> List[SecurityFinding]:
    """
    Load findings from a JSON file.
    
    Args:
        filepath: Path to the JSON file
    
    Returns:
        List of SecurityFinding objects
    
    Raises:
        FileNotFoundError: If the file doesn't exist
        ValueError: If the file format is invalid
    
    Example:
        >>> findings = load_findings_json("/tmp/trellis-keychain-findings-26-02-25-101154.json")
        >>> len(findings)
        8
    """
    filepath = Path(filepath)
    
    if not filepath.exists():
        raise FileNotFoundError(f"Findings file not found: {filepath}")
    
    with open(filepath, 'r', encoding='utf-8') as f:
        findings_data = json.load(f)
    
    # Validate format
    if "findings" not in findings_data:
        raise ValueError(f"Invalid findings file format: missing 'findings' key")
    
    # Convert dictionaries back to SecurityFinding objects
    findings = [dict_to_finding(f) for f in findings_data["findings"]]
    
    return findings


def load_findings_with_metadata(
    output_dir: str,
    category: str,
    binary_name: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Load the latest findings for a category along with JSON metadata.
    
    Returns both findings and metadata (including image_base) needed
    for Frida script generation.
    
    Args:
        output_dir: Directory containing findings files
        category: Category name
        binary_name: Optional binary name filter
    
    Returns:
        Dict with 'findings', 'metadata' keys, or None if not found
    """
    filepath = find_latest_findings(output_dir, category, binary_name)
    
    if filepath is None:
        return None
    
    filepath = Path(filepath)
    with open(filepath, 'r', encoding='utf-8') as f:
        findings_data = json.load(f)
    
    if "findings" not in findings_data:
        return None
    
    findings = [dict_to_finding(f) for f in findings_data["findings"]]
    metadata = findings_data.get("metadata", {})
    
    return {
        "findings": findings,
        "metadata": metadata,
    }


def find_latest_findings(
    output_dir: str,
    category: str,
    binary_name: Optional[str] = None
) -> Optional[str]:
    """
    Find the most recent findings file for a category.
    
    Args:
        output_dir: Directory containing findings files
        category: Category name (e.g., "keychain")
        binary_name: Optional binary name filter
    
    Returns:
        Path to the latest findings file, or None if not found
    
    Example:
        >>> filepath = find_latest_findings("/tmp", "keychain")
        >>> findings = load_findings_json(filepath)
    """
    output_path = Path(output_dir)
    
    if not output_path.exists():
        return None
    
    # Pattern: trellis-{category}-findings-*.json
    pattern = f"trellis-{category}-findings-*.json"
    matching_files = list(output_path.glob(pattern))
    
    if not matching_files:
        return None
    
    # If binary_name is provided, filter by reading metadata
    if binary_name:
        filtered_files = []
        for filepath in matching_files:
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    if data.get("metadata", {}).get("binary_name") == binary_name:
                        filtered_files.append(filepath)
            except (json.JSONDecodeError, IOError):
                continue
        matching_files = filtered_files
    
    if not matching_files:
        return None
    
    # Sort by modification time (most recent first)
    latest_file = max(matching_files, key=lambda p: p.stat().st_mtime)
    
    return str(latest_file)


def save_findings(
    findings: List[SecurityFinding],
    output_path: str,
    category: str,
    binary_name: str,
    timestamp: Optional[str] = None,
    image_base: Optional[int] = None
) -> str:
    """
    Convenience function to save findings (alias for save_findings_json).
    
    Args:
        findings: List of SecurityFinding objects
        output_path: Directory to save the file
        category: Category name
        binary_name: Name of the analyzed binary
        timestamp: Optional timestamp string
        image_base: Ghidra image base address
    
    Returns:
        Path to the saved file
    """
    return save_findings_json(findings, output_path, category, binary_name, timestamp, image_base)


def load_findings(
    output_dir: str,
    category: str,
    binary_name: Optional[str] = None
) -> Optional[List[SecurityFinding]]:
    """
    Convenience function to load the latest findings for a category.
    
    Args:
        output_dir: Directory containing findings files
        category: Category name
        binary_name: Optional binary name filter
    
    Returns:
        List of SecurityFinding objects, or None if not found
    
    Example:
        >>> findings = load_findings("/tmp", "keychain", "DVIA-v2")
        >>> if findings:
        ...     print(f"Loaded {len(findings)} findings")
    """
    filepath = find_latest_findings(output_dir, category, binary_name)
    
    if filepath is None:
        return None
    
    return load_findings_json(filepath)


def get_findings_summary(findings: List[SecurityFinding]) -> Dict[str, Any]:
    """
    Get a summary of findings for reporting.
    
    Args:
        findings: List of SecurityFinding objects
    
    Returns:
        Dictionary with summary statistics
    """
    severity_counts = {
        "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
        "high": sum(1 for f in findings if f.severity == Severity.HIGH),
        "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
        "low": sum(1 for f in findings if f.severity == Severity.LOW),
    }
    
    # Group by issue type
    issue_types = {}
    for finding in findings:
        issue_type = finding.issue_type
        if issue_type not in issue_types:
            issue_types[issue_type] = 0
        issue_types[issue_type] += 1
    
    # Group by function
    functions = {}
    for finding in findings:
        func_name = finding.function_name
        if func_name not in functions:
            functions[func_name] = 0
        functions[func_name] += 1
    
    return {
        "total": len(findings),
        "severity_counts": severity_counts,
        "issue_types": issue_types,
        "functions": functions,
    }


__all__ = [
    "save_findings",
    "save_findings_json",
    "load_findings",
    "load_findings_json",
    "load_findings_with_metadata",
    "find_latest_findings",
    "get_findings_summary",
    "finding_to_dict",
    "dict_to_finding",
]
