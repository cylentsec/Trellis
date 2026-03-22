from .base import generate_category_script

def generate_integrity_script(binary_name: str) -> str:
    """Generate Frida script for integrity hooks."""
    return generate_category_script("integrity", binary_name)
