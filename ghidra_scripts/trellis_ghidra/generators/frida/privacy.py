from .base import generate_category_script

def generate_privacy_script(binary_name: str) -> str:
    """Generate Frida script for privacy hooks."""
    return generate_category_script("privacy", binary_name)
