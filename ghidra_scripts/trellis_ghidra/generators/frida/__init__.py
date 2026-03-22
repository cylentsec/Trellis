"""
Frida script generators for Trellis.

This package provides utilities for generating Frida JavaScript hooks from
Trellis function signatures. It transforms the YAML-based signature database
into executable instrumentation code for runtime analysis of iOS applications.

The generated scripts can:
- Hook security-relevant functions
- Log parameters with proper type formatting
- Display return values
- Show backtraces for each call
- Decode enum values to readable names
- Hexdump buffer contents

Basic usage:
    >>> from trellis.generators.frida import generate_category_script
    >>>
    >>> # Generate hooks for all crypto functions
    >>> script = generate_category_script("crypto", "MyApp")
    >>> print(script)

Advanced usage:
    >>> from trellis.signatures import get_function
    >>> from trellis.generators.frida import generate_hook, combine_hooks
    >>>
    >>> # Generate specific hooks
    >>> cccrypt = get_function("crypto", "CCCrypt")
    >>> cchmac = get_function("crypto", "CCHmac")
    >>>
    >>> hooks = [generate_hook(cccrypt), generate_hook(cchmac)]
    >>> script = combine_hooks(hooks, "crypto", "MyApp")
    >>>
    >>> # Save for use with Frida
    >>> with open("hooks.js", "w") as f:
    ...     f.write(script)

The generated scripts are compatible with Frida's JavaScript API and can be
injected using frida-tools:
    $ frida -U -f com.example.app -l hooks.js

Script Structure:
    The generated scripts follow this structure:
    1. Header with metadata (timestamp, category, target)
    2. Constant definitions (enum mappings, helpers)
    3. Individual hooks wrapped in IIFEs
    4. Each hook includes:
       - findExport helper to locate function (Frida 17+ compatible)
       - Interceptor.attach with onEnter/onLeave
       - Parameter logging with type-aware formatting
       - Backtrace for call context
       - Return value logging

Type Formatting:
    The generator intelligently formats different parameter types:
    - Enums (CCOperation, CCAlgorithm, etc.) -> Decoded names
    - Integers (int, size_t, uint32_t, etc.) -> .toInt32()
    - Strings (char*) -> ptr.readUtf8String()
    - Buffers (void*) -> Hexdump with size from size_param
    - CF types (CFDictionaryRef, etc.) -> ObjC description
    - Pointers -> Address as string

Available Functions:
    - generate_hook(signature): Generate hook for a single function
    - combine_hooks(hooks, category, binary): Combine hooks into script
    - generate_category_script(category, binary): Generate entire category
    - get_script_header(category, binary, timestamp): Generate header only
    - get_frida_formatter(param, index, size_map): Get formatter for param

Constants:
    - CC_CONSTANTS: JavaScript string with all enum mappings and helpers
"""

from .base import (
    CC_CONSTANTS,
    combine_hooks,
    generate_category_script,
    generate_hook,
    get_frida_formatter,
    get_script_header,
)

# Import category-specific generators
from .crypto import generate_crypto_script
from .networking import generate_networking_script
from .keychain import generate_keychain_script
from .antidebug import generate_antidebug_script
from .jailbreak import generate_jailbreak_script
from .secrets import generate_secrets_script
from .tls_delegate import generate_tls_delegate_script
from .webview_bridge import generate_webview_bridge_script
from .deeplinks import generate_deeplinks_script
from .storage import generate_storage_script
from .deserialization import generate_deserialization_script

__all__ = [
    "generate_hook",
    "combine_hooks",
    "generate_category_script",
    "get_script_header",
    "get_frida_formatter",
    "CC_CONSTANTS",
    "generate_crypto_script",
    "generate_networking_script",
    "generate_keychain_script",
    "generate_antidebug_script",
    "generate_jailbreak_script",
    "generate_secrets_script",
    "generate_tls_delegate_script",
    "generate_webview_bridge_script",
    "generate_deeplinks_script",
    "generate_storage_script",
    "generate_deserialization_script",
]

__version__ = "0.1.0"
