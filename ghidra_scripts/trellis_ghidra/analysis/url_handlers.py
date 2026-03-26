"""
URL Handler detection and analysis for iOS applications in Ghidra.

This module provides functionality to detect URL scheme handlers in iOS
binaries, with special support for SwiftUI apps where traditional backtrace-based
analysis fails due to the reactive architecture.

SwiftUI apps use a state-based architecture:
1. handleIncomingURL receives URL, updates state, returns
2. SwiftUI observes state change
3. View re-renders
4. WebView loads URL (backtrace starts here - handler already returned)

Therefore, URL handlers are detected by SYMBOL SEARCH, not backtrace analysis.

Example usage:
    from trellis_ghidra.ghidra_api import GhidraProgram
    from trellis_ghidra.analysis.url_handlers import find_url_handlers
    
    program = GhidraProgram(currentProgram)
    handlers = find_url_handlers(program)
    
    for handler in handlers:
        print(f"{handler.symbol_name} @ {hex(handler.address)}")
"""

import re
from dataclasses import dataclass
from typing import Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ..ghidra_api import GhidraProgram

from .swift_demangle import demangle


@dataclass
class URLHandler:
    """
    Represents a detected URL handler in an iOS binary.

    Attributes:
        symbol_name: The full (possibly mangled) symbol name
        demangled_name: Human-readable name if demangled, else same as symbol_name
        address: Virtual address of the handler function
        handler_type: Classification of handler type (swiftui, uikit, appdelegate, custom)
        confidence: Confidence level (high, medium, low)
    """

    symbol_name: str
    demangled_name: str
    address: int
    handler_type: str
    confidence: str


# URL handler detection patterns
# These patterns identify functions that handle incoming URLs

SWIFTUI_URL_PATTERNS = [
    # SwiftUI .onOpenURL modifier handlers
    r"handleIncomingURL",
    r"handleURL",
    r"handleDeepLink",
    r"onOpenURL",
    r"openURL",
    # SwiftUI scene phase handlers
    r"handleScenePhase",
    r"scenePhase",
]

UIKIT_URL_PATTERNS = [
    # UIApplicationDelegate methods
    r"application:openURL:options:",
    r"application:openURL:sourceApplication:",
    r"application:handleOpenURL:",
    # UISceneDelegate methods
    r"scene:openURLContexts:",
    r"scene:willConnectToSession:",
]

APPDELEGATE_PATTERNS = [
    # App delegate URL handling
    r"AppDelegate.*openURL",
    r"AppDelegate.*handleURL",
    r"SceneDelegate.*openURL",
    r"SceneDelegate.*handleURL",
]

CUSTOM_URL_PATTERNS = [
    # Common custom handler patterns
    r"deeplink",
    r"DeepLink",
    r"universal.*link",
    r"UniversalLink",
    r"urlScheme",
    r"URLScheme",
    r"routeURL",
    r"RouteURL",
    r"handleRoute",
    r"processURL",
]


def _classify_handler(symbol: str, demangled: str) -> tuple:
    """
    Classify a URL handler and assign confidence level.

    Args:
        symbol: Original symbol name
        demangled: Demangled symbol name

    Returns:
        Tuple of (handler_type, confidence)
    """
    lower_symbol = symbol.lower()
    lower_demangled = demangled.lower()

    # Check SwiftUI patterns (highest confidence for explicit handlers)
    for pattern in SWIFTUI_URL_PATTERNS:
        if re.search(pattern.lower(), lower_symbol) or re.search(
            pattern.lower(), lower_demangled
        ):
            # handleIncomingURL and onOpenURL are very high confidence
            if "handleincomingurl" in lower_symbol or "onopenurl" in lower_symbol:
                return ("swiftui", "high")
            return ("swiftui", "medium")

    # Check UIKit delegate patterns
    for pattern in UIKIT_URL_PATTERNS:
        if re.search(pattern.lower(), lower_symbol) or re.search(
            pattern.lower(), lower_demangled
        ):
            return ("uikit", "high")

    # Check AppDelegate patterns
    for pattern in APPDELEGATE_PATTERNS:
        if re.search(pattern.lower(), lower_symbol) or re.search(
            pattern.lower(), lower_demangled
        ):
            return ("appdelegate", "high")

    # Check custom patterns
    for pattern in CUSTOM_URL_PATTERNS:
        if re.search(pattern.lower(), lower_symbol) or re.search(
            pattern.lower(), lower_demangled
        ):
            return ("custom", "medium")

    # Generic URL-related function
    if "url" in lower_symbol and (
        "handle" in lower_symbol or "process" in lower_symbol or "open" in lower_symbol
    ):
        return ("custom", "low")

    return ("unknown", "low")


def find_url_handlers(program: "GhidraProgram") -> List[URLHandler]:
    """
    Find URL scheme handlers in an iOS binary.

    This function searches for URL handler functions using symbol analysis,
    which is more reliable than backtrace analysis for SwiftUI apps.

    Args:
        program: GhidraProgram to analyze

    Returns:
        List of URLHandler objects for detected handlers

    Example:
        >>> program = GhidraProgram(currentProgram)
        >>> handlers = find_url_handlers(program)
        >>> for h in handlers:
        ...     print(f"[{h.confidence}] {h.handler_type}: {h.demangled_name}")
    """
    handlers = []
    seen_addresses = set()

    # Compile all patterns into a single regex for efficiency
    all_patterns = (
        SWIFTUI_URL_PATTERNS
        + UIKIT_URL_PATTERNS
        + APPDELEGATE_PATTERNS
        + CUSTOM_URL_PATTERNS
    )

    # Also search for generic URL patterns
    url_patterns = [r"url", r"URL", r"Url", r"deeplink", r"DeepLink", r"scheme"]

    # Search through function symbols (both internal and external)
    for sym in program.get_function_symbols():
        # Skip if we've already seen this address
        if sym.address in seen_addresses:
            continue

        symbol_str = sym.name

        # Check if symbol matches any URL-related pattern
        matches_pattern = False
        for pattern in all_patterns:
            if re.search(pattern, symbol_str, re.IGNORECASE):
                matches_pattern = True
                break

        # Also check for generic URL patterns with handler-like context
        if not matches_pattern:
            for pattern in url_patterns:
                if re.search(pattern, symbol_str, re.IGNORECASE):
                    # Must also have handler-like context
                    if re.search(
                        r"(handle|process|open|route|receive|incoming)",
                        symbol_str,
                        re.IGNORECASE,
                    ):
                        matches_pattern = True
                        break

        if matches_pattern:
            # Demangle Swift symbols
            demangled = demangle(symbol_str) if symbol_str.startswith(("$s", "_$s")) else symbol_str
            handler_type, confidence = _classify_handler(symbol_str, demangled)

            handlers.append(
                URLHandler(
                    symbol_name=symbol_str,
                    demangled_name=demangled,
                    address=sym.address,
                    handler_type=handler_type,
                    confidence=confidence,
                )
            )
            seen_addresses.add(sym.address)

    # Sort by confidence (high first) then by address
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    handlers.sort(key=lambda h: (confidence_order.get(h.confidence, 3), h.address))

    return handlers


def generate_url_handler_frida_script(
    handlers: List[URLHandler], binary_name: str
) -> str:
    """
    Generate a Frida script to hook detected URL handlers.

    Note: Hooking Swift functions directly may cause crashes due to calling
    convention differences. This script includes warnings and focuses on
    logging entry points rather than modifying behavior.

    Args:
        handlers: List of URLHandler objects from find_url_handlers
        binary_name: Name of the target binary

    Returns:
        Complete Frida script as a string
    """
    from datetime import datetime

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Split handlers into ObjC and Swift
    objc_handlers = []
    swift_handlers = []
    for handler in handlers:
        is_swift = handler.symbol_name.startswith(
            "$s"
        ) or handler.symbol_name.startswith("_$s")
        if is_swift:
            swift_handlers.append(handler)
        else:
            objc_handlers.append(handler)

    script = f"""// trellis_url_handlers.js
// Generated by Trellis-Ghidra - URL Handler Detection
// Target: {binary_name}
// Generated: {timestamp}
// Frida API: 17.x+ compatible
//
// This script monitors URL scheme handler entry points.
// Uses ObjC runtime lookup for ObjC methods, offset-based hooking for Swift.
//
// IMPORTANT: Swift function hooks may cause crashes due to calling conventions.
// This script focuses on detection and logging, not modification.

(function() {{
    'use strict';

    // App module detection
    var appModules = Process.enumerateModules().filter(function(m) {{
        return m.path.includes('.app/');
    }});
    var mainModule = appModules.length > 0 ? appModules[0] : Process.enumerateModules()[0];

    console.log('[*] Trellis URL Handler Monitor');
    console.log('[*] Target module:', mainModule.name);
    console.log('[*] Base address:', mainModule.base);

    // Read __TEXT vmaddr once from Mach-O header for address translation
    var textVmaddr = ptr(0);
    (function() {{
        var header = mainModule.base;
        if (header.readU32() === 0xfeedfacf) {{  // MH_MAGIC_64
            var ncmds = header.add(16).readU32();
            var cmdPtr = header.add(32);
            for (var i = 0; i < ncmds; i++) {{
                var cmd = cmdPtr.readU32();
                var cmdsize = cmdPtr.add(4).readU32();
                if (cmd === 0x19) {{  // LC_SEGMENT_64
                    var segname = cmdPtr.add(8).readUtf8String();
                    if (segname && segname.startsWith('__TEXT')) {{
                        textVmaddr = ptr(cmdPtr.add(24).readU64());
                        break;
                    }}
                }}
                cmdPtr = cmdPtr.add(cmdsize);
            }}
        }}
    }})();
    console.log('[*] __TEXT vmaddr:', textVmaddr);

    // Ghidra address -> runtime address
    function getRuntimeAddress(ghidraAddrStr) {{
        return mainModule.base.add(ptr(ghidraAddrStr).sub(textVmaddr));
    }}

    // Runtime address -> Ghidra address
    function getGhidraOffset(runtimeAddr) {{
        return runtimeAddr.sub(mainModule.base).add(textVmaddr);
    }}

    // Backtrace formatting
    function formatBacktrace(ctx, maxFrames) {{
        var bt = Thread.backtrace(ctx, Backtracer.ACCURATE);
        var lines = [];
        for (var i = 0; i < Math.min(bt.length, maxFrames || 5); i++) {{
            var addr = bt[i];
            var sym = DebugSymbol.fromAddress(addr);
            var ghidra = getGhidraOffset(addr);
            lines.push('      ' + addr + ' (Ghidra: 0x' + ghidra.toString(16) + ') ' + (sym.name || '<unknown>'));
        }}
        return lines.join('\\n');
    }}

    console.log('');

"""

    # ObjC handlers: single-pass enumeration via ObjC runtime with offset fallback
    if objc_handlers:
        selector_entries = []
        for h in objc_handlers:
            display = h.demangled_name[:50].replace('\\', '\\\\').replace('"', '\\"')
            selector_entries.append(
                f'        "{h.symbol_name}": {{'
                f' type: "{h.handler_type}",'
                f' confidence: "{h.confidence}",'
                f' ghidraAddr: "0x{h.address:x}",'
                f' display: "{display}",'
                f' found: false }}'
            )
        selector_map_js = ",\n".join(selector_entries)

        script += f"""    // ========================================
    // ObjC URL Handler Detection (Runtime)
    // ========================================
    (function() {{
        var selectorMap = {{
{selector_map_js}
        }};
        var selectorList = Object.keys(selectorMap);
        console.log('[*] Searching ObjC runtime for ' + selectorList.length + ' URL handler selectors...');

        // Single pass through ObjC classes
        for (var className in ObjC.classes) {{
            try {{
                var cls = ObjC.classes[className];
                for (var i = 0; i < selectorList.length; i++) {{
                    var sel = selectorList[i];
                    var method = cls['- ' + sel];
                    if (method && method.implementation) {{
                        selectorMap[sel].found = true;
                        (function(sel, clsName, impl, info) {{
                            try {{
                                Interceptor.attach(impl, {{
                                    onEnter: function(args) {{
                                        console.log('\\n[+] URL Handler called: ' + sel);
                                        console.log('    Class: ' + clsName);
                                        console.log('    Type: ' + info.type);
                                        console.log('    Backtrace:');
                                        console.log(formatBacktrace(this.context, 5));
                                    }}
                                }});
                                console.log('[+] Hooked ' + clsName + ' -' + sel);
                            }} catch (e) {{
                                console.log('[-] Hook failed: ' + clsName + ' -' + sel + ': ' + e);
                            }}
                        }})(sel, className, method.implementation, selectorMap[sel]);
                    }}
                }}
            }} catch (e) {{}}
        }}

        // Offset fallback for selectors not found via ObjC runtime
        for (var i = 0; i < selectorList.length; i++) {{
            var sel = selectorList[i];
            var info = selectorMap[sel];
            if (!info.found) {{
                (function(sel, info) {{
                    try {{
                        var funcPtr = getRuntimeAddress(info.ghidraAddr);
                        Interceptor.attach(funcPtr, {{
                            onEnter: function(args) {{
                                console.log('\\n[+] URL Handler called (offset): ' + sel);
                                console.log('    Type: ' + info.type);
                                console.log('    Backtrace:');
                                console.log(formatBacktrace(this.context, 5));
                            }}
                        }});
                        console.log('[+] Hooked ' + sel + ' at ' + funcPtr + ' (offset fallback)');
                    }} catch (e) {{
                        console.log('[-] Handler not hookable: ' + sel + ': ' + e);
                    }}
                }})(sel, info);
            }}
        }}
    }})();

"""

    # Swift handlers: offset-based hooking using known Ghidra addresses
    if swift_handlers:
        script += """    // ========================================
    // Swift URL Handler Detection (Offset-based)
    // ========================================

"""
        for handler in swift_handlers:
            display = handler.demangled_name[:50].replace("'", "\\'")
            script += f"""    // {handler.demangled_name[:60]}
    // Type: {handler.handler_type} | Confidence: {handler.confidence}
    (function() {{
        try {{
            var funcPtr = getRuntimeAddress("0x{handler.address:x}");
            console.log('[*] Swift handler: {display}');
            console.log('    Runtime: ' + funcPtr + ' | Ghidra: 0x{handler.address:x}');
            console.log('    [!] Swift function - hook may crash');
            Interceptor.attach(funcPtr, {{
                onEnter: function(args) {{
                    console.log('\\n[+] Swift URL Handler: {display}');
                    console.log('    Type: {handler.handler_type}');
                    console.log('    Backtrace:');
                    console.log(formatBacktrace(this.context, 5));
                }}
            }});
            console.log('    [+] Hook installed');
        }} catch (e) {{
            console.log('[-] Swift handler failed: {display}: ' + e);
        }}
    }})();

"""

    script += """
    console.log('');
    console.log('[*] URL Handler monitoring active');
    console.log('[*] Trigger URL schemes to see handler activity');

})();
"""

    return script


def format_url_handlers_report(
    handlers: List[URLHandler], binary_name: str
) -> str:
    """
    Format URL handlers into a Markdown report.

    Args:
        handlers: List of URLHandler objects
        binary_name: Name of the binary

    Returns:
        Markdown formatted report string
    """
    from datetime import datetime

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = f"""## URL Handler Analysis Report

**Binary**: {binary_name}
**Generated**: {timestamp}
**Total Handlers Found**: {len(handlers)}

---

### Summary by Type

| Type | Count | Description |
|------|-------|-------------|
| swiftui | {len([h for h in handlers if h.handler_type == 'swiftui'])} | SwiftUI .onOpenURL handlers |
| uikit | {len([h for h in handlers if h.handler_type == 'uikit'])} | UIKit delegate methods |
| appdelegate | {len([h for h in handlers if h.handler_type == 'appdelegate'])} | AppDelegate/SceneDelegate handlers |
| custom | {len([h for h in handlers if h.handler_type == 'custom'])} | Custom URL handling functions |

### Summary by Confidence

| Confidence | Count |
|------------|-------|
| high | {len([h for h in handlers if h.confidence == 'high'])} |
| medium | {len([h for h in handlers if h.confidence == 'medium'])} |
| low | {len([h for h in handlers if h.confidence == 'low'])} |

---

### Detected Handlers

"""

    # Group by confidence
    for confidence in ["high", "medium", "low"]:
        confidence_handlers = [h for h in handlers if h.confidence == confidence]
        if confidence_handlers:
            report += f"#### {confidence.upper()} Confidence\n\n"
            report += "| Address | Type | Symbol |\n"
            report += "|---------|------|--------|\n"
            for h in confidence_handlers:
                # Truncate long symbol names
                symbol_display = (
                    h.demangled_name[:60] + "..."
                    if len(h.demangled_name) > 60
                    else h.demangled_name
                )
                report += f"| `{hex(h.address)}` | {h.handler_type} | `{symbol_display}` |\n"
            report += "\n"

    report += """---

### Analysis Notes

**SwiftUI Reactive Architecture**:
- URL handlers in SwiftUI apps update state, then return
- Traditional backtrace analysis will NOT show the handler on the call stack
- Use symbol-based detection (this report) for SwiftUI apps

**Recommended Next Steps**:
1. Open handlers in Ghidra for static analysis
2. Use generated Frida script for runtime monitoring
3. Test URL schemes to trigger handlers and observe behavior

"""

    return report


@dataclass
class URLScheme:
    """
    Represents a URL scheme discovered in binary strings.

    Attributes:
        scheme: The scheme name (e.g. 'myapp')
        full_string: The full string reference containing the scheme
        string_address: Address where the string was found in the binary
        handler_address: Address of a handler function (if cross-referenced)
        handler_name: Name of the handler function (if found)
        source: How the scheme was detected ('string_search', 'info_plist')
    """

    scheme: str
    full_string: str
    string_address: int
    handler_address: Optional[int] = None
    handler_name: Optional[str] = None
    source: str = "string_search"


# Common system/third-party schemes to exclude from results
SYSTEM_SCHEMES = {
    "http", "https", "file", "ftp", "ftps", "ssh", "tel", "mailto",
    "sms", "geo", "data", "about", "blob", "javascript", "ws", "wss",
    "itms", "itms-apps", "itms-appss", "itms-services",
    "maps", "facetime", "facetime-audio",
    "x-apple", "prefs", "app-settings",
    # Common third-party SDKs
    "fb", "fbauth", "fbauth2", "fbapi", "fbshareextension",
    "twitter", "twitterauth",
    "com-google", "googlechrome", "googlechrome-x-callback",
    "instagram", "instagram-stories",
    "whatsapp", "line", "weixin", "wechat",
    "linkedin", "linkedin-sdk",
    "spotify",
}

# Patterns that look like schemes but aren't
SCHEME_FALSE_POSITIVES = {
    "com.apple", "org.cocoapods", "org.swift", "com.google",
    "undefined", "null", "example", "test", "localhost",
    "0.0.0.0", "127.0.0.1",
}


def extract_url_schemes(program: "GhidraProgram") -> List[URLScheme]:
    """
    Extract custom URL schemes from binary string references.

    Searches binary strings for patterns matching `scheme://` and filters
    out system/third-party schemes to identify app-specific URL schemes
    that may represent attack surface.

    Args:
        program: GhidraProgram to analyze

    Returns:
        List of URLScheme objects for discovered custom schemes
    """
    schemes = []
    seen_schemes = set()

    # Pattern: word characters followed by ://
    scheme_pattern = re.compile(r'^([a-zA-Z][a-zA-Z0-9+\-.]{1,30})://')

    # Search all strings in the binary
    for string_data in program.get_defined_strings():
        try:
            text = string_data.value
            if not text:
                continue
        except Exception:
            continue

        match = scheme_pattern.match(text)
        if not match:
            continue

        scheme_name = match.group(1).lower()

        # Filter out system/known schemes
        if scheme_name in SYSTEM_SCHEMES:
            continue

        # Filter out false positives
        skip = False
        for fp in SCHEME_FALSE_POSITIVES:
            if scheme_name.startswith(fp):
                skip = True
                break
        if skip:
            continue

        # Filter out very long "schemes" (likely not real schemes)
        if len(scheme_name) > 25:
            continue

        # Deduplicate by scheme name
        if scheme_name in seen_schemes:
            continue
        seen_schemes.add(scheme_name)

        schemes.append(URLScheme(
            scheme=scheme_name,
            full_string=text[:100],
            string_address=string_data.address,
            source="string_search",
        ))

    return schemes


def cross_reference_schemes_with_handlers(
    schemes: List[URLScheme],
    handlers: List[URLHandler],
    program: "GhidraProgram",
) -> List[URLScheme]:
    """
    Cross-reference discovered URL schemes with URL handler functions.

    For each scheme, tries to find which handler function processes it
    by searching for xrefs from handler functions to the scheme string.

    Args:
        schemes: List of URLScheme objects from extract_url_schemes
        handlers: List of URLHandler objects from find_url_handlers
        program: GhidraProgram

    Returns:
        Updated list of URLScheme objects with handler info populated
    """
    if not handlers:
        return schemes

    # Build a set of handler function address ranges for quick lookup
    handler_ranges = []
    for handler in handlers:
        func = program.get_function_at(handler.address)
        if func:
            # Get function size from Ghidra
            ghidra_func = func._ghidra_function
            body = ghidra_func.getBody()
            func_start = ghidra_func.getEntryPoint().getOffset()
            func_end = body.getMaxAddress().getOffset()
            handler_ranges.append((func_start, func_end, handler.demangled_name))

    for scheme in schemes:
        # Get references to this string address
        refs = program.get_references_to(scheme.string_address)
        
        for ref in refs:
            # Check if the reference is from a known handler
            for start, end, name in handler_ranges:
                if start <= ref.from_address < end:
                    scheme.handler_address = start
                    scheme.handler_name = name
                    break
            if scheme.handler_address:
                break

    return schemes


def format_url_schemes_report(
    schemes: List[URLScheme],
    binary_name: str,
) -> str:
    """
    Format discovered URL schemes into a report section.

    Args:
        schemes: List of URLScheme objects
        binary_name: Name of the binary

    Returns:
        Markdown formatted report string
    """
    if not schemes:
        return "### URL Schemes\n\nNo custom URL schemes detected in binary strings.\n"

    report = f"### URL Schemes Detected ({len(schemes)})\n\n"
    report += "| Scheme | String Reference | Handler |\n"
    report += "|--------|-----------------|----------|\n"

    for s in schemes:
        handler_info = f"`{s.handler_name}` @ `{hex(s.handler_address)}`" if s.handler_address else "—"
        # Escape pipe characters in the string
        safe_string = s.full_string.replace("|", "\\|")[:60]
        report += f"| `{s.scheme}://` | `{safe_string}` | {handler_info} |\n"

    report += "\n**Note**: These are custom URL schemes found in binary strings. "
    report += "Each scheme represents potential attack surface for deep link injection.\n\n"

    return report


@dataclass
class UIEntryPoint:
    """
    Represents a UI entry point detected in an iOS binary.

    These are functions where user interaction begins — useful for
    tracing input flow during security analysis.

    Attributes:
        symbol_name: The full symbol name
        demangled_name: Human-readable name
        address: Virtual address of the function
        entry_type: Classification (viewDidLoad, ibaction, swiftui, gesture)
        class_name: Containing class name if available
    """

    symbol_name: str
    demangled_name: str
    address: int
    entry_type: str
    class_name: Optional[str] = None


# UI entry point detection patterns
VIEWDIDLOAD_PATTERN = re.compile(r"\[(\w+)\s+viewDidLoad\]")
IBACTION_PATTERN = re.compile(r"\[(\w+)\s+(\w+):\].*IBAction|IBAction.*\[(\w+)\s+(\w+):\]")

UIKIT_ENTRY_PATTERNS = [
    (r"viewDidLoad", "viewDidLoad"),
    (r"viewWillAppear", "viewWillAppear"),
    (r"viewDidAppear", "viewDidAppear"),
    (r"IBAction", "ibaction"),
    (r"touchesBegan:withEvent:", "touches"),
    (r"touchesEnded:withEvent:", "touches"),
    (r"motionBegan:withEvent:", "motion"),
]

SWIFTUI_ENTRY_PATTERNS = [
    (r"onTapGesture", "swiftui_gesture"),
    (r"onAppear", "swiftui_lifecycle"),
    (r"onDisappear", "swiftui_lifecycle"),
    (r"onChange", "swiftui_observer"),
    (r"onSubmit", "swiftui_form"),
    (r"onReceive", "swiftui_publisher"),
]


def find_ui_entry_points(program: "GhidraProgram") -> List[UIEntryPoint]:
    """
    Find UI entry points in an iOS binary.

    Detects viewDidLoad implementations, IBAction methods, SwiftUI
    lifecycle handlers, and gesture recognizer targets. These represent
    where user interaction begins and are useful starting points for
    tracing input flow during security analysis.

    Args:
        program: GhidraProgram to analyze

    Returns:
        List of UIEntryPoint objects sorted by entry type and address
    """
    entry_points = []
    seen_addresses = set()

    for sym in program.get_function_symbols():
        if sym.address in seen_addresses:
            continue

        name = sym.name
        matched = False

        # Check UIKit patterns
        for pattern, entry_type in UIKIT_ENTRY_PATTERNS:
            if re.search(pattern, name):
                # Extract class name from ObjC selector pattern
                class_name = None
                class_match = re.match(r"-\[(\w+)\s+", name)
                if class_match:
                    class_name = class_match.group(1)

                demangled = demangle(name) if name.startswith(("$s", "_$s")) else name
                entry_points.append(UIEntryPoint(
                    symbol_name=name,
                    demangled_name=demangled,
                    address=sym.address,
                    entry_type=entry_type,
                    class_name=class_name,
                ))
                seen_addresses.add(sym.address)
                matched = True
                break

        if matched:
            continue

        # Check SwiftUI patterns
        for pattern, entry_type in SWIFTUI_ENTRY_PATTERNS:
            if re.search(pattern, name, re.IGNORECASE):
                demangled = demangle(name) if name.startswith(("$s", "_$s")) else name
                entry_points.append(UIEntryPoint(
                    symbol_name=name,
                    demangled_name=demangled,
                    address=sym.address,
                    entry_type=entry_type,
                ))
                seen_addresses.add(sym.address)
                break

    # Sort by entry type then address
    type_order = {
        "viewDidLoad": 0, "ibaction": 1, "touches": 2, "motion": 3,
        "swiftui_gesture": 4, "swiftui_lifecycle": 5, "swiftui_form": 6,
        "swiftui_observer": 7, "swiftui_publisher": 8,
        "viewWillAppear": 9, "viewDidAppear": 10,
    }
    entry_points.sort(key=lambda e: (type_order.get(e.entry_type, 99), e.address))

    return entry_points


__all__ = [
    "URLHandler",
    "URLScheme",
    "UIEntryPoint",
    "find_url_handlers",
    "find_ui_entry_points",
    "extract_url_schemes",
    "cross_reference_schemes_with_handlers",
    "generate_url_handler_frida_script",
    "format_url_handlers_report",
    "format_url_schemes_report",
]
