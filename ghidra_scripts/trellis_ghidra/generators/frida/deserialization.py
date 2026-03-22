"""
Frida script generator for deserialization operation hooks.

This module provides specialized hook generation for NSKeyedArchiver/NSKeyedUnarchiver
and NSCoding operations, helping detect insecure deserialization patterns.
"""

from typing import Optional

from .base import combine_hooks


# Deserialization-specific helpers
DESERIALIZATION_HELPERS = """
// Deserialization Helpers

// Helper to log NSData contents (first few bytes)
function logDataPreview(dataPtr, maxBytes) {
    maxBytes = maxBytes || 32;
    if (dataPtr.isNull()) return 'nil';

    try {
        var data = new ObjC.Object(dataPtr);
        var length = data.length();
        var bytes = data.bytes();

        if (length === 0) return '<empty data>';

        var preview = '';
        var previewLen = Math.min(length, maxBytes);
        for (var i = 0; i < previewLen; i++) {
            var byte = bytes.add(i).readU8();
            preview += ('0' + byte.toString(16)).slice(-2) + ' ';
        }

        if (length > maxBytes) {
            preview += '... (' + length + ' bytes total)';
        }

        return preview;
    } catch (e) {
        return '<data preview failed>';
    }
}

// Helper to check if data looks like a plist/archive
function detectDataFormat(dataPtr) {
    if (dataPtr.isNull()) return 'nil';

    try {
        var data = new ObjC.Object(dataPtr);
        var length = data.length();
        if (length < 8) return 'unknown';

        var bytes = data.bytes();

        // Check for binary plist magic
        if (bytes.readUtf8String(6) === 'bplist') {
            return 'Binary Plist (NSKeyedArchive)';
        }

        // Check for XML plist
        if (bytes.readUtf8String(5) === '<?xml') {
            return 'XML Plist';
        }

        // Check for JSON
        var firstByte = bytes.readU8();
        if (firstByte === 0x7B || firstByte === 0x5B) { // { or [
            return 'Possible JSON';
        }

        return 'Binary data';
    } catch (e) {
        return 'unknown';
    }
}

// Track requiresSecureCoding state
var unarchiverSecureCodingState = {};

"""


def generate_deserialization_hooks(binary_name: str = "unknown") -> str:
    """
    Generate Frida hooks for deserialization operations.

    Args:
        binary_name: Name of the target binary/application

    Returns:
        JavaScript code with deserialization hooks
    """
    hooks = []

    # Hook NSKeyedUnarchiver +unarchiveObjectWithData: (deprecated, insecure)
    hooks.append("""
// Hook: NSKeyedUnarchiver +unarchiveObjectWithData: (DEPRECATED, INSECURE)
hookObjCMethod('NSKeyedUnarchiver', '+ unarchiveObjectWithData:', function(impl) {
    Interceptor.attach(impl, {
        onEnter: function(args) {
            console.log('\\n[!] WARNING: Insecure deserialization detected!');
            console.log('[!] NSKeyedUnarchiver +unarchiveObjectWithData: (DEPRECATED)');

            var data = new ObjC.Object(args[2]);
            console.log('  Data length:', data.length());
            console.log('  Data preview:', logDataPreview(args[2]));
            console.log('  Data format:', detectDataFormat(args[2]));

            console.log('\\n[!] SECURITY RISK: No class validation!');
            console.log('[!] This allows arbitrary object instantiation (potential RCE)');

            var mainModule = getMainAppModule();
            console.log('  Backtrace:');
            console.log(formatBacktrace(this.context, mainModule, 8));
        },
        onLeave: function(retval) {
            if (!retval.isNull()) {
                var obj = new ObjC.Object(retval);
                console.log('  => Deserialized object:', obj.$className, obj);
            }
        }
    });
});
""")

    # Hook NSKeyedUnarchiver +unarchivedObjectOfClass:fromData:error: (secure)
    hooks.append("""
// Hook: NSKeyedUnarchiver +unarchivedObjectOfClass:fromData:error: (Secure API)
hookObjCMethod('NSKeyedUnarchiver', '+ unarchivedObjectOfClass:fromData:error:', function(impl) {
    Interceptor.attach(impl, {
        onEnter: function(args) {
            console.log('\\n[+] Secure deserialization (with class validation)');
            console.log('[+] NSKeyedUnarchiver +unarchivedObjectOfClass:fromData:error:');

            var cls = new ObjC.Object(args[2]);
            console.log('  Allowed class:', cls);

            var data = new ObjC.Object(args[3]);
            console.log('  Data length:', data.length());
            console.log('  Data format:', detectDataFormat(args[3]));

            var mainModule = getMainAppModule();
            console.log('  Backtrace:');
            console.log(formatBacktrace(this.context, mainModule, 5));
        },
        onLeave: function(retval) {
            if (!retval.isNull()) {
                var obj = new ObjC.Object(retval);
                console.log('  => Deserialized:', obj.$className);
            }
        }
    });
});
""")

    # Hook NSKeyedUnarchiver -initForReadingFromData:error:
    hooks.append("""
// Hook: NSKeyedUnarchiver -initForReadingFromData:error:
hookObjCMethod('NSKeyedUnarchiver', '- initForReadingFromData:error:', function(impl) {
    Interceptor.attach(impl, {
        onEnter: function(args) {
            console.log('\\n[*] NSKeyedUnarchiver initialization');
            console.log('[*] -initForReadingFromData:error:');

            this.unarchiver = args[0];

            var data = new ObjC.Object(args[2]);
            console.log('  Data length:', data.length());
            console.log('  Data format:', detectDataFormat(args[2]));

            // Track this unarchiver
            unarchiverSecureCodingState[args[0]] = 'unknown';
            console.log('  [!] Watch for setRequiresSecureCoding: call');
        },
        onLeave: function(retval) {
            if (!retval.isNull()) {
                console.log('  => Unarchiver created:', retval);
            }
        }
    });
});
""")

    # Hook NSKeyedUnarchiver -setRequiresSecureCoding:
    hooks.append("""
// Hook: NSKeyedUnarchiver -setRequiresSecureCoding:
hookObjCMethod('NSKeyedUnarchiver', '- setRequiresSecureCoding:', function(impl) {
    Interceptor.attach(impl, {
        onEnter: function(args) {
            var value = args[2].toInt32();
            var valueStr = value ? 'YES' : 'NO';

            if (value === 0) {
                console.log('\\n[!] CRITICAL: Disabling secure coding!');
                console.log('[!] NSKeyedUnarchiver -setRequiresSecureCoding:NO');
                console.log('[!] This disables ALL deserialization security checks!');
            } else {
                console.log('\\n[+] Enabling secure coding');
                console.log('[+] NSKeyedUnarchiver -setRequiresSecureCoding:YES');
            }

            console.log('  Unarchiver:', args[0]);
            console.log('  Value:', valueStr);

            // Update tracking
            unarchiverSecureCodingState[args[0]] = value ? 'secure' : 'INSECURE';

            var mainModule = getMainAppModule();
            console.log('  Backtrace:');
            console.log(formatBacktrace(this.context, mainModule, 5));
        }
    });
});
""")

    # Hook NSCoder -decodeObjectForKey: (insecure variant)
    hooks.append("""
// Hook: NSCoder -decodeObjectForKey: (No class validation)
hookObjCMethod('NSCoder', '- decodeObjectForKey:', function(impl) {
    Interceptor.attach(impl, {
        onEnter: function(args) {
            var key = new ObjC.Object(args[2]);

            // Only log first few to avoid spam
            if (Math.random() < 0.1) {  // Sample 10% of calls
                console.log('\\n[*] NSCoder -decodeObjectForKey: (no class validation)');
                console.log('  Key:', key);
                console.log('  Coder:', args[0]);

                // Check if this coder requires secure coding
                var state = unarchiverSecureCodingState[args[0]];
                if (state === 'INSECURE') {
                    console.log('  [!] WARNING: Coder has secure coding DISABLED');
                }
            }

            this.key = key.toString();
        },
        onLeave: function(retval) {
            if (!retval.isNull() && Math.random() < 0.1) {
                var obj = new ObjC.Object(retval);
                console.log('  => Decoded [' + this.key + ']:', obj.$className);
            }
        }
    });
});
""")

    return "\n".join(hooks)


def generate_deserialization_script(binary_name: str = "unknown") -> str:
    """
    Generate a complete Frida script for deserialization monitoring.

    Args:
        binary_name: Name of the target binary/application

    Returns:
        Complete Frida script with all deserialization hooks
    """
    hooks = generate_deserialization_hooks(binary_name)

    # Split hooks into individual hook strings
    hook_list = hooks.split("\n\n")
    hook_list = [h for h in hook_list if h.strip()]

    return combine_hooks(
        hook_list,
        category="deserialization",
        binary_name=binary_name,
        include_constants=False,  # We don't need crypto constants
        extra_prelude=DESERIALIZATION_HELPERS,
        use_lazy_loading=True
    )


__all__ = ["generate_deserialization_script"]