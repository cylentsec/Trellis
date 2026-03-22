"""
Frida script generator for insecure data storage hooks.

This module provides specialized hook generation for data storage functions,
including NSUserDefaults, file operations, SQLite, and NSKeyedArchiver.
It highlights when sensitive-looking keys are accessed.

Example usage:
    >>> from trellis.generators.frida.storage import generate_storage_script
    >>>
    >>> # Generate hooks for all storage functions
    >>> script = generate_storage_script("MyApp")
    >>> with open("storage_hooks.js", "w") as f:
    ...     f.write(script)
"""

from typing import Optional

from ...signatures import load_category
from .base import combine_hooks


# Storage-specific constants and helper functions
STORAGE_HELPERS = """
// Storage Security Helpers

// Sensitive key patterns to highlight
const SENSITIVE_PATTERNS = [
    'token', 'auth', 'password', 'credential', 'secret', 'apikey', 'api_key',
    'access_token', 'refresh_token', 'session', 'jwt', 'bearer',
    'key', 'encryption', 'decrypt', 'private_key', 'public_key', 'certificate',
    'cert', 'pin', 'hmac', 'trusted', 'allowed', 'whitelist', 'allowlist',
    'blocklist', 'blacklist', 'domain', 'host', 'endpoint', 'url',
    'ssn', 'social_security', 'credit_card', 'card_number', 'cvv', 'account'
];

// Critical patterns that should NEVER be in UserDefaults
const CRITICAL_PATTERNS = [
    'password', 'secret', 'private_key', 'apikey', 'api_key',
    'access_token', 'refresh_token', 'bearer', 'jwt',
    'credit_card', 'card_number', 'cvv', 'ssn'
];

// Check if a key name looks sensitive
function isSensitiveKey(key) {
    if (!key) return false;
    const keyLower = key.toLowerCase();

    for (const pattern of CRITICAL_PATTERNS) {
        if (keyLower.includes(pattern)) {
            return 'CRITICAL';
        }
    }

    for (const pattern of SENSITIVE_PATTERNS) {
        if (keyLower.includes(pattern)) {
            return 'SENSITIVE';
        }
    }

    return false;
}

// Format key with security highlighting
function formatKey(key) {
    const sensitivity = isSensitiveKey(key);
    if (sensitivity === 'CRITICAL') {
        return '🔴 CRITICAL KEY: ' + key;
    } else if (sensitivity === 'SENSITIVE') {
        return '⚠️  SENSITIVE KEY: ' + key;
    }
    return key;
}

// Safe string conversion for various types
function safeString(obj) {
    if (!obj) return 'nil';
    try {
        if (obj.class) {
            const className = obj.class().toString();
            if (className === '__NSCFString' || className === 'NSString') {
                return obj.toString();
            } else if (className === '__NSCFNumber' || className === 'NSNumber') {
                return obj.toString();
            } else if (className === '__NSCFBoolean') {
                return obj.boolValue() ? 'YES' : 'NO';
            } else if (className === '__NSCFData' || className === 'NSData') {
                return '<NSData: ' + obj.length() + ' bytes>';
            } else if (className === '__NSCFArray' || className === 'NSArray') {
                return '<NSArray: ' + obj.count() + ' items>';
            } else if (className === '__NSCFDictionary' || className === 'NSDictionary') {
                return '<NSDictionary: ' + obj.count() + ' items>';
            }
            return '<' + className + '>';
        }
        return obj.toString();
    } catch (e) {
        return '<conversion failed>';
    }
}
"""


def _generate_userdefaults_hooks() -> str:
    """Generate hooks for NSUserDefaults methods."""
    return """
// NSUserDefaults Hooks

// Hook setObject:forKey:
if (ObjC.available) {
    const NSUserDefaults = ObjC.classes.NSUserDefaults;
    if (NSUserDefaults && NSUserDefaults['- setObject:forKey:'] && NSUserDefaults['- setObject:forKey:'].implementation) {
        Interceptor.attach(NSUserDefaults['- setObject:forKey:'].implementation, {
            onEnter: function(args) {
                const key = ObjC.Object(args[3]);
                const value = ObjC.Object(args[2]);
                const keyStr = key ? key.toString() : 'nil';
                const valueStr = safeString(value);

                console.log('\\n[NSUserDefaults setObject:forKey:]');
                console.log('  Key: ' + formatKey(keyStr));
                console.log('  Value: ' + valueStr);

                const sensitivity = isSensitiveKey(keyStr);
                if (sensitivity) {
                    console.log('  ⚠️  WARNING: ' + sensitivity + ' data being stored in plaintext!');
                }
            }
        });
    }

    // Hook objectForKey:
    if (NSUserDefaults && NSUserDefaults['- objectForKey:'] && NSUserDefaults['- objectForKey:'].implementation) {
        Interceptor.attach(NSUserDefaults['- objectForKey:'].implementation, {
            onEnter: function(args) {
                const key = ObjC.Object(args[2]);
                const keyStr = key ? key.toString() : 'nil';
                this.key = keyStr;
            },
            onLeave: function(retval) {
                if (retval.isNull()) return;

                const value = ObjC.Object(retval);
                const valueStr = safeString(value);

                console.log('\\n[NSUserDefaults objectForKey:]');
                console.log('  Key: ' + formatKey(this.key));
                console.log('  Retrieved: ' + valueStr);

                const sensitivity = isSensitiveKey(this.key);
                if (sensitivity) {
                    console.log('  ⚠️  WARNING: ' + sensitivity + ' data being read from plaintext!');
                }
            }
        });
    }

    // Hook setBool:forKey:
    if (NSUserDefaults && NSUserDefaults['- setBool:forKey:'] && NSUserDefaults['- setBool:forKey:'].implementation) {
        Interceptor.attach(NSUserDefaults['- setBool:forKey:'].implementation, {
            onEnter: function(args) {
                const key = ObjC.Object(args[3]);
                const value = args[2];
                const keyStr = key ? key.toString() : 'nil';
                const boolStr = value ? 'YES' : 'NO';

                console.log('\\n[NSUserDefaults setBool:forKey:]');
                console.log('  Key: ' + formatKey(keyStr));
                console.log('  Value: ' + boolStr);

                // Check for security policy keys
                const keyLower = keyStr.toLowerCase();
                if (keyLower.includes('jailbreak') || keyLower.includes('debug') ||
                    keyLower.includes('skip') || keyLower.includes('bypass')) {
                    console.log('  🔴 SECURITY POLICY KEY DETECTED!');
                }
            }
        });
    }

    // Hook boolForKey:
    if (NSUserDefaults && NSUserDefaults['- boolForKey:'] && NSUserDefaults['- boolForKey:'].implementation) {
        Interceptor.attach(NSUserDefaults['- boolForKey:'].implementation, {
            onEnter: function(args) {
                const key = ObjC.Object(args[2]);
                const keyStr = key ? key.toString() : 'nil';
                this.key = keyStr;
            },
            onLeave: function(retval) {
                const boolStr = retval ? 'YES' : 'NO';

                console.log('\\n[NSUserDefaults boolForKey:]');
                console.log('  Key: ' + formatKey(this.key));
                console.log('  Retrieved: ' + boolStr);

                // Check for security policy keys
                const keyLower = this.key.toLowerCase();
                if (keyLower.includes('jailbreak') || keyLower.includes('debug') ||
                    keyLower.includes('skip') || keyLower.includes('bypass')) {
                    console.log('  🔴 SECURITY POLICY CHECK!');
                }
            }
        });
    }
}
"""


def _generate_file_hooks() -> str:
    """Generate hooks for file operations."""
    return """
// File Operation Hooks

if (ObjC.available) {
    // Hook writeToFile:atomically: (NSDictionary and NSArray)
    const classes = ['NSDictionary', 'NSArray'];

    for (const className of classes) {
        const cls = ObjC.classes[className];
        if (cls && cls['- writeToFile:atomically:'] && cls['- writeToFile:atomically:'].implementation) {
            Interceptor.attach(cls['- writeToFile:atomically:'].implementation, {
                onEnter: function(args) {
                    const path = ObjC.Object(args[2]);
                    const atomic = args[3];
                    const pathStr = path ? path.toString() : 'nil';

                    console.log('\\n[' + className + ' writeToFile:atomically:]');
                    console.log('  Path: ' + pathStr);
                    console.log('  Atomic: ' + (atomic ? 'YES' : 'NO'));

                    // Check for insecure locations
                    if (pathStr.includes('/Documents') || pathStr.includes('/tmp') ||
                        pathStr.includes('/Library/Caches')) {
                        console.log('  ⚠️  WARNING: Writing to accessible location!');
                    }
                }
            });
        }

        // Hook initWithContentsOfFile:
        if (cls && cls['- initWithContentsOfFile:'] && cls['- initWithContentsOfFile:'].implementation) {
            Interceptor.attach(cls['- initWithContentsOfFile:'].implementation, {
                onEnter: function(args) {
                    const path = ObjC.Object(args[2]);
                    const pathStr = path ? path.toString() : 'nil';

                    console.log('\\n[' + className + ' initWithContentsOfFile:]');
                    console.log('  Path: ' + pathStr);
                    console.log('  ⚠️  No integrity verification on file contents');
                }
            });
        }
    }
}
"""


def _generate_archiver_hooks() -> str:
    """Generate hooks for NSKeyedArchiver methods."""
    return """
// NSKeyedArchiver Hooks

if (ObjC.available) {
    const NSKeyedArchiver = ObjC.classes.NSKeyedArchiver;

    // Hook deprecated archivedDataWithRootObject:
    if (NSKeyedArchiver && NSKeyedArchiver['+ archivedDataWithRootObject:'] && NSKeyedArchiver['+ archivedDataWithRootObject:'].implementation) {
        Interceptor.attach(NSKeyedArchiver['+ archivedDataWithRootObject:'].implementation, {
            onEnter: function(args) {
                const obj = ObjC.Object(args[2]);
                const objClass = obj ? obj.class().toString() : 'nil';

                console.log('\\n[NSKeyedArchiver archivedDataWithRootObject:] (DEPRECATED)');
                console.log('  Object Class: ' + objClass);
                console.log('  🔴 WARNING: Using deprecated archiver without secure coding!');
                console.log('  Vulnerable to deserialization attacks');
            }
        });
    }

    // Hook secure version
    if (NSKeyedArchiver && NSKeyedArchiver['+ archivedDataWithRootObject:requiringSecureCoding:error:'] && NSKeyedArchiver['+ archivedDataWithRootObject:requiringSecureCoding:error:'].implementation) {
        Interceptor.attach(NSKeyedArchiver['+ archivedDataWithRootObject:requiringSecureCoding:error:'].implementation, {
            onEnter: function(args) {
                const obj = ObjC.Object(args[2]);
                const secureCoding = args[3];
                const objClass = obj ? obj.class().toString() : 'nil';

                console.log('\\n[NSKeyedArchiver archivedDataWithRootObject:requiringSecureCoding:error:]');
                console.log('  Object Class: ' + objClass);
                console.log('  Secure Coding: ' + (secureCoding ? 'YES' : 'NO'));

                if (!secureCoding) {
                    console.log('  ⚠️  WARNING: Secure coding disabled - vulnerable to attacks!');
                }
            }
        });
    }
}
"""


def _generate_sqlite_hooks() -> str:
    """Generate hooks for SQLite operations."""
    return """
// SQLite Hooks

// Hook sqlite3_open
const sqlite3_open = Module.findExportByName('libsqlite3.dylib', 'sqlite3_open');
if (sqlite3_open) {
    Interceptor.attach(sqlite3_open, {
        onEnter: function(args) {
            const filename = args[0].readCString();

            console.log('\\n[sqlite3_open]');
            console.log('  Database: ' + filename);

            // Check for insecure locations
            if (filename && (filename.includes('/Documents') ||
                filename.includes('/Library/Caches'))) {
                console.log('  🔴 WARNING: Unencrypted database in accessible location!');
                console.log('  Databases in these locations are included in backups');
            } else {
                console.log('  ⚠️  SQLite databases are unencrypted by default');
            }
        }
    });
}

// Hook sqlite3_exec
const sqlite3_exec = Module.findExportByName('libsqlite3.dylib', 'sqlite3_exec');
if (sqlite3_exec) {
    Interceptor.attach(sqlite3_exec, {
        onEnter: function(args) {
            const sql = args[1].readCString();

            console.log('\\n[sqlite3_exec]');
            console.log('  🔴 DIRECT SQL EXECUTION - High injection risk!');
            if (sql) {
                // Truncate long queries
                const preview = sql.length > 200 ? sql.substring(0, 200) + '...' : sql;
                console.log('  SQL: ' + preview);

                // Check for concatenation patterns
                if (sql.includes('||') || sql.includes('" +') || sql.includes("' +")) {
                    console.log('  🔴 STRING CONCATENATION DETECTED - SQL INJECTION RISK!');
                }
            }
        }
    });
}

// Hook sqlite3_prepare_v2
const sqlite3_prepare_v2 = Module.findExportByName('libsqlite3.dylib', 'sqlite3_prepare_v2');
if (sqlite3_prepare_v2) {
    Interceptor.attach(sqlite3_prepare_v2, {
        onEnter: function(args) {
            const sql = args[1].readCString();

            console.log('\\n[sqlite3_prepare_v2]');
            if (sql) {
                // Truncate long queries
                const preview = sql.length > 200 ? sql.substring(0, 200) + '...' : sql;
                console.log('  SQL: ' + preview);

                // Check for sensitive data patterns
                const sqlLower = sql.toLowerCase();
                for (const pattern of CRITICAL_PATTERNS) {
                    if (sqlLower.includes(pattern)) {
                        console.log('  ⚠️  Query references sensitive data: ' + pattern);
                        break;
                    }
                }

                // Check for concatenation
                if (sql.includes('||') || sql.includes('" +') || sql.includes("' +")) {
                    console.log('  ⚠️  Possible string concatenation - use parameter binding!');
                }
            }
        }
    });
}
"""


def generate_storage_script(binary_name: str = "unknown") -> str:
    """
    Generate a complete Frida script for hooking storage functions.

    Args:
        binary_name: Name of the target binary for the script header

    Returns:
        Complete Frida script as a string
    """
    # Load function signatures (though we're using custom hooks here)
    try:
        category = load_category("insecure_storage")
    except:
        # If signatures aren't loaded, we can still generate hooks
        pass

    # Build the complete script
    hooks = [
        _generate_userdefaults_hooks(),
        _generate_file_hooks(),
        _generate_archiver_hooks(),
        _generate_sqlite_hooks(),
    ]

    # Combine all hooks into a complete script
    return combine_hooks(
        hooks=hooks,
        category="insecure_storage",
        binary_name=binary_name,
        include_constants=False,
        include_runtime_helpers=True,
        extra_prelude=STORAGE_HELPERS
    )


# Export public API
__all__ = ["generate_storage_script"]