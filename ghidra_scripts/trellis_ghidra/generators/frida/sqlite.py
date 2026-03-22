"""
Frida script generator for SQLite monitoring.

Generates Frida 17+ compatible hooks to monitor SQLite operations,
capture SQL statements, and detect potential injection attacks at runtime.
"""

from datetime import datetime
from typing import List, Optional

from .base import FRIDA_RUNTIME_HELPERS


def generate_sqlite_script(
    binary_name: str = "Unknown",
    findings: Optional[List] = None,
    use_lazy_loading: bool = True,
) -> str:
    """
    Generate a Frida script to monitor SQLite operations.

    Args:
        binary_name: Name of the target binary
        findings: Optional list of SecurityFinding objects to add context
        use_lazy_loading: Whether to defer hooks until app launch (default True)

    Returns:
        Complete Frida JavaScript code as a string
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    header = f"""// ==========================================================================
// Trellis SQLite Monitor - Frida 17+ Compatible
// ==========================================================================
// Target: {binary_name}
// Generated: {timestamp}
// Category: SQLite injection detection and SQL statement monitoring
//
// This script hooks SQLite functions to:
// - Capture all SQL statements executed
// - Detect potential SQL injection patterns
// - Log backtraces for identified call sites
//
// Usage: frida -U -f <bundle_id> -l this_script.js
// ==========================================================================

'use strict';

"""

    script = header + FRIDA_RUNTIME_HELPERS + """

// ==========================================================================
// SQLite Monitoring Configuration
// ==========================================================================

var SQLITE_MONITOR_CONFIG = {
    // Log all SQL statements (can be noisy)
    logAllStatements: true,
    
    // Highlight statements containing these patterns
    suspiciousPatterns: [
        /OR\s+1\s*=\s*1/i,
        /OR\s+'[^']*'\s*=\s*'[^']*'/i,
        /UNION\s+SELECT/i,
        /--\s*$/,
        /;\s*DROP\s+/i,
        /;\s*DELETE\s+/i,
        /'\s*OR\s+'/i,
    ],
    
    // Keywords that suggest sensitive queries
    sensitiveKeywords: [
        'password', 'token', 'secret', 'credential',
        'api_key', 'session', 'auth'
    ],
    
    // Maximum SQL length to log (truncate longer)
    maxSqlLength: 500,
};

// ==========================================================================
// SQLite Hook Implementation
// ==========================================================================

function installSQLiteHooks() {
    var mainModule = getMainAppModule();
    console.log('[SQLite Monitor] Main module: ' + mainModule.name);
    console.log('[SQLite Monitor] Installing hooks...');

    // -----------------------------------------------------------------------
    // Hook sqlite3_exec - Direct SQL execution
    // -----------------------------------------------------------------------
    var sqlite3_exec = Module.getGlobalExportByName('sqlite3_exec');
    if (sqlite3_exec) {
        console.log('[+] Hooking sqlite3_exec at ' + sqlite3_exec);
        
        Interceptor.attach(sqlite3_exec, {
            onEnter: function(args) {
                this.db = args[0];
                this.sqlPtr = args[1];
                this.sql = args[1].readUtf8String();
                
                var isSuspicious = checkSuspiciousSQL(this.sql);
                var isSensitive = checkSensitiveSQL(this.sql);
                
                if (SQLITE_MONITOR_CONFIG.logAllStatements || isSuspicious || isSensitive) {
                    var prefix = isSuspicious ? '[!!! SUSPICIOUS]' : (isSensitive ? '[SENSITIVE]' : '[SQL]');
                    console.log('\\n' + prefix + ' sqlite3_exec');
                    console.log('    SQL: ' + truncateSQL(this.sql));
                    
                    if (isSuspicious) {
                        console.log('    [!!!] Potential SQL injection detected!');
                    }
                    
                    console.log('    Backtrace (BN offsets for cross-reference):');
                    console.log(formatBacktrace(this.context, mainModule, 6));
                }
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) {
                    console.log('    [ERROR] sqlite3_exec returned: ' + retval.toInt32());
                }
            }
        });
    } else {
        console.log('[-] sqlite3_exec not found (app may not use SQLite)');
    }

    // -----------------------------------------------------------------------
    // Hook sqlite3_prepare_v2 - Prepared statement creation
    // -----------------------------------------------------------------------
    var sqlite3_prepare_v2 = Module.getGlobalExportByName('sqlite3_prepare_v2');
    if (sqlite3_prepare_v2) {
        console.log('[+] Hooking sqlite3_prepare_v2 at ' + sqlite3_prepare_v2);
        
        Interceptor.attach(sqlite3_prepare_v2, {
            onEnter: function(args) {
                this.db = args[0];
                this.sqlPtr = args[1];
                this.sql = args[1].readUtf8String();
                
                var isSuspicious = checkSuspiciousSQL(this.sql);
                var isSensitive = checkSensitiveSQL(this.sql);
                
                // Prepared statements with ? are safe; flag if no placeholders but dynamic-looking
                var hasPlaceholders = this.sql.indexOf('?') !== -1;
                var looksParameterized = hasPlaceholders || this.sql.indexOf(':') !== -1;
                
                if (SQLITE_MONITOR_CONFIG.logAllStatements || isSuspicious || isSensitive) {
                    var prefix = isSuspicious ? '[!!! SUSPICIOUS]' : (isSensitive ? '[SENSITIVE]' : '[SQL]');
                    console.log('\\n' + prefix + ' sqlite3_prepare_v2');
                    console.log('    SQL: ' + truncateSQL(this.sql));
                    console.log('    Parameterized: ' + (looksParameterized ? 'Yes (safe)' : 'No (review needed)'));
                    
                    if (isSuspicious) {
                        console.log('    [!!!] Potential SQL injection detected!');
                        console.log('    Backtrace (BN offsets for cross-reference):');
                        console.log(formatBacktrace(this.context, mainModule, 6));
                    }
                }
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) {
                    console.log('    [ERROR] sqlite3_prepare_v2 returned: ' + retval.toInt32());
                }
            }
        });
    }

    // -----------------------------------------------------------------------
    // Hook sqlite3_bind_text - Parameter binding (safe pattern)
    // -----------------------------------------------------------------------
    var sqlite3_bind_text = Module.getGlobalExportByName('sqlite3_bind_text');
    if (sqlite3_bind_text) {
        console.log('[+] Hooking sqlite3_bind_text at ' + sqlite3_bind_text);
        
        Interceptor.attach(sqlite3_bind_text, {
            onEnter: function(args) {
                var paramIndex = args[1].toInt32();
                var valuePtr = args[2];
                var value = valuePtr.isNull() ? '<NULL>' : valuePtr.readUtf8String();
                
                // Check if bound value looks like injection attempt
                var isSuspicious = checkSuspiciousSQL(value);
                
                if (isSuspicious) {
                    console.log('\\n[!!! SUSPICIOUS] sqlite3_bind_text');
                    console.log('    Parameter index: ' + paramIndex);
                    console.log('    Value: ' + truncateSQL(value));
                    console.log('    [!!!] Bound value contains suspicious pattern!');
                    console.log('    Backtrace:');
                    console.log(formatBacktrace(this.context, mainModule, 6));
                }
            }
        });
    }

    // -----------------------------------------------------------------------
    // Hook NSPredicate predicateWithFormat: (ObjC)
    // -----------------------------------------------------------------------
    hookObjCMethod('NSPredicate', '+ predicateWithFormat:', function(impl) {
        Interceptor.attach(impl, {
            onEnter: function(args) {
                var format = new ObjC.Object(args[2]);
                var formatStr = format.toString();
                
                var isSuspicious = checkSuspiciousSQL(formatStr);
                
                if (SQLITE_MONITOR_CONFIG.logAllStatements || isSuspicious) {
                    var prefix = isSuspicious ? '[!!! SUSPICIOUS]' : '[Predicate]';
                    console.log('\\n' + prefix + ' NSPredicate predicateWithFormat:');
                    console.log('    Format: ' + truncateSQL(formatStr));
                    
                    if (isSuspicious) {
                        console.log('    [!!!] Potential predicate injection!');
                        console.log('    Backtrace:');
                        console.log(formatBacktrace(this.context, mainModule, 6));
                    }
                }
            }
        });
    });

    console.log('[SQLite Monitor] Hook installation complete');
}

// ==========================================================================
// Helper Functions
// ==========================================================================

function checkSuspiciousSQL(sql) {
    if (!sql) return false;
    
    for (var i = 0; i < SQLITE_MONITOR_CONFIG.suspiciousPatterns.length; i++) {
        if (SQLITE_MONITOR_CONFIG.suspiciousPatterns[i].test(sql)) {
            return true;
        }
    }
    return false;
}

function checkSensitiveSQL(sql) {
    if (!sql) return false;
    
    var lowerSql = sql.toLowerCase();
    for (var i = 0; i < SQLITE_MONITOR_CONFIG.sensitiveKeywords.length; i++) {
        if (lowerSql.indexOf(SQLITE_MONITOR_CONFIG.sensitiveKeywords[i]) !== -1) {
            return true;
        }
    }
    return false;
}

function truncateSQL(sql) {
    if (!sql) return '<null>';
    if (sql.length <= SQLITE_MONITOR_CONFIG.maxSqlLength) {
        return sql;
    }
    return sql.substring(0, SQLITE_MONITOR_CONFIG.maxSqlLength) + '... [truncated]';
}

// ==========================================================================
// Script Entry Point
// ==========================================================================

"""

    if use_lazy_loading:
        script += """
// ==========================================================================
// Lazy Loading (Watchdog Prevention)
// ==========================================================================

function deferHooksUntilReady(installFn) {
    if (typeof ObjC !== 'undefined' && ObjC.available) {
        var NSNotificationCenter = ObjC.classes.NSNotificationCenter;
        var center = NSNotificationCenter.defaultCenter();
        center.addObserverForName_object_queue_usingBlock_(
            'UIApplicationDidFinishLaunchingNotification',
            null,
            null,
            new ObjC.Block({
                rettype: 'void',
                argTypes: ['object'],
                implementation: function(notification) {
                    console.log('[*] App launched, installing SQLite hooks...');
                    installFn();
                }
            })
        );
        
        setTimeout(function() {
            installFn();
        }, 2000);
    } else {
        installFn();
    }
}

deferHooksUntilReady(installSQLiteHooks);
"""
    else:
        script += """
// Immediate hook installation (may trigger watchdog on slow devices)
installSQLiteHooks();
"""

    return script


__all__ = ["generate_sqlite_script"]
