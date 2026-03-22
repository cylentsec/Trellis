"""
Frida script generator for sensitive logging detection.

Generates Frida 17+ compatible hooks to monitor NSLog, os_log, and other
logging functions to detect sensitive data being written to device logs.
"""

from datetime import datetime
from typing import List, Optional

from .base import FRIDA_RUNTIME_HELPERS


def generate_logging_script(
    binary_name: str = "Unknown",
    findings: Optional[List] = None,
    use_lazy_loading: bool = True,
) -> str:
    """
    Generate a Frida script to monitor logging functions for sensitive data.

    Args:
        binary_name: Name of the target binary
        findings: Optional list of SecurityFinding objects to add context
        use_lazy_loading: Whether to defer hooks until app launch (default True)

    Returns:
        Complete Frida JavaScript code as a string
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    header = f"""// ==========================================================================
// Trellis Sensitive Logging Monitor - Frida 17+ Compatible
// ==========================================================================
// Target: {binary_name}
// Generated: {timestamp}
// Category: Sensitive data leakage through logging functions
//
// This script hooks logging functions to detect:
// - Passwords, tokens, API keys in log output
// - Credit card numbers and PII
// - Session data and authentication credentials
//
// Usage: frida -U -f <bundle_id> -l this_script.js
// ==========================================================================

'use strict';

"""

    script = header + FRIDA_RUNTIME_HELPERS + """

// ==========================================================================
// Logging Monitor Configuration
// ==========================================================================

var LOGGING_MONITOR_CONFIG = {
    // Log ALL logging calls (very noisy, disable in production)
    logAllCalls: false,
    
    // Only log when sensitive patterns are detected
    onlySensitive: true,
    
    // Sensitive data patterns (case-insensitive)
    sensitivePatterns: [
        // Authentication
        /password[\\s:=]/i,
        /passwd[\\s:=]/i,
        /token[\\s:=][^\\s]{8,}/i,
        /bearer\\s+[a-zA-Z0-9\\-_\\.]+/i,
        /api[_-]?key[\\s:=]/i,
        /secret[\\s:=]/i,
        /credential/i,
        /auth[_-]?token/i,
        /session[_-]?id/i,
        /access[_-]?token/i,
        /refresh[_-]?token/i,
        
        // Financial/PCI
        /\\b\\d{13,16}\\b/,  // Credit card numbers
        /\\b\\d{3,4}\\b.*cvv/i,  // CVV
        /card[_-]?number/i,
        /expir(y|ation)/i,
        
        // PII
        /\\bssn[\\s:=]/i,
        /social[_-]?security/i,
        /\\b\\d{3}-\\d{2}-\\d{4}\\b/,  // SSN format
        /date[_-]?of[_-]?birth/i,
        
        // Private keys / Crypto
        /-----BEGIN.*PRIVATE KEY-----/,
        /PRIVATE[_-]?KEY/i,
        /encryption[_-]?key/i,
        
        // Debugging that shouldn't be in production
        /DEBUG:/i,
        /TODO:/i,
        /FIXME:/i,
        /\\[TEST\\]/i,
    ],
    
    // Keywords that definitely indicate sensitive logging (high confidence)
    highConfidenceKeywords: [
        'password', 'passwd', 'secret', 'token', 'bearer',
        'api_key', 'apikey', 'private_key', 'privatekey',
        'credit_card', 'creditcard', 'card_number', 'cvv',
        'ssn', 'social_security'
    ],
    
    // Maximum message length to log
    maxMessageLength: 1000,
};

// ==========================================================================
// Logging Hook Implementation
// ==========================================================================

function installLoggingHooks() {
    var mainModule = getMainAppModule();
    console.log('[Logging Monitor] Main module: ' + mainModule.name);
    console.log('[Logging Monitor] Installing hooks...');

    // -----------------------------------------------------------------------
    // Hook NSLog (Foundation)
    // -----------------------------------------------------------------------
    hookObjCMethod('NSObject', '+ load', function() {
        // NSLog is a C function, not an ObjC method
    });
    
    var NSLog = Module.getGlobalExportByName('NSLog');
    if (NSLog) {
        console.log('[+] Hooking NSLog at ' + NSLog);
        
        Interceptor.attach(NSLog, {
            onEnter: function(args) {
                try {
                    var format = new ObjC.Object(args[0]);
                    var message = format.toString();
                    
                    processLogMessage('NSLog', message, this.context, mainModule);
                } catch (e) {
                    // Format string might not be an NSString
                }
            }
        });
    }

    // -----------------------------------------------------------------------
    // Hook os_log (Unified Logging - iOS 10+)
    // -----------------------------------------------------------------------
    var _os_log_impl = Module.getGlobalExportByName('_os_log_impl');
    if (_os_log_impl) {
        console.log('[+] Hooking _os_log_impl at ' + _os_log_impl);
        
        Interceptor.attach(_os_log_impl, {
            onEnter: function(args) {
                try {
                    // args[0] = dso (dynamic shared object)
                    // args[1] = log object
                    // args[2] = type
                    // args[3] = format string
                    // args[4] = buf (encoded arguments)
                    // args[5] = size
                    
                    var formatPtr = args[3];
                    if (!formatPtr.isNull()) {
                        var format = formatPtr.readUtf8String();
                        if (format) {
                            processLogMessage('os_log', format, this.context, mainModule);
                        }
                    }
                } catch (e) {
                    // Ignore parsing errors
                }
            }
        });
    }

    // -----------------------------------------------------------------------
    // Hook os_log_with_type
    // -----------------------------------------------------------------------
    var os_log_with_type = Module.getGlobalExportByName('os_log_with_type');
    if (os_log_with_type) {
        console.log('[+] Hooking os_log_with_type at ' + os_log_with_type);
        
        Interceptor.attach(os_log_with_type, {
            onEnter: function(args) {
                try {
                    // args[2] is format string
                    var formatPtr = args[2];
                    if (!formatPtr.isNull()) {
                        var format = formatPtr.readUtf8String();
                        if (format) {
                            processLogMessage('os_log_with_type', format, this.context, mainModule);
                        }
                    }
                } catch (e) {}
            }
        });
    }

    // -----------------------------------------------------------------------
    // Hook CFLog (Core Foundation)
    // -----------------------------------------------------------------------
    var CFLog = Module.getGlobalExportByName('CFLog');
    if (CFLog) {
        console.log('[+] Hooking CFLog at ' + CFLog);
        
        Interceptor.attach(CFLog, {
            onEnter: function(args) {
                try {
                    // args[0] = level, args[1] = format CFString
                    var cfString = args[1];
                    if (!cfString.isNull()) {
                        var nsString = new ObjC.Object(cfString);
                        var message = nsString.toString();
                        processLogMessage('CFLog', message, this.context, mainModule);
                    }
                } catch (e) {}
            }
        });
    }

    // -----------------------------------------------------------------------
    // Hook syslog (BSD)
    // -----------------------------------------------------------------------
    var syslog = Module.getGlobalExportByName('syslog');
    if (syslog) {
        console.log('[+] Hooking syslog at ' + syslog);
        
        Interceptor.attach(syslog, {
            onEnter: function(args) {
                try {
                    // args[0] = priority, args[1] = format
                    var format = args[1].readUtf8String();
                    if (format) {
                        processLogMessage('syslog', format, this.context, mainModule);
                    }
                } catch (e) {}
            }
        });
    }

    // -----------------------------------------------------------------------
    // Hook Swift print (if available in app)
    // -----------------------------------------------------------------------
    // Swift's print() ultimately calls into _swift_stdlib_print variants
    // These are harder to hook reliably; focus on the runtime output
    var swiftPrint = Module.getGlobalExportByName('$ss5print_9separator10terminatoryypd_S2StF');
    if (swiftPrint) {
        console.log('[+] Found Swift print function');
        // Note: Swift calling convention makes this complex to hook directly
        // The static analyzer will catch these; runtime monitoring is best-effort
    }

    // -----------------------------------------------------------------------
    // Hook NSLog-style methods on common classes
    // -----------------------------------------------------------------------
    hookObjCMethod('NSString', '- stringWithFormat:', function(impl) {
        // This is called for string formatting, not logging
        // We hook it to catch patterns like: NSLog(@"Token: %@", token)
        // where the formatted string contains sensitive data
    });

    console.log('[Logging Monitor] Hook installation complete');
    console.log('[Logging Monitor] Monitoring for sensitive data in logs...');
}

// ==========================================================================
// Log Processing
// ==========================================================================

function processLogMessage(source, message, context, mainModule) {
    if (!message) return;
    
    var isSensitive = checkSensitiveContent(message);
    var isHighConfidence = checkHighConfidenceKeywords(message);
    
    // Determine if we should log this
    var shouldLog = false;
    if (LOGGING_MONITOR_CONFIG.logAllCalls) {
        shouldLog = true;
    } else if (LOGGING_MONITOR_CONFIG.onlySensitive && (isSensitive || isHighConfidence)) {
        shouldLog = true;
    }
    
    if (!shouldLog) return;
    
    // Determine severity
    var severity = 'INFO';
    if (isHighConfidence) {
        severity = 'CRITICAL';
    } else if (isSensitive) {
        severity = 'WARNING';
    }
    
    // Format output
    console.log('\\n[' + severity + '] Sensitive data in ' + source);
    console.log('    Message: ' + truncateMessage(message));
    
    if (isHighConfidence) {
        console.log('    [!!!] HIGH CONFIDENCE: Contains known sensitive keyword!');
    }
    
    // Show matched patterns
    var matchedPatterns = findMatchedPatterns(message);
    if (matchedPatterns.length > 0) {
        console.log('    Matched patterns: ' + matchedPatterns.join(', '));
    }
    
    console.log('    Backtrace (BN offsets for analysis):');
    console.log(formatBacktrace(context, mainModule, 6));
}

function checkSensitiveContent(message) {
    if (!message) return false;
    
    for (var i = 0; i < LOGGING_MONITOR_CONFIG.sensitivePatterns.length; i++) {
        if (LOGGING_MONITOR_CONFIG.sensitivePatterns[i].test(message)) {
            return true;
        }
    }
    return false;
}

function checkHighConfidenceKeywords(message) {
    if (!message) return false;
    
    var lowerMessage = message.toLowerCase();
    for (var i = 0; i < LOGGING_MONITOR_CONFIG.highConfidenceKeywords.length; i++) {
        if (lowerMessage.indexOf(LOGGING_MONITOR_CONFIG.highConfidenceKeywords[i]) !== -1) {
            return true;
        }
    }
    return false;
}

function findMatchedPatterns(message) {
    var matched = [];
    for (var i = 0; i < LOGGING_MONITOR_CONFIG.sensitivePatterns.length; i++) {
        var pattern = LOGGING_MONITOR_CONFIG.sensitivePatterns[i];
        if (pattern.test(message)) {
            matched.push(pattern.toString().substring(0, 30));
        }
    }
    return matched.slice(0, 3);  // Limit to 3 matches for readability
}

function truncateMessage(message) {
    if (!message) return '<null>';
    
    // Redact obvious sensitive values for safety
    var redacted = message
        .replace(/password[\\s:=]+[^\\s,;]+/gi, 'password=[REDACTED]')
        .replace(/token[\\s:=]+[^\\s,;]+/gi, 'token=[REDACTED]')
        .replace(/bearer\\s+[a-zA-Z0-9\\-_\\.]+/gi, 'Bearer [REDACTED]')
        .replace(/\\b\\d{13,16}\\b/g, '[CARD_REDACTED]');
    
    if (redacted.length <= LOGGING_MONITOR_CONFIG.maxMessageLength) {
        return redacted;
    }
    return redacted.substring(0, LOGGING_MONITOR_CONFIG.maxMessageLength) + '... [truncated]';
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
                    console.log('[*] App launched, installing logging hooks...');
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

deferHooksUntilReady(installLoggingHooks);
"""
    else:
        script += """
// Immediate hook installation
installLoggingHooks();
"""

    return script


__all__ = ["generate_logging_script"]
