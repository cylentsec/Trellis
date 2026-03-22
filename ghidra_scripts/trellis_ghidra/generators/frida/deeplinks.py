"""
Frida script generator for deep link and URL scheme hooks.

This module provides specialized hook generation for deep link handlers,
URL scheme validation, and Universal Links processing. It tracks incoming
URLs, source applications, and how the app processes external links.

Example usage:
    >>> from trellis.generators.frida.deeplinks import generate_deeplinks_script
    >>>
    >>> # Generate hooks for deep link handlers
    >>> script = generate_deeplinks_script("MyApp")
    >>> with open("deeplink_hooks.js", "w") as f:
    ...     f.write(script)
"""

from .base import combine_hooks


# Deep link specific constants and helpers
DEEPLINK_CONSTANTS = """
// Deep Link / URL Scheme Constants

// URL validation helpers
function isValidURL(urlString) {
    try {
        if (typeof urlString === 'string') {
            return urlString.startsWith('http://') ||
                   urlString.startsWith('https://') ||
                   urlString.startsWith('file://') ||
                   urlString.indexOf('://') !== -1;
        }
        return false;
    } catch (e) {
        return false;
    }
}

// Extract URL components for logging
function parseURL(url) {
    try {
        if (ObjC.available && url) {
            var nsurl = new ObjC.Object(url);
            return {
                scheme: nsurl.scheme() ? nsurl.scheme().toString() : null,
                host: nsurl.host() ? nsurl.host().toString() : null,
                path: nsurl.path() ? nsurl.path().toString() : null,
                query: nsurl.query() ? nsurl.query().toString() : null,
                fragment: nsurl.fragment() ? nsurl.fragment().toString() : null,
                absoluteString: nsurl.absoluteString() ? nsurl.absoluteString().toString() : null
            };
        }
    } catch (e) {
        return null;
    }
    return null;
}

// Extract source application from options dictionary
function getSourceApplication(options) {
    try {
        if (ObjC.available && options && !options.isNull()) {
            var dict = new ObjC.Object(options);

            // Try UIApplicationOpenURLOptionsSourceApplicationKey
            var sourceAppKey = ObjC.classes.NSString.stringWithString_("UIApplicationOpenURLOptionsSourceApplicationKey");
            var sourceApp = dict.objectForKey_(sourceAppKey);
            if (sourceApp) {
                return sourceApp.toString();
            }

            // Try older key format
            var oldKey = ObjC.classes.NSString.stringWithString_("UIApplicationOpenURLOptionsSourceApplicationKey");
            sourceApp = dict.objectForKey_(oldKey);
            if (sourceApp) {
                return sourceApp.toString();
            }
        }
    } catch (e) {
        return null;
    }
    return null;
}

// Extract URL contexts from NSSet
function extractURLContexts(contextSet) {
    var contexts = [];
    try {
        if (ObjC.available && contextSet && !contextSet.isNull()) {
            var set = new ObjC.Object(contextSet);
            var enumerator = set.objectEnumerator();
            var context;

            while ((context = enumerator.nextObject()) !== null) {
                var url = context.URL();
                var options = context.options();

                contexts.push({
                    url: url ? parseURL(url) : null,
                    sourceApp: options ? getSourceApplication(options) : null
                });
            }
        }
    } catch (e) {
        console.log("   [!] Error extracting URL contexts: " + e);
    }
    return contexts;
}

// Extract user activity details
function extractUserActivity(activity) {
    try {
        if (ObjC.available && activity && !activity.isNull()) {
            var act = new ObjC.Object(activity);
            var type = act.activityType() ? act.activityType().toString() : null;
            var url = act.webpageURL() ? parseURL(act.webpageURL()) : null;
            var title = act.title() ? act.title().toString() : null;

            return {
                type: type,
                url: url,
                title: title,
                isUniversalLink: type === 'NSUserActivityTypeBrowsingWeb'
            };
        }
    } catch (e) {
        return null;
    }
    return null;
}
"""


def generate_deeplinks_script(binary_name: str = "unknown") -> str:
    """
    Generate a Frida script to hook deep link and URL scheme handlers.

    Args:
        binary_name: Name of the target binary for logging context

    Returns:
        Complete Frida script as a string

    The generated script will:
    1. Hook all UIApplicationDelegate deep link methods
    2. Hook all UISceneDelegate URL handling methods
    3. Track source applications and URL parameters
    4. Monitor canOpenURL and openURL calls
    5. Log Universal Links activity
    """

    hooks = []

    # UIApplicationDelegate hooks
    application_delegate_hook = f"""
// ============================================================================
// UIApplicationDelegate Deep Link Hooks
// ============================================================================

// Find and hook all UIApplicationDelegate implementations
setTimeout(function() {{
    console.log("[*] Searching for UIApplicationDelegate deep link handlers...");
    var delegateCount = 0;

    for (var className in ObjC.classes) {{
        try {{
            var cls = ObjC.classes[className];

            // Hook application:openURL:options: (modern deep link handler)
            if (cls['- application:openURL:options:'] && cls['- application:openURL:options:'].implementation) {{
                (function(className) {{
                    Interceptor.attach(cls['- application:openURL:options:'].implementation, {{
                        onEnter: function(args) {{
                            console.log("\\n[*** Deep Link Entry ***] " + className);
                            console.log("   Method: application:openURL:options:");
                            console.log("   Time: " + new Date().toISOString());

                            var url = new ObjC.Object(args[2]);
                            var options = new ObjC.Object(args[3]);

                            var urlInfo = parseURL(url);
                            if (urlInfo) {{
                                console.log("   URL Scheme: " + (urlInfo.scheme || "none"));
                                console.log("   URL Host: " + (urlInfo.host || "none"));
                                console.log("   URL Path: " + (urlInfo.path || "/"));
                                console.log("   URL Query: " + (urlInfo.query || "none"));
                                console.log("   Full URL: " + (urlInfo.absoluteString || "unknown"));
                            }}

                            var sourceApp = getSourceApplication(options);
                            if (sourceApp) {{
                                console.log("   Source App: " + sourceApp);
                            }} else {{
                                console.log("   [!] WARNING: No source application identified!");
                            }}

                            // Check for dangerous schemes
                            if (urlInfo && urlInfo.scheme) {{
                                if (urlInfo.scheme === 'file') {{
                                    console.log("   [!] CRITICAL: file:// scheme detected - potential file access!");
                                }} else if (urlInfo.scheme === 'javascript') {{
                                    console.log("   [!] HIGH: javascript: scheme detected - potential XSS!");
                                }}
                            }}

                            console.log("   Backtrace (BN = Ghidra offset):");
                            console.log(formatBacktrace(this.context, getMainAppModule(), 5));
                        }},
                        onLeave: function(retval) {{
                            console.log("   Handled: " + (retval ? "YES" : "NO"));
                        }}
                    }});
                }})(className);
                delegateCount++;
            }}

            // Hook deprecated application:handleOpenURL:
            if (cls['- application:handleOpenURL:'] && cls['- application:handleOpenURL:'].implementation) {{
                (function(className) {{
                    Interceptor.attach(cls['- application:handleOpenURL:'].implementation, {{
                        onEnter: function(args) {{
                            console.log("\\n[*** Deep Link Entry (Deprecated) ***] " + className);
                            console.log("   Method: application:handleOpenURL:");
                            console.log("   [!] WARNING: Using deprecated API - no source validation!");
                            console.log("   Time: " + new Date().toISOString());

                            var url = new ObjC.Object(args[2]);
                            var urlInfo = parseURL(url);
                            if (urlInfo) {{
                                console.log("   URL: " + (urlInfo.absoluteString || "unknown"));
                                console.log("   Scheme: " + (urlInfo.scheme || "none"));
                            }}
                        }},
                        onLeave: function(retval) {{
                            console.log("   Handled: " + (retval ? "YES" : "NO"));
                        }}
                    }});
                }})(className);
                delegateCount++;
            }}

            // Hook Universal Links handler
            if (cls['- application:continueUserActivity:restorationHandler:'] && cls['- application:continueUserActivity:restorationHandler:'].implementation) {{
                (function(className) {{
                    Interceptor.attach(cls['- application:continueUserActivity:restorationHandler:'].implementation, {{
                        onEnter: function(args) {{
                            var activity = new ObjC.Object(args[2]);
                            var activityInfo = extractUserActivity(activity);

                            if (activityInfo && activityInfo.isUniversalLink) {{
                                console.log("\\n[*** Universal Link ***] " + className);
                                console.log("   Method: application:continueUserActivity:restorationHandler:");
                                console.log("   Time: " + new Date().toISOString());

                                if (activityInfo.url) {{
                                    console.log("   URL: " + (activityInfo.url.absoluteString || "unknown"));
                                    console.log("   Host: " + (activityInfo.url.host || "none"));
                                    console.log("   Path: " + (activityInfo.url.path || "/"));
                                }}

                                console.log("   Title: " + (activityInfo.title || "none"));
                            }}
                        }},
                        onLeave: function(retval) {{
                            console.log("   Handled: " + (retval ? "YES" : "NO"));
                        }}
                    }});
                }})(className);
                delegateCount++;
            }}

        }} catch (e) {{
            // Silently skip classes that cause errors
        }}
    }}

    console.log("[*] Hooked " + delegateCount + " UIApplicationDelegate methods");
}}, 100);
"""

    # UISceneDelegate hooks
    scene_delegate_hook = f"""
// ============================================================================
// UISceneDelegate Deep Link Hooks (iOS 13+)
// ============================================================================

setTimeout(function() {{
    if (ObjC.classes.UISceneDelegate) {{
        console.log("[*] Searching for UISceneDelegate deep link handlers...");
        var sceneDelegateCount = 0;

        for (var className in ObjC.classes) {{
            try {{
                var cls = ObjC.classes[className];

                // Hook scene:openURLContexts:
                if (cls['- scene:openURLContexts:'] && cls['- scene:openURLContexts:'].implementation) {{
                    (function(className) {{
                        Interceptor.attach(cls['- scene:openURLContexts:'].implementation, {{
                            onEnter: function(args) {{
                                console.log("\\n[*** Scene Deep Link ***] " + className);
                                console.log("   Method: scene:openURLContexts:");
                                console.log("   Time: " + new Date().toISOString());

                                var contexts = extractURLContexts(args[2]);
                                console.log("   URL Count: " + contexts.length);

                                contexts.forEach(function(ctx, idx) {{
                                    console.log("   URL #" + (idx + 1) + ":");
                                    if (ctx.url) {{
                                        console.log("     Scheme: " + (ctx.url.scheme || "none"));
                                        console.log("     Host: " + (ctx.url.host || "none"));
                                        console.log("     Path: " + (ctx.url.path || "/"));
                                        console.log("     Full: " + (ctx.url.absoluteString || "unknown"));
                                    }}
                                    if (ctx.sourceApp) {{
                                        console.log("     Source: " + ctx.sourceApp);
                                    }}
                                }});
                            }}
                        }});
                    }})(className);
                    sceneDelegateCount++;
                }}

                // Hook scene:continueUserActivity:
                if (cls['- scene:continueUserActivity:'] && cls['- scene:continueUserActivity:'].implementation) {{
                    (function(className) {{
                        Interceptor.attach(cls['- scene:continueUserActivity:'].implementation, {{
                            onEnter: function(args) {{
                                var activity = new ObjC.Object(args[2]);
                                var activityInfo = extractUserActivity(activity);

                                if (activityInfo && activityInfo.isUniversalLink) {{
                                    console.log("\\n[*** Scene Universal Link ***] " + className);
                                    console.log("   Method: scene:continueUserActivity:");
                                    console.log("   Time: " + new Date().toISOString());

                                    if (activityInfo.url) {{
                                        console.log("   URL: " + (activityInfo.url.absoluteString || "unknown"));
                                        console.log("   Host: " + (activityInfo.url.host || "none"));
                                    }}
                                }}
                            }}
                        }});
                    }})(className);
                    sceneDelegateCount++;
                }}

            }} catch (e) {{
                // Silently skip
            }}
        }}

        console.log("[*] Hooked " + sceneDelegateCount + " UISceneDelegate methods");
    }}
}}, 100);
"""

    # UIApplication URL opening hooks
    uiapplication_hook = f"""
// ============================================================================
// UIApplication URL Opening Hooks
// ============================================================================

if (ObjC.classes.UIApplication) {{
    var UIApplication = ObjC.classes.UIApplication;

    // Hook canOpenURL: (URL scheme checking)
    if (UIApplication['- canOpenURL:'] && UIApplication['- canOpenURL:'].implementation) {{
        Interceptor.attach(UIApplication['- canOpenURL:'].implementation, {{
            onEnter: function(args) {{
                var url = new ObjC.Object(args[2]);
                var urlInfo = parseURL(url);

                console.log("\\n[URL Scheme Check] canOpenURL:");
                console.log("   URL: " + (urlInfo ? urlInfo.absoluteString : "unknown"));
                console.log("   Scheme: " + (urlInfo ? urlInfo.scheme : "unknown"));

                // Common jailbreak detection schemes
                var jbSchemes = ['cydia', 'sileo', 'zbra', 'filza', 'activator'];
                if (urlInfo && urlInfo.scheme) {{
                    var scheme = urlInfo.scheme.toLowerCase();
                    if (jbSchemes.indexOf(scheme) !== -1) {{
                        console.log("   [!] Potential jailbreak detection: " + scheme);
                    }}
                }}
            }},
            onLeave: function(retval) {{
                console.log("   Can Open: " + (retval ? "YES" : "NO"));
            }}
        }});
    }}

    // Hook openURL:options:completionHandler:
    if (UIApplication['- openURL:options:completionHandler:'] && UIApplication['- openURL:options:completionHandler:'].implementation) {{
        Interceptor.attach(UIApplication['- openURL:options:completionHandler:'].implementation, {{
            onEnter: function(args) {{
                var url = new ObjC.Object(args[2]);
                var urlInfo = parseURL(url);

                console.log("\\n[External URL Opening] openURL:options:completionHandler:");
                console.log("   URL: " + (urlInfo ? urlInfo.absoluteString : "unknown"));
                console.log("   Scheme: " + (urlInfo ? urlInfo.scheme : "unknown"));

                // Warn about sensitive schemes
                if (urlInfo && urlInfo.scheme) {{
                    var scheme = urlInfo.scheme.toLowerCase();
                    if (scheme === 'tel') {{
                        console.log("   [!] Opening phone number");
                    }} else if (scheme === 'sms') {{
                        console.log("   [!] Opening SMS");
                    }} else if (scheme === 'mailto') {{
                        console.log("   [!] Opening email");
                    }} else if (scheme === 'facetime') {{
                        console.log("   [!] Opening FaceTime");
                    }}
                }}

                console.log("   Backtrace (BN = Ghidra offset):");
                console.log(formatBacktrace(this.context, getMainAppModule(), 5));
            }}
        }});
    }}

    // Hook deprecated openURL:
    if (UIApplication['- openURL:'] && UIApplication['- openURL:'].implementation) {{
        Interceptor.attach(UIApplication['- openURL:'].implementation, {{
            onEnter: function(args) {{
                var url = new ObjC.Object(args[2]);
                var urlInfo = parseURL(url);

                console.log("\\n[External URL Opening (Deprecated)] openURL:");
                console.log("   [!] Using deprecated API");
                console.log("   URL: " + (urlInfo ? urlInfo.absoluteString : "unknown"));
            }},
            onLeave: function(retval) {{
                console.log("   Opened: " + (retval ? "YES" : "NO"));
            }}
        }});
    }}
}}
"""

    hooks.append(application_delegate_hook)
    hooks.append(scene_delegate_hook)
    hooks.append(uiapplication_hook)

    # Combine all hooks with the constants
    full_script = DEEPLINK_CONSTANTS + "\n\n" + combine_hooks(
        hooks,
        category="deeplinks",
        binary_name=binary_name
    )

    return full_script


__all__ = ["generate_deeplinks_script"]