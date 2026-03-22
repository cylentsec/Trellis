"""
Frida script generator for WebView JavaScript bridge monitoring.

Generates hooks to intercept WKScriptMessageHandler calls, evaluateJavaScript
invocations, and WKURLSchemeHandler requests at runtime.
"""

from .base import combine_hooks, get_script_header


WEBVIEW_BRIDGE_HOOKS = '''
// ========================================
// WebView JavaScript Bridge Monitoring
// ========================================

// Hook all WKScriptMessageHandler implementations
(function() {
    if (!ObjC.available) {
        console.log("[Trellis WebView] ObjC runtime not available");
        return;
    }

    // Find all classes implementing WKScriptMessageHandler
    var handlerClasses = [];
    for (var className in ObjC.classes) {
        try {
            var cls = ObjC.classes[className];
            if (cls['- userContentController:didReceiveScriptMessage:']) {
                handlerClasses.push(className);
            }
        } catch (e) {}
    }

    console.log("[Trellis WebView] Found " + handlerClasses.length + " WKScriptMessageHandler classes");

    handlerClasses.forEach(function(className) {
        try {
            var method = ObjC.classes[className]['- userContentController:didReceiveScriptMessage:'];
            if (method && method.implementation) {
                Interceptor.attach(method.implementation, {
                    onEnter: function(args) {
                        var message = new ObjC.Object(args[3]);
                        var name = message.name().toString();
                        var body = message.body();
                        var bodyStr = body ? body.toString() : "nil";

                        console.log("\\n[JS BRIDGE] " + className + " received message:");
                        console.log("  Handler: " + name);
                        console.log("  Body: " + bodyStr.substring(0, 500));
                        console.log("  Backtrace:");
                        console.log(formatBacktrace(this.context, getMainAppModule(), 5));
                    }
                });
                console.log("[Trellis WebView] Hooked " + className + " -userContentController:didReceiveScriptMessage:");
            }
        } catch (e) {
            console.log("[Trellis WebView] Failed to hook " + className + ": " + e);
        }
    });

    // Also find classes with the newer handler variant
    var handlerWithReplyClasses = [];
    for (var className in ObjC.classes) {
        try {
            var cls = ObjC.classes[className];
            if (cls['- userContentController:didReceiveScriptMessage:replyHandler:']) {
                handlerWithReplyClasses.push(className);
            }
        } catch (e) {}
    }

    handlerWithReplyClasses.forEach(function(className) {
        try {
            var method = ObjC.classes[className]['- userContentController:didReceiveScriptMessage:replyHandler:'];
            if (method && method.implementation) {
                Interceptor.attach(method.implementation, {
                    onEnter: function(args) {
                        var message = new ObjC.Object(args[3]);
                        console.log("\\n[JS BRIDGE+REPLY] " + className + " received message:");
                        console.log("  Handler: " + message.name().toString());
                        console.log("  Body: " + (message.body() ? message.body().toString().substring(0, 500) : "nil"));
                    }
                });
            }
        } catch (e) {}
    });
})();

// Hook addScriptMessageHandler:name: to catch registration
(function() {
    var cls = ObjC.classes.WKUserContentController;
    if (!cls) return;

    var method = cls['- addScriptMessageHandler:name:'];
    if (method && method.implementation) {
        Interceptor.attach(method.implementation, {
            onEnter: function(args) {
                var handler = new ObjC.Object(args[2]);
                var name = new ObjC.Object(args[3]);
                console.log("\\n[JS BRIDGE REGISTER] Handler registered:");
                console.log("  Name: " + name.toString());
                console.log("  Handler class: " + handler.$className);
                console.log("  JS access: window.webkit.messageHandlers." + name.toString() + ".postMessage()");
            }
        });
        console.log("[Trellis WebView] Hooked WKUserContentController -addScriptMessageHandler:name:");
    }
})();

// Hook evaluateJavaScript:completionHandler:
(function() {
    var cls = ObjC.classes.WKWebView;
    if (!cls) return;

    var method = cls['- evaluateJavaScript:completionHandler:'];
    if (method && method.implementation) {
        Interceptor.attach(method.implementation, {
            onEnter: function(args) {
                var js = new ObjC.Object(args[2]);
                var jsStr = js.toString();
                console.log("\\n[JS EVAL] evaluateJavaScript called:");
                console.log("  Script: " + jsStr.substring(0, 1000));
                if (jsStr.length > 1000) {
                    console.log("  ... (truncated, " + jsStr.length + " chars total)");
                }
                console.log("  Backtrace:");
                console.log(formatBacktrace(this.context, getMainAppModule(), 3));
            }
        });
        console.log("[Trellis WebView] Hooked WKWebView -evaluateJavaScript:completionHandler:");
    }
})();

// Hook WKURLSchemeHandler implementations
(function() {
    var schemeHandlers = [];
    for (var className in ObjC.classes) {
        try {
            var cls = ObjC.classes[className];
            if (cls['- webView:startURLSchemeTask:']) {
                schemeHandlers.push(className);
            }
        } catch (e) {}
    }

    console.log("[Trellis WebView] Found " + schemeHandlers.length + " WKURLSchemeHandler classes");

    schemeHandlers.forEach(function(className) {
        try {
            var method = ObjC.classes[className]['- webView:startURLSchemeTask:'];
            if (method && method.implementation) {
                Interceptor.attach(method.implementation, {
                    onEnter: function(args) {
                        var task = new ObjC.Object(args[3]);
                        var request = task.request();
                        var url = request.URL();

                        console.log("\\n[URL SCHEME] " + className + " handling request:");
                        console.log("  URL: " + url.absoluteString().toString());
                        console.log("  Scheme: " + url.scheme().toString());
                        if (url.path()) {
                            console.log("  Path: " + url.path().toString());
                        }
                        console.log("  Backtrace:");
                        console.log(formatBacktrace(this.context, getMainAppModule(), 5));
                    }
                });
                console.log("[Trellis WebView] Hooked " + className + " -webView:startURLSchemeTask:");
            }
        } catch (e) {}
    });
})();

// Hook navigation policy decisions
(function() {
    var policyClasses = [];
    for (var className in ObjC.classes) {
        try {
            var cls = ObjC.classes[className];
            if (cls['- webView:decidePolicyForNavigationAction:decisionHandler:']) {
                policyClasses.push(className);
            }
        } catch (e) {}
    }

    policyClasses.forEach(function(className) {
        try {
            var method = ObjC.classes[className]['- webView:decidePolicyForNavigationAction:decisionHandler:'];
            if (method && method.implementation) {
                Interceptor.attach(method.implementation, {
                    onEnter: function(args) {
                        var action = new ObjC.Object(args[3]);
                        var request = action.request();
                        var url = request.URL();
                        var navType = action.navigationType();

                        var navTypes = {
                            0: "linkActivated",
                            1: "formSubmitted",
                            2: "backForward",
                            3: "reload",
                            4: "formResubmitted",
                            5: "other"
                        };

                        console.log("\\n[NAV POLICY] " + className + " deciding navigation:");
                        console.log("  URL: " + url.absoluteString().toString());
                        console.log("  Type: " + (navTypes[navType] || navType));
                    }
                });
            }
        } catch (e) {}
    });
})();
'''


def generate_webview_bridge_script(binary_name: str = "unknown") -> str:
    """
    Generate a Frida script for monitoring WebView JavaScript bridge.

    Args:
        binary_name: Name of the target binary

    Returns:
        Complete Frida script as a string
    """
    return combine_hooks(
        [WEBVIEW_BRIDGE_HOOKS],
        "webview_bridge",
        binary_name,
        include_constants=False,
    )


__all__ = ["generate_webview_bridge_script"]