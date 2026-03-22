"""
Frida script generator for TLS delegate monitoring.

Generates hooks to intercept URLSession delegate methods and monitor
certificate validation behavior at runtime.
"""

from .base import combine_hooks, get_script_header


TLS_DELEGATE_HOOKS = '''
// ========================================
// TLS Delegate Monitoring Hooks
// ========================================

// Hook URLSession:didReceiveChallenge:completionHandler:
// This monitors session-level authentication challenges
(function() {
    var resolved = ObjC.classes.NSURLSession;
    if (!resolved) {
        console.log("[Trellis] NSURLSession not available");
        return;
    }

    // Find all classes that implement the delegate method
    var delegateClasses = [];
    for (var className in ObjC.classes) {
        try {
            var cls = ObjC.classes[className];
            if (cls['- URLSession:didReceiveChallenge:completionHandler:']) {
                delegateClasses.push(className);
            }
        } catch (e) {
            // Skip classes that cause issues
        }
    }

    console.log("[Trellis TLS] Found " + delegateClasses.length + " URLSession delegate classes");

    delegateClasses.forEach(function(className) {
        try {
            var method = ObjC.classes[className]['- URLSession:didReceiveChallenge:completionHandler:'];
            if (method && method.implementation) {
                Interceptor.attach(method.implementation, {
                    onEnter: function(args) {
                        var self = new ObjC.Object(args[0]);
                        var challenge = new ObjC.Object(args[3]);
                        var protectionSpace = challenge.protectionSpace();

                        this.className = className;
                        this.host = protectionSpace.host().toString();
                        this.method = protectionSpace.authenticationMethod().toString();

                        console.log("\\n[TLS DELEGATE] " + className + " -URLSession:didReceiveChallenge:completionHandler:");
                        console.log("  Host: " + this.host);
                        console.log("  Auth Method: " + this.method);
                        console.log("  Backtrace:");
                        console.log(formatBacktrace(this.context, getMainAppModule(), 5));

                        // Hook the completion handler to see what disposition is used
                        var completionHandler = new ObjC.Block(args[4]);
                        var origImpl = completionHandler.implementation;
                        var host = this.host;

                        completionHandler.implementation = function(disposition, credential) {
                            var dispositionNames = {
                                0: "UseCredential (ACCEPT ALL)",
                                1: "PerformDefaultHandling (SAFE)",
                                2: "CancelAuthenticationChallenge",
                                3: "RejectProtectionSpace"
                            };
                            var dispName = dispositionNames[disposition] || "Unknown(" + disposition + ")";

                            console.log("  [DISPOSITION] " + dispName + " for " + host);

                            if (disposition === 0) {
                                console.log("  [WARNING] Certificate accepted unconditionally!");
                                console.log("  [WARNING] This may indicate a TLS validation bypass");
                            }

                            return origImpl(disposition, credential);
                        };
                    }
                });
                console.log("[Trellis TLS] Hooked " + className + " -URLSession:didReceiveChallenge:completionHandler:");
            }
        } catch (e) {
            console.log("[Trellis TLS] Failed to hook " + className + ": " + e);
        }
    });
})();

// Hook URLSession:task:didReceiveChallenge:completionHandler:
// This monitors task-level authentication challenges
(function() {
    var delegateClasses = [];
    for (var className in ObjC.classes) {
        try {
            var cls = ObjC.classes[className];
            if (cls['- URLSession:task:didReceiveChallenge:completionHandler:']) {
                delegateClasses.push(className);
            }
        } catch (e) {}
    }

    console.log("[Trellis TLS] Found " + delegateClasses.length + " task-level delegate classes");

    delegateClasses.forEach(function(className) {
        try {
            var method = ObjC.classes[className]['- URLSession:task:didReceiveChallenge:completionHandler:'];
            if (method && method.implementation) {
                Interceptor.attach(method.implementation, {
                    onEnter: function(args) {
                        var challenge = new ObjC.Object(args[4]);
                        var protectionSpace = challenge.protectionSpace();

                        this.className = className;
                        this.host = protectionSpace.host().toString();

                        console.log("\\n[TLS DELEGATE] " + className + " -URLSession:task:didReceiveChallenge:completionHandler:");
                        console.log("  Host: " + this.host);

                        // Hook completion handler
                        var completionHandler = new ObjC.Block(args[5]);
                        var origImpl = completionHandler.implementation;
                        var host = this.host;

                        completionHandler.implementation = function(disposition, credential) {
                            var dispositionNames = {
                                0: "UseCredential (ACCEPT ALL)",
                                1: "PerformDefaultHandling (SAFE)",
                                2: "CancelAuthenticationChallenge",
                                3: "RejectProtectionSpace"
                            };
                            console.log("  [DISPOSITION] " + (dispositionNames[disposition] || disposition) + " for " + host);
                            if (disposition === 0) {
                                console.log("  [WARNING] Task-level certificate accepted unconditionally!");
                            }
                            return origImpl(disposition, credential);
                        };
                    }
                });
            }
        } catch (e) {}
    });
})();

// Hook legacy NSURLConnection delegate
(function() {
    var delegateClasses = [];
    for (var className in ObjC.classes) {
        try {
            var cls = ObjC.classes[className];
            if (cls['- connection:willSendRequestForAuthenticationChallenge:']) {
                delegateClasses.push(className);
            }
        } catch (e) {}
    }

    if (delegateClasses.length > 0) {
        console.log("[Trellis TLS] Found " + delegateClasses.length + " NSURLConnection delegate classes (LEGACY)");

        delegateClasses.forEach(function(className) {
            try {
                var method = ObjC.classes[className]['- connection:willSendRequestForAuthenticationChallenge:'];
                if (method && method.implementation) {
                    Interceptor.attach(method.implementation, {
                        onEnter: function(args) {
                            var challenge = new ObjC.Object(args[3]);
                            var protectionSpace = challenge.protectionSpace();

                            console.log("\\n[LEGACY TLS] " + className + " -connection:willSendRequestForAuthenticationChallenge:");
                            console.log("  [WARNING] NSURLConnection is deprecated - should use NSURLSession");
                            console.log("  Host: " + protectionSpace.host().toString());
                            console.log("  Auth Method: " + protectionSpace.authenticationMethod().toString());
                        }
                    });
                }
            } catch (e) {}
        });
    }
})();

// Hook SecTrustEvaluateWithError to see if trust evaluation is actually happening
(function() {
    var funcPtr = null;
    try {
        funcPtr = Module.getExportByName("Security", "SecTrustEvaluateWithError");
    } catch (e) {
        try {
            funcPtr = Module.findExportByName("Security", "SecTrustEvaluateWithError");
        } catch (e2) {}
    }

    if (funcPtr) {
        Interceptor.attach(funcPtr, {
            onEnter: function(args) {
                this.trustRef = args[0];
                this.errorPtr = args[1];
                console.log("\\n[SecTrustEvaluateWithError] Called");
                console.log("  Trust: " + this.trustRef);
                console.log("  Error ptr: " + (this.errorPtr.isNull() ? "NULL (errors ignored!)" : this.errorPtr));
                console.log("  Backtrace:");
                console.log(formatBacktrace(this.context, getMainAppModule(), 3));
            },
            onLeave: function(retval) {
                var result = retval.toInt32();
                console.log("  Result: " + (result ? "TRUSTED" : "FAILED"));
                if (!result && !this.errorPtr.isNull()) {
                    try {
                        var error = new ObjC.Object(this.errorPtr.readPointer());
                        console.log("  Error: " + error.localizedDescription());
                    } catch (e) {}
                }
            }
        });
        console.log("[Trellis TLS] Hooked SecTrustEvaluateWithError");
    }
})();

// Hook deprecated SecTrustEvaluate
(function() {
    var funcPtr = null;
    try {
        funcPtr = Module.getExportByName("Security", "SecTrustEvaluate");
    } catch (e) {
        try {
            funcPtr = Module.findExportByName("Security", "SecTrustEvaluate");
        } catch (e2) {}
    }

    if (funcPtr) {
        Interceptor.attach(funcPtr, {
            onEnter: function(args) {
                this.trustRef = args[0];
                this.resultPtr = args[1];
                console.log("\\n[SecTrustEvaluate] Called (DEPRECATED API)");
                console.log("  Trust: " + this.trustRef);
                console.log("  Result ptr: " + (this.resultPtr.isNull() ? "NULL (result ignored!)" : this.resultPtr));
                console.log("  Backtrace:");
                console.log(formatBacktrace(this.context, getMainAppModule(), 3));
            },
            onLeave: function(retval) {
                var status = retval.toInt32();
                console.log("  Status: " + (status === 0 ? "Success" : "Error " + status));
                if (!this.resultPtr.isNull()) {
                    var result = this.resultPtr.readU32();
                    var resultNames = {
                        1: "Proceed (user trust)",
                        4: "Unspecified (OS trust)",
                        5: "RecoverableTrustFailure (SHOULD REJECT)",
                        6: "FatalTrustFailure",
                        7: "OtherError"
                    };
                    console.log("  Trust Result: " + (resultNames[result] || "Unknown(" + result + ")"));
                    if (result === 5) {
                        console.log("  [WARNING] RecoverableTrustFailure should be rejected!");
                    }
                }
            }
        });
        console.log("[Trellis TLS] Hooked SecTrustEvaluate (deprecated)");
    }
})();

// Hook certificate pinning functions
(function() {
    var pinningFuncs = [
        "SecCertificateCopyData",
        "SecTrustCopyCertificateChain",
        "SecTrustGetCertificateAtIndex"
    ];

    pinningFuncs.forEach(function(funcName) {
        var funcPtr = null;
        try {
            funcPtr = Module.getExportByName("Security", funcName);
        } catch (e) {}

        if (funcPtr) {
            Interceptor.attach(funcPtr, {
                onEnter: function(args) {
                    console.log("\\n[CERT PINNING] " + funcName + " called");
                    console.log("  Backtrace:");
                    console.log(formatBacktrace(this.context, getMainAppModule(), 3));
                },
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        console.log("  Returned: " + retval);
                    }
                }
            });
            console.log("[Trellis TLS] Hooked " + funcName + " (cert pinning)");
        }
    });
})();

// Hook trust anchor functions
(function() {
    var anchorFuncs = [
        "SecTrustSetAnchorCertificates",
        "SecTrustSetAnchorCertificatesOnly"
    ];

    anchorFuncs.forEach(function(funcName) {
        var funcPtr = null;
        try {
            funcPtr = Module.getExportByName("Security", funcName);
        } catch (e) {}

        if (funcPtr) {
            Interceptor.attach(funcPtr, {
                onEnter: function(args) {
                    console.log("\\n[TRUST ANCHORS] " + funcName + " called");
                    if (funcName === "SecTrustSetAnchorCertificatesOnly") {
                        var anchorsOnly = args[1].toInt32();
                        console.log("  Anchors Only: " + (anchorsOnly ? "YES (strict pinning)" : "NO (system + custom)"));
                        if (!anchorsOnly) {
                            console.log("  [WARNING] Allowing system anchors reduces pinning effectiveness");
                        }
                    }
                    console.log("  Backtrace:");
                    console.log(formatBacktrace(this.context, getMainAppModule(), 3));
                }
            });
            console.log("[Trellis TLS] Hooked " + funcName);
        }
    });
})();
'''


def generate_tls_delegate_script(binary_name: str = "unknown") -> str:
    """
    Generate a Frida script for monitoring TLS delegate behavior.

    Args:
        binary_name: Name of the target binary

    Returns:
        Complete Frida script as a string
    """
    return combine_hooks(
        [TLS_DELEGATE_HOOKS],
        "tls_delegate",
        binary_name,
        include_constants=False,
    )


__all__ = ["generate_tls_delegate_script"]