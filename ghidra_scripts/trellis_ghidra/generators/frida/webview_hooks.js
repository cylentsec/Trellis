/**
 * Trellis WebView Enumeration & Security Scanner
 * -----------------------------------------------
 * Runtime enumeration and monitoring of WebViews for security analysis.
 *
 * Features:
 * - Scans for existing WKWebView/UIWebView instances in memory
 * - Detects UIWebView usage (CRITICAL - deprecated, arbitrary code execution)
 * - Lists URL schemes the app handles (deep link attack surface)
 * - Monitors JavaScript bridge registration (XSS to native escalation)
 * - Monitors WebView URL loading for dangerous schemes
 * - Finds URL handler symbols in app modules
 * - Provides exploitation guidance and test payloads
 *
 * Compatible with Frida 17+
 *
 * Usage:
 *     frida -U -f com.example.app -l webview_hooks.js
 */

// ============================================================================
// ANSI Colors (inlined, no external dependencies)
// ============================================================================

var Colors = {
    RESET: '\x1b[0m',
    RED: '\x1b[31m',
    GREEN: '\x1b[32m',
    YELLOW: '\x1b[33m',
    CYAN: '\x1b[36m'
};

// Runtime config (lazy loading + early capture)
var TRELLIS_WEBVIEW_CONFIG = { useLazyLoading: true, earlyCapture: false };

// ============================================================================
// Results Collection
// ============================================================================

var results = {
    wkwebviews: [],
    uiwebviews: [],
    urlSchemes: [],
    jsBridges: [],
    vulnerabilities: [],
    exploits: [],
    handlers: []
};

// ============================================================================
// Ghidra Address Translation
// ============================================================================

var textVmaddrCache = {};

function getTextVmaddr(module) {
    if (textVmaddrCache[module.path]) {
        return textVmaddrCache[module.path];
    }

    var textVmaddr = ptr(0);
    var filetype = 0;

    try {
        var header = module.base;
        var magic = header.readU32();

        if (magic === 0xfeedfacf) {  // MH_MAGIC_64
            filetype = header.add(12).readU32();
            var ncmds = header.add(16).readU32();
            var cmdPtr = header.add(32);

            for (var i = 0; i < ncmds && i < 50; i++) {
                var cmd = cmdPtr.readU32();
                var cmdsize = cmdPtr.add(4).readU32();

                if (cmd === 0x19) {  // LC_SEGMENT_64
                    var segname = cmdPtr.add(8).readUtf8String();
                    if (segname && segname.indexOf('__TEXT') === 0) {
                        textVmaddr = ptr(cmdPtr.add(24).readU64());
                        break;
                    }
                }
                cmdPtr = cmdPtr.add(cmdsize);
            }

            // Ghidra uses __TEXT vmaddr as-is (no rebasing for dylibs)
        }
    } catch (e) {
        // Fall back to 0
    }

    textVmaddrCache[module.path] = textVmaddr;
    return textVmaddr;
}

function getAddressInfo(address) {
    try {
        var module = Process.findModuleByAddress(address);
        if (module) {
            var runtimeOffset = address.sub(module.base);
            var textVmaddr = getTextVmaddr(module);
            var ghidraAddr = runtimeOffset.add(textVmaddr);

            return {
                runtime: address.toString(),
                module: module.name,
                base: module.base.toString(),
                offset: '0x' + ghidraAddr.toString(16)
            };
        }
    } catch (e) {
        return null;
    }
    return null;
}

function printAddressInfo(label, address) {
    var info = getAddressInfo(address);
    if (info) {
        console.log(Colors.CYAN + label + Colors.RESET);
        console.log(Colors.CYAN + '|-- Module:        ' + info.module + Colors.RESET);
        console.log(Colors.GREEN + '|-- Ghidra:  ' + info.offset + '  <-- GO HERE IN DISASSEMBLER' + Colors.RESET);
    }
}

// ============================================================================
// Helper: Find best app frame in backtrace
// ============================================================================

function findBestAppFrame(context) {
    var backtrace = Thread.backtrace(context, Backtracer.ACCURATE);

    var appModules = Process.enumerateModules().filter(function(m) {
        return m.path.indexOf('.app/') !== -1;
    });

    var bestFrame = null;
    var bestOffset = 0;

    for (var i = 1; i < backtrace.length; i++) {
        var addr = backtrace[i];
        var module = Process.findModuleByAddress(addr);

        if (module) {
            var isAppModule = appModules.some(function(m) {
                return m.path === module.path;
            });

            if (isAppModule) {
                var info = getAddressInfo(addr);
                if (info) {
                    var offsetValue = parseInt(info.offset, 16);
                    if (offsetValue > bestOffset) {
                        bestOffset = offsetValue;
                        bestFrame = info;
                    }
                }
            }
        }
    }

    return bestFrame;
}

// ============================================================================
// 1. Enumerate Existing WebView Instances
// ============================================================================

function enumerateWebViewInstances(done) {
    console.log(Colors.CYAN + '[*] Scanning for WebView instances in memory...' + Colors.RESET);
    var doneCallback = done;
    var pending = 0;
    function finish() {
        pending -= 1;
        if (pending <= 0 && doneCallback) {
            doneCallback();
            doneCallback = null;
        }
    }

    if (!ObjC.available) {
        console.log(Colors.RED + '[-] Objective-C runtime not available' + Colors.RESET);
        if (doneCallback) {
            doneCallback();
            doneCallback = null;
        }
        return;
    }

    // Scan for WKWebView instances
    try {
        var wkWebViewClass = ObjC.classes.WKWebView;
        if (wkWebViewClass) {
            pending += 1;
            ObjC.choose(wkWebViewClass, {
                onMatch: function(instance) {
                    var webView = {
                        address: instance.handle.toString(),
                        url: null,
                        configuration: null,
                        jsEnabled: null,
                        jsBridges: []
                    };

                    try {
                        var url = instance.URL();
                        if (url && !url.isNull()) {
                            webView.url = url.absoluteString().toString();
                        }
                    } catch (e) {}

                    try {
                        var config = instance.configuration();
                        if (config && !config.isNull()) {
                            webView.configuration = config.toString();

                            var prefs = config.preferences();
                            if (prefs && !prefs.isNull()) {
                                webView.jsEnabled = prefs.javaScriptEnabled();
                            }

                            var userContentController = config.userContentController();
                            if (userContentController && !userContentController.isNull()) {
                                webView.hasUserContentController = true;
                            }
                        }
                    } catch (e) {}

                    results.wkwebviews.push(webView);
                },
                onComplete: function() {
                    if (results.wkwebviews.length > 0) {
                        console.log(Colors.GREEN + '[+] Found ' + results.wkwebviews.length + ' WKWebView instance(s)' + Colors.RESET);
                        results.wkwebviews.forEach(function(wv, idx) {
                            console.log(Colors.GREEN + '    [' + idx + '] Address: ' + wv.address + Colors.RESET);
                            if (wv.url) {
                                console.log(Colors.GREEN + '        URL: ' + wv.url + Colors.RESET);
                            }
                            if (wv.jsEnabled !== null) {
                                console.log(Colors.GREEN + '        JavaScript: ' + (wv.jsEnabled ? 'ENABLED' : 'DISABLED') + Colors.RESET);
                            }
                        });
                    } else {
                        console.log(Colors.YELLOW + '[-] No WKWebView instances found in memory (may not be created yet)' + Colors.RESET);
                    }
                    finish();
                }
            });
        }
    } catch (e) {
        console.log(Colors.RED + '[-] Error scanning for WKWebView: ' + e.message + Colors.RESET);
        if (pending > 0) {
            finish();
        }
    }

    // Scan for UIWebView instances (deprecated - CRITICAL)
    try {
        var uiWebViewClass = ObjC.classes.UIWebView;
        if (uiWebViewClass) {
            pending += 1;
            ObjC.choose(uiWebViewClass, {
                onMatch: function(instance) {
                    var webView = {
                        address: instance.handle.toString(),
                        url: null
                    };

                    try {
                        var request = instance.request();
                        if (request && !request.isNull()) {
                            var url = request.URL();
                            if (url && !url.isNull()) {
                                webView.url = url.absoluteString().toString();
                            }
                        }
                    } catch (e) {}

                    results.uiwebviews.push(webView);
                },
                onComplete: function() {
                    if (results.uiwebviews.length > 0) {
                        console.log(Colors.RED + '[!!!] CRITICAL: Found ' + results.uiwebviews.length + ' UIWebView instance(s)' + Colors.RESET);
                        console.log(Colors.RED + '[!!!] UIWebView is deprecated and INSECURE - arbitrary code execution possible!' + Colors.RESET);
                        results.vulnerabilities.push({
                            severity: 'CRITICAL',
                            title: 'UIWebView Usage',
                            description: 'App uses deprecated UIWebView which is vulnerable to arbitrary code execution'
                        });
                        results.uiwebviews.forEach(function(wv, idx) {
                            console.log(Colors.RED + '    [' + idx + '] Address: ' + wv.address + Colors.RESET);
                            if (wv.url) {
                                console.log(Colors.RED + '        URL: ' + wv.url + Colors.RESET);
                            }
                        });
                    }
                    finish();
                }
            });
        }
    } catch (e) {
        console.log(Colors.YELLOW + '[-] Error scanning for UIWebView: ' + e.message + Colors.RESET);
        if (pending > 0) {
            finish();
        }
    }

    console.log('');

    if (pending === 0 && doneCallback) {
        doneCallback();
        doneCallback = null;
    }
}

// ============================================================================
// 2. Enumerate URL Schemes (Deep Links)
// ============================================================================

function enumerateURLSchemes() {
    console.log(Colors.CYAN + '[*] Enumerating URL schemes (deep link handlers)...' + Colors.RESET);

    try {
        var mainBundle = ObjC.classes.NSBundle.mainBundle();
        var infoDictionary = mainBundle.infoDictionary();

        if (infoDictionary) {
            var urlTypes = infoDictionary.objectForKey_('CFBundleURLTypes');

            if (urlTypes && !urlTypes.isNull()) {
                var count = urlTypes.count();

                for (var i = 0; i < count; i++) {
                    var urlType = urlTypes.objectAtIndex_(i);
                    var schemes = urlType.objectForKey_('CFBundleURLSchemes');

                    if (schemes && !schemes.isNull()) {
                        var schemeCount = schemes.count();
                        for (var j = 0; j < schemeCount; j++) {
                            var scheme = schemes.objectAtIndex_(j).toString();
                            results.urlSchemes.push(scheme);
                        }
                    }
                }

                if (results.urlSchemes.length > 0) {
                    console.log(Colors.GREEN + '[+] Found ' + results.urlSchemes.length + ' URL scheme(s):' + Colors.RESET);
                    results.urlSchemes.forEach(function(scheme) {
                        console.log(Colors.GREEN + '    - ' + scheme + '://' + Colors.RESET);
                        console.log(Colors.CYAN + '      Test: ' + scheme + '://open?url=https://attacker.com' + Colors.RESET);
                    });

                    results.vulnerabilities.push({
                        severity: 'HIGH',
                        title: 'URL Scheme Handlers Present',
                        description: 'App handles custom URL schemes: ' + results.urlSchemes.join(', ') + '. Test for improper input validation.'
                    });
                } else {
                    console.log(Colors.YELLOW + '[-] No custom URL schemes found' + Colors.RESET);
                }
            } else {
                console.log(Colors.YELLOW + '[-] No CFBundleURLTypes in Info.plist' + Colors.RESET);
            }
        }
    } catch (e) {
        console.log(Colors.RED + '[-] Error enumerating URL schemes: ' + e.message + Colors.RESET);
    }

    console.log('');
}

// ============================================================================
// 3. Monitor JavaScript Bridges
// ============================================================================

function monitorJSBridges() {
    console.log(Colors.CYAN + '[*] Installing hooks to detect JavaScript bridges...' + Colors.RESET);

    if (!ObjC.available || !ObjC.classes.WKUserContentController) {
        console.log(Colors.YELLOW + '[-] WKUserContentController not available' + Colors.RESET + '\n');
        return;
    }

    try {
        var method = ObjC.classes.WKUserContentController['- addScriptMessageHandler:name:'];

        if (method && method.implementation) {
            Interceptor.attach(method.implementation, {
                onEnter: function(args) {
                    var name = new ObjC.Object(args[3]).toString();
                    var handler = new ObjC.Object(args[2]);

                    if (results.jsBridges.indexOf(name) === -1) {
                        results.jsBridges.push(name);
                        console.log('\n' + Colors.YELLOW + '[!] JavaScript bridge detected: "' + name + '"' + Colors.RESET);
                        console.log(Colors.CYAN + '    Test: webkit.messageHandlers.' + name + '.postMessage("payload")' + Colors.RESET);

                        try {
                            var handlerClass = handler.$className;
                            console.log(Colors.CYAN + '    Handler class: ' + handlerClass + Colors.RESET);

                            var receiveMethod = ObjC.classes[handlerClass]['- userContentController:didReceiveScriptMessage:'];
                            if (receiveMethod && receiveMethod.implementation) {
                                printAddressInfo('    Handler method:', receiveMethod.implementation);

                                results.handlers.push({
                                    type: 'JSBridge',
                                    name: name,
                                    class: handlerClass,
                                    address: getAddressInfo(receiveMethod.implementation)
                                });
                            }
                        } catch (e) {
                            console.log(Colors.YELLOW + '    Could not resolve handler address: ' + e.message + Colors.RESET);
                        }

                        results.vulnerabilities.push({
                            severity: 'MEDIUM',
                            title: 'JavaScript Bridge: ' + name,
                            description: 'App exposes native functionality via webkit.messageHandlers.' + name + '.postMessage(). Test for injection vulnerabilities.'
                        });

                        console.log('');
                    }
                }
            });
            console.log(Colors.GREEN + '[+] JavaScript bridge monitor installed' + Colors.RESET);
        }
    } catch (e) {
        console.log(Colors.RED + '[-] Error monitoring JS bridges: ' + e.message + Colors.RESET);
    }

    console.log('');
}

// ============================================================================
// 4. Monitor WebView Creation
// ============================================================================

function monitorWebViewCreation() {
    console.log(Colors.CYAN + '[*] Installing hooks to monitor WebView creation...' + Colors.RESET);

    if (!ObjC.available) {
        console.log(Colors.YELLOW + '[-] Objective-C runtime not available' + Colors.RESET + '\n');
        return;
    }

    try {
        if (ObjC.classes.WKWebView) {
            var method = ObjC.classes.WKWebView['- initWithFrame:configuration:'];
            if (method && method.implementation) {
                Interceptor.attach(method.implementation, {
                    onEnter: function(args) {
                        var config = new ObjC.Object(args[3]);

                        console.log('\n' + Colors.CYAN + '[*] WKWebView being created' + Colors.RESET);

                        try {
                            var prefs = config.preferences();
                            var jsEnabled = prefs.javaScriptEnabled();
                            console.log(Colors.CYAN + '    JavaScript: ' + (jsEnabled ? 'ENABLED' : 'DISABLED') + Colors.RESET);
                        } catch (e) {}

                        var bestFrame = findBestAppFrame(this.context);
                        if (bestFrame) {
                            console.log(Colors.GREEN + '    Caller (app code): ' + bestFrame.module + Colors.RESET);
                            console.log(Colors.YELLOW + '    Ghidra: ' + bestFrame.offset + '  <-- GO HERE' + Colors.RESET);

                            results.handlers.push({
                                type: 'WebViewCreation',
                                name: 'WKWebView init caller',
                                address: bestFrame
                            });
                        } else {
                            console.log(Colors.YELLOW + '    No app frames found in backtrace' + Colors.RESET);
                        }

                        console.log('');
                    }
                });
                console.log(Colors.GREEN + '[+] WKWebView creation monitor installed' + Colors.RESET);
            }
        }
    } catch (e) {
        console.log(Colors.RED + '[-] Error monitoring WKWebView creation: ' + e.message + Colors.RESET);
    }

    console.log('');
}

// ============================================================================
// 5. Monitor URL Loading
// ============================================================================

function monitorURLLoading() {
    console.log(Colors.CYAN + '[*] Installing hooks to monitor URL loading...' + Colors.RESET);

    if (!ObjC.available || !ObjC.classes.WKWebView) {
        console.log(Colors.YELLOW + '[-] WKWebView not available' + Colors.RESET + '\n');
        return;
    }

    try {
        // Hook loadRequest:
        var loadRequestMethod = ObjC.classes.WKWebView['- loadRequest:'];
        if (loadRequestMethod && loadRequestMethod.implementation) {
            Interceptor.attach(loadRequestMethod.implementation, {
                onEnter: function(args) {
                    var request = new ObjC.Object(args[2]);

                    try {
                        var url = request.URL();
                        var urlString = url.absoluteString().toString();

                        console.log('\n' + Colors.YELLOW + '[!] WKWebView loading URL: ' + urlString + Colors.RESET);

                        var bestFrame = findBestAppFrame(this.context);
                        if (bestFrame) {
                            console.log(Colors.GREEN + '    Caller (app code): ' + bestFrame.module + Colors.RESET);
                            console.log(Colors.YELLOW + '    Ghidra: ' + bestFrame.offset + '  <-- GO HERE' + Colors.RESET);

                            results.handlers.push({
                                type: 'URLLoad',
                                name: 'Loading: ' + urlString.substring(0, 50),
                                address: bestFrame
                            });
                        } else {
                            console.log(Colors.YELLOW + '    No app frames found in backtrace' + Colors.RESET);
                        }

                        // Check for dangerous schemes
                        var lowerUrl = urlString.toLowerCase();
                        if (lowerUrl.indexOf('javascript:') === 0) {
                            console.log(Colors.RED + '    [!!!] CRITICAL: javascript: scheme detected!' + Colors.RESET);
                        } else if (lowerUrl.indexOf('file://') === 0) {
                            console.log(Colors.RED + '    [!!!] WARNING: file:// scheme detected!' + Colors.RESET);
                        }

                        console.log('');
                    } catch (e) {}
                }
            });
            console.log(Colors.GREEN + '[+] WKWebView loadRequest monitor installed' + Colors.RESET);
        }

        // Hook loadHTMLString:baseURL:
        var loadHTMLMethod = ObjC.classes.WKWebView['- loadHTMLString:baseURL:'];
        if (loadHTMLMethod && loadHTMLMethod.implementation) {
            Interceptor.attach(loadHTMLMethod.implementation, {
                onEnter: function(args) {
                    var baseURL = new ObjC.Object(args[3]);

                    console.log('\n' + Colors.YELLOW + '[!] WKWebView loading HTML string directly' + Colors.RESET);
                    console.log(Colors.YELLOW + '    [!] Potential XSS if HTML contains user input' + Colors.RESET);

                    if (baseURL && !baseURL.isNull()) {
                        console.log(Colors.YELLOW + '    Base URL: ' + baseURL.absoluteString().toString() + Colors.RESET);
                    }

                    var bestFrame = findBestAppFrame(this.context);
                    if (bestFrame) {
                        console.log(Colors.GREEN + '    Caller (app code): ' + bestFrame.module + Colors.RESET);
                        console.log(Colors.YELLOW + '    Ghidra: ' + bestFrame.offset + '  <-- GO HERE' + Colors.RESET);

                        results.handlers.push({
                            type: 'HTMLLoad',
                            name: 'Loading HTML string',
                            address: bestFrame
                        });
                    } else {
                        console.log(Colors.YELLOW + '    No app frames found in backtrace' + Colors.RESET);
                    }

                    console.log('');
                }
            });
            console.log(Colors.GREEN + '[+] WKWebView loadHTMLString monitor installed' + Colors.RESET);
        }
    } catch (e) {
        console.log(Colors.RED + '[-] Error monitoring URL loading: ' + e.message + Colors.RESET);
    }

    console.log('');
}

// ============================================================================
// 6. Find URL Handler Symbols
// ============================================================================

function findURLHandlers() {
    console.log(Colors.CYAN + '[*] Searching for URL handler symbols in app modules...' + Colors.RESET);

    var appModules = Process.enumerateModules().filter(function(m) {
        return m.path.indexOf('.app/') !== -1;
    });

    if (appModules.length === 0) {
        console.log(Colors.YELLOW + '[-] No app modules found' + Colors.RESET + '\n');
        return;
    }

    var urlPatterns = [
        'handleIncomingURL',
        'handleURL',
        'openURL',
        'handleDeepLink',
        'handleUniversalLink',
        'onOpenURL',
        'processURL',
        'routeURL'
    ];

    var foundHandlers = [];

    appModules.forEach(function(module) {
        try {
            var exports = module.enumerateExports();

            exports.forEach(function(exp) {
                var matchedPattern = urlPatterns.find(function(pattern) {
                    return exp.name.toLowerCase().indexOf(pattern.toLowerCase()) !== -1;
                });

                if (matchedPattern) {
                    var info = getAddressInfo(exp.address);
                    var offsetHex = info ? info.offset : '0x' + exp.address.sub(module.base).toString(16);

                    foundHandlers.push({
                        name: exp.name,
                        address: exp.address,
                        module: module.name,
                        offset: offsetHex,
                        pattern: matchedPattern
                    });

                    console.log('\n' + Colors.GREEN + '[+] Found URL handler: ' + matchedPattern + Colors.RESET);
                    console.log(Colors.CYAN + '    Module: ' + module.name + Colors.RESET);
                    console.log(Colors.YELLOW + '    Ghidra: ' + offsetHex + '  <-- GO HERE' + Colors.RESET);

                    try {
                        var demangled = DebugSymbol.fromAddress(exp.address);
                        if (demangled && demangled.name && demangled.name !== exp.name) {
                            console.log(Colors.CYAN + '    Demangled: ' + demangled.name + Colors.RESET);
                        }
                    } catch (e) {}

                    results.handlers.push({
                        type: 'URLHandler',
                        name: matchedPattern,
                        address: {
                            module: module.name,
                            offset: offsetHex
                        }
                    });
                }
            });
        } catch (e) {
            // Module might not have exports
        }
    });

    if (foundHandlers.length === 0) {
        console.log(Colors.YELLOW + '[-] No URL handler symbols found in exports' + Colors.RESET);
        console.log(Colors.CYAN + '    Try searching in Ghidra for: handleURL, openURL, deeplink' + Colors.RESET);
    } else {
        console.log('\n' + Colors.GREEN + '[+] Found ' + foundHandlers.length + ' URL handler(s)' + Colors.RESET);
    }

    console.log('');
}

// ============================================================================
// 7. Generate Exploitation Report
// ============================================================================

function generateReport() {
    console.log(Colors.CYAN + '[*] ========================================' + Colors.RESET);
    console.log(Colors.CYAN + '[*] EXPLOITATION GUIDANCE' + Colors.RESET);
    console.log(Colors.CYAN + '[*] ========================================' + Colors.RESET + '\n');

    // Handler Addresses
    if (results.handlers.length > 0) {
        console.log(Colors.CYAN + '[*] Handler Addresses for Ghidra Analysis' + Colors.RESET + '\n');

        results.handlers.forEach(function(handler, idx) {
            console.log(Colors.GREEN + '[' + (idx + 1) + '] ' + handler.type + ': ' + handler.name + Colors.RESET);
            if (handler.class) {
                console.log(Colors.GREEN + '    Class:         ' + handler.class + Colors.RESET);
            }
            if (handler.address) {
                console.log(Colors.GREEN + '    Module:        ' + handler.address.module + Colors.RESET);
                console.log(Colors.YELLOW + '    Ghidra:  ' + handler.address.offset + '  <-- GO HERE' + Colors.RESET);
            }
            console.log('');
        });
    }

    // Vulnerability Summary
    if (results.vulnerabilities.length > 0) {
        console.log(Colors.YELLOW + '[*] Vulnerabilities Found: ' + results.vulnerabilities.length + Colors.RESET + '\n');

        results.vulnerabilities.forEach(function(vuln, idx) {
            var color = vuln.severity === 'CRITICAL' ? Colors.RED :
                       vuln.severity === 'HIGH' ? Colors.YELLOW :
                       Colors.CYAN;

            console.log(color + '[' + (idx + 1) + '] ' + vuln.severity + ': ' + vuln.title + Colors.RESET);
            console.log(color + '    ' + vuln.description + Colors.RESET + '\n');
        });
    } else {
        console.log(Colors.GREEN + '[+] No immediate vulnerabilities detected' + Colors.RESET + '\n');
    }

    // Exploit Payloads
    console.log(Colors.CYAN + '[*] EXPLOIT PAYLOADS' + Colors.RESET + '\n');

    if (results.urlSchemes.length > 0) {
        console.log(Colors.YELLOW + '[*] Deep Link Attack Vectors:' + Colors.RESET + '\n');

        results.urlSchemes.forEach(function(scheme) {
            console.log(Colors.CYAN + '1. URL injection:' + Colors.RESET);
            console.log('   ' + scheme + '://open?url=https://attacker.com/phishing\n');

            console.log(Colors.CYAN + '2. JavaScript injection:' + Colors.RESET);
            console.log('   ' + scheme + '://open?url=javascript:alert(document.cookie)\n');

            console.log(Colors.CYAN + '3. File scheme:' + Colors.RESET);
            console.log('   ' + scheme + '://open?url=file:///etc/passwd\n');

            console.log(Colors.CYAN + '4. Data scheme:' + Colors.RESET);
            console.log('   ' + scheme + '://open?url=data:text/html,<script>alert(1)</script>\n');
        });
    }

    if (results.jsBridges.length > 0) {
        console.log(Colors.YELLOW + '[*] JavaScript Bridge Attack Vectors:' + Colors.RESET + '\n');

        results.jsBridges.forEach(function(bridge) {
            console.log(Colors.CYAN + '1. XSS to native bridge "' + bridge + '":' + Colors.RESET);
            console.log('   <script>webkit.messageHandlers.' + bridge + '.postMessage("payload")</script>\n');

            console.log(Colors.CYAN + '2. JSON injection:' + Colors.RESET);
            console.log('   <script>webkit.messageHandlers.' + bridge + '.postMessage({"cmd":"evil"})</script>\n');
        });
    }

    // Testing Instructions
    if (results.urlSchemes.length > 0) {
        console.log(Colors.CYAN + '[*] TESTING INSTRUCTIONS' + Colors.RESET + '\n');

        console.log(Colors.GREEN + 'To test deep links on device:' + Colors.RESET + '\n');

        console.log(Colors.YELLOW + 'Method 1: Safari' + Colors.RESET);
        console.log('   Type in address bar: ' + results.urlSchemes[0] + '://open?url=https://attacker.com\n');

        console.log(Colors.YELLOW + 'Method 2: Notes app' + Colors.RESET);
        console.log('   Create note with link, tap it\n');

        console.log(Colors.YELLOW + 'Method 3: HTML file' + Colors.RESET);
        console.log('   <a href="' + results.urlSchemes[0] + '://open?url=https://attacker.com">Test</a>\n');
    }

    console.log(Colors.CYAN + '[*] ========================================' + Colors.RESET + '\n');
}

// ============================================================================
// Main Execution
// ============================================================================

var _trellisWebViewStarted = false;

function startWebViewScanner() {
    if (_trellisWebViewStarted) return;
    _trellisWebViewStarted = true;

    console.log(Colors.CYAN + '[*] ========================================' + Colors.RESET);
    console.log(Colors.CYAN + '[*] Trellis WebView Security Scanner' + Colors.RESET);
    console.log(Colors.CYAN + '[*] ========================================' + Colors.RESET + '\n');

    console.log(Colors.CYAN + '[*] Starting enumeration...' + Colors.RESET + '\n');

    enumerateWebViewInstances(function() {
        enumerateURLSchemes();
        monitorJSBridges();
        monitorWebViewCreation();
        monitorURLLoading();
        findURLHandlers();

        generateReport();

        console.log(Colors.GREEN + '[+] Enumeration complete. Monitoring for runtime activity...' + Colors.RESET);
        console.log(Colors.YELLOW + '[*] Interact with the app to trigger WebViews and see dynamic analysis' + Colors.RESET + '\n');
    });
}

function trellisWebViewDeferHooksUntilReady(hookInstaller) {
    if (typeof ObjC !== 'undefined' && ObjC.available) {
        try {
            var NSNotificationCenter = ObjC.classes.NSNotificationCenter;
            var notificationName = ObjC.classes.NSString.stringWithString_('UIApplicationDidFinishLaunchingNotification');
            NSNotificationCenter.defaultCenter().addObserverForName_object_queue_usingBlock_(
                notificationName,
                null,
                null,
                new ObjC.Block({
                    retType: 'void',
                    argTypes: ['object'],
                    implementation: function() {
                        hookInstaller();
                    }
                })
            );
        } catch (e) {
            // Ignore and use fallback
        }
    }

    setTimeout(function() {
        if (!_trellisWebViewStarted) {
            hookInstaller();
        }
    }, 2000);
}

// Early capture (install immediately)
if (TRELLIS_WEBVIEW_CONFIG.earlyCapture) {
    startWebViewScanner();
}

// Lazy loading (default)
if (TRELLIS_WEBVIEW_CONFIG.useLazyLoading) {
    trellisWebViewDeferHooksUntilReady(startWebViewScanner);
} else if (!TRELLIS_WEBVIEW_CONFIG.earlyCapture) {
    startWebViewScanner();
}
