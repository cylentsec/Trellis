/*
    Trellis UI Interaction Hooks (UIControl, UIGestureRecognizer, SwiftUI)
    ----------------------------------------------------------------------
    Detects user interactions and resolves handler locations for static analysis.

    Features:
    - UIControl: Button clicks, switches, sliders (Objective-C)
    - UIGestureRecognizer: Tap gestures, swipes, custom gestures (Objective-C)
    - SwiftUI: Button actions with closure tracing via Stalker
    - UIAction: iOS 14+ action handlers

    Output includes Ghidra offsets for cross-referencing with static analysis.

    Compatible with Frida 17+

    Usage:
        frida -U -f com.example.app -l ui_hooks.js
*/

// Set to true to see detailed Stalker output for debugging
var DEBUG_STALKER = false;
// Runtime config (lazy loading + early capture)
var TRELLIS_UI_CONFIG = { useLazyLoading: true, earlyCapture: false };

// Lazy loading helpers (namespaced to avoid collisions when loading multiple scripts)
var _trellisUiHooksInstalled = false;
var _trellisUiDeferredHooks = [];

function trellisUiDeferHooksUntilReady(hookInstaller) {
    if (_trellisUiHooksInstalled) {
        hookInstaller();
        return;
    }

    _trellisUiDeferredHooks.push(hookInstaller);

    if (_trellisUiDeferredHooks.length === 1) {
        trellisUiSetupLaunchTrigger();
    }
}

function trellisUiSetupLaunchTrigger() {
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
                        trellisUiInstallDeferredHooks();
                    }
                })
            );
        } catch (e) {
            // ignore and fallback to timeout
        }
    }

    setTimeout(function() {
        if (!_trellisUiHooksInstalled) {
            trellisUiInstallDeferredHooks();
        }
    }, 2000);
}

function trellisUiInstallDeferredHooks() {
    if (_trellisUiHooksInstalled) return;
    _trellisUiHooksInstalled = true;

    for (var i = 0; i < _trellisUiDeferredHooks.length; i++) {
        try {
            _trellisUiDeferredHooks[i]();
        } catch (e) {
            console.log('[!] Error installing UI hooks: ' + e);
        }
    }
    _trellisUiDeferredHooks = [];
}

// Cache for Ghidra base address per module
var bnBaseCache = {};

// HELPER: Get Ghidra base address for a module
// Ghidra uses __TEXT vmaddr directly (no rebasing for dylibs)
function getGhidraBase(module) {
    if (bnBaseCache[module.path]) {
        return bnBaseCache[module.path];
    }

    var ghidraBase = ptr(0);

    try {
        var header = module.base;
        var magic = header.readU32();

        if (magic === 0xfeedfacf) {  // MH_MAGIC_64
            var ncmds = header.add(16).readU32();
            var cmdPtr = header.add(32);

            // Find __TEXT segment vmaddr
            for (var i = 0; i < ncmds && i < 50; i++) {
                var cmd = cmdPtr.readU32();
                var cmdsize = cmdPtr.add(4).readU32();

                if (cmd === 0x19) {  // LC_SEGMENT_64
                    var segname = cmdPtr.add(8).readUtf8String();
                    if (segname && segname.indexOf('__TEXT') === 0) {
                        ghidraBase = ptr(cmdPtr.add(24).readU64());
                        break;
                    }
                }
                cmdPtr = cmdPtr.add(cmdsize);
            }
        }
    } catch (e) {
        // Fall back to 0
    }

    bnBaseCache[module.path] = ghidraBase;
    return ghidraBase;
}

// HELPER: Calculate Ghidra offset from runtime address
function getGhidraOffset(addr, module) {
    var runtimeOffset = addr.sub(module.base);
    var ghidraBase = getGhidraBase(module);
    var ghidraAddr = runtimeOffset.add(ghidraBase);
    return '0x' + ghidraAddr.toString(16);
}

// HELPER: Print formatted method information
function printMethodInfo(interactionType, target, selector, eventHandle) {
    // Safety check: if selector is missing, we can't identify the function
    if (!selector) return;

    // 1. Resolve Names
    var selectorName = ObjC.selectorAsString(selector);

    // Enhanced safety checks for target - handle cases where target might not be a proper pointer
    var targetObj = null;
    if (target) {
        try {
            // Check if target has isNull method (proper NativePointer) before calling it
            if (typeof target.isNull === 'function' && !target.isNull()) {
                targetObj = new ObjC.Object(target);
            } else if (typeof target === 'object' && target.handle && !target.handle.isNull()) {
                // Handle case where target might already be an ObjC.Object
                targetObj = target;
            }
        } catch (e) {
            // If we can't convert to ObjC.Object, target is invalid - continue anyway
            console.log("  [Debug] Could not resolve target: " + e.message);
        }
    }
    var targetClassName = targetObj ? targetObj.$className : "nil (Responder Chain)";

    console.log("\n[+] " + interactionType + " Detected");
    console.log("--------------------------------------------------");
    console.log("  Selector: " + selectorName);
    console.log("  Target:   " + targetClassName);

    // 2. Resolve Event Details (if provided)
    if (eventHandle) {
        try {
            if (typeof eventHandle.isNull === 'function' && !eventHandle.isNull()) {
                var event = new ObjC.Object(eventHandle);
                // .toString() on UIEvent returns the detailed description (timestamps, touches, etc.)
                console.log("  Event:    " + event.toString());
            } else if (interactionType === "UIControl Action") {
                console.log("  Event:    nil (Likely programmatic trigger)");
            }
        } catch (e) {
            console.log("  Event:    (Could not resolve: " + e.message + ")");
        }
    } else if (interactionType === "UIControl Action") {
        console.log("  Event:    nil (Likely programmatic trigger)");
    }

    // 3. Calculate Static Analysis Offsets
    if (targetObj) {
        try {
            // Ask the target where the code for this selector lives in memory
            var implementation = targetObj.methodForSelector_(selector);

            if (implementation && !implementation.isNull()) {
                // Find which binary module owns this address
                var module = Process.findModuleByAddress(implementation);

                if (module) {
                    // Calculate Ghidra offset (accounts for dylib rebasing)
                    var ghidraAddr = getGhidraOffset(implementation, module);

                    console.log("\n  [Binary Location]");
                    console.log("  |-- Module:  " + module.name);
                    console.log("  |-- Address: " + implementation);
                    console.log("  |-- Ghidra: " + ghidraAddr + "  <-- GO HERE IN DISASSEMBLER");
                } else {
                    console.log("\n  [Binary Location]");
                    console.log("  |-- Address: " + implementation + " (Module not found)");
                }
            }
        } catch (e) {
            console.log("\n  [Binary Location]");
            console.log("  |-- (Could not resolve method: " + e.message + ")");
        }
    }
    console.log("--------------------------------------------------\n");
}

// HELPER: Print Swift function information with binary location
function printSwiftFunctionInfo(label, address, module) {
    var ghidraAddr = getGhidraOffset(address, module);

    console.log("\n[+] SwiftUI Button Action Handler");
    console.log("--------------------------------------------------");
    console.log("  " + label);
    console.log("\n  [Binary Location]");
    console.log("  |-- Module:  " + module.name);
    console.log("  |-- Address: " + address);
    console.log("  |-- Ghidra: " + ghidraAddr + "  <-- GO HERE IN DISASSEMBLER");
    console.log("--------------------------------------------------\n");
}

// HELPER: Try to demangle Swift symbol name
function tryDemangleSwift(mangledName) {
    // Simple Swift demangling for common patterns
    // Full demangling would require swift-demangle binary
    if (!mangledName || mangledName.indexOf('$s') === -1) {
        return mangledName;
    }

    // Try to extract meaningful parts from mangled name
    // Swift mangling: $s<module length><module><rest>
    try {
        var demangled = mangledName;
        // Remove leading _$s or $s
        if (demangled.startsWith('_$s')) {
            demangled = demangled.substring(3);
        } else if (demangled.startsWith('$s')) {
            demangled = demangled.substring(2);
        }
        return mangledName + " (Swift)";
    } catch (e) {
        return mangledName;
    }
}

function installUIHooks() {
    if (_trellisUiHooksInstalled) return;
    _trellisUiHooksInstalled = true;

    if (!ObjC.available) {
        console.log("[-] Error: Objective-C Runtime not available.");
        return;
    }

    // Get app modules info (Frida 17 compatible)
    // On jailbroken devices, the first module might be a hook dylib, not the app
    // We need to find ALL modules in the app bundle (main binary + embedded frameworks)
    function findAppModules() {
        var modules = Process.enumerateModules();
        var appModules = [];
        var mainModule = null;
        var appBundlePath = null;

        // First pass: find modules in app bundle and determine bundle path
        for (var i = 0; i < modules.length; i++) {
            var mod = modules[i];
            // App binaries are typically in /var/containers/Bundle/Application/
            // or /private/var/containers/Bundle/Application/
            if (mod.path.indexOf('/Bundle/Application/') !== -1 &&
                mod.path.indexOf('.app/') !== -1) {

                // Extract the .app bundle path
                if (!appBundlePath) {
                    var appMatch = mod.path.match(/.*\.app\//);
                    if (appMatch) {
                        appBundlePath = appMatch[0];
                    }
                }

                appModules.push(mod);

                // The main executable has no .framework or .dylib extension
                if (mod.path.indexOf('.framework') === -1 &&
                    mod.path.indexOf('.dylib') === -1) {
                    mainModule = mod;
                }
            }
        }

        // Fallback: find by excluding known system paths
        if (!mainModule) {
            for (var i = 0; i < modules.length; i++) {
                var mod = modules[i];
                var path = mod.path.toLowerCase();
                // Skip system libraries and jailbreak hooks
                if (path.indexOf('/system/') === -1 &&
                    path.indexOf('/usr/lib/') === -1 &&
                    path.indexOf('substrate') === -1 &&
                    path.indexOf('substitute') === -1 &&
                    path.indexOf('systemhook') === -1 &&
                    path.indexOf('ellekit') === -1 &&
                    path.indexOf('libhooker') === -1) {
                    if (!mainModule) mainModule = mod;
                    if (appModules.indexOf(mod) === -1) {
                        appModules.push(mod);
                    }
                }
            }
        }

        // Ultimate fallback
        if (!mainModule) {
            mainModule = modules[0];
        }
        if (appModules.length === 0) {
            appModules.push(mainModule);
        }

        return {
            main: mainModule,
            all: appModules,
            bundlePath: appBundlePath
        };
    }

    // Helper: Check if an address belongs to any app module
    function findAppModuleForAddress(address, appModules) {
        for (var i = 0; i < appModules.length; i++) {
            var mod = appModules[i];
            var modEnd = mod.base.add(mod.size);
            if (address.compare(mod.base) >= 0 && address.compare(modEnd) < 0) {
                return mod;
            }
        }
        return null;
    }

    var appInfo = findAppModules();
    var mainAppModule = appInfo.main;
    var allAppModules = appInfo.all;
    var swiftUIModule = Process.findModuleByName("SwiftUI");

    console.log("[*] Trellis UI Interaction Hooks");
    console.log("[*] Main app: " + mainAppModule.name);
    console.log("[*] Path: " + mainAppModule.path);
    console.log("[*] Base address: " + mainAppModule.base);
    console.log("[*] App modules found: " + allAppModules.length);
    for (var i = 0; i < allAppModules.length; i++) {
        console.log("    - " + allAppModules[i].name);
    }

    // --- HOOK 1: UIControl (Standard Buttons, Switches, Sliders) ---
    var UIControl = ObjC.classes.UIControl;

    if (UIControl) {
        var sendAction = UIControl["- sendAction:to:forEvent:"];
        if (sendAction && sendAction.implementation) {
            Interceptor.attach(sendAction.implementation, {
                onEnter: function (args) {
                    // args[2] = Selector (SEL)
                    // args[3] = Target (id)
                    // args[4] = Event (UIEvent)
                    printMethodInfo("UIControl Action", args[3], args[2], args[4]);
                }
            });
            console.log("[*] Hooked UIControl sendAction:to:forEvent:");
        } else {
            console.log("[-] Warning: 'sendAction:to:forEvent:' not found on UIControl.");
        }
    }

    // --- HOOK 2: UIGestureRecognizer (Popups, Custom Views, Tap to Dismiss) ---
    var UIGestureRecognizer = ObjC.classes.UIGestureRecognizer;

    if (UIGestureRecognizer) {
        // We hook 'setState:' to detect when a gesture is recognized
        var setState = UIGestureRecognizer["- setState:"];

        if (setState && setState.implementation) {
            Interceptor.attach(setState.implementation, {
                onEnter: function (args) {
                    // args[0] = Self (The Gesture Recognizer instance)
                    // args[2] = State (NSInteger)

                    // State 3 corresponds to UIGestureRecognizerStateEnded / Recognized
                    var state = args[2].toInt32();

                    if (state === 3) {
                        var gesture = new ObjC.Object(args[0]);

                        // Access the private '_targets' list which holds the destinations
                        // Note: This uses KVC (valueForKey) which is standard ObjC
                        var targets = gesture.valueForKey_("_targets");

                        if (targets) {
                            var count = targets.count().valueOf();
                            for (var i = 0; i < count; i++) {
                                try {
                                    var internalTarget = targets.objectAtIndex_(i);

                                    // ACCESS PRIVATE IVARS SAFELY using $ivars
                                    // 'internalTarget' is a private class (UIGestureRecognizerTarget)
                                    // It holds the real destination (_target) and the method (_action)
                                    var realTarget = internalTarget.$ivars["_target"];
                                    var actionSel  = internalTarget.$ivars["_action"];

                                    // Validate that we got valid values before passing to printMethodInfo
                                    // actionSel should be a selector (SEL), realTarget should be an object pointer
                                    if (actionSel && realTarget) {
                                        // Check if this is a SwiftUI bridge - if so, skip (we trace it separately)
                                        var selectorName = ObjC.selectorAsString(actionSel);
                                        if (selectorName === 'flushActions') {
                                            // This is SwiftUI - handled by our dedicated Stalker hook
                                            return;
                                        }
                                        // Pass null for eventHandle since gestures don't pass a UIEvent object here
                                        printMethodInfo("Gesture Interaction", realTarget, actionSel, null);
                                    }
                                } catch (e) {
                                    console.log("[-] Warning: Could not process gesture target: " + e.message);
                                }
                            }
                        }
                    }
                }
            });
            console.log("[*] Hooked UIGestureRecognizer setState:");
        } else {
             console.log("[-] Warning: 'setState:' not found on UIGestureRecognizer.");
        }
    }

    // --- HOOK 3: SwiftUI Button Actions ---
    // SwiftUI uses closures instead of target-action. We need to trace
    // the actual function calls that happen when a button action fires.

    // Find the SwiftUI bridge class - it might be registered under different names
    var swiftuiBridge = ObjC.classes.UIKitResponderEventBindingBridge ||
                        ObjC.classes['SwiftUI.UIKitResponderEventBindingBridge'] ||
                        ObjC.classes['_TtC7SwiftUI34UIKitResponderEventBindingBridge'];

    // If not found by name, search for it
    if (!swiftuiBridge) {
        var allClasses = ObjC.classes;
        for (var className in allClasses) {
            if (className.indexOf('ResponderEventBindingBridge') !== -1 ||
                className.indexOf('EventBindingBridge') !== -1) {
                console.log("[*] Found bridge class: " + className);
                swiftuiBridge = allClasses[className];
                break;
            }
        }
    }

    if (swiftuiBridge) {
        console.log("[*] SwiftUI detected - enabling closure tracing");
        console.log("[*] Bridge class: " + swiftuiBridge.$className);

        var flushActions = swiftuiBridge["- flushActions"];
        if (flushActions && flushActions.implementation) {

            // Use Stalker to trace function calls during flushActions
            Interceptor.attach(flushActions.implementation, {
                onEnter: function(args) {
                    this.tid = Process.getCurrentThreadId();
                    this.startTime = Date.now();
                    this.calledFunctions = [];

                    var self = this;

                    // Start Stalker to trace all calls during the action
                    Stalker.follow(this.tid, {
                        events: {
                            call: true,
                            ret: false,
                            exec: false,
                            block: false,
                            compile: false
                        },

                        onCallSummary: function(summary) {
                            // This is called when stalking ends
                            // summary is a map of target addresses to call counts
                            var totalCalls = Object.keys(summary).length;
                            if (DEBUG_STALKER) {
                                console.log("[DEBUG] Stalker captured " + totalCalls + " unique call targets");
                            }

                            for (var addr in summary) {
                                var targetAddr = ptr(addr);

                                // Check if this call target is in ANY app module
                                var targetModule = findAppModuleForAddress(targetAddr, allAppModules);
                                if (targetModule) {
                                    self.calledFunctions.push({
                                        address: targetAddr,
                                        count: summary[addr],
                                        module: targetModule
                                    });
                                    if (DEBUG_STALKER) {
                                        var sym = DebugSymbol.fromAddress(targetAddr);
                                        console.log("[DEBUG] App call: " + targetAddr + " in " + targetModule.name +
                                            (sym ? " (" + sym.name + ")" : ""));
                                    }
                                }
                            }

                            if (DEBUG_STALKER) {
                                console.log("[DEBUG] Found " + self.calledFunctions.length + " calls to app modules");
                            }
                        }
                    });
                },

                onLeave: function(retval) {
                    // Stop stalking
                    Stalker.unfollow(this.tid);
                    Stalker.flush();

                    var duration = Date.now() - this.startTime;

                    // Filter and display results
                    if (this.calledFunctions.length > 0) {
                        // Sort by address to group related functions
                        this.calledFunctions.sort(function(a, b) {
                            return a.address.compare(b.address);
                        });

                        // Find the most likely button handler
                        // Usually it's the first unique function called in the app module
                        // that isn't a common runtime function

                        var bestCandidate = null;
                        var seenAddresses = {};

                        for (var i = 0; i < this.calledFunctions.length; i++) {
                            var func = this.calledFunctions[i];
                            var addrStr = func.address.toString();

                            if (seenAddresses[addrStr]) continue;
                            seenAddresses[addrStr] = true;

                            // Try to get symbol name
                            var sym = DebugSymbol.fromAddress(func.address);
                            var symName = sym ? sym.name : null;

                            // Skip common Swift runtime functions
                            if (symName) {
                                var lowerName = symName.toLowerCase();
                                if (lowerName.indexOf('swift_') === 0 ||
                                    lowerName.indexOf('_swift') === 0 ||
                                    lowerName.indexOf('objc_') === 0 ||
                                    lowerName.indexOf('_objc') === 0) {
                                    continue;
                                }
                            }

                            // This is likely our button handler
                            if (!bestCandidate) {
                                bestCandidate = {
                                    address: func.address,
                                    symbol: symName,
                                    count: func.count,
                                    module: func.module
                                };
                            }
                        }

                        if (bestCandidate) {
                            var targetMod = bestCandidate.module || mainAppModule;
                            var ghidraAddr = getGhidraOffset(bestCandidate.address, targetMod);
                            var displayName = bestCandidate.symbol ?
                                tryDemangleSwift(bestCandidate.symbol) :
                                "(anonymous closure)";

                            console.log("\n[+] SwiftUI Button Action Detected");
                            console.log("--------------------------------------------------");
                            console.log("  Handler: " + displayName);
                            if (bestCandidate.symbol) {
                                console.log("  Symbol:  " + bestCandidate.symbol);
                            }
                            console.log("  Duration: " + duration + "ms");
                            console.log("\n  [Binary Location]");
                            console.log("  |-- Module:  " + targetMod.name);
                            console.log("  |-- Address: " + bestCandidate.address);
                            console.log("  |-- Ghidra: " + ghidraAddr + "  <-- GO HERE IN DISASSEMBLER");
                            console.log("--------------------------------------------------\n");
                        } else {
                            // No good candidate found, show all unique functions
                            console.log("\n[+] SwiftUI Button Action Detected");
                            console.log("--------------------------------------------------");
                            console.log("  Duration: " + duration + "ms");
                            console.log("  App functions called: " + Object.keys(seenAddresses).length);

                            // Show first few
                            var shown = 0;
                            for (var addr in seenAddresses) {
                                if (shown >= 5) {
                                    console.log("  ... and " + (Object.keys(seenAddresses).length - shown) + " more");
                                    break;
                                }
                                var a = ptr(addr);
                                var s = DebugSymbol.fromAddress(a);
                                var bnOff = getGhidraOffset(a, mainAppModule);
                                console.log("  |-- " + bnOff + ": " + (s ? s.name : "(unnamed)"));
                                shown++;
                            }
                            console.log("--------------------------------------------------\n");
                        }
                    } else {
                        // No app functions called - provide debugging help
                        console.log("\n[+] SwiftUI Button Action Detected");
                        console.log("--------------------------------------------------");
                        console.log("  Note: No app-specific handler found in traced modules");
                        console.log("  Duration: " + duration + "ms");
                        console.log("\n  Monitored modules:");
                        for (var i = 0; i < allAppModules.length; i++) {
                            console.log("    - " + allAppModules[i].name);
                        }
                        console.log("\n  Tip: Set DEBUG_STALKER=true at top of script for details");
                        console.log("--------------------------------------------------\n");
                    }

                    // Clear for garbage collection
                    this.calledFunctions = null;
                }
            });

            console.log("[*] Hooked SwiftUI flushActions with Stalker tracing");
        }
    } else {
        // Fallback: Try to hook flushActions via symbol lookup in SwiftUI module
        console.log("[*] Bridge class not found via ObjC.classes, trying symbol lookup...");

        if (swiftUIModule) {
            var flushActionsAddr = null;

            // Search for flushActions symbol in SwiftUI
            for (var exp of swiftUIModule.enumerateExports()) {
                if (exp.name.indexOf('flushActions') !== -1) {
                    console.log("[*] Found symbol: " + exp.name + " at " + exp.address);
                    flushActionsAddr = exp.address;
                    break;
                }
            }

            if (flushActionsAddr) {
                console.log("[*] Hooking flushActions via symbol address");

                Interceptor.attach(flushActionsAddr, {
                    onEnter: function(args) {
                        this.tid = Process.getCurrentThreadId();
                        this.startTime = Date.now();
                        this.calledFunctions = [];

                        var self = this;

                        Stalker.follow(this.tid, {
                            events: { call: true },
                            onCallSummary: function(summary) {
                                var totalCalls = Object.keys(summary).length;
                                if (DEBUG_STALKER) {
                                    console.log("[DEBUG] Stalker captured " + totalCalls + " unique call targets");
                                }

                                for (var addr in summary) {
                                    var targetAddr = ptr(addr);
                                    // Check if this call target is in ANY app module
                                    var targetModule = findAppModuleForAddress(targetAddr, allAppModules);
                                    if (targetModule) {
                                        self.calledFunctions.push({
                                            address: targetAddr,
                                            count: summary[addr],
                                            module: targetModule
                                        });
                                        if (DEBUG_STALKER) {
                                            var sym = DebugSymbol.fromAddress(targetAddr);
                                            console.log("[DEBUG] App call: " + targetAddr + " in " + targetModule.name +
                                                (sym ? " (" + sym.name + ")" : ""));
                                        }
                                    }
                                }

                                if (DEBUG_STALKER) {
                                    console.log("[DEBUG] Found " + self.calledFunctions.length + " calls to app modules");
                                }
                            }
                        });
                    },
                    onLeave: function(retval) {
                        Stalker.unfollow(this.tid);
                        Stalker.flush();

                        var duration = Date.now() - this.startTime;

                        if (this.calledFunctions.length > 0) {
                            var bestCandidate = null;
                            var seenAddresses = {};

                            for (var i = 0; i < this.calledFunctions.length; i++) {
                                var func = this.calledFunctions[i];
                                var addrStr = func.address.toString();
                                if (seenAddresses[addrStr]) continue;
                                seenAddresses[addrStr] = true;

                                var sym = DebugSymbol.fromAddress(func.address);
                                var symName = sym ? sym.name : null;

                                if (symName) {
                                    var lowerName = symName.toLowerCase();
                                    if (lowerName.indexOf('swift_') === 0 ||
                                        lowerName.indexOf('_swift') === 0 ||
                                        lowerName.indexOf('objc_') === 0 ||
                                        lowerName.indexOf('_objc') === 0) {
                                        continue;
                                    }
                                }

                                if (!bestCandidate) {
                                    bestCandidate = {
                                        address: func.address,
                                        symbol: symName,
                                        count: func.count,
                                        module: func.module
                                    };
                                }
                            }

                            if (bestCandidate) {
                                var targetMod = bestCandidate.module || mainAppModule;
                                var ghidraAddr = getGhidraOffset(bestCandidate.address, targetMod);
                                var displayName = bestCandidate.symbol ?
                                    tryDemangleSwift(bestCandidate.symbol) : "(anonymous closure)";

                                console.log("\n[+] SwiftUI Button Action Detected");
                                console.log("--------------------------------------------------");
                                console.log("  Handler: " + displayName);
                                if (bestCandidate.symbol) {
                                    console.log("  Symbol:  " + bestCandidate.symbol);
                                }
                                console.log("  Duration: " + duration + "ms");
                                console.log("\n  [Binary Location]");
                                console.log("  |-- Module:  " + targetMod.name);
                                console.log("  |-- Address: " + bestCandidate.address);
                                console.log("  |-- Ghidra: " + ghidraAddr + "  <-- GO HERE IN DISASSEMBLER");
                                console.log("--------------------------------------------------\n");
                            }
                        }
                        this.calledFunctions = null;
                    }
                });
            } else {
                console.log("[*] No SwiftUI bridge detected (UIKit-only app or unable to find symbol)");
            }
        } else {
            console.log("[*] No SwiftUI module loaded (UIKit-only app)");
        }
    }

    // --- HOOK 4: Additional SwiftUI entry points ---
    // Hook performAction methods that might be used by SwiftUI

    var uiAction = ObjC.classes.UIAction;
    if (uiAction) {
        var performWithSender = uiAction["- performWithSender:target:"];
        if (performWithSender && performWithSender.implementation) {
            Interceptor.attach(performWithSender.implementation, {
                onEnter: function(args) {
                    var action = new ObjC.Object(args[0]);
                    var sender = args[2];
                    var target = args[3];

                    console.log("\n[+] UIAction Performed");
                    console.log("--------------------------------------------------");
                    console.log("  Action: " + action.toString());

                    // Try to get the action's handler
                    try {
                        var title = action.title();
                        if (title) {
                            console.log("  Title: " + title);
                        }
                    } catch(e) {}

                    // Get the handler block if available
                    try {
                        var handler = action.valueForKey_("handler");
                        if (handler && !handler.isNull()) {
                            // Handler is a block - try to get its invoke pointer
                            var blockPtr = handler.handle;
                            // Block layout: isa, flags, reserved, invoke, descriptor
                            var invokePtr = blockPtr.add(Process.pointerSize * 2).readPointer();
                            var module = Process.findModuleByAddress(invokePtr);

                            if (module && module.name === mainAppModule.name) {
                                var ghidraAddr = getGhidraOffset(invokePtr, module);
                                console.log("\n  [Binary Location]");
                                console.log("  |-- Module:  " + module.name);
                                console.log("  |-- Address: " + invokePtr);
                                console.log("  |-- Ghidra: " + ghidraAddr + "  <-- GO HERE IN DISASSEMBLER");
                            }
                        }
                    } catch(e) {
                        console.log("  [Could not resolve handler: " + e.message + "]");
                    }

                    console.log("--------------------------------------------------\n");
                }
            });
            console.log("[*] Hooked UIAction performWithSender:target:");
        }
    }

    console.log("\\n[*] UI Interaction hooks installed successfully");
    console.log("[*] Tap buttons/controls to see handler locations\\n");
}

// Early capture (install immediately)
if (TRELLIS_UI_CONFIG.earlyCapture) {
    installUIHooks();
}

// Lazy loading (default)
if (TRELLIS_UI_CONFIG.useLazyLoading) {
    trellisUiDeferHooksUntilReady(installUIHooks);
} else if (!TRELLIS_UI_CONFIG.earlyCapture) {
    installUIHooks();
}
