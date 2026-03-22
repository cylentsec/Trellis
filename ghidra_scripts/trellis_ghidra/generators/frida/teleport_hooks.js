/**
 * Trellis GPS Teleporter
 * ----------------------
 * Spoof GPS location for iOS apps by hooking CLLocation.
 *
 * Features:
 * - Hooks -[CLLocation coordinate] to return custom coordinates
 * - Provides move(lat, lng) function for real-time location changes
 * - Useful for testing geofencing, location-based features, and CTFs
 *
 * Compatible with Frida 17+
 *
 * Usage:
 *     frida -U -f com.example.app -l teleport_hooks.js
 *
 * Then in the Frida console:
 *     move(37.7749, -122.4194)  // Teleport to San Francisco
 *     move(51.5074, -0.1278)    // Teleport to London
 *     move(35.6762, 139.6503)   // Teleport to Tokyo
 */

// Runtime config (lazy loading + early capture)
var TRELLIS_TELEPORT_CONFIG = { useLazyLoading: true, earlyCapture: false };

// Default starting location (customize as needed)
globalThis.lat = 37.7749;   // San Francisco
globalThis.lng = -122.4194;

var _trellisTeleportStarted = false;

function startTeleportHooks() {
    if (_trellisTeleportStarted) return;
    _trellisTeleportStarted = true;

    if (typeof ObjC === 'undefined' || !ObjC.available) {
        console.log("[-] Objective-C Runtime not available!");
        return;
    }

    console.log("[*] Trellis GPS Teleporter Loaded");
    console.log("[*] Current location: " + globalThis.lat + ", " + globalThis.lng);
    console.log("[*] Use move(lat, lng) in console to teleport");
    console.log("");

    try {
        // Hook -[CLLocation coordinate]
        // This is called by apps to read GPS coordinates
        var CLLocation = ObjC.classes.CLLocation;
        var method = CLLocation["- coordinate"];

        if (!method || !method.implementation) {
            throw new Error("CLLocation coordinate method not found");
        }

        Interceptor.attach(method.implementation, {
            onLeave: function () {
                // On ARM64, CLLocationCoordinate2D (two doubles) is returned
                // via registers d0 (latitude) and d1 (longitude)
                this.context.d0 = globalThis.lat;
                this.context.d1 = globalThis.lng;
            }
        });

        console.log("[+] Hooked -[CLLocation coordinate]");
        console.log("[+] All location queries will return spoofed coordinates");
        console.log("");

    } catch (err) {
        console.log("[-] Error hooking CLLocation: " + err.message);
    }

    // Helper function for easy teleportation from Frida console
    globalThis.move = function(newLat, newLng) {
        globalThis.lat = newLat;
        globalThis.lng = newLng;
        console.log("[*] Teleported to: " + globalThis.lat + ", " + globalThis.lng);
    };

    // Preset locations for convenience
    globalThis.teleport = {
        sanfrancisco: function() { globalThis.move(37.7749, -122.4194); },
        newyork: function() { globalThis.move(40.7128, -74.0060); },
        london: function() { globalThis.move(51.5074, -0.1278); },
        tokyo: function() { globalThis.move(35.6762, 139.6503); },
        sydney: function() { globalThis.move(-33.8688, 151.2093); },
        paris: function() { globalThis.move(48.8566, 2.3522); },
        berlin: function() { globalThis.move(52.5200, 13.4050); },
        moscow: function() { globalThis.move(55.7558, 37.6173); },
        beijing: function() { globalThis.move(39.9042, 116.4074); },
        dubai: function() { globalThis.move(25.2048, 55.2708); }
    };

    console.log("[*] Preset locations available:");
    console.log("    teleport.sanfrancisco()");
    console.log("    teleport.newyork()");
    console.log("    teleport.london()");
    console.log("    teleport.tokyo()");
    console.log("    teleport.sydney()");
    console.log("    teleport.paris()");
    console.log("    ... and more (berlin, moscow, beijing, dubai)");
    console.log("");
}

function trellisTeleportDeferHooksUntilReady(hookInstaller) {
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
        if (!_trellisTeleportStarted) {
            hookInstaller();
        }
    }, 2000);
}

// Early capture (install immediately)
if (TRELLIS_TELEPORT_CONFIG.earlyCapture) {
    startTeleportHooks();
}

// Lazy loading (default)
if (TRELLIS_TELEPORT_CONFIG.useLazyLoading) {
    trellisTeleportDeferHooksUntilReady(startTeleportHooks);
} else if (!TRELLIS_TELEPORT_CONFIG.earlyCapture) {
    startTeleportHooks();
}
