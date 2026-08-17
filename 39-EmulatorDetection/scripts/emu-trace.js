// scripts/emu-trace.js
//
// PURPOSE
//   Find out WHICH emulator signal an app actually reads, and which one made it
//   decide. This is a tracer, not a bypass: it changes nothing and hides
//   nothing. Run it BEFORE you write a single hook.
//
//   The reason is economic. An app may contain twenty emulator checks and
//   execute three. Hooking blind means guessing which three, and the usual
//   outcome is an hour spent neutralising File.exists() in an app whose real
//   check was the sensor list. Tracing first turns that hour into a minute.
//
//   It traces both layers, because they need different tools:
//     Java layer   -- SystemProperties, Build, File, Sensors, PackageManager,
//                     TelephonyManager
//     Native layer -- __system_property_get/find/foreach, access, stat, open,
//                     openat, fopen
//
//   A Java hook does NOT see a native property read. If the Java trace comes
//   back empty and the native trace does not, the check is in C and your bypass
//   has to move down a layer. That single fact is usually the most valuable
//   thing this script tells you.
//
// USAGE
//   # host -- ALWAYS spawn with -f, never attach with -p (see the warning below)
//   frida -U -f com.example.app -l emu-trace.js
//
//   # host -- with output to a file for a long session
//   frida -U -f com.example.app -l emu-trace.js -o trace.txt
//
//   # host -- summary only, no per-call lines (quieter on a chatty app)
//   #   edit CONFIG.verbose below, or from the REPL:
//   #   > cfg({verbose:false})
//
//   From the Frida REPL while it runs:
//     > summary()          print the tally so far
//     > cfg({stacks:true}) turn Java stack traces on
//
// WHY -f AND NOT -p
//   Many checks run in a static initialiser or in Application.onCreate, and
//   native checks run in JNI_OnLoad -- all of which execute before you can
//   attach to an already-running process. `frida -U -f` spawns suspended and
//   installs hooks first. `-p` attaches to something that already decided.
//   This is the single most common reason a trace comes back empty.
//
// AUTHORISED TESTING ONLY. Trace apps you own or are contracted to assess.

'use strict';

var CONFIG = {
    verbose: true,     // one line per observed read
    stacks: false,     // Java stack trace for each property read (noisy but decisive)
    native: true,      // hook libc as well as Java
    maxLines: 4000     // stop printing after this many, keep counting
};

var TALLY = {};        // signal -> count
var LINES = 0;

function bump(key) {
    TALLY[key] = (TALLY[key] || 0) + 1;
}

function say(tag, msg) {
    bump(tag);
    if (!CONFIG.verbose) { return; }
    if (LINES >= CONFIG.maxLines) { return; }
    LINES++;
    console.log('[' + tag + '] ' + msg);
    if (LINES === CONFIG.maxLines) {
        console.log('--- maxLines reached; still counting, call summary() ---');
    }
}

// Anything matching this is worth reporting; everything else is noise. Apps read
// hundreds of properties for legitimate reasons and printing them all buries the
// signal you came for.
var INTERESTING = /qemu|goldfish|ranchu|emulat|genymo|vbox|bluestack|nox|hardware|characteristics|cpu\.abi|native\.bridge|serialno|build\.tags|build\.type|product\.(model|name|device|board)|soc\.model|kernel|boot\./i;

var INTERESTING_PATH = /qemu|goldfish|ranchu|genyd|vbox|androVM|microvirt|cpuinfo|\/proc\/modules|tty\/drivers|cmdline|self\/(maps|mounts)/i;

// --------------------------------------------------------------------------- //
// Java layer
// --------------------------------------------------------------------------- //

function javaStack() {
    try {
        var Exception = Java.use('java.lang.Exception');
        var Log = Java.use('android.util.Log');
        return Log.getStackTraceString(Exception.$new());
    } catch (e) {
        return '(stack unavailable)';
    }
}

// Give the caller in one short line: the first frame that is not framework code.
function caller() {
    try {
        var Thread = Java.use('java.lang.Thread');
        var frames = Thread.currentThread().getStackTrace();
        for (var i = 0; i < frames.length; i++) {
            var cn = frames[i].getClassName();
            if (cn.indexOf('java.lang.Thread') === 0) { continue; }
            if (cn.indexOf('android.os.SystemProperties') === 0) { continue; }
            if (cn.indexOf('android.os.Build') === 0) { continue; }
            if (cn.indexOf('java.io.File') === 0) { continue; }
            if (cn.indexOf('dalvik.system') === 0) { continue; }
            if (cn.indexOf('com.android.internal.os') === 0) { continue; }
            return cn + '.' + frames[i].getMethodName() +
                   '(' + frames[i].getFileName() + ':' + frames[i].getLineNumber() + ')';
        }
    } catch (e) { /* the stack is best-effort; never let it break the trace */ }
    return '?';
}

function traceJava() {

    // ---- system properties -------------------------------------------------
    // Every Build field was populated through this method too, but that happened
    // at class-init before we attached -- so this catches RUNTIME reads only.
    try {
        var SP = Java.use('android.os.SystemProperties');
        SP.get.overload('java.lang.String').implementation = function (k) {
            var v = this.get(k);
            if (INTERESTING.test(k)) {
                say('prop', pad(k, 34) + ' -> ' + JSON.stringify(v) + '   <- ' + caller());
                if (CONFIG.stacks) { console.log(javaStack()); }
            }
            return v;
        };
        SP.get.overload('java.lang.String', 'java.lang.String')
          .implementation = function (k, d) {
            var v = this.get(k, d);
            if (INTERESTING.test(k)) {
                say('prop', pad(k, 34) + ' -> ' + JSON.stringify(v) + '   <- ' + caller());
            }
            return v;
        };
    } catch (e) {
        console.log('[!] SystemProperties not hookable: ' + e);
    }

    // ---- Build fields ------------------------------------------------------
    // The values are static finals, latched long ago -- there is no getter to
    // hook. So instead of tracing reads, we PRINT what the app will see. If any
    // of these look like an emulator, the app can see that too.
    try {
        var B = Java.use('android.os.Build');
        console.log('--- Build fields as the app will read them ---');
        ['FINGERPRINT', 'MODEL', 'BRAND', 'DEVICE', 'PRODUCT', 'MANUFACTURER',
         'HARDWARE', 'BOARD', 'BOOTLOADER', 'TAGS', 'TYPE', 'HOST', 'USER']
        .forEach(function (f) {
            try { console.log('    Build.' + pad(f, 14) + ' = ' + B[f].value); }
            catch (e) { /* field absent on this API level */ }
        });
        try {
            console.log('    Build.SUPPORTED_ABIS = ' + B.SUPPORTED_ABIS.value);
        } catch (e) { /* API < 21 */ }
        console.log('----------------------------------------------');
    } catch (e) {
        console.log('[!] Build not readable: ' + e);
    }

    // ---- filesystem --------------------------------------------------------
    try {
        var F = Java.use('java.io.File');
        ['exists', 'canRead', 'isFile', 'isDirectory'].forEach(function (m) {
            if (!F[m]) { return; }
            F[m].implementation = function () {
                var r = this[m]();
                var p = this.getAbsolutePath();
                if (INTERESTING_PATH.test(p)) {
                    say('file', m + '("' + p + '") -> ' + r + '   <- ' + caller());
                }
                return r;
            };
        });
    } catch (e) {
        console.log('[!] java.io.File not hookable: ' + e);
    }

    // ---- sensors -----------------------------------------------------------
    // The strongest Java-reachable signal. Report the COUNT and the vendor
    // distribution, because that is what a good check looks at -- not the count
    // alone. Measured: 41 sensors / 0 AOSP-vendored on a Redmi; 18 / 18 on an AVD.
    try {
        var SM = Java.use('android.hardware.SensorManager');
        SM.getSensorList.implementation = function (type) {
            var list = this.getSensorList(type);
            var n = list.size();
            var aosp = 0;
            var vendors = {};
            for (var i = 0; i < n; i++) {
                var v = list.get(i).getVendor();
                vendors[v] = true;
                if (v && (v.indexOf('AOSP') >= 0 ||
                          v.indexOf('The Android Open Source Project') >= 0 ||
                          v.indexOf('Goldfish') >= 0)) { aosp++; }
            }
            say('sensor', 'getSensorList(' + type + ') -> ' + n + ' sensors, ' +
                aosp + ' AOSP-vendored, vendors=' + JSON.stringify(Object.keys(vendors)) +
                '   <- ' + caller());
            return list;
        };
        SM.getDefaultSensor.overload('int').implementation = function (t) {
            var s = this.getDefaultSensor(t);
            say('sensor', 'getDefaultSensor(' + t + ') -> ' +
                (s === null ? 'null' : s.getName()) + '   <- ' + caller());
            return s;
        };
    } catch (e) {
        console.log('[!] SensorManager not hookable: ' + e);
    }

    // ---- packages ----------------------------------------------------------
    try {
        var PM = Java.use('android.app.ApplicationPackageManager');
        PM.getInstalledPackages.overload('int').implementation = function (f) {
            var l = this.getInstalledPackages(f);
            say('pkg', 'getInstalledPackages(' + f + ') -> ' + l.size() +
                ' packages (API 30+ FILTERS this)   <- ' + caller());
            return l;
        };
        PM.getPackageInfo.overload('java.lang.String', 'int')
          .implementation = function (p, f) {
            try {
                var r = this.getPackageInfo(p, f);
                if (/emulat|genymo|bluestack|nox|vbox|goldfish/i.test(p)) {
                    say('pkg', 'getPackageInfo("' + p + '") -> FOUND   <- ' + caller());
                }
                return r;
            } catch (e) {
                if (/emulat|genymo|bluestack|nox|vbox|goldfish/i.test(p)) {
                    say('pkg', 'getPackageInfo("' + p + '") -> not found   <- ' + caller());
                }
                throw e;
            }
        };
    } catch (e) {
        console.log('[!] ApplicationPackageManager not hookable: ' + e);
    }

    // ---- telephony ---------------------------------------------------------
    try {
        var TM = Java.use('android.telephony.TelephonyManager');
        ['getNetworkOperator', 'getSimOperator',
         'getNetworkOperatorName', 'getSimOperatorName'].forEach(function (m) {
            if (!TM[m]) { return; }
            TM[m].overload().implementation = function () {
                var v = this[m]();
                say('telephony', m + '() -> ' + JSON.stringify(v) + '   <- ' + caller());
                return v;
            };
        });
    } catch (e) {
        console.log('[!] TelephonyManager not hookable: ' + e);
    }

    // ---- the verdict -------------------------------------------------------
    // Find methods that LOOK like the verdict and report what they return. This
    // is a heuristic over loaded classes; it will miss an obfuscated name, which
    // is exactly why the layers above trace INPUTS rather than relying on it.
    try {
        Java.enumerateLoadedClasses({
            onMatch: function (name) {
                if (!/^(com|io|net|org)\./.test(name)) { return; }
                if (/^(com\.google\.android|com\.android)\./.test(name)) { return; }
                var cls;
                try { cls = Java.use(name); } catch (e) { return; }
                var methods;
                try { methods = cls.class.getDeclaredMethods(); } catch (e) { return; }
                for (var i = 0; i < methods.length; i++) {
                    var mn = methods[i].getName();
                    if (!/emulator|isEmu|virtual|isGeny|sandbox/i.test(mn)) { continue; }
                    if (methods[i].getParameterTypes().length !== 0) { continue; }
                    try {
                        cls[mn].overload().implementation = function () {
                            var r = this[mn]();
                            say('VERDICT', name + '.' + mn + '() -> ' + r);
                            return r;
                        };
                        console.log('[+] watching verdict candidate: ' + name + '.' + mn);
                    } catch (e) { /* not overloadable as expected */ }
                }
            },
            onComplete: function () {}
        });
    } catch (e) {
        console.log('[!] class enumeration failed: ' + e);
    }
}

// --------------------------------------------------------------------------- //
// Native layer
// --------------------------------------------------------------------------- //

function traceNative() {

    // Property reads that never touch Java. A Java.use hook is blind to these,
    // and this is where a serious check lives.
    ['__system_property_get', '__system_property_find'].forEach(function (sym) {
        var p = Module.findExportByName('libc.so', sym);
        if (!p) { return; }
        Interceptor.attach(p, {
            onEnter: function (args) {
                try { this.name = args[0].readCString(); } catch (e) { this.name = '?'; }
            },
            onLeave: function () {
                if (this.name && INTERESTING.test(this.name)) {
                    say('native-prop', pad(this.name, 34) + '   <- ' +
                        DebugSymbol.fromAddress(this.returnAddress));
                }
            }
        });
        console.log('[+] hooked libc!' + sym);
    });

    // Whole-trie enumeration. Almost nothing does this, so a single hit is
    // notable -- it means the app is looking for emulator-named KEYS, which is
    // both stronger than one-at-a-time reads and (per README 3.3.1) prone to
    // false-positiving on real phones.
    var fe = Module.findExportByName('libc.so', '__system_property_foreach');
    if (fe) {
        Interceptor.attach(fe, {
            onEnter: function () {
                say('native-prop', '__system_property_foreach() -- ENUMERATING THE ' +
                    'WHOLE TRIE   <- ' + DebugSymbol.fromAddress(this.returnAddress));
            }
        });
        console.log('[+] hooked libc!__system_property_foreach');
    }

    // Filesystem probes. Cover every spelling: apps use all of them, and a
    // check that uses stat() while you hooked access() looks like no check.
    [['access', 0], ['faccessat', 1], ['stat', 0], ['lstat', 0],
     ['open', 0], ['openat', 1], ['fopen', 0], ['__statx', 1]
    ].forEach(function (pair) {
        var fn = pair[0], argIdx = pair[1];
        var p = Module.findExportByName('libc.so', fn);
        if (!p) { return; }
        Interceptor.attach(p, {
            onEnter: function (args) {
                try { this.path = args[argIdx].readCString(); }
                catch (e) { this.path = null; }
            },
            onLeave: function (ret) {
                if (this.path && INTERESTING_PATH.test(this.path)) {
                    say('native-fs', pad(fn, 10) + ' "' + this.path + '" -> ' + ret +
                        '   <- ' + DebugSymbol.fromAddress(this.returnAddress));
                }
            }
        });
    });
    console.log('[+] hooked libc filesystem entry points');

    // dlopen: catches a library loaded late, after our hooks were installed,
    // whose own JNI_OnLoad then runs a check. Without this the trace simply
    // stops seeing anything and looks like the app gave up.
    ['dlopen', 'android_dlopen_ext'].forEach(function (sym) {
        var p = Module.findExportByName(null, sym);
        if (!p) { return; }
        Interceptor.attach(p, {
            onEnter: function (args) {
                try { this.lib = args[0].readCString(); } catch (e) { this.lib = '?'; }
            },
            onLeave: function () {
                if (this.lib && this.lib.indexOf('/data/') >= 0) {
                    say('dlopen', this.lib + '  (a late load -- its JNI_OnLoad may check)');
                }
            }
        });
    });
}

// --------------------------------------------------------------------------- //

function pad(s, n) {
    s = String(s);
    while (s.length < n) { s += ' '; }
    return s;
}

function summary() {
    console.log('');
    console.log('================ TRACE SUMMARY ================');
    var keys = Object.keys(TALLY).sort(function (a, b) { return TALLY[b] - TALLY[a]; });
    if (keys.length === 0) {
        console.log('NOTHING OBSERVED.');
        console.log('');
        console.log('Three explanations, in order of likelihood:');
        console.log('  1. You attached with -p instead of spawning with -f, and the');
        console.log('     check ran in a static initialiser before you got there.');
        console.log('  2. The check is native and CONFIG.native was false.');
        console.log('  3. The app genuinely performs no emulator detection --');
        console.log('     which, if it runs fine on a stock AVD, is your finding.');
    } else {
        keys.forEach(function (k) {
            console.log('  ' + pad(k, 14) + ' ' + TALLY[k]);
        });
        console.log('');
        console.log('Next: neutralise ONLY the family that fired, with');
        console.log('scripts/emu-bypass.js. Disabling everything at once tells you');
        console.log('nothing about which signal was load-bearing.');
    }
    console.log('==============================================');
}

function cfg(o) {
    for (var k in o) { if (o.hasOwnProperty(k)) { CONFIG[k] = o[k]; } }
    console.log('[cfg] ' + JSON.stringify(CONFIG));
}

// Exported so they can be called from the Frida REPL.
global.summary = summary;
global.cfg = cfg;

console.log('=== emu-trace.js (chapter 39) ===');
console.log('Tracing only. Nothing is modified.');
console.log('Call summary() at any time; cfg({stacks:true}) for Java stacks.');
console.log('');

if (CONFIG.native) {
    try { traceNative(); }
    catch (e) { console.log('[!] native tracing failed: ' + e); }
}

Java.perform(function () {
    try { traceJava(); }
    catch (e) { console.log('[!] java tracing failed: ' + e); }
    console.log('[+] Java hooks installed. Drive the app now.');
});

// A late summary catches checks that run well after startup -- a payment screen,
// for instance, which is exactly where apps re-check.
setTimeout(summary, 15000);
