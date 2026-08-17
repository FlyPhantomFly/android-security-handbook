/*
 * scripts/boundary-confirm.js
 *
 * PURPOSE
 *   The RUNTIME half of the managed/native boundary map. Hooks RegisterNatives
 *   and records every explicit binding the process performs: the class, the
 *   method name, the JNI signature, and the module and offset the function
 *   pointer lands in.
 *
 *   This is the only cheap way to see the ~87% of the boundary that symbol
 *   lookup cannot. Measured on com.android.chrome 147.0.7727.111 (Redmi
 *   M2101K6P, Android 11 / API 30) while writing chapter 68:
 *
 *       SUMMARY calls=78 methods=509 distinct=509
 *       all 509 bound into base.apk!/lib/arm64-v8a/libelements.so
 *
 *   -- byte-identical across three consecutive spawns. Compare that against the
 *   STATIC map of the same base.apk, which shows 323 declared native methods of
 *   which only 6 are symbol-resolvable. Two things fall out:
 *
 *     * The runtime bound MORE methods (509) than the artefact declares (323),
 *       because Chrome ships seven APKs and only base.apk had been pulled. The
 *       artefact you have is not the program.
 *     * Note the `!` in the module path: the library is mapped straight out of
 *       the APK (extractNativeLibs="false"), so it does NOT exist as a file
 *       under /data/app/.../lib/arm64/. Looking for that file and not finding
 *       it would have read as "the library is absent".
 *
 * USAGE
 *   # host -- ALWAYS pass -D <serial>. With two devices attached,
 *   # frida.get_usb_device() picked the emulator, not the phone. See section 7.5.
 *   frida -D <serial> -f com.example.target -l boundary-confirm.js
 *
 *   # host -- capture to a file for diffing against the static map
 *   frida -D <serial> -f com.example.target -l boundary-confirm.js -o rn.txt
 *
 *   # host -- then diff the two halves
 *   python3 -B boundary-map.py base.apk --unresolved | cut -f1 | sort > static.txt
 *   grep '^RN' rn.txt | cut -f2,3 | tr '\t' '.' | sort -u          > runtime.txt
 *   comm -13 static.txt runtime.txt   # bound at runtime, not declared in base.apk
 *
 *   # Options, set at the top of this file or via the FRIDA_* environment of
 *   # your wrapper: WINDOW_MS (how long before the summary prints), VERBOSE.
 *
 * REQUIREMENTS
 *   frida-server running on the device, matching your frida version.
 *   Tested with frida 16.1.6.
 *
 * WHY SLOT 215 AND NOT A SYMBOL
 *   RegisterNatives is NOT an exported symbol of libart.so -- enumerating
 *   libart's exports for the name returns nothing, which was verified while
 *   writing the chapter. It is reached through the JNIEnv function table
 *   (JNINativeInterface), where RegisterNatives is entry 215. That index is
 *   fixed by the JNI specification and has been stable since JNI 1.1.
 *
 * LIVENESS -- READ THIS BEFORE REPORTING A ZERO
 *   A silent run and a broken hook produce identical output. This script prints
 *   the resolved address unconditionally at install time so you can tell that
 *   the hook installed; that is necessary but NOT sufficient. Before recording
 *   "this app performs no explicit binding", run this same script against a
 *   target you know does (a browser or a Google app is a safe bet) and confirm
 *   it reports non-zero. Chapter 68 section 7.2.
 *
 * ETHICS
 *   Apps you own, or are authorised to test, or purpose-built targets only.
 */

'use strict';

var WINDOW_MS = 25000;   // when to print the summary
var VERBOSE   = true;    // print every binding as it happens
var MAX_ARRAY = 8192;    // refuse to walk an implausibly large array

var REGISTER_NATIVES_SLOT = 215;

var state = {
    calls: 0,
    methods: 0,
    distinct: {},
    byModule: {},
    installed: false
};

function moduleFor(ptr) {
    try {
        var m = Process.findModuleByAddress(ptr);
        if (m) {
            return { name: m.name, path: m.path,
                     off: ptr.sub(m.base).toString(16) };
        }
    } catch (e) { /* fall through */ }
    return null;
}

function classNameOf(jclass) {
    try {
        return Java.vm.getEnv().getClassName(jclass);
    } catch (e) {
        return '<unresolved-jclass>';
    }
}

function readCStringSafe(p) {
    try {
        var s = p.readCString();
        return (s === null) ? '<null>' : s;
    } catch (e) {
        return '<unreadable>';
    }
}

function onRegisterNatives(args) {
    state.calls++;

    var jclass   = args[1];
    var arrayPtr = args[2];
    var count    = args[3].toInt32();

    if (count < 0 || count > MAX_ARRAY) {
        console.log('RN-WARN implausible nMethods=' + count + ' -- not walking');
        return;
    }

    var cls    = classNameOf(jclass);
    var stride = Process.pointerSize * 3;   // {name, signature, fnPtr}

    state.methods += count;

    for (var i = 0; i < count; i++) {
        var entry = arrayPtr.add(i * stride);
        var name, sig, fnPtr;

        try {
            name  = readCStringSafe(entry.readPointer());
            sig   = readCStringSafe(entry.add(Process.pointerSize).readPointer());
            fnPtr = entry.add(Process.pointerSize * 2).readPointer();
        } catch (e) {
            console.log('RN-WARN could not read entry ' + i + ' of ' + count);
            continue;
        }

        var mod  = moduleFor(fnPtr);
        var where = mod ? (mod.path + '+0x' + mod.off) : fnPtr.toString();
        var key   = cls + '.' + name;

        state.distinct[key] = true;
        var modKey = mod ? mod.path : '<anonymous>';
        state.byModule[modKey] = (state.byModule[modKey] || 0) + 1;

        if (VERBOSE) {
            // Tab separated so the usage block's cut/comm pipeline works.
            console.log('RN\t' + cls + '\t' + name + '\t' + sig + '\t' + where);
        }
    }
}

function install() {
    var env, table, fn;

    try {
        env = Java.vm.getEnv();
    } catch (e) {
        console.log('[!] no JNIEnv on this thread yet -- is this a Java process?');
        return false;
    }

    table = env.handle.readPointer();
    fn    = table.add(REGISTER_NATIVES_SLOT * Process.pointerSize).readPointer();

    // Sanity: the slot must point into a mapped module, and that module should
    // be libart. If it is not, the JNINativeInterface layout is not what we
    // assume and every subsequent number would be garbage.
    var mod = moduleFor(fn);
    if (!mod) {
        console.log('[!] slot ' + REGISTER_NATIVES_SLOT +
                    ' does not point into a mapped module -- refusing to hook');
        return false;
    }
    if (mod.name.indexOf('libart') !== 0) {
        console.log('[!] slot ' + REGISTER_NATIVES_SLOT + ' points into ' +
                    mod.name + ', not libart. Layout assumption may be wrong.');
        console.log('[!] continuing, but treat the results as unverified.');
    }

    // This line is the install-time liveness signal. Its absence means the hook
    // is not there; its presence does NOT mean the app binds anything.
    console.log('[*] RegisterNatives @ ' + fn + '  (' + mod.name + '+0x' +
                mod.off + ')');

    Interceptor.attach(fn, { onEnter: onRegisterNatives });
    state.installed = true;
    return true;
}

function summarise() {
    var distinct = Object.keys(state.distinct).length;

    console.log('');
    console.log('SUMMARY calls=' + state.calls +
                ' methods=' + state.methods +
                ' distinct=' + distinct);

    var mods = Object.keys(state.byModule);
    if (mods.length) {
        mods.sort(function (a, b) { return state.byModule[b] - state.byModule[a]; });
        console.log('');
        console.log('bindings by module (this is your target list):');
        mods.forEach(function (m) {
            console.log('  ' + String(state.byModule[m]).padStart(6) + '  ' + m);
        });
    }

    if (state.calls === 0) {
        console.log('');
        console.log('ZERO CALLS. Before you record that as a result, read this.');
        console.log('  A silent run and a broken hook are indistinguishable from');
        console.log('  here. The hook DID install (the [*] line above proves that');
        console.log('  much) but that is not enough. Run this same script against');
        console.log('  a target you know performs explicit binding and confirm it');
        console.log('  reports non-zero. Only then does this zero mean anything.');
        console.log('  -- chapter 68 section 7.2, liveness before silence.');
    }
}

setTimeout(function () {
    Java.perform(function () {
        if (!install()) {
            console.log('[!] install failed -- no measurement was taken.');
        }
    });
}, 0);

setTimeout(summarise, WINDOW_MS);

rpc.exports = {
    // Call from a Python driver to read the state at any point, e.g.
    //   session.create_script(open('boundary-confirm.js').read()).exports.snapshot()
    snapshot: function () {
        return {
            installed: state.installed,
            calls: state.calls,
            methods: state.methods,
            distinct: Object.keys(state.distinct).length,
            byModule: state.byModule
        };
    },
    summarise: summarise
};
