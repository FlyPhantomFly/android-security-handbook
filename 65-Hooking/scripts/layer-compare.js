// scripts/layer-compare.js
//
// layer-compare.js -- apply the SAME interception at four different layers and
//                     print, side by side, what each one caught and what it
//                     missed.
//
// WHAT IT DOES
//   Pick one observable behaviour -- by default, "the app opened a file" -- and
//   intercept it at every layer where it is visible:
//
//     1. MANAGED      java.io.File.exists / FileInputStream.<init>
//                     ART-level, via entry-point replacement. Mechanism owned by
//                     ../../13-ART/README.md section 3.15-3.17.
//     2. JNI          libcore's native bridge, when the Java call descends
//                     into one.
//     3. PLT/GOT      the target library's import slot for open/openat/fopen.
//                     Scoped to ONE module.
//     4. INLINE       libc's exported open/openat itself, patched in place.
//                     Process-wide.
//
//   Then it prints a table of which layers fired for each event, which is the
//   only honest way to learn the trade-off: hooking high is easy and misses
//   native callers; hooking low catches everything and drowns you in noise from
//   the runtime itself.
//
// HOW TO RUN
//   frida -U -f com.your.own.testapp -l layer-compare.js
//   frida -U -n com.your.own.testapp -l layer-compare.js
//
//   Then, from the REPL:
//     cmp.layers()                 // what got installed, and what did not
//     cmp.report()                 // the comparison table
//     cmp.reset()                  // clear counters between experiments
//     cmp.plt("libnative.so", "openat")   // add a PLT hook on one module
//     cmp.inline("libc.so", "openat")     // add an inline hook on the export
//
// REQUIREMENTS
//   frida-server running on the device, matching your frida CLI version, and
//   therefore root. On an unrooted device none of this runs -- which is exactly
//   why this chapter's SPINE (../examples/trampoline-hook.c and labs/lab-02) is
//   hand-written C that needs neither.
//
//   NOTE ON THIS REPOSITORY'S DEVICES. Two phones are in rotation. The Redmi
//   M2101K6P (Android 11 / API 30) is rooted and runs frida-server 16.1.6; the
//   i9000S (Android 13 / API 33) is NOT rooted and has no frida-server. This
//   script was authored against the i9000S and therefore has NOT been executed.
//   It is presented as reviewed code, not as measured output. Everything in
//   this chapter that IS measured says so and shows the numbers.
//
// ONLY HOOK APPLICATIONS YOU BUILT OR ARE AUTHORISED TO TEST.
//
// WHAT THIS WILL *NOT* TELL YOU
//   - Which layer is "best". There is no best; there is a layer that answers
//     your question with the least noise. The table is the point.
//   - Whether a missing hit means the layer failed. A managed hook that never
//     fires may mean the call came from native code, or that ART inlined the
//     method, or that a different ClassLoader holds the class. The script
//     distinguishes "not installed" from "installed, zero hits" precisely so
//     you do not conflate them.
//   - Anything about how Frida installs these hooks internally. Frida is
//     ../../53-Frida/README.md's subject. This script uses it as a convenient
//     driver for a comparison; the MECHANISMS are this chapter's subject and
//     are implemented from scratch, without Frida, in ../examples/.

'use strict';

var counters = {};
var installed = {};
var notInstalled = {};

function bump(layer, detail) {
    if (!counters[layer]) counters[layer] = { hits: 0, samples: [] };
    counters[layer].hits++;
    if (counters[layer].samples.length < 5 && detail) {
        counters[layer].samples.push(String(detail));
    }
}

function mark(layer, ok, why) {
    if (ok) { installed[layer] = why || 'installed'; }
    else    { notInstalled[layer] = why || 'unavailable'; }
}

// ---------------------------------------------------------------- 1. MANAGED
//
// Java.use(...).method.implementation = fn replaces the ArtMethod's
// entry_point_from_quick_compiled_code_ so every dispatch lands in the
// replacement. That is 13-ART's mechanism; see its section 3.16 and
// scripts/artmethod-inspect.js. It is the EASIEST layer and the most fragile:
// if the method was inlined by the AOT compiler, or resolved through a
// non-default ClassLoader, the hook installs and never fires.

function installManaged() {
    if (!Java.available) { mark('managed', false, 'no Java VM in this process'); return; }
    Java.perform(function () {
        try {
            var File = Java.use('java.io.File');
            File.exists.implementation = function () {
                var r = this.exists();
                bump('managed', this.getAbsolutePath() + ' -> ' + r);
                return r;
            };
            var FIS = Java.use('java.io.FileInputStream');
            FIS.$init.overload('java.io.File').implementation = function (f) {
                bump('managed', 'FileInputStream(' + f.getAbsolutePath() + ')');
                return this.$init(f);
            };
            mark('managed', true, 'File.exists + FileInputStream(File)');
        } catch (e) {
            mark('managed', false, String(e));
        }
    });
}

// -------------------------------------------------------------------- 2. JNI
//
// libcore reaches the filesystem through Os.stat/Os.open, which are JNI methods
// implemented in libjavacore.so. Hooking the NATIVE symbol catches Java callers
// that a managed hook on File would miss (different Java entry point, same
// syscall), and misses pure-native callers that never enter libcore at all.

function installJni() {
    var syms = ['Java_libcore_io_Linux_open', 'Java_libcore_io_Linux_stat'];
    var any = false;
    syms.forEach(function (s) {
        var p = Module.findExportByName(null, s);
        if (!p) return;
        try {
            Interceptor.attach(p, { onEnter: function () { bump('jni', s); } });
            any = true;
        } catch (e) { /* fall through to the not-installed branch */ }
    });
    mark('jni', any, any ? syms.join(', ') : 'no libcore Linux JNI exports found');
}

// ---------------------------------------------------------------- 3. PLT/GOT
//
// One module's import table. Frida does not expose a GOT-patching primitive, so
// this walks the module's relocations the same way ../examples/plt-got-hook.c
// does and replaces the pointer. The defining property is SCOPE: only calls
// made BY this module are affected. Calls to the same libc function from
// anywhere else are untouched, which is a feature when an app and its RASP SDK
// both call open() and you only want to see one of them.

function installPlt(moduleName, symbolName) {
    var m = Process.findModuleByName(moduleName);
    if (!m) { mark('plt', false, moduleName + ' not loaded'); return; }
    var real = Module.findExportByName(null, symbolName);
    if (!real) { mark('plt', false, symbolName + ' not exported anywhere'); return; }

    var replacement = new NativeCallback(function (dirfd, path, flags, mode) {
        bump('plt', moduleName + ' -> ' + symbolName + '(' + path.readUtf8String() + ')');
        return new NativeFunction(real, 'int', ['int', 'pointer', 'int', 'int'])(
            dirfd, path, flags, mode);
    }, 'int', ['int', 'pointer', 'int', 'int']);

    var patched = 0;
    m.enumerateImports().forEach(function (imp) {
        if (imp.name !== symbolName || !imp.slot) return;
        try {
            Memory.protect(imp.slot, Process.pointerSize, 'rw-');
            imp.slot.writePointer(replacement);
            patched++;
        } catch (e) { /* full RELRO can still refuse; reported below */ }
    });
    // Keep the callback alive; a collected NativeCallback leaves a dangling slot.
    if (!global.__keepalive) global.__keepalive = [];
    global.__keepalive.push(replacement);

    mark('plt', patched > 0,
         patched > 0 ? patched + ' slot(s) in ' + moduleName
                     : 'no ' + symbolName + ' import slot in ' + moduleName +
                       ' (statically linked, inlined, or GLOB_DAT rather than JUMP_SLOT)');
}

// ----------------------------------------------------------------- 4. INLINE
//
// Interceptor.attach on an exported symbol is an inline hook: Frida overwrites
// the function's prologue with a branch to its own trampoline, relocating the
// displaced instructions exactly as ../examples/trampoline-hook.c does by hand.
// It is PROCESS-WIDE: every module's calls are caught, including the runtime's
// own, which is why the hit count here is normally an order of magnitude larger
// than the PLT layer's.

function installInline(moduleName, symbolName) {
    var p = Module.findExportByName(moduleName, symbolName);
    if (!p) { mark('inline', false, symbolName + ' not found in ' + moduleName); return; }
    try {
        Interceptor.attach(p, {
            onEnter: function (args) {
                var path = '';
                try { path = args[1].readUtf8String(); } catch (e) { path = '<unreadable>'; }
                bump('inline', symbolName + '(' + path + ')');
            }
        });
        mark('inline', true, moduleName + '!' + symbolName + ' @ ' + p);
    } catch (e) {
        // The honest failure: Frida refuses when the prologue cannot be
        // relocated. That is the same refusal ../scripts/hookability.py
        // predicts statically.
        mark('inline', false, 'Interceptor refused: ' + e);
    }
}

// ---------------------------------------------------------------- reporting

function pad(s, n) {
    s = String(s);
    while (s.length < n) s += ' ';
    return s;
}

var cmp = {
    layers: function () {
        console.log('\n--- installed ---');
        Object.keys(installed).forEach(function (k) {
            console.log('  ' + pad(k, 10) + installed[k]);
        });
        console.log('--- NOT installed (and why) ---');
        Object.keys(notInstalled).forEach(function (k) {
            console.log('  ' + pad(k, 10) + notInstalled[k]);
        });
        console.log('');
    },

    report: function () {
        console.log('\n' + pad('LAYER', 10) + pad('STATE', 16) + pad('HITS', 8) + 'SAMPLE');
        console.log(Array(78).join('-'));
        ['managed', 'jni', 'plt', 'inline'].forEach(function (layer) {
            var state = installed[layer] ? 'installed'
                      : (notInstalled[layer] ? 'NOT INSTALLED' : 'not attempted');
            var c = counters[layer] || { hits: 0, samples: [] };
            console.log(pad(layer, 10) + pad(state, 16) + pad(c.hits, 8) +
                        (c.samples[0] || ''));
            c.samples.slice(1).forEach(function (s) {
                console.log(pad('', 34) + s);
            });
        });
        console.log(Array(78).join('-'));
        console.log('An installed layer with ZERO hits is a finding, not a bug:');
        console.log('  managed 0  -> the call came from native code, the method was');
        console.log('               inlined by ART, or a different ClassLoader owns');
        console.log('               the class. See 13-ART section 3.17.');
        console.log('  plt     0  -> the module resolves the symbol internally, or the');
        console.log('               call is made by a DIFFERENT module.');
        console.log('  inline  0  -> nothing in the process called it at all.');
        console.log('');
    },

    reset: function () { counters = {}; console.log('counters cleared'); },
    plt: installPlt,
    inline: installInline
};

// -------------------------------------------------------------------- driver

installManaged();
installJni();
installPlt('libc.so', 'openat');          // usually zero: libc does not import itself
installInline('libc.so', 'openat');

global.cmp = cmp;

console.log('layer-compare.js loaded. Exercise the app, then run cmp.report().');
console.log('Add module-specific hooks with cmp.plt("libnative.so", "openat").');
cmp.layers();
