// scripts/detect-classic-xposed.js
//
// frida -U -f com.pentest.ch64.vault -l scripts/detect-classic-xposed.js
// frida -U -n <running process>      -l scripts/detect-classic-xposed.js
//
// PURPOSE
//   Ask, from inside a running process, whether a managed-code hooking
//   framework is present -- and distinguish CLASSIC XPOSED from LSPosed,
//   which almost every published detector fails to do.
//
//   Four independent signals, because any one of them alone is weak:
//
//     1. api()       is de.robv.android.xposed resolvable in THIS process,
//                    and by which class loader?
//     2. stack()     is a hook dispatcher between a method and its caller?
//                    handleHookedMethod -> classic; LSPHooker -> LSPlant.
//     3. artmethod() does a method with BYTECODE claim kAccNative?  That is
//                    the classic-Xposed hook, structurally -- see README
//                    section 6.4.  A method cannot legitimately be in that
//                    state.
//     4. maps()      does the process map a framework library by name?
//
//   Signal 3 is the reason this script exists.  Signals 1, 2 and 4 are
//   available to the application itself in pure Java and are covered by
//   examples/XposedDetector.java.  Signal 3 needs to read a runtime structure,
//   which is what Frida is for.
//
// *** EXECUTION STATUS ***
//   *** REVIEWED, NOT EXECUTED. ***
//
//   frida-server does NOT load on the API 35 AVD used for this chapter.
//   Measured by chapter 61 on the same device and reproduced here:
//
//       CANNOT LINK EXECUTABLE "/data/local/tmp/frida-server":
//         empty/missing DT_HASH/DT_GNU_HASH in "/data/local/tmp/frida-server"
//         (new hash type from the future?)
//
//   That is a frida-version problem, not a root problem -- `su 0 id` returns
//   uid 0 on the same device seconds later -- and it is confusing because
//   `frida-ps -U` still lists processes; the failure appears only on attach.
//   No physical device was attached during this chapter's work.
//
//   What WAS done instead:
//     * every Frida API used below was checked against Frida's published Java
//       and Memory API surface;
//     * the ArtMethod offset handling deliberately DELEGATES to
//       13-ART/scripts/artmethod-inspect.js rather than hard-coding an
//       offset, because that is the part most likely to be wrong in a script
//       of this kind, and 13-ART's version derives it at runtime;
//     * `node --check` was run over this file and it parses.
//
//   Treat this as a reviewed draft that will need a real run.  If you have a
//   working frida-server and it fails, the failure is a finding worth writing
//   down.  This repository would rather ship a labelled untested script than
//   an unlabelled fabricated transcript.
//
// AUTHORISED TESTING ONLY.  Run this against an application you own or are
// explicitly authorised to assess.

'use strict';

var TAG = '[ch64] ';

function log(s) { console.log(TAG + s); }

// ---------------------------------------------------------------------------
// The names.  Split by ERA, because that split is the whole point: an app that
// looks only for the CLASSIC names is looking for a framework that has not
// been installable since API 27.
// ---------------------------------------------------------------------------
var CLASSIC_CLASSES = [
    'de.robv.android.xposed.XposedBridge',
    'de.robv.android.xposed.XposedHelpers',
    'de.robv.android.xposed.XC_MethodHook',
    'de.robv.android.xposed.IXposedHookLoadPackage',
    'de.robv.android.xposed.IXposedHookZygoteInit'
];

// Frames that identify WHICH framework installed the hook.
var FRAME_MARKERS = [
    { needle: 'handleHookedMethod',   era: 'CLASSIC Xposed (single generic dispatcher)' },
    { needle: 'LSPHooker',            era: 'LSPosed / LSPlant (generated hook class)' },
    { needle: 'de.robv.android.xposed', era: 'Xposed API layer (classic OR LSPosed compat)' },
    { needle: 'com.elderdrivers.riru', era: 'EdXposed / Riru' },
    { needle: 'org.lsposed',          era: 'LSPosed daemon or manager' }
];

// Library names a framework would map into the process.
var MAP_MARKERS = [
    { needle: 'libxposed_art',    era: 'CLASSIC Xposed, ART engine' },
    { needle: 'libxposed_dalvik', era: 'CLASSIC Xposed, Dalvik engine' },
    { needle: 'liblspd',          era: 'LSPosed' },
    { needle: 'lsposed',          era: 'LSPosed' },
    { needle: 'riru',             era: 'Riru / EdXposed' },
    { needle: 'zygisk',           era: 'Zygisk (the SUBSTRATE, not the framework)' }
];

// ---------------------------------------------------------------------------
// SIGNAL 1 -- is the API resolvable in this process?
//
// Note the deliberate use of Java.enumerateClassLoaders rather than a bare
// Java.use: WHICH loader holds the class is the informative part.
//
//   * on the boot class loader  -> classic Xposed put its jar on the BOOT
//                                  CLASS PATH, so this is its signature
//   * on some other loader      -> a framework loaded it into this process,
//                                  which is what LSPosed does
// ---------------------------------------------------------------------------
function api() {
    var out = { found: [], loaders: [] };
    Java.perform(function () {
        CLASSIC_CLASSES.forEach(function (name) {
            try {
                Java.use(name);
                out.found.push(name);
            } catch (e) {
                // not resolvable via the app loader -- expected on a clean process
            }
        });

        try {
            Java.enumerateClassLoadersSync().forEach(function (loader) {
                var s = String(loader);
                out.loaders.push(s.length > 200 ? s.substring(0, 200) + '...' : s);
            });
        } catch (e) {
            out.loaders.push('(enumerateClassLoaders failed: ' + e + ')');
        }
    });

    log('SIGNAL 1 -- Xposed API in this process');
    if (out.found.length === 0) {
        log('  none of ' + CLASSIC_CLASSES.length + ' API classes resolvable');
    } else {
        out.found.forEach(function (n) { log('  RESOLVABLE  ' + n); });
        log('  -> something loaded a hooking framework into THIS process.');
        log('     Under classic Xposed this would be true in EVERY process on');
        log('     the device, because the jar was on the boot class path.');
        log('     Under LSPosed it is true only where a module is scoped.');
    }
    log('  class loaders in this process: ' + out.loaders.length);
    out.loaders.forEach(function (l) { log('    ' + l); });
    return out;
}

// ---------------------------------------------------------------------------
// SIGNAL 2 -- a dispatcher frame between a method and its caller.
//
// This ONLY fires while a HOOKED method is executing, which is why it takes a
// class and method name: it installs its own temporary hook on the target,
// throws inside it, and reads its own stack.  If a foreign dispatcher is
// present it will be BELOW this frame.
// ---------------------------------------------------------------------------
function stack(className, methodName) {
    Java.perform(function () {
        var clazz;
        try {
            clazz = Java.use(className);
        } catch (e) {
            log('SIGNAL 2 -- cannot resolve ' + className + ': ' + e);
            return;
        }
        var overloads;
        try {
            overloads = clazz[methodName].overloads;
        } catch (e) {
            log('SIGNAL 2 -- no such method: ' + className + '.' + methodName);
            return;
        }

        log('SIGNAL 2 -- stack inspection at ' + className + '.' + methodName
            + ' (' + overloads.length + ' overload(s))');

        overloads.forEach(function (ov) {
            ov.implementation = function () {
                var Log = Java.use('android.util.Log');
                var Exception = Java.use('java.lang.Exception');
                var trace = Log.getStackTraceString(Exception.$new());
                var hits = [];
                FRAME_MARKERS.forEach(function (m) {
                    if (trace.indexOf(m.needle) !== -1) { hits.push(m); }
                });
                if (hits.length) {
                    log('  FOREIGN FRAME(S) on the stack of ' + methodName + ':');
                    hits.forEach(function (h) {
                        log('    ' + h.needle + '  -> ' + h.era);
                    });
                } else {
                    log('  no foreign frame at ' + methodName);
                }
                // Our own hook is on this stack too. That is unavoidable and it
                // is why the markers are specific names rather than "anything
                // that is not the app".
                return ov.apply(this, arguments);
            };
        });
        log('  instrumented. Exercise the app and watch for FOREIGN FRAME lines.');
    });
}

// ---------------------------------------------------------------------------
// SIGNAL 3 -- the structural one.  README section 6.4:
//
//   A method DECLARED IN JAVA WITH A BODY whose access_flags_ claim kAccNative
//   is not a state ART produces.  It is what classic Xposed's hookMethodNative
//   left behind.
//
// Reading access_flags_ requires the ArtMethod layout, which is NOT stable --
// ART is a Mainline module from API 29, so two devices reporting the same
// Android release can differ.  13-ART ships a script that derives the offsets
// at runtime; this function refuses to guess and points at it.
// ---------------------------------------------------------------------------
var K_ACC_NATIVE = 0x0100;   // from art/runtime/modifiers.h; same value as Java's ACC_NATIVE

function artmethod(className, methodName) {
    log('SIGNAL 3 -- ArtMethod consistency for ' + className + '.' + methodName);
    Java.perform(function () {
        var Modifier, clazz, refl;
        try {
            clazz = Java.use(className);
            refl = Java.use('java.lang.Class');
            Modifier = Java.use('java.lang.reflect.Modifier');
        } catch (e) {
            log('  cannot resolve: ' + e);
            return;
        }

        // The cheap half needs no native reads at all: java.lang.reflect
        // reports the access flags the runtime currently holds.  If a method
        // you can see declared with a body in the DEX reports isNative(), the
        // flag was flipped underneath you.
        try {
            var jclass = Java.use(className).class;
            var methods = jclass.getDeclaredMethods();
            var any = false;
            for (var i = 0; i < methods.length; i++) {
                var m = methods[i];
                if (String(m.getName()) !== methodName) { continue; }
                any = true;
                var mods = m.getModifiers();
                var isNative = Modifier.isNative(mods);
                var isAbstract = Modifier.isAbstract(mods);
                log('  ' + m.toString());
                log('    modifiers=0x' + mods.toString(16)
                    + '  native=' + isNative + '  abstract=' + isAbstract);
                if (isNative) {
                    log('    *** reports NATIVE. If this method has a body in the');
                    log('        DEX, that is the classic-Xposed hook signature.');
                    log('        Confirm by checking the DEX -- see README 6.4.');
                } else {
                    log('    consistent: not native.');
                }
            }
            if (!any) { log('  no declared method named ' + methodName); }
        } catch (e) {
            log('  reflection failed: ' + e);
        }

        log('  For the raw access_flags_ and entry-point values, use');
        log('    13-ART/scripts/artmethod-inspect.js');
        log('  which DERIVES the field offsets rather than tabulating them.');
        log('  Never hard-code an ArtMethod offset: ART is a Mainline module');
        log('  from API 29 and the layout is not determined by the OS version.');
        log('  (kAccNative = 0x' + K_ACC_NATIVE.toString(16) + ', for reference.)');
    });
}

// ---------------------------------------------------------------------------
// SIGNAL 4 -- named mappings.
//
// Classic Xposed loaded libxposed_art.so into every process before the fork,
// so it was in every /proc/self/maps on the device.  LSPosed deliberately asks
// Magisk to dlclose its module library after specialisation, so this signal is
// much weaker against it -- which is itself informative.
// ---------------------------------------------------------------------------
function maps() {
    log('SIGNAL 4 -- named mappings');
    var hits = 0;
    Process.enumerateModules().forEach(function (m) {
        var lower = m.name.toLowerCase() + ' ' + String(m.path || '').toLowerCase();
        MAP_MARKERS.forEach(function (mk) {
            if (lower.indexOf(mk.needle) !== -1) {
                hits++;
                log('  ' + m.name + '  @' + m.base + '  -> ' + mk.era);
            }
        });
    });
    if (hits === 0) {
        log('  no framework library mapped by name (' +
            Process.enumerateModules().length + ' modules total)');
        log('  NOTE: absence is weak evidence. LSPosed dlcloses its module');
        log('  library after specialisation specifically so this is empty.');
    }
    return hits;
}

// ---------------------------------------------------------------------------
// Everything, once.
// ---------------------------------------------------------------------------
function scan() {
    log('=====================================================================');
    log(' classic-Xposed / LSPosed in-process scan');
    log(' pid=' + Process.id + '  arch=' + Process.arch
        + '  pointerSize=' + Process.pointerSize);
    log('=====================================================================');
    api();
    log('');
    maps();
    log('');
    log('SIGNAL 2 and 3 need a target method. Call them explicitly:');
    log('  cx.stack("com.example.Gate", "isUnlocked")');
    log('  cx.artmethod("com.example.Gate", "isUnlocked")');
    log('');
    log('HOW TO READ THE RESULT');
    log('  Signals 1 and 2 fire for classic Xposed AND for LSPosed. Only the');
    log('  frame NAME distinguishes them: handleHookedMethod is the classic');
    log('  single dispatcher; LSPHooker is LSPlant.');
    log('  Signal 3 firing on a method with bytecode is classic-Xposed-shaped');
    log('  and LSPosed does not produce it.');
    log('  Signal 4 firing on libxposed_* is conclusive for classic Xposed;');
    log('  firing on zygisk proves the SUBSTRATE only, which is a different');
    log('  question -- see 63-LSPosed section 11.3.');
}

var cx = {
    scan: scan,
    api: api,
    stack: stack,
    artmethod: artmethod,
    maps: maps
};

// Exported for `frida -l this.js` REPL use and for rpc callers alike.
rpc.exports = {
    scan: function () { scan(); return true; },
    api: function () { return api(); },
    maps: function () { return maps(); },
    stack: function (c, m) { stack(c, m); return true; },
    artmethod: function (c, m) { artmethod(c, m); return true; }
};

globalThis.cx = cx;

log('loaded. Try: cx.scan()');
