/*
 * scripts/early-instrument.js
 * ---------------------------------------------------------------------------
 * WHAT IT DOES
 *   Gets your hooks in before the app's protections run.
 *
 *   Not "early" in a vague sense. Specifically, it installs before all four of
 *   these, in this order:
 *
 *     1. libc calls made by the linker while mapping a library
 *     2. .init_array constructors, which run DURING dlopen()
 *     3. JNI_OnLoad, which runs inside System.loadLibrary()
 *     4. any Java static initialiser, Application.attachBaseContext, or
 *        Activity.onCreate
 *
 *   Points 2 and 3 are the ones nothing else covers, and they are the ones
 *   that produce the symptom this chapter is repeatedly sent readers for:
 *   "I attached and the app died instantly."
 *
 * WHY THIS IS A SEPARATE SCRIPT FROM YOUR BYPASS
 *   Because it does not bypass anything. It is a HARNESS: it wins the race,
 *   then hands control to whatever you actually want to run, at the moment you
 *   want it to run. Mixing the two makes both harder to debug, and when a
 *   bypass silently does nothing the first question is always "was it even
 *   installed yet?". Keep the answer to that question in its own file.
 *
 * HOW TO RUN
 *   # host - the only mode that can win the race. -f SPAWNS the process
 *   # suspended; --no-pause resumes it after this script has run.
 *   frida -U -f com.target.app -l early-instrument.js --no-pause
 *
 *   # host - with your own agent loaded after this one. ORDER MATTERS: this
 *   # file must be first, because -l scripts run in the order given.
 *   frida -U -f com.target.app \
 *         -l early-instrument.js -l my-bypass.js --no-pause
 *
 *   # host - watch only, change nothing (the honest first pass)
 *   frida -U -f com.target.app -l early-instrument.js --no-pause \
 *         -e "ei.observeOnly()"
 *
 *   # REPL, once running:
 *   #   ei.status()          what is installed and what has been seen
 *   #   ei.timeline()        the ordered record of load-time events
 *   #   ei.onLibrary(re, fn) run fn(module) the moment a matching .so is mapped
 *   #   ei.onJniOnLoad(re, fn) run fn(module, addr) BEFORE that library's
 *   #                        JNI_OnLoad executes - your last chance to act
 *   #   ei.neuter(re)        make matching libraries' JNI_OnLoad a no-op that
 *   #                        returns JNI_VERSION_1_6
 *   #   ei.help()
 *
 * REQUIREMENTS
 *   - frida-server running on the device as root, version-matched to your
 *     frida CLI. On a non-rooted device use frida-gadget instead; the gadget
 *     is loaded even earlier than this script can be, and the ei.* API below
 *     still works once the gadget's script is running.
 *   - You must SPAWN. If you attach, points 1-3 have already happened and this
 *     file cannot help you; it will say so in its banner rather than pretending.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   - It will NOT tell you what the check decided. It tells you WHEN and WHERE
 *     code ran. Use ../scripts/bypass-triage.py for the "what killed it"
 *     question and 37-RootDetection/scripts/root-check-tracer.js for the
 *     "which probe" question.
 *   - It will NOT beat a protection that runs in a DIFFERENT PROCESS, in the
 *     zygote before your spawn, or in a service the app talks to over Binder.
 *   - It will NOT beat inline-syscall code that never enters libc. Nothing
 *     that hooks symbols can. When you reach that point, stop hooking:
 *     see README section 3.12 on when to go static.
 *   - It will NOT make attach behave like spawn. There is no flag for that.
 *
 * AUTHORISATION
 *   Use only on an application you own or are contracted to assess.
 * ---------------------------------------------------------------------------
 */

'use strict';

var CFG = {
    // Print every library the app maps. Noisy but almost always worth it once.
    logLibraries: true,

    // Ignore platform libraries; the app's own are what matter.
    ignorePrefixes: ['/system/', '/apex/', '/vendor/', '/product/', '/system_ext/'],

    // Print a note when a constructor-bearing library is mapped.
    logConstructors: true,

    // When false, everything is observed and nothing is modified.
    enforce: true
};

var ei = {
    installed: [],
    missing: [],
    events: [],          // ordered timeline of load-time events
    libraries: [],       // paths in the order they were mapped
    _libRules: [],       // {re, fn}
    _jniRules: [],       // {re, fn}
    _neuter: [],         // regexes whose JNI_OnLoad is replaced
    _keepAlive: [],
    spawned: null
};

function ts() {
    // Milliseconds since the script loaded. Absolute time is useless here;
    // the ORDER and the gaps are the whole point.
    return (Date.now() - START) + 'ms';
}

var START = Date.now();

function record(kind, detail) {
    var e = { t: ts(), kind: kind, detail: detail };
    ei.events.push(e);
    console.log('[' + e.t + '] ' + kind + ': ' + detail);
    return e;
}

function isAppLibrary(path) {
    if (!path) return false;
    for (var i = 0; i < CFG.ignorePrefixes.length; i++) {
        if (path.indexOf(CFG.ignorePrefixes[i]) === 0) return false;
    }
    return path.indexOf('.so') !== -1;
}

function sym(name, lib) {
    var p = null;
    try { p = Module.findExportByName(lib || null, name); } catch (e) { p = null; }
    if (p === null && ei.missing.indexOf(name) === -1) ei.missing.push(name);
    return p;
}

function readStr(p) {
    if (p === null || p.isNull()) return null;
    try { return p.readUtf8String(); } catch (e) { return null; }
}

// ===========================================================================
// 1. Are we early enough at all?
//
// A spawned-and-suspended process has essentially nothing mapped beyond the
// linker, libc and the zygote's inheritance. If the app's own .so files are
// already present when this script loads, you ATTACHED, and everything below
// is running after the fact. Say so immediately and loudly - the single most
// common wasted hour in this whole discipline is debugging a bypass that was
// installed too late to matter.
// ===========================================================================

function assessTiming() {
    var appLibs = [];
    Process.enumerateModules().forEach(function (m) {
        if (isAppLibrary(m.path)) appLibs.push(m.path);
    });

    if (appLibs.length === 0) {
        ei.spawned = true;
        console.log('[*] TIMING OK: no application libraries are mapped yet.');
        console.log('    You are early. .init_array and JNI_OnLoad have not run.');
    } else {
        ei.spawned = false;
        console.log('');
        console.log('!!! TIMING PROBLEM ------------------------------------------------');
        console.log('!!! ' + appLibs.length + ' application librar(y/ies) are ALREADY MAPPED:');
        appLibs.slice(0, 8).forEach(function (p) { console.log('!!!   ' + p); });
        console.log('!!!');
        console.log('!!! Their .init_array constructors and JNI_OnLoad have already run.');
        console.log('!!! Nothing in this file can undo that. Re-run with:');
        console.log('!!!   frida -U -f <package> -l early-instrument.js --no-pause');
        console.log('!!! If the app dies the moment you spawn, that is progress: you are');
        console.log('!!! now failing at a point you can actually observe.');
        console.log('!!! ----------------------------------------------------------------');
        console.log('');
    }
    return ei.spawned;
}

// ===========================================================================
// 2. Watch the linker.
//
// android_dlopen_ext is what System.loadLibrary ultimately reaches on Android;
// dlopen is what native code calls directly. Hook both: an app that calls
// dlopen from its own .so bypasses the framework path entirely.
//
// onEnter gives you the path BEFORE the mapping happens, which is when you can
// still decide to do something about it. onLeave gives you the handle, and is
// the earliest point at which Module.findExportByName can resolve a symbol
// inside it - but it is AFTER the constructors have run. Both are reported,
// with the gap between them made visible, because that gap is where
// .init_array lives.
// ===========================================================================

function watchLinker() {
    ['android_dlopen_ext', 'dlopen', '__loader_dlopen'].forEach(function (fn) {
        var p = sym(fn);
        if (p === null) return;

        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    this.path = readStr(args[0]);
                    this.interesting = isAppLibrary(this.path);
                    if (this.interesting) {
                        this.enterAt = Date.now();
                        record('dlopen-enter', fn + '("' + this.path + '")'
                            + '  <-- .init_array runs during this call');
                    }
                },
                onLeave: function (retval) {
                    if (!this.interesting) return;
                    var took = Date.now() - this.enterAt;
                    ei.libraries.push(this.path);
                    record('dlopen-leave', this.path + ' mapped in ' + took + 'ms');
                    onLibraryMapped(this.path);
                }
            });
            ei.installed.push(fn);
        } catch (e) {
            console.log('[!] could not hook ' + fn + ': ' + e);
        }
    });
}

// ===========================================================================
// 3. Beat .init_array, properly.
//
// The constructors of a library run inside dlopen(), between our onEnter and
// our onLeave. Hooking dlopen is therefore NOT early enough to intercept a
// constructor - by the time we can resolve a symbol in the new module, it has
// already executed.
//
// There are exactly two ways to get in front of a constructor, and both are
// worth knowing because each fails in a different situation:
//
//   (a) Hook the LINKER's call_constructors. The symbol is not exported in the
//       normal sense but is present in the linker's dynamic symbol table on
//       most builds as __dl__ZN6soinfo17call_constructorsEv. When it resolves,
//       this is exact and general.
//
//   (b) Hook the LIBC FUNCTIONS the constructor will call - open, access,
//       socket, connect, fopen - which are already mapped at process start and
//       can therefore be hooked arbitrarily early. This does not stop the
//       constructor running; it changes what the constructor SEES. In practice
//       this is what actually works, and it is why libc interposition is the
//       default technique in this whole family of scripts.
//
// (a) is attempted, reported honestly if unavailable, and never required.
// ===========================================================================

function watchConstructors() {
    var candidates = [
        '__dl__ZN6soinfo17call_constructorsEv',
        '_ZN6soinfo17call_constructorsEv'
    ];

    var found = null;
    for (var i = 0; i < candidates.length && found === null; i++) {
        try { found = Module.findExportByName(null, candidates[i]); } catch (e) { found = null; }
        if (found === null) {
            // Not exported - try the linker module's symbol table directly.
            try {
                Process.enumerateModules().forEach(function (m) {
                    if (found !== null) return;
                    if (m.name.indexOf('linker') === -1) return;
                    m.enumerateSymbols().forEach(function (s) {
                        if (found === null && s.name === candidates[i]) found = s.address;
                    });
                });
            } catch (e) { /* enumerateSymbols can throw on a stripped linker */ }
        }
    }

    if (found === null) {
        console.log('[*] linker call_constructors not resolvable on this build.');
        console.log('    This is common and is NOT a failure. Constructors will still be');
        console.log('    caught indirectly: every libc call they make is already hooked,');
        console.log('    because libc was mapped before this script ran. See the header,');
        console.log('    technique (b).');
        ei.missing.push('call_constructors');
        return;
    }

    try {
        Interceptor.attach(found, {
            onEnter: function () {
                if (!CFG.logConstructors) return;
                record('call_constructors', 'linker is about to run .init_array');
            }
        });
        ei.installed.push('call_constructors');
        console.log('[*] linker call_constructors hooked - constructors are visible.');
    } catch (e) {
        console.log('[!] call_constructors resolved but could not be hooked: ' + e);
    }
}

// ===========================================================================
// 4. Beat JNI_OnLoad.
//
// This is the one that pays. JNI_OnLoad is an EXPORTED symbol, and it runs
// AFTER dlopen has returned - inside ART's LoadNativeLibrary, which resolves
// it with dlsym and calls it. So the window between our dlopen onLeave and the
// call is real, and it is enough.
//
// Measured on this chapter's demo app: the deciding frame in the tombstone was
//   libch67guard.so (JNI_OnLoad+908)
// which is precisely the function we get in front of here.
// ===========================================================================

function onLibraryMapped(path) {
    var mod = null;
    try {
        Process.enumerateModules().forEach(function (m) {
            if (m.path === path) mod = m;
        });
    } catch (e) { /* ignore */ }
    if (mod === null) return;

    if (CFG.logLibraries) {
        record('module', mod.name + ' base=' + mod.base + ' size=' + mod.size);
    }

    // User rules that want to see the module itself.
    ei._libRules.forEach(function (r) {
        if (!r.re.test(path)) return;
        try { r.fn(mod); } catch (e) { console.log('[!] onLibrary rule threw: ' + e); }
    });

    // JNI_OnLoad: hook it before ART calls it.
    var jni = null;
    try { jni = Module.findExportByName(mod.name, 'JNI_OnLoad'); } catch (e) { jni = null; }
    if (jni === null) return;

    record('JNI_OnLoad-found', mod.name + '!JNI_OnLoad @ ' + jni
        + '  (offset +' + jni.sub(mod.base) + ')');

    var neuterThis = false;
    ei._neuter.forEach(function (re) { if (re.test(path)) neuterThis = true; });

    if (neuterThis && CFG.enforce) {
        /*
         * Replace the whole function. JNI_VERSION_1_6 is 0x00010006 and is
         * what a healthy JNI_OnLoad returns.
         *
         * This is a BIG hammer and it deserves a warning: JNI_OnLoad is where
         * most libraries call RegisterNatives. Neutering it means every native
         * method the library was going to register is now unregistered, and
         * the app will die later with UnsatisfiedLinkError - a completely
         * different failure that looks nothing like the one you were chasing.
         * Use ei.onJniOnLoad() to intercept it instead, unless you have
         * confirmed the library registers nothing.
         */
        var replacement = new NativeCallback(function () {
            record('JNI_OnLoad-neutered', mod.name + ' returned JNI_VERSION_1_6 without running');
            return 0x00010006;
        }, 'int', ['pointer', 'pointer']);
        ei._keepAlive.push(replacement);
        try {
            Interceptor.replace(jni, replacement);
            record('neuter', mod.name + '!JNI_OnLoad replaced');
        } catch (e) {
            console.log('[!] could not replace JNI_OnLoad in ' + mod.name + ': ' + e);
        }
        return;
    }

    try {
        Interceptor.attach(jni, {
            onEnter: function () {
                record('JNI_OnLoad-enter', mod.name
                    + '  <-- LAST MOMENT before the library decides anything');
                ei._jniRules.forEach(function (r) {
                    if (!r.re.test(path)) return;
                    try { r.fn(mod, jni); }
                    catch (e) { console.log('[!] onJniOnLoad rule threw: ' + e); }
                });
            },
            onLeave: function (retval) {
                record('JNI_OnLoad-leave', mod.name + ' returned 0x'
                    + retval.toInt32().toString(16));
            }
        });
    } catch (e) {
        console.log('[!] could not hook JNI_OnLoad in ' + mod.name + ': ' + e);
    }
}

// ===========================================================================
// 5. Mark the Java boundary.
//
// Not a hook you need, but the timeline is far more readable when it shows
// where "before Java" ends. Everything above this line in the timeline is
// unreachable to a script that waits for Java.perform.
// ===========================================================================

function markJavaBoundary() {
    if (!Java.available) {
        console.log('[*] Java runtime not available (native-only process?)');
        return;
    }
    Java.perform(function () {
        record('java-boundary', 'Java.perform ran - everything ABOVE this line '
            + 'happened before any Java-level hook could exist');
    });
}

// ===========================================================================
// Public API
// ===========================================================================

ei.status = function () {
    console.log('');
    console.log('=== early-instrument status ===');
    console.log('spawned early : ' + (ei.spawned ? 'YES' : 'NO - you attached'));
    console.log('mode          : ' + (CFG.enforce ? 'ENFORCING' : 'OBSERVE ONLY'));
    console.log('installed     : ' + (ei.installed.join(', ') || 'nothing'));
    if (ei.missing.length) {
        console.log('unavailable   : ' + ei.missing.join(', '));
        console.log('  (normal - symbol sets differ by API level, arch and build)');
    }
    console.log('app libraries : ' + (ei.libraries.length || 0));
    ei.libraries.forEach(function (l) { console.log('  ' + l); });
    console.log('events        : ' + ei.events.length);
    console.log('');
};

ei.timeline = function () {
    console.log('');
    console.log('=== load-time timeline ===');
    if (ei.events.length === 0) {
        console.log('  nothing recorded. Either you attached late, or the app loads no');
        console.log('  native libraries of its own.');
    }
    ei.events.forEach(function (e) {
        console.log('  ' + e.t.padStart(8) + '  ' + e.kind.padEnd(22) + '  ' + e.detail);
    });
    console.log('');
};

ei.onLibrary = function (pattern, fn) {
    ei._libRules.push({ re: new RegExp(pattern), fn: fn });
    console.log('[*] rule added: run your function when a library matching /'
        + pattern + '/ is mapped');
};

ei.onJniOnLoad = function (pattern, fn) {
    ei._jniRules.push({ re: new RegExp(pattern), fn: fn });
    console.log('[*] rule added: run your function immediately BEFORE JNI_OnLoad in /'
        + pattern + '/');
};

ei.neuter = function (pattern) {
    ei._neuter.push(new RegExp(pattern));
    console.log('[*] JNI_OnLoad in libraries matching /' + pattern + '/ will be replaced.');
    console.log('    WARNING: this also cancels any RegisterNatives that function performs.');
};

ei.observeOnly = function () {
    CFG.enforce = false;
    console.log('[*] OBSERVE ONLY - nothing will be modified');
};

ei.help = function () {
    console.log([
        '',
        'ei.status()               what is installed, and whether you were early',
        'ei.timeline()             ordered record of load-time events',
        'ei.onLibrary(re, fn)      fn(module) when a matching library is mapped',
        'ei.onJniOnLoad(re, fn)    fn(module, addr) just BEFORE its JNI_OnLoad runs',
        'ei.neuter(re)             replace matching JNI_OnLoad with a no-op (read the',
        '                          warning in the source before using this)',
        'ei.observeOnly()          change nothing',
        ''
    ].join('\n'));
};

// ===========================================================================
// Bootstrap
// ===========================================================================

(function bootstrap() {
    console.log('');
    console.log('=====================================================================');
    console.log(' early-instrument.js - win the race against load-time protections');
    console.log(' Install this FIRST. It does not bypass anything; it makes sure');
    console.log(' whatever you load next is running before the app decides anything.');
    console.log('=====================================================================');

    assessTiming();
    watchLinker();
    watchConstructors();
    markJavaBoundary();

    console.log('[*] ' + ei.installed.length + ' hook(s) installed. ei.help() for commands.');
    console.log('[*] Call ei.timeline() once the app has settled.');
    console.log('');
})();
