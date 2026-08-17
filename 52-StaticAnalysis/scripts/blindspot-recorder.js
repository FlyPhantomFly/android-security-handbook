// blindspot-recorder.js -- measure what a static sweep could NOT have seen.
//
// frida -U -f com.example.target -l blindspot-recorder.js --no-pause
// frida -U -n com.example.target -l blindspot-recorder.js
//
// WHAT IT DOES
//   Chapter 52 section 3.9 lists the things static analysis structurally cannot
//   observe: receivers registered at runtime, reflective dispatch, DEX loaded
//   after installation, native libraries loaded by name, and native methods
//   bound with RegisterNatives instead of by symbol name. This script hooks all
//   five and produces a DELTA REPORT -- a list of the things that happened that
//   an APK-based tool had no way to know about.
//
//   The point is not to bypass anything. The point is that the "limits of this
//   assessment" section of your report should contain measurements rather than
//   boilerplate. Chapter 29 established the scale of the problem on a live
//   device: 299 of 431 distinct broadcast actions registered by third-party
//   processes had NO manifest-declared receiver anywhere -- 69% of the surface,
//   invisible to every tool that reads files.
//
// WHAT THIS WILL *NOT* TELL YOU
//   - Anything about code paths you did not exercise. This is dynamic analysis:
//     it sees what happened while you were watching. Drive the app properly --
//     log in, navigate, background it, rotate it, let it sit -- and say in the
//     report how long you drove it and what you covered. An empty section here
//     means "not observed in N minutes of use", never "does not happen".
//   - Anything that happened before the hooks were installed. Use -f to spawn,
//     not -n to attach, if you care about Application.onCreate and about the
//     ContentProviders that run before it. Attaching to a running process
//     misses every registration made at startup, which is most of them.
//   - The class that a RegisterNatives call belongs to. The JNIEnv* and jclass
//     are available at the hook, but resolving the jclass to a name from inside
//     Interceptor requires a JNI call on a thread whose state is not ours to
//     assume. This script reports the method names, signatures, function
//     pointers and owning module, which is enough to find them in Ghidra, and
//     it does not guess at the class.
//   - Whether anything observed is a vulnerability. Every line is an
//     observation. A reflective call is normal; 200 of them are normal. What
//     matters is which targets appear and whether any of them are yours.
//   - Anything on an app that detects Frida and refuses to run. See chapter 37
//     and chapter 67.
//
// REQUIREMENTS
//   frida-server running on the device, matching your frida client version.
//   Root. Nothing else.
//
// RELATED
//   ../README.md section 3.9   the blind spots, and why they are structural
//   ../README.md section 7.2   how this script's output enters the report
//   ../README.md section 5.3   the report template that consumes it
//   ./static-sweep.py          the static side; its BLIND SPOTS section names
//                              the same five mechanisms from the file side
//   ../../29-BroadcastReceivers/README.md  where the 69% number comes from
//   ../../16-JNI/README.md                 RegisterNatives, in depth
//   ../../53-Frida/README.md               everything about the tool itself
//
// AUTHORISED TESTING ONLY.

'use strict';

var seen = {
    receivers: {},      // action -> count
    receiverSites: [],  // {actions, stack}
    reflect: {},        // "Class.method" -> count
    dexLoads: [],       // {kind, detail}
    libLoads: {},       // name -> count
    natives: [],        // {name, sig, ptr, module}
    startedAt: Date.now()
};

function bump(map, key) {
    map[key] = (map[key] || 0) + 1;
}

function shortStack(maxFrames) {
    try {
        var Exception = Java.use('java.lang.Exception');
        var Log = Java.use('android.util.Log');
        var text = Log.getStackTraceString(Exception.$new());
        var lines = text.split('\n').slice(1, 1 + (maxFrames || 6));
        return lines.map(function (l) { return l.trim(); }).join('\n            ');
    } catch (e) {
        return '(stack unavailable: ' + e + ')';
    }
}

// ---------------------------------------------------------------------------
// 1. Receivers registered at runtime -- the largest blind spot by volume.
//
//    registerReceiver has many overloads and they have changed across API
//    levels (the API 33 exported-flag overloads are the newest). Rather than
//    naming overloads, hook every overload of the method by iterating them,
//    which keeps this script working across versions.
// ---------------------------------------------------------------------------

function hookRegisterReceiver() {
    var targets = ['android.content.ContextWrapper', 'android.app.ContextImpl'];
    targets.forEach(function (className) {
        var Klass;
        try {
            Klass = Java.use(className);
        } catch (e) {
            return;                       // not present on this API level
        }
        if (!Klass.registerReceiver) { return; }
        Klass.registerReceiver.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var actions = [];
                try {
                    // The IntentFilter is whichever argument is one; its
                    // position differs between overloads.
                    for (var i = 0; i < arguments.length; i++) {
                        var a = arguments[i];
                        if (a !== null && a !== undefined &&
                            a.$className === 'android.content.IntentFilter') {
                            var n = a.countActions();
                            for (var k = 0; k < n; k++) {
                                actions.push(a.getAction(k));
                            }
                        }
                    }
                } catch (e) { /* keep going: never break the app */ }

                if (actions.length) {
                    actions.forEach(function (act) { bump(seen.receivers, act); });
                    seen.receiverSites.push({
                        actions: actions,
                        stack: shortStack(4)
                    });
                    console.log('[receiver] ' + actions.join(', '));
                }
                return ov.apply(this, arguments);
            };
        });
    });
}

// ---------------------------------------------------------------------------
// 2. Reflection -- every call here is an edge your call graph does not have.
// ---------------------------------------------------------------------------

function hookReflection() {
    var Method = Java.use('java.lang.reflect.Method');
    Method.invoke.overload('java.lang.Object', '[Ljava.lang.Object;')
        .implementation = function (target, args) {
            try {
                var declaring = this.getDeclaringClass().getName();
                bump(seen.reflect, declaring + '.' + this.getName());
            } catch (e) { /* ignore */ }
            return this.invoke(target, args);
        };

    var ClassK = Java.use('java.lang.Class');
    ClassK.forName.overload('java.lang.String').implementation = function (name) {
        bump(seen.reflect, 'Class.forName(' + name + ')');
        return this.forName(name);
    };
}

// ---------------------------------------------------------------------------
// 3. Runtime code loading -- when this fires, the artefact you swept is not
//    the program that is running.
// ---------------------------------------------------------------------------

function hookCodeLoading() {
    ['dalvik.system.DexClassLoader',
     'dalvik.system.PathClassLoader',
     'dalvik.system.InMemoryDexClassLoader',
     'dalvik.system.DelegateLastClassLoader'].forEach(function (className) {
        var Loader;
        try {
            Loader = Java.use(className);
        } catch (e) {
            return;
        }
        Loader.$init.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var detail = [];
                for (var i = 0; i < arguments.length; i++) {
                    var a = arguments[i];
                    if (a === null || a === undefined) { continue; }
                    if (typeof a === 'string') { detail.push(a); }
                    else if (a.$className === 'java.nio.ByteBuffer' ||
                             a.$className === '[Ljava.nio.ByteBuffer;') {
                        detail.push('<in-memory buffer>');
                    }
                }
                seen.dexLoads.push({
                    kind: className,
                    detail: detail.join(' | ') || '(no string arguments)',
                    stack: shortStack(4)
                });
                console.log('[dexload] ' + className + '  ' + detail.join(' | '));
                return ov.apply(this, arguments);
            };
        });
    });
}

function hookLibraryLoading() {
    var System = Java.use('java.lang.System');
    System.loadLibrary.overload('java.lang.String').implementation = function (n) {
        bump(seen.libLoads, n);
        console.log('[loadLibrary] ' + n);
        return this.loadLibrary(n);
    };
    System.load.overload('java.lang.String').implementation = function (p) {
        bump(seen.libLoads, p);
        console.log('[System.load] ' + p);
        return this.load(p);
    };
}

// ---------------------------------------------------------------------------
// 4. RegisterNatives -- the binding that leaves no symbol behind.
//
//    art::JNI::RegisterNatives(JNIEnv*, jclass, const JNINativeMethod*, jint)
//    The symbol is mangled and its exact spelling differs between ART versions,
//    so find it by substring rather than by name. CheckJNI wraps it with a
//    second symbol; skip that one or every method is counted twice.
//
//    JNINativeMethod is three pointers: { const char* name;
//                                         const char* signature;
//                                         void* fnPtr; }
// ---------------------------------------------------------------------------

function hookRegisterNatives() {
    var libart = Process.findModuleByName('libart.so');
    if (libart === null) {
        console.log('[!] libart.so not found; RegisterNatives not hooked');
        return;
    }
    var candidates = libart.enumerateSymbols().filter(function (s) {
        return s.name.indexOf('RegisterNatives') !== -1 &&
               s.name.indexOf('CheckJNI') === -1 &&
               s.name.indexOf('RegisterNativeMethods') === -1;
    });
    if (!candidates.length) {
        console.log('[!] no RegisterNatives symbol in libart.so. On a stripped');
        console.log('    build you must find it by pattern instead -- see');
        console.log('    chapter 16. This section of the report will be empty');
        console.log('    and that is a gap, not a clean result.');
        return;
    }
    var ptrSize = Process.pointerSize;
    candidates.forEach(function (sym) {
        try {
            Interceptor.attach(sym.address, {
                onEnter: function (args) {
                    var methods = args[2];
                    var count = args[3].toInt32();
                    if (count < 0 || count > 4096) { return; }
                    for (var i = 0; i < count; i++) {
                        var base = methods.add(i * ptrSize * 3);
                        var name = base.readPointer().readCString();
                        var sig = base.add(ptrSize).readPointer().readCString();
                        var fn = base.add(ptrSize * 2).readPointer();
                        var mod = Process.findModuleByAddress(fn);
                        seen.natives.push({
                            name: name,
                            sig: sig,
                            ptr: fn.toString(),
                            module: mod ? (mod.name + '+0x' +
                                   fn.sub(mod.base).toString(16)) : '(unknown)'
                        });
                    }
                    console.log('[RegisterNatives] ' + count + ' method(s)');
                }
            });
        } catch (e) {
            console.log('[!] could not attach to ' + sym.name + ': ' + e);
        }
    });
}

// ---------------------------------------------------------------------------
// The delta report
// ---------------------------------------------------------------------------

function keysByCount(map) {
    return Object.keys(map).sort(function (a, b) { return map[b] - map[a]; });
}

function report() {
    var minutes = ((Date.now() - seen.startedAt) / 60000).toFixed(1);
    var out = [];
    out.push('');
    out.push('==============================================================');
    out.push(' DELTA: what static analysis could not have told you');
    out.push(' observation window: ' + minutes + ' minutes');
    out.push('==============================================================');

    var acts = keysByCount(seen.receivers);
    out.push('');
    out.push('  runtime-registered receivers   ' + acts.length +
             ' distinct action(s) across ' + seen.receiverSites.length +
             ' registration(s)');
    acts.slice(0, 40).forEach(function (a) {
        out.push('      ' + a + '   x' + seen.receivers[a]);
    });
    if (acts.length > 40) { out.push('      ... and ' + (acts.length - 40) + ' more'); }
    out.push('');
    out.push('      Cross-check each against the manifest. Anything not');
    out.push('      declared there was invisible to your sweep. Chapter 29');
    out.push('      measured 69% of the surface living exactly here.');

    var refs = keysByCount(seen.reflect);
    out.push('');
    out.push('  reflective invocations         ' + refs.length + ' distinct target(s)');
    refs.slice(0, 30).forEach(function (r) {
        out.push('      ' + r + '   x' + seen.reflect[r]);
    });
    if (refs.length > 30) { out.push('      ... and ' + (refs.length - 30) + ' more'); }
    out.push('');
    out.push('      Most of these are framework and library plumbing. Read the');
    out.push('      list for targets in the APP\'s own package: those are call');
    out.push('      graph edges you do not have.');

    out.push('');
    out.push('  runtime DEX loading            ' + seen.dexLoads.length + ' event(s)');
    seen.dexLoads.forEach(function (d) {
        out.push('      ' + d.kind + '  ' + d.detail);
        out.push('            ' + d.stack);
    });
    if (!seen.dexLoads.length) {
        out.push('      None observed. Note the wording: not observed, in this');
        out.push('      window, on this path.');
    }

    var libs = keysByCount(seen.libLoads);
    out.push('');
    out.push('  native libraries loaded        ' + libs.length);
    libs.forEach(function (l) { out.push('      ' + l + '   x' + seen.libLoads[l]); });

    out.push('');
    out.push('  RegisterNatives bindings       ' + seen.natives.length + ' method(s)');
    seen.natives.slice(0, 60).forEach(function (n) {
        out.push('      ' + n.name + n.sig + '  ->  ' + n.module);
    });
    if (seen.natives.length > 60) {
        out.push('      ... and ' + (seen.natives.length - 60) + ' more');
    }
    if (seen.natives.length) {
        out.push('');
        out.push('      None of these have a Java_-prefixed symbol in the .so.');
        out.push('      readelf --dyn-syms would have shown you nothing.');
    }

    out.push('');
    out.push('==============================================================');
    out.push(' Every line above is an OBSERVATION, not a finding, and the');
    out.push(' absence of a line means "not seen in ' + minutes + ' minutes",');
    out.push(' never "does not happen". Put the window length in the report.');
    out.push('==============================================================');
    out.push('');

    var text = out.join('\n');
    console.log(text);
    return text;
}

rpc.exports = {
    report: report,
    raw: function () { return seen; }
};

Java.perform(function () {
    hookRegisterReceiver();
    hookReflection();
    hookCodeLoading();
    hookLibraryLoading();
    console.log('[*] blindspot-recorder armed (java hooks)');
});

setTimeout(function () {
    // libart is present from process start, but attaching from inside
    // Java.perform can race the runtime's own initialisation on some builds.
    hookRegisterNatives();
    console.log('[*] blindspot-recorder armed (native hooks)');
    console.log('[*] drive the app, then call: rpc.exports.report()');
}, 200);
