// scripts/trace-method.js
//
// WHAT IT DOES
//     Hooks one or more Java/Kotlin methods that you located by reading Smali,
//     and prints, for every call:
//
//         - the actual argument values, decoded (byte arrays become hex-ish text
//           via Arrays.toString rather than "[object Object]")
//         - the actual return value
//         - a short stack trace naming the CALLER
//
//     Give it "com.example.Foo!bar" to hook one method (all overloads), or
//     "com.example.Foo" to hook every method on the class.
//
// WHY YOU WOULD RUN IT
//     Because reading Smali tells you what a method CAN do and this tells you
//     what it DID. The interesting question is almost never "what does this
//     method compute" -- it is "who calls it, with what, and what did it return
//     that made the app take that branch". That is a runtime question and Smali
//     cannot answer it.
//
//     Run this BEFORE you patch anything. Confirming a hypothesis takes seconds
//     here and fifteen minutes through a rebuild-sign-install cycle.
//
// HOW TO RUN
//     frida -U -f com.example.target -l scripts/trace-method.js --no-pause
//     frida -U -n com.example.target -l scripts/trace-method.js      # already running
//
//     Edit the TARGETS array below first. Entries are "Class!method" or "Class".
//
// REQUIREMENTS
//     frida-tools on the host, frida-server running on the device (or a
//     repackaged app carrying frida-gadget). Root, or a debuggable app.
//     See 53-Frida for setup.
//
// WHAT THIS WILL *NOT* TELL YOU
//     - It will not find classes that have not been loaded yet. If Java.use
//       fails with "class not found" the class either does not exist under that
//       name (check the descriptor against the Smali, exactly) or it lives in a
//       non-default ClassLoader. Packed and multi-DEX apps routinely use several
//       loaders; enumerate them with Java.enumerateClassLoaders and set
//       Java.classFactory.loader before calling Java.use.
//     - It will not see calls that were INLINED away by the AOT compiler. A hot
//       caller may have absorbed the callee entirely, in which case there is no
//       call instruction left to intercept. Force the method back to the
//       interpreter, or hook the caller instead. See 13-ART.
//     - It will not see native implementations. A .method native has no Java
//       body to replace; hook the JNI symbol instead.
//     - Calling toString() on an argument RUNS the app's code, which can have
//       side effects, can throw, and can itself be hooked or instrumented by
//       anti-analysis logic. describe() catches throws, but it cannot undo a
//       side effect.
//     - It changes timing. An app that measures its own execution time may
//       behave differently while this is attached.
//     - Hooking a method proves the hook landed. It does NOT prove the app's
//         behaviour changed. That needs an observable effect.
//
'use strict';

// Each entry: "fully.qualified.ClassName!methodName"  (methodName optional -> all methods)
var TARGETS = [
    'com.example.net.Pinner!verify',
    'com.example.Account!isPremium'
];

var MAX_STRING = 300;

function describe(v) {
    if (v === null || v === undefined) return String(v);
    try {
        if (typeof v === 'object' && v.$className !== undefined) {
            if (v.$className === '[B') {
                var J = Java.use('java.util.Arrays');
                return '[B ' + J.toString(v);
            }
            var s = v.toString();
            return v.$className + ' ' + (s.length > MAX_STRING ? s.substring(0, MAX_STRING) + '...' : s);
        }
        var t = String(v);
        return t.length > MAX_STRING ? t.substring(0, MAX_STRING) + '...' : t;
    } catch (e) {
        return '<toString failed: ' + e.message + '>';
    }
}

function hookOne(className, methodName) {
    var clazz;
    try {
        clazz = Java.use(className);
    } catch (e) {
        console.log('[!] class not loaded (yet): ' + className);
        return 0;
    }

    var names = methodName ? [methodName] : Object.keys(clazz).filter(function (k) {
        return k !== '$init' && typeof clazz[k] === 'function' && clazz[k].overloads !== undefined;
    });

    var count = 0;
    names.forEach(function (name) {
        var m = clazz[name];
        if (m === undefined || m.overloads === undefined) {
            console.log('[!] no such method: ' + className + '.' + name);
            return;
        }
        m.overloads.forEach(function (ov) {
            var sig = ov.argumentTypes.map(function (a) { return a.className; }).join(', ');
            ov.implementation = function () {
                var args = [];
                for (var i = 0; i < arguments.length; i++) args.push(describe(arguments[i]));
                console.log('\n--> ' + className + '.' + name + '(' + args.join(', ') + ')');
                var ret;
                try {
                    ret = ov.apply(this, arguments);
                } catch (e) {
                    console.log('<-- ' + name + ' THREW ' + e);
                    throw e;
                }
                console.log('<-- ' + name + ' = ' + describe(ret));
                console.log(Java.use('android.util.Log')
                    .getStackTraceString(Java.use('java.lang.Exception').$new())
                    .split('\n').slice(1, 8).join('\n'));
                return ret;
            };
            count++;
            console.log('[+] hooked ' + className + '.' + name + '(' + sig + ')');
        });
    });
    return count;
}

Java.perform(function () {
    var total = 0;
    TARGETS.forEach(function (t) {
        var parts = t.split('!');
        total += hookOne(parts[0], parts.length > 1 ? parts[1] : null);
    });
    console.log('[*] ' + total + ' method(s) hooked. Waiting.');
});
