/*
 * jadx-blindspot.js -- observe, at runtime, the classes jadx could not decompile.
 *
 * PURPOSE
 *   Chapter 56 section 6.4: when jadx refuses a method you get an instruction dump and a
 *   `throw new UnsupportedOperationException("Method not decompiled: ...")`. Reading the dump
 *   is the rigorous move. But when the question is "what does this thing DO" rather than
 *   "what exactly does this thing do", hooking it blind is often thirty seconds against an
 *   hour -- and you do not need to understand a method to log its arguments and its return.
 *
 *   This script takes one or more class names -- exactly as jadx printed them -- hooks every
 *   declared method and constructor, and logs calls with arguments, return values and
 *   (optionally) a Java stack trace.
 *
 *   It is deliberately the INVERSE of the usual order. Normally you read to decide what to
 *   hook. Here you hook to decide what to read.
 *
 * USAGE
 *   frida -U -f com.example.app -l jadx-blindspot.js --no-pause
 *   frida -U -n com.example.app -l jadx-blindspot.js
 *
 *   Configure by editing CONFIG below, or from the Frida REPL:
 *     rpc.exports.hook('com.example.obf.a')
 *     rpc.exports.hook('com.example.obf.a', { stacks: true })
 *     rpc.exports.methods('com.example.obf.a')     // list without hooking
 *     rpc.exports.loaders()                        // enumerate ClassLoaders
 *
 * GETTING THE CLASS LIST OUT OF jadx
 *   # host -- every class with at least one method jadx refused
 *   grep -rl "Method not decompiled" out/sources \
 *     | sed 's|out/sources/||; s|\.java$||; s|/|.|g' > refused-classes.txt
 *
 *   Then feed the ones in the app's own package into CONFIG.classes. Do not feed it all of
 *   them: on a real app that list is over a thousand entries, most of them Kotlin
 *   default-argument constructors that refuse benignly (chapter section 6.8).
 *
 * REQUIREMENTS
 *   - frida-server running on the device, version matching your host `frida --version`.
 *   - Root, or a gadget-embedded APK. See ../../53-Frida/README.md.
 *   - On the reference device (Redmi M2101K6P, Android 11 / API 30, MIUI 12.5, rooted)
 *     frida-server is already running, so no push or chmod step is needed. That device is a
 *     daily driver -- attach and observe, do not install or mutate.
 *
 * WHAT THIS WILL NOT TELL YOU
 *   - It will NOT tell you what the method does on paths you did not exercise. It is an
 *     observation, not an analysis. A method with a branch you never trigger is a method you
 *     have not seen. For completeness you still need the bytecode.
 *   - It will NOT reveal a method's internal control flow, its exception ordering, or its
 *     intermediate state -- exactly the things a refused method's instruction dump WOULD tell
 *     you. Use this to prioritise; use ../../14-Dalvik/README.md to be certain.
 *   - It cannot hook a class that is not loaded yet, or one loaded by a ClassLoader that
 *     Java.use does not see. Run rpc.exports.loaders() and see chapter 53 section on the
 *     ClassLoader problem.
 *   - Hooking changes timing and can change behaviour. An app with anti-instrumentation
 *     checks may detect it -- see ../../37-RootDetection/README.md and
 *     chapter 38-TamperDetection.
 *   - If you ran jadx with --deobf, the class name in the output is a jadx ALIAS (C0000a) and
 *     Java.use will not find it. The real name is in the /* renamed from *\/ comment.
 *
 * CHAPTER
 *   ../README.md sections 7.1, 7.2, 7.3, 7.4
 */

'use strict';

var CONFIG = {
    // Fully-qualified class names, exactly as jadx printed them (NOT --deobf aliases).
    classes: [
        // 'com.example.obf.a',
    ],

    // Print a Java stack trace the first time each method is called.
    stacks: false,

    // Skip methods whose name looks like a trivial accessor. Set false to see everything.
    skipAccessors: true,

    // Truncate any single logged value to this many characters.
    maxValueChars: 300,

    // Also hook constructors.
    hookConstructors: true
};

var ACCESSOR = /^(get|set|is|has|component)[A-Z0-9_]|^(hashCode|equals|toString)$/;
var seen = {};

function trunc(s) {
    s = String(s);
    return s.length > CONFIG.maxValueChars
        ? s.slice(0, CONFIG.maxValueChars) + '...<' + s.length + ' chars>'
        : s;
}

/* Render a Java value usefully. Byte arrays are the common case that String() ruins. */
function render(v) {
    if (v === null || v === undefined) { return String(v); }
    try {
        if (typeof v === 'object' && v.$className === undefined && v.length !== undefined
            && typeof v.length === 'number') {
            // A Java array reached us as a JS array.
            if (v.length > 0 && typeof v[0] === 'number') {
                var hex = [];
                for (var i = 0; i < Math.min(v.length, 64); i++) {
                    hex.push(('0' + ((v[i] + 256) % 256).toString(16)).slice(-2));
                }
                return '[' + v.length + ' bytes] ' + hex.join('') + (v.length > 64 ? '...' : '');
            }
            return '[' + v.length + '] ' + trunc(v.join(', '));
        }
    } catch (e) { /* fall through */ }
    return trunc(v);
}

function stack() {
    try {
        return Java.use('android.util.Log')
                   .getStackTraceString(Java.use('java.lang.Exception').$new());
    } catch (e) {
        return '(stack unavailable: ' + e + ')';
    }
}

function hookOne(className, opts) {
    opts = opts || {};
    var stacks = (opts.stacks !== undefined) ? opts.stacks : CONFIG.stacks;

    var cls;
    try {
        cls = Java.use(className);
    } catch (e) {
        console.log('[!] cannot use ' + className + ': ' + e);
        console.log('    If you ran jadx with --deobf, this may be a jadx alias rather than the');
        console.log('    real name. Check the /* renamed from: */ comment in the .java file.');
        console.log('    If the name is right, the class may not be loaded yet, or may live in');
        console.log('    another ClassLoader -- try rpc.exports.loaders().');
        return 0;
    }

    var count = 0;

    if (CONFIG.hookConstructors) {
        try {
            cls.$init.overloads.forEach(function (ov) {
                var sig = ov.argumentTypes.map(function (t) { return t.className; }).join(', ');
                ov.implementation = function () {
                    var args = Array.prototype.slice.call(arguments);
                    console.log('[' + className + '.<init>(' + sig + ')] '
                                + args.map(render).join(' | '));
                    return ov.apply(this, args);
                };
                count++;
            });
        } catch (e) { /* no accessible constructors */ }
    }

    var declared;
    try {
        declared = cls.class.getDeclaredMethods();
    } catch (e) {
        console.log('[!] getDeclaredMethods failed on ' + className + ': ' + e);
        return count;
    }

    declared.forEach(function (m) {
        var name;
        try { name = m.getName(); } catch (e) { return; }
        if (CONFIG.skipAccessors && ACCESSOR.test(name)) { return; }
        if (!cls[name]) { return; }

        try {
            cls[name].overloads.forEach(function (ov) {
                var sig = ov.argumentTypes.map(function (t) { return t.className; }).join(', ');
                var label = className + '.' + name + '(' + sig + ')';
                ov.implementation = function () {
                    var args = Array.prototype.slice.call(arguments);
                    var rv, threw = null;
                    try {
                        rv = ov.apply(this, args);
                    } catch (e) {
                        threw = e;
                    }
                    console.log('[' + label + ']');
                    if (args.length) {
                        args.forEach(function (a, i) {
                            console.log('    arg' + i + ' = ' + render(a));
                        });
                    }
                    if (threw !== null) {
                        console.log('    THREW ' + threw);
                    } else {
                        console.log('    -> ' + render(rv));
                    }
                    if (stacks && !seen[label]) {
                        seen[label] = true;
                        console.log(stack());
                    }
                    if (threw !== null) { throw threw; }
                    return rv;
                };
                count++;
            });
        } catch (e) {
            console.log('[!] could not hook ' + className + '.' + name + ': ' + e);
        }
    });

    console.log('[+] ' + className + ': hooked ' + count + ' entry points');
    return count;
}

function listMethods(className) {
    try {
        var cls = Java.use(className);
        cls.class.getDeclaredMethods().forEach(function (m) {
            console.log('    ' + m.toString());
        });
        cls.class.getDeclaredFields().forEach(function (f) {
            console.log('  F ' + f.toString());
        });
    } catch (e) {
        console.log('[!] ' + e);
    }
}

function listLoaders() {
    Java.enumerateClassLoaders({
        onMatch: function (l) { console.log('    ' + l); },
        onComplete: function () { console.log('[+] end of ClassLoaders'); }
    });
}

rpc.exports = {
    hook: function (name, opts) { Java.perform(function () { hookOne(name, opts); }); },
    methods: function (name) { Java.perform(function () { listMethods(name); }); },
    loaders: function () { Java.perform(listLoaders); }
};

Java.perform(function () {
    console.log('=== jadx-blindspot.js ===');
    if (CONFIG.classes.length === 0) {
        console.log('No classes configured. Either edit CONFIG.classes at the top of this');
        console.log('file, or call rpc.exports.hook("com.example.Foo") from the REPL.');
        console.log('');
        console.log('To get the list from jadx:');
        console.log('  grep -rl "Method not decompiled" out/sources \\');
        console.log('    | sed \'s|out/sources/||; s|\\.java$||; s|/|.|g\'');
        return;
    }
    var total = 0;
    CONFIG.classes.forEach(function (c) { total += hookOne(c); });
    console.log('[+] ' + total + ' entry points hooked across '
                + CONFIG.classes.length + ' classes');
    console.log('    Remember: this shows you what happened on the paths you exercise.');
    console.log('    It does not show you the paths you do not. For that, read the bytecode:');
    console.log('    ../../14-Dalvik/README.md');
});
