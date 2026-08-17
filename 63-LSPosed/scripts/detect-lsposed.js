// scripts/detect-lsposed.js
//
// detect-lsposed.js -- ask, from INSIDE a running process, whether an Xposed /
//                      LSPosed framework is present in it, using four
//                      independent in-process signals, and report each one
//                      separately rather than collapsing them into a boolean.
//
// WHY FOUR SIGNALS AND NOT ONE
//   Every one of these is defeatable on its own, because the checker and the
//   thing it checks share an address space -- the argument chapter 65 makes for
//   native hooks and this chapter's section 5.5 makes for managed ones. A module
//   that hooks ClassLoader.loadClass beats signal 1; one that hooks
//   Throwable.getStackTrace beats signal 3. Defeating all four at once is
//   possible and costs real work, and that cost is the whole value.
//
//   This script therefore reports a VECTOR, not a verdict. A tool that prints
//   "LSPosed: NOT DETECTED" is telling you what it failed to see.
//
// THE FOUR SIGNALS
//   1. API PRESENCE   Is de.robv.android.xposed.XposedBridge (or the libxposed
//                     equivalent) resolvable in this process? A scoped app's
//                     process has the framework loaded; an unscoped one does
//                     not. This distinguishes "LSPosed is installed on the
//                     device" from "this app is being hooked", which are
//                     different questions with different answers.
//   2. FOREIGN LOADER Walk every ClassLoader reachable in the process and list
//                     any whose DEX path is not this application's own APK. A
//                     module's DEX had to be loaded by something.
//   3. STACK FRAME    Throw and catch inside a method you suspect is hooked. If
//                     a dispatcher sits between the method and its caller, the
//                     stack names it. This is what "before -> backup -> after"
//                     (chapter section 3.10) MEANS, expressed as an observable.
//   4. ENTRY POINT    Read ArtMethod.entry_point_from_quick_compiled_code_ and
//                     ask whether it falls inside the boot image, the app's
//                     .odex, or the JIT code cache. Anywhere else is a hook.
//                     Mechanism owned by ../../13-ART/README.md; this script
//                     uses the RANGES, not a hard-coded field offset.
//
// HOW TO RUN
//   frida -U -f com.pentest.ch63.vault -l detect-lsposed.js
//   frida -U -n com.pentest.ch63.vault -l detect-lsposed.js
//
//   Then, from the REPL:
//     lsp.scan()                                  // all four signals, one report
//     lsp.api()                                   // signal 1 only
//     lsp.loaders()                               // signal 2 only
//     lsp.stack("com.pentest.ch63.vault.VaultGate", "isUnlocked")   // signal 3
//     lsp.ranges()                                // the legitimate code ranges
//
// REQUIREMENTS
//   frida-server on the device, matching your frida CLI, and therefore root.
//
// HONESTY NOTE -- READ THIS BEFORE QUOTING ANY OUTPUT
//   This script was NOT executed against a live LSPosed installation while the
//   chapter was written. The only device available was an AVD
//   (sdk_gphone16k_x86_64, Android 15 / API 35) with Magisk 30.7, Zygisk OFF and
//   no LSPosed -- so the framework could not have been running. Signals 2, 3 and
//   4 exercise ordinary runtime structures and were checked against an ordinary
//   process; signal 1 and the LSPosed-specific name matching are reviewed code,
//   not measured output. Chapter section 7.1 records the same gap. If you run
//   this against a real LSPosed device, the numbers you get are better than the
//   ones in the chapter, and they are yours.
//
// ETHICS
//   Point this at a process you own. It reads; it changes nothing.

'use strict';

var FRAMEWORK_CLASSES = [
    'de.robv.android.xposed.XposedBridge',
    'de.robv.android.xposed.XposedHelpers',
    'de.robv.android.xposed.XC_MethodHook',
    'io.github.libxposed.api.XposedInterface'
];

// Substrings that identify a hooking framework's own frames or class names.
var FRAMEWORK_MARKERS = [
    'de.robv.android.xposed',
    'io.github.libxposed',
    'org.lsposed',
    'LSPHooker',
    'EdHooker',
    'lspd'
];

function line(s) { console.log(s); }
function hr() { line('----------------------------------------------------------------------'); }

function marked(s) {
    if (!s) return false;
    for (var i = 0; i < FRAMEWORK_MARKERS.length; i++) {
        if (s.indexOf(FRAMEWORK_MARKERS[i]) !== -1) return true;
    }
    return false;
}

// -------------------------------------------------------------- signal 1: API

function signalApi() {
    var found = [];
    Java.perform(function () {
        FRAMEWORK_CLASSES.forEach(function (name) {
            try {
                var k = Java.use(name);
                var loader = null;
                try { loader = k.class.getClassLoader(); } catch (e) { /* ignore */ }
                found.push({
                    name: name,
                    loader: loader ? String(loader.getClass().getName()) : '<boot>'
                });
            } catch (e) {
                // ClassNotFound is the CLEAN result.
            }
        });
    });
    return found;
}

// ---------------------------------------------------- signal 2: class loaders

function signalLoaders() {
    var out = [];
    Java.perform(function () {
        var seen = {};
        Java.enumerateClassLoadersSync().forEach(function (cl) {
            var s;
            try { s = String(cl.toString()); } catch (e) { s = '<toString failed>'; }
            if (seen[s]) return;
            seen[s] = true;
            out.push(s);
        });
    });
    return out;
}

function ownApkPath() {
    var p = null;
    Java.perform(function () {
        try {
            var ActivityThread = Java.use('android.app.ActivityThread');
            var app = ActivityThread.currentApplication();
            if (app !== null) {
                p = String(app.getApplicationInfo().sourceDir.value);
            }
        } catch (e) { /* no Application yet */ }
    });
    return p;
}

// ---------------------------------------------------------- signal 3: a stack

function signalStack(className, methodName) {
    var hits = [];
    Java.perform(function () {
        var target;
        try {
            target = Java.use(className);
        } catch (e) {
            line('  cannot resolve ' + className + ': ' + e);
            return;
        }
        var overloads = target[methodName];
        if (!overloads) {
            line('  no method ' + methodName + ' on ' + className);
            return;
        }
        overloads.overloads.forEach(function (ov) {
            ov.implementation = function () {
                // Build a Java stack from INSIDE the method. If a dispatcher
                // wraps us, it is on this stack.
                var Log = Java.use('android.util.Log');
                var Exception = Java.use('java.lang.Exception');
                var trace = String(Log.getStackTraceString(Exception.$new('ch63-probe')));
                trace.split('\n').forEach(function (fr) {
                    if (marked(fr)) hits.push(fr.trim());
                });
                return ov.apply(this, arguments);
            };
        });
        line('  probe installed on ' + className + '.' + methodName +
             ' (' + overloads.overloads.length + ' overload(s))');
        line('  exercise the app, then run lsp.stackResults()');
    });
    return hits;
}

var stackHits = [];

// -------------------------------------------------- signal 4: entry-point range

// The legitimate homes for compiled code. Anything outside them is a hook or a
// bug -- see art/runtime/entrypoints/quick/quick_trampoline_entrypoints.cc for
// why a trampoline value is also legitimate.
function legitimateRanges() {
    var ranges = [];
    Process.enumerateModules().forEach(function (m) {
        if (/boot.*\.(art|oat)$/.test(m.name) ||
            /\.odex$/.test(m.name) ||
            /\.oat$/.test(m.name) ||
            /libart\.so$/.test(m.name)) {
            ranges.push({ name: m.name, base: m.base, size: m.size });
        }
    });
    // The JIT code cache is anonymous rx memory owned by the runtime.
    Process.enumerateRanges('r-x').forEach(function (r) {
        if (!r.file) ranges.push({ name: '<anonymous r-x (JIT cache?)>', base: r.base, size: r.size });
    });
    return ranges;
}

function inAnyRange(ptr, ranges) {
    for (var i = 0; i < ranges.length; i++) {
        var start = ranges[i].base;
        var end = start.add(ranges[i].size);
        if (ptr.compare(start) >= 0 && ptr.compare(end) < 0) return ranges[i].name;
    }
    return null;
}

// ------------------------------------------------------------------ reporting

var lsp = {

    api: function () {
        var found = signalApi();
        line('');
        line('SIGNAL 1 - Xposed API resolvable in THIS process');
        if (found.length === 0) {
            line('  none. Either no framework is installed, or this package is');
            line('  not in any module\'s scope, or the lookup itself is hooked.');
        } else {
            found.forEach(function (f) {
                line('  ' + f.name + '   (loader: ' + f.loader + ')');
            });
            line('  -> a hooking framework is loaded INTO THIS PROCESS.');
        }
        return found;
    },

    loaders: function () {
        var own = ownApkPath();
        var all = signalLoaders();
        line('');
        line('SIGNAL 2 - class loaders in this process');
        line('  own APK: ' + (own || '<unknown - no Application yet>'));
        var foreign = 0;
        all.forEach(function (s) {
            var isForeign = own && s.indexOf('.apk') !== -1 && s.indexOf(own) === -1;
            if (isForeign || marked(s)) foreign++;
            line((isForeign || marked(s) ? '  [FOREIGN] ' : '            ') + s);
        });
        line('  ' + all.length + ' loader(s), ' + foreign + ' not backed by this app\'s APK.');
        if (foreign > 0) {
            line('  -> something loaded DEX into this process that is not this app.');
            line('     A module APK path here NAMES the module.');
        }
        return all;
    },

    stack: function (className, methodName) {
        line('');
        line('SIGNAL 3 - dispatcher frames on our own stack');
        stackHits = signalStack(className, methodName);
        return stackHits;
    },

    stackResults: function () {
        line('');
        line('SIGNAL 3 results - ' + stackHits.length + ' framework frame(s) seen');
        stackHits.forEach(function (h) { line('  ' + h); });
        if (stackHits.length === 0) {
            line('  none. The method either was not called, or is not hooked, or');
            line('  the framework filters getStackTrace. All three are possible.');
        }
        return stackHits;
    },

    ranges: function () {
        var r = legitimateRanges();
        line('');
        line('SIGNAL 4 - legitimate ranges for compiled code (' + r.length + ')');
        r.slice(0, 25).forEach(function (x) {
            line('  ' + x.base + ' +' + x.size + '  ' + x.name);
        });
        if (r.length > 25) line('  ... ' + (r.length - 25) + ' more');
        line('  A method entry point OUTSIDE all of these is a hook, or a bug.');
        line('  Read the entry point itself with ../../13-ART/scripts/artmethod-inspect.js,');
        line('  which derives the field offset rather than hard-coding it - ART is a');
        line('  Mainline module since API 29 and the layout is not a constant.');
        return r;
    },

    inRange: function (addrString) {
        var p = ptr(addrString);
        var where = inAnyRange(p, legitimateRanges());
        line('  ' + addrString + ' -> ' + (where || '*** OUTSIDE EVERY KNOWN RANGE ***'));
        return where;
    },

    scan: function () {
        hr();
        line('detect-lsposed.js  --  four independent in-process signals');
        line('process: ' + Process.id + '  arch: ' + Process.arch +
             '  pointerSize: ' + Process.pointerSize);
        hr();
        var api = lsp.api();
        var loaders = lsp.loaders();
        lsp.ranges();
        line('');
        hr();
        line('SUMMARY');
        line('  API resolvable here        : ' + (api.length ? 'YES (' + api.length + ' classes)' : 'no'));
        line('  class loaders              : ' + loaders.length);
        line('  stack probe                : run lsp.stack("<class>", "<method>") then');
        line('                               exercise the app and lsp.stackResults()');
        line('');
        line('  This is a VECTOR, not a verdict. Each signal is independently');
        line('  defeatable by a module that hooks the thing doing the checking.');
        line('  Absence of all four raises confidence; it does not prove absence.');
        hr();
        return { api: api, loaders: loaders.length };
    }
};

global.lsp = lsp;

console.log('detect-lsposed.js loaded. Run lsp.scan() for all four signals.');
console.log('Then: lsp.stack("com.pentest.ch63.vault.VaultGate", "isUnlocked")');
console.log('      exercise the app, and lsp.stackResults()');
