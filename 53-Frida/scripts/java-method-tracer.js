/*
 * java-method-tracer.js — trace Java methods with arguments, return values,
 *                         timing and a filtered stack trace.
 *
 * WHAT IT DOES
 *   Hooks Java methods matched by wildcard patterns and prints, per call:
 *     - the fully-qualified method and the overload signature that fired
 *     - every argument, rendered by type (arrays hexdumped, objects toString'd)
 *     - the return value, or the exception if one was thrown
 *     - elapsed time in microseconds
 *     - optionally, the Java stack trace filtered to the app's own packages
 *
 *   It exists because `frida-trace -j` gives you handler files but not a
 *   configurable, single-session, RPC-controllable view — and because the
 *   argument rendering below is what turns "a method was called" into evidence.
 *
 * WHY IT WORKS
 *   Each hook is an ArtMethod entry-point rewrite. See ../README.md section 3.9
 *   and ../../13-ART/README.md section 3.17. If a hook installs and never fires,
 *   read ../README.md section 7.4 BEFORE assuming the app detected you.
 *
 * HOW TO RUN
 *   adb shell cmd package compile -m verify -f com.example.app
 *   adb shell am force-stop com.example.app
 *   frida -U -f com.example.app -l java-method-tracer.js --no-pause
 *
 *   Then from the REPL:
 *     trace.help()
 *     trace.cls("com.example.crypto.*")          // every method of matching classes
 *     trace.method("com.example.auth.Login", "check")
 *     trace.pattern("com.example.*", "*decrypt*")
 *     trace.framework()                          // the platform-boundary preset
 *     trace.stacks(true)                         // turn stack traces on
 *     trace.stop()                               // revert everything
 *     trace.stats()                              // call counts per method
 *
 *   Or drive it from a host script:
 *     script.exports_sync.cls("com.example.crypto.*")
 *
 * PERFORMANCE
 *   Tracing a class with hot methods (getters called thousands of times per
 *   second) will make the app unusable. Start narrow. `trace.stats()` tells you
 *   which method is drowning you; `trace.mute("name")` silences it.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var trace = {

    /* ------------------------------------------------------------ state */

    _hooks: [],              // {key, revert}
    _counts: {},             // key -> call count
    _muted: {},              // key -> true
    _showStacks: false,
    _maxArrayBytes: 64,
    _maxStringChars: 200,
    _appPrefix: null,        // set automatically from the package name
    _depth: 0,

    /* ------------------------------------------------------- formatting */

    /*
     * Render a single Java value for logging. This is the part that matters:
     * a byte[] printed as "[object Object]" is useless, and a 4 MB bitmap
     * printed in full is worse.
     */
    _fmt: function (v, typeName) {
        if (v === null || v === undefined) return 'null';

        try {
            // Primitive arrays: Frida gives a JS array of numbers.
            if (typeName && typeName.charAt(0) === '[') {
                var elem = typeName.charAt(1);
                if (elem === 'B') {                 // byte[]
                    return this._bytes(v);
                }
                if (elem === 'C') {                 // char[]
                    var s = '';
                    for (var i = 0; i < Math.min(v.length, this._maxStringChars); i++) {
                        s += String.fromCharCode(v[i]);
                    }
                    return 'char[' + v.length + '] "' + s + '"';
                }
                if (elem === 'L' || elem === '[') { // object array
                    var parts = [];
                    for (var j = 0; j < Math.min(v.length, 8); j++) {
                        parts.push(v[j] === null ? 'null' : String(v[j]));
                    }
                    return typeName + '[' + v.length + '] {' + parts.join(', ') +
                           (v.length > 8 ? ', …' : '') + '}';
                }
                // Numeric arrays
                var nums = [];
                for (var k = 0; k < Math.min(v.length, 16); k++) nums.push(v[k]);
                return typeName + '[' + v.length + '] {' + nums.join(', ') +
                       (v.length > 16 ? ', …' : '') + '}';
            }

            if (typeName === 'java.lang.String') {
                var str = String(v);
                return '"' + (str.length > this._maxStringChars
                    ? str.substring(0, this._maxStringChars) + '…(' + str.length + ')'
                    : str) + '"';
            }

            var out = String(v);
            if (out.length > this._maxStringChars) {
                out = out.substring(0, this._maxStringChars) + '…';
            }
            return out;
        } catch (e) {
            return '<unrenderable ' + (typeName || '?') + '>';
        }
    },

    _bytes: function (arr) {
        var n = Math.min(arr.length, this._maxArrayBytes);
        var hex = '';
        var ascii = '';
        for (var i = 0; i < n; i++) {
            var b = arr[i] & 0xff;
            hex += (b < 16 ? '0' : '') + b.toString(16);
            ascii += (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.';
        }
        return 'byte[' + arr.length + '] ' + hex +
               (arr.length > n ? '…' : '') + '  |' + ascii + '|';
    },

    /*
     * A Java stack trace, filtered to frames that belong to the app. The
     * unfiltered trace is 40 frames of android.* noise; the 3 frames that
     * matter are the app's own classes, and those are what let you walk back
     * up into obfuscated code (../README.md section 7.7).
     */
    _stack: function () {
        try {
            var Thread = Java.use('java.lang.Thread');
            var frames = Thread.currentThread().getStackTrace();
            var out = [];
            for (var i = 0; i < frames.length; i++) {
                var cls = frames[i].getClassName();
                if (cls.indexOf('java.lang.Thread') === 0) continue;
                if (cls.indexOf('com.frida') === 0) continue;
                var interesting = this._appPrefix === null ||
                                  cls.indexOf(this._appPrefix) === 0;
                if (interesting) {
                    out.push('      at ' + cls + '.' + frames[i].getMethodName() +
                             ':' + frames[i].getLineNumber());
                }
            }
            if (out.length === 0) {
                // Fall back to the unfiltered top few frames.
                for (var j = 1; j < Math.min(frames.length, 6); j++) {
                    out.push('      at ' + frames[j].getClassName() + '.' +
                             frames[j].getMethodName());
                }
            }
            return out.join('\n');
        } catch (e) {
            return '      <stack unavailable: ' + e.message + '>';
        }
    },

    _indent: function () {
        return new Array(this._depth + 1).join('  ');
    },

    /* ------------------------------------------------------------ hooking */

    /*
     * Hook every overload of one method. Returns the number of overloads
     * hooked. Guarded end to end: a class that vanished, a method that is
     * abstract, or an overload Frida cannot wrap must not abort the batch.
     */
    _hookMethod: function (klass, className, methodName) {
        var self = this;
        var member;

        try {
            member = klass[methodName];
        } catch (e) { return 0; }

        if (member === undefined) return 0;

        var overloads;
        try {
            overloads = member.overloads || [member];
        } catch (e) { return 0; }

        var hooked = 0;

        overloads.forEach(function (ov) {
            var sig, ret;
            try {
                sig = ov.argumentTypes.map(function (t) { return t.className; });
                ret = ov.returnType.className;
            } catch (e) { return; }

            var key = className + '.' + methodName + '(' + sig.join(',') + ')';
            var argTypes = sig;

            try {
                var original = ov.implementation;   // usually null; kept for revert

                ov.implementation = function () {
                    self._counts[key] = (self._counts[key] || 0) + 1;

                    if (self._muted[key]) {
                        return ov.apply(this, arguments);
                    }

                    var pad = self._indent();
                    var rendered = [];
                    for (var i = 0; i < arguments.length; i++) {
                        rendered.push(self._fmt(arguments[i], argTypes[i]));
                    }

                    console.log(pad + '-> ' + className + '.' + methodName +
                                '(' + rendered.join(', ') + ')');

                    if (self._showStacks) console.log(self._stack());

                    self._depth++;
                    var t0 = Date.now();
                    var result, threw = null;
                    try {
                        result = ov.apply(this, arguments);
                    } catch (e) {
                        threw = e;
                    }
                    var dt = Date.now() - t0;
                    self._depth--;

                    if (threw !== null) {
                        console.log(self._indent() + '<! ' + methodName +
                                    ' threw ' + threw + '  [' + dt + 'ms]');
                        throw threw;                 // preserve app semantics
                    }

                    if (ret === 'void') {
                        console.log(self._indent() + '<- ' + methodName +
                                    ' (void)  [' + dt + 'ms]');
                    } else {
                        console.log(self._indent() + '<- ' + methodName + ' = ' +
                                    self._fmt(result, ret) + '  [' + dt + 'ms]');
                    }
                    return result;
                };

                self._hooks.push({
                    key: key,
                    revert: function () {
                        try { ov.implementation = original; } catch (e) { /* ignore */ }
                    }
                });
                hooked++;
            } catch (e) {
                // Abstract methods, some synthetic bridges, and methods on
                // classes being redefined cannot be hooked. Not an error.
            }
        });

        return hooked;
    },

    /* -------------------------------------------------------- public API */

    /* Trace every declared method of every class matching a wildcard. */
    cls: function (classPattern) {
        var self = this;
        var re = this._wild(classPattern);
        var totalClasses = 0, totalMethods = 0;

        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (name) {
                    if (!re.test(name)) return;
                    var k;
                    try { k = Java.use(name); } catch (e) { return; }

                    var names = {};
                    try {
                        var declared = k.class.getDeclaredMethods();
                        for (var i = 0; i < declared.length; i++) {
                            names[declared[i].getName()] = true;
                        }
                    } catch (e) { return; }

                    var n = 0;
                    Object.keys(names).forEach(function (m) {
                        n += self._hookMethod(k, name, m);
                    });
                    if (n > 0) { totalClasses++; totalMethods += n; }
                },
                onComplete: function () {
                    console.log('[+] traced ' + totalMethods + ' method(s) across ' +
                                totalClasses + ' class(es) matching ' + classPattern);
                    if (totalClasses === 0) {
                        console.log('[!] No match. The class may not be LOADED yet, or');
                        console.log('    it may live in another ClassLoader. Try:');
                        console.log('      trace.loaders()      — list every loader');
                        console.log('    See ../README.md section 7.4.2.');
                    }
                }
            });
        });
        return totalMethods;
    },

    /* Trace one specific method (all overloads) on one specific class. */
    method: function (className, methodName) {
        var self = this;
        var n = 0;
        Java.perform(function () {
            var k;
            try {
                k = Java.use(className);
            } catch (e) {
                console.log('[-] ' + className + ' not found in the default loader.');
                console.log('    Searching every loader…');
                k = self._findInAnyLoader(className);
                if (k === null) {
                    console.log('[-] not found in any loaded loader either.');
                    return;
                }
            }
            n = self._hookMethod(k, className, methodName);
            console.log('[+] traced ' + n + ' overload(s) of ' +
                        className + '.' + methodName);
            if (n === 0) {
                console.log('[!] Zero overloads hooked. Either the method does not exist');
                console.log('    (R8 inlined or renamed it) or it is abstract.');
            }
        });
        return n;
    },

    /* Trace methods matching a name pattern within classes matching a pattern. */
    pattern: function (classPattern, methodPattern) {
        var self = this;
        var cre = this._wild(classPattern);
        var mre = this._wild(methodPattern);
        var total = 0;

        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (name) {
                    if (!cre.test(name)) return;
                    var k;
                    try { k = Java.use(name); } catch (e) { return; }
                    try {
                        var declared = k.class.getDeclaredMethods();
                        var seen = {};
                        for (var i = 0; i < declared.length; i++) {
                            var m = declared[i].getName();
                            if (seen[m] || !mre.test(m)) continue;
                            seen[m] = true;
                            total += self._hookMethod(k, name, m);
                        }
                    } catch (e) { /* skip */ }
                },
                onComplete: function () {
                    console.log('[+] traced ' + total + ' method(s) matching ' +
                                classPattern + '!' + methodPattern);
                }
            });
        });
        return total;
    },

    /*
     * The framework-boundary preset. When the app is obfuscated and you do not
     * know any of its class names, hook the PLATFORM instead — the app can
     * rename its own classes but not javax.crypto.Cipher.
     * See ../README.md section 6.4.
     */
    framework: function () {
        var self = this;
        var targets = [
            ['javax.crypto.Cipher', ['doFinal', 'update', 'init']],
            ['javax.crypto.Mac', ['doFinal', 'update', 'init']],
            ['javax.crypto.spec.SecretKeySpec', ['$init']],
            ['javax.crypto.spec.IvParameterSpec', ['$init']],
            ['java.security.MessageDigest', ['digest', 'update']],
            ['java.security.Signature', ['sign', 'verify', 'update']],
            ['java.util.Base64$Encoder', ['encodeToString']],
            ['java.util.Base64$Decoder', ['decode']],
            ['android.util.Base64', ['encodeToString', 'decode']],
            ['java.net.URL', ['openConnection']],
            ['android.util.Log', ['d', 'i', 'w', 'e', 'v']],
            ['java.lang.Runtime', ['exec', 'loadLibrary']],
            ['java.lang.System', ['loadLibrary', 'load']],
            ['java.lang.Class', ['forName']],
            ['java.lang.reflect.Method', ['invoke']],
            ['android.content.SharedPreferences$Editor', ['putString']],
            ['android.webkit.WebView', ['loadUrl', 'addJavascriptInterface', 'evaluateJavascript']],
            ['android.content.ContextWrapper', ['startActivity', 'sendBroadcast', 'startService']]
        ];

        var total = 0;
        Java.perform(function () {
            targets.forEach(function (t) {
                var k;
                try { k = Java.use(t[0]); } catch (e) { return; }
                t[1].forEach(function (m) {
                    total += self._hookMethod(k, t[0], m);
                });
            });
            console.log('[+] framework preset: ' + total + ' method(s) traced');
            console.log('    Exercise the app. Turn on stack traces to find the');
            console.log('    app class that called each one:  trace.stacks(true)');
        });
        return total;
    },

    /* ------------------------------------------------------------ control */

    stacks: function (on) {
        this._showStacks = (on !== false);
        console.log('[*] stack traces ' + (this._showStacks ? 'ON' : 'OFF'));
        return this._showStacks;
    },

    appPrefix: function (prefix) {
        this._appPrefix = prefix;
        console.log('[*] stack filter prefix = ' + prefix);
        return prefix;
    },

    mute: function (substring) {
        var n = 0;
        var self = this;
        Object.keys(this._counts).forEach(function (k) {
            if (k.indexOf(substring) !== -1) { self._muted[k] = true; n++; }
        });
        // Also mute future keys matching the pattern.
        this._muted['__pattern__' + substring] = true;
        console.log('[*] muted ' + n + ' known method(s) containing "' + substring + '"');
        return n;
    },

    stats: function () {
        var rows = Object.keys(this._counts).map(function (k) {
            return [k, this._counts[k]];
        }, this);
        rows.sort(function (a, b) { return b[1] - a[1]; });
        console.log('\n[*] call counts (most frequent first):');
        rows.slice(0, 40).forEach(function (r) {
            console.log(('        ' + r[1]).slice(-8) + '  ' + r[0]);
        });
        if (rows.length === 0) {
            console.log('    nothing has fired yet.');
            console.log('    If you expected hits, read ../README.md section 7.4.');
        }
        return rows.length;
    },

    stop: function () {
        var n = this._hooks.length;
        this._hooks.forEach(function (h) { h.revert(); });
        this._hooks = [];
        this._depth = 0;
        console.log('[*] reverted ' + n + ' hook(s)');
        return n;
    },

    /* -------------------------------------------------------- classloaders */

    loaders: function () {
        Java.perform(function () {
            var i = 0;
            Java.enumerateClassLoaders({
                onMatch: function (l) { console.log('[' + (i++) + '] ' + l); },
                onComplete: function () { console.log('[*] ' + i + ' loader(s)'); }
            });
        });
    },

    _findInAnyLoader: function (className) {
        var found = null;
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                if (found !== null) return;
                try {
                    loader.loadClass(className);
                    console.log('[+] found in ' + loader);
                    found = (typeof Java.ClassFactory !== 'undefined' &&
                             typeof Java.ClassFactory.get === 'function')
                        ? Java.ClassFactory.get(loader).use(className)
                        : (function () {
                            var prev = Java.classFactory.loader;
                            Java.classFactory.loader = loader;
                            var k = Java.use(className);
                            Java.classFactory.loader = prev;
                            return k;
                          })();
                } catch (e) { /* not this loader */ }
            },
            onComplete: function () {}
        });
        return found;
    },

    /* ---------------------------------------------------------- internals */

    /* Convert a shell-style wildcard into an anchored regular expression. */
    _wild: function (pattern) {
        var escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&')
                             .replace(/\*/g, '.*')
                             .replace(/\?/g, '.');
        return new RegExp('^' + escaped + '$');
    },

    help: function () {
        console.log([
            '',
            'trace.cls("com.example.crypto.*")        trace every method of matching classes',
            'trace.method("com.example.A", "check")   trace all overloads of one method',
            'trace.pattern("com.ex.*", "*decrypt*")   trace methods by name pattern',
            'trace.framework()                        the platform-boundary preset',
            '',
            'trace.stacks(true|false)                 Java stack trace on every call',
            'trace.appPrefix("com.example")           filter stacks to this package',
            'trace.mute("substring")                  silence noisy methods',
            'trace.stats()                            call counts, most frequent first',
            'trace.loaders()                          list every ClassLoader',
            'trace.stop()                             revert every hook',
            '',
            'If a hook never fires, read ../README.md section 7.4 before',
            'concluding the app detected you. The usual cause is inlining:',
            '  adb shell cmd package compile -m verify -f <pkg>',
            ''
        ].join('\n'));
    }
};

/* ---------------------------------------------------------- RPC surface */

rpc.exports = {
    init: function (stage, params) {
        console.log('[*] java-method-tracer loaded (stage=' + stage + ')');
        if (params && params.appPrefix) trace.appPrefix(params.appPrefix);
        if (params && params.framework) trace.framework();
    },
    dispose: function () { trace.stop(); },
    cls: function (p) { return trace.cls(p); },
    method: function (c, m) { return trace.method(c, m); },
    pattern: function (c, m) { return trace.pattern(c, m); },
    framework: function () { return trace.framework(); },
    stats: function () { return trace._counts; },
    stop: function () { return trace.stop(); }
};

/* --------------------------------------------------------------- bootstrap */

Java.perform(function () {
    console.log('');
    console.log('=== java-method-tracer ===');

    // Derive the app package automatically so stack filtering works with no
    // configuration. Guarded: this fails in a non-app process.
    try {
        var pkg = Java.use('android.app.ActivityThread').currentPackageName();
        if (pkg !== null) {
            // "com.example.app" -> filter on "com.example" so obfuscated
            // subpackages still match.
            var parts = String(pkg).split('.');
            trace._appPrefix = parts.slice(0, Math.min(2, parts.length)).join('.');
            console.log('[*] package = ' + pkg + ', stack filter = ' + trace._appPrefix);
        }
    } catch (e) {
        console.log('[.] could not determine package name: ' + e.message);
    }

    console.log('[+] ready — type trace.help()');
    console.log('');
});
