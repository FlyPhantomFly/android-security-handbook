/*
 * hook-kotlin.js — Frida helpers for the Kotlin constructs that make hooking
 * awkward.
 *
 * WHAT IT DOES
 *   Kotlin's compiler generates code that does not match what you read in the
 *   source, and that mismatch is the cause of most "my hook doesn't work"
 *   reports against Kotlin apps. This script handles the specific cases:
 *
 *     kt.suspend(cls, method)     hook a suspend function correctly, including
 *                                 the trailing Continuation parameter
 *     kt.body(cls, method)        hook the generated SuspendLambda where the
 *                                 real coroutine logic actually lives
 *     kt.companion(cls)           reach a companion object's methods
 *     kt.object_(cls)             reach an `object` singleton via INSTANCE
 *     kt.defaults(cls, method)    hook the $default bridge and decode the
 *                                 bitmask of omitted arguments
 *     kt.extension(fileCls, m)    hook an extension function (a static method)
 *     kt.dataLeaks()              find data classes whose toString() is being
 *                                 logged — a recurring real-world finding
 *     kt.overloads(cls, method)   list every overload with its exact signature
 *     kt.intrinsics()             trace Intrinsics null checks as they fire
 *
 * HOW TO RUN
 *   frida -U -f com.example.target -l hook-kotlin.js
 *
 *   Then from the REPL:
 *     kt.overloads("com.example.LoginRepository", "login")
 *     kt.suspend("com.example.LoginRepository", "login")
 *     kt.dataLeaks()
 *
 * SEE ALSO
 *   ../README.md sections 6, 7 and 9.4 for what each construct compiles to.
 *   ../../13-ART/README.md section 3.17 for why entry-point hooking works.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var kt = {

    /* ------------------------------------------------------------ utils */

    _safe: function (fn, label) {
        try { return fn(); }
        catch (e) { console.log('[-] ' + label + ': ' + e); return null; }
    },

    _sig: function (overload) {
        try {
            return overload.argumentTypes
                .map(function (t) { return t.className; })
                .join(', ');
        } catch (e) { return '?'; }
    },

    _describe: function (v) {
        if (v === null || v === undefined) return String(v);
        try {
            var s = v.toString();
            return s.length > 300 ? s.substring(0, 300) + '…' : s;
        } catch (e) { return '<toString threw>'; }
    },

    /* --------------------------------------------------------- overloads */

    /*
     * List every overload of a method with its exact runtime signature.
     *
     * ALWAYS run this first against a Kotlin app. The signature you see here
     * is what .overload() needs, and it will differ from the Kotlin source
     * for suspend functions, default arguments and extension functions.
     */
    overloads: function (className, methodName) {
        var self = this;
        Java.perform(function () {
            var cls = self._safe(function () { return Java.use(className); },
                                 'Java.use(' + className + ')');
            if (cls === null) {
                console.log('    Try kt.findClass("' + className + '") — it may be');
                console.log('    loaded by a non-default ClassLoader.');
                return;
            }

            var member = cls[methodName];
            if (member === undefined) {
                console.log('[-] No member named "' + methodName + '" on ' + className);
                console.log('    Listing all declared methods instead:');
                var declared = cls.class.getDeclaredMethods();
                declared.forEach(function (m) { console.log('      ' + m.getName()); });
                return;
            }

            var list = member.overloads || [member];
            console.log('\n[*] ' + className + '.' + methodName +
                        '  (' + list.length + ' overload(s))');
            list.forEach(function (ov, i) {
                var sig = self._sig(ov);
                console.log('    [' + i + '] .overload(' +
                    (sig ? sig.split(', ').map(function (t) {
                        return '"' + t + '"';
                    }).join(', ') : '') + ')');

                if (sig.indexOf('kotlin.coroutines.Continuation') !== -1) {
                    console.log('         ^ SUSPEND function. The trailing Continuation is');
                    console.log('           compiler-added. Use kt.suspend() for this one.');
                }
                if (sig.indexOf('kotlin.jvm.internal.DefaultConstructorMarker') !== -1) {
                    console.log('         ^ synthetic constructor — compiler plumbing.');
                }
            });
            console.log('');
        });
    },

    /* ----------------------------------------------------------- suspend */

    /*
     * Hook a suspend function.
     *
     * The Kotlin source signature is NOT the runtime signature: the compiler
     * appends a Continuation parameter. This picks the right overload for you.
     *
     * NOTE: hooking here shows you the CALL, not the body. The body lives in
     * a generated SuspendLambda — use kt.body() for that.
     */
    suspend: function (className, methodName, onEnterCb) {
        var self = this;
        Java.perform(function () {
            var cls = self._safe(function () { return Java.use(className); },
                                 'Java.use(' + className + ')');
            if (cls === null) return;

            var member = cls[methodName];
            if (member === undefined) {
                console.log('[-] Method not found: ' + methodName);
                return;
            }

            var list = member.overloads || [member];
            var target = null;
            list.forEach(function (ov) {
                if (self._sig(ov).indexOf('kotlin.coroutines.Continuation') !== -1) {
                    target = ov;
                }
            });

            if (target === null) {
                console.log('[-] No overload with a Continuation parameter.');
                console.log('    ' + methodName + ' is probably NOT a suspend function.');
                console.log('    Run kt.overloads("' + className + '", "' + methodName + '")');
                return;
            }

            target.implementation = function () {
                var args = Array.prototype.slice.call(arguments);
                // The last argument is always the Continuation.
                var real = args.slice(0, args.length - 1);

                console.log('\n[suspend] ' + className + '.' + methodName);
                real.forEach(function (a, i) {
                    console.log('    arg[' + i + '] = ' + self._describe(a));
                });

                if (typeof onEnterCb === 'function') {
                    self._safe(function () { onEnterCb(real); }, 'callback');
                }

                var ret = this[methodName].apply(this, args);
                // The return value is usually COROUTINE_SUSPENDED, not the
                // real result — the real result arrives later via the
                // Continuation. This is why hooking here has limits.
                console.log('    immediate return = ' + self._describe(ret));
                console.log('    (if this is COROUTINE_SUSPENDED, the real result');
                console.log('     arrives asynchronously — use kt.body() instead)');
                return ret;
            };

            console.log('[+] Hooked suspend ' + className + '.' + methodName +
                        '(' + self._sig(target) + ')');
        });
    },

    /*
     * Hook the generated coroutine body.
     *
     * For `suspend fun foo()` inside class Bar, the compiler typically emits
     * a class named  Bar$foo$1  or  Bar$foo$2  extending SuspendLambda or
     * ContinuationImpl, whose invokeSuspend contains the actual logic.
     *
     * This searches for those generated classes and hooks invokeSuspend.
     */
    body: function (className, methodName) {
        var self = this;
        Java.perform(function () {
            var prefix = className + '$' + methodName + '$';
            var found = [];

            Java.enumerateLoadedClasses({
                onMatch: function (name) {
                    if (name.indexOf(prefix) === 0) found.push(name);
                },
                onComplete: function () {
                    if (found.length === 0) {
                        console.log('[-] No generated coroutine classes matching ' +
                                    prefix + '*');
                        console.log('    The class may not be loaded yet. Exercise the');
                        console.log('    feature once, then retry.');
                        return;
                    }

                    found.forEach(function (name) {
                        self._safe(function () {
                            var gen = Java.use(name);
                            if (gen.invokeSuspend === undefined) return;

                            gen.invokeSuspend.implementation = function (result) {
                                // `label` is the state machine's position.
                                var label = '?';
                                try { label = this.label.value; } catch (e) {}

                                console.log('\n[coroutine] ' + name +
                                            '.invokeSuspend  label=' + label);
                                console.log('    incoming = ' + self._describe(result));

                                var ret = this.invokeSuspend(result);
                                console.log('    returned = ' + self._describe(ret));
                                return ret;
                            };
                            console.log('[+] Hooked ' + name + '.invokeSuspend');
                        }, 'hook ' + name);
                    });

                    console.log('\n[*] Read the `label` values in order — each is one');
                    console.log('    segment between suspension points. See README 9.4.');
                }
            });
        });
    },

    /* ---------------------------------------------------- companion/object */

    /* companion object -> static nested class named Companion. */
    companion: function (className) {
        var self = this;
        Java.perform(function () {
            var name = className + '$Companion';
            var comp = self._safe(function () { return Java.use(name); }, name);
            if (comp === null) {
                console.log('[-] No companion found at ' + name);
                return;
            }
            console.log('[+] Companion: ' + name);
            var methods = comp.class.getDeclaredMethods();
            methods.forEach(function (m) {
                console.log('    ' + m.getName() + '  ' + m.toString());
            });
            console.log('\n    Call one with:');
            console.log('      Java.use("' + className + '").Companion.value.<method>(...)');
        });
    },

    /* `object Foo` -> singleton reachable through the static INSTANCE field. */
    object_: function (className) {
        var self = this;
        Java.perform(function () {
            var cls = self._safe(function () { return Java.use(className); }, className);
            if (cls === null) return;
            try {
                var inst = cls.INSTANCE.value;
                console.log('[+] Singleton INSTANCE of ' + className + ' = ' +
                            self._describe(inst));
                console.log('    Invoke members directly on this instance.');
                return inst;
            } catch (e) {
                console.log('[-] No INSTANCE field — ' + className +
                            ' is probably a normal class, not an `object`.');
            }
        });
    },

    /* ---------------------------------------------------------- defaults */

    /*
     * Hook the $default bridge and decode which arguments were omitted.
     *
     * Signature is: name$default(<real args...>, int mask, Object marker)
     * Bit n of the mask set means parameter n was NOT supplied by the caller,
     * so its default is used. Occasionally more informative than the resolved
     * values — e.g. did the caller explicitly disable a security option, or
     * merely accept the default?
     */
    defaults: function (className, methodName) {
        var self = this;
        Java.perform(function () {
            var cls = self._safe(function () { return Java.use(className); }, className);
            if (cls === null) return;

            var bridgeName = methodName + '$default';
            var member = cls[bridgeName];
            if (member === undefined) {
                console.log('[-] No $default bridge for ' + methodName);
                console.log('    That method probably has no default arguments.');
                return;
            }

            var list = member.overloads || [member];
            list.forEach(function (ov) {
                ov.implementation = function () {
                    var args = Array.prototype.slice.call(arguments);
                    // mask is second-to-last, marker Object is last
                    var mask = args[args.length - 2];

                    console.log('\n[$default] ' + className + '.' + methodName);
                    console.log('    mask = 0x' + (mask >>> 0).toString(16));
                    for (var i = 0; i < args.length - 2; i++) {
                        var omitted = (mask & (1 << i)) !== 0;
                        console.log('    arg[' + i + '] = ' + self._describe(args[i]) +
                                    (omitted ? '   <-- OMITTED, default used' : ''));
                    }
                    return ov.apply(this, args);
                };
            });
            console.log('[+] Hooked ' + className + '.' + bridgeName);
        });
    },

    /* --------------------------------------------------------- extension */

    /*
     * Extension functions compile to STATIC methods on a synthetic class named
     * after the FILE, with the receiver as the first parameter.
     *
     *   // In Foo.kt:  fun String.mask(): String
     *   // Becomes:    FooKt.mask(String receiver)
     */
    extension: function (fileClassName, methodName) {
        var self = this;
        Java.perform(function () {
            var cls = self._safe(function () { return Java.use(fileClassName); },
                                 fileClassName);
            if (cls === null) {
                console.log('    Extension functions live on a class named after the');
                console.log('    FILE, e.g. "com.example.UtilsKt" for Utils.kt.');
                return;
            }

            var member = cls[methodName];
            if (member === undefined) {
                console.log('[-] Not found. Declared static methods on ' + fileClassName + ':');
                cls.class.getDeclaredMethods().forEach(function (m) {
                    console.log('      ' + m.getName());
                });
                return;
            }

            var list = member.overloads || [member];
            list.forEach(function (ov) {
                ov.implementation = function () {
                    var args = Array.prototype.slice.call(arguments);
                    console.log('\n[extension] ' + fileClassName + '.' + methodName);
                    console.log('    receiver = ' + self._describe(args[0]));
                    for (var i = 1; i < args.length; i++) {
                        console.log('    arg[' + (i - 1) + '] = ' + self._describe(args[i]));
                    }
                    var ret = ov.apply(this, args);
                    console.log('    return  = ' + self._describe(ret));
                    return ret;
                };
            });
            console.log('[+] Hooked extension ' + fileClassName + '.' + methodName);
        });
    },

    /* -------------------------------------------------------- data leaks */

    /*
     * Find the recurring real-world Kotlin finding: a data class whose
     * generated toString() renders every property, being passed to Log.
     *
     * Hooks android.util.Log and reports any message that looks like a data
     * class rendering (ClassName(prop=value, prop=value)).
     */
    dataLeaks: function (extraKeywords) {
        var self = this;
        var keywords = ['token', 'password', 'passwd', 'secret', 'key', 'auth',
                        'session', 'jwt', 'bearer', 'pin', 'otp', 'credential'];
        if (Array.isArray(extraKeywords)) keywords = keywords.concat(extraKeywords);

        Java.perform(function () {
            var Log = Java.use('android.util.Log');
            var dataClassPattern = /^[A-Za-z_$][\w$]*\([\w]+=/;

            ['d', 'v', 'i', 'w', 'e'].forEach(function (level) {
                var ov = Log[level].overload('java.lang.String', 'java.lang.String');
                ov.implementation = function (tag, msg) {
                    if (msg !== null) {
                        var looksLikeDataClass = dataClassPattern.test(msg);
                        var lower = msg.toLowerCase();
                        var hit = keywords.filter(function (k) {
                            return lower.indexOf(k) !== -1;
                        });

                        if (looksLikeDataClass || hit.length > 0) {
                            console.log('\n[LEAK?] Log.' + level + '("' + tag + '")');
                            console.log('    ' + self._describe(msg));
                            if (looksLikeDataClass) {
                                console.log('    ^ shape matches a data class toString()');
                            }
                            if (hit.length > 0) {
                                console.log('    ^ contains: ' + hit.join(', '));
                            }
                            console.log('    See ../../33-Storage/ for severity guidance.');
                        }
                    }
                    return ov.call(this, tag, msg);
                };
            });

            console.log('[+] Watching android.util.Log for data-class leakage');
            console.log('    Exercise the app, especially login and profile screens.');
        });
    },

    /* -------------------------------------------------------- intrinsics */

    /*
     * Trace Kotlin's null checks as they fire.
     *
     * Mostly a teaching aid: it makes visible how much compiler-generated
     * checking runs on every call. Also occasionally useful for recovering
     * original parameter names at runtime, since the second argument is the
     * original name.
     */
    intrinsics: function () {
        var self = this;
        Java.perform(function () {
            var I = self._safe(function () {
                return Java.use('kotlin.jvm.internal.Intrinsics');
            }, 'kotlin.jvm.internal.Intrinsics');
            if (I === null) {
                console.log('[-] Intrinsics not present — is this actually a Kotlin app?');
                console.log('    Check with scripts/detect-kotlin.py');
                return;
            }

            var names = {};

            self._safe(function () {
                I.checkNotNullParameter.overload('java.lang.Object', 'java.lang.String')
                    .implementation = function (value, name) {
                        if (names[name] === undefined) {
                            names[name] = 0;
                            console.log('[param] first sighting: "' + name + '"');
                        }
                        names[name]++;
                        return this.checkNotNullParameter(value, name);
                    };
            }, 'hook checkNotNullParameter');

            console.log('[+] Tracing Intrinsics.checkNotNullParameter');
            console.log('    The second argument is the ORIGINAL parameter name and');
            console.log('    survives most obfuscation. Run kt.paramNames() later.');

            kt._paramNames = names;
        });
    },

    paramNames: function () {
        if (this._paramNames === undefined) {
            console.log('[-] Run kt.intrinsics() first.');
            return;
        }
        var entries = Object.keys(this._paramNames).map(function (k) {
            return [k, kt._paramNames[k]];
        }).sort(function (a, b) { return b[1] - a[1]; });

        console.log('\n[*] Original parameter names observed (' + entries.length + '):');
        entries.forEach(function (e) {
            console.log('    ' + String(e[1]).padStart(6) + '  ' + e[0]);
        });
        console.log('');
    },

    /* ------------------------------------------------------- class loader */

    findClass: function (className) {
        Java.perform(function () {
            console.log('[*] Searching all class loaders for ' + className);
            var found = false;
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    try {
                        loader.loadClass(className);
                        console.log('[+] FOUND in ' + loader);
                        Java.classFactory.loader = loader;
                        console.log('    Java.classFactory.loader switched — retry your hook.');
                        found = true;
                    } catch (e) { /* not here */ }
                },
                onComplete: function () {
                    if (!found) console.log('[-] Not found in any loaded class loader.');
                }
            });
        });
    },

    help: function () {
        console.log([
            '',
            'kt.overloads(cls, m)      list overloads with exact signatures  <-- START HERE',
            'kt.suspend(cls, m)        hook a suspend function correctly',
            'kt.body(cls, m)           hook the generated coroutine invokeSuspend',
            'kt.companion(cls)         inspect a companion object',
            'kt.object_(cls)           get an `object` singleton via INSTANCE',
            'kt.defaults(cls, m)       hook the $default bridge, decode the mask',
            'kt.extension(fileCls, m)  hook an extension function (static)',
            'kt.dataLeaks()            watch Log for data-class toString() leakage',
            'kt.intrinsics()           trace null checks; harvests parameter names',
            'kt.paramNames()           report harvested original parameter names',
            'kt.findClass(cls)         locate a class across all ClassLoaders',
            ''
        ].join('\n'));
    }
};

/* --------------------------------------------------------------- bootstrap */

Java.perform(function () {
    console.log('');
    console.log('=== hook-kotlin ===');
    try {
        Java.use('kotlin.jvm.internal.Intrinsics');
        console.log('[+] Kotlin runtime detected.');
    } catch (e) {
        console.log('[!] kotlin.jvm.internal.Intrinsics not found.');
        console.log('    This may not be a Kotlin app — verify with detect-kotlin.py');
    }
    console.log('[+] Ready. Type kt.help(). Start with kt.overloads(cls, method).');
    console.log('');
});
