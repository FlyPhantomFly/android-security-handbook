/*
 * frida-string-decryptor.js
 * ---------------------------------------------------------------------------
 * WHAT IT DOES
 *   Finds an application's string-decryption routine automatically, hooks it,
 *   and dumps every string it recovers — with the call site that asked for it.
 *   Then, optionally, calls that routine yourself for every input in its
 *   domain, so you recover strings from code paths you never executed.
 *
 *   Three modes, used in this order:
 *
 *     1. DISCOVER  Hook java.lang.String.<init>([B) and ([C) and record which
 *                  method constructed each String. Every string decryptor,
 *                  whatever its cipher, ends by building a String from bytes
 *                  or chars — so this catches all of them, including per-class
 *                  decryptors, without knowing anything about the algorithm.
 *
 *     2. HARVEST   Hook the candidate decryptor(s) and log (args -> result)
 *                  with a stack trace. Passive: only sees code paths you run.
 *
 *     3. EXHAUST   Call the decryptor directly for every index / every
 *                  ciphertext constant, and record every output. Active:
 *                  recovers strings from unreached code, which is the whole
 *                  point.
 *
 * WHY IT MATTERS
 *   Chapter 40 section 6.1 puts string recovery at Phase 4 — before control
 *   flow, before renaming, before everything except unpacking — and the reason
 *   is worth stating precisely:
 *
 *     After identifier renaming, STRINGS ARE THE ONLY REMAINING SEMANTICS.
 *
 *   A method called `a` that contains "/v2/payments/authorize" is not called
 *   `a` any more. It is authorizePayment, you now know that, you can rename
 *   it, and every caller of it becomes partly understood too. Strings are the
 *   seeds from which the naming of the whole program regrows. Control flow
 *   tells you HOW; strings tell you WHAT, and "what" is what you are being
 *   paid to find out.
 *
 *   That is why this is the highest-value script in the chapter. Recovering
 *   strings first routinely makes the control-flow work unnecessary, because
 *   once you can grep for "/v2/transfer" you can find the one method you
 *   actually care about directly instead of deflattening forty you do not.
 *
 *   It also explains why the cipher does not matter. You are not breaking
 *   anything. The app must be able to decrypt its own strings, so there is
 *   always a moment and always a function at which plaintext exists; you are
 *   simply present at that moment with a notebook. XOR, AES, whitebox,
 *   per-class, native — all the same to this script, because it hooks the
 *   RESULT, not the algorithm.
 *
 * HOW TO RUN
 *   # host — spawn PAUSED. Decryptors frequently run from static initialisers
 *   # during class loading, long before you could attach.
 *   frida -U -f com.target.app -l frida-string-decryptor.js --pause
 *   # then, in the REPL:
 *   #   %resume
 *
 *   # Exercise the app for 30–60 seconds, then:
 *   sd.candidates()                 # ranked list of likely decryptors
 *   sd.harvest("com.x.a.q")         # hook every String-returning method there
 *   sd.exhaust("com.x.a.q", "a", 0, 4096)   # call a(int) for 0..4095
 *   sd.save()                       # write results to the device
 *   sd.stats()
 *
 *   # Retrieve:
 *   adb pull /data/local/tmp/strings-dump.txt .
 *   adb pull /data/local/tmp/strings-dump.json .
 *
 *   # Then annotate the Smali with what you recovered:
 *   python3 annotate-smali-strings.py --smali apktool_out --json strings-dump.json
 *
 * REQUIREMENTS
 *   - frida-server on the device, matching your frida client, running as root.
 *   - The app must reach the point where its decryptor runs. For a packed app,
 *     unpack first (frida-classloader-dump.js) — a stub has no strings worth
 *     recovering.
 *
 * DESIGN NOTES
 *   - Discovery is ON by default and cheap; stack capture is OFF by default
 *     and expensive. Turn stacks on once you have narrowed to a class.
 *   - Nothing is hard-coded: no class names, no method names, no offsets. The
 *     script asks the runtime what exists.
 *   - Every reflective operation is guarded. Obfuscated apps have malformed
 *     signatures, unloadable classes and methods that throw on any input, and
 *     a script that dies on the first one is useless.
 *   - Results are deduplicated and sorted, because a 4,000-line unsorted dump
 *     is a haystack while the same 4,000 lines grouped by caller is a map.
 *
 * AUTHORISED TESTING ONLY.
 * ---------------------------------------------------------------------------
 */

'use strict';

var sd = {

    // ---------------------------------------------------------------- config

    cfg: {
        // Log every discovered String construction as it happens. Very noisy;
        // the ranked summary from sd.candidates() is usually enough.
        liveLog: false,

        // Capture a Java stack trace for each hit. Costs a lot of time.
        // Discovery mode needs only ONE frame, which we always take; this flag
        // controls the deeper trace used during harvest.
        deepStacks: false,

        // Ignore strings shorter than this. Single characters and two-letter
        // fragments are noise from the framework, not recovered secrets.
        minLength: 3,

        // Packages to ignore when ranking candidates. The framework builds a
        // great many Strings from byte arrays and none of them are the app's
        // decryptor.
        ignore: [
            'java.', 'javax.', 'android.', 'androidx.', 'com.android.',
            'dalvik.', 'libcore.', 'sun.', 'org.apache.', 'org.json.',
            'kotlin.', 'kotlinx.', 'com.google.android.gms.'
        ],

        // Where to write results on the device.
        outPrefix: '/data/local/tmp/strings-dump',

        // Cap on exhaust() output so a runaway loop cannot fill storage.
        maxResults: 200000
    },

    // ----------------------------------------------------------------- state

    callers: {},     // "class.method" -> { count, samples: [] }
    results: [],     // { source, args, value }
    seen: {},        // dedupe key -> true
    installed: false,

    // --------------------------------------------------------------- helpers

    _ignored: function (name) {
        if (!name) return true;
        for (var i = 0; i < this.cfg.ignore.length; i++) {
            if (name.indexOf(this.cfg.ignore[i]) === 0) return true;
        }
        return false;
    },

    /*
     * Frame 0 of the trace is String.<init> itself. Frame 1 is the method that
     * constructed it — the decryptor candidate. We take only what we need,
     * because building a full stack trace for every String in an Android
     * process is genuinely slow enough to change the app's behaviour.
     */
    _immediateCaller: function () {
        try {
            var Ex = Java.use('java.lang.Exception');
            var st = Ex.$new().getStackTrace();
            for (var i = 0; i < st.length && i < 8; i++) {
                var cls = st[i].getClassName();
                if (cls === 'java.lang.String') continue;
                if (this._ignored(cls)) continue;
                return cls + '.' + st[i].getMethodName() +
                       '(' + st[i].getLineNumber() + ')';
            }
            // Nothing but framework frames — still record where it came from.
            return st.length > 1 ? (st[1].getClassName() + '.' +
                                    st[1].getMethodName()) : '<unknown>';
        } catch (e) {
            return '<no-stack>';
        }
    },

    _deepStack: function () {
        if (!this.cfg.deepStacks) return '';
        try {
            var Log = Java.use('android.util.Log');
            var Ex = Java.use('java.lang.Exception');
            var raw = Log.getStackTraceString(Ex.$new());
            var lines = raw.split('\n').filter(function (l) {
                return l.indexOf('at ') !== -1;
            });
            return lines.slice(1, 6).join('\n        <- ');
        } catch (e) {
            return '';
        }
    },

    _record: function (source, args, value) {
        if (value === null || value === undefined) return;
        var s = String(value);
        if (s.length < this.cfg.minLength) return;
        if (this.results.length >= this.cfg.maxResults) return;

        var key = source + '|' + args + '|' + s;
        if (this.seen[key]) return;
        this.seen[key] = true;

        this.results.push({ source: source, args: String(args), value: s });

        if (this.cfg.liveLog) {
            console.log('[str] ' + source + ' ' + args + ' => ' + s);
        }
    },

    _noteCaller: function (caller, sample) {
        if (!this.callers[caller]) {
            this.callers[caller] = { count: 0, samples: [] };
        }
        var c = this.callers[caller];
        c.count++;
        if (c.samples.length < 4 && sample && sample.length >= this.cfg.minLength) {
            c.samples.push(sample);
        }
    },

    // ============================================================== MODE 1
    // DISCOVER — who builds Strings out of bytes?
    // ==============================================================

    /*
     * Every string-decryption routine, regardless of cipher, ends the same
     * way: it produces a byte[] or char[] of plaintext and constructs a String
     * from it. Hooking those two constructors therefore catches:
     *
     *   - XOR with a fixed key            (section 3.2 variant A)
     *   - AES with the key in the DEX     (variant B)
     *   - Per-class decryptors, all 400   (variant C)
     *   - Custom stream ciphers, whitebox implementations, anything at all
     *
     * ...without knowing a single thing about any of them. That generality is
     * why this is the first thing to run, before any static analysis of the
     * decryptor.
     *
     * The framework also constructs a lot of Strings this way (charset
     * decoding, JSON parsing, resource loading), which is why callers in
     * platform packages are filtered out of the ranking.
     */
    discover: function () {
        if (this.installed) {
            console.log('[*] discovery already installed');
            return;
        }
        var self = this;

        Java.perform(function () {
            var S = Java.use('java.lang.String');
            var hooked = 0;

            // String(byte[]) — the common case.
            try {
                S.$init.overload('[B').implementation = function (b) {
                    this.$init(b);
                    try {
                        var v = this.toString();
                        if (v.length >= self.cfg.minLength) {
                            var caller = self._immediateCaller();
                            self._noteCaller(caller, v);
                        }
                    } catch (e) { }
                };
                hooked++;
            } catch (e) {
                console.log('[-] String([B) hook failed: ' + e);
            }

            // String(byte[], int, int) — offset/length variant, very common in
            // index-based per-class decryptors.
            try {
                S.$init.overload('[B', 'int', 'int').implementation =
                    function (b, off, len) {
                        this.$init(b, off, len);
                        try {
                            var v = this.toString();
                            if (v.length >= self.cfg.minLength) {
                                self._noteCaller(self._immediateCaller(), v);
                            }
                        } catch (e) { }
                    };
                hooked++;
            } catch (e) { }

            // String(char[]) — what an XOR-into-char[] decryptor uses.
            try {
                S.$init.overload('[C').implementation = function (c) {
                    this.$init(c);
                    try {
                        var v = this.toString();
                        if (v.length >= self.cfg.minLength) {
                            self._noteCaller(self._immediateCaller(), v);
                        }
                    } catch (e) { }
                };
                hooked++;
            } catch (e) { }

            // String(char[], int, int)
            try {
                S.$init.overload('[C', 'int', 'int').implementation =
                    function (c, off, len) {
                        this.$init(c, off, len);
                        try {
                            var v = this.toString();
                            if (v.length >= self.cfg.minLength) {
                                self._noteCaller(self._immediateCaller(), v);
                            }
                        } catch (e) { }
                    };
                hooked++;
            } catch (e) { }

            // StringBuilder.toString() catches decryptors that assemble their
            // output rather than constructing a String directly. Off by
            // default because it is extremely noisy; enable if discovery finds
            // nothing.
            self.installed = true;
            console.log('[+] discovery installed (' + hooked + ' constructor overloads)');
            console.log('    Exercise the app, then run sd.candidates()');
        });
    },

    /*
     * Enable this only if discover() finds nothing. Some obfuscators build
     * their plaintext through StringBuilder, which never touches
     * String.<init>([B).
     */
    discoverBuilders: function () {
        var self = this;
        Java.perform(function () {
            try {
                var SB = Java.use('java.lang.StringBuilder');
                SB.toString.implementation = function () {
                    var v = this.toString();
                    try {
                        if (v !== null && v.length >= self.cfg.minLength) {
                            self._noteCaller('SB:' + self._immediateCaller(), v);
                        }
                    } catch (e) { }
                    return v;
                };
                console.log('[+] StringBuilder.toString hooked (noisy — disable when done)');
            } catch (e) {
                console.log('[-] StringBuilder hook failed: ' + e);
            }
        });
    },

    /*
     * Rank the callers. The decryptor is, almost always, the single
     * application-package method that constructed the most Strings.
     */
    candidates: function (limit) {
        limit = limit || 15;
        var names = Object.keys(this.callers);
        if (names.length === 0) {
            console.log('[!] No candidates recorded.');
            console.log('    - Did you run sd.discover() BEFORE %resume?');
            console.log('    - Did you exercise the app after resuming?');
            console.log('    - Is the app packed? A stub has no strings — unpack first');
            console.log('      with frida-classloader-dump.js.');
            console.log('    - Try sd.discoverBuilders() for StringBuilder-based decryptors.');
            return;
        }

        var self = this;
        names.sort(function (a, b) {
            return self.callers[b].count - self.callers[a].count;
        });

        console.log('');
        console.log('=== String-construction callers, most frequent first ===');
        console.log('The top application-package entry is almost always your decryptor.');
        console.log('');
        names.slice(0, limit).forEach(function (n, i) {
            var c = self.callers[n];
            console.log((i + 1) + '. ' + c.count + 'x  ' + n);
            c.samples.forEach(function (s) {
                var t = s.length > 70 ? s.substring(0, 67) + '...' : s;
                console.log('        "' + t.replace(/\n/g, '\\n') + '"');
            });
        });
        console.log('');
        console.log('Next: sd.inspect("<class>")  to list its String-returning methods');
        console.log('      sd.harvest("<class>")  to hook them all');
        console.log('');
    },

    // ============================================================== MODE 2
    // HARVEST — hook the decryptor and log every call
    // ==============================================================

    /*
     * List the methods of a class that could be a decryptor: anything
     * returning java.lang.String. Prints the exact signature you need for
     * exhaust().
     *
     * This exists because guessing an overload is the classic failure. A class
     * with six methods named `a` will silently ignore a hook placed on the
     * wrong one, and the symptom is identical to "the decryptor is elsewhere".
     */
    inspect: function (className) {
        Java.perform(function () {
            var C;
            try {
                C = Java.use(className);
            } catch (e) {
                console.log('[-] cannot load ' + className + ': ' + e);
                console.log('    If the app is packed or uses a custom ClassLoader,');
                console.log('    run sd.loaders() to find the right one.');
                return;
            }

            console.log('');
            console.log('=== ' + className + ' — String-returning methods ===');
            var found = 0;
            try {
                var methods = C.class.getDeclaredMethods();
                for (var i = 0; i < methods.length; i++) {
                    var m = methods[i];
                    var sig = m.toString();
                    if (sig.indexOf('java.lang.String ') === -1) continue;
                    console.log('  ' + sig);
                    found++;
                }
            } catch (e) {
                console.log('[-] reflection failed: ' + e);
            }
            if (found === 0) {
                console.log('  (none — the decryptor may return char[] or byte[],');
                console.log('   or live in a superclass. Check getMethods() too.)');
            }
            console.log('');
        });
    },

    /*
     * Hook every String-returning method on a class and record
     * (arguments -> result). Passive: you only get strings on code paths you
     * actually execute. Use it to learn the decryptor's SIGNATURE and its
     * input domain, then switch to exhaust().
     */
    harvest: function (className) {
        var self = this;
        Java.perform(function () {
            var C;
            try {
                C = Java.use(className);
            } catch (e) {
                console.log('[-] cannot load ' + className + ': ' + e);
                return;
            }

            var count = 0;
            var names = {};
            try {
                var methods = C.class.getDeclaredMethods();
                for (var i = 0; i < methods.length; i++) {
                    var sig = methods[i].toString();
                    if (sig.indexOf('java.lang.String ') === -1) continue;
                    names[methods[i].getName()] = true;
                }
            } catch (e) {
                console.log('[-] reflection failed: ' + e);
                return;
            }

            Object.keys(names).forEach(function (name) {
                var handle = C[name];
                if (handle === undefined) return;
                handle.overloads.forEach(function (ov) {
                    try {
                        ov.implementation = function () {
                            var out = ov.apply(this, arguments);
                            try {
                                var a = [];
                                for (var i = 0; i < arguments.length; i++) {
                                    var v = arguments[i];
                                    a.push(v === null ? 'null' : String(v));
                                }
                                self._record(className + '.' + name,
                                             '(' + a.join(',') + ')', out);
                                var deep = self._deepStack();
                                if (deep) console.log('        <- ' + deep);
                            } catch (e) { }
                            return out;
                        };
                        count++;
                    } catch (e) { }
                });
            });

            console.log('[+] harvesting ' + count + ' overload(s) on ' + className);
            console.log('    Exercise the app, then sd.stats() / sd.save()');
        });
    },

    // ============================================================== MODE 3
    // EXHAUST — call the decryptor yourself for its whole input domain
    // ==============================================================

    /*
     * The important mode.
     *
     * Harvesting only recovers strings on paths you executed. A string used
     * exclusively in an error handler you never triggered — which is very
     * often the interesting one, because that is where the debug endpoints and
     * the hardcoded fallbacks live — stays hidden.
     *
     * Index-based decryptors (section 3.2 variant C) take an integer and
     * return the n-th string. So call it for every n. Invalid indices throw;
     * we catch and continue. Two hundred lines of output in three seconds, and
     * it is COMPLETE.
     *
     *   sd.exhaust("com.x.a.q", "a", 0, 4096)
     *
     * For a multi-argument decryptor, pass extra fixed arguments:
     *
     *   sd.exhaust("com.x.a.q", "a", 0, 4096, [0, 0])
     *
     * NOTE: this actually runs app code. A decryptor with side effects (some
     * update a cache, a few increment a counter used elsewhere) can perturb
     * the app. Exhaust late in your session, or in a process you are happy to
     * discard.
     */
    exhaust: function (className, methodName, from, to, extraArgs) {
        var self = this;
        extraArgs = extraArgs || [];

        Java.perform(function () {
            var C;
            try {
                C = Java.use(className);
            } catch (e) {
                console.log('[-] cannot load ' + className + ': ' + e);
                return;
            }

            var handle = C[methodName];
            if (handle === undefined) {
                console.log('[-] no method named ' + methodName + ' on ' + className);
                self.inspect(className);
                return;
            }

            var recovered = 0, failed = 0;
            console.log('[*] exhausting ' + className + '.' + methodName +
                        '(' + from + '..' + (to - 1) +
                        (extraArgs.length ? ', ' + extraArgs.join(',') : '') + ')');

            for (var i = from; i < to; i++) {
                try {
                    var args = [i].concat(extraArgs);
                    var out = handle.apply(C, args);
                    if (out === null) { failed++; continue; }
                    var s = String(out);
                    if (s.length < self.cfg.minLength) { failed++; continue; }
                    self._record(className + '.' + methodName, String(i), s);
                    recovered++;
                } catch (e) {
                    // Out of range, wrong overload, or the decryptor rejected
                    // the input. All normal; keep going.
                    failed++;
                }
            }

            console.log('[+] recovered ' + recovered + ' string(s), ' +
                        failed + ' input(s) produced nothing');
            if (recovered === 0) {
                console.log('    Nothing came back. Check:');
                console.log('      - the overload:      sd.inspect("' + className + '")');
                console.log('      - the argument order (index may not be first)');
                console.log('      - whether the decryptor needs class init first:');
                console.log('        touch any field of the class before exhausting');
            }
        });
    },

    /*
     * Exhaust a decryptor that takes a ciphertext STRING rather than an index.
     * Feed it the constants you extracted statically from the DEX:
     *
     *   sd.exhaustStrings("com.x.a.q", "a", ["A1B2...", "C3D4..."])
     *
     * Extract the constants with:
     *   grep -rhoP 'const-string [vp]\d+, "\K[^"]+' apktool_out/smali* | sort -u
     */
    exhaustStrings: function (className, methodName, inputs) {
        var self = this;
        Java.perform(function () {
            var C;
            try { C = Java.use(className); }
            catch (e) { console.log('[-] cannot load ' + className + ': ' + e); return; }

            var handle = C[methodName];
            if (handle === undefined) {
                console.log('[-] no method ' + methodName);
                return;
            }

            var ok = 0;
            inputs.forEach(function (inp) {
                try {
                    var out = handle.call(C, inp);
                    if (out === null) return;
                    var s = String(out);
                    if (s.length < self.cfg.minLength) return;
                    if (s === inp) return;        // identity: not a decryptor
                    self._record(className + '.' + methodName,
                                 JSON.stringify(inp), s);
                    ok++;
                } catch (e) { }
            });
            console.log('[+] recovered ' + ok + ' of ' + inputs.length + ' input(s)');
        });
    },

    // ------------------------------------------------------------- utilities

    /*
     * List every ClassLoader in the process. If Java.use() cannot find a class
     * you can see in jadx, it is almost certainly in a ClassLoader other than
     * the default — which on a packed app is the normal situation.
     */
    loaders: function () {
        Java.perform(function () {
            var n = 0;
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    console.log('[' + (n++) + '] ' + loader.toString());
                },
                onComplete: function () {
                    console.log('');
                    console.log('To use a class from a specific loader:');
                    console.log('  Java.classFactory.loader = <that loader>;');
                    console.log('  then Java.use("com.x.y") resolves against it.');
                }
            });
        });
    },

    /*
     * Switch the class factory to the Nth loader from loaders(). Necessary
     * after unpacking, when the real classes live in a loader the default
     * factory does not consult.
     */
    useLoader: function (index) {
        Java.perform(function () {
            var i = 0, chosen = null;
            Java.enumerateClassLoaders({
                onMatch: function (l) { if (i++ === index) chosen = l; },
                onComplete: function () { }
            });
            if (chosen === null) {
                console.log('[-] no loader at index ' + index);
                return;
            }
            Java.classFactory.loader = chosen;
            console.log('[+] class factory now using ' + chosen.toString());
        });
    },

    // --------------------------------------------------------------- output

    stats: function () {
        console.log('');
        console.log('=== recovered ' + this.results.length + ' unique string(s) ===');

        var bySource = {};
        this.results.forEach(function (r) {
            bySource[r.source] = (bySource[r.source] || 0) + 1;
        });
        Object.keys(bySource).sort(function (a, b) {
            return bySource[b] - bySource[a];
        }).forEach(function (s) {
            console.log('  ' + bySource[s] + '\t' + s);
        });

        // The triage categories from section 6.1 phase 4, applied inline so
        // you see the interesting ones immediately rather than after a pull.
        var buckets = {
            'endpoints':   /https?:\/\/|\.com|\.net|\/api\/|\/v[0-9]+\//i,
            'credentials': /key|secret|token|password|passwd|pwd|auth|bearer/i,
            'crypto':      /AES|RSA|HMAC|SHA-?\d|PBKDF|ECB|CBC|GCM|PKCS/i,
            'anti-analysis': /(^|\/)su$|\/system\/bin|magisk|frida|xposed|emulator|goldfish|ptrace|TracerPid/i,
            'sql':         /select\s|insert\s|update\s|delete\s|from\s|where\s/i,
            'files':       /^\/(data|sdcard|storage|proc|sys)\//
        };

        console.log('');
        console.log('=== triage ===');
        var self = this;
        Object.keys(buckets).forEach(function (name) {
            var hits = self.results.filter(function (r) {
                return buckets[name].test(r.value);
            });
            console.log('  ' + name + ': ' + hits.length);
            hits.slice(0, 8).forEach(function (h) {
                var t = h.value.length > 80 ? h.value.substring(0, 77) + '...' : h.value;
                console.log('      ' + t.replace(/\n/g, '\\n'));
            });
        });
        console.log('');
    },

    /*
     * Two output formats, on purpose:
     *   .txt   for reading and grepping
     *   .json  for annotate-smali-strings.py, which needs the index/argument
     *          so it can match call sites in the Smali
     */
    save: function (prefix) {
        prefix = prefix || this.cfg.outPrefix;

        try {
            var txt = new File(prefix + '.txt', 'w');
            txt.write('# recovered strings — ' + this.results.length + ' unique\n');
            txt.write('# format: <source> <args> => <value>\n\n');
            this.results.forEach(function (r) {
                txt.write(r.source + ' ' + r.args + ' => ' + r.value + '\n');
            });
            txt.close();
            console.log('[+] wrote ' + prefix + '.txt');
        } catch (e) {
            console.log('[-] could not write ' + prefix + '.txt: ' + e);
            console.log('    Try sd.save("/data/data/<pkg>/cache/strings-dump")');
        }

        try {
            var json = new File(prefix + '.json', 'w');
            json.write(JSON.stringify(this.results, null, 1));
            json.close();
            console.log('[+] wrote ' + prefix + '.json');
            console.log('    adb pull ' + prefix + '.json');
            console.log('    python3 annotate-smali-strings.py --smali apktool_out ' +
                        '--json $(basename ' + prefix + '.json)');
        } catch (e) {
            console.log('[-] could not write ' + prefix + '.json: ' + e);
        }
    },

    grep: function (pattern) {
        var re = new RegExp(pattern, 'i');
        var n = 0;
        this.results.forEach(function (r) {
            if (re.test(r.value)) {
                console.log(r.source + ' ' + r.args + ' => ' + r.value);
                n++;
            }
        });
        console.log('[' + n + ' match(es)]');
    },

    reset: function () {
        this.callers = {};
        this.results = [];
        this.seen = {};
        console.log('[*] state cleared (hooks remain installed)');
    },

    help: function () {
        console.log([
            '',
            'DISCOVER — who builds Strings from bytes?',
            '  sd.discover()                       install the universal finder',
            '  sd.discoverBuilders()               also catch StringBuilder decryptors',
            '  sd.candidates([n])                  ranked list of likely decryptors',
            '',
            'HARVEST — hook a specific class',
            '  sd.inspect("com.x.a")               list its String-returning methods',
            '  sd.harvest("com.x.a")               hook them all, log args -> result',
            '',
            'EXHAUST — call it yourself, recover EVERYTHING',
            '  sd.exhaust("com.x.a","a",0,4096)    index-based decryptor',
            '  sd.exhaust("com.x.a","a",0,4096,[0,0])   with extra fixed args',
            '  sd.exhaustStrings("com.x.a","a",[...])   ciphertext-based decryptor',
            '',
            'CLASSLOADERS — when Java.use cannot find a class',
            '  sd.loaders()                        list every ClassLoader',
            '  sd.useLoader(n)                     switch the class factory',
            '',
            'OUTPUT',
            '  sd.stats()                          summary + triage buckets',
            '  sd.grep("api|token")                search recovered strings',
            '  sd.save(["/path/prefix"])           write .txt and .json',
            '  sd.reset()                          clear collected results',
            '',
            'CONFIG (sd.cfg.*): liveLog, deepStacks, minLength, outPrefix',
            ''
        ].join('\n'));
    }
};

// --------------------------------------------------------------- bootstrap

Java.perform(function () {
    console.log('');
    console.log('=====================================================================');
    console.log(' frida-string-decryptor.js');
    console.log('');
    console.log(' After renaming, strings are the only remaining semantics.');
    console.log(' Recover them FIRST: a method called `a` containing');
    console.log(' "/v2/payments/authorize" is not called `a` any more.');
    console.log('=====================================================================');
    console.log('');

    sd.discover();

    console.log('');
    console.log('Workflow:');
    console.log('  1. %resume  (you spawned with --pause, did you not?)');
    console.log('  2. Exercise the app for 30-60 seconds');
    console.log('  3. sd.candidates()');
    console.log('  4. sd.inspect("<top candidate class>")');
    console.log('  5. sd.exhaust("<class>", "<method>", 0, 4096)');
    console.log('  6. sd.stats() then sd.save()');
    console.log('');
    console.log('sd.help() for everything.');
    console.log('');
});
