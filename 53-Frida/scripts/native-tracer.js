/*
 * native-tracer.js — trace native code, and recover dynamically registered
 *                    JNI methods.
 *
 * WHAT IT DOES
 *   Four capabilities that together cover the native side of an Android app:
 *
 *     1. JNI RECOVERY.  Hooks ART's RegisterNatives to dump the mapping from
 *        Java method name+signature to native function address. This is the
 *        answer to "nm shows no Java_* symbols but the app clearly has native
 *        methods" — the app registered them at runtime, deliberately, so that
 *        the mapping exists only in memory.
 *
 *     2. MODULE TRACING.  Hooks every exported function of a named library,
 *        printing arguments as raw values plus a best-effort string preview.
 *
 *     3. LIBC TRACING.  Presets for the syscall-adjacent functions that reveal
 *        behaviour: file access, process execution, network, and dlopen.
 *
 *     4. LAZY MODULE WATCH.  Hooks android_dlopen_ext so that a library loaded
 *        minutes after startup is instrumented the moment it appears — the
 *        common case for packed apps.
 *
 * WHY IT WORKS
 *   Native hooks are inline patches at the function prologue placed by Frida
 *   Gum's Interceptor. See ../README.md section 3.6.1 for the mechanism and
 *   section 7.5 for attach-versus-replace. JNI argument layout is explained in
 *   ../../16-JNI/README.md: args[0] is always JNIEnv*, args[1] is the jobject
 *   (instance methods) or jclass (static methods), and the declared parameters
 *   start at args[2].
 *
 * HOW TO RUN
 *   # RegisterNatives fires inside JNI_OnLoad, which runs during
 *   # System.loadLibrary — usually in a static initialiser. You MUST spawn.
 *   frida -U -f com.example.app -l native-tracer.js --no-pause
 *
 *   Then from the REPL:
 *     nat.help()
 *     nat.jni()                          // start JNI recovery (on by default)
 *     nat.table()                        // print what has been recovered
 *     nat.module("libnative.so")         // trace every export of a library
 *     nat.symbol("libnative.so", "check")
 *     nat.offset("libnative.so", 0x3e40) // trace an unexported function
 *     nat.libc("file")                   // presets: file | exec | net | dl | all
 *     nat.watch("libsecret")             // instrument when it is dlopen'd
 *     nat.call("libnative.so", 0x3e40, "int", ["pointer","int"], [p, 5])
 *     nat.stop()
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var nat = {

    /* ------------------------------------------------------------- state */

    _listeners: [],
    _jniTable: [],           // {clazz, name, sig, addr, module, offset}
    _counts: {},
    _maxPreview: 96,
    _traced: {},             // address string -> true, avoids double-hooking

    /* --------------------------------------------------- symbol resolution */

    /*
     * Frida 17 reorganised the Module API. Library code must work on both,
     * because you do not control which Frida the operator installed.
     * A null result is a NORMAL outcome, never an error.
     */
    _globalExport: function (name) {
        try {
            if (typeof Module.getGlobalExportByName === 'function') {
                return Module.getGlobalExportByName(name);
            }
        } catch (e) { /* not found */ }
        try {
            return Module.findExportByName(null, name);
        } catch (e) { return null; }
    },

    _moduleExport: function (mod, name) {
        try {
            if (typeof Process.findModuleByName === 'function') {
                var m = Process.findModuleByName(mod);
                if (m !== null && typeof m.findExportByName === 'function') {
                    var a = m.findExportByName(name);
                    if (a !== null) return a;
                }
            }
        } catch (e) { /* fall through */ }
        try {
            return Module.findExportByName(mod, name);
        } catch (e) { return null; }
    },

    /* Return the first symbol from a candidate list that actually resolves. */
    _firstOf: function (mod, names) {
        for (var i = 0; i < names.length; i++) {
            var a = (mod === null) ? this._globalExport(names[i])
                                   : this._moduleExport(mod, names[i]);
            if (a !== null && !a.isNull()) {
                return { name: names[i], addr: a };
            }
        }
        return null;
    },

    /* ------------------------------------------------------- formatting */

    /*
     * Render a pointer argument usefully without crashing. A pointer may be
     * a small integer, a C string, a Java object handle, or garbage. Try each
     * interpretation and report the first that looks plausible.
     */
    _arg: function (p) {
        try {
            if (p === null || p.isNull()) return 'NULL';

            var asInt = p.toInt32();
            // Small values are almost certainly integers, not pointers.
            if (asInt > -0x10000 && asInt < 0x10000) {
                return String(asInt) + ' (0x' + (asInt >>> 0).toString(16) + ')';
            }

            var range = Process.findRangeByAddress(p);
            if (range === null) {
                return p + ' <unmapped>';
            }

            if (range.protection.indexOf('r') !== -1) {
                var s = null;
                try { s = p.readCString(this._maxPreview); } catch (e) { s = null; }
                if (s !== null && s.length > 0 && /^[\x20-\x7e\r\n\t]+$/.test(s)) {
                    return p + ' "' + s + '"';
                }
            }

            var mod = Process.findModuleByAddress(p);
            if (mod !== null) {
                return p + ' <' + mod.name + '+0x' +
                       p.sub(mod.base).toString(16) + '>';
            }
            return p + ' <' + range.protection + '>';
        } catch (e) {
            return '<unreadable>';
        }
    },

    _where: function (addr) {
        var m = Process.findModuleByAddress(addr);
        if (m === null) return String(addr);
        return m.name + '+0x' + addr.sub(m.base).toString(16);
    },

    /* ==================================================================
     * 1. JNI RECOVERY
     *
     * The Java-side declaration `native byte[] sign(byte[])` normally maps to
     * an exported C symbol Java_com_example_Signer_sign. An app that wants to
     * hide the mapping calls RegisterNatives from JNI_OnLoad instead, binding
     * arbitrary (often stripped, non-exported) functions to Java methods.
     *
     * We hook the C++ implementation inside libart. Its mangled name differs
     * across Android releases and ART Mainline module versions, so several
     * candidates are tried and the one that resolves is reported.
     * ================================================================== */

    jni: function () {
        var self = this;

        var CANDIDATES = [
            // art::JNI<false>::RegisterNatives  (Android 11+ split templated form)
            '_ZN3art3JNIILb0EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi',
            '_ZN3art3JNIILb1EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi',
            // art::JNI::RegisterNatives  (older, non-templated)
            '_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi',
            // art::JNIEnvExt::RegisterNatives
            '_ZN3art8JNIEnvExt15RegisterNativesEP7_jclassPK15JNINativeMethodi'
        ];

        var found = this._firstOf('libart.so', CANDIDATES);

        if (found === null) {
            console.log('[-] No RegisterNatives symbol exported by this libart.so.');
            console.log('    This happens on some ART Mainline versions and on builds');
            console.log('    with restricted symbol tables. Falling back to reading the');
            console.log('    table from JNI_OnLoad — call nat.onload("libfoo.so").');
            return 0;
        }

        console.log('[+] RegisterNatives -> ' + found.name);
        console.log('    at ' + found.addr + ' (' + this._where(found.addr) + ')');

        // Argument index of the JNINativeMethod* differs between the two forms:
        //   JNI<...>::RegisterNatives(JNIEnv*, jclass, const JNINativeMethod*, jint)
        //     -> this=args[0]? No: these are static-like; methods at args[2], count args[3]
        //   JNIEnvExt::RegisterNatives(jclass, const JNINativeMethod*, jint)
        //     -> this=args[0], jclass=args[1], methods=args[2], count=args[3]
        // Both land on args[2]/args[3], which is why this works for all forms.
        var METHODS_IDX = 2;
        var COUNT_IDX = 3;

        var l = Interceptor.attach(found.addr, {
            onEnter: function (args) {
                var methods = args[METHODS_IDX];
                var count = args[COUNT_IDX].toInt32();

                // Sanity-check before dereferencing. A wrong signature guess
                // here is a segfault, not an exception.
                if (methods.isNull() || count <= 0 || count > 8192) return;

                // Recover the class name via JNIEnv if we can. Best effort:
                // if it fails we still report the methods.
                var clazzName = '<unknown class>';
                try {
                    var envOrThis = args[0];
                    var jclassArg = args[1];
                    clazzName = self._classNameOf(envOrThis, jclassArg);
                } catch (e) { /* keep the placeholder */ }

                var ps = Process.pointerSize;
                console.log('\n[jni] RegisterNatives  class=' + clazzName +
                            '  count=' + count);

                for (var i = 0; i < count; i++) {
                    // struct JNINativeMethod {
                    //     const char* name;
                    //     const char* signature;
                    //     void*       fnPtr;
                    // };
                    var entry = methods.add(i * ps * 3);
                    var name, sig, fn;
                    try {
                        name = entry.readPointer().readCString();
                        sig  = entry.add(ps).readPointer().readCString();
                        fn   = entry.add(ps * 2).readPointer();
                    } catch (e) { continue; }
                    if (name === null || fn === null || fn.isNull()) continue;

                    var mod = Process.findModuleByAddress(fn);
                    var rec = {
                        clazz: clazzName,
                        name: name,
                        sig: sig,
                        addr: fn,
                        module: mod ? mod.name : '<anon>',
                        offset: mod ? '0x' + fn.sub(mod.base).toString(16) : null
                    };
                    self._jniTable.push(rec);

                    console.log('      ' + name + sig);
                    console.log('        -> ' + rec.module +
                                (rec.offset ? '+' + rec.offset : '') +
                                '  (' + fn + ')');
                }
                console.log('');
            }
        });

        this._listeners.push(l);
        return 1;
    },

    /*
     * Resolve a jclass to its name. The call path differs depending on whether
     * the first argument is a JNIEnv* or an art::JNIEnvExt* `this`, so both
     * are attempted. Failure is tolerated — the method list is still useful.
     */
    _classNameOf: function (maybeEnv, jclazz) {
        try {
            var env = Java.vm.getEnv();
            // GetObjectClass + getName via the Java side is the robust route:
            // it does not depend on guessing the JNIEnv function-table layout.
            var obj = Java.cast(ptr(jclazz), Java.use('java.lang.Class'));
            return obj.getName();
        } catch (e) {
            return '<unknown class>';
        }
    },

    /* Print the recovered table. */
    table: function () {
        if (this._jniTable.length === 0) {
            console.log('[*] No dynamically registered JNI methods recovered (yet).');
            console.log('    Either the app uses static Java_* symbols — check with');
            console.log('    nat.exports("libnative.so") — or JNI_OnLoad has not run.');
            console.log('    RegisterNatives fires during System.loadLibrary, so you');
            console.log('    MUST have spawned with -f (../README.md section 7.4.4).');
            return [];
        }
        console.log('\n[*] Recovered JNI registrations (' + this._jniTable.length + '):');
        this._jniTable.forEach(function (r, i) {
            console.log('  [' + i + '] ' + r.clazz + '.' + r.name + r.sig);
            console.log('       ' + r.module + (r.offset ? '+' + r.offset : '') +
                        '   ' + r.addr);
        });
        console.log('\n    Trace one with:  nat.jniHook(<index>)');
        console.log('    Or open ' + this._jniTable[0].module + ' in Ghidra at the offset.');
        return this._jniTable;
    },

    /* Hook one recovered JNI function by table index. */
    jniHook: function (index) {
        var r = this._jniTable[index];
        if (r === undefined) { console.log('[-] no such index'); return false; }
        return this._hookAddress(r.addr, r.clazz + '.' + r.name, true);
    },

    /* Hook every recovered JNI function. */
    jniHookAll: function () {
        var self = this, n = 0;
        this._jniTable.forEach(function (r) {
            if (self._hookAddress(r.addr, r.clazz + '.' + r.name, true)) n++;
        });
        console.log('[+] hooked ' + n + ' recovered JNI function(s)');
        return n;
    },

    /*
     * Fallback when RegisterNatives is not resolvable: hook JNI_OnLoad itself.
     * You still see when the library initialises, and you can then inspect
     * memory around the call for the JNINativeMethod array.
     */
    onload: function (moduleName) {
        var addr = this._moduleExport(moduleName, 'JNI_OnLoad');
        if (addr === null) {
            console.log('[-] ' + moduleName + ' does not export JNI_OnLoad');
            return false;
        }
        var self = this;
        var l = Interceptor.attach(addr, {
            onEnter: function (args) {
                console.log('[jni] ' + moduleName + '!JNI_OnLoad(vm=' + args[0] +
                            ', reserved=' + args[1] + ')');
                console.log('      backtrace:');
                Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .slice(0, 6)
                    .forEach(function (f) {
                        console.log('        ' + DebugSymbol.fromAddress(f));
                    });
            },
            onLeave: function (retval) {
                console.log('[jni] JNI_OnLoad -> 0x' + retval.toInt32().toString(16) +
                            ' (JNI_VERSION)');
            }
        });
        this._listeners.push(l);
        console.log('[+] hooked ' + moduleName + '!JNI_OnLoad');
        return true;
    },

    /* ==================================================================
     * 2. MODULE / SYMBOL TRACING
     * ================================================================== */

    /* List a module's exports without hooking anything. */
    exports: function (moduleName, filter) {
        var m = Process.findModuleByName(moduleName);
        if (m === null) {
            console.log('[-] ' + moduleName + ' is not loaded.');
            console.log('    Loaded modules matching:');
            Process.enumerateModules()
                .filter(function (x) { return x.name.indexOf(moduleName.split('.')[0]) !== -1; })
                .forEach(function (x) { console.log('      ' + x.name); });
            return [];
        }
        var re = filter ? new RegExp(filter) : null;
        var list = m.enumerateExports().filter(function (e) {
            return e.type === 'function' && (re === null || re.test(e.name));
        });
        console.log('[*] ' + moduleName + ' base=' + m.base +
                    ' size=0x' + m.size.toString(16) +
                    '  ' + list.length + ' function export(s)');
        list.slice(0, 200).forEach(function (e) {
            console.log('      +0x' + e.address.sub(m.base).toString(16) + '  ' + e.name);
        });
        if (list.length > 200) console.log('      … ' + (list.length - 200) + ' more');
        return list.map(function (e) { return e.name; });
    },

    /* Hook every exported function of a module. */
    module: function (moduleName, filter) {
        var self = this;
        var m = Process.findModuleByName(moduleName);
        if (m === null) {
            console.log('[-] ' + moduleName + ' not loaded. Use nat.watch("' +
                        moduleName + '") to instrument it when it appears.');
            return 0;
        }

        var re = filter ? new RegExp(filter) : null;
        var n = 0;

        // Batch: one instruction-cache flush for the whole set rather than one
        // per hook. On a library with 500 exports this matters.
        Interceptor.flush();
        m.enumerateExports().forEach(function (e) {
            if (e.type !== 'function') return;
            if (re !== null && !re.test(e.name)) return;
            if (self._hookAddress(e.address, moduleName + '!' + e.name, false)) n++;
        });
        Interceptor.flush();

        console.log('[+] hooked ' + n + ' export(s) of ' + moduleName);
        if (n > 100) {
            console.log('[!] That is a lot of hooks. Expect a visible slowdown.');
            console.log('    Narrow with a filter:  nat.module("' + moduleName + '", "^crypt")');
        }
        return n;
    },

    symbol: function (moduleName, symbolName) {
        var addr = this._moduleExport(moduleName, symbolName);
        if (addr === null) {
            console.log('[-] ' + moduleName + '!' + symbolName + ' not found.');
            console.log('    If this is a Java_* symbol that should exist, the app');
            console.log('    probably used RegisterNatives. Run nat.jni() and respawn.');
            return false;
        }
        return this._hookAddress(addr, moduleName + '!' + symbolName, false);
    },

    /*
     * Hook a function that is not exported, by module base + offset. This is
     * the bridge from a disassembler to a live process: Ghidra gives you an
     * offset, ASLR gives the module a different base every run, and this
     * combines them correctly.
     */
    offset: function (moduleName, off) {
        var m = Process.findModuleByName(moduleName);
        if (m === null) { console.log('[-] ' + moduleName + ' not loaded'); return false; }
        var addr = m.base.add(off);
        if (addr.compare(m.base.add(m.size)) >= 0) {
            console.log('[-] offset 0x' + off.toString(16) + ' is beyond the module');
            return false;
        }
        return this._hookAddress(addr, moduleName + '+0x' + off.toString(16), false);
    },

    /* Shared hook installer. `jniStyle` shifts argument labelling. */
    _hookAddress: function (addr, label, jniStyle) {
        var self = this;
        var key = addr.toString();
        if (this._traced[key]) return false;

        try {
            var l = Interceptor.attach(addr, {
                onEnter: function (args) {
                    self._counts[label] = (self._counts[label] || 0) + 1;
                    this.t0 = Date.now();

                    var parts = [];
                    var start = jniStyle ? 2 : 0;
                    if (jniStyle) {
                        parts.push('JNIEnv*=' + args[0]);
                        parts.push('this/cls=' + args[1]);
                    }
                    // Read a fixed number of registers. We do not know the real
                    // arity, so 4 is a pragmatic compromise between useful and
                    // noisy. Reading beyond the real arity is harmless — those
                    // registers just hold whatever was there.
                    for (var i = start; i < start + 4; i++) {
                        parts.push('a' + (i - start) + '=' + self._arg(args[i]));
                    }
                    console.log('[>] ' + label + '(' + parts.join(', ') + ')');
                },
                onLeave: function (retval) {
                    var dt = Date.now() - this.t0;
                    console.log('[<] ' + label + ' -> ' + self._arg(retval) +
                                '  [' + dt + 'ms]');
                }
            });
            this._listeners.push(l);
            this._traced[key] = true;
            return true;
        } catch (e) {
            console.log('[-] could not hook ' + label + ': ' + e.message);
            return false;
        }
    },

    /* ==================================================================
     * 3. LIBC PRESETS
     * ================================================================== */

    libc: function (which) {
        var groups = {
            file: ['open', 'openat', 'fopen', 'stat', 'lstat', 'access',
                   'unlink', 'rename', 'mkdir', 'remove', 'readlink'],
            exec: ['execve', 'execl', 'execvp', 'system', 'popen', 'fork', 'vfork'],
            net:  ['socket', 'connect', 'bind', 'send', 'sendto', 'recv', 'recvfrom',
                   'getaddrinfo', 'gethostbyname'],
            dl:   ['dlopen', 'android_dlopen_ext', 'dlsym', 'dlclose'],
            mem:  ['mmap', 'mprotect', 'munmap'],
            proc: ['ptrace', 'kill', 'prctl', 'getpid', 'gettid']
        };

        var names;
        if (which === 'all') {
            names = [];
            Object.keys(groups).forEach(function (g) {
                names = names.concat(groups[g]);
            });
        } else {
            names = groups[which];
            if (names === undefined) {
                console.log('[-] unknown group. Available: ' +
                            Object.keys(groups).join(', ') + ', all');
                return 0;
            }
        }

        var self = this, n = 0;
        Interceptor.flush();
        names.forEach(function (sym) {
            var addr = self._moduleExport('libc.so', sym) || self._globalExport(sym);
            if (addr === null) { return; }          // not exported here — fine
            if (self._hookAddress(addr, 'libc!' + sym, false)) n++;
        });
        Interceptor.flush();

        console.log('[+] libc preset "' + which + '": ' + n + ' function(s) hooked');
        return n;
    },

    /* ==================================================================
     * 4. LAZY MODULE WATCH
     * ================================================================== */

    watch: function (namePattern, onLoaded) {
        var self = this;
        var re = new RegExp(namePattern);

        // Already loaded?
        var existing = Process.enumerateModules().filter(function (m) {
            return re.test(m.name);
        });
        if (existing.length > 0) {
            existing.forEach(function (m) {
                console.log('[+] ' + m.name + ' already loaded at ' + m.base);
                if (typeof onLoaded === 'function') onLoaded(m);
                else self.module(m.name);
            });
            return existing.length;
        }

        var dl = this._firstOf(null, ['android_dlopen_ext', 'dlopen', '__dl_dlopen']);
        if (dl === null) {
            console.log('[-] no dlopen symbol resolvable; cannot watch');
            return 0;
        }

        var l = Interceptor.attach(dl.addr, {
            onEnter: function (args) {
                this.path = null;
                try {
                    this.path = args[0].isNull() ? null : args[0].readCString();
                } catch (e) { /* ignore */ }
            },
            onLeave: function (retval) {
                if (this.path === null) return;
                var base = this.path.split('/').pop();
                if (!re.test(base)) return;
                console.log('[+] dlopen loaded ' + this.path);
                var m = Process.findModuleByName(base);
                if (m === null) return;
                if (typeof onLoaded === 'function') onLoaded(m);
                else self.module(m.name);
            }
        });
        this._listeners.push(l);
        console.log('[+] watching for a module matching /' + namePattern + '/ via ' + dl.name);
        return 1;
    },

    /* ==================================================================
     * CALLING NATIVE CODE — turn a discovered function into an oracle
     * ================================================================== */

    call: function (moduleName, off, retType, argTypes, args) {
        var m = Process.findModuleByName(moduleName);
        if (m === null) { console.log('[-] ' + moduleName + ' not loaded'); return null; }
        var addr = (typeof off === 'number') ? m.base.add(off) : ptr(off);

        try {
            // exceptions:'propagate' turns a native crash into a JS exception
            // instead of taking the whole process down. Essential while you are
            // still guessing the signature.
            var fn = new NativeFunction(addr, retType, argTypes,
                                        { exceptions: 'propagate' });
            var result = fn.apply(null, args);
            console.log('[call] ' + moduleName + '+0x' + off.toString(16) +
                        ' -> ' + result);
            return result;
        } catch (e) {
            console.log('[-] call failed: ' + e.message);
            console.log('    Check the signature. A wrong type string is a segfault,');
            console.log('    not a type error. See ../README.md section 7.8.');
            return null;
        }
    },

    /* ------------------------------------------------------------ control */

    stats: function () {
        var rows = Object.keys(this._counts).map(function (k) {
            return [k, this._counts[k]];
        }, this);
        rows.sort(function (a, b) { return b[1] - a[1]; });
        console.log('\n[*] native call counts:');
        rows.slice(0, 40).forEach(function (r) {
            console.log(('        ' + r[1]).slice(-8) + '  ' + r[0]);
        });
        return rows.length;
    },

    modules: function (filter) {
        var re = filter ? new RegExp(filter) : null;
        var list = Process.enumerateModules().filter(function (m) {
            return re === null || re.test(m.name);
        });
        console.log('[*] ' + list.length + ' module(s):');
        list.forEach(function (m) {
            console.log('      ' + m.base + '  0x' + m.size.toString(16) +
                        '  ' + m.name);
        });
        return list.map(function (m) { return m.name; });
    },

    stop: function () {
        var n = this._listeners.length;
        this._listeners.forEach(function (l) {
            try { l.detach(); } catch (e) { /* already gone */ }
        });
        this._listeners = [];
        this._traced = {};
        console.log('[*] detached ' + n + ' listener(s)');
        return n;
    },

    help: function () {
        console.log([
            '',
            'JNI RECOVERY',
            '  nat.jni()                          hook RegisterNatives (auto-run at load)',
            '  nat.table()                        print the recovered mapping',
            '  nat.jniHook(i) / nat.jniHookAll()  trace recovered function(s)',
            '  nat.onload("libfoo.so")            hook JNI_OnLoad directly',
            '',
            'MODULES AND SYMBOLS',
            '  nat.modules([filter])              list loaded modules',
            '  nat.exports("libfoo.so"[,re])      list exports WITHOUT hooking',
            '  nat.module("libfoo.so"[,re])       hook every matching export',
            '  nat.symbol("libfoo.so","sym")      hook one export',
            '  nat.offset("libfoo.so", 0x3e40)    hook an UNEXPORTED function',
            '  nat.watch("libsecret")             hook it when dlopen loads it',
            '',
            'CALLING IN',
            '  nat.call("libfoo.so",0x3e40,"int",["pointer","int"],[p,5])',
            '',
            'LIBC PRESETS',
            '  nat.libc("file"|"exec"|"net"|"dl"|"mem"|"proc"|"all")',
            '',
            'CONTROL',
            '  nat.stats()                        call counts',
            '  nat.stop()                         detach everything',
            ''
        ].join('\n'));
    }
};

/* ---------------------------------------------------------- RPC surface */

rpc.exports = {
    init: function (stage, params) {
        console.log('[*] native-tracer loaded (stage=' + stage + ')');
    },
    dispose: function () { nat.stop(); },
    jniTable: function () {
        return nat._jniTable.map(function (r) {
            return {
                clazz: r.clazz, name: r.name, sig: r.sig,
                module: r.module, offset: r.offset, address: r.addr.toString()
            };
        });
    },
    traceModule: function (name, filter) { return nat.module(name, filter); },
    stats: function () { return nat._counts; },
    stop: function () { return nat.stop(); }
};

/* --------------------------------------------------------------- bootstrap */

console.log('');
console.log('=== native-tracer ===');
console.log('[*] arch=' + Process.arch + ' pointerSize=' + Process.pointerSize +
            ' pid=' + Process.id);

// JNI recovery must be armed BEFORE System.loadLibrary runs, which is why this
// happens at script load rather than inside a Java.perform callback.
nat.jni();

Java.perform(function () {
    // Log every library the app loads, so you know what to trace and when.
    try {
        var System = Java.use('java.lang.System');
        System.loadLibrary.overload('java.lang.String').implementation = function (name) {
            console.log('[lib] System.loadLibrary("' + name + '")');
            var r = this.loadLibrary(name);
            var m = Process.findModuleByName('lib' + name + '.so');
            if (m !== null) {
                console.log('      -> ' + m.name + ' at ' + m.base +
                            ' size=0x' + m.size.toString(16));
            }
            return r;
        };
        System.load.overload('java.lang.String').implementation = function (path) {
            console.log('[lib] System.load("' + path + '")');
            return this.load(path);
        };
    } catch (e) {
        console.log('[.] could not hook System.loadLibrary: ' + e.message);
    }
});

console.log('[+] ready — type nat.help()');
console.log('');
