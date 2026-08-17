/*
 * force-deoptimize.js — push ART methods back into the interpreter so that
 * Java hooks land reliably.
 *
 * WHAT IT DOES
 *   When a Frida hook installs cleanly but never fires, the usual cause is
 *   that the optimizing compiler inlined the target into its caller, so no
 *   call instruction remains to intercept (../README.md section 3.17).
 *
 *   This script attacks that problem from inside the process, without needing
 *   to recompile the package:
 *
 *     1. Diagnoses whether compilation is actually the problem.
 *     2. Attempts to invoke ART's own deoptimization machinery.
 *     3. Falls back to per-method deoptimization via the instrumentation path.
 *     4. Tells you the out-of-process fix if neither is available.
 *
 * IMPORTANT
 *   ART is a Mainline module. Exported symbol names and mangled signatures
 *   differ between builds *within the same Android release*. Everything here
 *   is guarded and degrades gracefully. It will never blindly call an address.
 *
 *   The reliable, always-available fix is out of process:
 *
 *     adb shell cmd package compile -m verify -f <package>
 *     adb shell am force-stop <package>
 *
 *   Prefer that when you can restart the app. Use this script when you cannot.
 *
 * HOW TO RUN
 *   frida -U -f com.example.target -l force-deoptimize.js
 *
 *   Then from the REPL:
 *     deopt.diagnose("com.example.Auth", "isValid")
 *     deopt.everything()
 *     deopt.method("com.example.Auth", "isValid")
 *     deopt.status()
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var deopt = {
    _libart: null,
    _runtimeInstance: null,
    _symbols: {},

    /* ---------------------------------------------------------------- init */

    init: function () {
        this._libart = Process.findModuleByName('libart.so');
        if (this._libart === null) {
            console.log('[-] libart.so not found');
            return false;
        }
        console.log('[*] libart.so base=' + this._libart.base);
        this._resolveSymbols();
        return true;
    },

    /*
     * ART's C++ symbols are mangled and the exact mangling varies by build.
     * We search rather than assume, and we record what we found so the user
     * can see exactly which capabilities are available on this device.
     */
    _resolveSymbols: function () {
        var wanted = [
            { key: 'deoptimizeEverything',
              patterns: ['*Instrumentation*DeoptimizeEverything*'] },
            { key: 'undeoptimizeEverything',
              patterns: ['*Instrumentation*UndeoptimizeEverything*'] },
            { key: 'deoptimizeMethod',
              patterns: ['*Instrumentation*Deoptimize*ArtMethod*'] },
            { key: 'runtimeInstance',
              patterns: ['*Runtime*instance_*'] },
            { key: 'setEntryPoint',
              patterns: ['*ArtMethod*SetEntryPointFromQuickCompiledCode*'] },
            { key: 'interpreterBridge',
              patterns: ['art_quick_to_interpreter_bridge'] }
        ];

        var self = this;
        wanted.forEach(function (w) {
            w.patterns.forEach(function (p) {
                if (self._symbols[w.key] !== undefined) return;

                // Exact export first — cheapest and most reliable.
                var direct = Module.findExportByName('libart.so', p);
                if (direct !== null) {
                    self._symbols[w.key] = direct;
                    return;
                }

                // Then a debug-symbol search, which catches mangled names.
                try {
                    var matches = DebugSymbol.findFunctionsMatching(p);
                    if (matches && matches.length > 0) {
                        self._symbols[w.key] = matches[0];
                    }
                } catch (e) { /* symbol table unavailable */ }
            });
        });

        console.log('[*] Symbol availability on this ART build:');
        wanted.forEach(function (w) {
            var a = self._symbols[w.key];
            console.log('    ' + (a ? String(a) : '<unavailable>').padEnd(20) +
                        '  ' + w.key);
        });
    },

    /* ------------------------------------------------------------ diagnose */

    /*
     * The most useful function here. Answers: "is compilation the reason my
     * hook is not firing?" without any guessing.
     */
    diagnose: function (className, methodName) {
        var self = this;
        Java.perform(function () {
            console.log('\n=== Diagnosis: ' + className + '.' + methodName + ' ===');

            var clazz;
            try {
                clazz = Java.use(className);
            } catch (e) {
                console.log('[X] Class not resolvable in the default loader.');
                console.log('    CAUSE: wrong ClassLoader, not compilation.');
                console.log('    FIX:   enumerate loaders — see artmethod-inspect.js findLoader()');
                return;
            }

            var member = clazz[methodName];
            if (member === undefined) {
                console.log('[X] Method not found on the class.');
                console.log('    CAUSE: wrong name, or it is declared on a superclass.');
                return;
            }

            var overloads = member.overloads || [member];
            console.log('[*] ' + overloads.length + ' overload(s) found');

            var bridge = self._symbols['interpreterBridge'];
            var interpretedCount = 0;

            overloads.forEach(function (ov, i) {
                var handle = ptr(ov.handle);
                var state = 'unknown';
                var ep = null;

                // Probe for the entry point without hard-coding the offset:
                // look for a pointer that is either the bridge or executable.
                for (var off = 0; off <= 64; off += Process.pointerSize) {
                    try {
                        var v = handle.add(off).readPointer();
                        if (v.isNull()) continue;
                        if (bridge !== undefined && v.equals(bridge)) {
                            ep = v; state = 'INTERPRETED'; break;
                        }
                        var r = Process.findRangeByAddress(v);
                        if (r !== null && r.protection.indexOf('x') !== -1) {
                            ep = v;
                            var mod = Process.findModuleByAddress(v);
                            state = mod ? ('COMPILED (AOT in ' + mod.name + ')')
                                        : 'COMPILED (JIT, anonymous)';
                            // keep scanning: a later offset may be the real one
                        }
                    } catch (e) { /* not readable at this offset */ }
                }

                if (state === 'INTERPRETED') interpretedCount++;
                console.log('    [' + i + '] ArtMethod=' + ov.handle +
                            ' ep=' + (ep || '?') + ' -> ' + state);
            });

            console.log('');
            if (interpretedCount === overloads.length) {
                console.log('[+] All overloads are INTERPRETED.');
                console.log('    Compilation is NOT your problem. If the hook still does not');
                console.log('    fire, check: wrong overload, wrong ClassLoader, or you hooked');
                console.log('    an interface declaration instead of the concrete class.');
            } else {
                console.log('[!] At least one overload is COMPILED.');
                console.log('    Inlining is a likely cause of hook failure.');
                console.log('    TRY, in order:');
                console.log('      1. deopt.everything()');
                console.log('      2. Hook the CALLER instead of this method');
                console.log('      3. Out of process (most reliable):');
                console.log('           adb shell cmd package compile -m verify -f <pkg>');
                console.log('           adb shell am force-stop <pkg>');
            }
            console.log('');
        });
    },

    /* -------------------------------------------------------- deoptimize */

    /*
     * Ask ART to deoptimize the whole runtime. This is what the debugger does
     * when it attaches. Requires the symbol to be resolvable AND a valid
     * Instrumentation instance, which we cannot always obtain safely.
     */
    everything: function () {
        var sym = this._symbols['deoptimizeEverything'];
        if (sym === undefined) {
            console.log('[-] DeoptimizeEverything is not resolvable on this ART build.');
            this._recommendOutOfProcess();
            return false;
        }

        console.log('[*] Found DeoptimizeEverything at ' + sym);
        console.log('[!] Calling it requires a valid Instrumentation* (obtained from');
        console.log('    Runtime::Current()->GetInstrumentation()), whose layout is');
        console.log('    version-specific. Calling with a wrong pointer will crash the');
        console.log('    target, so this script does NOT do it blindly.');
        console.log('');
        console.log('    The safe equivalent is the Java-side approach below.');
        return this._javaSideDeopt();
    },

    /*
     * Safe alternative: trigger deoptimization through documented Java APIs.
     *
     * Setting a method trace, or enabling debugging, causes ART to install
     * instrumentation and deoptimize. This is slower but uses only supported
     * interfaces, so it works across ART versions.
     */
    _javaSideDeopt: function () {
        var ok = false;
        Java.perform(function () {
            try {
                var VMDebug = Java.use('dalvik.system.VMDebug');
                // Starting method tracing forces the runtime to instrument,
                // which deoptimizes compiled code.
                console.log('[*] Attempting deoptimization via VMDebug method tracing...');
                VMDebug.startMethodTracingDdms(8 * 1024 * 1024, 0, false, 0);
                console.log('[+] Method tracing started — runtime is now instrumented.');
                console.log('    Compiled code is being bypassed. Install your hooks now.');
                console.log('    Stop later with: deopt.stopTracing()');
                ok = true;
            } catch (e) {
                console.log('[-] VMDebug tracing failed: ' + e);
            }
        });
        if (!ok) this._recommendOutOfProcess();
        return ok;
    },

    stopTracing: function () {
        Java.perform(function () {
            try {
                Java.use('dalvik.system.VMDebug').stopMethodTracing();
                console.log('[+] Method tracing stopped.');
            } catch (e) {
                console.log('[-] ' + e);
            }
        });
    },

    /*
     * Per-method approach: force a single method's entry point to the
     * interpreter bridge. Narrower blast radius than deoptimizing everything.
     */
    method: function (className, methodName) {
        var self = this;
        var bridge = this._symbols['interpreterBridge'];
        if (bridge === undefined) {
            console.log('[-] art_quick_to_interpreter_bridge is not resolvable.');
            this._recommendOutOfProcess();
            return;
        }

        Java.perform(function () {
            var clazz;
            try { clazz = Java.use(className); }
            catch (e) { console.log('[-] Class not found: ' + className); return; }

            var member = clazz[methodName];
            if (member === undefined) { console.log('[-] Method not found'); return; }

            var overloads = member.overloads || [member];
            overloads.forEach(function (ov, i) {
                var handle = ptr(ov.handle);

                // Find the entry point offset by locating a currently-executable
                // pointer, then overwrite it with the interpreter bridge.
                var written = false;
                for (var off = 0; off <= 64; off += Process.pointerSize) {
                    try {
                        var v = handle.add(off).readPointer();
                        if (v.isNull()) continue;
                        var r = Process.findRangeByAddress(v);
                        if (r !== null && r.protection.indexOf('x') !== -1) {
                            if (self._backup === undefined) self._backup = [];
                            self._backup.push({
                                handle: handle, off: off, original: v,
                                label: className + '.' + methodName + '[' + i + ']'
                            });
                            handle.add(off).writePointer(bridge);
                            console.log('[+] ' + className + '.' + methodName +
                                        '[' + i + '] entry +0x' + off.toString(16) +
                                        ': ' + v + ' -> interpreter bridge');
                            written = true;
                        }
                    } catch (e) { /* skip */ }
                }
                if (!written) {
                    console.log('[-] Could not locate an entry point for overload ' + i);
                }
            });

            console.log('[*] Restore with deopt.restore()');
        });
    },

    restore: function () {
        if (this._backup === undefined || this._backup.length === 0) {
            console.log('[-] Nothing to restore.');
            return;
        }
        this._backup.forEach(function (b) {
            try {
                b.handle.add(b.off).writePointer(b.original);
                console.log('[+] Restored ' + b.label);
            } catch (e) {
                console.log('[-] Restore failed for ' + b.label + ': ' + e);
            }
        });
        this._backup = [];
    },

    _recommendOutOfProcess: function () {
        var pkg = '<package>';
        try {
            Java.perform(function () {
                pkg = Java.use('android.app.ActivityThread')
                          .currentApplication().getApplicationContext()
                          .getPackageName();
            });
        } catch (e) { /* ignore */ }

        console.log('');
        console.log('    RELIABLE FALLBACK (works on every ART build):');
        console.log('      adb shell cmd package compile -m verify -f ' + pkg);
        console.log('      adb shell am force-stop ' + pkg);
        console.log('      # then re-run your Frida script');
        console.log('');
        console.log('    Restore performance afterwards with:');
        console.log('      adb shell cmd package compile -m speed-profile -f ' + pkg);
        console.log('');
    },

    status: function () {
        console.log('\n[*] force-deoptimize status');
        console.log('    libart:  ' + (this._libart ? this._libart.base : '<none>'));
        var self = this;
        Object.keys(this._symbols).forEach(function (k) {
            console.log('    ' + k + ' = ' + self._symbols[k]);
        });
        console.log('    patched entry points: ' +
                    (this._backup ? this._backup.length : 0));
        console.log('');
    },

    help: function () {
        console.log([
            '',
            'deopt.diagnose(cls, method)   is compilation why my hook fails?',
            'deopt.everything()            deoptimize the whole runtime',
            'deopt.method(cls, method)     force one method to the interpreter',
            'deopt.restore()               undo entry-point patches',
            'deopt.stopTracing()           stop VMDebug method tracing',
            'deopt.status()                show resolved symbols and state',
            '',
            'Most reliable fix is out of process:',
            '  adb shell cmd package compile -m verify -f <pkg>',
            '  adb shell am force-stop <pkg>',
            ''
        ].join('\n'));
    }
};

/* --------------------------------------------------------------- bootstrap */

Java.perform(function () {
    console.log('');
    console.log('=== force-deoptimize ===');
    deopt.init();
    console.log('[+] Ready. Start with deopt.diagnose("<class>", "<method>")');
    console.log('    Type deopt.help() for all commands.');
    console.log('');
});
