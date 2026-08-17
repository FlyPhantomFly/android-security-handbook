/*
 * artmethod-inspect.js — inspect ArtMethod structures in a live Android process.
 *
 * WHAT IT DOES
 *   Resolves Java methods, reads their underlying ArtMethod structures, and
 *   classifies each method's current execution state (interpreted / AOT /
 *   JIT / trampolined) by examining entry_point_from_quick_compiled_code_.
 *
 *   Crucially, it DERIVES the entry-point offset at runtime rather than
 *   hard-coding it. ART ships as a Mainline module, so two devices reporting
 *   the same Android release can have different ArtMethod layouts. Scripts
 *   that hard-code offsets are the single biggest source of "works on my
 *   phone" breakage in public Frida tooling.
 *
 *   See ../README.md sections 3.15 - 3.17 for the theory.
 *
 * HOW TO RUN
 *   frida -U -f com.example.target -l artmethod-inspect.js
 *   frida -U -n com.example.target -l artmethod-inspect.js
 *
 *   Then from the REPL:
 *     art.inspect("com.example.Auth", "isValid")
 *     art.inspectClass("com.example.Auth")
 *     art.watch("com.example.Auth", "isValid")      // poll for state changes
 *     art.offset()                                   // show the derived offset
 *
 * TIP
 *   For reliable results while investigating a hook failure, first run:
 *     adb shell cmd package compile -m verify -f com.example.target
 *     adb shell am force-stop com.example.target
 *   That forces every method into the interpreter (README section 3.10).
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var art = {
    _entryOffset: null,
    _trampolines: {},
    _libart: null,

    /* ---------------------------------------------------------------- init */

    init: function () {
        this._libart = Process.findModuleByName('libart.so');
        if (this._libart === null) {
            console.log('[-] libart.so not found — is this an Android app process?');
            return false;
        }
        console.log('[*] libart.so  base=' + this._libart.base +
                    '  size=0x' + this._libart.size.toString(16));

        this._loadTrampolines();
        this._deriveEntryOffset();
        return this._entryOffset !== null;
    },

    _loadTrampolines: function () {
        var names = [
            'art_quick_to_interpreter_bridge',
            'art_quick_generic_jni_trampoline',
            'art_quick_resolution_trampoline',
            'art_quick_imt_conflict_trampoline',
            'art_quick_instrumentation_entry',
            'art_quick_deoptimize'
        ];

        var found = 0;
        names.forEach(function (name) {
            var addr = Module.findExportByName('libart.so', name);
            if (addr !== null) {
                art._trampolines[addr.toString()] = name;
                found++;
            }
        });

        console.log('[*] Resolved ' + found + '/' + names.length + ' trampoline symbols');
        if (found === 0) {
            console.log('[!] No trampolines exported on this build. Classification will be');
            console.log('    limited to module-backed vs anonymous. This is normal on some');
            console.log('    ART Mainline versions — see README section 3.26.');
        }
    },

    /*
     * Derive the entry-point offset empirically.
     *
     * Strategy: java.lang.Object.hashCode() is always present. We scan the
     * first 128 bytes of several well-known methods looking for a pointer
     * value that is either a known trampoline or lies inside a module /
     * executable range. The offset that holds such a value consistently
     * across multiple methods is the entry point field.
     */
    _deriveEntryOffset: function () {
        var self = this;
        var candidates = {};
        var probes = [];

        Java.perform(function () {
            try {
                probes.push(Java.use('java.lang.Object').hashCode.overload().handle);
                probes.push(Java.use('java.lang.Object').toString.overload().handle);
                probes.push(Java.use('java.lang.String').length.overload().handle);
            } catch (e) {
                console.log('[-] Could not resolve probe methods: ' + e);
            }
        });

        if (probes.length === 0) return;

        var ps = Process.pointerSize;
        for (var off = 0; off <= 64; off += ps) {
            var hits = 0;
            for (var i = 0; i < probes.length; i++) {
                try {
                    var val = ptr(probes[i]).add(off).readPointer();
                    if (val.isNull()) continue;
                    if (self._trampolines[val.toString()] !== undefined) { hits++; continue; }
                    var range = Process.findRangeByAddress(val);
                    if (range !== null && range.protection.indexOf('x') !== -1) hits++;
                } catch (e) { /* unreadable — not this offset */ }
            }
            if (hits === probes.length) {
                candidates[off] = hits;
            }
        }

        // The entry point is conventionally the LAST pointer-sized field, so
        // prefer the largest qualifying offset.
        var best = null;
        Object.keys(candidates).forEach(function (k) {
            var o = parseInt(k, 10);
            if (best === null || o > best) best = o;
        });

        if (best !== null) {
            this._entryOffset = best;
            console.log('[+] Derived entry-point offset: +0x' + best.toString(16));
        } else {
            console.log('[-] Could not derive entry-point offset automatically.');
            console.log('    Set it manually:  art._entryOffset = 0x18');
        }
    },

    offset: function () {
        console.log('[*] entry_point offset = ' +
            (this._entryOffset === null ? '<not derived>'
                                        : '+0x' + this._entryOffset.toString(16)));
        return this._entryOffset;
    },

    /* ------------------------------------------------------- classification */

    classify: function (handle) {
        if (this._entryOffset === null) return { state: 'unknown', ep: null };

        var ep;
        try {
            ep = ptr(handle).add(this._entryOffset).readPointer();
        } catch (e) {
            return { state: 'unreadable', ep: null };
        }

        var known = this._trampolines[ep.toString()];
        if (known !== undefined) {
            var friendly = {
                'art_quick_to_interpreter_bridge': 'INTERPRETED',
                'art_quick_resolution_trampoline': 'UNRESOLVED (first call will resolve)',
                'art_quick_generic_jni_trampoline': 'NATIVE (generic JNI stub)',
                'art_quick_imt_conflict_trampoline': 'IMT CONFLICT',
                'art_quick_instrumentation_entry': 'INSTRUMENTED (deoptimized/hooked)'
            };
            return { state: friendly[known] || known, ep: ep, symbol: known };
        }

        var mod = Process.findModuleByAddress(ep);
        if (mod !== null) {
            return { state: 'AOT compiled (' + mod.name + ')', ep: ep, module: mod.name };
        }

        var range = Process.findRangeByAddress(ep);
        if (range !== null) {
            return {
                state: 'JIT compiled (anon ' + range.protection +
                       (range.file ? ' ' + range.file.path : '') + ')',
                ep: ep
            };
        }

        return { state: 'UNKNOWN (' + ep + ')', ep: ep };
    },

    /* ------------------------------------------------------------ inspect */

    inspect: function (className, methodName) {
        var self = this;
        Java.perform(function () {
            var clazz;
            try {
                clazz = Java.use(className);
            } catch (e) {
                console.log('[-] Class not found in the default loader: ' + className);
                console.log('    Try art.findLoader("' + className + '") first.');
                return;
            }

            var member = clazz[methodName];
            if (member === undefined) {
                console.log('[-] No such method: ' + methodName);
                return;
            }

            console.log('\n[*] ' + className + '.' + methodName);
            var overloads = member.overloads || [member];
            overloads.forEach(function (ov, idx) {
                var sig;
                try {
                    sig = ov.argumentTypes.map(function (t) { return t.className; }).join(', ');
                } catch (e) { sig = '?'; }

                var info = self.classify(ov.handle);
                console.log('    [' + idx + '] (' + sig + ')');
                console.log('         ArtMethod* = ' + ov.handle);
                console.log('         entry      = ' + (info.ep || '?'));
                console.log('         state      = ' + info.state);
            });
        });
    },

    inspectClass: function (className) {
        var self = this;
        Java.perform(function () {
            var clazz;
            try { clazz = Java.use(className); }
            catch (e) { console.log('[-] Class not found: ' + className); return; }

            console.log('\n[*] All declared methods of ' + className);
            var jclass = clazz.class;
            var methods = jclass.getDeclaredMethods();

            var counts = {};
            methods.forEach(function (m) {
                var name = m.getName();
                try {
                    var ov = clazz[name];
                    if (ov === undefined) return;
                    var list = ov.overloads || [ov];
                    list.forEach(function (o) {
                        var info = self.classify(o.handle);
                        counts[info.state] = (counts[info.state] || 0) + 1;
                        console.log('    ' + name + '  -> ' + info.state);
                    });
                } catch (e) { /* skip unresolvable */ }
            });

            console.log('\n[*] Summary:');
            Object.keys(counts).forEach(function (k) {
                console.log('    ' + counts[k] + '  ' + k);
            });
        });
    },

    /* -------------------------------------------------------------- watch */

    watch: function (className, methodName, intervalMs) {
        var self = this;
        intervalMs = intervalMs || 250;

        Java.perform(function () {
            var clazz = Java.use(className);
            var ov = clazz[methodName].overload
                   ? clazz[methodName].overloads[0]
                   : clazz[methodName];
            var handle = ptr(ov.handle);
            var last = null;

            console.log('[*] Watching ' + className + '.' + methodName +
                        ' every ' + intervalMs + 'ms. Exercise the app now.');

            setInterval(function () {
                var info = self.classify(handle);
                var key = info.ep ? info.ep.toString() : 'null';
                if (last !== key) {
                    console.log('[!] state change -> ' + info.state + '  (ep=' + info.ep + ')');
                    last = key;
                }
            }, intervalMs);
        });
    },

    /* ------------------------------------------------------- class loaders */

    findLoader: function (className) {
        Java.perform(function () {
            console.log('[*] Searching all class loaders for ' + className);
            var found = false;
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    try {
                        loader.loadClass(className);
                        console.log('[+] FOUND in: ' + loader);
                        console.log('    Switch with: Java.classFactory.loader = <that loader>');
                        found = true;
                    } catch (e) { /* not here */ }
                },
                onComplete: function () {
                    if (!found) console.log('[-] Not found in any loaded class loader.');
                }
            });
        });
    },

    /* ---------------------------------------------------------- raw dump */

    dump: function (className, methodName, length) {
        var self = this;
        length = length || 64;
        Java.perform(function () {
            var clazz = Java.use(className);
            var ov = clazz[methodName].overloads
                   ? clazz[methodName].overloads[0]
                   : clazz[methodName];
            var base = ptr(ov.handle);

            console.log('\n[*] Raw ArtMethod at ' + base);
            console.log(hexdump(base, { length: length, ansi: false }));

            // access_flags_ is conventionally at +0x04 on 64-bit builds, but
            // verify against art/runtime/art_method.h for your ART version.
            try {
                var af = base.add(4).readU32();
                console.log('[*] Probable access_flags_ = 0x' + af.toString(16));
                var flags = {
                    0x0001: 'PUBLIC', 0x0002: 'PRIVATE', 0x0004: 'PROTECTED',
                    0x0008: 'STATIC', 0x0010: 'FINAL', 0x0020: 'SYNCHRONIZED',
                    0x0100: 'NATIVE', 0x0400: 'ABSTRACT', 0x1000: 'SYNTHETIC'
                };
                var set = [];
                Object.keys(flags).forEach(function (bit) {
                    if ((af & parseInt(bit, 10)) !== 0) set.push(flags[bit]);
                });
                console.log('    -> ' + set.join(' | '));
                console.log('    (upper bits include ART-internal and hidden-API state)');
            } catch (e) { /* ignore */ }
        });
    },

    help: function () {
        console.log([
            '',
            'art.offset()                          show derived entry-point offset',
            'art.inspect(cls, method)              classify one method\'s state',
            'art.inspectClass(cls)                 classify every method of a class',
            'art.watch(cls, method [, ms])         poll for state changes live',
            'art.findLoader(cls)                   locate a class across all loaders',
            'art.dump(cls, method [, len])         hexdump the raw ArtMethod',
            ''
        ].join('\n'));
    }
};

/* --------------------------------------------------------------- bootstrap */

Java.perform(function () {
    console.log('');
    console.log('=== artmethod-inspect ===');
    if (art.init()) {
        console.log('[+] Ready. Type art.help() for commands.');
    } else {
        console.log('[-] Initialisation incomplete. Some features unavailable.');
    }
    console.log('');
});
