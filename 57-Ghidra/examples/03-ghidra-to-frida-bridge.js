/*
 * 03-ghidra-to-frida-bridge.js — turn Ghidra addresses into live hooks.
 *
 * WHAT IT DOES
 *   Bridges the two halves of native analysis. You have addresses from Ghidra;
 *   this converts them to runtime addresses correctly, hooks them, dumps their
 *   arguments, and can dump memory regions back out for re-import into Ghidra.
 *
 *   It exists because the arithmetic is trivial and people get it wrong
 *   constantly, usually by pasting a raw address from a previous session.
 *
 * THE ARITHMETIC — the whole point of this file
 *
 *     runtime_address = module_base + (ghidra_address - image_base)
 *     ghidra_address  = image_base  + (runtime_address - module_base)
 *
 *   Ghidra loads a shared object at a default IMAGE BASE, usually 0x100000,
 *   so the addresses it shows are effectively offsets. At runtime, ASLR places
 *   the library at an arbitrary base which differs on every launch.
 *
 *   Check your image base in Ghidra: Window -> Memory Map, or the value shown
 *   in the import Options dialog.
 *
 * HOW TO RUN
 *   frida -U -f com.example.app -l 03-ghidra-to-frida-bridge.js --no-pause
 *
 *   Then from the REPL:
 *     g.help()
 *     g.setup("libnative.so", 0x100000)   // module name + Ghidra image base
 *     g.info()                            // bases, sizes, the conversion
 *     g.at(0x00103a10)                    // ghidra addr -> runtime addr
 *     g.rev("0x7b2c103a10")               // runtime addr -> ghidra addr
 *     g.hook(0x00103a10, "jni_decrypt")   // hook by GHIDRA address
 *     g.hookJni(0x00103a10, "decrypt")    // same, with JNI argument labelling
 *     g.dump(0x00102040, 96)              // hexdump at a Ghidra address
 *     g.jniTable(0x00102040, 3)           // decode a JNINativeMethod array
 *     g.call(0x00103a10, "int", ["pointer","int"], [ptr(0), 5])
 *     g.dumpModule("/data/local/tmp/dumped.so")   // for re-import into Ghidra
 *     g.unhookAll()
 *
 * SEE ALSO
 *   ../README.md section 7.1 (the address arithmetic)
 *   ../README.md section 7.4 (dumping memory back into Ghidra)
 *   ../../53-Frida/README.md section 7.8 (NativeFunction)
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var g = {

    /* ------------------------------------------------------------- state */

    _module: null,          // the Frida Module object
    _imageBase: ptr(0x100000),   // Ghidra's default for a .so
    _hooks: [],
    _counts: {},

    /* ---------------------------------------------------------- setup */

    /*
     * Bind to a module. `imageBase` is what Ghidra shows in Window -> Memory
     * Map; 0x100000 is the default for a shared object and is right the large
     * majority of the time.
     */
    setup: function (moduleName, imageBase) {
        var m = Process.findModuleByName(moduleName);
        if (m === null) {
            console.log('[-] ' + moduleName + ' is not loaded.');
            console.log('    Either the name is wrong, or the library has not been');
            console.log('    dlopen()d yet, or the APK ships it but nothing loads it.');
            console.log('');
            console.log('    Loaded modules matching that prefix:');
            var prefix = moduleName.replace(/\.so$/, '').replace(/^lib/, '');
            Process.enumerateModules().forEach(function (x) {
                if (x.name.indexOf(prefix) !== -1) {
                    console.log('      ' + x.name + '  @ ' + x.base);
                }
            });
            console.log('');
            console.log('    Use g.waitFor("' + moduleName + '") to hook it when it loads.');
            return false;
        }

        this._module = m;
        if (imageBase !== undefined && imageBase !== null) {
            this._imageBase = (typeof imageBase === 'number') ? ptr(imageBase)
                                                              : ptr(imageBase);
        }

        this.info();
        return true;
    },

    info: function () {
        if (this._module === null) {
            console.log('[-] call g.setup("libname.so") first');
            return null;
        }
        var m = this._module;
        console.log('');
        console.log('  module      : ' + m.name);
        console.log('  path        : ' + m.path);
        console.log('  runtime base: ' + m.base);
        console.log('  size        : 0x' + m.size.toString(16));
        console.log('  ghidra base : ' + this._imageBase);
        console.log('  delta       : ' + m.base.sub(this._imageBase) +
                    '   (add this to a Ghidra address)');
        console.log('');

        // The APK-mapped case: extractNativeLibs="false" means the library is
        // mapped straight out of base.apk rather than from a standalone file.
        if (m.path.indexOf('.apk!') !== -1) {
            console.log('  [note] this library is mapped from INSIDE the APK.');
            console.log('         extractNativeLibs="false". The bytes are the same;');
            console.log('         you just pull the APK and unzip rather than pulling');
            console.log('         a standalone .so. See ../README.md section 11.');
            console.log('');
        }
        return { base: m.base.toString(), size: m.size, imageBase: this._imageBase.toString() };
    },

    /*
     * Wait for a module that is dlopen'd later. Common for packed apps and for
     * SDKs that load their library lazily on first use.
     */
    waitFor: function (moduleName, callback) {
        var self = this;

        if (Process.findModuleByName(moduleName) !== null) {
            console.log('[+] ' + moduleName + ' is already loaded');
            self.setup(moduleName);
            if (typeof callback === 'function') callback(self._module);
            return true;
        }

        var dl = null;
        ['android_dlopen_ext', 'dlopen', '__dl_dlopen'].forEach(function (sym) {
            if (dl !== null) return;
            try {
                var a = (typeof Module.getGlobalExportByName === 'function')
                      ? Module.getGlobalExportByName(sym)
                      : Module.findExportByName(null, sym);
                if (a !== null) dl = { name: sym, addr: a };
            } catch (e) { /* not this one */ }
        });

        if (dl === null) {
            console.log('[-] no dlopen symbol resolvable; cannot wait');
            return false;
        }

        var l = Interceptor.attach(dl.addr, {
            onEnter: function (args) {
                this.path = null;
                try {
                    this.path = args[0].isNull() ? null : args[0].readCString();
                } catch (e) { /* ignore */ }
            },
            onLeave: function () {
                if (this.path === null) return;
                var base = this.path.split('/').pop();
                if (base !== moduleName) return;
                console.log('[+] ' + moduleName + ' loaded from ' + this.path);
                self.setup(moduleName);
                if (typeof callback === 'function') callback(self._module);
            }
        });
        this._hooks.push(l);
        console.log('[+] waiting for ' + moduleName + ' via ' + dl.name);
        return true;
    },

    /* ------------------------------------------------- address conversion */

    /* Ghidra address -> runtime NativePointer. THE function of this file. */
    at: function (ghidraAddr) {
        if (this._module === null) {
            throw new Error('call g.setup("libname.so") first');
        }
        var ga = (typeof ghidraAddr === 'number') ? ptr(ghidraAddr) : ptr(ghidraAddr);
        var offset = ga.sub(this._imageBase);

        if (offset.compare(ptr(0)) < 0) {
            console.log('[!] ' + ga + ' is BELOW the image base ' + this._imageBase);
            console.log('    Either your image base is wrong, or you passed an');
            console.log('    offset rather than a Ghidra address. Try g.off(x).');
        }
        if (offset.compare(ptr(this._module.size)) >= 0) {
            console.log('[!] ' + ga + ' is beyond the end of the module.');
            console.log('    Check the image base in Ghidra: Window -> Memory Map.');
        }

        var runtime = this._module.base.add(offset);
        console.log('  ghidra ' + ga + '  ->  runtime ' + runtime +
                    '   (offset +0x' + offset.toString(16) + ')');
        return runtime;
    },

    /* Raw offset (not a Ghidra address) -> runtime pointer. */
    off: function (offset) {
        if (this._module === null) throw new Error('call g.setup() first');
        var o = (typeof offset === 'number') ? ptr(offset) : ptr(offset);
        var runtime = this._module.base.add(o);
        console.log('  offset +0x' + o.toString(16) + '  ->  runtime ' + runtime);
        return runtime;
    },

    /* Runtime address -> Ghidra address. For turning a backtrace into something
     * you can look up in the disassembler. */
    rev: function (runtimeAddr) {
        if (this._module === null) throw new Error('call g.setup() first');
        var ra = ptr(runtimeAddr);
        var m = Process.findModuleByAddress(ra);
        if (m === null) {
            console.log('  ' + ra + ' is not inside any loaded module');
            return null;
        }
        if (m.name !== this._module.name) {
            console.log('  ' + ra + ' is in ' + m.name + ', not ' + this._module.name);
            console.log('  -> ' + m.name + '+0x' + ra.sub(m.base).toString(16));
            return null;
        }
        var ghidra = this._imageBase.add(ra.sub(m.base));
        console.log('  runtime ' + ra + '  ->  ghidra ' + ghidra);
        return ghidra;
    },

    /* ---------------------------------------------------------- hooking */

    /* Hook by GHIDRA address. Arguments are rendered generically. */
    hook: function (ghidraAddr, label, argCount) {
        var self = this;
        var addr;
        try { addr = this.at(ghidraAddr); } catch (e) {
            console.log('[-] ' + e.message); return false;
        }
        label = label || ('sub_' + ptr(ghidraAddr).toString(16));
        argCount = argCount || 4;

        try {
            var l = Interceptor.attach(addr, {
                onEnter: function (args) {
                    self._counts[label] = (self._counts[label] || 0) + 1;
                    this.t0 = Date.now();
                    var parts = [];
                    for (var i = 0; i < argCount; i++) {
                        parts.push('a' + i + '=' + self._renderArg(args[i]));
                    }
                    console.log('[>] ' + label + '(' + parts.join(', ') + ')');
                },
                onLeave: function (retval) {
                    console.log('[<] ' + label + ' -> ' + self._renderArg(retval) +
                                '  [' + (Date.now() - this.t0) + 'ms]');
                }
            });
            this._hooks.push(l);
            console.log('[+] hooked ' + label + ' at ' + addr);
            return true;
        } catch (e) {
            console.log('[-] could not hook ' + label + ': ' + e.message);
            return false;
        }
    },

    /*
     * Hook with JNI argument labelling. Use this for any function you recovered
     * from a RegisterNatives table or a Java_* export.
     *
     * JNI convention (../../16-JNI/README.md):
     *   args[0] = JNIEnv*
     *   args[1] = jobject (instance) or jclass (static)
     *   args[2] = the first DECLARED parameter
     */
    hookJni: function (ghidraAddr, javaName, declaredArgCount) {
        var self = this;
        var addr;
        try { addr = this.at(ghidraAddr); } catch (e) {
            console.log('[-] ' + e.message); return false;
        }
        javaName = javaName || ('jni_' + ptr(ghidraAddr).toString(16));
        declaredArgCount = (declaredArgCount === undefined) ? 3 : declaredArgCount;

        try {
            var l = Interceptor.attach(addr, {
                onEnter: function (args) {
                    self._counts[javaName] = (self._counts[javaName] || 0) + 1;
                    console.log('');
                    console.log('[jni] ' + javaName);
                    console.log('    JNIEnv*   = ' + args[0]);
                    console.log('    this/cls  = ' + args[1]);
                    for (var i = 0; i < declaredArgCount; i++) {
                        var a = args[2 + i];
                        console.log('    arg' + i + '      = ' + self._renderArg(a));
                        // Try to read it as a Java object. Casting through the
                        // Java bridge is far safer than decoding ART's object
                        // layout by hand, which differs across versions.
                        self._tryJava(a, '      ');
                    }
                },
                onLeave: function (retval) {
                    console.log('    return    = ' + self._renderArg(retval));
                    self._tryJava(retval, '      ');
                }
            });
            this._hooks.push(l);
            console.log('[+] hooked JNI ' + javaName + ' at ' + addr);
            return true;
        } catch (e) {
            console.log('[-] could not hook ' + javaName + ': ' + e.message);
            return false;
        }
    },

    _tryJava: function (p, indent) {
        if (p === null || p.isNull()) return;
        try {
            Java.perform(function () {
                try {
                    var s = Java.cast(p, Java.use('java.lang.String'));
                    console.log(indent + 'as String: "' + s.toString() + '"');
                    return;
                } catch (e) { /* not a String */ }
                try {
                    var b = Java.cast(p, Java.use('[B'));
                    console.log(indent + 'as byte[]: length ' + b.length);
                    return;
                } catch (e) { /* not a byte[] */ }
            });
        } catch (e) { /* not a Java object, or not on a VM thread */ }
    },

    _renderArg: function (p) {
        try {
            if (p === null || p.isNull()) return 'NULL';
            var i = p.toInt32();
            if (i > -0x10000 && i < 0x10000) {
                return String(i) + ' (0x' + (i >>> 0).toString(16) + ')';
            }
            var range = Process.findRangeByAddress(p);
            if (range === null) return p + ' <unmapped>';
            if (range.protection.indexOf('r') !== -1) {
                var s = null;
                try { s = p.readCString(80); } catch (e) { s = null; }
                if (s !== null && s.length > 0 && /^[\x20-\x7e]+$/.test(s)) {
                    return p + ' "' + s + '"';
                }
            }
            var mod = Process.findModuleByAddress(p);
            if (mod !== null) {
                var ghidra = (mod.name === (this._module && this._module.name))
                    ? '  = ghidra ' + this._imageBase.add(p.sub(mod.base))
                    : '';
                return p + ' <' + mod.name + '+0x' + p.sub(mod.base).toString(16) + '>' + ghidra;
            }
            return p + ' <' + range.protection + '>';
        } catch (e) {
            return '<unreadable>';
        }
    },

    /* ---------------------------------------------------------- reading */

    /* Hexdump at a GHIDRA address. */
    dump: function (ghidraAddr, length) {
        length = length || 128;
        var addr;
        try { addr = this.at(ghidraAddr); } catch (e) {
            console.log('[-] ' + e.message); return;
        }
        try {
            console.log(hexdump(addr, { length: length, ansi: false }));
        } catch (e) {
            console.log('[-] cannot read ' + addr + ': ' + e.message);
        }
    },

    /*
     * Decode a JNINativeMethod array at a Ghidra address. Use this when you
     * found the table statically and want to confirm it at runtime, or when
     * you want the CURRENT contents of a table that is patched at runtime.
     *
     *   struct JNINativeMethod {
     *       const char *name;
     *       const char *signature;
     *       void       *fnPtr;
     *   };
     */
    jniTable: function (ghidraAddr, count) {
        var base;
        try { base = this.at(ghidraAddr); } catch (e) {
            console.log('[-] ' + e.message); return [];
        }
        count = count || 8;
        var ps = Process.pointerSize;
        var out = [];

        console.log('');
        console.log('  JNINativeMethod array at ' + base + ':');
        for (var i = 0; i < count; i++) {
            var entry = base.add(i * ps * 3);
            var name, sig, fn;
            try {
                name = entry.readPointer().readCString();
                sig = entry.add(ps).readPointer().readCString();
                fn = entry.add(ps * 2).readPointer();
            } catch (e) {
                console.log('  [' + i + '] <unreadable - end of table?>');
                break;
            }
            if (name === null || fn === null || fn.isNull()) {
                console.log('  [' + i + '] <null - end of table>');
                break;
            }

            var mod = Process.findModuleByAddress(fn);
            var ghidraOfFn = (mod !== null && this._module !== null &&
                              mod.name === this._module.name)
                ? this._imageBase.add(fn.sub(mod.base))
                : null;

            console.log('  [' + i + '] ' + name + sig);
            console.log('       runtime ' + fn +
                        (ghidraOfFn ? '   ghidra ' + ghidraOfFn : ''));
            out.push({ name: name, sig: sig, runtime: fn.toString(),
                       ghidra: ghidraOfFn ? ghidraOfFn.toString() : null });
        }
        return out;
    },

    /* --------------------------------------------------------- calling */

    /*
     * Call a function you found in Ghidra, with arguments of your choosing.
     * This is how you turn a discovered routine into an oracle.
     *
     * A wrong type string here is a segmentation fault, not a type error.
     * exceptions:'propagate' converts most crashes into a JS exception so you
     * keep the session.
     */
    call: function (ghidraAddr, retType, argTypes, args) {
        var addr;
        try { addr = this.at(ghidraAddr); } catch (e) {
            console.log('[-] ' + e.message); return null;
        }
        try {
            var fn = new NativeFunction(addr, retType, argTypes,
                                        { exceptions: 'propagate' });
            var r = fn.apply(null, args || []);
            console.log('  -> ' + r);
            return r;
        } catch (e) {
            console.log('[-] call failed: ' + e.message);
            console.log('    Check the signature against the disassembly. Also check');
            console.log('    that you are on a VM-attached thread if the function');
            console.log('    touches JNI - wrap the call in Java.perform().');
            return null;
        }
    },

    /* ------------------------------------------------ dumping for Ghidra */

    /*
     * Dump the module's mapped image to a file, for re-import into Ghidra.
     *
     * WHY: if the library decrypts or patches itself at load time, the bytes on
     * disk are not the bytes that execute. Analysing the file is analysing the
     * wrong thing.
     *
     * WHEN YOU RE-IMPORT: set the image base to the RUNTIME base printed below,
     * not to 0x100000. Absolute pointers inside the dump refer to runtime
     * addresses, and they will only resolve if Ghidra loads the dump where the
     * process had it. This is the step people forget.
     */
    dumpModule: function (outPath) {
        if (this._module === null) { console.log('[-] call g.setup() first'); return; }
        var m = this._module;
        outPath = outPath || ('/data/local/tmp/' + m.name + '.dump');

        try {
            var f = new File(outPath, 'wb');
            var CHUNK = 0x10000;
            var written = 0;
            for (var off = 0; off < m.size; off += CHUNK) {
                var n = Math.min(CHUNK, m.size - off);
                var bytes;
                try {
                    bytes = m.base.add(off).readByteArray(n);
                } catch (e) {
                    // Unmapped or guard page inside the range: pad with zeros so
                    // that offsets in the dump still line up.
                    bytes = new ArrayBuffer(n);
                }
                if (bytes !== null) { f.write(bytes); written += n; }
            }
            f.flush();
            f.close();

            console.log('');
            console.log('[+] wrote ' + written + ' bytes to ' + outPath);
            console.log('');
            console.log('    adb pull ' + outPath);
            console.log('');
            console.log('    THEN, when importing into Ghidra:');
            console.log('      Format   : Raw Binary   (the ELF headers may be');
            console.log('                 patched, so the ELF loader can mislead)');
            console.log('      Language : ' + (Process.arch === 'arm64'
                        ? 'AARCH64:LE:64:v8A' : 'ARM:LE:32:v8'));
            console.log('      Base     : ' + m.base + '   <-- THE RUNTIME BASE');
            console.log('');
            console.log('    Using 0x100000 here will make every absolute pointer');
            console.log('    in the dump resolve to nothing. See ../README.md 7.4.');
            return outPath;
        } catch (e) {
            console.log('[-] dump failed: ' + e.message);
            console.log('    The app may not be able to write there. Try');
            console.log('    /data/data/<pkg>/files/ instead.');
            return null;
        }
    },

    /* ---------------------------------------------------------- control */

    stats: function () {
        var rows = Object.keys(this._counts).map(function (k) {
            return [k, this._counts[k]];
        }, this);
        rows.sort(function (a, b) { return b[1] - a[1]; });
        console.log('');
        console.log('  call counts:');
        rows.forEach(function (r) {
            console.log(('        ' + r[1]).slice(-8) + '  ' + r[0]);
        });
        return rows.length;
    },

    unhookAll: function () {
        var n = this._hooks.length;
        this._hooks.forEach(function (h) {
            try { h.detach(); } catch (e) { /* already gone */ }
        });
        this._hooks = [];
        console.log('[*] detached ' + n + ' hook(s)');
        return n;
    },

    modules: function (filter) {
        var re = filter ? new RegExp(filter) : null;
        Process.enumerateModules().forEach(function (m) {
            if (re !== null && !re.test(m.name)) return;
            console.log('  ' + m.base + '  0x' + m.size.toString(16).padStart(8, '0') +
                        '  ' + m.name);
        });
    },

    help: function () {
        console.log([
            '',
            'SETUP',
            '  g.setup("libnative.so" [, imageBase])   bind; default base 0x100000',
            '  g.waitFor("libnative.so" [, cb])        bind when it is dlopen\'d',
            '  g.info()                                bases, size, delta',
            '  g.modules([regex])                      list loaded modules',
            '',
            'ADDRESS CONVERSION',
            '  g.at(0x00103a10)      ghidra address -> runtime pointer',
            '  g.off(0x3a10)         raw offset     -> runtime pointer',
            '  g.rev("0x7b2c103a10") runtime address -> ghidra address',
            '',
            'HOOKING (arguments are GHIDRA addresses)',
            '  g.hook(0x00103a10, "label" [, argCount])',
            '  g.hookJni(0x00103a10, "decrypt" [, declaredArgs])',
            '  g.stats()             call counts',
            '  g.unhookAll()',
            '',
            'READING',
            '  g.dump(0x00102040, 96)          hexdump at a ghidra address',
            '  g.jniTable(0x00102040, 3)       decode a JNINativeMethod array',
            '',
            'CALLING',
            '  g.call(0x00103a10, "int", ["pointer","int"], [ptr(0), 5])',
            '',
            'DUMPING FOR RE-IMPORT',
            '  g.dumpModule("/data/local/tmp/x.dump")',
            '    -> import as Raw Binary at the RUNTIME base, not 0x100000',
            '',
            'THE ARITHMETIC:  runtime = module_base + (ghidra - image_base)',
            ''
        ].join('\n'));
    }
};

/* ---------------------------------------------------------- RPC surface */

rpc.exports = {
    init: function (stage, params) {
        console.log('[*] ghidra-to-frida bridge loaded (stage=' + stage + ')');
        if (params && params.module) {
            g.setup(params.module, params.imageBase);
        }
    },
    dispose: function () { g.unhookAll(); },
    setup: function (name, base) { return g.setup(name, base); },
    convert: function (ghidraAddr) { return g.at(ghidraAddr).toString(); },
    jniTable: function (addr, count) { return g.jniTable(addr, count); },
    read: function (ghidraAddr, length) {
        // ArrayBuffer returns travel as raw binary, not JSON.
        return g.at(ghidraAddr).readByteArray(length);
    }
};

/* --------------------------------------------------------------- bootstrap */

console.log('');
console.log('=== ghidra-to-frida bridge ===');
console.log('[*] pid=' + Process.id + ' arch=' + Process.arch);
console.log('[+] start with:  g.setup("libnative.so")');
console.log('    then:        g.help()');
console.log('');
