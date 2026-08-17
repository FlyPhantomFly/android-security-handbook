/*
 * dump-module.js — dump a loaded native library from memory for Ghidra import.
 *
 * WHAT IT DOES
 *   Waits until a shared library is loaded and (crucially) has finished any
 *   self-decryption, then writes its memory ranges to disk so you can load the
 *   *decrypted* code into Ghidra.
 *
 * WHY YOU NEED THIS
 *   A packed or self-modifying .so is useless on disk: the bytes in the APK are
 *   encrypted, and the code you want only exists after the loader has run. The
 *   on-disk file will decompile to garbage, or refuse to load at all.
 *
 *   Once the library is mapped and initialised, the plaintext is sitting in the
 *   process's address space. Dump it from there.
 *
 *   See ../README.md section 6.5, and ../../40-Obfuscation/README.md for the
 *   packer landscape this defends against.
 *
 * IMPORTANT — the dump is NOT a valid ELF
 *   Section headers may be inconsistent, and relocations have already been
 *   applied by the linker. Ghidra will not auto-analyse it as an ELF. Load it
 *   as a RAW BINARY at the base address this script prints, choose AArch64 as
 *   the language, and analyse from there. Section 6.5 of the chapter walks
 *   through the import dialog.
 *
 * HOW TO RUN
 *   # attach AFTER the library has loaded and decrypted
 *   frida -U -n com.example.target -l dump-module.js
 *
 *   # or spawn and wait for the load, which is safer for packers that
 *   # decrypt during Application.attachBaseContext
 *   frida -U -f com.example.target -l dump-module.js
 *
 *   Then from the REPL:
 *     dump.list()                      list loaded modules
 *     dump.module("libnative.so")      dump one module
 *     dump.waitFor("libnative.so")     hook dlopen and dump as soon as it loads
 *     dump.range("0x7b40000000", 0x20000)   dump an arbitrary range
 *     dump.anonExec()                  dump executable anonymous memory (JIT/packed)
 *
 *   Retrieve:
 *     adb pull /data/local/tmp/dumps/
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var dump = {

    outDir: '/data/local/tmp/dumps',

    /* ---------------------------------------------------------------- util */

    _ensureDir: function () {
        // File() will fail if the directory does not exist, and Frida has no
        // mkdir. Fall back to the app's own cache dir, which always exists.
        try {
            var probe = new File(this.outDir + '/.probe', 'wb');
            probe.write('x');
            probe.close();
            return this.outDir;
        } catch (e) {
            try {
                var ctx = Java.use('android.app.ActivityThread')
                              .currentApplication().getApplicationContext();
                this.outDir = ctx.getCacheDir().getAbsolutePath() + '/dumps';
                var File_ = Java.use('java.io.File');
                File_.$new(this.outDir).mkdirs();
                console.log('[*] /data/local/tmp not writable; using ' + this.outDir);
            } catch (e2) {
                console.log('[-] Could not establish an output directory: ' + e2);
            }
            return this.outDir;
        }
    },

    setOutDir: function (p) {
        this.outDir = p;
        console.log('[*] Output directory set to ' + p);
    },

    _hex: function (n) { return '0x' + n.toString(16); },

    /* ---------------------------------------------------------------- list */

    list: function (filter) {
        var mods = Process.enumerateModules();
        console.log('\n[*] ' + mods.length + ' loaded module(s)' +
                    (filter ? ' matching "' + filter + '"' : ''));
        mods.forEach(function (m) {
            if (filter && m.name.toLowerCase().indexOf(filter.toLowerCase()) === -1) return;
            console.log('    ' + m.base + '  ' + ('' + m.size).padStart(10) +
                        '  ' + m.name);
            console.log('        ' + m.path);
        });
        console.log('');
    },

    /* -------------------------------------------------------------- module */

    /*
     * Dump a module by walking its mapped ranges rather than doing one giant
     * read. A module's mapping is not necessarily contiguous or uniformly
     * readable, and a single readByteArray across a guard page throws.
     */
    module: function (name) {
        var self = this;
        var m = Process.findModuleByName(name);
        if (m === null) {
            console.log('[-] Module not loaded: ' + name);
            console.log('    Use dump.list() to see what is loaded, or');
            console.log('    dump.waitFor("' + name + '") to catch it at load time.');
            return null;
        }

        var dir = this._ensureDir();
        var out = dir + '/' + name + '_' + m.base + '.dump';

        console.log('\n[*] Dumping ' + name);
        console.log('    base : ' + m.base);
        console.log('    size : ' + m.size + ' (' + this._hex(m.size) + ')');
        console.log('    path : ' + m.path);

        // Collect the ranges that actually belong to this module.
        var ranges = Process.enumerateRanges('r--').filter(function (r) {
            return r.base.compare(m.base) >= 0 &&
                   r.base.compare(m.base.add(m.size)) < 0;
        });

        if (ranges.length === 0) {
            console.log('[-] No readable ranges found inside the module.');
            return null;
        }

        console.log('    ranges: ' + ranges.length);

        var f;
        try {
            f = new File(out, 'wb');
        } catch (e) {
            console.log('[-] Cannot open output file ' + out + ': ' + e);
            return null;
        }

        var written = 0;
        var gaps = 0;
        var cursor = m.base;

        ranges.sort(function (a, b) { return a.base.compare(b.base); });

        ranges.forEach(function (r) {
            // Pad any hole so file offsets still line up with virtual addresses.
            // This is what makes the raw-binary import in Ghidra usable.
            if (r.base.compare(cursor) > 0) {
                var gap = r.base.sub(cursor).toInt32();
                if (gap > 0 && gap < 0x1000000) {
                    f.write(new Uint8Array(gap));
                    written += gap;
                    gaps += gap;
                }
            }
            try {
                var bytes = r.base.readByteArray(r.size);
                if (bytes !== null) {
                    f.write(bytes);
                    written += r.size;
                }
            } catch (e) {
                // Unreadable page — pad it so offsets stay aligned.
                f.write(new Uint8Array(r.size));
                written += r.size;
                console.log('    [!] unreadable at ' + r.base + ' (' + r.size + ' bytes) — padded');
            }
            cursor = r.base.add(r.size);
        });

        f.flush();
        f.close();

        console.log('[+] Wrote ' + written + ' bytes to ' + out);
        if (gaps > 0) {
            console.log('    (' + gaps + ' bytes of zero padding to preserve offsets)');
        }

        this._importInstructions(out, m.base, name);
        return out;
    },

    /* ------------------------------------------------------------- waitFor */

    /*
     * Hook dlopen so you catch a library the moment it is mapped. Use this for
     * packers that load and decrypt during Application.attachBaseContext —
     * by the time you could attach manually, it is already done.
     *
     * Run with `frida -U -f <pkg>` so the hook is installed before any app code.
     */
    waitFor: function (name, delayMs) {
        var self = this;
        delayMs = delayMs === undefined ? 300 : delayMs;
        var done = false;

        ['dlopen', 'android_dlopen_ext'].forEach(function (sym) {
            var addr = Module.findExportByName(null, sym);
            if (addr === null) return;

            Interceptor.attach(addr, {
                onEnter: function (args) {
                    try {
                        this.path = args[0].isNull() ? null : args[0].readCString();
                    } catch (e) { this.path = null; }
                },
                onLeave: function (retval) {
                    if (done || this.path === null) return;
                    if (this.path.indexOf(name) === -1) return;

                    console.log('\n[!] ' + sym + '("' + this.path + '") returned ' + retval);
                    console.log('    Waiting ' + delayMs + 'ms for initialisation to finish...');

                    // JNI_OnLoad and .init_array run after dlopen returns, and
                    // that is usually where decryption happens. Dumping
                    // immediately gets you the still-encrypted image.
                    setTimeout(function () {
                        if (done) return;
                        done = true;
                        self.module(name);
                    }, delayMs);
                }
            });
            console.log('[+] Watching ' + sym + ' for "' + name + '"');
        });

        // It may already be loaded.
        if (Process.findModuleByName(name) !== null) {
            console.log('[*] ' + name + ' is already loaded — dumping now.');
            done = true;
            this.module(name);
        }
    },

    /* --------------------------------------------------------------- range */

    range: function (addr, size, label) {
        var dir = this._ensureDir();
        var base = ptr(addr);
        var out = dir + '/' + (label || 'range') + '_' + base + '.dump';

        try {
            var bytes = base.readByteArray(size);
            if (bytes === null) { console.log('[-] Read returned null'); return null; }
            var f = new File(out, 'wb');
            f.write(bytes);
            f.flush();
            f.close();
            console.log('[+] Wrote ' + size + ' bytes from ' + base + ' to ' + out);
            this._importInstructions(out, base, label || 'range');
            return out;
        } catch (e) {
            console.log('[-] Failed: ' + e);
            return null;
        }
    },

    /* ------------------------------------------------------------ anonExec */

    /*
     * Dump executable ANONYMOUS memory — not backed by any file.
     *
     * Two very different things live here:
     *   - the ART JIT code cache, which is legitimate and present in every app
     *   - code a packer wrote at runtime, which is what you are looking for
     *
     * The JIT cache is usually large and often labelled; a packer's payload is
     * typically a smaller region appearing shortly after a dlopen. Dump both
     * and triage afterwards.
     */
    anonExec: function (minSize) {
        var self = this;
        minSize = minSize || 0x1000;
        var dir = this._ensureDir();
        var found = 0;

        Process.enumerateRanges('r-x').forEach(function (r) {
            if (r.file !== undefined && r.file !== null) return;   // file-backed
            if (r.size < minSize) return;

            var label = 'anon';
            // Frida exposes the mapping name on some platforms.
            if (r.file && r.file.path) label = r.file.path.replace(/[\/:]/g, '_');

            var out = dir + '/anonexec_' + r.base + '_' + r.size + '.dump';
            try {
                var bytes = r.base.readByteArray(r.size);
                if (bytes === null) return;
                var f = new File(out, 'wb');
                f.write(bytes);
                f.flush();
                f.close();
                console.log('[+] ' + r.base + '  ' + ('' + r.size).padStart(9) +
                            '  ' + r.protection + '  -> ' + out);

                // Cheap triage: does it start with ELF or DEX magic?
                var magic = r.base.readByteArray(8);
                var u8 = new Uint8Array(magic);
                if (u8[0] === 0x7f && u8[1] === 0x45 && u8[2] === 0x4c && u8[3] === 0x46) {
                    console.log('    ^^ ELF magic — a whole library was mapped here');
                } else if (u8[0] === 0x64 && u8[1] === 0x65 && u8[2] === 0x78 && u8[3] === 0x0a) {
                    console.log('    ^^ DEX magic — see ../../12-DEX-Internals/');
                }
                found++;
            } catch (e) { /* range vanished */ }
        });

        console.log('\n[*] Dumped ' + found + ' executable anonymous range(s)');
        if (found > 0) {
            console.log('    NOTE: the ART JIT code cache is legitimately executable and');
            console.log('    anonymous. Not every hit here is a packer. See');
            console.log('    ../../13-ART/README.md section 3.14.');
        }
    },

    /* ------------------------------------------------------- import advice */

    _importInstructions: function (path, base, name) {
        console.log('');
        console.log('    --- Ghidra import ---');
        console.log('    1. adb pull ' + path);
        console.log('    2. File > Import File, select the dump');
        console.log('    3. Format:   Raw Binary        <- NOT "ELF"');
        console.log('    4. Language: AArch64:LE:64:v8A (or match the target ABI)');
        console.log('    5. Options > Base Address: ' + base);
        console.log('       ^ this is essential. Without it every pointer and');
        console.log('         cross-reference in the dump resolves to nonsense.');
        console.log('    6. Analyse. Expect no symbols — the dump has no symbol table.');
        console.log('       Recover JNI entry points with scripts/FindJNI.py and');
        console.log('       scripts/RecoverRegisterNatives.py.');
        console.log('');
    },

    help: function () {
        console.log([
            '',
            'dump.list([filter])            list loaded modules',
            'dump.module(name)              dump a loaded module',
            'dump.waitFor(name [, ms])      hook dlopen, dump once loaded+initialised',
            'dump.range(addr, size [, tag]) dump an arbitrary range',
            'dump.anonExec([minSize])       dump executable anonymous memory',
            'dump.setOutDir(path)           change the output directory',
            '',
            'Dumps are RAW BINARY, not valid ELF. Import at the printed base address.',
            ''
        ].join('\n'));
    }
};

/* --------------------------------------------------------------- bootstrap */

console.log('');
console.log('=== dump-module ===');
console.log('[*] arch=' + Process.arch + '  pointerSize=' + Process.pointerSize);
dump._ensureDir();
console.log('[*] output: ' + dump.outDir);
console.log('[+] Ready. Type dump.help().');
console.log('    For a packed library, prefer: frida -U -f <pkg> -l dump-module.js');
console.log('    then dump.waitFor("libtarget.so")');
console.log('');
