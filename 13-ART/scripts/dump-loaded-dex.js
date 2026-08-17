/*
 * dump-loaded-dex.js — capture DEX that is loaded dynamically at runtime.
 *
 * WHAT IT DOES
 *   Hooks every mechanism an Android app can use to load DEX bytecode that is
 *   not part of the APK's own classes*.dex, and writes each payload to disk.
 *
 *   Covers:
 *     - InMemoryDexClassLoader(ByteBuffer,   ClassLoader)
 *     - InMemoryDexClassLoader(ByteBuffer[], ClassLoader)
 *     - DexClassLoader(String, String, String, ClassLoader)
 *     - PathClassLoader(String, ClassLoader)
 *     - BaseDexClassLoader(String, File, String, ClassLoader)
 *     - DexFile.loadDex / DexFile.<init>            (legacy)
 *     - dalvik.system.DexFile.openDexFile*          (legacy, reflective)
 *   plus a raw memory sweep for the DEX magic as a fallback.
 *
 *   This is the primary technique for unpacking packed applications: a packer's
 *   stub Application class decrypts the real DEX and hands it to a ClassLoader,
 *   so the payload exists only in memory. Hook the handover and you have it.
 *
 *   See ../README.md section 3 and ../../40-Obfuscation/README.md.
 *
 * HOW TO RUN
 *   frida -U -f com.example.target -l dump-loaded-dex.js
 *
 *   Use -f (spawn), NOT -n (attach). Packers load their payload during
 *   Application.attachBaseContext, long before you could attach manually.
 *
 *   Then from the REPL:
 *     dex.sweep()        scan process memory for DEX magic (fallback)
 *     dex.stats()        show what has been captured
 *
 *   Retrieve the results:
 *     adb shell "su -c 'ls -la /data/local/tmp/dexdump'"
 *     adb pull /data/local/tmp/dexdump
 *     jadx -d out /path/to/dexdump/*.dex
 *
 * NOTE ON OUTPUT DIRECTORY
 *   Defaults to the app's own cache directory, which always exists and is
 *   always writable. Override with dex.setOutDir("/data/local/tmp/dexdump").
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var dex = {
    outDir: null,
    counter: 0,
    seen: {},          // sha-ish key -> filename, to avoid duplicate dumps
    captured: [],

    setOutDir: function (p) {
        this.outDir = p;
        console.log('[*] Output directory set to ' + p);
    },

    _ensureOutDir: function () {
        if (this.outDir !== null) return this.outDir;
        try {
            var ctx = Java.use('android.app.ActivityThread')
                          .currentApplication().getApplicationContext();
            this.outDir = ctx.getCacheDir().getAbsolutePath() + '/dexdump';
            var File = Java.use('java.io.File');
            var f = File.$new(this.outDir);
            if (!f.exists()) f.mkdirs();
        } catch (e) {
            this.outDir = '/data/local/tmp/dexdump';
        }
        console.log('[*] Dumping to ' + this.outDir);
        return this.outDir;
    },

    /* Cheap fingerprint so we do not write the same payload twice. */
    _fingerprint: function (bytes, len) {
        var acc = len;
        var step = Math.max(1, Math.floor(len / 64));
        for (var i = 0; i < len; i += step) {
            acc = ((acc * 31) ^ (bytes[i] & 0xff)) | 0;
        }
        return len + ':' + (acc >>> 0).toString(16);
    },

    _writeBytes: function (byteArray, len, tag) {
        var dir = this._ensureOutDir();
        var fp = this._fingerprint(byteArray, Math.min(len, 4096));
        if (this.seen[fp] !== undefined) {
            console.log('[=] Duplicate payload (' + tag + '), already saved as ' + this.seen[fp]);
            return null;
        }

        var name = dir + '/dump_' + (this.counter++) + '_' + tag + '.dex';
        try {
            var FOS = Java.use('java.io.FileOutputStream');
            var fos = FOS.$new(name);
            fos.write(byteArray);
            fos.flush();
            fos.close();

            this.seen[fp] = name;
            this.captured.push({ path: name, size: len, source: tag });
            console.log('[+] Wrote ' + len + ' bytes -> ' + name);
            return name;
        } catch (e) {
            console.log('[-] Write failed (' + name + '): ' + e);
            return null;
        }
    },

    _dumpByteBuffer: function (buf, tag) {
        try {
            var remaining = buf.remaining();
            if (remaining <= 0) { console.log('[-] Empty ByteBuffer'); return; }

            var JavaArray = Java.use('java.util.Arrays');   // force class init
            var bytes = Java.array('byte', new Array(remaining).fill(0));

            // Preserve the buffer's position — the app still needs it.
            var pos = buf.position();
            buf.get(bytes);
            buf.position(pos);

            this._verifyAndWrite(bytes, remaining, tag);
        } catch (e) {
            console.log('[-] ByteBuffer dump failed: ' + e);
        }
    },

    _dumpFile: function (path, tag) {
        try {
            var File = Java.use('java.io.File');
            var f = File.$new(path);
            if (!f.exists()) { console.log('[-] Not found: ' + path); return; }

            var FIS = Java.use('java.io.FileInputStream');
            var fis = FIS.$new(f);
            var len = f.length();
            var bytes = Java.array('byte', new Array(len).fill(0));
            fis.read(bytes);
            fis.close();

            this._verifyAndWrite(bytes, len, tag);
        } catch (e) {
            console.log('[-] File dump failed (' + path + '): ' + e);
        }
    },

    _verifyAndWrite: function (bytes, len, tag) {
        // DEX magic is "dex\n035\0" (or 037/038/039/040 depending on version).
        // An APK/JAR starts "PK\x03\x04" — also worth keeping.
        var isDex = len > 8 &&
                    (bytes[0] & 0xff) === 0x64 && (bytes[1] & 0xff) === 0x65 &&
                    (bytes[2] & 0xff) === 0x78 && (bytes[3] & 0xff) === 0x0a;
        var isZip = len > 4 &&
                    (bytes[0] & 0xff) === 0x50 && (bytes[1] & 0xff) === 0x4b;

        if (isDex) {
            var ver = String.fromCharCode(bytes[4] & 0xff, bytes[5] & 0xff, bytes[6] & 0xff);
            console.log('[*] Valid DEX, version ' + ver + ', ' + len + ' bytes');
        } else if (isZip) {
            console.log('[*] ZIP/APK container, ' + len + ' bytes');
            tag = tag + '_zip';
        } else {
            console.log('[!] Payload does not start with DEX or ZIP magic — ' +
                        'saving anyway (may be encrypted)');
            tag = tag + '_unknown';
        }

        this._writeBytes(bytes, len, tag);
    },

    /* ------------------------------------------------------------- hooks */

    installHooks: function () {
        var self = this;

        /* --- InMemoryDexClassLoader (the packer favourite) --- */
        try {
            var IMDCL = Java.use('dalvik.system.InMemoryDexClassLoader');

            IMDCL.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
                .implementation = function (buf, parent) {
                    console.log('\n[HOOK] InMemoryDexClassLoader(ByteBuffer, ClassLoader)');
                    self._dumpByteBuffer(buf, 'inmemory');
                    return this.$init(buf, parent);
                };

            if (IMDCL.$init.overload('[Ljava.nio.ByteBuffer;', 'java.lang.ClassLoader')) {
                IMDCL.$init.overload('[Ljava.nio.ByteBuffer;', 'java.lang.ClassLoader')
                    .implementation = function (bufs, parent) {
                        console.log('\n[HOOK] InMemoryDexClassLoader(ByteBuffer[], ClassLoader)');
                        for (var i = 0; i < bufs.length; i++) {
                            self._dumpByteBuffer(bufs[i], 'inmemory_' + i);
                        }
                        return this.$init(bufs, parent);
                    };
            }
            console.log('[+] Hooked InMemoryDexClassLoader');
        } catch (e) {
            console.log('[-] InMemoryDexClassLoader unavailable: ' + e);
        }

        /* --- DexClassLoader --- */
        try {
            var DCL = Java.use('dalvik.system.DexClassLoader');
            DCL.$init.overload('java.lang.String', 'java.lang.String',
                               'java.lang.String', 'java.lang.ClassLoader')
                .implementation = function (dexPath, optDir, libPath, parent) {
                    console.log('\n[HOOK] DexClassLoader');
                    console.log('       dexPath = ' + dexPath);
                    console.log('       optDir  = ' + optDir);
                    self._dumpFile(dexPath, 'dexclassloader');
                    return this.$init(dexPath, optDir, libPath, parent);
                };
            console.log('[+] Hooked DexClassLoader');
        } catch (e) {
            console.log('[-] DexClassLoader unavailable: ' + e);
        }

        /* --- PathClassLoader --- */
        try {
            var PCL = Java.use('dalvik.system.PathClassLoader');
            PCL.$init.overload('java.lang.String', 'java.lang.ClassLoader')
                .implementation = function (dexPath, parent) {
                    console.log('\n[HOOK] PathClassLoader: ' + dexPath);
                    // Usually the app's own APK — only dump unexpected paths.
                    if (dexPath && dexPath.indexOf('/data/app/') !== 0) {
                        self._dumpFile(dexPath, 'pathclassloader');
                    }
                    return this.$init(dexPath, parent);
                };
            console.log('[+] Hooked PathClassLoader');
        } catch (e) {
            console.log('[-] PathClassLoader unavailable: ' + e);
        }

        /* --- BaseDexClassLoader (catches subclasses generically) --- */
        try {
            var BDCL = Java.use('dalvik.system.BaseDexClassLoader');
            BDCL.$init.overload('java.lang.String', 'java.io.File',
                                'java.lang.String', 'java.lang.ClassLoader')
                .implementation = function (dexPath, optDir, libPath, parent) {
                    console.log('\n[HOOK] BaseDexClassLoader: ' + dexPath);
                    if (dexPath && dexPath.indexOf('/data/app/') !== 0) {
                        self._dumpFile(dexPath, 'basedex');
                    }
                    return this.$init(dexPath, optDir, libPath, parent);
                };
            console.log('[+] Hooked BaseDexClassLoader');
        } catch (e) {
            console.log('[-] BaseDexClassLoader unavailable: ' + e);
        }

        /* --- DexFile (legacy but still seen) --- */
        try {
            var DexFile = Java.use('dalvik.system.DexFile');
            DexFile.loadDex.overload('java.lang.String', 'java.lang.String', 'int')
                .implementation = function (src, out, flags) {
                    console.log('\n[HOOK] DexFile.loadDex: ' + src);
                    self._dumpFile(src, 'dexfile_loaddex');
                    return this.loadDex(src, out, flags);
                };
            console.log('[+] Hooked DexFile.loadDex');
        } catch (e) {
            console.log('[-] DexFile.loadDex unavailable: ' + e);
        }

        /* --- Observability: what classes are actually being loaded --- */
        try {
            var CL = Java.use('java.lang.ClassLoader');
            CL.loadClass.overload('java.lang.String').implementation = function (name) {
                var loaderName = this.$className;
                // Only log loads from non-standard loaders; the default ones
                // are far too noisy to be useful.
                if (loaderName.indexOf('InMemory') !== -1 ||
                    loaderName.indexOf('DexClassLoader') !== -1) {
                    console.log('[load] ' + loaderName + ' -> ' + name);
                }
                return this.loadClass(name);
            };
            console.log('[+] Hooked ClassLoader.loadClass (filtered)');
        } catch (e) { /* non-fatal */ }
    },

    /* ---------------------------------------------------- memory fallback */

    /*
     * Scan readable process memory for the DEX magic and dump anything that
     * looks like a complete DEX header. Use this when the app loads DEX by a
     * route the hooks above do not cover, or when it decrypts in native code.
     */
    sweep: function () {
        var self = this;
        var dir = this._ensureOutDir();
        console.log('[*] Sweeping process memory for DEX magic...');

        var pattern = '64 65 78 0a';   // "dex\n"
        var hits = 0;

        Process.enumerateRanges('r--').forEach(function (range) {
            // Skip enormous file-backed ranges; the APK is already on disk.
            if (range.file && range.file.path.indexOf('.apk') !== -1) return;
            if (range.size > 256 * 1024 * 1024) return;

            try {
                Memory.scanSync(range.base, range.size, pattern).forEach(function (m) {
                    try {
                        // DEX header: magic(8) checksum(4) sig(20) file_size(4)@0x20
                        var fileSize = m.address.add(0x20).readU32();
                        if (fileSize < 0x70 || fileSize > 64 * 1024 * 1024) return;

                        // header_size must be 0x70 for a real DEX.
                        var headerSize = m.address.add(0x24).readU32();
                        if (headerSize !== 0x70) return;

                        var bytes = m.address.readByteArray(fileSize);
                        if (bytes === null) return;

                        var name = dir + '/sweep_' + (self.counter++) + '_' +
                                   m.address + '.dex';
                        var f = new File(name, 'wb');
                        f.write(bytes);
                        f.close();

                        console.log('[+] Swept ' + fileSize + ' bytes @ ' +
                                    m.address + ' -> ' + name);
                        self.captured.push({ path: name, size: fileSize, source: 'sweep' });
                        hits++;
                    } catch (e) { /* not a valid DEX here */ }
                });
            } catch (e) { /* range vanished mid-scan */ }
        });

        console.log('[*] Sweep complete: ' + hits + ' candidate DEX file(s)');
    },

    stats: function () {
        console.log('\n[*] Captured ' + this.captured.length + ' payload(s):');
        this.captured.forEach(function (c) {
            console.log('    ' + c.size + ' bytes  [' + c.source + ']  ' + c.path);
        });
        if (this.captured.length > 0) {
            console.log('\n    Retrieve with:');
            console.log('      adb pull ' + this.outDir);
            console.log('      jadx -d out ' + this.outDir + '/*.dex');
        }
        console.log('');
    },

    help: function () {
        console.log([
            '',
            'dex.sweep()             scan process memory for DEX magic',
            'dex.stats()             list captured payloads',
            'dex.setOutDir(path)     change the output directory',
            ''
        ].join('\n'));
    }
};

/* --------------------------------------------------------------- bootstrap */

Java.perform(function () {
    console.log('');
    console.log('=== dump-loaded-dex ===');
    dex._ensureOutDir();
    dex.installHooks();
    console.log('[+] Ready. Exercise the app, then run dex.stats().');
    console.log('    If nothing is captured, try dex.sweep().');
    console.log('');
});
