/*
 * frida-classloader-dump.js
 * ---------------------------------------------------------------------------
 * WHAT IT DOES
 *   Catches a packer in the act of handing the real DEX to the runtime, and
 *   writes that DEX to disk.
 *
 *   It hooks every constructor by which DEX bytecode can enter ART:
 *     - dalvik.system.InMemoryDexClassLoader(ByteBuffer,   ClassLoader)
 *     - dalvik.system.InMemoryDexClassLoader(ByteBuffer[], ClassLoader)
 *     - dalvik.system.DexClassLoader(String, String, String, ClassLoader)
 *     - dalvik.system.PathClassLoader(String[, String], ClassLoader)
 *     - dalvik.system.BaseDexClassLoader(String, File, String, ClassLoader)
 *     - dalvik.system.DexFile.<init> / DexFile.loadDex          (legacy)
 *
 *   ...and, because a packed app's unpacking is a SEQUENCE and not a single
 *   event, it also instruments the moments around it so you can see the whole
 *   thing happen and know exactly where your timing went wrong when nothing is
 *   captured:
 *     - Application.attachBaseContext          (the packer's entry point)
 *     - System.loadLibrary / System.load       (the native runtime arriving)
 *     - android_dlopen_ext                     (.init_array anti-debug moment)
 *     - ptrace                                 (the commonest anti-debug)
 *     - LoadedApk.mClassLoader replacement     (the ClassLoader swap)
 *     - BaseDexClassLoader.findClass           (real classes appearing)
 *
 * RELATIONSHIP TO ../../13-ART/scripts/dump-loaded-dex.js
 *   That script is the HARDENED, general-purpose version: same loader hooks
 *   plus a raw memory-sweep fallback, written for the ART chapter's "capture
 *   dynamically loaded DEX" problem in general.
 *
 *   THIS script is the packer-unpacking WORKFLOW: it is built around the
 *   runtime sequence in chapter 40 section 3.7.1, it narrates that sequence as
 *   it happens, and it tells you which step failed when you come away
 *   empty-handed. Use it when the question is "how do I unpack this app";
 *   use the ART one when the question is "what DEX did this process load".
 *
 *   Neither one duplicates the memory sweep of frida-dexdump-lite.js in this
 *   directory, which is the fallback for when the DEX never passes through a
 *   Java constructor at all — some packers build it entirely in native code.
 *
 * WHY IT MATTERS
 *   A packer replaces the app's real classes.dex with an encrypted blob plus a
 *   small stub, and rewrites <application android:name> to point at the stub.
 *   The stub's attachBaseContext loads a native library, that library decrypts
 *   the real DEX, and the result is handed to a ClassLoader.
 *
 *   The consequence is the whole game, and chapter 40 section 3.7.3 states it
 *   as a mental model worth memorising:
 *
 *     UNPACKING IS NOT CODE-BREAKING. IT IS TIMING.
 *
 *   The plaintext DEX must exist, in the process, in a form ART accepts, or
 *   the app cannot run. You do not need the key, the algorithm, or the
 *   vendor's name. You need to be inside the process at the moment of
 *   handover with somewhere to write the bytes. This script is that.
 *
 * HOW TO RUN
 *   # host — SPAWN PAUSED. This is not optional for a packer.
 *   # Everything above happens inside attachBaseContext, which completes in
 *   # milliseconds. `frida -U -n pkg` (attach) is always too late; even
 *   # `-f` without --pause loses the race against a fast packer.
 *   frida -U -f com.target.app -l frida-classloader-dump.js --pause
 *   # in the REPL, once you see "hooks installed":
 *   #   %resume
 *
 *   # then:
 *   cld.status()          what was hooked, what fired, what was captured
 *   cld.timeline()        the unpacking sequence, in the order it happened
 *   cld.loaders()         every ClassLoader — did unpacking actually happen?
 *
 *   # retrieve and decompile:
 *   adb shell "su -c 'ls -la /data/local/tmp/dexdump'"
 *   adb pull /data/local/tmp/dexdump
 *   jadx -d out /path/to/dexdump/*.dex
 *
 * REQUIREMENTS
 *   frida-server matching your client, running as root on the device.
 *
 * WHEN THIS SCRIPT CAPTURES NOTHING
 *   Run cld.timeline() first — it tells you how far the sequence got.
 *     - No attachBaseContext line     -> you resumed before hooks installed,
 *                                        or the app is not packed at all.
 *     - loadLibrary but no loader     -> the DEX is built in native code and
 *                                        never passes a Java constructor.
 *                                        Use frida-dexdump-lite.js.
 *     - Process died during resume    -> .init_array anti-debug. Enable
 *                                        cld.cfg.neutralisePtrace and retry.
 *     - Loader fired, payload not DEX -> the packer decrypts lazily, per class
 *                                        or per method. See section 3.7.3's
 *                                        note on method-level protection.
 *
 * AUTHORISED TESTING ONLY.
 * ---------------------------------------------------------------------------
 */

'use strict';

var cld = {

    cfg: {
        // Where to write dumps. Falls back to the app's cache dir, which
        // always exists and is always writable by the app itself.
        outDir: null,

        // Dump PathClassLoader/BaseDexClassLoader payloads whose path is the
        // app's own APK. Normally noise — the base APK is already on disk —
        // but occasionally a packer loads a second, patched copy of it.
        dumpOwnApk: false,

        // Neutralise ptrace(PTRACE_TRACEME). Off by default: it breaks apps
        // that use ptrace legitimately, and blindly replacing it is how you
        // end up debugging your own script. Turn it on when the process dies
        // on resume.
        neutralisePtrace: false,

        // Log every class the app resolves. Very noisy, but it is the fastest
        // way to confirm that unpacking worked: real class names appear.
        logFindClass: false,

        // Maximum payload we will write, as a sanity guard.
        maxBytes: 256 * 1024 * 1024
    },

    counter: 0,
    captured: [],
    events: [],
    seen: {},
    hooks: { ok: [], failed: [] },

    // ------------------------------------------------------------- utilities

    _t: function () {
        if (this._t0 === undefined) this._t0 = Date.now();
        return ('    +' + (Date.now() - this._t0) + 'ms').slice(-9);
    },

    _event: function (tag, detail) {
        var line = this._t() + '  ' + tag + '  ' + (detail || '');
        this.events.push(line);
        console.log(line);
    },

    _outDir: function () {
        if (this.cfg.outDir !== null) return this.cfg.outDir;
        try {
            var ctx = Java.use('android.app.ActivityThread')
                          .currentApplication().getApplicationContext();
            this.cfg.outDir = ctx.getCacheDir().getAbsolutePath() + '/dexdump';
        } catch (e) {
            // currentApplication() is null this early in a packed app's life,
            // which is entirely expected — we are running inside
            // attachBaseContext, before the Application exists.
            this.cfg.outDir = '/data/local/tmp/dexdump';
        }
        try {
            var File = Java.use('java.io.File');
            var d = File.$new(this.cfg.outDir);
            if (!d.exists()) d.mkdirs();
        } catch (e) { }
        return this.cfg.outDir;
    },

    /* Cheap content fingerprint, so the same payload is not written twice when
       a packer creates several loaders over identical bytes. */
    _fingerprint: function (bytes, len) {
        var acc = len | 0;
        var step = Math.max(1, Math.floor(len / 64));
        for (var i = 0; i < len; i += step) {
            acc = ((acc * 31) ^ (bytes[i] & 0xff)) | 0;
        }
        return len + ':' + (acc >>> 0).toString(16);
    },

    /*
     * Validate before writing, and SAY what we found. A payload that is not a
     * DEX is still worth keeping — an encrypted blob tells you the decryption
     * happens later, which is itself the finding that redirects your approach.
     */
    _classify: function (bytes, len) {
        if (len < 8) return { kind: 'tiny', note: 'too short to classify' };

        var b0 = bytes[0] & 0xff, b1 = bytes[1] & 0xff,
            b2 = bytes[2] & 0xff, b3 = bytes[3] & 0xff;

        // "dex\n" then three version digits then NUL.
        if (b0 === 0x64 && b1 === 0x65 && b2 === 0x78 && b3 === 0x0a) {
            var ver = String.fromCharCode(bytes[4] & 0xff,
                                          bytes[5] & 0xff,
                                          bytes[6] & 0xff);
            return { kind: 'dex', note: 'DEX version ' + ver };
        }
        // "PK\x03\x04" — an APK or JAR containing DEX.
        if (b0 === 0x50 && b1 === 0x4b) {
            return { kind: 'zip', note: 'ZIP/APK container' };
        }
        // "\x7fELF" — a .so handed to a loader is unusual and interesting.
        if (b0 === 0x7f && b1 === 0x45 && b2 === 0x4c && b3 === 0x46) {
            return { kind: 'elf', note: 'ELF — not DEX; note this' };
        }
        // "cdex" — CompactDex, ART's internal form. jadx will not read it;
        // extract with oatdump or convert. See ../../13-ART/README.md.
        if (b0 === 0x63 && b1 === 0x64 && b2 === 0x65 && b3 === 0x78) {
            return { kind: 'cdex', note: 'CompactDex — use oatdump to extract' };
        }
        return { kind: 'unknown', note: 'no known magic — probably still encrypted' };
    },

    _write: function (byteArray, len, tag) {
        if (len <= 0) { console.log('[-] empty payload (' + tag + ')'); return null; }
        if (len > this.cfg.maxBytes) {
            console.log('[-] payload too large (' + len + '), refusing (' + tag + ')');
            return null;
        }

        var fp = this._fingerprint(byteArray, Math.min(len, 8192));
        if (this.seen[fp] !== undefined) {
            console.log('[=] duplicate payload (' + tag + '), already at ' + this.seen[fp]);
            return null;
        }

        var cls = this._classify(byteArray, len);
        var dir = this._outDir();
        var name = dir + '/' + (this.counter++) + '_' + tag + '.' +
                   (cls.kind === 'dex' ? 'dex' : cls.kind);

        try {
            var FOS = Java.use('java.io.FileOutputStream');
            var fos = FOS.$new(name);
            fos.write(byteArray);
            fos.flush();
            fos.close();
        } catch (e) {
            console.log('[-] write failed (' + name + '): ' + e);
            console.log('    try cld.cfg.outDir = "/data/local/tmp/dexdump"');
            return null;
        }

        this.seen[fp] = name;
        this.captured.push({ path: name, size: len, source: tag, kind: cls.kind });
        this._event('[DUMP]', len + ' bytes, ' + cls.note + ' -> ' + name);
        return name;
    },

    _dumpByteBuffer: function (buf, tag) {
        try {
            var remaining = buf.remaining();
            if (remaining <= 0) { console.log('[-] empty ByteBuffer (' + tag + ')'); return; }

            var bytes = Java.array('byte', new Array(remaining).fill(0));

            // Preserve the buffer's position. The app is about to use it, and
            // a consumed buffer is a crash the packer will interpret as
            // tampering.
            var pos = buf.position();
            buf.get(bytes);
            buf.position(pos);

            this._write(bytes, remaining, tag);
        } catch (e) {
            console.log('[-] ByteBuffer dump failed (' + tag + '): ' + e);
        }
    },

    _dumpPath: function (path, tag) {
        if (path === null || path === undefined) return;
        var p = String(path);

        // A dexPath can be a colon-separated list.
        var self = this;
        p.split(':').forEach(function (one) {
            if (one.length === 0) return;
            try {
                var File = Java.use('java.io.File');
                var f = File.$new(one);
                if (!f.exists()) {
                    console.log('[-] not on disk: ' + one +
                                '  (in-memory load? check the ByteBuffer hooks)');
                    return;
                }
                var len = f.length();
                if (len <= 0 || len > self.cfg.maxBytes) return;

                var FIS = Java.use('java.io.FileInputStream');
                var fis = FIS.$new(f);
                var bytes = Java.array('byte', new Array(len).fill(0));
                fis.read(bytes);
                fis.close();

                self._write(bytes, len, tag);
            } catch (e) {
                console.log('[-] file dump failed (' + one + '): ' + e);
            }
        });
    },

    _isOwnApk: function (path) {
        if (!path) return false;
        var p = String(path);
        return p.indexOf('/data/app/') === 0 && p.indexOf('.apk') !== -1;
    },

    _hook: function (name, fn) {
        try {
            fn();
            this.hooks.ok.push(name);
        } catch (e) {
            this.hooks.failed.push(name + ' (' + e + ')');
        }
    },

    // ============================================================ THE HOOKS

    /*
     * Stage 1 — the packer's entry point.
     *
     * ActivityThread.handleBindApplication instantiates the class named by
     * <application android:name>, which the packer rewrote to its stub, and
     * calls attachBaseContext on it FIRST — before onCreate, before any
     * Activity, before any of the app's real code.
     *
     * Seeing this line in the timeline confirms two things: your hooks are in
     * place early enough, and the class name printed is the stub, which is
     * your identification of the protector family (section 3.7.4).
     */
    hookApplicationEntry: function () {
        var self = this;
        this._hook('Application.attachBaseContext', function () {
            var App = Java.use('android.app.Application');
            App.attachBaseContext.implementation = function (ctx) {
                self._event('[STAGE1]', 'attachBaseContext on ' + this.$className +
                                        '  <-- the stub Application, if packed');
                var r = this.attachBaseContext(ctx);
                self._event('[STAGE1]', 'attachBaseContext returned — ' +
                                        'unpacking has finished by now');
                return r;
            };
        });

        this._hook('ContextWrapper.attachBaseContext', function () {
            var CW = Java.use('android.content.ContextWrapper');
            CW.attachBaseContext.implementation = function (ctx) {
                var n = this.$className;
                // Only interesting for non-framework subclasses.
                if (n.indexOf('android.') !== 0 && n.indexOf('androidx.') !== 0) {
                    self._event('[STAGE1]', 'ContextWrapper.attachBaseContext on ' + n);
                }
                return this.attachBaseContext(ctx);
            };
        });
    },

    /*
     * Stage 2 — the native runtime arrives.
     *
     * System.loadLibrary names the protector's library. The dynamic linker
     * then runs every function pointer in that library's .init_array section
     * BEFORE dlopen returns and before JNI_OnLoad — which is where the
     * anti-debug lives, and why hooking JNI_OnLoad is always too late
     * (section 3.7.1).
     *
     * We hook android_dlopen_ext so we are present on both sides of that
     * moment: if the process dies between the two lines, you have located the
     * anti-debug precisely.
     */
    hookNativeLoad: function () {
        var self = this;

        this._hook('System.loadLibrary/load', function () {
            var Sys = Java.use('java.lang.System');
            Sys.loadLibrary.implementation = function (name) {
                self._event('[STAGE2]', 'System.loadLibrary("' + name +
                                        '")  <-- inspect lib' + name + '.so in Ghidra');
                return this.loadLibrary(name);
            };
            Sys.load.implementation = function (path) {
                self._event('[STAGE2]', 'System.load("' + path +
                                        '")  <-- loaded from a path, not lib/');
                return this.load(path);
            };
        });

        this._hook('android_dlopen_ext', function () {
            var p = Module.findExportByName(null, 'android_dlopen_ext');
            if (p === null) p = Module.findExportByName(null, 'dlopen');
            if (p === null) throw new Error('no dlopen export found');

            Interceptor.attach(p, {
                onEnter: function (args) {
                    this.path = null;
                    try { this.path = args[0].readUtf8String(); } catch (e) { }
                    if (this.path && this.path.indexOf('/system/') !== 0 &&
                        this.path.indexOf('/apex/') !== 0) {
                        self._event('[STAGE2]', 'dlopen ENTER ' + this.path +
                                                '  (.init_array runs now)');
                    }
                },
                onLeave: function () {
                    if (this.path && this.path.indexOf('/system/') !== 0 &&
                        this.path.indexOf('/apex/') !== 0) {
                        self._event('[STAGE2]', 'dlopen LEAVE ' + this.path +
                                                '  (.init_array survived)');
                    }
                }
            });
        });
    },

    /*
     * Optional — neutralise the commonest anti-debug.
     *
     * ptrace(PTRACE_TRACEME, ...) succeeds only if nobody is already tracing
     * the process. Frida's spawn mode traces it, so the call fails and the
     * packer knows. Returning 0 makes it look fine.
     *
     * Off by default, deliberately. Some apps use ptrace legitimately, and a
     * blind Interceptor.replace here has caused more confusing crashes than it
     * has solved. Log first, replace second.
     *
     * If this hook never fires but the process still dies, the protector is
     * issuing the syscall through inline assembly rather than the libc
     * wrapper — see ../../67-BypassingProtections/README.md.
     */
    hookPtrace: function () {
        var self = this;
        this._hook('ptrace', function () {
            var p = Module.findExportByName(null, 'ptrace');
            if (p === null) throw new Error('ptrace not exported');

            if (!self.cfg.neutralisePtrace) {
                Interceptor.attach(p, {
                    onEnter: function (args) {
                        self._event('[ANTI-DEBUG]', 'ptrace(request=' +
                            args[0].toInt32() + ') called — set ' +
                            'cld.cfg.neutralisePtrace=true and respawn if the process dies');
                    }
                });
                return;
            }

            Interceptor.replace(p, new NativeCallback(function (req, pid, addr, data) {
                self._event('[ANTI-DEBUG]', 'ptrace(' + req + ') -> 0 (neutralised)');
                return 0;
            }, 'long', ['int', 'int', 'pointer', 'pointer']));
        });
    },

    /*
     * Stage 3 — the handover. This is the moment the whole script exists for.
     */
    hookLoaders: function () {
        var self = this;

        // --- InMemoryDexClassLoader: the modern packer's favourite ---------
        // API 26+. Takes plaintext DEX in a ByteBuffer and never touches disk,
        // which is exactly why packers moved to it: there is no file for you
        // to find afterwards. There is, however, a ByteBuffer right here.
        this._hook('InMemoryDexClassLoader', function () {
            var IMDCL = Java.use('dalvik.system.InMemoryDexClassLoader');

            IMDCL.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
                .implementation = function (buf, parent) {
                    self._event('[STAGE3]', 'InMemoryDexClassLoader(ByteBuffer)  ' +
                                            '<-- THE HANDOVER');
                    self._dumpByteBuffer(buf, 'inmemory');
                    return this.$init(buf, parent);
                };

            try {
                IMDCL.$init.overload('[Ljava.nio.ByteBuffer;', 'java.lang.ClassLoader')
                    .implementation = function (bufs, parent) {
                        self._event('[STAGE3]', 'InMemoryDexClassLoader(ByteBuffer[' +
                                                bufs.length + '])');
                        for (var i = 0; i < bufs.length; i++) {
                            self._dumpByteBuffer(bufs[i], 'inmemory_' + i);
                        }
                        return this.$init(bufs, parent);
                    };
            } catch (e) { /* overload absent on this API level */ }
        });

        // --- DexClassLoader: the classic, writes an odex to optimizedDir ---
        this._hook('DexClassLoader', function () {
            var DCL = Java.use('dalvik.system.DexClassLoader');
            DCL.$init.overload('java.lang.String', 'java.lang.String',
                               'java.lang.String', 'java.lang.ClassLoader')
                .implementation = function (dexPath, optDir, libPath, parent) {
                    self._event('[STAGE3]', 'DexClassLoader dexPath=' + dexPath);
                    self._event('       ', '              optDir =' + optDir);
                    // Dump BEFORE the constructor runs: some packers delete
                    // the temporary file the instant the loader is built.
                    self._dumpPath(dexPath, 'dexclassloader');
                    return this.$init(dexPath, optDir, libPath, parent);
                };
        });

        // --- PathClassLoader ------------------------------------------------
        this._hook('PathClassLoader', function () {
            var PCL = Java.use('dalvik.system.PathClassLoader');
            PCL.$init.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var dexPath = arguments.length > 0 ? arguments[0] : null;
                    var own = self._isOwnApk(dexPath);
                    self._event('[STAGE3]', 'PathClassLoader ' + dexPath +
                                            (own ? '  (own APK)' : '  <-- unexpected path'));
                    if (!own || self.cfg.dumpOwnApk) {
                        self._dumpPath(dexPath, 'pathclassloader');
                    }
                    return ov.apply(this, arguments);
                };
            });
        });

        // --- BaseDexClassLoader: catches custom subclasses generically ------
        // A packer that ships its own ClassLoader subclass still calls up to
        // this constructor, so this hook catches loaders whose class name you
        // have never seen.
        this._hook('BaseDexClassLoader', function () {
            var BDCL = Java.use('dalvik.system.BaseDexClassLoader');
            BDCL.$init.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var dexPath = arguments.length > 0 ? arguments[0] : null;
                    var cls = this.$className;
                    if (cls !== 'dalvik.system.PathClassLoader' &&
                        cls !== 'dalvik.system.DexClassLoader' &&
                        cls !== 'dalvik.system.InMemoryDexClassLoader') {
                        self._event('[STAGE3]', 'CUSTOM loader ' + cls +
                                                ' dexPath=' + dexPath);
                    }
                    if (dexPath !== null && !self._isOwnApk(dexPath)) {
                        self._dumpPath(dexPath, 'basedex');
                    }
                    return ov.apply(this, arguments);
                };
            });
        });

        // --- DexFile: legacy, still seen in older packers -------------------
        this._hook('DexFile', function () {
            var DF = Java.use('dalvik.system.DexFile');
            try {
                DF.loadDex.overload('java.lang.String', 'java.lang.String', 'int')
                    .implementation = function (src, out, flags) {
                        self._event('[STAGE3]', 'DexFile.loadDex ' + src);
                        self._dumpPath(src, 'dexfile_loaddex');
                        return this.loadDex(src, out, flags);
                    };
            } catch (e) { }
            try {
                DF.$init.overload('java.lang.String').implementation = function (p) {
                    self._event('[STAGE3]', 'new DexFile(' + p + ')');
                    self._dumpPath(p, 'dexfile_ctor');
                    return this.$init(p);
                };
            } catch (e) { }
        });
    },

    /*
     * Stage 4 — the ClassLoader swap.
     *
     * Having created a loader over the real DEX, the stub must make the
     * framework use it. It does that reflectively, replacing
     * LoadedApk.mClassLoader (see section 4.3 of the chapter). Observing this
     * is how you confirm unpacking completed, and the reflective Field.set is
     * a reliable, algorithm-independent tell.
     */
    hookClassLoaderSwap: function () {
        var self = this;
        this._hook('Field.set (mClassLoader swap)', function () {
            var Field = Java.use('java.lang.reflect.Field');
            Field.set.implementation = function (obj, value) {
                try {
                    var fname = this.getName();
                    if (fname === 'mClassLoader' || fname === 'classLoader' ||
                        fname === 'parent') {
                        self._event('[STAGE4]', 'reflective set of ' + fname +
                                                ' = ' + (value === null ? 'null'
                                                                        : value.toString()));
                    }
                } catch (e) { }
                return this.set(obj, value);
            };
        });
    },

    /*
     * Stage 5 — confirmation. Real class names appearing through findClass is
     * the proof that unpacking happened and that the DEX you captured is the
     * real one.
     */
    hookFindClass: function () {
        var self = this;
        if (!this.cfg.logFindClass) return;
        this._hook('BaseDexClassLoader.findClass', function () {
            var BDCL = Java.use('dalvik.system.BaseDexClassLoader');
            BDCL.findClass.implementation = function (name) {
                console.log('[class] ' + this.$className + ' -> ' + name);
                return this.findClass(name);
            };
        });
    },

    // ================================================================ API

    status: function () {
        console.log('');
        console.log('=== frida-classloader-dump status ===');
        console.log('hooks installed : ' + this.hooks.ok.length);
        console.log('  ' + this.hooks.ok.join(', '));
        if (this.hooks.failed.length) {
            console.log('hooks FAILED    :');
            this.hooks.failed.forEach(function (f) { console.log('  ' + f); });
        }

        console.log('');
        console.log('captured ' + this.captured.length + ' payload(s):');
        this.captured.forEach(function (c) {
            console.log('  ' + c.size + ' bytes  [' + c.kind + ']  ' +
                        c.source + '  ' + c.path);
        });

        if (this.captured.length === 0) {
            console.log('  NOTHING CAPTURED. Run cld.timeline() to see how far it got.');
            console.log('  Then, in order:');
            console.log('    - Did you spawn with --pause and resume AFTER "hooks installed"?');
            console.log('    - Is the app actually packed? Run apk-obfuscation-triage.sh.');
            console.log('    - Did the process die on resume? Set');
            console.log('        cld.cfg.neutralisePtrace = true');
            console.log('      and respawn.');
            console.log('    - DEX built in native code, never via a Java ctor?');
            console.log('        use frida-dexdump-lite.js (memory sweep).');
        } else {
            var dexes = this.captured.filter(function (c) { return c.kind === 'dex'; });
            console.log('');
            if (dexes.length === 0) {
                console.log('  No payload had DEX magic. What you captured is probably');
                console.log('  still encrypted — the decryption happens further along.');
                console.log('  Try frida-dexdump-lite.js AFTER the first Activity appears.');
            } else {
                console.log('  Retrieve and decompile:');
                console.log('    adb pull ' + this.cfg.outDir);
                console.log('    jadx -d out ' + this.cfg.outDir + '/*.dex');
                console.log('  Success criterion (section 6.1 phase 3): jadx shows classes');
                console.log('  whose names match the manifest components. Until then you');
                console.log('  have not unpacked.');
            }
        }
        console.log('');
    },

    timeline: function () {
        console.log('');
        console.log('=== unpacking timeline ===');
        if (this.events.length === 0) {
            console.log('(nothing recorded — hooks may have installed after the fact)');
        }
        this.events.forEach(function (e) { console.log(e); });
        console.log('');
        console.log('Expected sequence for a packed app (section 3.7.1):');
        console.log('  STAGE1 attachBaseContext on <vendor stub class>');
        console.log('  STAGE2 System.loadLibrary("<protector>")');
        console.log('  STAGE2 dlopen ENTER / LEAVE   (.init_array anti-debug)');
        console.log('  STAGE3 InMemoryDexClassLoader / DexClassLoader  <-- dump here');
        console.log('  STAGE4 reflective set of mClassLoader');
        console.log('  STAGE1 attachBaseContext returned');
        console.log('');
    },

    /*
     * Every ClassLoader in the process. BaseDexClassLoader.toString() prints
     * its DexPathList, which prints dexElements — so this answers "did
     * unpacking actually happen" directly. Before unpacking you see one entry,
     * the base APK. Afterwards you see additional entries, often with no path
     * at all for in-memory loads.
     */
    loaders: function () {
        Java.perform(function () {
            var i = 0;
            Java.enumerateClassLoaders({
                onMatch: function (l) {
                    console.log('[' + (i++) + '] ' + l.toString());
                },
                onComplete: function () {
                    console.log('');
                    console.log('Entries with no path = in-memory DEX. That is the');
                    console.log('unpacked payload, and the ByteBuffer hooks should');
                    console.log('have captured it.');
                }
            });
        });
    },

    setOutDir: function (p) {
        this.cfg.outDir = p;
        console.log('[*] output directory: ' + p);
    },

    help: function () {
        console.log([
            '',
            'cld.status()      hooks, captures, and what to do if empty',
            'cld.timeline()    the unpacking sequence in order',
            'cld.loaders()     every ClassLoader — did unpacking happen?',
            'cld.setOutDir(p)  change the dump directory',
            '',
            'cld.cfg.neutralisePtrace = true   before respawn, if the process dies',
            'cld.cfg.logFindClass     = true   log every class resolved',
            'cld.cfg.dumpOwnApk       = true   also dump the base APK',
            ''
        ].join('\n'));
    }
};

// --------------------------------------------------------------- bootstrap

Java.perform(function () {
    console.log('');
    console.log('=====================================================================');
    console.log(' frida-classloader-dump.js — catch the handover');
    console.log('');
    console.log(' Unpacking is not code-breaking. It is TIMING. The plaintext DEX');
    console.log(' must exist in this process for the app to run; be present at that');
    console.log(' moment with somewhere to write the bytes.');
    console.log('=====================================================================');
    console.log('');

    cld._t0 = Date.now();

    cld.hookApplicationEntry();
    cld.hookNativeLoad();
    cld.hookPtrace();
    cld.hookLoaders();
    cld.hookClassLoaderSwap();
    cld.hookFindClass();

    console.log('');
    console.log('[+] hooks installed: ' + cld.hooks.ok.length +
                ', failed: ' + cld.hooks.failed.length);
    if (cld.hooks.failed.length) {
        cld.hooks.failed.forEach(function (f) { console.log('    [-] ' + f); });
    }
    console.log('[*] dumping to ' + cld._outDir());
    console.log('');
    console.log('NOW TYPE %resume — and not before.');
    console.log('Then exercise the app and run cld.status() / cld.timeline().');
    console.log('cld.help() for everything.');
    console.log('');
});
