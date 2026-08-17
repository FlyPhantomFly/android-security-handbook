/*
 * ============================================================================
 *  hook-classloaders.js  —  Chapter 11, Android Runtime
 * ============================================================================
 *
 *  WHAT THIS DOES
 *  --------------
 *  A complete Frida script that answers one question about a running app:
 *  "what code is being loaded into this process, from where, and by whom?"
 *
 *  It does four things:
 *
 *    1. Enumerates every live ClassLoader with Java.enumerateClassLoaders and
 *       prints its type, identity and DEX list.
 *    2. Hooks the constructors of DexClassLoader, InMemoryDexClassLoader and
 *       PathClassLoader, so that any loader created AFTER we attach is reported
 *       with its arguments and a Java stack trace showing who created it.
 *    3. Dumps the DEX bytes of every InMemoryDexClassLoader to a file, which is
 *       the whole point: in-memory DEX never touches the filesystem, so this
 *       hook is often the only way to obtain the second-stage code of a packed
 *       app.
 *    4. Optionally hooks BaseDexClassLoader.loadClass so you can watch class
 *       resolution happen in real time (noisy - off by default, see CONFIG).
 *
 *  HOW TO RUN IT
 *  -------------
 *  Spawn the app so you catch loaders created during startup (strongly
 *  preferred - packers unpack in Application.attachBaseContext, long before any
 *  UI exists):
 *
 *      # host shell
 *      frida -U -f com.example.runtimelab -l hook-classloaders.js
 *
 *  Attach to an already-running app (you will only see loaders created from now
 *  on, plus the enumeration of the ones that already exist):
 *
 *      # host shell
 *      frida -U -n com.example.runtimelab -l hook-classloaders.js
 *
 *  Non-interactive, log to a file:
 *
 *      # host shell
 *      frida -U -f com.example.runtimelab -l hook-classloaders.js -o loaders.log
 *
 *  Pull whatever got dumped:
 *
 *      # host shell
 *      adb shell ls -l /data/local/tmp/dexdump
 *      adb pull /data/local/tmp/dexdump ./dexdump
 *      jadx -d out ./dexdump/inmemory_1234_0.dex
 *
 *  PREREQUISITES
 *  -------------
 *   - frida-tools on the host:            pip install frida-tools
 *   - A matching frida-server running on the device as root:
 *         adb push frida-server /data/local/tmp/
 *         adb shell "chmod 755 /data/local/tmp/frida-server"
 *         adb shell "su -c /data/local/tmp/frida-server &"
 *     (Or a repackaged APK with frida-gadget, if the device is not rooted.)
 *   - USB debugging on, device visible to `frida-ls-devices`.
 *
 *  CAVEATS
 *  -------
 *   - SELinux: an untrusted_app process usually may NOT write to
 *     /data/local/tmp on Android 9+. The script therefore tries that directory
 *     first and automatically falls back to the app's own files directory,
 *     which always works. Both paths are printed.
 *   - InMemoryDexClassLoader exists only on API 26+; on older devices that hook
 *     is silently skipped and the script says so.
 *   - Hooking a constructor sees the arguments BEFORE the object is
 *     constructed, which is exactly when the ByteBuffer still holds plaintext.
 *     Dumping later (from a heap scan) frequently gets you a buffer that has
 *     already been zeroed by the packer.
 * ============================================================================
 */

'use strict';

/* -------------------------------------------------------------------------
 *  CONFIG - edit these three flags to taste.
 * ---------------------------------------------------------------------- */
var CONFIG = {
    // Print a Java stack trace for every loader creation. Very useful, a bit
    // verbose. Turn it off if the app creates hundreds of loaders.
    stackTraces: true,

    // Hook BaseDexClassLoader.loadClass. This fires for essentially every class
    // the app resolves, so it is LOUD. Turn it on when you are hunting for a
    // specific class name, then filter with LOAD_CLASS_FILTER below.
    hookLoadClass: false,

    // Only report loadClass calls whose class name contains one of these
    // substrings. Empty array means "report everything" (do not do that).
    loadClassFilter: ['payload', 'plugin', 'Stage', 'stub'],

    // Preferred dump directory. Falls back to the app's files dir on failure.
    dumpDir: '/data/local/tmp/dexdump'
};

/* -------------------------------------------------------------------------
 *  Small logging helpers. Frida's console.log goes to the REPL / -o file.
 * ---------------------------------------------------------------------- */
function log(msg) {
    console.log(msg);
}

function banner(title) {
    log('');
    log('==== ' + title + ' ' + Array(Math.max(1, 60 - title.length)).join('='));
}

/* Frida's own PID, used to make dump filenames unique per process. */
var PID = Process.id;

/* Counter so multiple dumps in one run do not overwrite each other. */
var dumpCounter = 0;

/* Resolved lazily on first dump; see resolveDumpDir(). */
var resolvedDumpDir = null;

/* =========================================================================
 *  Java stack traces
 *
 *  WHY: knowing that an InMemoryDexClassLoader was created tells you what
 *  happened. The stack tells you WHERE in the app it happened, which is the
 *  class you then open in JADX. Without it you are searching an obfuscated APK
 *  for a needle.
 *
 *  HOW: there is no "give me the stack" API in Java, so we do the standard
 *  trick - create a Throwable (which captures the stack at construction) and
 *  ask android.util.Log to format it.
 * ====================================================================== */
function javaStack() {
    if (!CONFIG.stackTraces) {
        return '(stack traces disabled in CONFIG)';
    }
    try {
        var Exception = Java.use('java.lang.Exception');
        var Log = Java.use('android.util.Log');
        return Log.getStackTraceString(Exception.$new('frida-stack-marker'));
    } catch (e) {
        return '(stack unavailable: ' + e + ')';
    }
}

/* =========================================================================
 *  Where can we write?
 *
 *  /data/local/tmp is the classic answer and is convenient because `adb pull`
 *  reaches it without root. But since Android 9 the SELinux policy for the
 *  untrusted_app domain generally forbids writing there, and the failure looks
 *  like a plain FileNotFoundException (EACCES). The app's own files directory
 *  is always writable by definition, so we fall back to it.
 * ====================================================================== */
function resolveDumpDir() {
    if (resolvedDumpDir !== null) {
        return resolvedDumpDir;
    }

    var File = Java.use('java.io.File');

    // Candidate 1: the configured directory.
    try {
        var d = File.$new(CONFIG.dumpDir);
        if (!d.exists()) {
            d.mkdirs();
        }
        // canWrite() can lie under some SELinux configurations, so we prove it
        // by actually creating and deleting a probe file.
        var probe = File.$new(d, '.frida-probe');
        if (probe.createNewFile()) {
            probe['delete']();          // 'delete' is a JS keyword - use bracket form
            resolvedDumpDir = CONFIG.dumpDir;
            log('[dump] using ' + resolvedDumpDir);
            return resolvedDumpDir;
        }
    } catch (e) {
        log('[dump] ' + CONFIG.dumpDir + ' unusable (' + e + '), falling back');
    }

    // Candidate 2: the app's private files dir, via the current Application.
    try {
        var ActivityThread = Java.use('android.app.ActivityThread');
        var app = ActivityThread.currentApplication();
        if (app !== null) {
            var ctx = app.getApplicationContext();
            resolvedDumpDir = ctx.getFilesDir().getAbsolutePath();
            log('[dump] using ' + resolvedDumpDir +
                '   (pull with: adb shell run-as <pkg> cat <file> > out.dex)');
            return resolvedDumpDir;
        }
    } catch (e) {
        log('[dump] could not reach Application context: ' + e);
    }

    // Last resort: the process working directory, which for an app is "/".
    resolvedDumpDir = '.';
    log('[dump] falling back to the process working directory');
    return resolvedDumpDir;
}

/* =========================================================================
 *  Dump a java.nio.ByteBuffer to a .dex file.
 *
 *  The trick that makes this reliable:
 *    - duplicate() gives us an independent position/limit over the SAME bytes,
 *      so we never disturb the buffer the app is about to hand to ART. Mutating
 *      the original's position would break the app - and a crashed target
 *      teaches you nothing.
 *    - rewind() sets position back to 0 so we write the whole image, not just
 *      the unread remainder.
 *    - FileChannel.write(ByteBuffer) copies straight from the buffer to the fd.
 *      That avoids marshalling megabytes of bytes across the JS/Java bridge,
 *      which would be painfully slow and can exhaust memory on large payloads.
 * ====================================================================== */
function dumpByteBuffer(buffer, label) {
    try {
        var ByteBuffer = Java.use('java.nio.ByteBuffer');
        var buf = Java.cast(buffer, ByteBuffer);

        var dup = buf.duplicate();
        dup.rewind();
        var size = dup.remaining();

        var name = 'inmemory_' + PID + '_' + (dumpCounter++) + '.dex';
        var dir = resolveDumpDir();
        var path = dir + '/' + name;

        var FileOutputStream = Java.use('java.io.FileOutputStream');
        var FileChannel = Java.use('java.nio.channels.FileChannel');

        var fos = FileOutputStream.$new(path);
        var ch = Java.cast(fos.getChannel(), FileChannel);
        // Explicit overload: FileChannel.write is overloaded four ways and Frida
        // will refuse to guess.
        ch.write.overload('java.nio.ByteBuffer').call(ch, dup);
        ch.close();
        fos.close();

        log('[dump] ' + label + ': wrote ' + size + ' bytes -> ' + path);

        // Sanity-check the magic so you know immediately whether you grabbed a
        // real DEX or an encrypted blob. A valid DEX starts with the ASCII
        // bytes "dex\n" followed by a three-digit version and a NUL, e.g.
        // 64 65 78 0a 30 33 35 00. If you see high-entropy garbage here, the
        // app is decrypting somewhere further down and you are hooking too
        // early - or it is using a custom loader you have not found yet.
        var probe = buf.duplicate();
        probe.rewind();
        var magic = [];
        for (var i = 0; i < 8 && probe.hasRemaining(); i++) {
            // get() returns a signed Java byte (-128..127); mask to 0..255.
            var b = probe.get() & 0xff;
            magic.push(('0' + b.toString(16)).slice(-2));
        }
        log('[dump] ' + label + ': magic = ' + magic.join(' '));
    } catch (e) {
        log('[dump] FAILED for ' + label + ': ' + e);
        log('[dump] if this is an SELinux denial, check: adb logcat | grep avc');
    }
}

/* =========================================================================
 *  Hook installation helper.
 *
 *  Classes and methods come and go between Android versions. Wrapping each
 *  installation in try/catch means one missing class does not abort the whole
 *  script - the difference between "my script does not work" and "this device
 *  does not have InMemoryDexClassLoader, everything else is running".
 * ====================================================================== */
function safely(description, fn) {
    try {
        fn();
        log('[hook] installed: ' + description);
    } catch (e) {
        log('[hook] SKIPPED  : ' + description + '  (' + e + ')');
    }
}

/* Hook every overload of a constructor, calling `onEnter(argsArray, thisObj)`
 * before the real constructor runs.
 *
 * WHY EVERY OVERLOAD: InMemoryDexClassLoader alone has a (ByteBuffer,
 * ClassLoader) form, a (ByteBuffer[], ClassLoader) form, and on newer platform
 * versions a form that also takes a library search path. Hooking only the
 * first is the single most common reason people "hook the constructor" and see
 * nothing. */
function hookAllConstructors(className, onEnter) {
    var klass = Java.use(className);
    klass.$init.overloads.forEach(function (overload) {
        overload.implementation = function () {
            var args = Array.prototype.slice.call(arguments);
            try {
                onEnter(args, this, overload);
            } catch (e) {
                log('[hook] handler error for ' + className + ': ' + e);
            }
            // Call the original constructor. Invoking the overload object from
            // JS runs the ORIGINAL implementation, not our replacement, so this
            // does not recurse.
            return overload.apply(this, arguments);
        };
    });
}

/* Pretty-print one constructor argument. Java objects arrive as Frida wrappers;
 * null arrives as JS null. */
function fmt(v) {
    if (v === null || v === undefined) {
        return 'null';
    }
    try {
        return '' + v;
    } catch (e) {
        return '<unprintable ' + e + '>';
    }
}

/* =========================================================================
 *  MAIN
 * ====================================================================== */
Java.perform(function () {

    banner('runtime facts');
    try {
        var VMRuntimeSystem = Java.use('java.lang.System');
        log('java.vm.version = ' + VMRuntimeSystem.getProperty('java.vm.version'));
        log('java.vm.name    = ' + VMRuntimeSystem.getProperty('java.vm.name'));
        log('process pid     = ' + PID + '   pointerSize = ' + Process.pointerSize +
            ' (' + (Process.pointerSize === 8 ? '64-bit' : '32-bit') + ')');
    } catch (e) {
        log('could not read VM properties: ' + e);
    }

    /* ------------------------------------------------------------------
     *  1. Enumerate the loaders that already exist.
     *
     *  Java.enumerateClassLoaders walks ART's internal list of registered
     *  class loaders. Everything currently able to define a class in this
     *  process is in here. Run this immediately after attaching to a suspect
     *  app and compare the result with a clean app: extra loaders are the
     *  packer, the plugin framework, or the malware.
     *
     *  BaseDexClassLoader.toString() is deliberately informative - it prints
     *  the whole DexPathList, including every DEX path and every native
     *  library directory. That saves us the reflection ladder that
     *  ClassLoaderInspector.java has to perform from inside the app.
     * --------------------------------------------------------------- */
    banner('live ClassLoaders (Java.enumerateClassLoaders)');
    var seen = 0;
    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            seen++;
            try {
                log('[' + seen + '] ' + loader.$className);
                log('    ' + loader.toString());
                // Walk up the delegation chain so you can see who the parent is.
                // Parent delegation means the parent answers FIRST, so the chain
                // is the resolution order.
                var parent = loader.getParent();
                var depth = 1;
                while (parent !== null && depth < 8) {
                    log('    parent[' + depth + '] = ' + parent.$className);
                    parent = parent.getParent();
                    depth++;
                }
            } catch (e) {
                log('    <could not describe loader: ' + e + '>');
            }
        },
        onComplete: function () {
            log('total loaders: ' + seen);
            log('Baseline for a plain app is 2: one PathClassLoader for the APK');
            log('plus java.lang.BootClassLoader. Anything else deserves a look.');
        }
    });

    /* ------------------------------------------------------------------
     *  2. DexClassLoader - DEX from a file path.
     * --------------------------------------------------------------- */
    banner('installing hooks');

    safely('dalvik.system.DexClassLoader.$init', function () {
        hookAllConstructors('dalvik.system.DexClassLoader', function (args) {
            log('');
            log('[!] DexClassLoader created');
            log('    dexPath            = ' + fmt(args[0]));
            log('    optimizedDirectory = ' + fmt(args[1]) +
                '   (ignored since API 26)');
            log('    librarySearchPath  = ' + fmt(args[2]) +
                '   (non-null means native code comes too)');
            log('    parent             = ' + fmt(args[3]));
            log('    NOTE: copy that dexPath off the device now - many packers');
            log('          delete the file immediately after loading it:');
            log('          adb shell run-as <pkg> cat ' + fmt(args[0]) + ' > stage2.dex');
            log(javaStack());
        });
    });

    /* ------------------------------------------------------------------
     *  3. InMemoryDexClassLoader - DEX from a ByteBuffer. The prize.
     *
     *  API 26+ only. args[0] is either a ByteBuffer or a ByteBuffer[],
     *  depending on the overload, so we handle both.
     * --------------------------------------------------------------- */
    safely('dalvik.system.InMemoryDexClassLoader.$init (API 26+)', function () {
        hookAllConstructors('dalvik.system.InMemoryDexClassLoader', function (args) {
            log('');
            log('[!!] InMemoryDexClassLoader created - dumping payload');

            var first = args[0];
            if (first === null) {
                log('    first argument is null; nothing to dump');
            } else if (Array.isArray(first)) {
                // The (ByteBuffer[], ...) overload. Frida presents a Java object
                // array as a JS array of wrappers.
                log('    ' + first.length + ' buffer(s) in this payload');
                for (var i = 0; i < first.length; i++) {
                    dumpByteBuffer(first[i], 'buffer[' + i + ']');
                }
            } else {
                dumpByteBuffer(first, 'buffer');
            }
            log(javaStack());
        });
    });

    /* ------------------------------------------------------------------
     *  4. PathClassLoader - the ordinary app loader.
     *
     *  You will rarely catch the app's OWN PathClassLoader being constructed,
     *  because the framework builds it before Frida's Java bridge is ready,
     *  even with -f. Hook it anyway: plugin frameworks and some packers create
     *  ADDITIONAL PathClassLoaders at runtime, and those are exactly as
     *  interesting as a DexClassLoader.
     * --------------------------------------------------------------- */
    safely('dalvik.system.PathClassLoader.$init', function () {
        hookAllConstructors('dalvik.system.PathClassLoader', function (args) {
            log('');
            log('[!] PathClassLoader created');
            log('    arg0 (dexPath)   = ' + fmt(args[0]));
            if (args.length > 2) {
                log('    arg1 (libPath)   = ' + fmt(args[1]));
                log('    arg2 (parent)    = ' + fmt(args[2]));
            } else {
                log('    arg1 (parent)    = ' + fmt(args[1]));
            }
            log(javaStack());
        });
    });

    /* ------------------------------------------------------------------
     *  5. DelegateLastClassLoader - inverted delegation (API 27+).
     *
     *  This loader searches ITSELF first and only then asks its parent. That
     *  inverts the guarantee everyone assumes, so a class in this loader can
     *  shadow one of the app's own classes. Worth flagging loudly whenever it
     *  shows up.
     * --------------------------------------------------------------- */
    safely('dalvik.system.DelegateLastClassLoader.$init (API 27+)', function () {
        hookAllConstructors('dalvik.system.DelegateLastClassLoader', function (args) {
            log('');
            log('[!] DelegateLastClassLoader created - INVERTED parent delegation');
            log('    arg0 = ' + fmt(args[0]));
            log('    classes in this loader take precedence over the parent,');
            log('    so app classes can be shadowed here.');
            log(javaStack());
        });
    });

    /* ------------------------------------------------------------------
     *  6. BaseDexClassLoader.loadClass - watch resolution happen.
     *
     *  Off by default because it fires constantly. When you switch it on, keep
     *  the filter tight: you are looking for the moment the app asks for a
     *  class that is not in the APK, which is the moment the packer must have
     *  already unpacked.
     *
     *  AOSP: libcore/dalvik/src/main/java/dalvik/system/BaseDexClassLoader.java
     *  Not every platform version declares loadClass on BaseDexClassLoader
     *  itself (it may be inherited from java.lang.ClassLoader), so the
     *  installation is guarded and falls back to ClassLoader.loadClass.
     * --------------------------------------------------------------- */
    if (CONFIG.hookLoadClass) {
        var reportLoad = function (name, loaderThis) {
            if (CONFIG.loadClassFilter.length > 0) {
                var interesting = false;
                for (var i = 0; i < CONFIG.loadClassFilter.length; i++) {
                    if (name.indexOf(CONFIG.loadClassFilter[i]) !== -1) {
                        interesting = true;
                        break;
                    }
                }
                if (!interesting) {
                    return;
                }
            }
            log('[loadClass] ' + name + '   by ' + loaderThis.$className);
            log(javaStack());
        };

        safely('dalvik.system.BaseDexClassLoader.loadClass', function () {
            var Base = Java.use('dalvik.system.BaseDexClassLoader');
            Base.loadClass.overloads.forEach(function (overload) {
                overload.implementation = function () {
                    var args = Array.prototype.slice.call(arguments);
                    try {
                        reportLoad('' + args[0], this);
                    } catch (e) {
                        /* never let logging break the target */
                    }
                    return overload.apply(this, arguments);
                };
            });
        });

        safely('java.lang.ClassLoader.loadClass (fallback, very noisy)', function () {
            var CL = Java.use('java.lang.ClassLoader');
            CL.loadClass.overload('java.lang.String').implementation = function (name) {
                try {
                    reportLoad('' + name, this);
                } catch (e) {
                    /* ignore */
                }
                return this.loadClass(name);
            };
        });
    } else {
        log('[hook] loadClass hooks disabled (CONFIG.hookLoadClass = false)');
    }

    banner('ready');
    log('Now drive the app: launch activities, log in, trigger the feature you');
    log('suspect. Loader creations will appear above as they happen.');
});

/*
 * ============================================================================
 *  WHAT TO DO WITH WHAT YOU CAUGHT
 * ============================================================================
 *
 *  1. You got a dexPath from DexClassLoader.
 *     Pull the file before the app deletes it. If it is inside the app's
 *     private storage and the device is not rooted:
 *         adb shell run-as com.example.app cat files/stage2.dex > stage2.dex
 *     Then: jadx -d out stage2.dex
 *
 *  2. You got an inmemory_*.dex dump.
 *     Check the magic printed by the script. "64 65 78 0a" means a real DEX -
 *     open it in JADX directly. Anything else means you dumped an encrypted or
 *     compressed blob, which usually means the app is using a custom loader
 *     (look for a class that extends ClassLoader and overrides findClass) or is
 *     calling into native code that hands ART a memory-mapped DEX without ever
 *     constructing an InMemoryDexClassLoader. For that case you need to hook the
 *     native side - see chapters 13, 15 and 16.
 *
 *  3. You got a stack trace.
 *     The frame just below the constructor is the unpacking routine. Open that
 *     class in JADX and you will normally find the decryption key, the asset
 *     name, or the download URL within a few lines.
 *
 *  4. Nothing fired at all.
 *     Three usual reasons, in order of likelihood:
 *       a) You attached instead of spawning, and the unpacking happened during
 *          Application.attachBaseContext. Use -f.
 *       b) The app detected Frida and took a different code path. Check for
 *          root/Frida detection first (chapters 37 and 53).
 *       c) The loading is happening entirely in native code. Enumerate the
 *          loaders again after some time and compare - if a new loader exists
 *          that you never saw constructed, native code made it.
 *
 *  RELATED FILES IN THIS CHAPTER
 *  -----------------------------
 *   ./DynamicDexLoader.kt          - the target this script is designed against
 *   ./ClassLoaderInspector.java    - the same enumeration, from inside the app
 *   ../scripts/runtime-recon.js    - broader runtime facts plus exec hooks
 *   ../scripts/find-dynamic-loading.py - find the call sites statically first
 * ============================================================================
 */
