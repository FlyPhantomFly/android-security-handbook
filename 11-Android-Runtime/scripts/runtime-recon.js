/*
 * ============================================================================
 *  runtime-recon.js  —  Chapter 11, Android Runtime
 * ============================================================================
 *
 *  WHAT THIS DOES
 *  --------------
 *  The first script you run against an unfamiliar app. It answers, in one
 *  screenful, the questions you need answered before any other analysis makes
 *  sense:
 *
 *    1. Which runtime am I in?   java.vm.name, java.vm.version, vendor.
 *    2. Which Android is this?   Build.VERSION.SDK_INT / RELEASE, and the raw
 *                                ro.build.version.sdk property.
 *    3. Is this process 32-bit or 64-bit?  (Decides which frida-server,
 *                                which .so, and which ABI your gadgets need.)
 *    4. What is the ClassLoader chain?  (Who can define classes here.)
 *    5. Which OAT / VDEX / ODEX / ART images are mapped into the process?
 *       (Tells you whether the app is running AOT-compiled code, interpreted
 *       code, or something the app supplied itself.)
 *    6. Live hooks on java.lang.Runtime.exec and java.lang.ProcessBuilder.start
 *       so every child process the app spawns is printed with its full argv and
 *       a Java stack trace.
 *
 *  HOW TO RUN IT
 *  -------------
 *  Spawn (preferred - catches startup behaviour):
 *
 *      # host shell
 *      frida -U -f com.example.target -l runtime-recon.js
 *
 *  Attach to a running app:
 *
 *      # host shell
 *      frida -U -n com.example.target -l runtime-recon.js
 *
 *  Attach by pid, saving output:
 *
 *      # host shell
 *      frida -U -p $(adb shell pidof com.example.target) -l runtime-recon.js -o recon.log
 *
 *  PREREQUISITES
 *  -------------
 *   - frida-tools on the host:  pip install frida-tools
 *   - frida-server of the SAME major version running as root on the device,
 *     and of the right architecture. If you are unsure which architecture:
 *         adb shell getprop ro.product.cpu.abi
 *   - The device visible to:  frida-ls-devices
 *
 *  NOTE ON 32 vs 64 BIT
 *  --------------------
 *  A 64-bit device runs a 64-bit Zygote AND a 32-bit Zygote (zygote64 and
 *  zygote). An app is forked from whichever matches its native libraries, so
 *  two apps on the same phone can be in different bitnesses. If you attach with
 *  the wrong frida-server build you get confusing failures, and if you write a
 *  native hook against the wrong pointer size you get garbage. Section 3 of the
 *  output tells you which one you are in.
 * ============================================================================
 */

'use strict';

function log(msg) {
    console.log(msg);
}

function section(title) {
    log('');
    log('---- ' + title + ' ' + Array(Math.max(2, 58 - title.length)).join('-'));
}

/* Read a text file through Java rather than Frida's File API, because
 * java.io.BufferedReader is guaranteed present on every Android version and
 * handles the /proc quirk that these files report size 0 and must be read
 * sequentially rather than stat()ed and slurped. */
function readLines(path) {
    var lines = [];
    try {
        var FileReader = Java.use('java.io.FileReader');
        var BufferedReader = Java.use('java.io.BufferedReader');
        var br = BufferedReader.$new(FileReader.$new(path));
        var line = br.readLine();
        while (line !== null) {
            lines.push('' + line);
            line = br.readLine();
        }
        br.close();
    } catch (e) {
        log('  could not read ' + path + ': ' + e);
    }
    return lines;
}

/* Build a Java stack trace string. A Throwable captures the stack when it is
 * constructed, and android.util.Log formats it for us. */
function javaStack() {
    try {
        var Exception = Java.use('java.lang.Exception');
        var Log = Java.use('android.util.Log');
        return Log.getStackTraceString(Exception.$new('recon'));
    } catch (e) {
        return '(no stack: ' + e + ')';
    }
}

/* Format one exec/ProcessBuilder argument. Frida hands Java String[] to JS as a
 * JS array of strings, and a plain String as a string wrapper. */
function fmtArg(v) {
    if (v === null || v === undefined) {
        return 'null';
    }
    if (Array.isArray(v)) {
        var parts = [];
        for (var i = 0; i < v.length; i++) {
            parts.push(JSON.stringify('' + v[i]));
        }
        return '[' + parts.join(', ') + ']';
    }
    return JSON.stringify('' + v);
}

/* Heuristic: does this command line look like it will be parsed by a shell?
 * If yes, any attacker-controlled substring in it is a command injection. */
function looksLikeShell(text) {
    return /(^|\/)(sh|bash|toybox\s+sh)\b/.test(text) || text.indexOf(' -c ') !== -1;
}

Java.perform(function () {

    log('============================================================');
    log('  runtime-recon.js  -  Android Runtime reconnaissance');
    log('============================================================');

    /* =====================================================================
     *  1. Which runtime?
     *
     *  These are ordinary Java system properties, readable by any code with no
     *  permission at all. On every modern Android device java.vm.name reads
     *  "Dalvik" for historical/compatibility reasons even though the runtime is
     *  ART - too much code checked that string for it ever to be changed. The
     *  version number is the one that actually tells you something.
     * ================================================================== */
    section('1. runtime identity');
    try {
        var System = Java.use('java.lang.System');
        var props = ['java.vm.name', 'java.vm.version', 'java.vm.vendor',
                     'java.vm.specification.version', 'java.runtime.name',
                     'java.runtime.version', 'os.arch', 'os.version',
                     'java.io.tmpdir', 'user.dir'];
        for (var i = 0; i < props.length; i++) {
            log('  ' + props[i] + ' = ' + System.getProperty(props[i]));
        }
        log('  NOTE: java.vm.name reports "Dalvik" on ART for compatibility.');
        log('        Do not use it to detect the runtime. Use SDK_INT.');
    } catch (e) {
        log('  failed: ' + e);
    }

    /* =====================================================================
     *  2. Which Android version?
     *
     *  Two sources, deliberately printed side by side:
     *    - android.os.Build.VERSION.SDK_INT: the public, always-allowed answer.
     *    - android.os.SystemProperties.get("ro.build.version.sdk"): the raw
     *      property store, reached by reflection. SystemProperties is @hide, so
     *      on API 28+ this doubles as a live test of whether hidden API
     *      enforcement is active in this process. If it works, either
     *      enforcement is off (settings put global hidden_api_policy 1), or
     *      the member is on a permissive list, or something already exempted
     *      the process.
     * ================================================================== */
    section('2. platform version');
    try {
        var VERSION = Java.use('android.os.Build$VERSION');
        log('  Build.VERSION.SDK_INT = ' + VERSION.SDK_INT.value);
        log('  Build.VERSION.RELEASE = ' + VERSION.RELEASE.value);
        var Build = Java.use('android.os.Build');
        log('  Build.FINGERPRINT     = ' + Build.FINGERPRINT.value);
        log('  Build.TAGS            = ' + Build.TAGS.value +
            '   ("test-keys" hints at a non-production build)');
    } catch (e) {
        log('  Build read failed: ' + e);
    }
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');
        log('  ro.build.version.sdk  = ' +
            SystemProperties.get('ro.build.version.sdk'));
        log('  ro.debuggable         = ' + SystemProperties.get('ro.debuggable'));
        log('  ro.product.cpu.abi    = ' + SystemProperties.get('ro.product.cpu.abi'));
        log('  hidden API enforcement did NOT block SystemProperties here.');
    } catch (e) {
        log('  SystemProperties unreachable: ' + e);
        log('  That is what hidden API enforcement looks like from the inside.');
    }

    /* =====================================================================
     *  3. 32-bit or 64-bit?
     *
     *  Three independent signals, because each can be misleading alone:
     *    - Process.pointerSize   : Frida's view of the address size. Definitive.
     *    - Process.arch          : the CPU architecture string.
     *    - the libart.so path in the memory map: /apex/.../lib64/ vs /lib/.
     *  On a 64-bit device both zygote (32-bit) and zygote64 exist, and the app
     *  is forked from whichever suits its native libraries.
     * ================================================================== */
    section('3. process bitness');
    log('  Process.arch        = ' + Process.arch);
    log('  Process.pointerSize = ' + Process.pointerSize +
        ' bytes -> ' + (Process.pointerSize === 8 ? '64-bit' : '32-bit') + ' process');
    log('  Process.id          = ' + Process.id);
    try {
        var artModule = Process.findModuleByName('libart.so');
        if (artModule !== null) {
            log('  libart.so           = ' + artModule.path);
            log('  libart base/size    = ' + artModule.base + ' / ' + artModule.size);
        } else {
            log('  libart.so not found by name; listing runtime-ish modules:');
            Process.enumerateModules().forEach(function (m) {
                if (m.name.indexOf('art') !== -1 || m.name.indexOf('dvm') !== -1) {
                    log('    ' + m.name + '  ' + m.path);
                }
            });
        }
    } catch (e) {
        log('  module enumeration failed: ' + e);
    }

    /* =====================================================================
     *  4. ClassLoader chain
     *
     *  The chain is the class-resolution order. BaseDexClassLoader.toString()
     *  prints its whole DexPathList, so we get every DEX path for free without
     *  any reflection - and therefore without tripping hidden API enforcement.
     * ================================================================== */
    section('4. ClassLoader chain');
    try {
        var start = null;
        var ActivityThread = Java.use('android.app.ActivityThread');
        var app = ActivityThread.currentApplication();
        if (app !== null) {
            start = app.getClassLoader();
            log('  starting from Application.getClassLoader()');
        } else {
            // Very early in startup there is no Application yet. The current
            // thread's context loader is the next best anchor.
            start = Java.use('java.lang.Thread').currentThread().getContextClassLoader();
            log('  no Application yet; using Thread.contextClassLoader');
        }
        var depth = 0;
        var cl = start;
        while (cl !== null && depth < 16) {
            log('  [' + depth + '] ' + cl.$className);
            log('       ' + cl.toString());
            cl = cl.getParent();
            depth++;
        }
        log('  [' + depth + '] null  (the loader above is BootClassLoader)');
    } catch (e) {
        log('  chain walk failed: ' + e);
    }

    log('');
    log('  all registered loaders (Java.enumerateClassLoaders):');
    var count = 0;
    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            count++;
            log('    - ' + loader.$className);
        },
        onComplete: function () {
            log('    total = ' + count + '  (2 is the baseline for a plain app)');
        }
    });

    /* =====================================================================
     *  5. Compiled artefacts mapped into the process
     *
     *  /proc/self/maps lists every memory mapping. The interesting extensions:
     *
     *    .art   boot image / app image: pre-initialised heap objects, mapped in
     *           at startup so the process does not have to re-create them.
     *    .oat   AOT-compiled native code produced by dex2oat.
     *    .odex  the older name for the same idea; still seen on some paths.
     *    .vdex  the verified DEX container - holds the DEX plus verification
     *           results so the runtime can skip re-verifying.
     *    .apk / .jar / .dex  raw containers being read for their DEX.
     *
     *  READ IT LIKE THIS: an app whose base.apk appears but whose oat/ artefacts
     *  do not is running interpreted or JIT-compiled, which is normal right
     *  after install (compilation filter "verify"). Seeing a .oat under
     *  /data/app/.../oat/ means dex2oat has run for that app. Seeing a .dex or
     *  .vdex mapped from an unexpected directory - the app's files dir, the
     *  cache dir, /data/local/tmp - means dynamically loaded code, which is the
     *  finding you care about.
     * ================================================================== */
    section('5. mapped DEX / OAT / VDEX / ART artefacts');
    var maps = readLines('/proc/self/maps');
    var interesting = [];
    var seenPaths = {};
    for (var m = 0; m < maps.length; m++) {
        var lineText = maps[m];
        if (/\.(art|oat|odex|vdex|dex|apk|jar)(\s|$)/.test(lineText)) {
            // Keep one line per distinct path: a single file is mapped many
            // times with different protections and offsets.
            var idx = lineText.indexOf('/');
            var p = idx >= 0 ? lineText.substring(idx) : lineText;
            if (!seenPaths[p]) {
                seenPaths[p] = true;
                interesting.push(p);
            }
        }
    }
    if (interesting.length === 0) {
        log('  none found (unusual - check that /proc/self/maps was readable)');
    } else {
        for (var k = 0; k < interesting.length; k++) {
            var path = interesting[k];
            var flag = '';
            if (path.indexOf('/data/local/tmp') === 0) {
                flag = '   <== NOT a normal app code location';
            } else if (/\/(files|cache|app_[^/]*)\//.test(path) &&
                       /\.(dex|jar|apk|vdex|oat)$/.test(path)) {
                flag = '   <== app-writable location: dynamic loading suspected';
            }
            log('  ' + path + flag);
        }
    }
    log('  total distinct code artefacts: ' + interesting.length);

    /* =====================================================================
     *  6. Hook the process-spawning sinks.
     *
     *  Runtime.exec has six overloads; ProcessBuilder.start is the other door
     *  to the same fork/exec machinery. We hook all of them and print argv plus
     *  the Java stack, because the stack tells you which app class decided to
     *  run a command - which is where you look for the injection.
     *
     *  What you are hunting for in the output:
     *    - "/system/bin/sh" with "-c" and a long concatenated string. Any
     *      attacker-influenced substring in that string is command injection.
     *    - "su", "which su", "id", "mount", "getprop ro.debuggable": root and
     *      environment detection. See chapters 37 and 39.
     *    - "pm", "am", "settings": the app driving the platform through the
     *      shell rather than through an API, which usually fails on modern
     *      Android and is worth reporting as broken behaviour.
     * ================================================================== */
    section('6. hooking Runtime.exec and ProcessBuilder.start');

    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overloads.forEach(function (overload) {
            overload.implementation = function () {
                var args = Array.prototype.slice.call(arguments);
                var rendered = [];
                for (var i = 0; i < args.length; i++) {
                    rendered.push(fmtArg(args[i]));
                }
                var joined = rendered.join(', ');
                log('');
                log('[exec] Runtime.exec(' + joined + ')');
                if (looksLikeShell(joined)) {
                    log('[exec] *** a SHELL is being invoked - check every');
                    log('[exec]     substring of that command for attacker input');
                }
                log(javaStack());
                // Invoking the overload wrapper from JS runs the original
                // implementation, so this does not recurse into our hook.
                return overload.apply(this, arguments);
            };
        });
        log('  hooked ' + Runtime.exec.overloads.length + ' Runtime.exec overload(s)');
    } catch (e) {
        log('  Runtime.exec hook failed: ' + e);
    }

    try {
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.start.overloads.forEach(function (overload) {
            overload.implementation = function () {
                var cmd = 'unavailable';
                try {
                    // command() returns List<String>; toString() is enough for
                    // a log line and cannot throw for a plain ArrayList.
                    cmd = '' + this.command();
                } catch (e) {
                    cmd = '<command() threw ' + e + '>';
                }
                log('');
                log('[exec] ProcessBuilder.start() argv = ' + cmd);
                if (looksLikeShell(cmd)) {
                    log('[exec] *** shell invocation via ProcessBuilder');
                }
                try {
                    log('[exec] directory = ' + this.directory());
                } catch (e) {
                    /* directory() may be null; not important enough to fail on */
                }
                log(javaStack());
                return overload.apply(this, arguments);
            };
        });
        log('  hooked ' + ProcessBuilder.start.overloads.length +
            ' ProcessBuilder.start overload(s)');
    } catch (e) {
        log('  ProcessBuilder hook failed: ' + e);
    }

    section('ready');
    log('  Drive the app now. exec/ProcessBuilder calls will print above.');
    log('  For DEX loading specifically, run ../examples/hook-classloaders.js');
    log('  which also dumps in-memory DEX payloads to disk.');
});
