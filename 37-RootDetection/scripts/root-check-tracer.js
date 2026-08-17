/*
 * root-check-tracer.js
 * ---------------------------------------------------------------------------
 * PURPOSE
 *   Report WHICH root check an application performs, WHERE it is implemented,
 *   and WHAT answer it received. This script deliberately does NOT bypass
 *   anything. Its entire job is reconnaissance, so that the bypass you write
 *   afterwards is a small, targeted change instead of a shotgun.
 *
 *   Run this BEFORE you write a single hook. It converts an open-ended fight
 *   into a specific task, and it is the most useful thirty seconds you will
 *   spend on a root-detection engagement.
 *
 * WHAT IT INSTRUMENTS
 *   Java layer   : File.exists/canRead/canWrite/isDirectory/isFile/length,
 *                  Runtime.exec (all overloads), ProcessBuilder.start,
 *                  ApplicationPackageManager.getPackageInfo/getApplicationInfo/
 *                  getInstalledPackages/getInstalledApplications,
 *                  SystemProperties.get/getInt/getBoolean,
 *                  Settings.Global.getInt/getString,
 *                  BufferedReader.readLine on procfs-backed readers,
 *                  System.loadLibrary (so you learn which .so to look at).
 *   Native layer : access, faccessat, stat, stat64, lstat, __xstat, fstatat,
 *                  newfstatat, open, openat, fopen, opendir, readlink,
 *                  realpath, system, popen, execve,
 *                  __system_property_get, __system_property_find.
 *
 * USAGE
 *   # host — always SPAWN, never attach: most checks run in Application.onCreate
 *   frida -U -f com.target.app -l root-check-tracer.js --no-pause
 *
 *   # Only show hits whose path/argument looks root-related (default):
 *   #   set FILTER_NOISE = true below.
 *   # To see absolutely every filesystem probe (very verbose but occasionally
 *   # the only way to spot an unusual path):
 *   #   set FILTER_NOISE = false.
 *
 * READING THE OUTPUT
 *   [J] lines are Java-layer hits and carry a Java stack trace, which names the
 *       class implementing the check. Go straight there in JADX.
 *   [N] lines are native hits and carry module+offset. Open that module in
 *       Ghidra at that offset.
 *   If you see [N] lines but no [J] lines, do not waste time on Java hooks.
 *   If you see NEITHER but the app still detects root, you are looking at
 *   inline syscall assembly — switch to strace and static patching.
 *
 * REQUIREMENTS
 *   frida-server matching your frida client version, running as root.
 * ---------------------------------------------------------------------------
 */

'use strict';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// When true, only report arguments that look root-related. Turn off to see
// every probe the app makes (useful when a check uses an unexpected path).
var FILTER_NOISE = true;

// Print a Java stack trace for each Java-layer hit. Costs performance, worth it.
var JAVA_STACKS = true;

// Print a native backtrace (module+offset) for each native hit.
var NATIVE_BACKTRACE = true;

// Deduplicate: report each (function, argument) pair only once.
var DEDUPE = true;

// The pattern that decides "this argument is root-related".
var SUSPECT = new RegExp(
    [
        '(^|/)su$', '/su/', 'busybox', 'magisk', 'supersu', 'superuser',
        'daemonsu', 'kingroot', 'kinguser', 'luckypatcher', 'lackypatch',
        'rootcloak', 'xposed', 'substrate', 'lsposed', 'riru', 'zygisk',
        'frida', 'gum-js', 'gadget',
        '/sbin', '/data/adb', 'init\\.d', 'init\\.magisk',
        '/proc/self/(maps|mounts|status|mountinfo|cmdline)',
        '/proc/(mounts|net/unix|version|cmdline)',
        '/sys/fs/selinux',
        '/system/(bin|xbin)', '/vendor/bin', '/data/local',
        'test-keys', 'release-keys',
        '^ro\\.', '^service\\.adb', '^sys\\.oem', '^init\\.svc',
        'which', 'getenforce', 'mount', 'getprop', '\\bid\\b'
    ].join('|'), 'i');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var seen = {};

function interesting(s) {
    if (s === null || s === undefined) return false;
    if (!FILTER_NOISE) return true;
    return SUSPECT.test(String(s));
}

function once(key) {
    if (!DEDUPE) return true;
    if (seen[key]) return false;
    seen[key] = true;
    return true;
}

function javaStack() {
    if (!JAVA_STACKS) return '';
    try {
        var Log = Java.use('android.util.Log');
        var Exception = Java.use('java.lang.Exception');
        var raw = Log.getStackTraceString(Exception.$new());
        // Trim to the first few frames that are not Frida/runtime plumbing.
        var lines = raw.split('\n').filter(function (l) {
            return l.indexOf('at ') !== -1 &&
                   l.indexOf('java.lang.reflect') === -1 &&
                   l.indexOf('com.android.internal.os') === -1;
        });
        return '\n        <- ' + lines.slice(1, 5).join('\n        <- ');
    } catch (e) {
        return '';
    }
}

function nativeFrom(ctx) {
    if (!NATIVE_BACKTRACE) return '';
    try {
        var bt = Thread.backtrace(ctx, Backtracer.FUZZY).slice(0, 3);
        return bt.map(function (a) {
            var s = DebugSymbol.fromAddress(a);
            return s.moduleName ? (s.moduleName + '!' + (s.name || s.address)) : String(a);
        }).join(' <- ');
    } catch (e) {
        return '';
    }
}

function reportJava(fn, arg, result) {
    var key = 'J:' + fn + ':' + arg;
    if (!once(key)) return;
    var r = (result === undefined) ? '' : '  => ' + result;
    console.log('[J] ' + fn + '("' + arg + '")' + r + javaStack());
}

function reportNative(fn, arg, ctx, extra) {
    var key = 'N:' + fn + ':' + arg;
    if (!once(key)) return;
    console.log('[N] ' + fn + '("' + arg + '")' + (extra || '') +
                '\n        from ' + nativeFrom(ctx));
}

// ---------------------------------------------------------------------------
// Native layer
// ---------------------------------------------------------------------------

// Functions whose FIRST argument is a path.
var PATH_ARG0 = [
    'access', 'stat', 'stat64', 'lstat', 'lstat64', '__xstat', '__lxstat',
    'open', 'open64', 'fopen', 'fopen64', 'opendir', 'readlink', 'realpath',
    'chdir', 'unlink', 'chmod', 'statfs', 'statvfs'
];

// Functions whose SECOND argument is a path (the *at family takes a dirfd first).
var PATH_ARG1 = [
    'faccessat', 'openat', 'openat64', 'fstatat', 'fstatat64',
    'newfstatat', '__fxstatat', 'readlinkat', 'unlinkat', 'mkdirat'
];

// Functions whose first argument is a command string.
var CMD_ARG0 = ['system', 'popen', 'execl', 'execlp'];

function hookPathFn(name, argIndex) {
    var p = Module.findExportByName('libc.so', name);
    if (p === null) return;
    try {
        Interceptor.attach(p, {
            onEnter: function (args) {
                this.path = null;
                try { this.path = args[argIndex].readUtf8String(); } catch (e) { return; }
                this.ctx = this.context;
            },
            onLeave: function (retval) {
                if (!interesting(this.path)) return;
                reportNative(name, this.path, this.ctx, '  => ' + retval);
            }
        });
    } catch (e) {
        console.log('[!] could not hook ' + name + ': ' + e);
    }
}

function hookCmdFn(name) {
    var p = Module.findExportByName('libc.so', name);
    if (p === null) return;
    try {
        Interceptor.attach(p, {
            onEnter: function (args) {
                this.cmd = null;
                try { this.cmd = args[0].readUtf8String(); } catch (e) { return; }
                this.ctx = this.context;
            },
            onLeave: function (retval) {
                if (!interesting(this.cmd)) return;
                reportNative(name, this.cmd, this.ctx, '  => ' + retval);
            }
        });
    } catch (e) { }
}

function hookExecve() {
    var p = Module.findExportByName('libc.so', 'execve');
    if (p === null) return;
    Interceptor.attach(p, {
        onEnter: function (args) {
            var path = '';
            try { path = args[0].readUtf8String(); } catch (e) { return; }
            var argv = [];
            try {
                var a = args[1];
                for (var i = 0; i < 12; i++) {
                    var s = a.add(i * Process.pointerSize).readPointer();
                    if (s.isNull()) break;
                    argv.push(s.readUtf8String());
                }
            } catch (e) { }
            var joined = path + ' ' + argv.join(' ');
            if (interesting(joined)) {
                reportNative('execve', joined.trim(), this.context, '');
            }
        }
    });
}

function hookProperties() {
    var pget = Module.findExportByName('libc.so', '__system_property_get');
    if (pget !== null) {
        Interceptor.attach(pget, {
            onEnter: function (args) {
                this.key = null;
                try { this.key = args[0].readUtf8String(); } catch (e) { }
                this.out = args[1];
                this.ctx = this.context;
            },
            onLeave: function (retval) {
                if (!interesting(this.key)) return;
                var v = '';
                try { v = this.out.readUtf8String(); } catch (e) { }
                reportNative('__system_property_get', this.key, this.ctx, '  => "' + v + '"');
            }
        });
    }

    // Modern bionic frequently uses find + read_callback instead. If you see
    // hits here but none above, your spoofing hook must target this path.
    var pfind = Module.findExportByName('libc.so', '__system_property_find');
    if (pfind !== null) {
        Interceptor.attach(pfind, {
            onEnter: function (args) {
                this.key = null;
                try { this.key = args[0].readUtf8String(); } catch (e) { }
                this.ctx = this.context;
            },
            onLeave: function () {
                if (!interesting(this.key)) return;
                reportNative('__system_property_find', this.key, this.ctx, '');
            }
        });
    }
}

function installNativeHooks() {
    PATH_ARG0.forEach(function (n) { hookPathFn(n, 0); });
    PATH_ARG1.forEach(function (n) { hookPathFn(n, 1); });
    CMD_ARG0.forEach(hookCmdFn);
    hookExecve();
    hookProperties();
    console.log('[*] native hooks installed');
}

// Libraries loaded later must be caught as they arrive; more importantly,
// knowing WHICH library the app loads tells you where to point Ghidra.
function watchDlopen() {
    ['android_dlopen_ext', 'dlopen'].forEach(function (fn) {
        var p = Module.findExportByName(null, fn);
        if (p === null) return;
        Interceptor.attach(p, {
            onEnter: function (args) {
                this.path = null;
                try { this.path = args[0].readUtf8String(); } catch (e) { }
            },
            onLeave: function () {
                if (this.path && this.path.indexOf('.so') !== -1 &&
                    this.path.indexOf('/system/') !== 0) {
                    console.log('[L] ' + fn + '("' + this.path + '")  <-- app library, inspect this');
                }
            }
        });
    });
}

// ---------------------------------------------------------------------------
// Java layer
// ---------------------------------------------------------------------------

function installJavaHooks() {
    Java.perform(function () {

        // --- java.io.File ---------------------------------------------------
        var File = Java.use('java.io.File');
        ['exists', 'canRead', 'canWrite', 'canExecute', 'isDirectory', 'isFile'].forEach(
            function (m) {
                if (File[m] === undefined) return;
                File[m].implementation = function () {
                    var r = this[m]();
                    var p = this.getAbsolutePath();
                    if (interesting(p)) reportJava('File.' + m, p, r);
                    return r;
                };
            });
        File.listFiles.overload().implementation = function () {
            var r = this.listFiles();
            var p = this.getAbsolutePath();
            if (interesting(p)) reportJava('File.listFiles', p, r === null ? 'null' : 'array');
            return r;
        };

        // --- libcore Os (catches FileInputStream, Files, RandomAccessFile) ---
        try {
            var BlockGuardOs = Java.use('libcore.io.BlockGuardOs');
            BlockGuardOs.stat.implementation = function (path) {
                if (interesting(path)) reportJava('Os.stat', path);
                return this.stat(path);
            };
            BlockGuardOs.access.implementation = function (path, mode) {
                var r = this.access(path, mode);
                if (interesting(path)) reportJava('Os.access', path, r);
                return r;
            };
        } catch (e) { /* class layout differs on some versions */ }

        // --- process execution ----------------------------------------------
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var joined = '';
                for (var i = 0; i < arguments.length; i++) {
                    var a = arguments[i];
                    if (a === null || a === undefined) continue;
                    try {
                        joined += (typeof a === 'object' && a.length !== undefined)
                                ? Array.prototype.join.call(a, ' ')
                                : a.toString();
                    } catch (e) { }
                    joined += ' ';
                }
                reportJava('Runtime.exec', joined.trim());
                return ov.apply(this, arguments);
            };
        });

        var PB = Java.use('java.lang.ProcessBuilder');
        PB.start.implementation = function () {
            reportJava('ProcessBuilder.start', this.command().toString());
            return this.start();
        };

        // --- PackageManager ---------------------------------------------------
        var APM = Java.use('android.app.ApplicationPackageManager');
        ['getPackageInfo', 'getApplicationInfo'].forEach(function (m) {
            if (APM[m] === undefined) return;
            APM[m].overloads.forEach(function (ov) {
                ov.implementation = function (name) {
                    reportJava('PM.' + m, name === null ? 'null' : name.toString());
                    return ov.apply(this, arguments);
                };
            });
        });
        ['getInstalledPackages', 'getInstalledApplications'].forEach(function (m) {
            if (APM[m] === undefined) return;
            APM[m].overloads.forEach(function (ov) {
                ov.implementation = function () {
                    reportJava('PM.' + m, '(enumeration)');
                    return ov.apply(this, arguments);
                };
            });
        });

        // --- system properties -------------------------------------------------
        try {
            var SP = Java.use('android.os.SystemProperties');
            SP.get.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var r = ov.apply(this, arguments);
                    reportJava('SystemProperties.get', arguments[0].toString(), '"' + r + '"');
                    return r;
                };
            });
        } catch (e) { }

        // --- Settings.Global / Settings.Secure ----------------------------------
        ['android.provider.Settings$Global', 'android.provider.Settings$Secure'].forEach(
            function (cls) {
                try {
                    var C = Java.use(cls);
                    C.getInt.overloads.forEach(function (ov) {
                        ov.implementation = function () {
                            var r = ov.apply(this, arguments);
                            reportJava(cls.split('$')[1] + '.getInt',
                                       arguments[1].toString(), r);
                            return r;
                        };
                    });
                } catch (e) { }
            });

        // --- reading procfs via BufferedReader -----------------------------------
        // We do not hook readLine (too noisy). Instead we note the file being opened.
        var FIS = Java.use('java.io.FileInputStream');
        FIS.$init.overload('java.io.File').implementation = function (f) {
            var p = f.getAbsolutePath();
            if (interesting(p)) reportJava('new FileInputStream', p);
            return this.$init(f);
        };
        var FR = Java.use('java.io.FileReader');
        FR.$init.overload('java.lang.String').implementation = function (s) {
            if (interesting(s)) reportJava('new FileReader', s.toString());
            return this.$init(s);
        };

        // --- which native libraries exist ------------------------------------------
        var System = Java.use('java.lang.System');
        System.loadLibrary.implementation = function (name) {
            console.log('[L] System.loadLibrary("' + name + '")  <-- inspect lib' + name + '.so');
            return this.loadLibrary(name);
        };

        console.log('[*] Java hooks installed');
    });
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

console.log('');
console.log('=========================================================');
console.log(' root-check-tracer.js — observing, not bypassing');
console.log(' [J] Java-layer hit   [N] native hit   [L] library load');
console.log('=========================================================');
console.log('');

watchDlopen();
installNativeHooks();
installJavaHooks();

// Re-install native hooks a moment later: libraries loaded during onCreate may
// not have been mapped when the script first ran.
setTimeout(function () {
    console.log('[*] re-scanning for late-loaded libraries');
    installNativeHooks();
}, 3000);
