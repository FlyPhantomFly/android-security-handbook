/*
 * root-detection-bypass.js — neutralise Android root / tamper detection.
 *
 * WHAT IT DOES
 *   Root detection is never one check. A serious implementation stacks a dozen
 *   independent probes, and a bypass that handles only the famous one (File.exists
 *   on /system/xbin/su) fails on the second probe. This script covers the
 *   categories that actually appear in shipped apps:
 *
 *     A. Filesystem probes        java.io.File.exists/canRead/isFile,
 *                                 native stat/lstat/access/fopen/open
 *     B. Command execution        Runtime.exec, ProcessBuilder, native system/popen
 *     C. Package queries          getPackageInfo, getInstalledPackages, queryIntent*
 *     D. System properties        SystemProperties.get, native __system_property_get,
 *                                 Build.TAGS containing "test-keys"
 *     E. Mount / partition state  reading /proc/mounts for rw on /system
 *     F. Native library presence  dlopen of Magisk/Zygisk artefacts
 *     G. Debug / instrumentation  Debug.isDebuggerConnected, TracerPid,
 *                                 ApplicationInfo.FLAG_DEBUGGABLE
 *     H. Library helpers          RootBeer and similar third-party detectors
 *
 *   Every hook is guarded and reported. Classes and symbols that do not exist
 *   on this device are skipped, not fatal.
 *
 * WHY IT WORKS
 *   Every one of these checks executes inside a process the analyst controls.
 *   See ../README.md section 5 and ../../37-RootDetection/README.md for the
 *   full argument, and ../../38-TamperDetection/README.md for the integrity
 *   checks that often accompany them.
 *
 * HOW TO RUN
 *   adb shell cmd package compile -m verify -f com.example.app
 *   adb shell am force-stop com.example.app
 *
 *   # MUST be spawned with -f: most detection runs in attachBaseContext,
 *   # before any Activity exists (see ../README.md section 7.4.4).
 *   frida -U -f com.example.app -l root-detection-bypass.js --no-pause
 *
 * DIAGNOSING WHAT THE APP ACTUALLY CHECKS
 *   Set OBSERVE_ONLY = true. Nothing is faked; every probe is logged with a
 *   Java stack trace so you can see which class is asking and why. Run once in
 *   observe mode, read the output, then switch it off. This is far faster than
 *   guessing.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var OBSERVE_ONLY = false;   /* true = log probes, fake nothing */
var VERBOSE      = true;    /* per-probe logging */
var SHOW_STACKS  = false;   /* Java stack trace on every probe — noisy but decisive */

/* ------------------------------------------------------------------ config */

var ROOT_PATH_TOKENS = [
    'su', 'busybox', 'magisk', 'magiskhide', 'magiskinit', 'magiskpolicy',
    'supersu', 'superuser', 'daemonsu', 'ksud', 'kernelsu',
    'xposed', 'substrate', 'frida', 'riru', 'zygisk',
    '/system/app/Superuser.apk', '/system/etc/init.d',
    '.topjohnwu', 'com.noshufou', 'eu.chainfire', 'com.thirdparty.superuser',
    'RootCloak', 'com.saurik'
];

var ROOT_PACKAGES = [
    'com.topjohnwu.magisk', 'com.noshufou.android.su', 'com.noshufou.android.su.elite',
    'eu.chainfire.supersu', 'com.koushikdutta.superuser', 'com.thirdparty.superuser',
    'com.yellowes.su', 'com.zachspong.temprootremovejb', 'com.ramdroid.appquarantine',
    'com.koushikdutta.rommanager', 'com.dimonvideo.luckypatcher',
    'com.chelpus.lackypatch', 'com.android.vending.billing.InAppBillingService.COIN',
    'de.robv.android.xposed.installer', 'me.weishu.kernelsu', 'io.github.huskydg.magisk'
];

var ROOT_COMMANDS = [
    'su', 'which su', 'busybox', 'which busybox', 'id', 'mount',
    'getprop ro.debuggable', 'getprop ro.secure', 'magisk', 'which magisk'
];

var DANGEROUS_PROPS = {
    'ro.debuggable':        '0',
    'ro.secure':            '1',
    'ro.build.selinux':     '1',
    'ro.build.type':        'user',
    'ro.build.tags':        'release-keys',
    'ro.boot.veritymode':   'enforcing',
    'ro.boot.verifiedbootstate': 'green',
    'ro.boot.flash.locked': '1',
    'service.adb.root':     '0',
    'ro.adb.secure':        '1',
    'sys.oem_unlock_allowed': '0',
    'init.svc.magisk':      '',
    'init.svc.su':          ''
};

/* ------------------------------------------------------------------ utility */

var installed = 0;
var skipped = [];

function ok(what) { installed++; console.log('[+] ' + what); }
function no(what, why) { skipped.push(what); if (VERBOSE) console.log('[.] skip ' + what + ' (' + why + ')'); }
function hit(what) { if (VERBOSE) console.log('    [probe] ' + what + (OBSERVE_ONLY ? ' (OBSERVED, not faked)' : ' -> FAKED')); }

function tryUse(name) {
    try { return Java.use(name); } catch (e) { return null; }
}

/* Frida 16/17 compatible export resolution. A null result is normal. */
function resolveExport(moduleName, symbolName) {
    try {
        if (moduleName === null && typeof Module.getGlobalExportByName === 'function') {
            return Module.getGlobalExportByName(symbolName);
        }
    } catch (e) { /* fall through */ }
    try {
        if (moduleName !== null && typeof Process.findModuleByName === 'function') {
            var m = Process.findModuleByName(moduleName);
            if (m !== null && typeof m.findExportByName === 'function') {
                var a = m.findExportByName(symbolName);
                if (a !== null) return a;
            }
        }
    } catch (e) { /* fall through */ }
    try { return Module.findExportByName(moduleName, symbolName); }
    catch (e) { return null; }
}

function looksRooty(s) {
    if (s === null || s === undefined) return false;
    var lower = String(s).toLowerCase();
    for (var i = 0; i < ROOT_PATH_TOKENS.length; i++) {
        var t = ROOT_PATH_TOKENS[i].toLowerCase();
        // Guard against the single-letter false positives: "su" must be a path
        // component, not a substring of "issue" or "usurp".
        if (t === 'su' || t === 'id') {
            if (/(^|\/)su($|\/)/.test(lower)) return true;
            continue;
        }
        if (lower.indexOf(t) !== -1) return true;
    }
    return false;
}

function javaStack() {
    if (!SHOW_STACKS) return '';
    try {
        return '\n' + Java.use('android.util.Log')
            .getStackTraceString(Java.use('java.lang.Exception').$new());
    } catch (e) { return ''; }
}

/* =========================================================================
 * A. FILESYSTEM PROBES — Java side
 * ========================================================================= */

function categoryA_javaFilesystem() {
    var File = tryUse('java.io.File');
    if (File === null) { no('java.io.File', 'missing'); return; }

    ['exists', 'canRead', 'canExecute', 'isFile', 'isDirectory'].forEach(function (m) {
        if (File[m] === undefined) return;
        try {
            (File[m].overloads || [File[m]]).forEach(function (ov) {
                ov.implementation = function () {
                    var path;
                    try { path = this.getAbsolutePath(); } catch (e) { path = '?'; }
                    if (looksRooty(path)) {
                        hit('File.' + m + '(' + path + ')' + javaStack());
                        if (!OBSERVE_ONLY) return false;
                    }
                    return ov.apply(this, arguments);
                };
            });
            ok('A: java.io.File.' + m);
        } catch (e) { no('java.io.File.' + m, e.message); }
    });

    // FileInputStream / FileReader constructors throw FileNotFoundException for
    // a non-existent file; apps use the exception itself as the signal.
    var FIS = tryUse('java.io.FileInputStream');
    if (FIS !== null) {
        try {
            (FIS.$init.overloads || []).forEach(function (ov) {
                var types = ov.argumentTypes.map(function (t) { return t.className; });
                if (types.length !== 1) return;
                ov.implementation = function (arg) {
                    var p = String(arg);
                    if (looksRooty(p)) {
                        hit('new FileInputStream(' + p + ')');
                        if (!OBSERVE_ONLY) {
                            throw Java.use('java.io.FileNotFoundException')
                                .$new(p + ': open failed: ENOENT (No such file or directory)');
                        }
                    }
                    return ov.apply(this, arguments);
                };
            });
            ok('A: java.io.FileInputStream.<init>');
        } catch (e) { no('FileInputStream.<init>', e.message); }
    }
}

/* =========================================================================
 * A'. FILESYSTEM PROBES — native side
 *
 * A native check calls stat/access/fopen directly and never touches java.io.
 * Hooking only the Java layer therefore misses it entirely, which is the most
 * common reason a "working" bypass fails against a hardened app.
 * ========================================================================= */

function categoryA_nativeFilesystem() {
    // Each entry: [symbol, index of the path argument, return value meaning "absent"]
    var probes = [
        ['stat',    0, -1],
        ['stat64',  0, -1],
        ['lstat',   0, -1],
        ['lstat64', 0, -1],
        ['access',  0, -1],
        ['faccessat', 1, -1],
        ['open',    0, -1],
        ['openat',  1, -1],
        ['fopen',   0,  0],
        ['opendir', 0,  0],
        ['readlink', 0, -1]
    ];

    probes.forEach(function (p) {
        var name = p[0], argIdx = p[1], failValue = p[2];
        var addr = resolveExport('libc.so', name);
        if (addr === null) { no('libc!' + name, 'not exported'); return; }

        try {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    this.fake = false;
                    try {
                        var pathPtr = args[argIdx];
                        if (pathPtr.isNull()) return;
                        var path = pathPtr.readCString();
                        if (looksRooty(path)) {
                            this.path = path;
                            this.fake = true;
                        }
                    } catch (e) { /* unreadable pointer */ }
                },
                onLeave: function (retval) {
                    if (!this.fake) return;
                    hit('libc!' + name + '(' + this.path + ')');
                    if (!OBSERVE_ONLY) {
                        retval.replace(ptr(failValue));
                        // Set errno to ENOENT so a caller that checks it is satisfied.
                        var errnoLoc = resolveExport('libc.so', '__errno');
                        if (errnoLoc !== null) {
                            try {
                                var f = new NativeFunction(errnoLoc, 'pointer', []);
                                f().writeS32(2);            // ENOENT
                            } catch (e) { /* best effort */ }
                        }
                    }
                }
            });
            ok('A: libc!' + name);
        } catch (e) { no('libc!' + name, e.message); }
    });
}

/* =========================================================================
 * B. COMMAND EXECUTION
 * ========================================================================= */

function categoryB_exec() {
    var Runtime = tryUse('java.lang.Runtime');
    if (Runtime !== null && Runtime.exec !== undefined) {
        try {
            (Runtime.exec.overloads || []).forEach(function (ov) {
                ov.implementation = function () {
                    var cmd = '';
                    try {
                        var a0 = arguments[0];
                        cmd = (a0 !== null && a0.length !== undefined && typeof a0 !== 'string')
                            ? Java.array('java.lang.String', a0).join(' ')
                            : String(a0);
                    } catch (e) { cmd = String(arguments[0]); }

                    var isRootCmd = ROOT_COMMANDS.some(function (c) {
                        return cmd === c || cmd.indexOf(c + ' ') === 0 || looksRooty(cmd);
                    });

                    if (isRootCmd) {
                        hit('Runtime.exec(' + cmd + ')' + javaStack());
                        if (!OBSERVE_ONLY) {
                            throw Java.use('java.io.IOException')
                                .$new('Cannot run program "' + cmd +
                                      '": error=2, No such file or directory');
                        }
                    }
                    return ov.apply(this, arguments);
                };
            });
            ok('B: java.lang.Runtime.exec (' + Runtime.exec.overloads.length + ' overloads)');
        } catch (e) { no('Runtime.exec', e.message); }
    }

    var PB = tryUse('java.lang.ProcessBuilder');
    if (PB !== null) {
        try {
            PB.start.implementation = function () {
                var cmd = '';
                try { cmd = this.command().toString(); } catch (e) { /* ignore */ }
                if (looksRooty(cmd) || ROOT_COMMANDS.some(function (c) { return cmd.indexOf(c) !== -1; })) {
                    hit('ProcessBuilder.start(' + cmd + ')' + javaStack());
                    if (!OBSERVE_ONLY) {
                        throw Java.use('java.io.IOException')
                            .$new('error=2, No such file or directory');
                    }
                }
                return this.start();
            };
            ok('B: java.lang.ProcessBuilder.start');
        } catch (e) { no('ProcessBuilder.start', e.message); }
    }

    // Native equivalents. system() and popen() are the C-level route.
    [['system', 0], ['popen', 0], ['execve', 0], ['execl', 0], ['execvp', 0]]
        .forEach(function (p) {
            var addr = resolveExport('libc.so', p[0]);
            if (addr === null) { no('libc!' + p[0], 'not exported'); return; }
            try {
                Interceptor.attach(addr, {
                    onEnter: function (args) {
                        this.fake = false;
                        try {
                            var s = args[p[1]].readCString();
                            if (s !== null && looksRooty(s)) {
                                this.cmd = s;
                                this.fake = true;
                            }
                        } catch (e) { /* ignore */ }
                    },
                    onLeave: function (retval) {
                        if (!this.fake) return;
                        hit('libc!' + p[0] + '(' + this.cmd + ')');
                        if (!OBSERVE_ONLY) retval.replace(ptr(-1));
                    }
                });
                ok('B: libc!' + p[0]);
            } catch (e) { no('libc!' + p[0], e.message); }
        });
}

/* =========================================================================
 * C. PACKAGE QUERIES
 * ========================================================================= */

function categoryC_packages() {
    var PM = tryUse('android.app.ApplicationPackageManager');
    if (PM === null) { no('ApplicationPackageManager', 'missing'); return; }

    if (PM.getPackageInfo !== undefined) {
        try {
            (PM.getPackageInfo.overloads || []).forEach(function (ov) {
                ov.implementation = function () {
                    var pkg = String(arguments[0]);
                    if (ROOT_PACKAGES.indexOf(pkg) !== -1 || looksRooty(pkg)) {
                        hit('getPackageInfo(' + pkg + ')' + javaStack());
                        if (!OBSERVE_ONLY) {
                            throw Java.use('android.content.pm.PackageManager$NameNotFoundException')
                                .$new(pkg);
                        }
                    }
                    return ov.apply(this, arguments);
                };
            });
            ok('C: getPackageInfo');
        } catch (e) { no('getPackageInfo', e.message); }
    }

    if (PM.getInstalledPackages !== undefined) {
        try {
            (PM.getInstalledPackages.overloads || []).forEach(function (ov) {
                ov.implementation = function () {
                    var list = ov.apply(this, arguments);
                    if (OBSERVE_ONLY) return list;
                    try {
                        // Filter the returned List<PackageInfo> in place.
                        var it = list.iterator();
                        var removed = 0;
                        var ArrayList = Java.use('java.util.ArrayList');
                        var filtered = ArrayList.$new();
                        while (it.hasNext()) {
                            var pi = Java.cast(it.next(), Java.use('android.content.pm.PackageInfo'));
                            var name = String(pi.packageName.value);
                            if (ROOT_PACKAGES.indexOf(name) !== -1 || looksRooty(name)) {
                                removed++;
                                continue;
                            }
                            filtered.add(pi);
                        }
                        if (removed > 0) hit('getInstalledPackages: removed ' + removed);
                        return filtered;
                    } catch (e) {
                        return list;
                    }
                };
            });
            ok('C: getInstalledPackages');
        } catch (e) { no('getInstalledPackages', e.message); }
    }

    if (PM.getInstalledApplications !== undefined) {
        try {
            (PM.getInstalledApplications.overloads || []).forEach(function (ov) {
                ov.implementation = function () {
                    var list = ov.apply(this, arguments);
                    if (OBSERVE_ONLY) return list;
                    try {
                        var ArrayList = Java.use('java.util.ArrayList');
                        var AppInfo = Java.use('android.content.pm.ApplicationInfo');
                        var filtered = ArrayList.$new();
                        var it = list.iterator();
                        while (it.hasNext()) {
                            var ai = Java.cast(it.next(), AppInfo);
                            var n = String(ai.packageName.value);
                            if (ROOT_PACKAGES.indexOf(n) === -1 && !looksRooty(n)) filtered.add(ai);
                        }
                        return filtered;
                    } catch (e) { return list; }
                };
            });
            ok('C: getInstalledApplications');
        } catch (e) { no('getInstalledApplications', e.message); }
    }
}

/* =========================================================================
 * D. SYSTEM PROPERTIES
 * ========================================================================= */

function categoryD_properties() {
    var SP = tryUse('android.os.SystemProperties');
    if (SP !== null && SP.get !== undefined) {
        try {
            (SP.get.overloads || []).forEach(function (ov) {
                ov.implementation = function () {
                    var key = String(arguments[0]);
                    if (DANGEROUS_PROPS.hasOwnProperty(key)) {
                        hit('SystemProperties.get(' + key + ')');
                        if (!OBSERVE_ONLY) return DANGEROUS_PROPS[key];
                    }
                    return ov.apply(this, arguments);
                };
            });
            ok('D: SystemProperties.get');
        } catch (e) { no('SystemProperties.get', e.message); }
    }

    // Build.TAGS is a public static field; overwrite it directly.
    var Build = tryUse('android.os.Build');
    if (Build !== null && !OBSERVE_ONLY) {
        try {
            var tags = String(Build.TAGS.value);
            if (tags.indexOf('test-keys') !== -1) {
                Build.TAGS.value = 'release-keys';
                ok('D: Build.TAGS "' + tags + '" -> "release-keys"');
            } else {
                no('Build.TAGS', 'already ' + tags);
            }
        } catch (e) { no('Build.TAGS', e.message); }
    }

    // Native property reader — used by every native detector.
    var pget = resolveExport('libc.so', '__system_property_get');
    if (pget !== null) {
        try {
            Interceptor.attach(pget, {
                onEnter: function (args) {
                    this.key = null;
                    this.out = args[1];
                    try { this.key = args[0].readCString(); } catch (e) { /* ignore */ }
                },
                onLeave: function (retval) {
                    if (this.key === null) return;
                    if (!DANGEROUS_PROPS.hasOwnProperty(this.key)) return;
                    hit('__system_property_get(' + this.key + ')');
                    if (OBSERVE_ONLY) return;
                    try {
                        var v = DANGEROUS_PROPS[this.key];
                        this.out.writeUtf8String(v);
                        retval.replace(ptr(v.length));
                    } catch (e) { /* best effort */ }
                }
            });
            ok('D: libc!__system_property_get');
        } catch (e) { no('__system_property_get', e.message); }
    }
}

/* =========================================================================
 * E. MOUNT / PARTITION STATE
 *
 * Reading /proc/mounts and looking for "/system ... rw" is a classic probe.
 * We cannot rewrite the file, but we can make the OPEN fail, which most
 * implementations treat as "cannot determine, assume clean".
 * ========================================================================= */

function categoryE_mounts() {
    var SENSITIVE_FILES = ['/proc/mounts', '/proc/self/mounts', '/proc/self/mountinfo'];

    var BufferedReader = tryUse('java.io.BufferedReader');
    if (BufferedReader !== null) {
        try {
            BufferedReader.readLine.overload().implementation = function () {
                var line = this.readLine();
                if (line === null) return null;
                var s = String(line);
                // Hide rw-mounted system partitions and any magisk overlay.
                if (!OBSERVE_ONLY &&
                    (/\s(\/system|\/vendor)\s.*\brw\b/.test(s) ||
                     /magisk|KSU|overlay.*system/i.test(s))) {
                    hit('BufferedReader.readLine hid: ' + s.substring(0, 80));
                    return this.readLine();          // skip this line entirely
                }
                return line;
            };
            ok('E: BufferedReader.readLine (mount + status filtering)');
        } catch (e) { no('BufferedReader.readLine', e.message); }
    }
}

/* =========================================================================
 * F. NATIVE LIBRARY PRESENCE — dlopen probing
 * ========================================================================= */

function categoryF_dlopen() {
    ['android_dlopen_ext', 'dlopen', '__dl_dlopen'].forEach(function (sym) {
        var addr = resolveExport(null, sym) || resolveExport('libdl.so', sym);
        if (addr === null) { no(sym, 'not exported'); return; }
        try {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    this.fake = false;
                    try {
                        var p = args[0].isNull() ? null : args[0].readCString();
                        if (p !== null && looksRooty(p)) { this.path = p; this.fake = true; }
                    } catch (e) { /* ignore */ }
                },
                onLeave: function (retval) {
                    if (!this.fake) return;
                    hit(sym + '(' + this.path + ')');
                    if (!OBSERVE_ONLY) retval.replace(ptr(0));   // NULL = load failed
                }
            });
            ok('F: ' + sym);
        } catch (e) { no(sym, e.message); }
    });
}

/* =========================================================================
 * G. DEBUG / INSTRUMENTATION DETECTION
 * ========================================================================= */

function categoryG_debug() {
    var Debug = tryUse('android.os.Debug');
    if (Debug !== null) {
        ['isDebuggerConnected', 'waitingForDebugger'].forEach(function (m) {
            if (Debug[m] === undefined) return;
            try {
                Debug[m].implementation = function () {
                    hit('Debug.' + m + '()');
                    return OBSERVE_ONLY ? this[m]() : false;
                };
                ok('G: Debug.' + m);
            } catch (e) { no('Debug.' + m, e.message); }
        });
    }

    // ApplicationInfo.FLAG_DEBUGGABLE (0x2) in the app's own flags.
    var AI = tryUse('android.content.pm.ApplicationInfo');
    if (AI !== null && !OBSERVE_ONLY) {
        try {
            var Context = tryUse('android.content.Context');
            // The flags field is read directly, so patch it on the live object
            // when the app asks for its own ApplicationInfo.
            var PM = tryUse('android.app.ApplicationPackageManager');
            if (PM !== null && PM.getApplicationInfo !== undefined) {
                (PM.getApplicationInfo.overloads || []).forEach(function (ov) {
                    ov.implementation = function () {
                        var info = ov.apply(this, arguments);
                        try {
                            var f = info.flags.value;
                            if ((f & 0x2) !== 0) {
                                hit('ApplicationInfo.FLAG_DEBUGGABLE cleared');
                                info.flags.value = f & ~0x2;
                            }
                        } catch (e) { /* ignore */ }
                        return info;
                    };
                });
                ok('G: ApplicationInfo.FLAG_DEBUGGABLE');
            }
        } catch (e) { no('ApplicationInfo flags', e.message); }
    }

    // ptrace(PTRACE_TRACEME) self-protection and TracerPid reads are covered
    // in ../../67-BypassingProtections/README.md. Neutralise the syscall here.
    var ptraceAddr = resolveExport('libc.so', 'ptrace');
    if (ptraceAddr !== null) {
        try {
            Interceptor.attach(ptraceAddr, {
                onEnter: function (args) {
                    this.request = args[0].toInt32();
                },
                onLeave: function (retval) {
                    // PTRACE_TRACEME == 0. An app calling it is trying to occupy
                    // the tracer slot so nothing else can attach.
                    if (this.request === 0) {
                        hit('ptrace(PTRACE_TRACEME)');
                        if (!OBSERVE_ONLY) retval.replace(ptr(0));  // pretend success
                    }
                }
            });
            ok('G: libc!ptrace');
        } catch (e) { no('libc!ptrace', e.message); }
    }
}

/* =========================================================================
 * H. THIRD-PARTY DETECTION LIBRARIES
 * ========================================================================= */

function categoryH_libraries() {
    // RootBeer — by far the most common off-the-shelf detector.
    var RootBeer = tryUse('com.scottyab.rootbeer.RootBeer');
    if (RootBeer !== null) {
        var methods = [
            'isRooted', 'isRootedWithoutBusyBoxCheck', 'detectRootManagementApps',
            'detectPotentiallyDangerousApps', 'detectTestKeys', 'checkForBusyBoxBinary',
            'checkForSuBinary', 'checkSuExists', 'checkForRWPaths',
            'checkForDangerousProps', 'checkForRootNative', 'detectRootCloakingApps',
            'checkForMagiskBinary'
        ];
        var count = 0;
        methods.forEach(function (m) {
            if (RootBeer[m] === undefined) return;
            try {
                (RootBeer[m].overloads || [RootBeer[m]]).forEach(function (ov) {
                    ov.implementation = function () {
                        hit('RootBeer.' + m + '()');
                        return OBSERVE_ONLY ? ov.apply(this, arguments) : false;
                    };
                });
                count++;
            } catch (e) { /* skip */ }
        });
        if (count > 0) ok('H: RootBeer (' + count + ' methods)');
    } else {
        no('RootBeer', 'not present');
    }

    // RootTools / Stericson
    var RootTools = tryUse('com.stericson.RootTools.RootTools');
    if (RootTools !== null) {
        try {
            if (RootTools.isRootAvailable !== undefined) {
                RootTools.isRootAvailable.implementation = function () {
                    hit('RootTools.isRootAvailable()');
                    return OBSERVE_ONLY ? this.isRootAvailable() : false;
                };
                ok('H: RootTools.isRootAvailable');
            }
        } catch (e) { no('RootTools', e.message); }
    }

    // SafetyNet / Play Integrity helper classes cannot be meaningfully faked
    // client-side because the verdict is signed by Google and checked by the
    // app's server. Detect and REPORT rather than pretending.
    ['com.google.android.gms.safetynet.SafetyNetClient',
     'com.google.android.play.core.integrity.IntegrityManager']
        .forEach(function (n) {
            if (tryUse(n) !== null) {
                console.log('[!] DETECTED ' + n);
                console.log('    This produces a SERVER-VERIFIED verdict. A client-side hook');
                console.log('    changes what the app sees, not what the server is told.');
                console.log('    See ../../50-HardwareBackedSecurity/README.md.');
            }
        });
}

/* ------------------------------------------------------------- bootstrap */

Java.perform(function () {
    console.log('');
    console.log('==================================================');
    console.log('  root-detection-bypass.js');
    console.log('  mode: ' + (OBSERVE_ONLY ? 'OBSERVE ONLY (nothing faked)' : 'ACTIVE'));
    console.log('==================================================');
    console.log('');

    categoryA_javaFilesystem();
    categoryA_nativeFilesystem();
    categoryB_exec();
    categoryC_packages();
    categoryD_properties();
    categoryE_mounts();
    categoryF_dlopen();
    categoryG_debug();
    categoryH_libraries();

    console.log('');
    console.log('[*] ' + installed + ' hook(s) installed, ' + skipped.length + ' skipped.');
    if (OBSERVE_ONLY) {
        console.log('[*] OBSERVE mode: probes are logged but NOT faked.');
        console.log('    Read the output, then set OBSERVE_ONLY = false.');
    }
    console.log('[*] If the app still detects root:');
    console.log('    - set SHOW_STACKS = true to see WHICH class is probing');
    console.log('    - re-run with OBSERVE_ONLY = true to enumerate every probe');
    console.log('    - the check may be entirely native: use native-tracer.js');
    console.log('');
});
