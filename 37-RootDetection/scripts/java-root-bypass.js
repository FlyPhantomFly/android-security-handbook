/*
 * java-root-bypass.js
 * ---------------------------------------------------------------------------
 * PURPOSE
 *   Neutralise every root-detection technique that is implemented in the
 *   Java/Kotlin layer of an Android application, for AUTHORISED testing.
 *
 *   This covers, in one script:
 *     - java.io.File existence / readability / writability probes
 *     - libcore.io.BlockGuardOs stat/access (catches FileInputStream, Files,
 *       RandomAccessFile, FileReader — every Java filesystem API, not just File)
 *     - Runtime.exec and ProcessBuilder.start for "which su" / "su -c id"
 *     - ApplicationPackageManager lookups and enumerations for root managers
 *     - android.os.Build fields (TAGS, FINGERPRINT, TYPE)
 *     - android.os.SystemProperties reads
 *     - Settings.Global adb_enabled / development_settings_enabled
 *     - BufferedReader line filtering for /proc/<pid>/mounts style checks
 *       (written with <pid> rather than a glob because the glob's slash-star
 *       would close this block comment)
 *     - The RootBeer library's public surface
 *
 *   It does NOT cover checks implemented in native code. If this script has no
 *   effect, the check is native: use native-root-bypass.js. If you do not know
 *   which it is, run root-check-tracer.js first — that is always the right
 *   first move.
 *
 * USAGE
 *   # host — SPAWN, do not attach. Most checks run in Application.onCreate,
 *   # which has already completed by the time an attach succeeds.
 *   frida -U -f com.target.app -l java-root-bypass.js --no-pause
 *
 *   # Combine with the native script when both layers are in play:
 *   frida -U -f com.target.app -l java-root-bypass.js -l native-root-bypass.js --no-pause
 *
 * DESIGN NOTES
 *   - Hooks are SURGICAL, not blanket. Returning false from every File.exists()
 *     breaks apps in ways that look exactly like the root check firing, and you
 *     will waste an hour debugging your own script. Only paths matching SUSPECT
 *     are lied about.
 *   - Failures are made to look NATURAL: File.exists returns false,
 *     getPackageInfo throws NameNotFoundException, Runtime.exec throws
 *     IOException. This is what the framework genuinely does when the artefact
 *     is absent, so the app's existing error handling copes.
 *   - Every lie is logged, so you can see exactly what the app asked for and
 *     build a picture of the check while you bypass it.
 *
 * AUTHORISATION
 *   Use only on applications you own or are contracted to assess.
 * ---------------------------------------------------------------------------
 */

'use strict';

// ---------------------------------------------------------------------------
// Configuration — tune these to the target
// ---------------------------------------------------------------------------

var VERBOSE = true;

// Paths we deny the existence of.
var SUSPECT_PATH = new RegExp(
    [
        '(^|/)su$', '/su/bin', '(^|/)busybox$', '(^|/)daemonsu$',
        'magisk', 'supersu', 'superuser', 'zygisk', 'riru', 'lsposed', 'xposed',
        'substrate', 'frida', 'gum-js', 'gadget', 're\\.frida',
        '^/sbin(/|$)', '^/data/adb', 'init\\.d', 'init\\.magisk',
        '/system/app/Superuser', '/system/etc/init\\.d',
        '/dev/com\\.koushikdutta', '/cache/magisk', '/cache/su',
        '/system/xbin/su', '/system/bin/su', '/system/bin/\\.ext',
        '/system/usr/we-need-root', '/system/sd/xbin'
    ].join('|'), 'i');

// Commands we refuse to run.
var SUSPECT_CMD = new RegExp(
    [
        '(^|\\s|/)su(\\s|$)', 'which\\s+su', 'busybox', 'magisk',
        'getprop', 'getenforce', '\\bmount\\b', '\\bid\\b'
    ].join('|'), 'i');

// Packages we claim are not installed.
var SUSPECT_PKGS = [
    'com.topjohnwu.magisk', 'com.topjohnwu.magisk.debug',
    'eu.chainfire.supersu', 'eu.chainfire.supersu.pro',
    'com.noshufou.android.su', 'com.noshufou.android.su.elite',
    'com.koushikdutta.superuser', 'com.thirdparty.superuser',
    'com.yellowes.su', 'com.zachspong.temprootremovejb',
    'com.ramdroid.appquarantine', 'com.ramdroid.appquarantinepro',
    'com.devadvance.rootcloak', 'com.devadvance.rootcloakplus',
    'de.robv.android.xposed.installer', 'org.lsposed.manager',
    'com.saurik.substrate', 'com.amphoras.hidemyroot',
    'com.amphoras.hidemyrootadfree', 'com.formyhm.hideroot',
    'com.formyhm.hiderootPremium',
    'com.dimonvideo.luckypatcher', 'com.chelpus.lackypatch',
    'com.android.vending.billing.InAppBillingService.LACK',
    'com.android.vending.billing.InAppBillingService.LOCK',
    'com.kingroot.kinguser', 'com.kingo.root', 'com.smedialink.oneclickroot',
    'com.zhiqupk.root.global', 'com.alephzain.framaroot',
    'com.baidu.easyroot', 'com.gmail.heagoo.pmaster',
    'me.phh.superuser', 'com.blackmartalpha', 'org.blackmart.market'
];

// Property values we substitute.
var SAFE_PROPS = {
    'ro.build.tags': 'release-keys',
    'ro.build.type': 'user',
    'ro.debuggable': '0',
    'ro.secure': '1',
    'ro.build.selinux': '1',
    'ro.boot.verifiedbootstate': 'green',
    'ro.boot.flash.locked': '1',
    'ro.boot.veritymode': 'enforcing',
    'ro.boot.vbmeta.device_state': 'locked',
    'ro.boot.warranty_bit': '0',
    'ro.warranty_bit': '0',
    'sys.oem_unlock_allowed': '0',
    'service.adb.root': '',
    'init.svc.magisk': '',
    'init.svc.magiskd': '',
    'ro.bootmode': 'unknown',
    'ro.boot.mode': 'unknown'
};

// Lines dropped from /proc/*/mounts style reads.
var SUSPECT_LINE = new RegExp(
    ['magisk', '/data/adb', 'tmpfs\\s+/sbin', 'overlay\\s+/system',
     'overlayfs', '\\bsu\\b', 'zygisk', 'riru', 'lsposed', 'frida',
     'KSU', 'kernelsu'].join('|'), 'i');

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

var hits = {};

function log(msg) {
    if (VERBOSE) console.log('[java-bypass] ' + msg);
}

function note(category) {
    hits[category] = (hits[category] || 0) + 1;
}

function summary() {
    console.log('');
    console.log('---- bypass summary ------------------------------------');
    Object.keys(hits).sort().forEach(function (k) {
        console.log('  ' + k + ': ' + hits[k] + ' intercepted');
    });
    console.log('--------------------------------------------------------');
}

// ---------------------------------------------------------------------------
// 1. Filesystem — java.io.File
// ---------------------------------------------------------------------------

function hookFile() {
    var File = Java.use('java.io.File');

    File.exists.implementation = function () {
        var p = this.getAbsolutePath();
        if (SUSPECT_PATH.test(p)) {
            log('File.exists("' + p + '") -> false');
            note('File.exists');
            return false;
        }
        return this.exists();
    };

    File.canRead.implementation = function () {
        var p = this.getAbsolutePath();
        if (SUSPECT_PATH.test(p)) { note('File.canRead'); return false; }
        return this.canRead();
    };

    File.canExecute.implementation = function () {
        var p = this.getAbsolutePath();
        if (SUSPECT_PATH.test(p)) { note('File.canExecute'); return false; }
        return this.canExecute();
    };

    // Writability of system partitions is a separate check (see chapter 3.6).
    var RO_DIRS = /^\/(system|vendor|product|system_ext|odm|sbin|etc|apex)(\/|$)|^\/$/;
    File.canWrite.implementation = function () {
        var p = this.getAbsolutePath();
        if (RO_DIRS.test(p) || SUSPECT_PATH.test(p)) {
            log('File.canWrite("' + p + '") -> false');
            note('File.canWrite');
            return false;
        }
        return this.canWrite();
    };

    File.isDirectory.implementation = function () {
        var p = this.getAbsolutePath();
        if (SUSPECT_PATH.test(p)) { note('File.isDirectory'); return false; }
        return this.isDirectory();
    };

    File.isFile.implementation = function () {
        var p = this.getAbsolutePath();
        if (SUSPECT_PATH.test(p)) { note('File.isFile'); return false; }
        return this.isFile();
    };

    File.length.implementation = function () {
        var p = this.getAbsolutePath();
        if (SUSPECT_PATH.test(p)) { note('File.length'); return 0; }
        return this.length();
    };

    // Directory listings: strip suspicious entries rather than returning null,
    // because null makes some checks conclude "cannot read => suspicious".
    File.listFiles.overload().implementation = function () {
        var r = this.listFiles();
        if (r === null) return r;
        var p = this.getAbsolutePath();
        if (!/^\/(system|sbin|data\/local|data\/adb|vendor)/.test(p)) return r;
        var kept = [];
        for (var i = 0; i < r.length; i++) {
            if (!SUSPECT_PATH.test(r[i].getAbsolutePath())) kept.push(r[i]);
        }
        if (kept.length !== r.length) {
            log('File.listFiles("' + p + '") filtered ' + (r.length - kept.length));
            note('File.listFiles');
        }
        return Java.array('java.io.File', kept);
    };

    log('java.io.File hooked');
}

// ---------------------------------------------------------------------------
// 2. Filesystem — the layer below File, which catches every other Java API
// ---------------------------------------------------------------------------

function hookLibcoreOs() {
    try {
        var BlockGuardOs = Java.use('libcore.io.BlockGuardOs');
        var ErrnoException = Java.use('android.system.ErrnoException');
        var ENOENT = 2;

        BlockGuardOs.stat.implementation = function (path) {
            if (SUSPECT_PATH.test(path)) {
                log('Os.stat("' + path + '") -> ENOENT');
                note('Os.stat');
                throw ErrnoException.$new('stat', ENOENT);
            }
            return this.stat(path);
        };

        BlockGuardOs.lstat.implementation = function (path) {
            if (SUSPECT_PATH.test(path)) {
                note('Os.lstat');
                throw ErrnoException.$new('lstat', ENOENT);
            }
            return this.lstat(path);
        };

        BlockGuardOs.access.implementation = function (path, mode) {
            if (SUSPECT_PATH.test(path)) { note('Os.access'); return false; }
            return this.access(path, mode);
        };

        log('libcore.io.BlockGuardOs hooked (covers FileInputStream, Files, RAF)');
    } catch (e) {
        log('BlockGuardOs unavailable on this API level: ' + e);
    }
}

// ---------------------------------------------------------------------------
// 3. Process execution
// ---------------------------------------------------------------------------

function hookExec() {
    var Runtime = Java.use('java.lang.Runtime');
    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
    var IOException = Java.use('java.io.IOException');

    function flatten(argsObj) {
        var joined = '';
        for (var i = 0; i < argsObj.length; i++) {
            var a = argsObj[i];
            if (a === null || a === undefined) continue;
            try {
                if (typeof a === 'object' && a.length !== undefined && a.charAt === undefined) {
                    joined += Array.prototype.join.call(a, ' ');
                } else {
                    joined += a.toString();
                }
            } catch (e) { }
            joined += ' ';
        }
        return joined.trim();
    }

    Runtime.exec.overloads.forEach(function (ov) {
        ov.implementation = function () {
            var cmd = flatten(arguments);
            if (SUSPECT_CMD.test(cmd)) {
                log('Runtime.exec("' + cmd + '") -> IOException');
                note('Runtime.exec');
                // IOException is exactly what the framework throws when the
                // binary does not exist, so existing error handling copes.
                throw IOException.$new('Cannot run program "' +
                        cmd.split(' ')[0] + '": error=2, No such file or directory');
            }
            return ov.apply(this, arguments);
        };
    });

    ProcessBuilder.start.implementation = function () {
        var cmd = this.command().toString();
        if (SUSPECT_CMD.test(cmd)) {
            log('ProcessBuilder.start(' + cmd + ') -> IOException');
            note('ProcessBuilder.start');
            throw IOException.$new('error=2, No such file or directory');
        }
        return this.start();
    };

    log('Runtime.exec / ProcessBuilder hooked');
}

// ---------------------------------------------------------------------------
// 4. PackageManager
// ---------------------------------------------------------------------------

function hookPackageManager() {
    var APM = Java.use('android.app.ApplicationPackageManager');
    var NNFE = Java.use('android.content.pm.PackageManager$NameNotFoundException');
    var ArrayList = Java.use('java.util.ArrayList');

    function bad(name) {
        return name !== null && name !== undefined &&
               SUSPECT_PKGS.indexOf(name.toString()) !== -1;
    }

    ['getPackageInfo', 'getApplicationInfo', 'getPackageUid',
     'getPackageGids', 'getLaunchIntentForPackage',
     'getApplicationEnabledSetting'].forEach(function (m) {
        if (APM[m] === undefined) return;
        APM[m].overloads.forEach(function (ov) {
            ov.implementation = function (name) {
                if (bad(name)) {
                    log('PM.' + m + '("' + name + '") -> NameNotFoundException');
                    note('PM.' + m);
                    throw NNFE.$new(name.toString());
                }
                return ov.apply(this, arguments);
            };
        });
    });

    ['getInstalledPackages', 'getInstalledApplications'].forEach(function (m) {
        if (APM[m] === undefined) return;
        APM[m].overloads.forEach(function (ov) {
            ov.implementation = function () {
                var list = ov.apply(this, arguments);
                var out = ArrayList.$new();
                var it = list.iterator();
                var removed = 0;
                while (it.hasNext()) {
                    var item = it.next();
                    var pkg = null;
                    try {
                        pkg = item.packageName.value;
                    } catch (e) {
                        try { pkg = item.applicationInfo.value.packageName.value; } catch (e2) { }
                    }
                    if (pkg !== null && SUSPECT_PKGS.indexOf(pkg) !== -1) { removed++; continue; }
                    out.add(item);
                }
                if (removed > 0) {
                    log('PM.' + m + ' filtered ' + removed + ' package(s)');
                    note('PM.' + m);
                }
                return out;
            };
        });
    });

    // queryIntentActivities is a back door for the same enumeration.
    if (APM.queryIntentActivities !== undefined) {
        APM.queryIntentActivities.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var list = ov.apply(this, arguments);
                var out = ArrayList.$new();
                var it = list.iterator();
                var removed = 0;
                while (it.hasNext()) {
                    var ri = it.next();
                    var pkg = null;
                    try { pkg = ri.activityInfo.value.packageName.value; } catch (e) { }
                    if (pkg !== null && SUSPECT_PKGS.indexOf(pkg) !== -1) { removed++; continue; }
                    out.add(ri);
                }
                if (removed > 0) note('PM.queryIntentActivities');
                return out;
            };
        });
    }

    log('ApplicationPackageManager hooked (' + SUSPECT_PKGS.length + ' packages hidden)');
}

// ---------------------------------------------------------------------------
// 5. Build fields and system properties
// ---------------------------------------------------------------------------

function hookBuildAndProperties() {
    var Build = Java.use('android.os.Build');

    try {
        if (Build.TAGS.value && Build.TAGS.value.indexOf('test-keys') !== -1) {
            log('Build.TAGS "' + Build.TAGS.value + '" -> release-keys');
            Build.TAGS.value = 'release-keys';
            note('Build.TAGS');
        }
        if (Build.FINGERPRINT.value && Build.FINGERPRINT.value.indexOf('test-keys') !== -1) {
            Build.FINGERPRINT.value =
                Build.FINGERPRINT.value.replace(/test-keys/g, 'release-keys');
            note('Build.FINGERPRINT');
        }
        if (Build.TYPE.value && Build.TYPE.value !== 'user') {
            Build.TYPE.value = 'user';
            note('Build.TYPE');
        }
    } catch (e) {
        log('Build field patch failed: ' + e);
    }

    try {
        var SP = Java.use('android.os.SystemProperties');

        SP.get.overload('java.lang.String').implementation = function (k) {
            var key = k.toString();
            if (key in SAFE_PROPS) {
                log('SystemProperties.get("' + key + '") -> "' + SAFE_PROPS[key] + '"');
                note('SystemProperties.get');
                return SAFE_PROPS[key];
            }
            return this.get(k);
        };

        SP.get.overload('java.lang.String', 'java.lang.String')
          .implementation = function (k, def) {
            var key = k.toString();
            if (key in SAFE_PROPS) {
                note('SystemProperties.get');
                return SAFE_PROPS[key];
            }
            return this.get(k, def);
        };

        if (SP.getInt !== undefined) {
            SP.getInt.implementation = function (k, def) {
                var key = k.toString();
                if (key in SAFE_PROPS) {
                    var v = parseInt(SAFE_PROPS[key], 10);
                    note('SystemProperties.getInt');
                    return isNaN(v) ? def : v;
                }
                return this.getInt(k, def);
            };
        }

        if (SP.getBoolean !== undefined) {
            SP.getBoolean.implementation = function (k, def) {
                var key = k.toString();
                if (key in SAFE_PROPS) {
                    note('SystemProperties.getBoolean');
                    return SAFE_PROPS[key] === '1' || SAFE_PROPS[key] === 'true';
                }
                return this.getBoolean(k, def);
            };
        }

        log('android.os.SystemProperties hooked');
    } catch (e) {
        log('SystemProperties unavailable: ' + e);
    }
}

// ---------------------------------------------------------------------------
// 6. Settings.Global — adb_enabled, development_settings_enabled
// ---------------------------------------------------------------------------

function hookSettings() {
    var SAFE_SETTINGS = {
        'adb_enabled': 0,
        'development_settings_enabled': 0,
        'install_non_market_apps': 0,
        'stay_on_while_plugged_in': 0
    };

    ['android.provider.Settings$Global', 'android.provider.Settings$Secure'].forEach(
        function (cls) {
            try {
                var C = Java.use(cls);
                C.getInt.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        var name = arguments[1] ? arguments[1].toString() : '';
                        if (name in SAFE_SETTINGS) {
                            log(cls + '.getInt("' + name + '") -> ' + SAFE_SETTINGS[name]);
                            note('Settings.getInt');
                            return SAFE_SETTINGS[name];
                        }
                        return ov.apply(this, arguments);
                    };
                });
                C.getString.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        var name = arguments[1] ? arguments[1].toString() : '';
                        if (name in SAFE_SETTINGS) {
                            note('Settings.getString');
                            return String(SAFE_SETTINGS[name]);
                        }
                        return ov.apply(this, arguments);
                    };
                });
            } catch (e) { }
        });

    log('Settings.Global / Settings.Secure hooked');
}

// ---------------------------------------------------------------------------
// 7. Line filtering for /proc reads
// ---------------------------------------------------------------------------
// WARNING: this hook is broad. It affects EVERY BufferedReader in the app,
// including legitimate parsing. Excellent for triage, risky for a long session.
// Set ENABLE_LINE_FILTER = false once you know which file the check reads, and
// hook that path specifically in the native script instead.

var ENABLE_LINE_FILTER = true;

function hookLineFilter() {
    if (!ENABLE_LINE_FILTER) return;
    var BufferedReader = Java.use('java.io.BufferedReader');

    BufferedReader.readLine.overload().implementation = function () {
        var line = this.readLine();
        var dropped = 0;
        while (line !== null && SUSPECT_LINE.test(line.toString())) {
            dropped++;
            line = this.readLine();
        }
        if (dropped > 0) {
            log('BufferedReader.readLine dropped ' + dropped + ' suspicious line(s)');
            note('BufferedReader.readLine');
        }
        return line;
    };

    log('BufferedReader.readLine filtering enabled (broad — narrow it when you can)');
}

// ---------------------------------------------------------------------------
// 8. RootBeer library
// ---------------------------------------------------------------------------

function hookRootBeer() {
    var FALSE_METHODS = [
        'isRooted', 'isRootedWithBusyBoxCheck', 'isRootedWithoutBusyBoxCheck',
        'isRootedWithEmulatorCheck',
        'detectRootManagementApps', 'detectPotentiallyDangerousApps',
        'detectRootCloakingApps', 'checkForSuBinary', 'checkForBusyBoxBinary',
        'checkForDangerousProps', 'checkForRWPaths', 'detectTestKeys',
        'checkSuExists', 'checkForRootNative', 'checkForMagiskBinary',
        'checkForBinary', 'isSelinuxFlagInEnabled'
    ];

    ['com.scottyab.rootbeer.RootBeer',
     'com.scottyab.rootbeer.RootBeerNative'].forEach(function (cls) {
        try {
            var C = Java.use(cls);
            FALSE_METHODS.forEach(function (m) {
                if (C[m] === undefined) return;
                C[m].overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        log('RootBeer.' + m + '() -> false');
                        note('RootBeer.' + m);
                        return false;
                    };
                });
            });
            log(cls + ' neutralised');
        } catch (e) { /* not present */ }
    });

    // The native component's JNI symbol survives obfuscation because the JNI
    // linker resolves it by name. This is the reliable anchor.
    try {
        var sym = Module.findExportByName('librootbeer.so',
                    'Java_com_scottyab_rootbeer_RootBeerNative_checkForRoot');
        if (sym !== null) {
            Interceptor.replace(sym, new NativeCallback(function () {
                log('librootbeer.so native checkForRoot() -> 0');
                note('RootBeer.native');
                return 0;
            }, 'int', ['pointer', 'pointer', 'pointer']));
        }
    } catch (e) { }
}

// ---------------------------------------------------------------------------
// 9. Common consequence removal — last resort, use sparingly
// ---------------------------------------------------------------------------
// If a check you cannot find is still firing, blocking the CONSEQUENCE gets you
// moving. It is a blunt instrument: it can leave the app in a state the
// developer never anticipated. Prefer fixing the check. Off by default.

var BLOCK_CONSEQUENCES = false;

function hookConsequences() {
    if (!BLOCK_CONSEQUENCES) return;
    var Log = Java.use('android.util.Log');
    var Exception = Java.use('java.lang.Exception');

    Java.use('android.app.Activity').finish.implementation = function () {
        console.log('[BLOCKED] Activity.finish() from:\n' +
                    Log.getStackTraceString(Exception.$new()));
        note('Activity.finish blocked');
    };

    Java.use('java.lang.System').exit.implementation = function (code) {
        console.log('[BLOCKED] System.exit(' + code + ') from:\n' +
                    Log.getStackTraceString(Exception.$new()));
        note('System.exit blocked');
    };

    Java.use('android.os.Process').killProcess.implementation = function (pid) {
        console.log('[BLOCKED] Process.killProcess(' + pid + ')');
        note('killProcess blocked');
    };
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

Java.perform(function () {
    console.log('');
    console.log('==========================================================');
    console.log(' java-root-bypass.js — Java-layer root detection bypass');
    console.log(' If nothing changes, the check is NATIVE.');
    console.log(' Use native-root-bypass.js, and run root-check-tracer.js');
    console.log(' first to find out which layer you are fighting.');
    console.log('==========================================================');
    console.log('');

    hookFile();
    hookLibcoreOs();
    hookExec();
    hookPackageManager();
    hookBuildAndProperties();
    hookSettings();
    hookLineFilter();
    hookRootBeer();
    hookConsequences();

    console.log('');
    console.log('[java-bypass] all hooks installed. Exercise the app.');
    console.log('[java-bypass] a summary prints after 15 seconds.');

    setTimeout(summary, 15000);
});
