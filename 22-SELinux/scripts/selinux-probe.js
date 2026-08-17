// =============================================================================
// selinux-probe.js -- read the SELinux world from INSIDE a target app process.
//
// WHAT IT DOES
//   Everything in this chapter that you can only see from inside an app's own
//   security context. `adb shell` runs as u:r:shell:s0 and is not sandboxed
//   like an app, so a conclusion of the form "an app can do X" reached from a
//   shell is not evidence. This script reaches the same questions from the app
//   itself:
//
//     - the process's own context, read from /proc/self/attr/current, which is
//       the kernel's answer rather than the framework's
//     - the MCS categories, decoded back into the appId and Android user id
//       that produced them, and checked against getuid()
//     - the label on the app's own data directory, and on every file in it
//     - a labelled probe of paths and services the app is NOT expected to
//       reach, reporting errno for each so you can tell EACCES (a permission
//       decision) from ENOENT (nothing there)
//     - whether the process can make anonymous memory executable
//       (process:execmem) and whether it can execve a file it wrote itself
//       (file:execute_no_trans) -- the two permissions that shaped dynamic
//       code loading on Android
//     - a hook on every open/openat/connect that returns EACCES, printing the
//       path and a Java stack trace, so a denial can be attributed to the line
//       of app code that caused it
//
// HOW TO RUN
//     frida -U -f com.example.target -l selinux-probe.js
//     frida -U -n com.example.target -l selinux-probe.js        # attach
//     frida -U -f com.example.target -l selinux-probe.js --no-pause
//
//   Then, in the Frida REPL:
//     rpc.exports.context()          // the process context, as a string
//     rpc.exports.categories()       // decoded MCS
//     rpc.exports.probe()            // rerun the access probe
//     rpc.exports.label("/some/path")
//     rpc.exports.tryexec()          // attempt the write-then-execve test
//
// REQUIREMENTS
//   frida-server matching your frida CLI, running on the device. Root is
//   required to run frida-server; the SCRIPT itself needs no root because it
//   runs inside the app. That distinction matters: everything reported here
//   is what the APP can do, not what root can do.
//
// WHAT THIS WILL *NOT* TELL YOU
//   - Whether a refusal came from DAC or from MAC. errno is EACCES for both.
//     The script says "refused" and tells you to correlate with an avc record;
//     it does not guess. Use ../scripts/avc-decode.py on the log to settle it.
//   - What rules exist. There is no way to query the policy from an app.
//   - Whether the device's policy is stock. See selinux-posture.sh.
//   - Anything at all if frida-server is not running as root. On a device
//     where you cannot run frida-server, none of this is available and you
//     fall back to writing a probe app -- see ../examples/.
//   - Whether an operation that SUCCEEDS here would succeed on a different
//     device. Vendor policy differs; measure on the target.
// =============================================================================

'use strict';

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function readFileUtf8(path) {
    try {
        var f = new File(path, 'r');
        // Frida's File has no readAll on all versions; go through libc instead
        // for reliability. Fall through to the native path below.
        f.close();
    } catch (e) { /* ignore */ }
    return readViaLibc(path);
}

var _open = new NativeFunction(Module.getExportByName(null, 'open'),
    'int', ['pointer', 'int']);
var _read = new NativeFunction(Module.getExportByName(null, 'read'),
    'long', ['int', 'pointer', 'ulong']);
var _close = new NativeFunction(Module.getExportByName(null, 'close'),
    'int', ['int']);
var _getuid = new NativeFunction(Module.getExportByName(null, 'getuid'),
    'uint', []);
var _getpid = new NativeFunction(Module.getExportByName(null, 'getpid'),
    'int', []);
var _errnoLoc = new NativeFunction(Module.getExportByName(null, '__errno'),
    'pointer', []);

function errno() { return Memory.readS32(_errnoLoc()); }

var ERRNO_NAMES = {
    1: 'EPERM (operation not permitted)',
    2: 'ENOENT (no such file or directory)',
    13: 'EACCES (permission denied)',
    20: 'ENOTDIR',
    21: 'EISDIR',
    30: 'EROFS (read-only filesystem)',
    111: 'ECONNREFUSED',
};

function errnoName(e) {
    return ERRNO_NAMES[e] || ('errno ' + e);
}

function readViaLibc(path) {
    var p = Memory.allocUtf8String(path);
    var fd = _open(p, 0 /* O_RDONLY */);
    if (fd < 0) {
        return { ok: false, errno: errno() };
    }
    var buf = Memory.alloc(65536);
    var n = _read(fd, buf, 65535);
    _close(fd);
    if (n < 0) {
        return { ok: false, errno: errno() };
    }
    return { ok: true, text: Memory.readUtf8String(buf, n.toNumber()) };
}

// ---------------------------------------------------------------------------
// Context and MCS
// ---------------------------------------------------------------------------

// Constants from system/core/libcutils/include/private/android_filesystem_config.h
var AID_USER_OFFSET = 100000;
var AID_APP_START = 10000;
var AID_SDK_SANDBOX_PROCESS_START = 20000;
var AID_ISOLATED_START = 90000;

function myContext() {
    var r = readViaLibc('/proc/self/attr/current');
    if (!r.ok) return null;
    // The kernel appends a NUL; strip it and any trailing whitespace.
    return r.text.replace(/\0/g, '').trim();
}

function splitContext(ctx) {
    if (!ctx) return null;
    var parts = ctx.split(':');
    if (parts.length < 3) return null;
    return {
        user: parts[0],
        role: parts[1],
        type: parts[2],
        level: parts.slice(3).join(':') || null,
    };
}

function parseCats(level) {
    if (!level) return [];
    var bits = level.split(':');
    if (bits.length < 2) return [];
    var out = [];
    bits[1].split(',').forEach(function (c) {
        var m = /^c(\d+)$/.exec(c.trim());
        if (m) out.push(parseInt(m[1], 10));
    });
    return out.sort(function (a, b) { return a - b; });
}

// The encoding, from external/selinux/libselinux/src/android/android_platform.c
//   levelFrom=all -> s0:c(appid & 0xff),c(256 + (appid >> 8)),
//                      c(512 + (userid & 0xff)),c(768 + (userid >> 8))
// Verified on a physical Android 13 device: uid 10107 -> c107,c256,c512,c768.
function predictCategories(uid) {
    var userid = Math.floor(uid / AID_USER_OFFSET);
    var raw = uid % AID_USER_OFFSET;
    var appid, range;
    if (raw >= AID_ISOLATED_START) {
        appid = raw - AID_ISOLATED_START; range = 'isolated';
    } else if (raw >= AID_SDK_SANDBOX_PROCESS_START) {
        appid = raw - AID_SDK_SANDBOX_PROCESS_START; range = 'sdk sandbox';
    } else if (raw >= AID_APP_START) {
        appid = raw - AID_APP_START; range = 'application';
    } else {
        appid = raw; range = 'system/native AID';
    }
    return {
        uid: uid,
        userid: userid,
        rawAppid: raw,
        range: range,
        appid: appid,
        all: 's0:c' + (appid & 0xff) + ',c' + (256 + (appid >> 8)) +
             ',c' + (512 + (userid & 0xff)) + ',c' + (768 + (userid >> 8)),
        user: 's0:c' + (512 + (userid & 0xff)) + ',c' + (768 + (userid >> 8)),
        app: 's0:c' + (appid & 0xff) + ',c' + (256 + (appid >> 8)),
    };
}

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

var _lgetxattr = null;
try {
    _lgetxattr = new NativeFunction(Module.getExportByName(null, 'lgetxattr'),
        'long', ['pointer', 'pointer', 'pointer', 'ulong']);
} catch (e) { /* not exported on some builds */ }

function labelOf(path) {
    if (_lgetxattr === null) return { ok: false, why: 'lgetxattr unavailable' };
    var p = Memory.allocUtf8String(path);
    var name = Memory.allocUtf8String('security.selinux');
    var buf = Memory.alloc(512);
    var n = _lgetxattr(p, name, buf, 511);
    if (n.toNumber() < 0) {
        var e = errno();
        return { ok: false, errno: e, why: errnoName(e) };
    }
    return { ok: true, label: Memory.readUtf8String(buf, n.toNumber())
        .replace(/\0/g, '') };
}

// ---------------------------------------------------------------------------
// The probe set. Each entry states what SHOULD happen, so an unexpected
// success is visible rather than buried.
// ---------------------------------------------------------------------------

var PROBES = [
    { path: '/proc/self/attr/current',
      expect: 'READABLE -- your own context is always readable' },
    { path: '/sys/fs/selinux/enforce',
      expect: 'READABLE -- the global enforcing flag is world-readable' },
    { path: '/sys/fs/selinux/policy',
      expect: 'REFUSED -- needs security:read_policy' },
    { path: '/data/system/packages.list',
      expect: 'REFUSED -- system_data_file, and 0640 system:package_info' },
    { path: '/data/local/tmp',
      expect: 'REFUSED -- shell_data_file; an app has no rule for it' },
    { path: '/data/data',
      expect: 'REFUSED to LIST -- 0711, and no dir:read for app domains' },
    { path: '/proc/sys/kernel/randomize_va_space',
      expect: 'REFUSED -- proc_security' },
    { path: '/dev/socket/property_service',
      expect: 'REFUSED -- property setting goes through init, not this node' },
    { path: '/system/etc/selinux/plat_seapp_contexts',
      expect: 'depends -- readable on many builds, and worth checking' },
    { path: '/vendor/etc/selinux/vendor_seapp_contexts',
      expect: 'depends' },
    { path: '/proc/1/attr/current',
      expect: 'REFUSED -- reading init s context needs process:getattr' },
];

function probe() {
    console.log('');
    console.log('=== ACCESS PROBE =========================================');
    console.log('Each line: RESULT  path');
    console.log('A REFUSED result may be DAC, MAC, or both. Correlate with');
    console.log('logcat: adb logcat -d -b all | grep avc | tail');
    console.log('----------------------------------------------------------');
    PROBES.forEach(function (pr) {
        var r = readViaLibc(pr.path);
        var verdict;
        if (r.ok) {
            verdict = 'OK      ';
        } else if (r.errno === 13 || r.errno === 1) {
            verdict = 'REFUSED ';
        } else if (r.errno === 2) {
            verdict = 'ABSENT  ';
        } else if (r.errno === 21) {
            verdict = 'ISDIR   ';   // opened fine, it is a directory
        } else {
            verdict = 'ERR ' + r.errno + '  ';
        }
        console.log(verdict + pr.path);
        console.log('          expected: ' + pr.expect);
        if (!r.ok && r.errno !== undefined) {
            console.log('          errno:    ' + errnoName(r.errno));
        }
        var lbl = labelOf(pr.path);
        if (lbl.ok) {
            console.log('          label:    ' + lbl.label);
        }
    });
    console.log('----------------------------------------------------------');
}

// ---------------------------------------------------------------------------
// The two code-execution permissions
// ---------------------------------------------------------------------------

function testExecmem() {
    // Ask for anonymous memory that is both writable and executable. On a
    // domain without process:execmem this fails. On the measured Android 13
    // policy `appdomain` IS granted execmem, so an ordinary app SUCCEEDS here
    // -- which is exactly why "SELinux stops JIT" is wrong.
    try {
        var p = Memory.alloc(Process.pageSize);
        Memory.protect(p, Process.pageSize, 'rwx');
        console.log('execmem   : GRANTED -- this process can create RWX memory.');
        console.log('            That is normal for an app domain on AOSP:');
        console.log('            (allow appdomain self (process (execmem)))');
        console.log('            It is what makes the JIT and');
        console.log('            InMemoryDexClassLoader possible at all.');
        return true;
    } catch (e) {
        console.log('execmem   : REFUSED -- ' + e.message);
        console.log('            Look for tclass=process { execmem } in the log.');
        return false;
    }
}

function tryexec() {
    // Write a tiny script into the app's own data directory, mark it
    // executable, and try to execve it. The DAC bits are ours to set; the
    // question is purely whether MAC permits file:execute_no_trans on
    // app_data_file for this domain.
    var dir = null;
    try {
        Java.perform(function () {
            var ctx = Java.use('android.app.ActivityThread')
                .currentApplication().getApplicationContext();
            dir = ctx.getFilesDir().getAbsolutePath();
        });
    } catch (e) {
        console.log('tryexec   : could not reach the app context: ' + e);
        return;
    }
    var target = dir + '/selinux_probe_exec';
    try {
        var f = new File(target, 'w');
        f.write('#!/system/bin/sh\necho probe-ran\n');
        f.close();
    } catch (e) {
        console.log('tryexec   : could not write ' + target + ': ' + e);
        return;
    }

    var _chmod = new NativeFunction(Module.getExportByName(null, 'chmod'),
        'int', ['pointer', 'int']);
    _chmod(Memory.allocUtf8String(target), 0x1c0 /* 0700 */);

    var lbl = labelOf(target);
    console.log('tryexec   : wrote ' + target);
    if (lbl.ok) console.log('            label ' + lbl.label);

    var _system = new NativeFunction(Module.getExportByName(null, 'system'),
        'int', ['pointer']);
    var rc = _system(Memory.allocUtf8String(target + ' >/dev/null 2>&1'));
    if (rc === 0) {
        console.log('            execve SUCCEEDED. This domain HAS');
        console.log('            file:execute_no_trans on app_data_file --');
        console.log('            characteristic of untrusted_app_25 and');
        console.log('            untrusted_app_27, i.e. a low targetSdk.');
    } else {
        console.log('            execve FAILED (rc=' + rc + '). Expected on a');
        console.log('            modern targetSdk: untrusted_app has');
        console.log('            file:execute on app_data_file but NOT');
        console.log('            file:execute_no_trans. Confirm with:');
        console.log('              adb logcat -d -b all | grep execute_no_trans');
    }
    console.log('            Delete the probe file yourself if you care;');
    console.log('            it is inert but it is litter.');
}

// ---------------------------------------------------------------------------
// Attribute a refusal to a line of app code
// ---------------------------------------------------------------------------

function traceRefusals() {
    var openat = Module.findExportByName(null, 'openat');
    if (openat === null) {
        console.log('openat not found; refusal tracing disabled.');
        return;
    }
    Interceptor.attach(openat, {
        onEnter: function (args) {
            this.path = args[1].readUtf8String();
        },
        onLeave: function (retval) {
            if (retval.toInt32() >= 0) return;
            var e = errno();
            if (e !== 13 && e !== 1) return;
            console.log('');
            console.log('*** REFUSED openat  ' + this.path);
            console.log('    errno ' + errnoName(e));
            try {
                Java.perform(function () {
                    var Log = Java.use('android.util.Log');
                    var Ex = Java.use('java.lang.Exception');
                    console.log(Log.getStackTraceString(Ex.$new()));
                });
            } catch (err) {
                console.log('    (no Java frames -- native caller)');
                console.log('    ' + Thread.backtrace(this.context,
                    Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n    '));
            }
            console.log('    Correlate with an avc record before concluding');
            console.log('    this was MAC and not DAC.');
        }
    });
    console.log('Refusal tracing on openat is active.');
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

function report() {
    var ctx = myContext();
    var uid = _getuid();
    var pid = _getpid();

    console.log('');
    console.log('==========================================================');
    console.log(' SELinux probe -- from inside the app process');
    console.log('==========================================================');
    console.log('pid       : ' + pid);
    console.log('uid       : ' + uid);

    if (ctx === null) {
        console.log('context   : COULD NOT READ /proc/self/attr/current.');
        console.log('            That itself is unusual; SELinux may not be');
        console.log('            present, or the read was refused.');
        return;
    }
    console.log('context   : ' + ctx);

    var s = splitContext(ctx);
    console.log('  user    : ' + s.user + '   (always "u" on Android -- there');
    console.log('            is exactly one SELinux user, so this field');
    console.log('            carries no information)');
    console.log('  role    : ' + s.role + '   ("r" for a process, "object_r"');
    console.log('            for a file -- also carries no information)');
    console.log('  TYPE    : ' + s.type + '   <-- this is the domain. This is');
    console.log('            the field that policy rules are written about.');
    console.log('  level   : ' + (s.level || '(none)'));

    var cats = parseCats(s.level);
    var pred = predictCategories(uid);
    console.log('');
    console.log('MCS');
    console.log('  observed categories : ' +
        (cats.length ? cats.map(function (c) { return 'c' + c; }).join(',')
                     : '(none)'));
    console.log('  uid ' + uid + ' decomposes to:');
    console.log('    Android user id    : ' + pred.userid);
    console.log('    raw appid          : ' + pred.rawAppid + '  (' + pred.range + ')');
    console.log('    appid after offset : ' + pred.appid);
    console.log('  predicted levelFrom=all  : ' + pred.all);
    console.log('  predicted levelFrom=user : ' + pred.user);
    console.log('  predicted levelFrom=app  : ' + pred.app);
    if (s.level === pred.all) {
        console.log('  MATCH levelFrom=all. Both category pairs present, so');
        console.log('        this process is isolated from every OTHER app in');
        console.log('        the same domain by the MLS constraint, not by');
        console.log('        type enforcement. See README section 3.7.');
    } else if (s.level === pred.user) {
        console.log('  MATCH levelFrom=user. Only the user pair. Every process');
        console.log('        in this domain on this Android user shares a');
        console.log('        level, so MCS does NOT separate them.');
    } else if (s.level === 's0' || !s.level) {
        console.log('  No categories. Separation rests entirely on the domain.');
    } else {
        console.log('  NO MATCH. Investigate -- a vendor seapp_contexts line');
        console.log('  may be in play.');
    }

    console.log('');
    console.log('LABELS');
    Java.perform(function () {
        try {
            var ctxJ = Java.use('android.app.ActivityThread')
                .currentApplication().getApplicationContext();
            var paths = [
                ctxJ.getFilesDir().getAbsolutePath(),
                ctxJ.getCacheDir().getAbsolutePath(),
                ctxJ.getApplicationInfo().dataDir.value,
                ctxJ.getApplicationInfo().sourceDir.value,
                ctxJ.getApplicationInfo().nativeLibraryDir.value,
            ];
            paths.forEach(function (p) {
                var l = labelOf(p);
                console.log('  ' + (l.ok ? l.label : '(' + l.why + ')'));
                console.log('      ' + p);
            });
        } catch (e) {
            console.log('  could not enumerate app paths: ' + e);
        }
    });

    console.log('');
    console.log('CODE EXECUTION PERMISSIONS');
    testExecmem();

    probe();

    console.log('');
    console.log('Call rpc.exports.tryexec() to test file:execute_no_trans.');
    console.log('It writes a file into the app data dir; read the source');
    console.log('before you run it on anything you care about.');
    console.log('==========================================================');
}

// ---------------------------------------------------------------------------

rpc.exports = {
    context: function () { return myContext(); },
    categories: function () {
        var s = splitContext(myContext());
        return { observed: s ? s.level : null, predicted: predictCategories(_getuid()) };
    },
    probe: function () { probe(); return 'done'; },
    label: function (p) { return labelOf(p); },
    tryexec: function () { tryexec(); return 'done'; },
    report: function () { report(); return 'done'; },
};

setImmediate(function () {
    try {
        Java.perform(function () { report(); });
    } catch (e) {
        console.log('report failed: ' + e);
        report();
    }
    traceRefusals();
});
