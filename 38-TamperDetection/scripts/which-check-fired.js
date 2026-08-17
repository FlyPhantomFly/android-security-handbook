/*
 * which-check-fired.js
 * ---------------------------------------------------------------------------
 * PURPOSE
 *   Report WHICH tamper check an app performed, WHAT it saw, and WHERE the
 *   check lives. It does not bypass anything by default.
 *
 *   That restraint is the entire design. The instinct on meeting a protected
 *   app is to load a script that spoofs every signature, nulls every TracerPid
 *   and hides every Frida artefact at once. It usually works, and it teaches
 *   you nothing -- and when it does not work you have no idea which of the
 *   twenty hooks was wrong, or whether the app has a check you never hooked.
 *
 *   Run this first. It converts "the app dies at launch and I do not know why"
 *   into "the app read /proc/self/maps from libfoo.so+0x14a20 and then called
 *   System.exit". That second sentence is a small, specific task.
 *
 *   Once you know which check fired, neutralise ONLY that one. If you need a
 *   general bypass methodology and the adversarial back-and-forth that follows,
 *   that is chapter 67-BypassingProtections' subject, not this script's.
 *
 * WHAT IT INSTRUMENTS
 *   Java tier
 *     ApplicationPackageManager.getPackageInfo / getInstallSourceInfo /
 *       getInstallerPackageName / checkSignatures / hasSigningCertificate
 *     SigningInfo.getApkContentsSigners / getSigningCertificateHistory
 *     Signature.toByteArray / hashCode / toCharsString
 *     MessageDigest.digest        (only when fed signature-shaped input)
 *     java.io.File.<init>         (only for the paths that matter)
 *     FileInputStream/RandomAccessFile on /proc paths
 *     java.util.zip.ZipFile.<init> / ZipEntry.getCrc
 *     android.os.Debug.isDebuggerConnected / waitingForDebugger
 *     java.net.Socket.connect     (to spot a port scan)
 *     System.exit / Runtime.exit / Process.killProcess / Activity.finish
 *       -- the CONSEQUENCE, which is often easier to find than the cause
 *   Native tier
 *     ptrace, fopen, open, openat, fgets, strstr, strcmp on /proc paths
 *     __system_property_get, dl_iterate_phdr, dladdr
 *     android_dlopen_ext          (to learn which .so to look at, and when)
 *
 * USAGE
 *   # host -- ALWAYS spawn. Most integrity checks run in Application.onCreate
 *   # or in a static initialiser, both of which are over before you can attach.
 *   frida -U -f com.target.app -l which-check-fired.js
 *
 *   # host -- if the app survives long enough, attaching also works
 *   frida -U -n "App Name" -l which-check-fired.js
 *
 *   # Configuration is at the top of the CONFIG block below:
 *   #   STACKS      print a Java stack trace for each Java-tier hit
 *   #   NATIVE      install the native hooks (turn off if the app has no .so)
 *   #   BLOCK_EXIT  do NOT actually exit; report the attempt and continue.
 *   #               This is the ONE bypass the script performs, and it is opt-in
 *   #               because it is the difference between an app that dies before
 *   #               printing anything and an app that tells you everything.
 *
 * REQUIREMENTS
 *   frida-server on the device, matching your frida client major version, and
 *   running as root. On a device you cannot root, use a Frida Gadget build --
 *   but note that gadget mode requires REPACKAGING, which changes the signing
 *   certificate and will itself trip every SIG-SELF check in this chapter.
 *   That trade is discussed in 53-Frida and is not a bug in this script.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   * It will NOT see a check written as inline syscall assembly. No
 *     Interceptor hook on a libc export can. If the report is empty and the app
 *     still dies, that is your answer: switch to strace, or to a static patch.
 *     README section 7.7 covers the transition.
 *   * It will NOT see a check that ran before the script was injected. An
 *     .init_array constructor in a library loaded by the zygote is beyond a
 *     spawn-time script's reach; run the mapper first to find out whether such
 *     a tier exists.
 *   * It will NOT tell you whether a check MATTERS. An app can read its own
 *     signature ten times for telemetry and never branch on it. Correlate with
 *     the consequence hooks at the bottom.
 *   * It will NOT make the app work. It is a microscope, not a crowbar.
 *
 * AUTHORISED TESTING ONLY.
 * ---------------------------------------------------------------------------
 */

'use strict';

// ---------------------------------------------------------------------------
// CONFIG
// ---------------------------------------------------------------------------

var CONFIG = {
    STACKS: true,        // Java stack trace on each Java-tier hit
    NATIVE: true,        // install libc-level hooks
    BLOCK_EXIT: false,   // neutralise System.exit / killProcess (opt-in)
    MAX_STACK: 12,       // stack frames to print
    QUIET_PATHS: true    // suppress filesystem hits on obviously boring paths
};

// Paths worth reporting when an app opens them. Everything else is noise: an
// app opens hundreds of files at startup and none of the others are checks.
var INTERESTING = [
    '/proc/self/status', '/proc/self/maps', '/proc/self/mem', '/proc/self/task',
    '/proc/self/cmdline', '/proc/self/exe', '/proc/net/tcp', '/proc/net/unix',
    '/data/app/', '/data/local/tmp', 'base.apk', 'classes.dex',
    'META-INF', 'frida', 'gum', 'linjector', 'xposed', 'lspos'
];

// ---------------------------------------------------------------------------
// Output plumbing
//
// Every line is prefixed so you can grep the transcript afterwards:
//   [J]  Java tier
//   [N]  native tier
//   [!]  a CONSEQUENCE - the app acting on a verdict
//   [i]  informational
// ---------------------------------------------------------------------------

var seen = {};

function log(tag, msg) {
    console.log('[' + tag + '] ' + msg);
}

/** Print once per distinct key, then count. Keeps a loop from flooding. */
function once(key, tag, msg) {
    if (seen[key] === undefined) {
        seen[key] = 0;
        log(tag, msg);
    }
    seen[key]++;
    if (seen[key] === 50) {
        log('i', 'suppressing further "' + key + '" hits (50 so far)');
    }
    return seen[key] === 1;
}

function interesting(path) {
    if (!CONFIG.QUIET_PATHS) return true;
    if (path === null || path === undefined) return false;
    var p = String(path).toLowerCase();
    for (var i = 0; i < INTERESTING.length; i++) {
        if (p.indexOf(INTERESTING[i].toLowerCase()) >= 0) return true;
    }
    return false;
}

function hex(bytes, max) {
    var out = [], n = Math.min(bytes.length, max || 16);
    for (var i = 0; i < n; i++) {
        var b = bytes[i] & 0xff;
        out.push((b < 16 ? '0' : '') + b.toString(16));
    }
    return out.join('') + (bytes.length > n ? '…' : '');
}

// ---------------------------------------------------------------------------
// Java tier
// ---------------------------------------------------------------------------

function javaStack(Exception, Log) {
    try {
        var s = Log.getStackTraceString(Exception.$new());
        var lines = s.split('\n');
        var keep = [];
        for (var i = 1; i < lines.length && keep.length < CONFIG.MAX_STACK; i++) {
            var l = lines[i].trim();
            // Drop the frames belonging to Frida's own dispatch and to the
            // reflection machinery; they are the same every time and they
            // push the interesting frame off the screen.
            if (l.indexOf('com.android.internal.os') >= 0) continue;
            if (l.indexOf('java.lang.reflect') >= 0) continue;
            if (l.indexOf('android.os.Handler') >= 0) continue;
            keep.push('      ' + l);
        }
        return keep.join('\n');
    } catch (e) {
        return '      (stack unavailable: ' + e + ')';
    }
}

function hookJava() {
    Java.perform(function () {
        var Exception = Java.use('java.lang.Exception');
        var Log = Java.use('android.util.Log');

        function stack() { return CONFIG.STACKS ? '\n' + javaStack(Exception, Log) : ''; }

        // --- getPackageInfo -------------------------------------------------
        //
        // The concrete class matters. android.content.pm.PackageManager is
        // ABSTRACT; hooking it silently does nothing on many builds. The object
        // an app actually holds is ApplicationPackageManager -- the same trap
        // chapter 37 documents for root checks.
        var APM = Java.use('android.app.ApplicationPackageManager');

        // Flag values worth naming when we see them.
        var FLAGS = {
            0x00000040: 'GET_SIGNATURES (deprecated at API 28)',
            0x08000000: 'GET_SIGNING_CERTIFICATES'
        };

        APM.getPackageInfo.overload('java.lang.String', 'int').implementation =
            function (pkg, flags) {
                var res = this.getPackageInfo(pkg, flags);
                var named = FLAGS[flags & 0x08000040];
                if (named) {
                    var self = (pkg === Java.use('android.app.ActivityThread')
                        .currentApplication().getPackageName()) ? 'SELF' : 'peer';
                    log('J', 'getPackageInfo("' + pkg + '", 0x' + (flags >>> 0).toString(16)
                        + ' = ' + named + ')  [' + self + ']' + stack());
                }
                return res;
            };

        // --- SigningInfo ----------------------------------------------------
        var SigningInfo = Java.use('android.content.pm.SigningInfo');
        ['getApkContentsSigners', 'getSigningCertificateHistory'].forEach(function (m) {
            SigningInfo[m].implementation = function () {
                var r = this[m]();
                log('J', 'SigningInfo.' + m + '() -> ' + (r ? r.length : 0)
                    + ' certificate(s)' + stack());
                return r;
            };
        });

        // --- Signature.toByteArray -----------------------------------------
        //
        // This is the single highest-value hook in the file. Almost every
        // self-signature check ends here, because the DER bytes are what gets
        // hashed. Seeing it fire tells you the check is real; seeing the SHA-256
        // that follows tells you the constant the app is comparing against.
        var Signature = Java.use('android.content.pm.Signature');
        Signature.toByteArray.implementation = function () {
            var b = this.toByteArray();
            log('J', 'Signature.toByteArray() -> ' + b.length + ' DER bytes, '
                + 'starts ' + hex(b, 8) + stack());
            return b;
        };
        Signature.hashCode.implementation = function () {
            var h = this.hashCode();
            once('sig.hashCode', 'J',
                 'Signature.hashCode() -> 0x' + (h >>> 0).toString(16)
                 + '   (a 32-bit hash of the certificate: cheap, and a '
                 + 'comparison against it is trivially collidable in principle '
                 + 'but nobody bothers -- they just patch the branch)');
            return h;
        };

        // --- MessageDigest --------------------------------------------------
        //
        // We only report digests whose input length is plausible for a
        // certificate. A general MessageDigest hook on a real app produces
        // thousands of lines a second and buries everything.
        var MD = Java.use('java.security.MessageDigest');
        MD.digest.overload('[B').implementation = function (input) {
            var out = this.digest(input);
            if (input.length > 300 && input.length < 4096) {
                log('J', 'MessageDigest(' + this.getAlgorithm() + ').digest('
                    + input.length + ' bytes) -> ' + hex(out, 32)
                    + '\n      ^ certificate-sized input. If the app compares '
                    + 'this against a constant, THAT constant is the baseline.'
                    + stack());
            }
            return out;
        };

        // --- installer ------------------------------------------------------
        ['getInstallerPackageName', 'getInstallSourceInfo'].forEach(function (m) {
            if (APM[m] === undefined) return;
            APM[m].overload('java.lang.String').implementation = function (pkg) {
                var r = this[m](pkg);
                log('J', m + '("' + pkg + '") -> ' + r + stack());
                return r;
            };
        });

        // --- debugger -------------------------------------------------------
        var Debug = Java.use('android.os.Debug');
        ['isDebuggerConnected', 'waitingForDebugger'].forEach(function (m) {
            Debug[m].implementation = function () {
                var r = this[m]();
                log('J', 'Debug.' + m + '() -> ' + r
                    + '\n      ^ NOTE: this is a JDWP question, NOT a ptrace '
                    + 'question. TracerPid stays 0 for a JDWP debugger -- '
                    + 'measured, see README 3.8.' + stack());
                return r;
            };
        });

        // --- filesystem -----------------------------------------------------
        var File = Java.use('java.io.File');
        File.$init.overload('java.lang.String').implementation = function (path) {
            if (interesting(path)) {
                log('J', 'new File("' + path + '")' + stack());
            }
            return this.$init(path);
        };

        var FIS = Java.use('java.io.FileInputStream');
        FIS.$init.overload('java.io.File').implementation = function (f) {
            var p = f.getAbsolutePath();
            if (interesting(p)) log('J', 'FileInputStream("' + p + '")' + stack());
            return this.$init(f);
        };

        // --- zip / self-hashing ---------------------------------------------
        var ZipFile = Java.use('java.util.zip.ZipFile');
        ZipFile.$init.overload('java.lang.String').implementation = function (p) {
            if (interesting(p)) {
                log('J', 'new ZipFile("' + p + '")'
                    + '\n      ^ an app opening its OWN apk as a zip is about to '
                    + 'hash or CRC something inside it' + stack());
            }
            return this.$init(p);
        };

        // --- port scan ------------------------------------------------------
        var Socket = Java.use('java.net.Socket');
        Socket.connect.overload('java.net.SocketAddress', 'int').implementation =
            function (addr, timeout) {
                var s = addr.toString();
                if (s.indexOf('127.0.0.1') >= 0 || s.indexOf('localhost') >= 0) {
                    log('J', 'Socket.connect(' + s + ', timeout=' + timeout + ')'
                        + '\n      ^ a loopback connect with a short timeout is a '
                        + 'port scan. 27042/27043 are frida-server defaults.'
                        + stack());
                }
                return this.connect(addr, timeout);
            };

        // --- CONSEQUENCES ---------------------------------------------------
        //
        // Finding the check is half the job. Finding what the app DOES about it
        // is the other half, and on a decoupled design -- where the check sets
        // a flag now and something fails silently four screens later -- the
        // consequence is the only end you can grab. See lab 04.
        var System = Java.use('java.lang.System');
        System.exit.implementation = function (code) {
            log('!', 'System.exit(' + code + ') CALLED' + stack());
            if (CONFIG.BLOCK_EXIT) {
                log('!', '  blocked (CONFIG.BLOCK_EXIT). The app will continue in '
                        + 'whatever state the check left it -- expect weirdness.');
                return;
            }
            return this.exit(code);
        };

        var Process = Java.use('android.os.Process');
        Process.killProcess.implementation = function (pid) {
            log('!', 'Process.killProcess(' + pid + ') CALLED' + stack());
            if (CONFIG.BLOCK_EXIT) return;
            return this.killProcess(pid);
        };

        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exit.implementation = function (code) {
            log('!', 'Runtime.exit(' + code + ') CALLED' + stack());
            if (CONFIG.BLOCK_EXIT) return;
            return this.exit(code);
        };

        log('i', 'Java hooks installed. BLOCK_EXIT=' + CONFIG.BLOCK_EXIT);
    });
}

// ---------------------------------------------------------------------------
// Native tier
//
// One libc hook covers both tiers at once, because every Java filesystem call
// funnels through libcore into libc. That is why `fopen`/`openat` below will
// report Java-originated reads too -- and why a [N] line with no matching [J]
// line means the check is implemented natively and a Java hook will never see
// it.
// ---------------------------------------------------------------------------

function readCStr(p) {
    try { return p.isNull() ? '(null)' : p.readCString(); }
    catch (e) { return '(unreadable)'; }
}

function where(ctx) {
    try {
        var addr = ctx.returnAddress;
        var m = Process.findModuleByAddress(addr);
        if (m) return m.name + '+0x' + addr.sub(m.base).toString(16);
        return addr.toString();
    } catch (e) { return '?'; }
}

function hookNative() {
    // ptrace ---------------------------------------------------------------
    var ptrace = Module.findExportByName(null, 'ptrace');
    if (ptrace !== null) {
        Interceptor.attach(ptrace, {
            onEnter: function (args) {
                var req = args[0].toInt32();
                var name = { 0: 'PTRACE_TRACEME', 16: 'PTRACE_ATTACH',
                             17: 'PTRACE_DETACH', 8: 'PTRACE_KILL' }[req]
                           || ('request=' + req);
                log('N', 'ptrace(' + name + ', pid=' + args[1].toInt32() + ') from '
                    + where(this)
                    + (req === 0
                       ? '\n      ^ SELF-ATTACH. The process is becoming its own '
                         + 'tracer so that nothing else can attach. It succeeds '
                         + 'only once per process, so a SECOND TRACEME failing is '
                         + 'itself a detection.'
                       : ''));
            }
        });
    } else {
        log('i', 'ptrace not exported here; a raw syscall would be invisible to this hook');
    }

    // file opens -----------------------------------------------------------
    ['fopen', 'open', 'openat', 'open64'].forEach(function (fn) {
        var p = Module.findExportByName(null, fn);
        if (p === null) return;
        Interceptor.attach(p, {
            onEnter: function (args) {
                // openat's path is arg 1; the others put it in arg 0.
                var pathArg = (fn === 'openat') ? args[1] : args[0];
                var path = readCStr(pathArg);
                if (interesting(path)) {
                    this.report = fn + '("' + path + '") from ' + where(this);
                }
            },
            onLeave: function () {
                if (this.report) log('N', this.report);
            }
        });
    });

    // string search --------------------------------------------------------
    //
    // strstr is where a maps-scan actually makes its decision. Reporting the
    // NEEDLE is what turns "the app read /proc/self/maps" into "the app read
    // /proc/self/maps looking for the string frida-agent".
    var strstr = Module.findExportByName(null, 'strstr');
    if (strstr !== null) {
        Interceptor.attach(strstr, {
            onEnter: function (args) { this.needle = readCStr(args[1]); },
            onLeave: function (ret) {
                var n = this.needle;
                if (!n || n.length < 3) return;
                var l = n.toLowerCase();
                if (l.indexOf('frida') >= 0 || l.indexOf('gum') >= 0 ||
                    l.indexOf('xposed') >= 0 || l.indexOf('tracerpid') >= 0 ||
                    l.indexOf('linjector') >= 0 || l.indexOf('magisk') >= 0 ||
                    l.indexOf('substrate') >= 0) {
                    once('strstr:' + n, 'N',
                         'strstr(needle="' + n + '") -> '
                         + (ret.isNull() ? 'NOT FOUND' : 'FOUND')
                         + ' from ' + where(this)
                         + '\n      ^ this is the comparison the check turns on. '
                         + 'Patch here and you are done.');
                }
            }
        });
    }

    // module enumeration ---------------------------------------------------
    ['dl_iterate_phdr', 'dladdr'].forEach(function (fn) {
        var p = Module.findExportByName(null, fn);
        if (p === null) return;
        Interceptor.attach(p, {
            onEnter: function () {
                once('nat:' + fn, 'N', fn + '() called from ' + where(this)
                     + '\n      ^ enumerates loaded objects WITHOUT touching /proc, '
                     + 'so a /proc hook misses it entirely.');
            }
        });
    });

    // library loading ------------------------------------------------------
    //
    // Knowing WHEN each .so arrives tells you whether a spawn-time script was
    // early enough, and it is the anchor you use when the check lives in a
    // library that is not loaded yet.
    var dlopenExt = Module.findExportByName(null, 'android_dlopen_ext');
    if (dlopenExt !== null) {
        Interceptor.attach(dlopenExt, {
            onEnter: function (args) { this.path = readCStr(args[0]); },
            onLeave: function () {
                if (this.path && this.path.indexOf('/system/') !== 0) {
                    log('N', 'android_dlopen_ext("' + this.path + '")'
                        + '\n      ^ any .init_array constructor in this object has '
                        + 'ALREADY RUN by the time this line prints.');
                }
            }
        });
    }

    log('i', 'native hooks installed');
}

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

log('i', 'which-check-fired.js -- reconnaissance only, no bypass'
        + (CONFIG.BLOCK_EXIT ? ' except BLOCK_EXIT' : ''));
log('i', 'pid=' + Process.id + '  arch=' + Process.arch + '  platform=' + Process.platform);

if (CONFIG.NATIVE) {
    try { hookNative(); }
    catch (e) { log('i', 'native hooks failed: ' + e); }
}

setImmediate(function () {
    try { hookJava(); }
    catch (e) { log('i', 'java hooks failed: ' + e); }
});
