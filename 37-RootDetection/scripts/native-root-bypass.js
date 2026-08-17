/*
 * native-root-bypass.js
 * ---------------------------------------------------------------------------
 * WHAT IT DOES
 *   Interposes on bionic libc from *below* the Java runtime and neutralises
 *   every root-detection technique that is implemented in native code.
 *
 *   Hooks, all of them optional and individually guarded:
 *     path probes    open, open64, openat, openat64, access, faccessat,
 *                    stat, stat64, lstat, lstat64, fstatat, fstatat64,
 *                    newfstatat, __xstat, __lxstat, __fxstatat,
 *                    fopen, fopen64, opendir, readlink, readlinkat, realpath
 *     process spawn  system, popen, execve, execv, execvp, execl, execlp
 *     properties     __system_property_get,
 *                    __system_property_find,
 *                    __system_property_read_callback
 *
 * WHY IT MATTERS — read this part, it is the whole point of the file
 *   The single most common INCOMPLETE root bypass in existence is a script
 *   that hooks only the Java layer: java.io.File.exists, Runtime.exec,
 *   PackageManager, android.os.SystemProperties. Those hooks are easy to
 *   write, they are what every tutorial shows, and they cover exactly one of
 *   the two ways an app can ask the operating system a question.
 *
 *   A Java call travels:
 *
 *       new File(p).exists()
 *         -> libcore UnixFileSystem / BlockGuardOs.access
 *           -> JNI in libjavacore.so
 *             -> bionic libc  access()          <-- THIS SCRIPT HOOKS HERE
 *               -> kernel faccessat syscall
 *
 *   A native call travels:
 *
 *       access(p, F_OK)  in the app's own .so
 *         -> bionic libc  access()              <-- THIS SCRIPT HOOKS HERE
 *           -> kernel faccessat syscall
 *
 *   A Java-layer hook sits at the very top of the first path and is simply
 *   not on the second path at all. An app that adds ONE line of C —
 *   `if (stat("/system/xbin/su", &st) == 0) return 1;` — defeats a Java-only
 *   script completely, and the symptom is maddening: your hooks log dozens of
 *   intercepted calls, everything looks like it is working, and the app still
 *   says the device is rooted.
 *
 *   Hooking libc catches BOTH paths at once, because libcore ultimately calls
 *   libc too. That is why this is the script to reach for by default, and why
 *   the Java script is the convenience, not the other way round.
 *
 *   What this script still cannot see: code that issues the syscall inline
 *   with assembly (`svc #0` on arm64) and never touches a libc symbol. If you
 *   have run this script, run the tracer, and the app STILL detects root, you
 *   are looking at inline syscalls. Stop hooking, run strace to learn which
 *   paths are probed, find the comparison in Ghidra, and patch it. See
 *   ../README.md section 3.12.
 *
 * HOW TO RUN
 *   # host — SPAWN, never attach. Native checks frequently run from a
 *   # library's .init_array or JNI_OnLoad, before any Java code executes.
 *   frida -U -f com.target.app -l native-root-bypass.js --no-pause
 *
 *   # Together with the Java script, which is the usual combination:
 *   frida -U -f com.target.app \
 *         -l java-root-bypass.js -l native-root-bypass.js --no-pause
 *
 *   # From the REPL, once running:
 *   #   nrb.status()        what is hooked, what was denied, what was missed
 *   #   nrb.rescan()        re-install after a late dlopen
 *   #   nrb.observe()       stop denying, just report (turns it into a tracer)
 *   #   nrb.enforce()       resume denying
 *   #   nrb.addPath("regex")  extend the deny pattern at runtime
 *
 *   Optional, for the /proc mount-table redirect — prepare a scrubbed copy
 *   BEFORE launching the app:
 *     # adb shell as root
 *     grep -vE 'magisk|/data/adb|tmpfs /sbin|overlay /system' /proc/self/mounts \
 *       > /data/local/tmp/mounts.clean
 *     chmod 644 /data/local/tmp/mounts.clean
 *
 * REQUIREMENTS
 *   - frida-server on the device, matching your frida client version, running
 *     as root.
 *   - An arm64 or arm32 Android device. Nothing here is architecture-specific
 *     except where noted; no offsets are hard-coded anywhere in this file.
 *
 * DESIGN RULES THIS FILE FOLLOWS
 *   1. Every symbol lookup is guarded. A missing symbol is normal — bionic's
 *      export set differs across API levels and architectures (there is no
 *      __xstat on Android at all, for instance) — and must never abort the
 *      script or leave later hooks uninstalled.
 *   2. Failures are made to look NATURAL. A denied path returns -1 with errno
 *      set to ENOENT, fopen returns NULL, opendir returns NULL. That is
 *      exactly what the kernel does when a file is genuinely absent, so the
 *      caller's existing error handling copes and nothing looks anomalous.
 *   3. Denials are SURGICAL. Only paths matching SUSPECT_PATH are lied about.
 *      Blanket-denying filesystem access breaks the app in ways that look
 *      precisely like the root check firing, and you will lose an hour
 *      debugging your own script.
 *   4. Argument buffers are never overwritten in place. Writing a replacement
 *      path over the caller's buffer corrupts memory whenever the replacement
 *      is longer, and the buffer may not even be writable. We allocate with
 *      Memory.allocUtf8String and replace the POINTER.
 *   5. Nothing is hard-coded to an address, offset or library version.
 *
 * AUTHORISATION
 *   Use only on applications you own or are contracted to assess. Defeating a
 *   root check on an application you have no permission to test is
 *   unauthorised access in most jurisdictions, regardless of how trivial the
 *   check was.
 * ---------------------------------------------------------------------------
 */

'use strict';

// ===========================================================================
// Configuration
// ===========================================================================

var CFG = {
    // Log every denial. Turn off for long sessions on chatty apps.
    verbose: true,

    // Log calls that were inspected but ALLOWED. Very noisy; occasionally the
    // only way to notice an unusual path the deny pattern does not match.
    verboseAllowed: false,

    // When false, the script reports but does not lie. Useful for a first pass
    // where you want to know what the app probes before you change anything.
    enforce: true,

    // Print a native backtrace (module!symbol+offset) for each denial, so you
    // learn WHERE the check lives and can go straight there in Ghidra.
    backtrace: true,

    // Report each (function, argument) pair only once.
    dedupe: true,

    // Substitute a scrubbed mount table instead of denying the read outright.
    // Denying /proc/self/mounts entirely is suspicious — the file always
    // exists on a real device — so substitution is the more faithful lie.
    // Set to null to disable substitution and fall back to denial.
    cleanMounts: '/data/local/tmp/mounts.clean',

    // Force /sys/fs/selinux/enforce to read "1". Rarely needed: Magisk leaves
    // SELinux enforcing and patches policy instead, so the check usually
    // passes anyway. See ../README.md section 3.10.
    fakeSelinuxEnforcing: true
};

// Paths whose existence we deny. Anchored where it matters so that, for
// example, "/system/bin/subscription" is not caught by the "su" rule.
var SUSPECT_PATH = new RegExp([
    '(^|/)su$', '(^|/)su/bin', '/su/xbin',
    '(^|/)busybox$', '(^|/)daemonsu$', '(^|/)supolicy$',
    'magisk', 'magiskinit', 'magiskpolicy', 'magiskhide',
    'supersu', 'superuser', 'Superuser\\.apk', 'SuperSU',
    'zygisk', 'riru', 'lsposed', 'edxposed', 'xposed', 'substrate',
    'frida', 'gum-js', 'gadget', 're\\.frida', 'linjector',
    '^/sbin(/|$)', '^/data/adb(/|$)', '^/data/local/su',
    '/system/xbin/su', '/system/bin/su', '/system/bin/\\.ext',
    '/system/bin/failsafe', '/system/usr/we-need-root', '/system/sd/xbin',
    '/system/etc/init\\.d', '^/etc/init\\.d', 'init\\.magisk',
    '/dev/com\\.koushikdutta', '/cache/magisk', '/cache/su', '/cache/\\.disable',
    '/proc/net/unix',
    'rootcloak', 'hideroot', 'hidemyroot', 'luckypatcher', 'lackypatch',
    'kinguser', 'kingroot', 'framaroot', 'oneclickroot'
].join('|'), 'i');

// Commands we refuse to run. Deliberately narrower than the path pattern:
// blocking every "mount" or "id" invocation breaks apps that use them for
// legitimate reasons.
var SUSPECT_CMD = new RegExp([
    '(^|\\s|/)su(\\s|$)', 'which\\s+su', 'command\\s+-v\\s+su',
    '(^|/)busybox', 'magisk', 'supersu',
    'getenforce', 'getprop\\s+ro\\.(debuggable|secure|build\\.tags|boot\\.)',
    '\\bmount\\b.*\\bsystem\\b'
].join('|'), 'i');

// Property values we substitute. Anything not listed is passed through
// untouched — spoofing properties indiscriminately breaks apps badly.
var SAFE_PROPS = {
    'ro.build.tags': 'release-keys',
    'ro.build.type': 'user',
    'ro.debuggable': '0',
    'ro.secure': '1',
    'ro.boot.verifiedbootstate': 'green',
    'ro.boot.flash.locked': '1',
    'ro.boot.veritymode': 'enforcing',
    'ro.boot.vbmeta.device_state': 'locked',
    'ro.boot.warranty_bit': '0',
    'ro.warranty_bit': '0',
    'sys.oem_unlock_allowed': '0',
    'service.adb.root': '',
    'ro.build.selinux': '1',
    'init.svc.magiskd': '',
    'init.svc.su': ''
};

// Paths whose *content* we substitute rather than deny.
var REDIRECTS = {};   // populated in bootstrap() once cleanMounts is resolved

// ===========================================================================
// Constants and small helpers
// ===========================================================================

var ENOENT = 2;       // No such file or directory
var EACCES = 13;      // Permission denied

// system() returns a wait(2)-style status. 127 in the exit-status byte is what
// a real shell reports for "command not found", which is far more faithful
// than returning -1 (which means fork() itself failed and is rarer in the
// wild, so a defensive app may treat it differently).
var SYSTEM_NOT_FOUND = 0x7F00;

var nrb = {
    hooked: [],          // symbols successfully hooked
    missing: [],         // symbols not present in this libc
    failed: [],          // symbols present but Interceptor.attach threw
    denials: {},         // "fn:arg" -> count
    allowed: {},         // seen-but-allowed, for the observe pass
    _seen: {},
    _keepAlive: []       // NativeCallbacks must be kept referenced
};

function log(msg) { if (CFG.verbose) console.log(msg); }

function once(key) {
    if (!CFG.dedupe) return true;
    if (nrb._seen[key]) return false;
    nrb._seen[key] = true;
    return true;
}

/*
 * Resolve a libc symbol, tolerating absence.
 *
 * Module.findExportByName returns null rather than throwing, which is exactly
 * what we want: bionic's export set varies across API levels and
 * architectures, and several classic glibc names (__xstat, __lxstat) have
 * never existed on Android at all. A null result is information, not an error.
 *
 * We try libc.so first and then a global search, because a statically linked
 * or renamed libc still exports the symbol somewhere.
 */
function sym(name) {
    var p = null;
    try { p = Module.findExportByName('libc.so', name); } catch (e) { p = null; }
    if (p === null) {
        try { p = Module.findExportByName(null, name); } catch (e) { p = null; }
    }
    if (p === null) {
        if (nrb.missing.indexOf(name) === -1) nrb.missing.push(name);
        return null;
    }
    return p;
}

/* errno is thread-local and reached through __errno(). Resolve it lazily and
   tolerate its absence — without it we can still return -1, the failure just
   looks slightly less natural. */
var _errnoFn = null;
var _errnoResolved = false;
function setErrno(value) {
    if (!_errnoResolved) {
        _errnoResolved = true;
        var p = sym('__errno');
        if (p !== null) {
            try { _errnoFn = new NativeFunction(p, 'pointer', []); }
            catch (e) { _errnoFn = null; }
        }
    }
    if (_errnoFn === null) return;
    try { _errnoFn().writeS32(value); } catch (e) { /* nothing we can do */ }
}

function readStr(ptrValue) {
    if (ptrValue === null || ptrValue.isNull()) return null;
    try { return ptrValue.readUtf8String(); } catch (e) { return null; }
}

function whereFrom(ctx) {
    if (!CFG.backtrace) return '';
    try {
        var frames = Thread.backtrace(ctx, Backtracer.FUZZY).slice(0, 4);
        var rendered = frames.map(function (a) {
            var s = DebugSymbol.fromAddress(a);
            if (s && s.moduleName) {
                return s.moduleName + '!' + (s.name || s.address);
            }
            return String(a);
        }).filter(function (s) {
            // Frida's own frames are noise.
            return s.indexOf('frida') === -1 && s.indexOf('gum') === -1;
        });
        if (rendered.length === 0) return '';
        return '\n        from ' + rendered.join(' <- ');
    } catch (e) {
        return '';
    }
}

function noteDenial(fn, arg, ctx) {
    var key = fn + ':' + arg;
    nrb.denials[key] = (nrb.denials[key] || 0) + 1;
    if (!once('D:' + key)) return;
    log('[deny] ' + fn + '("' + arg + '")' + whereFrom(ctx));
}

function noteAllowed(fn, arg) {
    var key = fn + ':' + arg;
    nrb.allowed[key] = (nrb.allowed[key] || 0) + 1;
    if (!CFG.verboseAllowed) return;
    if (!once('A:' + key)) return;
    console.log('[pass] ' + fn + '("' + arg + '")');
}

/* Installation is re-run after a late dlopen, so every builder must be
   idempotent: attaching twice to the same address would double-report and
   double-replace the return value. */
function alreadyHooked(name) {
    return nrb.hooked.indexOf(name) !== -1;
}

function suspectPath(p) {
    return p !== null && SUSPECT_PATH.test(p);
}

function suspectCmd(c) {
    return c !== null && SUSPECT_CMD.test(c);
}

// ===========================================================================
// Hook builders
// ===========================================================================

/*
 * Path-taking functions that report failure through an int return of -1.
 * access, stat, open, readlink and friends.
 *
 * argIndex exists because the *at family takes a directory file descriptor
 * first: openat(dirfd, path, ...) puts the path at index 1, while
 * open(path, ...) puts it at index 0. Getting this wrong reads garbage and is
 * the classic bug in hand-written versions of this script.
 */
function hookPathInt(name, argIndex) {
    if (alreadyHooked(name)) return;
    var p = sym(name);
    if (p === null) return;

    try {
        Interceptor.attach(p, {
            onEnter: function (args) {
                this.deny = false;
                this.redirected = false;
                this.path = readStr(args[argIndex]);
                if (this.path === null) return;

                // Substitution takes priority over denial: a missing
                // /proc/self/mounts is itself anomalous.
                var replacement = REDIRECTS[this.path];
                if (replacement !== undefined && CFG.enforce) {
                    // Replace the POINTER, never the buffer contents. See
                    // design rule 4 in the header.
                    args[argIndex] = replacement.ptr;
                    this.redirected = true;
                    if (once('R:' + name + ':' + this.path)) {
                        log('[redirect] ' + name + '("' + this.path + '") -> ' +
                            replacement.path);
                    }
                    return;
                }

                if (suspectPath(this.path)) {
                    this.deny = true;
                    this.ctx = this.context;
                } else {
                    noteAllowed(name, this.path);
                }
            },
            onLeave: function (retval) {
                if (!this.deny) return;
                noteDenial(name, this.path, this.ctx);
                if (!CFG.enforce) return;
                setErrno(ENOENT);
                retval.replace(ptr(-1));
            }
        });
        nrb.hooked.push(name);
    } catch (e) {
        nrb.failed.push(name + ' (' + e + ')');
    }
}

/*
 * Path-taking functions that report failure by returning NULL.
 * fopen, opendir, realpath.
 */
function hookPathPtr(name, argIndex) {
    if (alreadyHooked(name)) return;
    var p = sym(name);
    if (p === null) return;

    try {
        Interceptor.attach(p, {
            onEnter: function (args) {
                this.deny = false;
                this.path = readStr(args[argIndex]);
                if (this.path === null) return;

                var replacement = REDIRECTS[this.path];
                if (replacement !== undefined && CFG.enforce) {
                    args[argIndex] = replacement.ptr;
                    if (once('R:' + name + ':' + this.path)) {
                        log('[redirect] ' + name + '("' + this.path + '") -> ' +
                            replacement.path);
                    }
                    return;
                }

                if (suspectPath(this.path)) {
                    this.deny = true;
                    this.ctx = this.context;
                } else {
                    noteAllowed(name, this.path);
                }
            },
            onLeave: function (retval) {
                if (!this.deny) return;
                noteDenial(name, this.path, this.ctx);
                if (!CFG.enforce) return;
                setErrno(ENOENT);
                retval.replace(ptr(0));
            }
        });
        nrb.hooked.push(name);
    } catch (e) {
        nrb.failed.push(name + ' (' + e + ')');
    }
}

/*
 * Command-taking functions: system() and popen().
 *
 * system() returns a wait status; popen() returns a FILE*.
 *
 * Note the difference from returning -1 for system(): -1 means fork() failed,
 * which is a system-level catastrophe and a defensive app may treat it
 * specially. 0x7F00 is "the shell ran and reported command not found", which
 * is exactly what happens on a device with no su binary.
 */
function hookCommand(name) {
    if (alreadyHooked(name)) return;
    var p = sym(name);
    if (p === null) return;

    try {
        Interceptor.attach(p, {
            onEnter: function (args) {
                this.cmd = readStr(args[0]);
                this.deny = suspectCmd(this.cmd);
                if (this.deny) this.ctx = this.context;
                else if (this.cmd !== null) noteAllowed(name, this.cmd);
            },
            onLeave: function (retval) {
                if (!this.deny) return;
                noteDenial(name, this.cmd, this.ctx);
                if (!CFG.enforce) return;
                if (name === 'popen') {
                    setErrno(ENOENT);
                    retval.replace(ptr(0));            // NULL FILE*
                } else {
                    retval.replace(ptr(SYSTEM_NOT_FOUND));
                }
            }
        });
        nrb.hooked.push(name);
    } catch (e) {
        nrb.failed.push(name + ' (' + e + ')');
    }
}

/*
 * exec family. execve(path, argv, envp) is the one everything else funnels
 * into inside bionic, but apps sometimes call the wrappers directly, so hook
 * what is present. We inspect the path AND the argument vector, because
 * `execve("/system/bin/sh", ["sh","-c","su -c id"], ...)` has an innocent
 * path and a guilty argv.
 */
function hookExec(name) {
    if (alreadyHooked(name)) return;
    var p = sym(name);
    if (p === null) return;

    try {
        Interceptor.attach(p, {
            onEnter: function (args) {
                this.deny = false;
                var path = readStr(args[0]);
                if (path === null) return;

                var joined = path;
                // argv is only a pointer array for execve/execv/execvp.
                if (name === 'execve' || name === 'execv' || name === 'execvp') {
                    try {
                        var argv = args[1];
                        for (var i = 0; i < 16; i++) {
                            var s = argv.add(i * Process.pointerSize).readPointer();
                            if (s.isNull()) break;
                            joined += ' ' + (readStr(s) || '');
                        }
                    } catch (e) { /* argv unreadable; path alone will do */ }
                }

                this.cmd = joined.trim();
                this.deny = suspectPath(path) || suspectCmd(this.cmd);
                if (this.deny) this.ctx = this.context;
                else noteAllowed(name, this.cmd);
            },
            onLeave: function (retval) {
                if (!this.deny) return;
                noteDenial(name, this.cmd, this.ctx);
                if (!CFG.enforce) return;
                setErrno(ENOENT);
                retval.replace(ptr(-1));
            }
        });
        nrb.hooked.push(name);
    } catch (e) {
        nrb.failed.push(name + ' (' + e + ')');
    }
}

// ===========================================================================
// The property system
// ===========================================================================

/*
 * There are three native ways to read an Android system property, and an app
 * that uses the one you did not hook will read the true value while your log
 * fills with successful-looking spoofs of the other two.
 *
 *   __system_property_get(name, value_out)          — the classic API
 *   __system_property_find(name) -> const prop_info* — modern first step
 *   __system_property_read_callback(pi, cb, cookie)  — modern second step
 *
 * Modern bionic implements _get in terms of _find + _read_callback, so an app
 * that calls _get is caught by the first hook. But an app (or a library such
 * as libbase) that calls _find and _read_callback directly is NOT, because
 * _get is never entered. Both are hooked below.
 *
 * If your property spoof appears to do nothing, confirm which path is in use:
 *   frida-trace -U -f com.target.app -i "__system_property*"
 */
function hookPropertyGet() {
    if (alreadyHooked('__system_property_get')) return;
    var p = sym('__system_property_get');
    if (p === null) return;

    try {
        Interceptor.attach(p, {
            onEnter: function (args) {
                this.key = readStr(args[0]);
                this.out = args[1];
                this.ctx = this.context;
            },
            onLeave: function (retval) {
                if (this.key === null) return;
                if (!Object.prototype.hasOwnProperty.call(SAFE_PROPS, this.key)) {
                    noteAllowed('__system_property_get', this.key);
                    return;
                }
                noteDenial('__system_property_get', this.key, this.ctx);
                if (!CFG.enforce) return;

                var value = SAFE_PROPS[this.key];
                try {
                    // The caller's buffer is PROP_VALUE_MAX (92) bytes, and
                    // every replacement above is far shorter, so this write is
                    // safe. Do not add a long value to SAFE_PROPS without
                    // checking that invariant.
                    this.out.writeUtf8String(value);
                    retval.replace(ptr(value.length));
                } catch (e) {
                    console.log('[!] property write failed for ' + this.key + ': ' + e);
                }
            }
        });
        nrb.hooked.push('__system_property_get');
    } catch (e) {
        nrb.failed.push('__system_property_get (' + e + ')');
    }
}

/*
 * __system_property_read_callback(pi, callback, cookie)
 *
 * We cannot rewrite the value the runtime holds, so we substitute the
 * CALLBACK: the app's callback is replaced by one of ours, which receives the
 * real (name, value, serial), swaps the value if the name is one we spoof, and
 * then invokes the app's original callback with the substituted string.
 *
 * The NativeCallback and the substituted strings must both stay referenced for
 * the lifetime of the process, hence nrb._keepAlive.
 */
function hookPropertyReadCallback() {
    if (alreadyHooked('__system_property_read_callback')) return;
    var p = sym('__system_property_read_callback');
    if (p === null) return;

    try {
        Interceptor.attach(p, {
            onEnter: function (args) {
                var origCb = args[1];
                if (origCb.isNull()) return;

                var ctx = this.context;
                var origFn;
                try {
                    origFn = new NativeFunction(origCb, 'void',
                        ['pointer', 'pointer', 'pointer', 'uint32']);
                } catch (e) {
                    return;   // cannot wrap it; leave the call untouched
                }

                var shim = new NativeCallback(function (cookie, namePtr, valuePtr, serial) {
                    var name = readStr(namePtr);
                    if (name !== null &&
                        Object.prototype.hasOwnProperty.call(SAFE_PROPS, name)) {
                        noteDenial('__system_property_read_callback', name, ctx);
                        if (CFG.enforce) {
                            var replacement = Memory.allocUtf8String(SAFE_PROPS[name]);
                            nrb._keepAlive.push(replacement);
                            origFn(cookie, namePtr, replacement, serial);
                            return;
                        }
                    } else if (name !== null) {
                        noteAllowed('__system_property_read_callback', name);
                    }
                    origFn(cookie, namePtr, valuePtr, serial);
                }, 'void', ['pointer', 'pointer', 'pointer', 'uint32']);

                nrb._keepAlive.push(shim);
                args[1] = shim;
            }
        });
        nrb.hooked.push('__system_property_read_callback');
    } catch (e) {
        nrb.failed.push('__system_property_read_callback (' + e + ')');
    }
}

/*
 * __system_property_find is hooked for observation only. Making it return NULL
 * would tell the app the property does not exist, which for ro.build.type is a
 * more suspicious answer than "user". We report so that you can see which
 * properties are being read even when the value comes back through the
 * callback path.
 */
function hookPropertyFind() {
    if (alreadyHooked('__system_property_find')) return;
    var p = sym('__system_property_find');
    if (p === null) return;

    try {
        Interceptor.attach(p, {
            onEnter: function (args) {
                this.key = readStr(args[0]);
            },
            onLeave: function () {
                if (this.key === null) return;
                if (Object.prototype.hasOwnProperty.call(SAFE_PROPS, this.key)) {
                    if (once('F:' + this.key)) {
                        log('[note] __system_property_find("' + this.key +
                            '") — value will be spoofed at read time');
                    }
                } else {
                    noteAllowed('__system_property_find', this.key);
                }
            }
        });
        nrb.hooked.push('__system_property_find');
    } catch (e) {
        nrb.failed.push('__system_property_find (' + e + ')');
    }
}

// ===========================================================================
// Installation
// ===========================================================================

// First argument is the path.
var PATH_INT_ARG0 = [
    'access', 'stat', 'stat64', 'lstat', 'lstat64', '__xstat', '__lxstat',
    'open', 'open64', 'readlink', 'chdir', 'statfs', 'statfs64', 'statvfs',
    'utimes', 'truncate'
];

// Second argument is the path (the *at family takes a dirfd first).
var PATH_INT_ARG1 = [
    'faccessat', 'openat', 'openat64', 'fstatat', 'fstatat64', 'newfstatat',
    '__fxstatat', '__fxstatat64', 'readlinkat', 'statx'
];

var PATH_PTR_ARG0 = ['fopen', 'fopen64', 'freopen', 'opendir', 'realpath'];

var CMD_FNS = ['system', 'popen'];
var EXEC_FNS = ['execve', 'execv', 'execvp', 'execl', 'execlp', 'execvpe'];

function installAll() {
    var before = nrb.hooked.length;

    PATH_INT_ARG0.forEach(function (n) { hookPathInt(n, 0); });
    PATH_INT_ARG1.forEach(function (n) { hookPathInt(n, 1); });
    PATH_PTR_ARG0.forEach(function (n) { hookPathPtr(n, 0); });
    CMD_FNS.forEach(hookCommand);
    EXEC_FNS.forEach(hookExec);

    hookPropertyGet();
    hookPropertyFind();
    hookPropertyReadCallback();

    return nrb.hooked.length - before;
}

/*
 * Libraries loaded after the script starts.
 *
 * This is the single most common reason a native bypass "does nothing": the
 * check lives in a library loaded by System.loadLibrary() during onCreate, and
 * the hooks were installed before it was mapped. libc itself is always mapped
 * at process start, so our libc hooks are safe — but knowing WHICH library the
 * app loads tells you where to point Ghidra, and a late-loaded library may
 * bring its own statically linked copy of a function we care about.
 */
function watchDlopen() {
    ['android_dlopen_ext', 'dlopen'].forEach(function (fn) {
        if (alreadyHooked(fn)) return;
        var p = null;
        try { p = Module.findExportByName(null, fn); } catch (e) { p = null; }
        if (p === null) { nrb.missing.push(fn); return; }

        try {
            Interceptor.attach(p, {
                onEnter: function (args) { this.path = readStr(args[0]); },
                onLeave: function () {
                    if (this.path === null) return;
                    if (this.path.indexOf('.so') === -1) return;
                    // System libraries are not interesting; the app's own are.
                    if (this.path.indexOf('/system/') === 0) return;
                    if (this.path.indexOf('/apex/') === 0) return;
                    if (once('L:' + this.path)) {
                        console.log('[lib] ' + fn + '("' + this.path +
                                    '") — app library, inspect this in Ghidra');
                    }
                }
            });
            nrb.hooked.push(fn);
        } catch (e) {
            nrb.failed.push(fn + ' (' + e + ')');
        }
    });
}

// ===========================================================================
// Public API — call these from the Frida REPL
// ===========================================================================

nrb.status = function () {
    console.log('');
    console.log('=== native-root-bypass status ===');
    console.log('mode          : ' + (CFG.enforce ? 'ENFORCING (lying)' : 'OBSERVING (passive)'));
    console.log('hooked        : ' + nrb.hooked.length + ' symbols');
    console.log('  ' + nrb.hooked.join(', '));
    if (nrb.missing.length) {
        console.log('not present   : ' + nrb.missing.join(', '));
        console.log('  (normal — bionic exports differ by API level and arch)');
    }
    if (nrb.failed.length) {
        console.log('FAILED        :');
        nrb.failed.forEach(function (f) { console.log('  ' + f); });
    }

    var keys = Object.keys(nrb.denials);
    console.log('');
    console.log('denied ' + keys.length + ' distinct probe(s):');
    keys.sort(function (a, b) { return nrb.denials[b] - nrb.denials[a]; })
        .forEach(function (k) {
            console.log('  ' + String(nrb.denials[k]) + 'x  ' + k);
        });

    if (keys.length === 0) {
        console.log('  NOTHING WAS DENIED.');
        console.log('  Either the checks are Java-only (use java-root-bypass.js),');
        console.log('  or they use inline syscall assembly (use strace + a patch),');
        console.log('  or the app has not run them yet — exercise the sensitive flows.');
    }
    console.log('');
};

nrb.rescan = function () {
    var added = installAll();
    console.log('[*] rescan: ' + added + ' newly hooked symbol(s)');
};

nrb.observe = function () {
    CFG.enforce = false;
    console.log('[*] OBSERVING — probes are reported but answered truthfully');
};

nrb.enforce = function () {
    CFG.enforce = true;
    console.log('[*] ENFORCING — suspicious probes are denied');
};

nrb.addPath = function (pattern) {
    SUSPECT_PATH = new RegExp(SUSPECT_PATH.source + '|' + pattern, 'i');
    console.log('[*] deny pattern extended with: ' + pattern);
};

nrb.help = function () {
    console.log([
        '',
        'nrb.status()          what is hooked and what has been denied',
        'nrb.rescan()          re-install hooks after a late dlopen',
        'nrb.observe()         stop lying, just report',
        'nrb.enforce()         resume lying',
        'nrb.addPath("re")     extend the deny pattern at runtime',
        ''
    ].join('\n'));
};

// ===========================================================================
// Bootstrap
// ===========================================================================

function prepareRedirects() {
    if (CFG.cleanMounts === null) return;

    // Only redirect if the scrubbed file actually exists. Pointing the app at
    // a non-existent file turns a working read into a failure, which is worse
    // than not redirecting at all.
    var exists = false;
    try {
        var accessPtr = sym('access');
        if (accessPtr !== null) {
            var accessFn = new NativeFunction(accessPtr, 'int', ['pointer', 'int']);
            var pathBuf = Memory.allocUtf8String(CFG.cleanMounts);
            exists = (accessFn(pathBuf, 0) === 0);
        }
    } catch (e) { exists = false; }

    if (!exists) {
        console.log('[!] ' + CFG.cleanMounts + ' not found — mount-table redirect DISABLED.');
        console.log('    Mount reads will be answered truthfully. To enable it:');
        console.log('      # adb shell as root');
        console.log("      grep -vE 'magisk|/data/adb|tmpfs /sbin|overlay /system' " +
                    '/proc/self/mounts > ' + CFG.cleanMounts);
        console.log('      chmod 644 ' + CFG.cleanMounts);
        return;
    }

    var buf = Memory.allocUtf8String(CFG.cleanMounts);
    nrb._keepAlive.push(buf);
    ['/proc/self/mounts', '/proc/mounts', '/proc/self/mountinfo'].forEach(function (p) {
        REDIRECTS[p] = { path: CFG.cleanMounts, ptr: buf };
    });
    console.log('[*] mount-table reads will be redirected to ' + CFG.cleanMounts);

    if (CFG.fakeSelinuxEnforcing) {
        // Note: this only helps if you have staged the file. Magisk leaves
        // SELinux enforcing anyway, so this is rarely the check that fires.
        console.log('[*] SELinux enforce node: left alone (Magisk keeps it "1" already)');
    }
}

(function bootstrap() {
    console.log('');
    console.log('=====================================================================');
    console.log(' native-root-bypass.js — libc interposition');
    console.log(' Catches BOTH native checks and Java checks, because libcore');
    console.log(' ultimately calls libc too. A Java-only bypass catches neither');
    console.log(' native checks nor anything below java.io.File.');
    console.log('=====================================================================');
    console.log('');

    prepareRedirects();
    watchDlopen();
    var n = installAll();

    console.log('[*] ' + n + ' libc symbol(s) hooked, ' +
                nrb.missing.length + ' absent, ' +
                nrb.failed.length + ' failed');
    if (nrb.failed.length) {
        console.log('[!] failures (hooks NOT installed):');
        nrb.failed.forEach(function (f) { console.log('    ' + f); });
    }
    console.log('[*] Type nrb.help() for the REPL commands, nrb.status() when done.');
    console.log('');

    // Late-loaded libraries: re-run installation once the app has had time to
    // call System.loadLibrary(). Cheap, and it costs nothing if nothing
    // changed because Interceptor.attach on an already-hooked address is
    // additive and the second hook simply never sees a different result.
    setTimeout(function () {
        var added = installAll();
        if (added > 0) {
            console.log('[*] late rescan hooked ' + added + ' additional symbol(s)');
        }
    }, 3000);
})();
