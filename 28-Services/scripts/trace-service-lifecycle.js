/*
 * trace-service-lifecycle.js -- watch every Service callback in a target app and
 *                               print WHO the caller was at each one.
 *
 * WHAT IT DOES
 *     A Service has two completely different kinds of entry point, and the
 *     difference is the whole security story of chapter 28:
 *
 *       LIFECYCLE callbacks  onCreate / onBind / onStartCommand / onUnbind /
 *                            onRebind / onDestroy / onTaskRemoved
 *                            These run on the app's MAIN thread, dispatched by
 *                            ActivityThread from a message. There is NO client
 *                            transaction in flight, so Binder.getCallingUid()
 *                            here returns the app's OWN uid. A caller check
 *                            written in one of these is checking the app
 *                            against itself and always passes.
 *
 *       BINDER dispatch      Binder.execTransact -> YourStub.onTransact -> your
 *                            AIDL method, and Handler.dispatchMessage for a
 *                            Messenger. These run on a Binder thread pool
 *                            thread, INSIDE the caller's transaction, so
 *                            Binder.getCallingUid() is the real, kernel-stamped
 *                            caller uid.
 *
 *     This script prints both, side by side, with the uid resolved to package
 *     names. Seeing "onBind uid=10310 (self)" one line above
 *     "execTransact code=1 uid=10291 (com.attacker.probe)" is the proof that
 *     goes in the report.
 *
 *     It also prints:
 *       - the interface descriptor of every binder returned from onBind
 *       - startForeground() calls, with the notification id
 *       - the onStartCommand return value, decoded to START_STICKY etc.
 *       - Messenger traffic: msg.what, msg.sendingUid, and whether msg.replyTo
 *         is set (an attacker-chosen reply channel -- see README section 5.3.4)
 *
 * HOW TO RUN
 *     # host -- frida-server already running on the device.
 *     # ALWAYS pass --runtime=v8. See the note below.
 *     frida -U -f com.example.target -l trace-service-lifecycle.js --runtime=v8
 *
 *     # attach to a process that is already running
 *     frida -U -n com.example.target -l trace-service-lifecycle.js --runtime=v8
 *
 *     # a service declared with android:process=":remote" is a DIFFERENT
 *     # process. Attach to its pid, not to the main one.
 *     adb shell ps -A | grep com.example.target
 *     frida -U -p 27413 -l trace-service-lifecycle.js --runtime=v8
 *
 *     # only trace classes under a package prefix (faster, less noise)
 *     frida -U -n com.example.target -l trace-service-lifecycle.js \
 *           --runtime=v8 -P '{"prefix":"com.example"}'
 *
 *     Options are read from the "prefix" and "quiet" parameters if present,
 *     otherwise from the CONFIG block below.
 *
 *     WHY --runtime=v8 IS NOT OPTIONAL HERE. On the setup this script was
 *     measured against (Frida 16.1.6, Windows host, Android 11 arm64), the
 *     default QuickJS runtime did not run the agent's timers: setInterval
 *     never fired, so the rescan for late-loaded Service classes and the
 *     deferred uid resolution both silently did nothing, and no asynchronous
 *     console.log output was delivered at all. The banner printed and then the
 *     script appeared dead. --runtime=v8 fixed it completely. If you see the
 *     banner and nothing else, change this before you change anything else.
 *
 * REQUIREMENTS
 *     frida / frida-tools on the host, a matching frida-server on the device,
 *     and root (or a repackaged app) to attach. Tested with Frida 16.1.6
 *     against Android 11 / API 30 arm64.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *     - Whether a service is VULNERABLE. It tells you which callbacks ran and
 *       who the caller was. Whether that caller should have been allowed is a
 *       judgement about what the method does, which is README sections 5 and 9.
 *     - Anything about a service in a process you did not attach to. A service
 *       declared with android:process=":remote" runs in a DIFFERENT process
 *       with a different pid; attach to that pid, not to the main one.
 *       `adb shell ps -A | grep <pkg>` will show you both.
 *     - Anything about an ISOLATED service. isolated_app processes are spawned
 *       per-bind and frida cannot usefully attach to them on a stock build.
 *     - The transaction ARGUMENTS. This script deliberately does not read the
 *       incoming Parcel: reading it moves the read cursor and breaks the real
 *       dispatch that follows. To see arguments, hook the generated AIDL method
 *       by name instead -- the method signature gives you typed parameters for
 *       free. See README section 7.5.
 *     - Native services. A service implemented in C++ with a hand-written
 *       BBinder never enters the Java Binder path. Use the native tracing in
 *       25-Binder for those.
 *     - Whether a uid maps to exactly one package. getPackagesForUid() returns
 *       an ARRAY, and a sharedUserId means several packages share one uid. The
 *       output prints all of them; do not quote just the first in a report.
 */

'use strict';

// ---------------------------------------------------------------- CONFIG
var CONFIG = {
    // Only hook Service subclasses whose class name starts with one of these.
    // Empty array = hook every Service subclass found, including framework and
    // library ones (noisy, but occasionally what you want).
    prefix: [],
    // Suppress the periodic rescan message.
    quiet: false,
    // How long to keep rescanning for late-loaded Service subclasses, in ms.
    // Services are often in classes that are not loaded until first use.
    rescanForMs: 60000,
    rescanEveryMs: 2000
};

if (typeof parameters !== 'undefined' && parameters) {
    if (parameters.prefix) {
        CONFIG.prefix = Array.isArray(parameters.prefix)
            ? parameters.prefix : [parameters.prefix];
    }
    if (parameters.quiet) CONFIG.quiet = true;
}

// ---------------------------------------------------------------- helpers

var SELF_UID = -1;
var uidCache = {};

function log(s) { console.log(s); }

function pad(s, n) {
    s = String(s);
    while (s.length < n) s += ' ';
    return s;
}

function startResult(v) {
    switch (v) {
        case 0: return 'START_STICKY_COMPATIBILITY';
        case 1: return 'START_STICKY';
        case 2: return 'START_NOT_STICKY';
        case 3: return 'START_REDELIVER_INTENT';
        default: return 'unknown(' + v + ')';
    }
}

// Resolve a uid to package names. A sharedUserId gives several; print them all.
//
// CRITICAL: this must NEVER be called from inside a Binder transaction.
// getPackagesForUid() is itself a Binder call to system_server. Issuing it while
// handling an inbound transaction on a Binder pool thread is exactly the
// reentrancy hazard README section 3.5.1 describes, and it was measured here:
// the first version of this script called it from the execTransact hook and the
// target's Binder threads stopped answering -- onServiceConnected never fired on
// the client and the trace produced no output at all. The lookup is now deferred
// to a timer that runs on a normal thread, and the hot path prints the bare
// number plus anything already cached.
var pendingUids = {};

function uidNameCached(uid) {
    if (uid === SELF_UID) return 'SELF';
    if (uidCache[uid] !== undefined) return uidCache[uid];
    if (uid === 0) return 'root';
    if (uid === 1000) return 'system';
    if (uid === 2000) return 'shell';
    if (uid >= 99000 && uid <= 99999) return 'isolated';
    if (uid >= 90000 && uid <= 98999) return 'isolated(appZygote)';
    pendingUids[uid] = true;          // resolved later, off the Binder thread
    return 'resolving...';
}

function resolvePendingUids() {
    var todo = Object.keys(pendingUids);
    if (todo.length === 0) return;
    pendingUids = {};
    Java.perform(function () {
        var app = Java.use('android.app.ActivityThread').currentApplication();
        if (app === null) return;
        var pm = app.getPackageManager();
        todo.forEach(function (k) {
            var uid = parseInt(k, 10);
            if (uidCache[uid] !== undefined) return;
            var name = '?';
            try {
                var pkgs = pm.getPackagesForUid(uid);
                if (pkgs !== null && pkgs.length > 0) name = pkgs.join(',');
            } catch (e) { name = '?'; }
            uidCache[uid] = name;
            log('[uid]       ' + uid + ' = ' + name);
        });
    });
}

function caller(tag) {
    var Binder = Java.use('android.os.Binder');
    var uid = Binder.getCallingUid();
    var pid = Binder.getCallingPid();
    var self = (uid === SELF_UID);
    return pad(tag, 18) + ' uid=' + pad(uid, 7) + ' pid=' + pad(pid, 7)
        + (self ? '(SELF -- no transaction in flight, a check here does NOTHING)'
                : '(' + uidNameCached(uid) + ')');
}

function descriptorOf(binder) {
    if (binder === null) return '<null -- onBind refused this Intent>';
    try {
        var d = binder.getInterfaceDescriptor();
        if (d === null || d === '') {
            return "'' (raw Binder -- no interface token is enforced, "
                 + 'every transaction code is reachable with an empty parcel)';
        }
        return "'" + d + "'";
    } catch (e) {
        return '<getInterfaceDescriptor threw: ' + e + '>';
    }
}

// Class-name prefixes that are never the app's own service. Enumerating and
// Java.use()-ing every loaded class whose name contains "Service" was tried
// first and it killed the target process outright -- thousands of Java.use()
// calls, each of which may run a static initialiser, is not a safe thing to do
// inside a live app. Individually every one of those hooks is fine; in bulk they
// are not. Scope the scan.
var SKIP_PREFIXES = [
    'android.', 'com.android.', 'androidx.', 'java.', 'javax.', 'sun.',
    'dalvik.', 'libcore.', 'kotlin.', 'kotlinx.', 'org.chromium.',
    'com.google.android.gms.internal.'
];

function isFramework(name) {
    for (var i = 0; i < SKIP_PREFIXES.length; i++) {
        if (name.indexOf(SKIP_PREFIXES[i]) === 0) return true;
    }
    return false;
}

function wanted(name) {
    if (CONFIG.prefix.length === 0) return !isFramework(name);
    for (var i = 0; i < CONFIG.prefix.length; i++) {
        if (name.indexOf(CONFIG.prefix[i]) === 0) return true;
    }
    return false;
}

// Assign an implementation without caring how many overloads there are, and
// without letting one bad class abort the whole scan.
function safeHook(C, method, overloadSig, impl) {
    try {
        var m = C[method];
        if (!m) return false;
        var target = (overloadSig && m.overload) ? m.overload.apply(m, overloadSig) : m;
        target.implementation = impl;
        return true;
    } catch (e) {
        return false;
    }
}

// ---------------------------------------------------------------- hooking

var hooked = {};

function isServiceSubclass(clazz) {
    try {
        var c = clazz.class;
        while (c !== null) {
            var n = c.getName();
            if (n === 'android.app.Service') return true;
            if (n === 'java.lang.Object') return false;
            c = c.getSuperclass();
        }
    } catch (e) { /* class failed to resolve; ignore */ }
    return false;
}

function hookService(name) {
    if (hooked[name]) return;
    hooked[name] = true;

    var C;
    try { C = Java.use(name); } catch (e) { return; }

    log('[+] hooking Service subclass ' + name);

    safeHook(C, 'onCreate', null, function () {
        log('[LIFECYCLE] ' + caller('onCreate') + '  ' + name);
        return this.onCreate();
    });

    safeHook(C, 'onBind', ['android.content.Intent'], function (intent) {
        log('[LIFECYCLE] ' + caller('onBind') + '  ' + name);
        log('            intent=' + (intent === null ? 'null' : intent.toString()));
        var b = this.onBind(intent);
        log('            returned binder descriptor=' + descriptorOf(b));
        return b;
    });

    safeHook(C, 'onStartCommand', ['android.content.Intent', 'int', 'int'],
        function (intent, flags, startId) {
            log('[LIFECYCLE] ' + caller('onStartCommand') + '  ' + name);
            log('            startId=' + startId + ' flags=0x' + flags.toString(16)
                + ' intent=' + (intent === null
                    ? 'NULL  <-- a START_STICKY restart; dereferencing it here crashes'
                    : intent.toString()));
            var r = this.onStartCommand(intent, flags, startId);
            log('            returned ' + startResult(r));
            return r;
        });

    safeHook(C, 'onUnbind', ['android.content.Intent'], function (intent) {
        var r = this.onUnbind(intent);
        log('[LIFECYCLE] ' + caller('onUnbind') + '  ' + name
            + '  returned ' + r + (r ? ' (onRebind will be used next time)' : ''));
        return r;
    });

    safeHook(C, 'onRebind', ['android.content.Intent'], function (intent) {
        log('[LIFECYCLE] ' + caller('onRebind') + '  ' + name);
        return this.onRebind(intent);
    });

    safeHook(C, 'onDestroy', null, function () {
        log('[LIFECYCLE] ' + caller('onDestroy') + '  ' + name);
        return this.onDestroy();
    });

    safeHook(C, 'onTaskRemoved', ['android.content.Intent'], function (root) {
        log('[LIFECYCLE] ' + caller('onTaskRemoved') + '  ' + name
            + '  (android:stopWithTask decides what happens next)');
        return this.onTaskRemoved(root);
    });
}

function scan() {
    var found = 0;
    Java.enumerateLoadedClassesSync().forEach(function (name) {
        if (hooked[name]) return;
        if (name.indexOf('[') === 0) return;
        if (name.indexOf('$$') >= 0) return;      // synthetic / lambda classes
        if (!wanted(name)) return;
        // Cheap prefilter: almost every Service subclass has "Service" in its
        // name. Drop this line if you are hunting for one that does not -- and
        // read the SKIP_PREFIXES comment before you widen the scan.
        if (name.indexOf('Service') < 0) return;
        var C;
        try { C = Java.use(name); } catch (e) { return; }
        if (isServiceSubclass(C)) { hookService(name); found++; }
    });
    return found;
}

Java.perform(function () {

    SELF_UID = Java.use('android.os.Process').myUid();
    log('');
    log('=== trace-service-lifecycle.js ===');
    log('this process uid = ' + SELF_UID);
    log('any callback reporting uid=' + SELF_UID + ' is NOT telling you who called.');
    if (CONFIG.prefix.length === 0) {
        log('scope: every non-framework class (SKIP_PREFIXES applies). Pass a');
        log('       "prefix" parameter to narrow it.');
    } else {
        log('scope: ' + CONFIG.prefix.join(', '));
    }
    log('');

    // ---- 1. Service lifecycle callbacks -----------------------------------
    scan();

    var elapsed = 0;
    var timer = setInterval(function () {
        elapsed += CONFIG.rescanEveryMs;
        var n = scan();
        if (n > 0 && !CONFIG.quiet) {
            log('[*] rescan found ' + n + ' newly loaded Service subclass(es)');
        }
        if (elapsed >= CONFIG.rescanForMs) clearInterval(timer);
    }, CONFIG.rescanEveryMs);

    // Deferred uid -> package resolution. See the comment on uidNameCached():
    // this MUST NOT happen on a Binder thread.
    setInterval(resolvePendingUids, 500);

    // ---- 2. startForeground ----------------------------------------------
    var Service = Java.use('android.app.Service');
    Service.startForeground.overload('int', 'android.app.Notification')
        .implementation = function (id, n) {
            log('[FOREGROUND] startForeground(id=' + id + ')  '
                + this.getClass().getName()
                + '   -- the 5s promotion deadline is now satisfied');
            return this.startForeground(id, n);
        };
    try {
        Service.startForeground.overload('int', 'android.app.Notification', 'int')
            .implementation = function (id, n, type) {
                log('[FOREGROUND] startForeground(id=' + id + ', type=0x'
                    + type.toString(16) + ')  ' + this.getClass().getName());
                return this.startForeground(id, n, type);
            };
    } catch (e) {
        log('[i] no 3-arg startForeground on this API level (that overload is API 29+)');
    }
    Service.stopSelf.overload().implementation = function () {
        log('[LIFECYCLE] stopSelf()  <-- no startId: stops even if another start is pending');
        return this.stopSelf();
    };

    // ---- 3. Binder dispatch: the real caller identity ---------------------
    // execTransact is the single funnel every Java Binder object goes through.
    var Binder = Java.use('android.os.Binder');
    var hookedExec = false;
    ['execTransact', 'execTransactInternal'].forEach(function (m) {
        if (hookedExec || !Binder[m]) return;
        try {
            Binder[m].overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var code = arguments[0];
                    var cls = this.getClass().getName();
                    if (wanted(cls) || CONFIG.prefix.length === 0) {
                        log('[BINDER]    ' + caller('execTransact')
                            + '  code=' + code + '  on ' + cls);
                    }
                    return ov.apply(this, arguments);
                };
            });
            hookedExec = true;
            log('[+] hooked android.os.Binder.' + m);
        } catch (e) { /* try the next name */ }
    });
    if (!hookedExec) {
        log('[!] could not hook execTransact; AIDL dispatch will not be traced');
    }

    // ---- 4. Messenger traffic --------------------------------------------
    //
    // DO NOT hook android.os.Handler.dispatchMessage for this. It was the first
    // thing tried here and it SIGSEGV'd the target: dispatchMessage runs for
    // every message on every looper in the process, thousands per second, and
    // routing all of that through a Java replacement is enough to kill the app.
    // The measured crash was:
    //     F libc: Fatal signal 11 (SIGSEGV) ... in tid 25428 (mple.notesvault)
    //
    // Handler$MessengerImpl.send is the correct hook. It is the ONLY entry point
    // for cross-process Messenger traffic, it is where the framework stamps
    // msg.sendingUid, and it fires only when a Messenger is actually used.
    try {
        var MessengerImpl = Java.use('android.os.Handler$MessengerImpl');
        MessengerImpl.send.implementation = function (msg) {
            try {
                var reply = msg.replyTo.value;
                log('[MESSENGER] ' + caller('Messenger.send')
                    + '  what=' + msg.what.value
                    + ' arg1=' + msg.arg1.value + ' arg2=' + msg.arg2.value
                    + ' replyTo=' + (reply === null
                        ? 'null'
                        : 'SET  <-- attacker-chosen reply channel, README 5.3.4'));
                var b = msg.getData();
                if (b !== null && !b.isEmpty()) log('            data=' + b.toString());
            } catch (e) { /* Message fields move across releases; never break send */ }
            return this.send(msg);
        };
        log('[+] hooked android.os.Handler$MessengerImpl.send');
    } catch (e) {
        log('[i] Handler$MessengerImpl not present on this build; '
            + 'Messenger traffic will not be traced');
    }

    log('[+] ready. Bind or start the service now.');
    log('');
});
