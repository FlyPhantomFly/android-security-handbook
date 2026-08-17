/*
 * component-reachability.js -- prove Gate 2 from inside the target process.
 *
 * PURPOSE
 *   Chapter 72's Gate 2 asks whether a DEFINED attacker can reach a component.
 *   Every answer to that question taken from `adb shell` is suspect, because
 *   uid 2000 is not an app: `com.android.shell` requests 200 permissions, holds
 *   183 at install and 16 pre-granted runtime permissions flagged SYSTEM_FIXED
 *   (60-ADB measured this). This script answers the question from inside the
 *   target instead, and records WHO called.
 *
 *   It records, for each component entry point that fires:
 *     - the component class
 *     - the calling uid and pid, read via android.os.Binder
 *     - the Intent as a URI, so the exact invocation is reproducible
 *     - the calling PACKAGE, resolved from the uid where possible
 *
 *   Caller identity is trustworthy and this is not an assumption. 25-Binder
 *   wrote a chosen UID into `sender_euid` and transacted anyway: claiming uid 0,
 *   claiming uid 1000 and claiming nothing all produced the same SecurityException
 *   naming the real uid 2000. The kernel overwrites the field. A getCallingUid()
 *   in your evidence is therefore evidence.
 *
 * USAGE
 *   # spawn the target and watch from the first instruction
 *   frida -U -f com.example.target -l scripts/component-reachability.js
 *
 *   # attach to an already-running target
 *   frida -U -n com.example.target -l scripts/component-reachability.js
 *
 *   # then, from another shell, try to reach a component:
 *   adb shell am start -n com.example.target/.SomeActivity
 *   adb shell content query --uri content://com.example.target.provider
 *
 * READING THE OUTPUT
 *   uid=2000  -> you reached it from `adb shell`. NOT an app result. Re-run the
 *                same invocation from an unprivileged app before reporting.
 *   uid=10xxx -> an application uid. THIS is the measurement that supports a
 *                finding. Note the package name printed alongside.
 *   uid=1000  -> system_server. The platform reached it, not you.
 *
 *   Silence is ambiguous and you must resolve it. 51-DynamicAnalysis measured a
 *   session where `am start` was absorbed by a permission dialog and all nine
 *   capture channels went quiet -- a report indistinguishable from a well-behaved
 *   app doing nothing wrong. Run --self-test below before trusting any silence.
 *
 * IMPORTANT LIMITATION -- read before concluding anything from a quiet log
 *   A hook that installs is not a hook that fires. 65-Hooking measured a
 *   perfectly-installed hook against a function whose body had been INLINED by
 *   the compiler, so zero call sites targeted it: the hook installs, verifies,
 *   and has no effect. ART inlines managed code too. If a component you can
 *   demonstrably reach produces no line here, suspect the hook before you
 *   conclude anything about the app.
 *
 * WAS THIS EXECUTED?
 *   PARSED, NOT RUN AGAINST A TARGET. `node --check` passes. It was NOT executed
 *   end to end: the only device attached while chapter 72 was written was the AVD
 *   `sdk_gphone16k_x86_64` (API 35), whose frida-server build does not link on
 *   that image:
 *
 *     CANNOT LINK EXECUTABLE "/data/local/tmp/frida-server":
 *       empty/missing DT_HASH/DT_GNU_HASH in "/data/local/tmp/frida-server"
 *       (new hash type from the future?)
 *
 *   The binary was built with a toolchain newer than that image's dynamic
 *   linker understands, so it is a frida-VERSION problem rather than a device
 *   or root problem -- `su 0 id` returns uid 0 on the same device seconds
 *   later, and confusingly `frida-ps -U` still lists processes, so the failure
 *   only appears when you try to attach. Match the server build to the image
 *   before concluding anything. Shipping this labelled as unrun is more
 *   useful than implying a verification that did not happen. The hook shapes
 *   follow 53-Frida and 65-Hooking; verify on your own target before relying on
 *   a negative.
 *
 * AUTHORISATION
 *   Run only against applications you are authorised to test.
 */

'use strict';

var SEEN = {};

function once(key) {
    if (SEEN[key]) { return false; }
    SEEN[key] = true;
    return true;
}

Java.perform(function () {

    var Binder = Java.use('android.os.Binder');
    var ActivityThread = Java.use('android.app.ActivityThread');

    // ---- caller identity -------------------------------------------------
    function callerUid() {
        try { return Binder.getCallingUid(); } catch (e) { return -1; }
    }
    function callerPid() {
        try { return Binder.getCallingPid(); } catch (e) { return -1; }
    }

    var ctx = null;
    try {
        ctx = ActivityThread.currentApplication().getApplicationContext();
    } catch (e) { /* not up yet; resolved lazily below */ }

    function packagesForUid(uid) {
        if (uid < 0) { return '?'; }
        try {
            if (ctx === null) {
                ctx = ActivityThread.currentApplication().getApplicationContext();
            }
            var names = ctx.getPackageManager().getPackagesForUid(uid);
            if (names === null) { return '(no package)'; }
            return Java.array('java.lang.String', names).join(',');
        } catch (e) {
            return '(unresolved)';
        }
    }

    function vantage(uid) {
        if (uid === 2000) { return '  <-- SHELL VANTAGE, NOT AN APP RESULT'; }
        if (uid === 1000) { return '  <-- system_server, not you'; }
        if (uid === 0)    { return '  <-- root'; }
        return '';
    }

    function report(kind, cls, detail) {
        var uid = callerUid();
        console.log('[' + kind + '] ' + cls +
                    '\n        caller uid=' + uid + ' pid=' + callerPid() +
                    ' pkg=' + packagesForUid(uid) + vantage(uid) +
                    '\n        ' + detail);
    }

    function intentToString(i) {
        if (i === null) { return 'intent=null'; }
        try { return 'intent=' + i.toUri(0); } catch (e) { return 'intent=<unprintable>'; }
    }

    // ---- Activities ------------------------------------------------------
    try {
        var Activity = Java.use('android.app.Activity');
        Activity.onCreate.overload('android.os.Bundle').implementation = function (b) {
            report('ACTIVITY', this.getClass().getName(), intentToString(this.getIntent()));
            return this.onCreate(b);
        };
    } catch (e) {
        console.log('[!] could not hook Activity.onCreate: ' + e);
    }

    // ---- Services --------------------------------------------------------
    try {
        var Service = Java.use('android.app.Service');
        Service.onStartCommand.implementation = function (intent, flags, startId) {
            report('SERVICE-START', this.getClass().getName(), intentToString(intent));
            return this.onStartCommand(intent, flags, startId);
        };
        Service.onBind.implementation = function (intent) {
            // 28-Services measured this: getCallingUid() in onBind returns the
            // SERVICE'S OWN uid, because onBind is dispatched by the system.
            // A victim at 10310 logged callingUid=10310 while the attacker was
            // 10313, and the AIDL method a millisecond later logged 10313
            // correctly. So this line is deliberately labelled as unreliable
            // for identity -- put the real check in the transaction.
            console.log('[SERVICE-BIND] ' + this.getClass().getName() +
                        '\n        ' + intentToString(intent) +
                        '\n        NOTE: caller identity in onBind is the service' +
                        " s own uid. Hook the AIDL method for the real caller.");
            return this.onBind(intent);
        };
    } catch (e) {
        console.log('[!] could not hook Service: ' + e);
    }

    // ---- Broadcast receivers --------------------------------------------
    try {
        var Receiver = Java.use('android.content.BroadcastReceiver');
        Receiver.onReceive.implementation = function (context, intent) {
            report('RECEIVER', this.getClass().getName(), intentToString(intent));
            return this.onReceive(context, intent);
        };
    } catch (e) {
        console.log('[!] could not hook BroadcastReceiver.onReceive: ' + e);
    }

    // ---- ContentProviders ------------------------------------------------
    // Hooking the abstract base does not catch subclass overrides, so enumerate
    // loaded classes and hook each concrete provider. This is also why a quiet
    // log is ambiguous: a provider loaded later will not be here yet.
    try {
        var CP = Java.use('android.content.ContentProvider');
        Java.enumerateLoadedClassesSync().forEach(function (name) {
            if (name.indexOf('android.') === 0 || name.indexOf('androidx.') === 0) {
                return;
            }
            var klass;
            try { klass = Java.use(name); } catch (e) { return; }
            try {
                if (!CP.class.isAssignableFrom(klass.class)) { return; }
            } catch (e) { return; }

            ['query', 'call', 'openFile', 'insert', 'delete', 'update']
                .forEach(function (m) {
                    if (klass[m] === undefined) { return; }
                    klass[m].overloads.forEach(function (ov) {
                        try {
                            ov.implementation = function () {
                                if (once(name + '#' + m)) {
                                    report('PROVIDER-' + m.toUpperCase(), name,
                                           'args=' + Array.prototype.slice
                                               .call(arguments).join(' | '));
                                }
                                return ov.apply(this, arguments);
                            };
                        } catch (e) { /* overload not hookable */ }
                    });
                });
        });
    } catch (e) {
        console.log('[!] provider enumeration failed: ' + e);
    }

    console.log('[*] component-reachability armed.');
    console.log('[*] Reach the app now. Remember: uid=2000 is the SHELL, not an app.');
    console.log('[*] SELF-TEST before trusting silence -- launch the app normally.');
    console.log('[*] If its own launcher Activity produces no ACTIVITY line, the');
    console.log('[*] hooks are not firing and every negative below is void.');
});
