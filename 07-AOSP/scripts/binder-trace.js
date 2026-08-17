/*
 * binder-trace.js — trace every Java Binder call entering a process, with the
 *                   kernel-stamped caller identity.
 *
 * PURPOSE
 *   Trace A in ../README.md section 4.1 ends at android.os.Binder.execTransact,
 *   the single funnel through which EVERY incoming Java Binder transaction
 *   passes in EVERY process. One hook there sees all of it.
 *
 *   Attach to system_server and you observe every framework call the whole
 *   device makes, with the calling UID and PID that the binder driver stamped
 *   into the transaction — an identity the caller cannot forge.
 *
 *   Attach to an application and you observe every inbound call that app
 *   serves, which is how you find an app that is itself a Binder server.
 *
 *   This complements, and does not replace, the platform patch in section 3.10.
 *   Frida is available anywhere; the platform patch is below anything user
 *   space can hook. Use Frida when you cannot build an image.
 *
 * USAGE
 *   # every framework call on the device (requires root + a Frida server)
 *   frida -U -n system_server -l binder-trace.js
 *
 *   # everything a target app SERVES
 *   frida -U -f com.example.app -l binder-trace.js --no-pause
 *
 *   # spawn and record to a file
 *   frida -U -n system_server -l binder-trace.js -o binder-trace.log
 *
 * CONFIGURATION
 *   Edit the CONFIG block below. On system_server the unfiltered volume is
 *   enormous (thousands of transactions per second); set FILTER_UID or
 *   FILTER_INTERFACE before you attach or you will drown.
 *
 * OUTPUT
 *   [binder] <impl class>
 *            iface=<interface descriptor>  code=<txn code>
 *            callingUid=<uid>  callingPid=<pid>  pkg=<resolved package>
 *
 * SEE ALSO
 *   ../README.md sections 4.1, 7.2
 *   ../../25-Binder/README.md for the transaction format
 *   ../../53-Frida/README.md for Frida setup
 */

'use strict';

// ===========================================================================
// CONFIG
// ===========================================================================

var CONFIG = {
    // Only log transactions from this UID. null = all.
    // Find an app's UID with:  adb shell dumpsys package <pkg> | grep userId
    FILTER_UID: null,

    // Only log interfaces whose descriptor matches this regex. null = all.
    // e.g. /IActivityTaskManager|IPackageManager|IPermission/
    FILTER_INTERFACE: null,

    // Skip these very high-volume interfaces even when unfiltered, so the
    // interesting traffic is visible. Set to [] to see everything.
    NOISY_INTERFACES: [
        'android.os.IPowerManager',
        'android.app.IActivityManager$ContentProviderHolder',
        'android.content.pm.IPackageManager',   // comment out when auditing PM
        'android.os.IServiceManager'
    ],

    // Resolve the calling UID to a package name. Costs one extra IPC per
    // distinct UID; results are cached. Turn off if performance matters.
    RESOLVE_PACKAGE: true,

    // Print a Java stack trace for each transaction. Very verbose; useful when
    // you need to know WHY a call was made, not just that it was.
    STACK_TRACE: false,

    // Print a hex preview of the incoming Parcel. Requires reading the Parcel
    // without consuming it, which is not always safe — off by default.
    PARCEL_PREVIEW: false,

    // Summarise counts every N seconds instead of / as well as per-call lines.
    SUMMARY_INTERVAL_MS: 0        // 0 = disabled
};

// ===========================================================================

var stats = {};          // "iface#code" -> count
var uidToPkg = {};       // uid -> package name (cache)
var total = 0;
var suppressed = 0;

function resolvePackage(uid) {
    if (!CONFIG.RESOLVE_PACKAGE) return '';
    if (uidToPkg.hasOwnProperty(uid)) return uidToPkg[uid];
    var name = '?';
    try {
        var ActivityThread = Java.use('android.app.ActivityThread');
        var app = ActivityThread.currentApplication();
        if (app !== null) {
            var pm = app.getApplicationContext().getPackageManager();
            var pkgs = pm.getPackagesForUid(uid);
            if (pkgs !== null && pkgs.length > 0) {
                name = pkgs[0];
                if (pkgs.length > 1) name += '(+' + (pkgs.length - 1) + ')';
            }
        }
    } catch (e) { /* system_server may not have an Application */ }
    // Well-known system UIDs, so the output is readable even without a PM.
    if (name === '?') {
        var known = {
            0: 'root', 1000: 'system', 1001: 'radio', 1002: 'bluetooth',
            1013: 'media', 1017: 'keystore', 1019: 'drm', 1021: 'gps',
            1027: 'nfc', 1041: 'audioserver', 1047: 'cameraserver',
            2000: 'shell', 9999: 'nobody'
        };
        if (known.hasOwnProperty(uid)) name = known[uid];
    }
    uidToPkg[uid] = name;
    return name;
}

function shouldLog(iface, uid) {
    if (CONFIG.FILTER_UID !== null && uid !== CONFIG.FILTER_UID) return false;
    if (CONFIG.FILTER_INTERFACE !== null && !CONFIG.FILTER_INTERFACE.test(iface)) return false;
    for (var i = 0; i < CONFIG.NOISY_INTERFACES.length; i++) {
        if (iface === CONFIG.NOISY_INTERFACES[i]) return false;
    }
    return true;
}

Java.perform(function () {

    var Binder = Java.use('android.os.Binder');
    var Log = Java.use('android.util.Log');
    var Exception = Java.use('java.lang.Exception');

    console.log('');
    console.log('========================================================');
    console.log('  binder-trace.js — hooking android.os.Binder.execTransact');
    console.log('  Every incoming Java Binder call in this process passes');
    console.log('  through here. callingUid/callingPid are stamped by the');
    console.log('  KERNEL in binder_transaction() and cannot be forged.');
    console.log('========================================================');
    if (CONFIG.FILTER_UID !== null)
        console.log('  filter: uid == ' + CONFIG.FILTER_UID);
    if (CONFIG.FILTER_INTERFACE !== null)
        console.log('  filter: iface matches ' + CONFIG.FILTER_INTERFACE);
    if (CONFIG.NOISY_INTERFACES.length > 0)
        console.log('  suppressing ' + CONFIG.NOISY_INTERFACES.length + ' noisy interfaces');
    console.log('');

    // execTransact has had more than one signature across releases. Hook every
    // overload we find, so the script works on old and new platforms alike.
    var overloads = Binder.execTransact.overloads;
    console.log('  found ' + overloads.length + ' execTransact overload(s)');

    overloads.forEach(function (ovl) {
        ovl.implementation = function () {
            var args = Array.prototype.slice.call(arguments);
            // The transaction code is the first int argument in every known
            // signature.
            var code = args.length > 0 ? args[0] : -1;

            var uid = -1, pid = -1, iface = '?', impl = '?';
            try { uid = Binder.getCallingUid(); } catch (e) { }
            try { pid = Binder.getCallingPid(); } catch (e) { }
            try { iface = this.getInterfaceDescriptor(); } catch (e) { }
            try { impl = this.$className; } catch (e) { }
            if (iface === null || iface === undefined) iface = '(none)';

            total++;

            if (shouldLog(iface, uid)) {
                var key = iface + '#' + code;
                stats[key] = (stats[key] || 0) + 1;

                var pkg = resolvePackage(uid);
                console.log('[binder] ' + impl);
                console.log('         iface=' + iface + '  code=' + code);
                console.log('         callingUid=' + uid +
                            (pkg ? ' (' + pkg + ')' : '') +
                            '  callingPid=' + pid);

                if (CONFIG.STACK_TRACE) {
                    try {
                        console.log('         ' +
                            Log.getStackTraceString(Exception.$new())
                               .split('\n').slice(1, 12).join('\n         '));
                    } catch (e) { }
                }
            } else {
                suppressed++;
            }

            // Always call through. This hook observes; it does not modify.
            return ovl.apply(this, args);
        };
    });

    if (CONFIG.SUMMARY_INTERVAL_MS > 0) {
        setInterval(function () {
            console.log('');
            console.log('---- summary: ' + total + ' transactions (' +
                        suppressed + ' suppressed) ----');
            var keys = Object.keys(stats).sort(function (a, b) {
                return stats[b] - stats[a];
            });
            keys.slice(0, 20).forEach(function (k) {
                console.log('  ' + String(stats[k]).padStart(7) + '  ' + k);
            });
            console.log('');
        }, CONFIG.SUMMARY_INTERVAL_MS);
    }
});

/*
 * ---------------------------------------------------------------------------
 * INTERPRETING THE OUTPUT
 * ---------------------------------------------------------------------------
 *
 * iface  The AIDL interface descriptor. Search for it on cs.android.com to find
 *        the .aidl file, and search for "extends <Iface>.Stub" to find the
 *        server implementation. That class is where the permission checks are.
 *
 * code   The transaction code. It corresponds to a method in the AIDL file, in
 *        declaration order, starting at Stub.FIRST_CALL_TRANSACTION (1). To map
 *        a code to a method name, read the generated Stub in
 *        out/soong/.intermediates/... after a build, or count methods in the
 *        .aidl. Codes shift when methods are added, so they are release-specific.
 *
 * callingUid  The identity the KERNEL stamped into the transaction. This is the
 *        value every real permission check uses. Note that a hook in the CALLING
 *        process cannot change it — that is the entire point of section 4.3.
 *
 * ---------------------------------------------------------------------------
 * WHAT TO DO NEXT
 * ---------------------------------------------------------------------------
 *
 * Auditing a vendor service:
 *     CONFIG.FILTER_INTERFACE = /com\.vendor\./;
 *   then exercise the vendor's app and watch which methods it calls. That gives
 *   you the real API of an undocumented interface for free, including the
 *   transaction codes, which you then reach directly from a zero-permission app.
 *
 * Understanding what an app asks the system for:
 *     Attach to system_server with CONFIG.FILTER_UID set to the app's UID
 *     (adb shell dumpsys package <pkg> | grep userId).
 *
 * Finding an app that is itself a Binder server:
 *     Attach to the app. Any output at all means something outside the app is
 *     calling into it — check the callingUid to see who.
 */
