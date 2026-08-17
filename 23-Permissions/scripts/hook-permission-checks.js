/*
 * hook-permission-checks.js -- watch every permission question an app asks.
 *
 * WHAT IT DOES
 *     Hooks the whole Context.check*Permission / enforce*Permission family, the
 *     runtime request flow, and PackageManager.checkPermission, and prints:
 *
 *         - every permission string the app asks about, and the answer it got
 *         - every runtime request, with its request code
 *         - every result callback, which is the ONLY authoritative record of
 *           what the user actually decided
 *         - a loud flag, with a stack trace, on every use of the
 *           checkCallingOrSelfPermission / enforceCallingOrSelfPermission
 *           variants, which authorise everyone when they run off the Binder
 *           thread (README.md section 3.8)
 *         - a summary on exit: every permission seen, and its last answer
 *
 *     It gives you three things static analysis cannot. The complete set of
 *     permissions the app cares about, INCLUDING any hidden by string
 *     encryption -- the string must reach the framework verbatim, so it is
 *     always in the argument. The exact moment each request fires, which tells
 *     you what user action triggers it. And the threading context of every
 *     OrSelf call, which is what turns a grep hit into a finding.
 *
 * WHY IT OBSERVES RATHER THAN FORCES, BY DEFAULT
 *     Forcing checkSelfPermission to return GRANTED produces a misleading
 *     transcript: the app proceeds as though it has the permission, the
 *     underlying framework API refuses anyway, and you spend an hour debugging
 *     your own hook. You changed the app's BELIEF. The enforcing code is in
 *     system_server or in the kernel, and neither consults the app's belief.
 *
 *     --force exists because exploring a gated code path is legitimate. When it
 *     is on, every line is prefixed [FORCED] and a banner is printed at start,
 *     so a transcript can never be mistaken for an unmodified run.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *     - Whether a permission is actually GRANTED. It reports what the framework
 *       returned to this app at this moment. For grant state, use
 *       ../scripts/grant-state.py against a `dumpsys package` capture.
 *     - Anything about GID-backed permissions. INTERNET is a Linux group fixed
 *       at process fork, and no hook in this process can affect it. Hook
 *       checkSelfPermission("android.permission.INTERNET"), force GRANTED, and
 *       watch every socket call still return EACCES. Doing that once, on
 *       purpose, is the best possible lesson in the difference between
 *       defeating a check and defeating a control. See README.md section 3.5.
 *     - Anything about App Ops. An appop-flagged permission's effective state
 *       is a function of a separate state machine this script does not touch.
 *       Run `adb shell cmd appops get <pkg>` alongside.
 *     - Anything about a check that happens in ANOTHER process. A provider's
 *       permission is enforced in system_server and in the provider's own
 *       process. To see the callee's side, attach to the callee.
 *     - Permission checks in native code. There are essentially none: the
 *       permission model is a Java-layer and kernel concept, and native code
 *       inherits rather than checks.
 *
 * HOW TO RUN
 *     # host -- spawn and observe
 *     frida -U -f com.target.app -l hook-permission-checks.js --no-pause
 *
 *     # host -- attach to something already running
 *     frida -U -n com.target.app -l hook-permission-checks.js
 *
 *     # host -- explore a gated path. Transcript is marked as modified.
 *     frida -U -f com.target.app -l hook-permission-checks.js --no-pause \
 *           -P '{"force": true}'
 *
 *     # host -- quieter: skip the stack traces
 *     frida -U -f com.target.app -l hook-permission-checks.js --no-pause \
 *           -P '{"stacks": false}'
 *
 *     # Frida REPL, at any time
 *     rpc.exports.summary()      // everything seen so far, as an object
 *     rpc.exports.reset()        // clear the table
 *
 * REQUIREMENTS
 *     frida-server on the device, matching your frida-tools version. See
 *     53-Frida for setup, version pinning and the usual failure modes.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var PARAMS  = (typeof parameters !== 'undefined' && parameters) ? parameters : {};
var FORCE   = PARAMS.force  === true;
var STACKS  = PARAMS.stacks !== false;      // default on
var MAXFRM  = PARAMS.frames || 8;

var GRANTED = 0;                            // PackageManager.PERMISSION_GRANTED
var DENIED  = -1;                           // PackageManager.PERMISSION_DENIED

// permission -> { asked: n, lastAnswer: 'GRANTED'|'DENIED', methods: {} }
var seen = {};

function note(perm, answer, method) {
    if (!seen[perm]) {
        seen[perm] = { asked: 0, lastAnswer: null, methods: {} };
    }
    seen[perm].asked += 1;
    seen[perm].lastAnswer = answer;
    seen[perm].methods[method] = (seen[perm].methods[method] || 0) + 1;
}

function tag() {
    return FORCE ? '[FORCED] ' : '';
}

Java.perform(function () {

    var Log       = Java.use('android.util.Log');
    var Exception = Java.use('java.lang.Exception');
    var Binder    = Java.use('android.os.Binder');
    var Process   = Java.use('android.os.Process');

    function stack(skip) {
        try {
            var lines = Log.getStackTraceString(Exception.$new()).split('\n');
            // Drop the exception line and the frames inside this hook.
            return lines.slice(1 + (skip || 0), 1 + (skip || 0) + MAXFRM)
                        .map(function (l) { return '        ' + l.trim(); })
                        .join('\n');
        } catch (e) {
            return '        <stack unavailable: ' + e + '>';
        }
    }

    /* ---------------------------------------------------------------
     * Why the identity matters for the OrSelf variants.
     *
     * Binder.getCallingUid() returns the UID the binder driver stamped
     * into the CURRENT transaction. Off a Binder thread there is no
     * transaction, so it returns OUR OWN uid -- and that is exactly
     * when checkCallingOrSelfPermission stops being an authorisation
     * check and starts returning GRANTED for everybody.
     * --------------------------------------------------------------- */
    function identity() {
        try {
            var cu = Binder.getCallingUid();
            var my = Process.myUid();
            return 'callingUid=' + cu + ' myUid=' + my +
                   (cu === my ? '  <-- NO BINDER TRANSACTION IN PROGRESS' : '');
        } catch (e) {
            return 'identity unavailable: ' + e;
        }
    }

    if (FORCE) {
        console.log('');
        console.log('  ##################################################################');
        console.log('  #  FORCE MODE. Every check below returns PERMISSION_GRANTED.      #');
        console.log('  #  This transcript is MODIFIED. The app now BELIEVES it holds     #');
        console.log('  #  these permissions; the framework and the kernel do not agree.  #');
        console.log('  #  Do not paste this into a report as evidence of a bypass.       #');
        console.log('  ##################################################################');
        console.log('');
    }

    // -- 1. the Context family -------------------------------------------
    //
    // ContextWrapper is what an Activity or Service actually is, so hooking it
    // catches nearly every app-side call site. ContextImpl is hooked too
    // because framework code and some libraries hold one directly.

    var CONTEXT_CLASSES = ['android.content.ContextWrapper', 'android.app.ContextImpl'];

    var CHECK_ONE_ARG = [
        'checkSelfPermission',
        'checkCallingPermission',
        'checkCallingOrSelfPermission'
    ];

    CONTEXT_CLASSES.forEach(function (cls) {
        var C;
        try {
            C = Java.use(cls);
        } catch (e) {
            return;                                  // not present on this platform
        }

        CHECK_ONE_ARG.forEach(function (m) {
            if (!C[m]) { return; }
            try {
                C[m].overload('java.lang.String').implementation = function (perm) {
                    var real = this[m](perm);
                    var answer = (real === GRANTED) ? 'GRANTED' : 'DENIED';
                    note(perm, answer, m);

                    console.log(tag() + '[' + m + '] ' + perm + ' -> ' + answer);

                    if (m.indexOf('OrSelf') !== -1) {
                        console.log('    !! OrSelf variant. This returns GRANTED for ANY caller');
                        console.log('    !! when it runs off the Binder thread. ' + identity());
                        if (STACKS) { console.log(stack(1)); }
                    }

                    return FORCE ? GRANTED : real;
                };
            } catch (e) { /* overload absent on this platform */ }
        });

        // checkPermission(String, int pid, int uid) -- the explicit form.
        try {
            C.checkPermission.overload('java.lang.String', 'int', 'int')
             .implementation = function (perm, pid, uid) {
                var real = this.checkPermission(perm, pid, uid);
                var answer = (real === GRANTED) ? 'GRANTED' : 'DENIED';
                note(perm, answer, 'checkPermission');
                console.log(tag() + '[checkPermission] ' + perm +
                            ' pid=' + pid + ' uid=' + uid + ' -> ' + answer);
                return FORCE ? GRANTED : real;
            };
        } catch (e) { }

        // The enforce* family throws instead of returning. Wrap so a thrown
        // SecurityException is visible as the DENIED it is.
        [['enforceCallingPermission', 2],
         ['enforceCallingOrSelfPermission', 2]].forEach(function (pair) {
            var m = pair[0];
            if (!C[m]) { return; }
            try {
                C[m].overload('java.lang.String', 'java.lang.String')
                 .implementation = function (perm, msg) {
                    if (m.indexOf('OrSelf') !== -1) {
                        console.log('    !! ' + m + ' on ' + perm);
                        console.log('    !! ' + identity());
                        if (STACKS) { console.log(stack(1)); }
                    }
                    if (FORCE) {
                        note(perm, 'GRANTED', m);
                        console.log('[FORCED] [' + m + '] ' + perm + ' -> allowed');
                        return;
                    }
                    try {
                        this[m](perm, msg);
                        note(perm, 'GRANTED', m);
                        console.log('[' + m + '] ' + perm + ' -> GRANTED');
                    } catch (e) {
                        note(perm, 'DENIED', m);
                        console.log('[' + m + '] ' + perm + ' -> DENIED (SecurityException)');
                        throw e;                     // preserve app behaviour
                    }
                };
            } catch (e) { }
        });
    });

    // -- 2. PackageManager.checkPermission --------------------------------
    //
    // This asks about a PACKAGE, not a UID. It is a reporting call, not an
    // authorisation call: a package name is ambiguous under sharedUserId.

    try {
        var PM = Java.use('android.content.pm.PackageManager');
        PM.checkPermission.overload('java.lang.String', 'java.lang.String')
          .implementation = function (perm, pkg) {
            var real = this.checkPermission(perm, pkg);
            var answer = (real === GRANTED) ? 'GRANTED' : 'DENIED';
            note(perm, answer, 'PackageManager.checkPermission');
            console.log(tag() + '[PM.checkPermission] ' + perm +
                        ' pkg=' + pkg + ' -> ' + answer);
            return FORCE ? GRANTED : real;
        };
    } catch (e) { }

    // -- 3. the runtime request flow --------------------------------------

    try {
        var Activity = Java.use('android.app.Activity');

        Activity.requestPermissions.overload('[Ljava.lang.String;', 'int')
          .implementation = function (perms, code) {
            console.log('[requestPermissions] code=' + code +
                        ' perms=[' + perms.join(', ') + ']');
            if (STACKS) { console.log(stack(1)); }
            // The dialog is drawn by the PermissionController app, not by this
            // process. Everything after this line happens somewhere else, and
            // the result arrives asynchronously.
            return this.requestPermissions(perms, code);
        };

        Activity.onRequestPermissionsResult
          .overload('int', '[Ljava.lang.String;', '[I')
          .implementation = function (code, perms, results) {
            for (var i = 0; i < perms.length; i++) {
                var answer = (results[i] === GRANTED) ? 'GRANTED' : 'DENIED';
                note(perms[i], answer, 'onRequestPermissionsResult');
                console.log('[result] code=' + code + ' ' + perms[i] + ' -> ' + answer +
                            '   <-- the AUTHORITATIVE record of the user decision');
            }
            return this.onRequestPermissionsResult(code, perms, results);
        };

        Activity.shouldShowRequestPermissionRationale.overload('java.lang.String')
          .implementation = function (perm) {
            var r = this.shouldShowRequestPermissionRationale(perm);
            console.log('[shouldShowRationale] ' + perm + ' -> ' + r +
                        (r ? '' : '   (false means NEVER ASKED *or* PERMANENTLY REFUSED)'));
            return r;
        };
    } catch (e) { }

    // -- 4. the dynamic permission surface --------------------------------
    //
    // addPermission is only possible under a <permission-tree> the app
    // declared, and the platform limits the level to normal or dangerous --
    // so anything added here is, by construction, obtainable by an attacker.

    try {
        var PMcls = Java.use('android.content.pm.PackageManager');
        PMcls.addPermission.overload('android.content.pm.PermissionInfo')
          .implementation = function (info) {
            console.log('[addPermission] !! DYNAMIC PERMISSION being created at runtime');
            console.log('    name  = ' + info.name.value);
            console.log('    level = ' + info.protectionLevel.value +
                        '  (0=normal 1=dangerous; signature cannot be added dynamically)');
            console.log('    This permission is in NO manifest. Every manifest-only tool,');
            console.log('    including this chapter\'s permission-audit.py, is blind to it.');
            return this.addPermission(info);
        };
    } catch (e) { }

    console.log('[*] hook-permission-checks.js armed' +
                (FORCE ? '  (FORCE MODE)' : '  (observe only)'));
    console.log('[*] rpc.exports.summary() for the table, rpc.exports.reset() to clear');
});

rpc.exports = {
    summary: function () {
        return seen;
    },
    reset: function () {
        seen = {};
        return 'cleared';
    },
    // Printed table, for when you are driving from the REPL rather than a script.
    table: function () {
        var names = Object.keys(seen).sort();
        var out = [];
        out.push('PERMISSION QUESTIONS OBSERVED' + (FORCE ? '  (FORCE MODE - MODIFIED)' : ''));
        out.push('-----------------------------------------------------------------------');
        names.forEach(function (n) {
            var e = seen[n];
            out.push(pad(e.lastAnswer || '?', 9) + pad(String(e.asked), 5) + n);
            out.push('         via ' + Object.keys(e.methods).join(', '));
        });
        if (!names.length) { out.push('(nothing yet -- exercise the app)'); }
        return out.join('\n');
    }
};

function pad(s, n) {
    s = String(s);
    while (s.length < n) { s += ' '; }
    return s;
}
