/*
 * activity-trace.js -- trace Activity starts, task placement, caller identity,
 *                      the result channel, and obscured touches, in one process.
 *
 * PURPOSE
 *     `dumpsys activity activities` gives you the task graph as it is NOW.
 *     scripts/task-affinity-map.py reads that. What neither shows is the
 *     SEQUENCE -- which call produced which placement, what identity the
 *     receiving Activity could see at that moment, and what came back out
 *     through the result channel. That sequence is where chapter 30's bugs live,
 *     so this script instruments it:
 *
 *       1. TASK PLACEMENT PER START. Every startActivity / startActivityForResult
 *          is logged with its task-affecting flags DECODED, and every arrival
 *          (onCreate / onNewIntent) is logged with getTaskId(), isTaskRoot() and
 *          the object's identity hash. Reading "onNewIntent, same instance" vs
 *          "onCreate, new instance" is how you read a launch mode off a running
 *          app instead of guessing it from the manifest.
 *
 *       2. CALLER IDENTITY, TIERED AND HONEST. For each arrival the script prints
 *          every identity source that exists and labels each with what it is
 *          worth. It also calls Binder.getCallingUid() inside onCreate and prints
 *          the result next to Process.myUid(), because they are equal, and seeing
 *          them equal once cures the single most common misconception in
 *          "hardened" Android code.
 *
 *       3. THE RESULT CHANNEL AS AN ATTACK CHANNEL. setResult, onActivityResult
 *          and finish() are traced, with the result Intent's data, flags and
 *          ClipData. A URI grant riding home on a result is invisible in a proxy
 *          and easy to miss in a decompiler.
 *
 *       4. OBSCURED TOUCHES. dispatchTouchEvent is hooked and every MotionEvent
 *          carrying FLAG_WINDOW_IS_OBSCURED is reported, together with whether
 *          the Activity's decor view actually filters them. That is the
 *          tapjacking question, answered at runtime rather than by grepping for
 *          filterTouchesWhenObscured.
 *
 * WHERE THE BOUNDARY IS
 *     26-Intent/scripts/intent-monitor.js owns the INTENT: full field dumps,
 *     nested-extra taint tracking for intent redirection, and PendingIntent
 *     mutability. Run BOTH -- they are complementary and deliberately do not
 *     overlap. If you want to know what was in the Intent, that is 26's script.
 *     If you want to know where the Activity landed, who it thought called it,
 *     and what went back out, this is the one.
 *
 * HOW TO RUN
 *     # host -- spawn (best: catches the very first Activity)
 *     frida -U -f com.example.target -l activity-trace.js
 *
 *     # host -- attach to something already running
 *     frida -U -n com.example.target -l activity-trace.js
 *
 *     # host -- trace the deliberately vulnerable lab app from examples/
 *     frida -U -f com.pentest.ch30.victim -l activity-trace.js
 *
 *     # from the Frida REPL, at runtime
 *     rpc.exports.tasks()      // one line per live Activity: task, root, mode
 *     rpc.exports.quiet(true)  // lifecycle noise off, security events only
 *     rpc.exports.stats()
 *
 * REQUIREMENTS
 *     frida-tools on the host and frida-server on the device (see 53-Frida for
 *     getting there). Java hooks only -- every class here is framework Java, so
 *     R8 obfuscation of the app does not affect it, and no native symbols are
 *     needed.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *     * WHO started an Activity, in the strong sense. There is no unforgeable
 *       caller identity on the Activity path; see README section 3.6. The script
 *       prints the weak sources and LABELS them weak. Do not report a package
 *       name from getCallingPackage() as proof of anything without pinning the
 *       signature.
 *     * Anything happening in system_server. The placement DECISION is made by
 *       ActivityStarter inside system_server, in another process. You see the
 *       call go in and the consequence come out, never the reasoning. Pair with
 *       `dumpsys activity activities` and, if you must, with
 *       `am start --activity-debug-log-resolution`.
 *     * Activities in OTHER processes. An app with android:process components has
 *       several; attach to each. A cross-app flow needs the script in both apps.
 *     * Whether an obscured touch was MALICIOUS. A legitimate system overlay --
 *       a volume panel, an OEM gesture bar, a screen-dimming app -- sets the same
 *       flag. The flag says "covered", never "attacked". Correlate with
 *       `dumpsys window windows` to see whose window it was.
 *     * Whether the task placement you observe is reachable by an UNPRIVILEGED
 *       app. If you drove it with `adb shell am`, you drove it as uid 2000, which
 *       is privileged and supplies FLAG_ACTIVITY_NEW_TASK for you.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

/* ------------------------------------------------------------------ CONFIG */
var CONFIG = {
    lifecycle: true,     // onCreate/onResume/onPause/onStop/onDestroy
    starts: true,        // startActivity family
    results: true,       // setResult / onActivityResult / finish
    touches: true,       // obscured-touch reporting
    identity: true,      // the identity block on every arrival
    stacks: false        // Java stack trace on each start (loud, but decisive)
};

/* ------------------------------------------------- task-affecting flag table
 * Only the flags that change TASK or STACK placement, plus the three with
 * security consequences that ride along on a forwarded Intent. The full flag
 * list is 26-Intent section 3.7; duplicating it here would be noise.
 */
var FLAGS = [
    [0x10000000, 'NEW_TASK'],
    [0x04000000, 'CLEAR_TOP'],
    [0x00008000, 'CLEAR_TASK'],
    [0x20000000, 'SINGLE_TOP'],
    [0x08000000, 'MULTIPLE_TASK'],
    [0x00020000, 'REORDER_TO_FRONT'],
    [0x40000000, 'NO_HISTORY'],
    [0x00004000, 'TASK_ON_HOME'],
    [0x00002000, 'RETAIN_IN_RECENTS'],
    [0x00001000, 'LAUNCH_ADJACENT'],
    [0x00800000, 'NEW_DOCUMENT'],
    [0x00010000, 'NO_ANIMATION'],
    [0x00400000, 'BROUGHT_TO_FRONT'],
    /* security-relevant riders */
    [0x02000000, 'FORWARD_RESULT  <-- result channel re-pointed'],
    [0x00000001, 'GRANT_READ_URI  <-- a grant is being issued'],
    [0x00000002, 'GRANT_WRITE_URI <-- a grant is being issued'],
    [0x00000040, 'GRANT_PERSISTABLE_URI'],
    [0x00000080, 'GRANT_PREFIX_URI']
];

function decodeFlags(f) {
    if (!f) { return '0x0'; }
    var out = [];
    for (var i = 0; i < FLAGS.length; i++) {
        if ((f & FLAGS[i][0]) === FLAGS[i][0]) { out.push(FLAGS[i][1]); }
    }
    return '0x' + (f >>> 0).toString(16) + (out.length ? ' [' + out.join(', ') + ']' : '');
}

/* MotionEvent flags -- frameworks/base/core/java/android/view/MotionEvent.java */
var FLAG_WINDOW_IS_OBSCURED = 0x1;
var FLAG_WINDOW_IS_PARTIALLY_OBSCURED = 0x2;   /* API 29+ */

/* --------------------------------------------------------------- reporting */
var STATS = { starts: 0, arrivals: 0, results: 0, obscured: 0 };
var LIVE = {};        /* identityHashCode -> {cls, task, root, mode} */
var QUIET = false;

function line(s) { console.log(s); }
function sec(s) { console.log('\n[!] ' + s); }

function head(tag, s) {
    line('[' + tag + '] ' + s);
}

/* ------------------------------------------------------------------- hooks */
Java.perform(function () {

    var Activity = Java.use('android.app.Activity');
    var Intent = Java.use('android.content.Intent');
    var Binder = Java.use('android.os.Binder');
    var Process = Java.use('android.os.Process');
    var System = Java.use('java.lang.System');
    var Log = Java.use('android.util.Log');
    var Exception = Java.use('java.lang.Exception');
    var MotionEvent = Java.use('android.view.MotionEvent');

    function id(obj) {
        try { return System.identityHashCode(obj); } catch (e) { return -1; }
    }

    function name(act) {
        try { return act.getClass().getName(); } catch (e) { return '?'; }
    }

    function stack(why) {
        if (!CONFIG.stacks) { return; }
        line('    ' + Log.getStackTraceString(Exception.$new(why))
            .split('\n').slice(1, 9).join('\n    '));
    }

    /* ---------------------------------------------------------- identity --
     * Printed on every arrival. The LABELS are the point: three tiers, and a
     * reader who internalises which line belongs to which tier will not write
     * an authorisation check against tier 3 again.
     */
    function identityBlock(act) {
        if (!CONFIG.identity || QUIET) { return; }
        var callingActivity = null, callingPackage = null, referrer = null;
        try { var ca = act.getCallingActivity(); callingActivity = ca ? ca.toString() : null; } catch (e) {}
        try { callingPackage = act.getCallingPackage(); } catch (e) {}
        try { var r = act.getReferrer(); referrer = r ? r.toString() : null; } catch (e) {}

        var binderUid = -1, myUid = -1;
        try { binderUid = Binder.getCallingUid(); } catch (e) {}
        try { myUid = Process.myUid(); } catch (e) {}

        line('    identity:');
        line('      [tier 2 system-stamped] getCallingActivity() = ' + callingActivity);
        line('      [tier 2 system-stamped] getCallingPackage()  = ' + callingPackage);
        if (callingActivity === null) {
            line('        ^ null means a PLAIN startActivity (no result channel), a');
            line('          PendingIntent, or the shell. You have NO identity here.');
        } else {
            line('        ^ set only because startActivityForResult was used. It is a');
            line('          PACKAGE NAME, not a signature -- pin the cert before trusting it.');
        }
        line('      [tier 3 attacker-authored] getReferrer()     = ' + referrer);
        line('      [USELESS HERE] Binder.getCallingUid() = ' + binderUid
            + '   Process.myUid() = ' + myUid
            + (binderUid === myUid ? '   <-- IDENTICAL. This is your OWN uid.' : ''));
        line('        ^ the Binder identity stamp is per-transaction. system_server');
        line('          made the start; by the time onCreate runs, the only calling');
        line('          identity in scope is your own. See 25-Binder.');
    }

    function taskBlock(act, tag) {
        var t = -1, root = null;
        try { t = act.getTaskId(); } catch (e) {}
        try { root = act.isTaskRoot(); } catch (e) {}
        LIVE[id(act)] = { cls: name(act), task: t, root: root };
        line('    task: taskId=' + t + '  isTaskRoot=' + root
            + '  instance=' + id(act) + '   (' + tag + ')');
    }

    function intentBlock(i, label) {
        if (i === null) { line('    ' + label + ': null'); return; }
        var comp = null, data = null, act = null, flags = 0;
        try { var c = i.getComponent(); comp = c ? c.flattenToShortString() : null; } catch (e) {}
        try { var d = i.getData(); data = d ? d.toString() : null; } catch (e) {}
        try { act = i.getAction(); } catch (e) {}
        try { flags = i.getFlags(); } catch (e) {}
        line('    ' + label + ': action=' + act + ' component=' + comp);
        if (data) { line('      data=' + data); }
        line('      flags=' + decodeFlags(flags));
        try {
            var clip = i.getClipData();
            if (clip !== null) {
                line('      clipData present, ' + clip.getItemCount()
                    + ' item(s) -- FLAG_GRANT_* applies to these too, not only to getData()');
            }
        } catch (e) {}
    }

    /* -------------------------------------------------------- arrivals ---- */
    Activity.onCreate.overload('android.os.Bundle').implementation = function (b) {
        STATS.arrivals++;
        if (!QUIET) {
            sec('ARRIVAL onCreate  ' + name(this));
            taskBlock(this, 'NEW INSTANCE -- the system constructed a fresh object');
            try { intentBlock(this.getIntent(), 'intent'); } catch (e) {}
            identityBlock(this);
        }
        return this.onCreate(b);
    };

    Activity.onNewIntent.overload('android.content.Intent').implementation = function (i) {
        STATS.arrivals++;
        sec('ARRIVAL onNewIntent  ' + name(this));
        line('    ^ the system REUSED an existing instance. That means singleTop at');
        line('      the top of its task, singleTask, singleInstance, or an explicit');
        line('      FLAG_ACTIVITY_SINGLE_TOP / FLAG_ACTIVITY_CLEAR_TOP on the caller.');
        line('    ^ AND: getIntent() still returns the ORIGINAL Intent unless the');
        line('      Activity calls setIntent(i). A component that authorises on');
        line('      getIntent() but acts on the new one is a real bug class.');
        taskBlock(this, 'REUSED INSTANCE');
        intentBlock(i, 'new intent');
        return this.onNewIntent(i);
    };

    if (CONFIG.lifecycle) {
        ['onResume', 'onPause', 'onStop', 'onRestart'].forEach(function (m) {
            try {
                Activity[m].overload().implementation = function () {
                    if (!QUIET) { head('life', m + '  ' + name(this) + '  t=' + this.getTaskId()); }
                    return this[m]();
                };
            } catch (e) { /* not all overloads exist on all API levels */ }
        });
        try {
            Activity.onDestroy.overload().implementation = function () {
                if (!QUIET) {
                    head('life', 'onDestroy  ' + name(this)
                        + '  isFinishing=' + this.isFinishing()
                        + '  instance=' + id(this));
                }
                delete LIVE[id(this)];
                return this.onDestroy();
            };
        } catch (e) {}
    }

    /* ---------------------------------------------------------- starts ---- */
    if (CONFIG.starts) {
        Activity.startActivity.overload('android.content.Intent').implementation = function (i) {
            STATS.starts++;
            sec('START startActivity  from ' + name(this) + ' (t=' + this.getTaskId() + ')');
            intentBlock(i, 'outgoing');
            line('    NOTE: no FLAG_ACTIVITY_NEW_TASK means the callee joins THIS task,');
            line('      even if it belongs to another package. That is how two packages');
            line('      end up in one task -- README section 3.8.');
            stack('startActivity');
            return this.startActivity(i);
        };

        Activity.startActivityForResult.overload('android.content.Intent', 'int')
            .implementation = function (i, rc) {
                STATS.starts++;
                sec('START startActivityForResult rc=' + rc + '  from ' + name(this));
                intentBlock(i, 'outgoing');
                line('    a RESULT CHANNEL now exists back to this Activity, and the');
                line('    callee can read getCallingActivity(). Both are consequences');
                line('    of using this overload rather than startActivity().');
                stack('startActivityForResult');
                return this.startActivityForResult(i, rc);
            };

        try {
            Activity.startActivities.overload('[Landroid.content.Intent;')
                .implementation = function (arr) {
                    STATS.starts++;
                    sec('START startActivities  n=' + arr.length + '  from ' + name(this));
                    line('    ^ a whole synthetic back stack in one call. Historically the');
                    line('      primitive behind the code-only task attacks, because it');
                    line('      builds a stack the user never navigated.');
                    for (var k = 0; k < arr.length; k++) { intentBlock(arr[k], '  [' + k + ']'); }
                    return this.startActivities(arr);
                };
        } catch (e) {}

        try {
            Activity.moveTaskToBack.overload('boolean').implementation = function (nonRoot) {
                sec('TASK moveTaskToBack(' + nonRoot + ')  ' + name(this));
                line('    ^ an app hiding its own task. Legitimate for a "close" button;');
                line('      also how an overlay sample gets out of the way after arming.');
                return this.moveTaskToBack(nonRoot);
            };
        } catch (e) {}
    }

    /* --------------------------------------------------------- results ---- */
    if (CONFIG.results) {
        Activity.setResult.overload('int', 'android.content.Intent')
            .implementation = function (code, data) {
                STATS.results++;
                sec('RESULT setResult(' + code + ')  from ' + name(this));
                intentBlock(data, 'result intent');
                line('    ^ this goes to whoever called startActivityForResult -- and if');
                line('      THEIR Intent carried FLAG_ACTIVITY_FORWARD_RESULT, one level');
                line('      further out again, to a party you never saw.');
                return this.setResult(code, data);
            };

        try {
            Activity.onActivityResult.overload('int', 'int', 'android.content.Intent')
                .implementation = function (req, res, data) {
                    STATS.results++;
                    sec('RESULT onActivityResult req=' + req + ' res=' + res
                        + '  in ' + name(this));
                    intentBlock(data, 'incoming result');
                    line('    ^ THIS IS ATTACKER-CONTROLLED INPUT. The Activity you started');
                    line('      may not be the one you meant to start (implicit Intent, or a');
                    line('      hijacked scheme), and the result is whatever it chose to');
                    line('      send. Validate it exactly as you would validate an inbound');
                    line('      Intent -- most code does not.');
                    return this.onActivityResult(req, res, data);
                };
        } catch (e) {}

        try {
            Activity.finish.overload().implementation = function () {
                if (!QUIET) { head('life', 'finish()  ' + name(this)); }
                return this.finish();
            };
        } catch (e) {}
    }

    /* --------------------------------------------------------- touches ---- */
    if (CONFIG.touches) {
        try {
            Activity.dispatchTouchEvent.overload('android.view.MotionEvent')
                .implementation = function (ev) {
                    var f = 0;
                    try { f = ev.getFlags(); } catch (e) {}
                    if (f & FLAG_WINDOW_IS_OBSCURED) {
                        STATS.obscured++;
                        sec('TAPJACK obscured touch delivered to ' + name(this));
                        line('    MotionEvent.flags=0x' + (f >>> 0).toString(16)
                            + '  FLAG_WINDOW_IS_OBSCURED set'
                            + ((f & FLAG_WINDOW_IS_PARTIALLY_OBSCURED)
                                ? ' (+PARTIALLY_OBSCURED)' : ''));
                        var filtered = null;
                        try {
                            filtered = this.getWindow().getDecorView()
                                .getFilterTouchesWhenObscured();
                        } catch (e) {}
                        line('    decorView.getFilterTouchesWhenObscured() = ' + filtered);
                        if (filtered === false) {
                            line('    ^ FINDING SHAPE: another application\'s window was covering');
                            line('      this one AT THE MOMENT OF THE TOUCH, and this Activity');
                            line('      accepted the event anyway. Confirm whose window it was');
                            line('      with `dumpsys window windows`, then decide whether the');
                            line('      action behind the tap is consequential. A legitimate');
                            line('      system overlay sets the same flag -- see the header.');
                        } else {
                            line('    ^ filtering is ON at the decor view. Note that filtering');
                            line('      is per-VIEW: a child that clears it is still exposed,');
                            line('      and a Dialog is a different window entirely.');
                        }
                    }
                    return this.dispatchTouchEvent(ev);
                };
        } catch (e) {}
    }

    line('[*] activity-trace.js armed.');
    line('[*] lifecycle=' + CONFIG.lifecycle + ' starts=' + CONFIG.starts
        + ' results=' + CONFIG.results + ' touches=' + CONFIG.touches);
    line('[*] rpc.exports: tasks(), quiet(bool), stats()');
});

/* --------------------------------------------------------------- exports */
rpc.exports = {
    quiet: function (v) { QUIET = !!v; return QUIET; },
    stats: function () { return STATS; },
    tasks: function () {
        var out = [];
        for (var k in LIVE) {
            if (Object.prototype.hasOwnProperty.call(LIVE, k)) {
                out.push(LIVE[k].cls + '  taskId=' + LIVE[k].task
                    + '  isTaskRoot=' + LIVE[k].root + '  instance=' + k);
            }
        }
        return out;
    }
};
