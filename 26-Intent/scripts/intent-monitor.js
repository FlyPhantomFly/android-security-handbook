/*
 * intent-monitor.js — log every Intent a target app sends and receives,
 *                     recursively dumping extras that are themselves Intents.
 *
 * PURPOSE
 *     Chapter 26's two primitives are invisible in a proxy and awkward to see
 *     in a decompiler:
 *
 *       1. INTENT REDIRECTION. A component reads an Intent out of an extra and
 *          starts it, so the send happens with the victim's uid. Statically this
 *          is a `getParcelableExtra` followed by a `check-cast` to
 *          Landroid/content/Intent; (README section 6.2). This script proves it
 *          dynamically: it tags every Intent that came out of an extra and shouts
 *          if that same object later reaches startActivity / startService /
 *          bindService / sendBroadcast / setResult.
 *
 *       2. PENDINGINTENT MUTABILITY. Every PendingIntent creation is logged with
 *          its decoded flags and whether the wrapped Intent has a component, so a
 *          "blank cheque" (mutable + no component) is obvious at the moment it is
 *          minted rather than after you have read a thousand lines of smali.
 *
 *     It also dumps ordinary traffic -- action, data, type, categories, component,
 *     package, flags and every extra -- which is usually how you discover the
 *     undocumented action or extra key that the deep-link handler actually wants.
 *
 * HOW TO RUN
 *     # host -- spawn the app under Frida (best: catches Application.onCreate)
 *     frida -U -f com.example.target -l intent-monitor.js
 *
 *     # host -- attach to something already running
 *     frida -U -n com.example.target -l intent-monitor.js
 *
 *     # host -- quieter: only the security-relevant events
 *     frida -U -f com.example.target -l intent-monitor.js -- --quiet
 *     # (or edit the CONFIG block below)
 *
 *     # from a Frida REPL, at runtime
 *     rpc.exports.setTaint(true)     rpc.exports.setVerbose(false)
 *     rpc.exports.stats()
 *
 * REQUIREMENTS
 *     frida-tools on the host, frida-server running on the device (or a Gadget),
 *     and the usual root/patched-app prerequisites -- see 53-Frida. Java only:
 *     everything hooked here is framework Java, so no native symbols are needed
 *     and obfuscation does not matter (framework class and method names are never
 *     renamed by R8).
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *     * WHO sent an inbound Intent. There is no caller identity on the Intent
 *       path (README section 3.8). The script prints getCallingActivity() where it
 *       exists, which is only after startActivityForResult, and says so.
 *     * Whether anything logged is a vulnerability. A nested Intent extra is the
 *       PRIMITIVE; whether it is a finding depends on what the component does with
 *       it and whether an unprivileged app can reach the component at all.
 *     * Intents sent by OTHER processes. This hooks one process. To see what the
 *       system delivered, hook the receiver side in the receiving app.
 *     * Intents constructed and sent entirely in native code, or sent by calling
 *       IActivityTaskManager over Binder directly. Rare, but a determined app can
 *       bypass every hook here. Cross-check with `dumpsys activity activities`.
 *     * Extras that fail to unparcel. If the sender embedded a Parcelable whose
 *       class the receiver does not have, Bundle.get() throws. The script catches
 *       that and reports the key -- a key that cannot be unparcelled is itself a
 *       clue that you are looking at the wrong receiver.
 *     * Anything about resolution. Use scripts/intent-surface-map.py for that.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

/* ----------------------------------------------------------------------- */
/*  CONFIG                                                                  */
/* ----------------------------------------------------------------------- */

var CONFIG = {
    verbose: true,       // dump every Intent, not just the interesting ones
    taint: true,         // track Intents that came out of an extra
    maxDepth: 4,         // how deep to recurse into nested Intent extras
    maxExtraLen: 400,    // truncate long extra values
    stacks: false        // print a Java stack trace for each REDIRECTION hit
};

// crude argv handling: `frida ... -- --quiet --stacks`
try {
    var argv = Process.argv || [];
    for (var ai = 0; ai < argv.length; ai++) {
        if (argv[ai] === '--quiet')  { CONFIG.verbose = false; }
        if (argv[ai] === '--stacks') { CONFIG.stacks = true;   }
        if (argv[ai] === '--no-taint') { CONFIG.taint = false; }
    }
} catch (e) { /* Process.argv is not available everywhere; defaults stand */ }

var STATS = { received: 0, sent: 0, nested: 0, redirections: 0, pendingIntents: 0 };

/* ----------------------------------------------------------------------- */
/*  Flag decoding                                                           */
/* ----------------------------------------------------------------------- */

var INTENT_FLAGS = [
    [0x00000001, 'GRANT_READ_URI_PERMISSION'],
    [0x00000002, 'GRANT_WRITE_URI_PERMISSION'],
    [0x00000004, 'FROM_BACKGROUND'],
    [0x00000008, 'DEBUG_LOG_RESOLUTION'],
    [0x00000010, 'EXCLUDE_STOPPED_PACKAGES'],
    [0x00000020, 'INCLUDE_STOPPED_PACKAGES'],
    [0x00000040, 'GRANT_PERSISTABLE_URI_PERMISSION'],
    [0x00000080, 'GRANT_PREFIX_URI_PERMISSION'],
    [0x00001000, 'ACTIVITY_LAUNCH_ADJACENT'],
    [0x00002000, 'ACTIVITY_RETAIN_IN_RECENTS'],
    [0x00008000, 'ACTIVITY_CLEAR_TASK'],
    [0x00010000, 'ACTIVITY_NO_ANIMATION'],
    [0x00020000, 'ACTIVITY_REORDER_TO_FRONT'],
    [0x00080000, 'ACTIVITY_NEW_DOCUMENT'],
    [0x00800000, 'ACTIVITY_EXCLUDE_FROM_RECENTS'],
    [0x01000000, 'ACTIVITY_PREVIOUS_IS_TOP'],
    [0x02000000, 'ACTIVITY_FORWARD_RESULT'],
    [0x04000000, 'ACTIVITY_CLEAR_TOP'],
    [0x08000000, 'ACTIVITY_MULTIPLE_TASK / RECEIVER_NO_ABORT'],
    [0x10000000, 'ACTIVITY_NEW_TASK / RECEIVER_FOREGROUND'],
    [0x20000000, 'ACTIVITY_SINGLE_TOP / RECEIVER_REPLACE_PENDING'],
    [0x40000000, 'ACTIVITY_NO_HISTORY / RECEIVER_REGISTERED_ONLY']
];

// The four flags that turn a redirection into grant laundering (27-ContentProviders).
var GRANT_MASK = 0x00000001 | 0x00000002 | 0x00000040 | 0x00000080;

function decodeIntentFlags(f) {
    if (f === 0) { return '0x0'; }
    var names = [];
    for (var i = 0; i < INTENT_FLAGS.length; i++) {
        if ((f & INTENT_FLAGS[i][0]) !== 0) { names.push(INTENT_FLAGS[i][1]); }
    }
    return '0x' + (f >>> 0).toString(16) + (names.length ? ' [' + names.join(', ') + ']' : '');
}

var PI_FLAGS = [
    [0x02000000, 'MUTABLE'],
    [0x04000000, 'IMMUTABLE'],
    [0x08000000, 'UPDATE_CURRENT'],
    [0x10000000, 'CANCEL_CURRENT'],
    [0x20000000, 'NO_CREATE'],
    [0x40000000, 'ONE_SHOT']
];

function decodePendingFlags(f) {
    var names = [];
    for (var i = 0; i < PI_FLAGS.length; i++) {
        if ((f & PI_FLAGS[i][0]) !== 0) { names.push(PI_FLAGS[i][1]); }
    }
    return '0x' + (f >>> 0).toString(16) + (names.length ? ' [' + names.join(', ') + ']' : '');
}

/* ----------------------------------------------------------------------- */
/*  Output helpers                                                          */
/* ----------------------------------------------------------------------- */

function pad(depth) {
    var s = '';
    for (var i = 0; i < depth; i++) { s += '    '; }
    return s;
}

function line(s) { console.log(s); }

function banner(kind, where) {
    line('');
    line('======== ' + kind + '  ' + where + ' ========');
}

function truncate(s) {
    if (s === null || s === undefined) { return String(s); }
    s = String(s);
    return s.length > CONFIG.maxExtraLen
        ? s.substring(0, CONFIG.maxExtraLen) + '...<' + s.length + ' chars>'
        : s;
}

/* ----------------------------------------------------------------------- */
/*  Taint table                                                             */
/*                                                                          */
/*  We key on System.identityHashCode, not on Intent.hashCode(). Intent      */
/*  overrides hashCode via filterHashCode in some paths, and two distinct    */
/*  Intents with the same fields would collide -- which would produce false  */
/*  REDIRECTION reports. identityHashCode is the object identity we want:    */
/*  "is this the SAME object that came out of the extra?"                    */
/* ----------------------------------------------------------------------- */

var TAINT = {};   // identityHashCode -> extra key it came from

function taintKey(obj) {
    try {
        var System = Java.use('java.lang.System');
        return System.identityHashCode(obj);
    } catch (e) {
        return null;
    }
}

function markTainted(obj, fromKey) {
    if (!CONFIG.taint) { return; }
    var k = taintKey(obj);
    if (k !== null) { TAINT[k] = fromKey; }
}

function taintedFrom(obj) {
    if (!CONFIG.taint || obj === null) { return null; }
    var k = taintKey(obj);
    return (k !== null && Object.prototype.hasOwnProperty.call(TAINT, k)) ? TAINT[k] : null;
}

/* ----------------------------------------------------------------------- */
/*  Intent dumping                                                          */
/* ----------------------------------------------------------------------- */

var Intent, Bundle, Uri, ComponentName, Log;

function dumpIntent(intent, depth, label) {
    if (intent === null) { line(pad(depth) + (label || '') + 'null'); return; }
    var p = pad(depth);

    var comp = null, compStr = 'null (IMPLICIT)';
    try {
        comp = intent.getComponent();
        if (comp !== null) { compStr = comp.flattenToShortString(); }
    } catch (e) { compStr = '<error>'; }

    var flags = 0;
    try { flags = intent.getFlags(); } catch (e) { }

    if (label) { line(p + label); }
    line(p + '  action    = ' + intent.getAction());
    line(p + '  data      = ' + intent.getDataString());
    line(p + '  type      = ' + intent.getType());
    line(p + '  component = ' + compStr);
    line(p + '  package   = ' + intent.getPackage());
    line(p + '  flags     = ' + decodeIntentFlags(flags));

    try {
        // getCategories() returns an ArraySet whose JS wrapper does not stringify
        // usefully -- printing it directly gives "[object Object]". Walk it.
        var cats = intent.getCategories();
        if (cats !== null) {
            var arr = cats.toArray();
            var names = [];
            for (var ci = 0; ci < arr.length; ci++) { names.push(arr[ci].toString()); }
            line(p + '  categories= [' + names.join(', ') + ']');
            if (names.indexOf('android.intent.category.BROWSABLE') >= 0) {
                line(p + '    ^ BROWSABLE: this Intent shape is reachable from a WEB PAGE.');
            }
        }
    } catch (e) { }

    if ((flags & GRANT_MASK) !== 0) {
        line(p + '  *** carries URI GRANT flags -- if this Intent is forwarded, the');
        line(p + '      forwarder lends its own read/write authority. 27-ContentProviders.');
    }

    dumpExtras(intent, depth);
}

function dumpExtras(intent, depth) {
    var b = null;
    try { b = intent.getExtras(); } catch (e) {
        line(pad(depth) + '  extras    = <unparcel failed: ' + e + '>');
        return;
    }
    if (b === null) { return; }

    var keys;
    try { keys = b.keySet().toArray(); } catch (e) {
        line(pad(depth) + '  extras    = <keySet failed: ' + e + '>');
        return;
    }
    if (keys.length === 0) { return; }

    line(pad(depth) + '  extras    (' + keys.length + '):');
    for (var i = 0; i < keys.length; i++) {
        var k = keys[i].toString();
        var v;
        try {
            // This is what forces the lazy unparcel (README section 3.1).
            v = b.get(k);
        } catch (e) {
            line(pad(depth) + '    ' + k + ' = <BadParcelable: ' + e + '>');
            line(pad(depth) + '      ^ the sender embedded a class this app does not have.');
            continue;
        }
        if (v === null) { line(pad(depth) + '    ' + k + ' = null'); continue; }

        var cls = '';
        try { cls = v.$className || v.getClass().getName(); } catch (e) { }

        if (cls === 'android.content.Intent') {
            STATS.nested++;
            line(pad(depth) + '    ' + k + ' = <<< NESTED INTENT >>>');
            line(pad(depth) + '      ^ THIS is the intent-redirection primitive. If this app');
            line(pad(depth) + '        starts it, the send runs with THIS app\'s uid.');
            markTainted(v, k);
            if (depth < CONFIG.maxDepth) {
                dumpIntent(Java.cast(v, Intent), depth + 2, '');
            } else {
                line(pad(depth) + '      (max depth reached)');
            }
        } else if (cls === 'android.app.PendingIntent') {
            line(pad(depth) + '    ' + k + ' = <<< PENDINGINTENT >>>');
            try {
                var pi = Java.cast(v, Java.use('android.app.PendingIntent'));
                line(pad(depth) + '      creatorPackage = ' + pi.getCreatorPackage());
                line(pad(depth) + '      creatorUid     = ' + pi.getCreatorUid());
                line(pad(depth) + '      ^ creator* is SYSTEM-STAMPED and is the one trustworthy');
                line(pad(depth) + '        identity primitive on the Intent path (section 3.8).');
            } catch (e) {
                line(pad(depth) + '      <' + e + '>');
            }
        } else if (cls === 'android.os.Bundle') {
            line(pad(depth) + '    ' + k + ' = Bundle ' + truncate(v.toString()));
        } else {
            line(pad(depth) + '    ' + k + ' = (' + cls + ') ' + truncate(v.toString()));
        }
    }
}

/* ----------------------------------------------------------------------- */
/*  The send-side check                                                     */
/* ----------------------------------------------------------------------- */

function checkSend(intent, apiName, self) {
    STATS.sent++;
    var from = taintedFrom(intent);

    if (from !== null) {
        STATS.redirections++;
        line('');
        line('[!!] REDIRECTION  ' + apiName);
        try { line('     in: ' + self.$className); } catch (e) { }
        line('     an Intent taken from extra "' + from + '" is being sent.');
        line('     It will be delivered with THIS app\'s uid, so it can reach this');
        line('     app\'s non-exported components and use permissions this app holds.');
        dumpIntent(intent, 1, '');
        if (CONFIG.stacks) {
            try {
                line(Java.use('android.util.Log').getStackTraceString(
                    Java.use('java.lang.Exception').$new('redirection stack')));
            } catch (e) { }
        }
        return;
    }

    if (!CONFIG.verbose) {
        // Quiet mode still reports implicit sends, because an implicit Intent
        // carrying data is how apps leak (README section 5.5).
        var implicit = false;
        try {
            implicit = (intent !== null && intent.getComponent() === null
                        && intent.getPackage() === null);
        } catch (e) { }
        if (!implicit) { return; }
        banner('SENT (IMPLICIT)', apiName);
        dumpIntent(intent, 1, '');
        line('     ^ no component and no package: the SYSTEM picks the target, and');
        line('       any app declaring a matching filter is a candidate.');
        return;
    }

    banner('SENT', apiName);
    dumpIntent(intent, 1, '');
}

/* ----------------------------------------------------------------------- */
/*  Hooks                                                                   */
/* ----------------------------------------------------------------------- */

Java.perform(function () {

    Intent = Java.use('android.content.Intent');
    Bundle = Java.use('android.os.Bundle');
    Uri = Java.use('android.net.Uri');
    ComponentName = Java.use('android.content.ComponentName');
    Log = Java.use('android.util.Log');

    line('[*] intent-monitor.js loaded  verbose=' + CONFIG.verbose
         + ' taint=' + CONFIG.taint);
    line('[*] reminder: an inbound Intent carries NO caller identity. Nothing this');
    line('    script prints tells you who sent it. README section 3.8.');

    /* ---------- receiving side ---------- */

    var Activity = Java.use('android.app.Activity');

    Activity.onCreate.overload('android.os.Bundle').implementation = function (b) {
        var r = this.onCreate(b);
        try {
            STATS.received++;
            banner('RECEIVED  Activity.onCreate', this.$className);
            var callingAct = null;
            try { callingAct = this.getCallingActivity(); } catch (e) { }
            if (callingAct !== null) {
                line('  getCallingActivity() = ' + callingAct.flattenToShortString());
                line('  ^ present, so the caller used startActivityForResult. This is');
                line('    SYSTEM-STAMPED and is trustworthy -- but a package NAME is');
                line('    still not an identity; bind it to a signing certificate.');
            } else {
                line('  getCallingActivity() = null');
                line('  ^ plain startActivity (or a PendingIntent, or shell). There is');
                line('    NO caller identity available to this component at all.');
            }
            dumpIntent(this.getIntent(), 1, '');
        } catch (e) { line('[!] onCreate hook error: ' + e); }
        return r;
    };

    Activity.onNewIntent.overload('android.content.Intent').implementation = function (i) {
        try {
            STATS.received++;
            banner('RECEIVED  Activity.onNewIntent', this.$className);
            dumpIntent(i, 1, '');
        } catch (e) { }
        return this.onNewIntent(i);
    };

    // BroadcastReceiver.onReceive is abstract, so there is nothing to hook on the
    // base class. Hooking the framework's dispatch object is more reliable than
    // enumerating concrete subclasses, which misses receivers loaded later.
    try {
        var LoadedApkReceiverDispatcher = Java.use(
            'android.app.LoadedApk$ReceiverDispatcher$Args');
        LoadedApkReceiverDispatcher.getRunnable.implementation = function () {
            try {
                var i = this.mCurIntent ? this.mCurIntent.value : null;
                if (i !== null) {
                    STATS.received++;
                    banner('RECEIVED  broadcast', 'dynamic receiver');
                    dumpIntent(Java.cast(i, Intent), 1, '');
                    line('  ^ Binder.getCallingUid() here returns THIS app\'s uid, not the');
                    line('    sender\'s. There is no sender identity on this path.');
                }
            } catch (e) { }
            return this.getRunnable();
        };
    } catch (e) {
        line('[*] LoadedApk$ReceiverDispatcher$Args not hookable on this platform '
             + '(' + e + '); manifest receivers will still show via onCreate/onStartCommand.');
    }

    var Service = Java.use('android.app.Service');
    Service.onStartCommand.implementation = function (i, f, id) {
        try {
            STATS.received++;
            banner('RECEIVED  Service.onStartCommand', this.$className);
            dumpIntent(i, 1, '');
        } catch (e) { }
        return this.onStartCommand(i, f, id);
    };

    /* ---------- the primitive: an Intent coming OUT of an extra ---------- */

    Intent.getParcelableExtra.overload('java.lang.String').implementation = function (name) {
        var v = this.getParcelableExtra(name);
        try {
            if (v !== null && v.$className === 'android.content.Intent') {
                line('[taint] Intent read from extra "' + name + '" in an Intent');
                markTainted(v, name);
            }
        } catch (e) { }
        return v;
    };

    // API 33+ typed overload. Same primitive, different descriptor -- and the one
    // most static greps miss (README section 6.2).
    try {
        Intent.getParcelableExtra.overload('java.lang.String', 'java.lang.Class')
            .implementation = function (name, cls) {
                var v = this.getParcelableExtra(name, cls);
                try {
                    if (v !== null && v.$className === 'android.content.Intent') {
                        line('[taint] Intent read from extra "' + name
                             + '" (typed overload)');
                        markTainted(v, name);
                    }
                } catch (e) { }
                return v;
            };
    } catch (e) { /* pre-33 */ }

    // The string flavour: Intent.parseUri turns attacker TEXT into an Intent, and
    // unlike the Parcelable flavour this one is reachable from a web page.
    Intent.parseUri.overload('java.lang.String', 'int').implementation = function (u, f) {
        var out = this.parseUri(u, f);
        try {
            line('');
            line('[!] Intent.parseUri("' + truncate(u) + '", flags=0x' + f.toString(16) + ')');
            line('    ^ the STRING flavour of redirection. If the string came from a');
            line('      deep link or an extra, this is attacker-authored. It is also');
            line('      reachable from a WEB PAGE when the entry filter is BROWSABLE.');
            dumpIntent(out, 1, '');
            markTainted(out, '<parseUri>');
        } catch (e) { }
        return out;
    };

    /* ---------- sending side ---------- */

    var ContextWrapper = Java.use('android.content.ContextWrapper');

    Activity.startActivity.overload('android.content.Intent').implementation = function (i) {
        checkSend(i, 'Activity.startActivity', this);
        return this.startActivity(i);
    };
    Activity.startActivityForResult.overload('android.content.Intent', 'int')
        .implementation = function (i, rc) {
            checkSend(i, 'Activity.startActivityForResult(rc=' + rc + ')', this);
            return this.startActivityForResult(i, rc);
        };
    Activity.setResult.overload('int', 'android.content.Intent')
        .implementation = function (code, data) {
            try {
                if (data !== null) {
                    var f = data.getFlags();
                    if ((f & GRANT_MASK) !== 0) {
                        line('');
                        line('[!!] setResult carries URI GRANT flags ' + decodeIntentFlags(f));
                        line('     data = ' + data.getDataString());
                        line('     ^ the grant is issued to WHOEVER started this activity.');
                        line('       This is the return path of grant laundering.');
                    }
                }
            } catch (e) { }
            return this.setResult(code, data);
        };

    ContextWrapper.startActivity.overload('android.content.Intent')
        .implementation = function (i) {
            checkSend(i, 'ContextWrapper.startActivity', this);
            return this.startActivity(i);
        };
    ContextWrapper.startService.overload('android.content.Intent')
        .implementation = function (i) {
            checkSend(i, 'ContextWrapper.startService', this);
            return this.startService(i);
        };
    ContextWrapper.bindService.overload(
        'android.content.Intent', 'android.content.ServiceConnection', 'int')
        .implementation = function (i, c, f) {
            checkSend(i, 'ContextWrapper.bindService', this);
            return this.bindService(i, c, f);
        };
    ContextWrapper.sendBroadcast.overload('android.content.Intent')
        .implementation = function (i) {
            checkSend(i, 'ContextWrapper.sendBroadcast', this);
            return this.sendBroadcast(i);
        };
    try {
        ContextWrapper.sendBroadcast.overload('android.content.Intent', 'java.lang.String')
            .implementation = function (i, perm) {
                checkSend(i, 'ContextWrapper.sendBroadcast(perm=' + perm + ')', this);
                return this.sendBroadcast(i, perm);
            };
    } catch (e) { }

    /* ---------- dynamic receiver registration ---------- */

    try {
        ContextWrapper.registerReceiver.overload(
            'android.content.BroadcastReceiver', 'android.content.IntentFilter')
            .implementation = function (r, f) {
                line('');
                line('[registerReceiver] ' + (r !== null ? r.$className : 'null'));
                line('    filter: ' + f.toString());
                line('    ^ a DYNAMIC receiver. It is not in the manifest and a manifest');
                line('      audit will never see it. Below targetSdk 33 it is effectively');
                line('      EXPORTED with nothing declaring so.');
                return this.registerReceiver(r, f);
            };
    } catch (e) { }

    /* ---------- PendingIntent creation ---------- */

    var PendingIntent = Java.use('android.app.PendingIntent');

    // NOTE ON RE-ENTRY: inside a Frida `implementation` callback, invoking the
    // method on `this` calls the ORIGINAL implementation, not the hook. For a
    // static method `this` is the class wrapper, so `this[method](...)` is the
    // correct way to chain. Calling `PendingIntent[method](...)` instead would
    // re-enter the hook and recurse until the app dies.
    function hookPi(method) {
        try {
            PendingIntent[method].overload(
                'android.content.Context', 'int', 'android.content.Intent', 'int')
                .implementation = function (ctx, rc, i, flags) {
                    try {
                        STATS.pendingIntents++;
                        var immutable = (flags & 0x04000000) !== 0;
                        var mutable = (flags & 0x02000000) !== 0;
                        var hasComponent = false;
                        try { hasComponent = (i !== null && i.getComponent() !== null); }
                        catch (e) { }

                        banner('PendingIntent.' + method, decodePendingFlags(flags));
                        dumpIntent(i, 1, '');

                        if (!immutable) {
                            if (!hasComponent) {
                                line('  *** MUTABLE and the wrapped Intent has NO COMPONENT.');
                                line('      This is a blank cheque signed with this app\'s uid:');
                                line('      whoever holds the token can set the component in a');
                                line('      fill-in Intent and have the system start it AS THIS');
                                line('      APP -- including non-exported components.');
                            } else {
                                line('  *   mutable, but the component is set. The holder can');
                                line('      still add extras and (if data is unset) a data URI');
                                line('      plus FLAG_GRANT_* -- which this app would then issue.');
                            }
                            if (!mutable) {
                                line('      (no explicit FLAG_MUTABLE either: this app targets');
                                line('       below API 31, where mutable is the DEFAULT.)');
                            }
                        }
                    } catch (e) { }
                    return this[method](ctx, rc, i, flags);
                };
        } catch (e) { }
    }
    hookPi('getActivity');
    hookPi('getBroadcast');
    hookPi('getService');
    try { hookPi('getForegroundService'); } catch (e) { }

    line('[*] hooks installed. Exercise the app.');
});

/* ----------------------------------------------------------------------- */
/*  RPC — drive it from a Frida REPL or a Python harness                     */
/* ----------------------------------------------------------------------- */

rpc.exports = {
    setVerbose: function (v) { CONFIG.verbose = !!v; return CONFIG.verbose; },
    setTaint: function (v) { CONFIG.taint = !!v; return CONFIG.taint; },
    setStacks: function (v) { CONFIG.stacks = !!v; return CONFIG.stacks; },
    stats: function () { return STATS; },
    clearTaint: function () { TAINT = {}; return true; }
};
