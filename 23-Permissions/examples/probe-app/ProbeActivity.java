/*
 * examples/probe-app/ProbeActivity.java
 * =====================================
 *
 * THE UNPRIVILEGED PROBE.
 *
 * WHY THIS EXISTS
 *     `adb shell` runs as UID 2000 in the `shell` SELinux domain, and
 *     /system/etc/permissions/platform.xml hands that UID permissions by policy
 *     that no installed package could ever request - INTERNET among them,
 *     measured on the test device:
 *
 *         <assign-permission name="android.permission.INTERNET" uid="shell" />
 *
 *     So `adb shell am start`, `adb shell content query` and `adb shell service
 *     call` are a REACHABILITY UPPER BOUND. They tell you what a privileged
 *     local user can do. They tell you nothing about what an attacker's app can
 *     do, and a report that conflates the two is not defensible.
 *
 *     This app is an ordinary third-party app with an ordinary UID and no
 *     special anything. When it reaches a component, an attacker can too.
 *
 * WHAT IT DOES
 *     Reads its own Intent extras and performs one of four probes, printing
 *     everything to logcat under the tag PROBE. It is driven entirely from the
 *     command line, so you never rebuild it to test a different target:
 *
 *         --es probe query    --es target content://authority/path
 *         --es probe call     --es target content://authority  --es method NAME
 *         --es probe activity --es target pkg/.ClassName
 *         --es probe service  --es target pkg/.ServiceName
 *         --es probe perm     --es target android.permission.CAMERA
 *
 *     Every probe reports THREE things, and the third is the one people forget:
 *     what it asked for, what happened, and what the exception type was. A
 *     SecurityException, an IllegalArgumentException and an empty Cursor mean
 *     three completely different things and only one of them is "not
 *     reachable".
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *     - Whether the data you got back is sensitive. An exported provider that
 *       returns an empty table is not a leak.
 *     - Whether a component you could NOT reach is genuinely unreachable, if
 *       you forgot the <queries> entry. From targetSdk 30 an app cannot see a
 *       package it has not declared an interest in, and the failure looks
 *       identical to a permission denial in some paths. The manifest beside
 *       this file carries <queries> entries; ADD YOUR TARGET TO IT.
 *     - Anything about GID-backed permissions. This app requests no INTERNET,
 *       deliberately, so that `perm` probes against it show what a process
 *       without group 3003 looks like.
 *     - Anything about the target's internal logic. This is a reachability
 *       probe, not an exploit. Once you know a component is reachable, read it
 *       in JADX and go to 27-ContentProviders or 26-Intent.
 *
 * HOW TO RUN
 *     ./build-probe.sh
 *     adb install -r out/probe-app.apk
 *
 *     adb logcat -c
 *     adb shell am start -n com.probe.unprivileged/.ProbeActivity \
 *         --es probe query --es target 'content://com.target.app.provider/items'
 *     adb logcat -d -s PROBE:V
 *
 * AUTHORISED TESTING ONLY. Install on a device you own, against an app you are
 * scoped to test.
 */

package com.probe.unprivileged;

import android.app.Activity;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Process;
import android.util.Log;

public class ProbeActivity extends Activity {

    private static final String TAG = "PROBE";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        banner();

        final Intent intent = getIntent();
        final String probe  = str(intent, "probe", "info");
        final String target = str(intent, "target", null);
        final String method = str(intent, "method", null);
        final String arg    = str(intent, "arg", null);

        Log.i(TAG, "probe=" + probe + " target=" + target);

        try {
            if ("query".equals(probe)) {
                doQuery(target);
            } else if ("call".equals(probe)) {
                doCall(target, method, arg);
            } else if ("activity".equals(probe)) {
                doActivity(target, intent);
            } else if ("service".equals(probe)) {
                doService(target);
            } else if ("perm".equals(probe)) {
                doPermission(target);
            } else {
                Log.i(TAG, "no probe requested. Use --es probe "
                        + "query|call|activity|service|perm");
            }
        } catch (Throwable t) {
            // Catch Throwable, not Exception. A SecurityException crossing a
            // Binder boundary is an Exception, but a missing class or a
            // NoSuchMethodError from an API level mismatch is an Error, and
            // silently dying on one of those looks exactly like "not reachable".
            report("UNCAUGHT", t);
        }

        finish();
    }

    /**
     * Print who we are, every run. Half the value of this app is the contrast
     * with `adb shell`, and that contrast is only convincing if the identity is
     * on the transcript.
     */
    private void banner() {
        Log.i(TAG, "================================================================");
        Log.i(TAG, "  unprivileged probe");
        Log.i(TAG, "  package = " + getPackageName());
        Log.i(TAG, "  uid     = " + Process.myUid() + "   (adb shell is 2000)");
        Log.i(TAG, "  pid     = " + Process.myPid());
        Log.i(TAG, "  sdk     = " + Build.VERSION.SDK_INT);
        Log.i(TAG, "  Anything this app can reach, an attacker's app can reach.");
        Log.i(TAG, "================================================================");
    }

    // -- probes -----------------------------------------------------------

    private void doQuery(String target) {
        if (target == null) { Log.w(TAG, "query needs --es target content://..."); return; }
        final ContentResolver cr = getContentResolver();
        Cursor c = null;
        try {
            c = cr.query(Uri.parse(target), null, null, null, null);
            if (c == null) {
                // A null Cursor is NOT a permission denial. The provider ran and
                // chose to return nothing, which means you got THROUGH the gate.
                Log.i(TAG, "RESULT: query returned NULL cursor");
                Log.i(TAG, "  -> the permission check PASSED and the provider "
                        + "declined to return a cursor");
                return;
            }
            Log.i(TAG, "RESULT: query returned " + c.getCount() + " rows, "
                    + c.getColumnCount() + " columns");
            StringBuilder cols = new StringBuilder();
            for (String n : c.getColumnNames()) { cols.append(n).append(' '); }
            Log.i(TAG, "  columns: " + cols);
            int shown = 0;
            while (c.moveToNext() && shown < 5) {
                StringBuilder row = new StringBuilder();
                for (int i = 0; i < c.getColumnCount(); i++) {
                    row.append('[').append(safeCell(c, i)).append(']');
                }
                Log.i(TAG, "  row " + shown + ": " + row);
                shown++;
            }
            if (c.getCount() > shown) {
                Log.i(TAG, "  ... " + (c.getCount() - shown) + " more rows");
            }
        } catch (Throwable t) {
            report("query", t);
        } finally {
            if (c != null) { try { c.close(); } catch (Throwable ignored) { } }
        }
    }

    private String safeCell(Cursor c, int i) {
        try {
            String v = c.getString(i);
            if (v == null) { return "null"; }
            return v.length() > 60 ? v.substring(0, 60) + "..." : v;
        } catch (Throwable t) {
            return "<non-string>";
        }
    }

    private void doCall(String target, String method, String arg) {
        if (target == null || method == null) {
            Log.w(TAG, "call needs --es target content://authority --es method NAME");
            return;
        }
        try {
            Bundle result = getContentResolver().call(Uri.parse(target), method, arg, null);
            if (result == null) {
                Log.i(TAG, "RESULT: call returned null Bundle "
                        + "(reached the provider; method may not exist)");
                return;
            }
            Log.i(TAG, "RESULT: call returned Bundle with keys: " + result.keySet());
            for (String k : result.keySet()) {
                Object v = result.get(k);
                Log.i(TAG, "  " + k + " = " + v);
            }
        } catch (Throwable t) {
            report("call", t);
        }
    }

    private void doActivity(String target, Intent src) {
        if (target == null) { Log.w(TAG, "activity needs --es target pkg/.Class"); return; }
        try {
            Intent i = new Intent();
            i.setComponent(ComponentName.unflattenFromString(target));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            // Forward any extras the operator supplied, minus our own control keys.
            Bundle extras = src.getExtras();
            if (extras != null) {
                Bundle copy = new Bundle(extras);
                copy.remove("probe"); copy.remove("target");
                copy.remove("method"); copy.remove("arg");
                i.putExtras(copy);
            }
            startActivity(i);
            Log.i(TAG, "RESULT: startActivity did not throw -- the component is REACHABLE "
                    + "from an unprivileged UID");
        } catch (Throwable t) {
            report("activity", t);
        }
    }

    private void doService(String target) {
        if (target == null) { Log.w(TAG, "service needs --es target pkg/.Service"); return; }
        try {
            Intent i = new Intent();
            i.setComponent(ComponentName.unflattenFromString(target));
            ServiceConnection conn = new ServiceConnection() {
                @Override public void onServiceConnected(ComponentName n, IBinder b) {
                    Log.i(TAG, "RESULT: BOUND to " + n.flattenToShortString()
                            + " binder=" + b);
                    Log.i(TAG, "  -> reachable from an unprivileged UID. Next: enumerate the "
                            + "interface; see 25-Binder.");
                }
                @Override public void onServiceDisconnected(ComponentName n) {
                    Log.i(TAG, "disconnected from " + n.flattenToShortString());
                }
            };
            boolean ok = bindService(i, conn, BIND_AUTO_CREATE);
            Log.i(TAG, "RESULT: bindService returned " + ok
                    + (ok ? "  (wait for onServiceConnected)"
                          : "  -> refused. Check <queries>, exported state, and permission."));
        } catch (Throwable t) {
            report("service", t);
        }
    }

    private void doPermission(String target) {
        if (target == null) { Log.w(TAG, "perm needs --es target android.permission.X"); return; }
        int self = checkSelfPermission(target);
        Log.i(TAG, "RESULT: checkSelfPermission(" + target + ") = " + self
                + (self == PackageManager.PERMISSION_GRANTED ? "  GRANTED" : "  DENIED"));
        Log.i(TAG, "  NOTE: this is the app asking about ITSELF. It is feature detection, "
                + "not an authorisation check, and hooking it changes nothing about what "
                + "the framework or the kernel will allow.");
    }

    // -- reporting --------------------------------------------------------

    /**
     * The exception TYPE is the finding. Print it, and say what it means,
     * because these three are routinely conflated:
     *
     *   SecurityException          -> the gate refused you
     *   IllegalArgumentException   -> you got THROUGH the gate and the
     *                                 provider's own code rejected your path
     *   NullPointerException on a  -> the authority does not resolve at all,
     *   null resolver result          often a <queries> problem, not a
     *                                 permission problem
     */
    private void report(String what, Throwable t) {
        Log.w(TAG, "RESULT: " + what + " threw " + t.getClass().getName());
        Log.w(TAG, "  message: " + t.getMessage());
        String cls = t.getClass().getName();
        if (cls.endsWith("SecurityException")) {
            Log.w(TAG, "  -> DENIED by a permission check. Read the message for the "
                    + "permission name, then resolve its level: "
                    + "adb shell pm list permissions -f -g | grep -A4 <name>");
        } else if (cls.endsWith("IllegalArgumentException")) {
            Log.w(TAG, "  -> you got THROUGH the permission check. The provider's own code "
                    + "rejected the URI. That converts 'is this reachable' into 'which paths "
                    + "does it accept' -- see 27-ContentProviders.");
        } else if (cls.endsWith("ActivityNotFoundException")) {
            Log.w(TAG, "  -> the component did not resolve. Either it is not exported, or "
                    + "this app cannot SEE the package. Add it to <queries> in "
                    + "AndroidManifest.xml and rebuild before concluding anything.");
        } else if (cls.endsWith("NullPointerException")) {
            Log.w(TAG, "  -> often a visibility problem rather than a permission problem. "
                    + "Check <queries>.");
        }
    }

    private static String str(Intent i, String key, String def) {
        try {
            String v = i.getStringExtra(key);
            return v == null ? def : v;
        } catch (Throwable t) {
            return def;
        }
    }
}
