// examples/CtfVaultReceivers.java
//
// The CTF target for labs/lab-04-ctf-the-receiver-that-is-not-there.md.
//
// Five flags, five distinct primitives from this chapter:
//
//   FLAG 1  a runtime-registered receiver that appears in no manifest
//   FLAG 2  telling a protected action from a forgeable one
//   FLAG 3  the ordered-broadcast RESULT channel
//   FLAG 4  winning a priority race and REWRITING a result
//   FLAG 5  the broadcast history: sender attribution and cleartext extras
//
// INSTRUCTOR NOTE -- READ BEFORE HANDING THIS TO A LEARNER
//   This file contains all five flags in plain text. It is the answer key as
//   well as the target. If you are running this as an exercise for somebody
//   else, build the APK, hand them the APK, and keep this file back.
//
//   Nothing here is obfuscated on purpose. The lesson is not "can you defeat
//   R8"; it is "can you find a component that no static tool reports, decide
//   which of its actions you can actually reach, and use the ordered-broadcast
//   primitives correctly". A learner who reads the source has learned nothing
//   about any of those three.
//
// BUILD
//   cd examples && ./build.sh --ctf
//   adb install -r build/vault-ctf.apk
//   adb shell am start -n com.example.vaultctf/.MainActivity
//
//   The build.sh in this directory builds the vulnerable and fixed variants;
//   add a third build_one call for this file with a manifest declaring
//   .MainActivity as the launcher and .Flag2Receiver as an exported receiver
//   with the intent-filter described in the comments below. Writing that
//   manifest is itself part of the exercise -- it forces you to decide which
//   components must be declared and which must not.
//
// AUTHORISED TESTING ONLY. This app is deliberately vulnerable. Do not ship it,
// do not install it on a device holding real data, and uninstall it afterwards.

package com.example.vaultctf;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;

/**
 * Registers everything that must not be in the manifest.
 *
 * A player who audits AndroidManifest.xml sees exactly one receiver
 * (Flag2Receiver). Four of the five flags live behind components registered
 * here, at runtime, which no APK-based tool can enumerate.
 */
public class CtfApplication extends android.app.Application {

    static final String TAG = "vaultctf";

    // ------------------------------------------------------------------
    // FLAG 1 -- the invisible receiver.
    //
    // Registered at runtime. Not in the manifest. `cmd package
    // query-receivers -a com.example.vaultctf.PROBE_BUS` returns
    // "No receivers found", while `dumpsys activity broadcasts` shows this
    // registration with its action.
    //
    // The intended path:
    //   1. python3 ../scripts/receiver-surface.py --package com.example.vaultctf
    //   2. read the action string out of the AMS table
    //   3. send it
    //
    // Deliberately an ANONYMOUS INNER CLASS. It compiles to CtfApplication$1,
    // so a sweep for classes extending BroadcastReceiver by name misses it --
    // the same shape as the real receiver measured on a stock device,
    // com.miui.calculator.CalculatorApplication$1.
    // ------------------------------------------------------------------
    static final String ACTION_PROBE = "com.example.vaultctf.PROBE_BUS";
    private static final String FLAG_1 = "FLAG{no_manifest_no_problem_1a2b3c}";

    // ------------------------------------------------------------------
    // FLAG 4 -- the priority race, and the rewrite.
    //
    // Three receivers listen for ACTION_RELAY on an ordered broadcast:
    //
    //   priority 100 : Flag4Blocker  -- overwrites the result with "blocked",
    //                                   but ONLY while the incoming result code
    //                                   is still 0
    //   priority  50 : Flag4Holder   -- prints FLAG 4 only if the result that
    //                                   reaches it is exactly RELAY_PASSPHRASE
    //
    // Aborting achieves nothing here: abort the chain and the holder never runs
    // at all. Setting the passphrase from a lower priority achieves nothing
    // either, because the blocker has already run.
    //
    // The solution needs both chapter facts at once. Register a receiver ABOVE
    // priority 100 -- priority is an unauthenticated integer, so nothing stops
    // you -- and from it set BOTH the passphrase as the result data AND a
    // non-zero result code. The non-zero code makes the blocker stand down, so
    // the passphrase survives all the way to the holder.
    //
    // The point: the result is not a return value, it is a MUTABLE token
    // travelling forward through the chain, and whoever is highest owns it.
    // ------------------------------------------------------------------
    static final String ACTION_RELAY = "com.example.vaultctf.RELAY";
    static final String RELAY_PASSPHRASE = "let-me-through";
    private static final String FLAG_4 = "FLAG{priority_is_just_an_int_7f8e9d}";

    // ------------------------------------------------------------------
    // FLAG 5 -- the broadcast history.
    //
    // MainActivity publishes this on every launch, as an IMPLICIT broadcast
    // with no receiverPermission and no setPackage. Two independent routes:
    //
    //   a) eavesdrop -- register a matching filter and wait
    //   b) read the history -- `dumpsys activity broadcasts` records extras in
    //      cleartext, and records the SENDER uid in the caller= field
    //
    // Route (b) is the intended one, because it also teaches that the history
    // is the only place a broadcast's sender is ever recorded.
    // ------------------------------------------------------------------
    static final String ACTION_TELEMETRY = "com.example.vaultctf.TELEMETRY";
    static final String FLAG_5 = "FLAG{the_history_remembers_who_spoke_4c5d6e}";

    @Override
    public void onCreate() {
        super.onCreate();

        // FLAG 1 -- anonymous inner class, two-argument overload, no permission,
        // no export flag. On any device below API 33 this is reachable by every
        // app on the system.
        registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(Context c, Intent i) {
                if (!ACTION_PROBE.equals(i.getAction())) return;
                Log.i(TAG, "flag1: " + FLAG_1);
            }
        }, new IntentFilter(ACTION_PROBE));

        // FLAG 4 -- the blocker, at priority 100.
        IntentFilter blockerFilter = new IntentFilter(ACTION_RELAY);
        blockerFilter.setPriority(100);
        registerReceiver(new Flag4Blocker(), blockerFilter);

        // FLAG 4 -- the holder, at priority 50. It runs last of the two.
        IntentFilter holderFilter = new IntentFilter(ACTION_RELAY);
        holderFilter.setPriority(50);
        registerReceiver(new Flag4Holder(), holderFilter);

        Log.i(TAG, "three receivers registered. None of them is in the manifest.");
        Log.i(TAG, "targetSdk-dependent note: on API " + Build.VERSION.SDK_INT
                + " these carry no export flag below 33.");
    }

    /**
     * Priority 100. Overwrites the result -- but only when the incoming result
     * code is still 0.
     *
     * That condition is the puzzle. A player who registers above priority 100
     * and sets a non-zero result code disarms this receiver without needing to
     * abort anything.
     */
    static class Flag4Blocker extends BroadcastReceiver {
        @Override
        public void onReceive(Context c, Intent i) {
            int incoming = getResultCode();
            Log.i(TAG, "flag4/blocker: incoming resultCode=" + incoming
                    + " resultData=" + getResultData());
            if (incoming == 0) {
                setResultData("blocked");
                Log.i(TAG, "flag4/blocker: result overwritten");
            } else {
                Log.i(TAG, "flag4/blocker: standing down, someone upstream set a code");
            }
        }
    }

    /**
     * Priority 50. Prints the flag only if the result reaching it is exactly the
     * passphrase.
     */
    static class Flag4Holder extends BroadcastReceiver {
        @Override
        public void onReceive(Context c, Intent i) {
            String carried = getResultData();
            Log.i(TAG, "flag4/holder: carried=" + carried);
            if (RELAY_PASSPHRASE.equals(carried)) {
                Log.i(TAG, "flag4: " + FLAG_4);
            }
        }
    }
}

/**
 * FLAG 2 and FLAG 3. The ONLY component in the manifest.
 *
 * Declare it as:
 *
 *   <receiver android:name=".Flag2Receiver" android:exported="true">
 *       <intent-filter>
 *           <action android:name="android.intent.action.BOOT_COMPLETED" />
 *           <action android:name="android.intent.action.LOCALE_CHANGED" />
 *           <action android:name="com.example.vaultctf.REFRESH" />
 *       </intent-filter>
 *   </receiver>
 *
 * Three actions in one filter. Two of them are <protected-broadcast> and cannot
 * be sent by an ordinary app; one is an app-defined string and can. A player who
 * does not check which is which will spend an hour attacking the wrong door --
 * which is the entire point of FLAG 2.
 */
class Flag2Receiver extends BroadcastReceiver {

    private static final String TAG = CtfApplication.TAG;

    static final String ACTION_REFRESH = "com.example.vaultctf.REFRESH";

    // ------------------------------------------------------------------
    // FLAG 2 -- forgeable versus protected.
    //
    // Printed when the forgeable action arrives carrying the right extra.
    // The extra's expected value is the action string of FLAG 1's receiver,
    // which chains the two: you cannot solve 2 without having solved 1.
    // ------------------------------------------------------------------
    private static final String FLAG_2 = "FLAG{one_of_these_three_is_not_like_the_others_9a8b7c}";

    // ------------------------------------------------------------------
    // FLAG 3 -- the ordered-broadcast result channel.
    //
    // Placed in setResultData(), which means it travels to whoever SENT the
    // broadcast, not to anyone this app chose.
    //
    // The gate is `getResultCode() == 1337`. `am broadcast` cannot set an
    // initial result code, so a shell one-liner will never see this. The player
    // must call sendOrderedBroadcast(..., 1337, null, null) from an app, and
    // read getResultData() in their own result receiver.
    //
    // That is the lesson: adb shell is not an attacker, and the result channel
    // points back at the sender.
    // ------------------------------------------------------------------
    private static final String FLAG_3 = "FLAG{the_result_comes_home_to_you_2d3e4f}";

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        Log.i(TAG, "flag2/3 receiver: action=" + action);

        // Deliberately reachable by explicit component with a null action: the
        // branches below test `action` where it matters, so an actionless
        // explicit Intent falls through harmlessly. That is the FIXED
        // behaviour, on purpose -- the CTF is about the forgeable-action
        // question, not about the filter-bypass question, which lab 02 covers.
        if (!ACTION_REFRESH.equals(action)) {
            Log.i(TAG, "flag2/3 receiver: not the interesting action, ignoring");
            return;
        }

        // FLAG 2
        String token = intent.getStringExtra("bus");
        if (CtfApplication.ACTION_PROBE.equals(token)) {
            Log.i(TAG, "flag2: " + FLAG_2);
        } else {
            Log.i(TAG, "flag2: wrong or missing 'bus' extra. "
                    + "Hint: it is a string you already found in the AMS table.");
        }

        // FLAG 3 -- only on the ordered path, and only with the right initial code.
        if (getResultCode() == 1337) {
            setResultData(FLAG_3);
            Log.i(TAG, "flag3: result set (it went to the SENDER, not to logcat)");
        }
    }
}

/**
 * Launcher activity. Publishes the FLAG 5 telemetry broadcast on every start.
 */
class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        // FLAG 5 -- an implicit broadcast, no setPackage, no receiverPermission.
        // Every app on the device with a matching filter receives it, and the
        // payload is recorded verbatim in the AMS broadcast history where
        // anything with shell access can read it.
        Intent i = new Intent(CtfApplication.ACTION_TELEMETRY);
        i.putExtra("session_token", CtfApplication.FLAG_5);
        i.putExtra("build", "ctf-1.0");
        sendBroadcast(i);

        Log.i(CtfApplication.TAG, "telemetry published. It is now in two places "
                + "you can reach without this app's cooperation.");
        finish();
    }
}
