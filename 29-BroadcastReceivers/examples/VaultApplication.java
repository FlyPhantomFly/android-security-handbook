// examples/VaultApplication.java
//
// The half of the vulnerable app that no manifest audit can see.
//
// WHY THIS FILE EXISTS
//   AndroidManifest-vulnerable.xml declares two receivers. An auditor reading
//   it concludes the app has a two-receiver broadcast surface. This class adds
//   two more at runtime, and they are strictly worse than the declared ones:
//   one listens for a forgeable custom action with no protection at all, and
//   one is a high-priority ordered-broadcast interceptor.
//
//   Nothing in the APK reveals them as receivers. apktool, aapt2, jadx's
//   manifest view, MobSF's component table and every commercial SAST tool that
//   works from the manifest will report this app as having two receivers.
//
//   They ARE visible, in exactly two places:
//     1. `dumpsys activity broadcasts`, while the process is alive:
//            python3 ../scripts/receiver-surface.py --package com.example.vault
//     2. A hook on registerReceiver, which additionally recovers the CLASS NAME
//        that dumpsys does not print:
//            frida -U -f com.example.vault -l ../scripts/hook-broadcast.js
//
//   That gap is the reason this chapter exists.
//
// AUTHORISED TESTING ONLY.

package com.example.vault;

import android.app.Application;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.util.Log;

public class VaultApplication extends Application {

    private static final String TAG = "VaultApp";

    @Override
    public void onCreate() {
        super.onCreate();

        // ------------------------------------------------------------------
        // RUNTIME RECEIVER 1 -- an unguarded custom action.
        //
        // The two-argument registerReceiver overload. Below API 33 there is no
        // export flag and no permission here, so this receiver is reachable by
        // every app on the device. From API 33, an app with targetSdk 33 or
        // higher calling this overload for a non-system action gets a
        // SecurityException at registration time -- which is why the flag was
        // made mandatory, and why an app that still ships this line is telling
        // you its targetSdk is below 33.
        //
        // Measured on Android 11 / API 30: 1,227 of 1,438 runtime filters on a
        // stock device had no sender permission at all. This is the normal
        // state of the world, not an exotic mistake.
        //
        // Written as an ANONYMOUS INNER CLASS on purpose. It compiles to
        // VaultApplication$1, which is what a hook reports, and it is invisible
        // to any tool that looks for classes extending BroadcastReceiver by
        // name. A real measured example from a stock device looked exactly like
        // this: com.miui.calculator.CalculatorApplication$1.
        // ------------------------------------------------------------------
        IntentFilter wipeFilter = new IntentFilter("com.example.vault.ACTION_WIPE_CACHE");
        registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                // No action check, no sender check, no permission. Any app that
                // knows the string -- and the string is in the DEX -- triggers
                // this.
                String scope = intent.getStringExtra("scope");
                Log.i(TAG, "wiping cache scope=" + scope);
                // ... deleting whatever `scope` names, including "all" ...
            }
        }, wipeFilter);

        // ------------------------------------------------------------------
        // RUNTIME RECEIVER 2 -- a high-priority ordered interceptor.
        //
        // IntentFilter.setPriority() on a RUNTIME registration is the same
        // primitive as android:priority in a manifest, with one advantage for
        // an attacker: it does not appear in the APK, so a reviewer diffing
        // manifests across releases never sees it appear.
        //
        // For an ORDERED broadcast, the highest-priority receiver is handed the
        // Intent first and may call abortBroadcast(), after which no
        // lower-priority receiver in ANY app sees it. It may also rewrite the
        // result with setResultData() before passing it on.
        //
        // This is the SMS-interception pattern, generalised. The SMS path
        // itself is restricted to the default SMS app on modern Android, but
        // the pattern -- high priority plus abortBroadcast on an ordered
        // broadcast between two ordinary apps -- still works.
        // ------------------------------------------------------------------
        IntentFilter syncFilter = new IntentFilter("com.example.vault.SYNC_COMPLETE");
        syncFilter.setPriority(999);
        registerReceiver(new SyncResultWatcher(), syncFilter);

        Log.i(TAG, "two receivers registered that are in no manifest");
    }

    /**
     * A named class rather than an anonymous one, so the two shapes sit next to
     * each other. A hook reports this as com.example.vault.SyncResultWatcher; a
     * class-name sweep would find it, and would miss the anonymous one above.
     */
    static class SyncResultWatcher extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            // getResultData() is meaningful only inside an ordered broadcast.
            // Whatever an earlier receiver put there is readable here -- which
            // is the same channel ConfigSyncReceiver-vulnerable.java leaks its
            // session token through.
            String carried = getResultData();
            Log.i("SyncWatch", "result carried: " + carried);

            // And this receiver can stop the chain. Every receiver below
            // priority 999 that registered for SYNC_COMPLETE is now silent, and
            // will never know why.
            if (carried != null) {
                abortBroadcast();
            }
        }
    }
}
