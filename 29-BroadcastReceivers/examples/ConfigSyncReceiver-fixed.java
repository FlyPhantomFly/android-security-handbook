// examples/ConfigSyncReceiver-fixed.java
//
// The same feature as ConfigSyncReceiver-vulnerable.java, written so that none
// of its six bugs exists. Read the two side by side; the diff is the lesson.
//
// THE PRINCIPLE
//   A receiver has exactly one job that cannot be delegated: deciding whether
//   the message in front of it is one it is allowed to act on. The manifest
//   cannot do that job, because an exported component can be addressed
//   explicitly with any action; the platform cannot do it, because the platform
//   does not know which of your actions are sensitive; and the action name
//   cannot do it, because the action name is a public string in your APK.
//
// THE FOUR MOVES, IN ORDER OF VALUE
//   1. SPLIT the receiver. One receiver, one trust level. A receiver that
//      handles a protected system action must not also handle an app action.
//   2. Make the sensitive path UNREACHABLE from outside: android:exported=
//      "false" for a manifest receiver, RECEIVER_NOT_EXPORTED for a runtime
//      one, or a signature-level permission if another app genuinely must
//      reach it.
//   3. VALIDATE the action anyway, as the first statement of onReceive. Defence
//      in depth costs one line and survives someone flipping exported later.
//   4. Never let a broadcast extra become a URL, a file path, a class name or a
//      permission decision. Allowlist, do not sanitise.
//
// PAIRS WITH
//   ConfigSyncReceiver-vulnerable.java  -- the version this fixes
//   AndroidManifest-fixed.xml           -- the matching declaration
//
// BUILD
//   cd examples/vulnerable-app && ./build.sh   (swap the sources in the module)
//
// AUTHORISED TESTING ONLY.

package com.example.vault;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.os.Build;
import android.util.Log;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Receiver 1 of 2: the boot hook, and NOTHING else.
 *
 * Declared in the manifest with android:exported="true", which is not a choice
 * -- a manifest receiver that must hear a system broadcast has to be exported,
 * and from API 31 the attribute must be written explicitly or the app will not
 * install. The safety does not come from the export flag here. It comes from
 * (a) the filter listing exactly one action, (b) that action being a
 * <protected-broadcast> that no ordinary app can forge, and (c) the action
 * check below, which stops an explicit Intent from taking this path.
 */
public class BootReceiver extends BroadcastReceiver {

    private static final String TAG = "VaultBoot";

    @Override
    public void onReceive(Context context, Intent intent) {

        // FIX for BUG 1. The first statement of every onReceive, without
        // exception. An exported receiver can be reached by component name with
        // any action, or with none -- the filter is bypassed entirely. This
        // line is what makes the filter's promise true.
        if (!Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
            Log.w(TAG, "refusing unexpected action: " + intent.getAction());
            return;
        }

        // FIX for BUG 6. Schedule; do not work. The broadcast queue's timeout
        // was measured at 10 seconds on the foreground queue on Android 11 /
        // API 30. WorkManager or JobScheduler is the correct home for a network
        // sync. goAsync() buys a little more time but is not a licence to do
        // network I/O -- it keeps the process alive, it does not lift the limit.
        ConfigSyncScheduler.enqueueOneOffSync(context);
    }
}

/**
 * Receiver 2 of 2: the sensitive configuration path.
 *
 * This one is NOT in the manifest at all. It is registered at runtime and
 * explicitly NOT exported, which means the AMS registration carries a marker
 * that makes the platform refuse deliveries from other apps.
 *
 * Registering at runtime is not itself a security control -- 1,227 of the 1,438
 * runtime filters measured on one API 30 device had no protection whatsoever.
 * What protects this one is the NOT_EXPORTED flag, plus the explicit
 * self-addressed send in requestSync() below.
 */
class ConfigSyncReceiver extends BroadcastReceiver {

    private static final String TAG = "ConfigSync";

    static final String ACTION_SYNC = "com.example.vault.ACTION_SYNC_CONFIG";
    static final String EXTRA_CONFIG_ENV = "config_env";

    // android.content.Context.RECEIVER_NOT_EXPORTED, added in API 33. Written
    // as a literal so this file compiles against an older compileSdk; in a real
    // project use ContextCompat.registerReceiver, which does the version dance
    // and, below 33, emulates NOT_EXPORTED by inventing a signature permission
    // named <package>.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION.
    //
    // That shim is observable: 119 filters on one measured API 30 device
    // carried it, across com.google.android.gms, com.google.android.youtube and
    // com.miui.securitycenter. Seeing it in `dumpsys activity broadcasts` tells
    // you the developer asked for NOT_EXPORTED and the library honoured it.
    private static final int RECEIVER_NOT_EXPORTED = 0x4;

    // FIX for BUG 2. The broadcast chooses an ENVIRONMENT NAME, not a URL. The
    // set of endpoints is fixed at compile time, so the worst an attacker who
    // somehow reaches this receiver can do is select one of the developer's own
    // servers. Allowlist the values; never sanitise a URL.
    private static final Set<String> ALLOWED_ENVS =
            new HashSet<>(Arrays.asList("prod", "staging"));

    private static String endpointFor(String env) {
        if ("staging".equals(env)) return "https://cfg-staging.example.com/v1";
        return "https://cfg.example.com/v1";
    }

    /**
     * Register from Application.onCreate or from the component that needs it.
     * Unregister in the matching lifecycle callback -- a receiver that outlives
     * its need is surface that exists for no reason.
     */
    static ConfigSyncReceiver register(Context context) {
        ConfigSyncReceiver r = new ConfigSyncReceiver();
        IntentFilter f = new IntentFilter(ACTION_SYNC);
        if (Build.VERSION.SDK_INT >= 33) {
            context.registerReceiver(r, f, RECEIVER_NOT_EXPORTED);
        } else {
            // Below 33 the flag does not exist and a two-argument registration
            // is reachable by every app on the device. Use the AndroidX
            // backport in a real project:
            //     ContextCompat.registerReceiver(context, r, f,
            //             ContextCompat.RECEIVER_NOT_EXPORTED);
            // The line below is the manual equivalent: a signature permission
            // only this app's signing key can hold.
            context.registerReceiver(r, f,
                    "com.example.vault.permission.INTERNAL_SYNC", null);
        }
        return r;
    }

    /**
     * FIX for BUG 5, on the sending side.
     *
     * setPackage() turns an implicit broadcast into one that can only resolve
     * inside this app. Without it, every app with a matching filter receives
     * the message and its extras. This is the send-side control that appears in
     * no manifest and that only a hook or a code read will reveal --
     * scripts/hook-broadcast.js reports it as `receiverPermission`.
     *
     * Better still, where the receiver is in-process only: use
     * LocalBroadcastManager, or drop broadcasts entirely for a LiveData /
     * StateFlow / callback. Traffic that never reaches ActivityManagerService
     * cannot be observed or forged by another app, and does not appear in
     * `dumpsys activity broadcasts` at all.
     */
    static void requestSync(Context context, String env) {
        Intent i = new Intent(ACTION_SYNC);
        i.setPackage(context.getPackageName());
        i.putExtra(EXTRA_CONFIG_ENV, env);
        context.sendBroadcast(i, "com.example.vault.permission.INTERNAL_SYNC");
    }

    @Override
    public void onReceive(Context context, Intent intent) {

        // FIX for BUG 1, again. Runtime registrations are reached by filter
        // only -- there is no explicit-component path to a runtime receiver --
        // but the check costs nothing and protects against the filter being
        // widened later by someone who does not read this comment.
        if (!ACTION_SYNC.equals(intent.getAction())) {
            Log.w(TAG, "refusing unexpected action: " + intent.getAction());
            return;
        }

        String env = intent.getStringExtra(EXTRA_CONFIG_ENV);
        if (env == null || !ALLOWED_ENVS.contains(env)) {
            Log.w(TAG, "refusing unknown environment: " + env);
            return;
        }

        SharedPreferences prefs =
                context.getSharedPreferences("vault_config", Context.MODE_PRIVATE);
        prefs.edit().putString("config_env", env).apply();

        // FIX for BUG 3. The URL is derived from the allowlist, never taken
        // from the message. Nothing an attacker controls reaches a network sink.
        ConfigSyncScheduler.enqueueOneOffSync(context, endpointFor(env));

        // FIX for BUG 4. No setResultData, ever, with anything sensitive in it.
        // The result of an ordered broadcast is delivered to the SENDER. If the
        // sender is untrusted -- and any sender you did not authenticate is
        // untrusted -- the result is a channel out of your app. If you need a
        // status code, return a status code:
        setResultCode(android.app.Activity.RESULT_OK);

        // FIX for BUG 5. The completion notice stays inside the app, and
        // carries no identifiers.
        Intent done = new Intent("com.example.vault.SYNC_COMPLETE");
        done.setPackage(context.getPackageName());
        context.sendBroadcast(done, "com.example.vault.permission.INTERNAL_SYNC");
    }
}

/**
 * Stand-in for the real scheduler, so the example compiles and so the shape of
 * the fix is visible: onReceive decides, something else does.
 */
final class ConfigSyncScheduler {
    private ConfigSyncScheduler() { }

    static void enqueueOneOffSync(Context context) {
        enqueueOneOffSync(context, "https://cfg.example.com/v1");
    }

    static void enqueueOneOffSync(Context context, String endpoint) {
        // In a real app: WorkManager.getInstance(context).enqueue(
        //     new OneTimeWorkRequest.Builder(SyncWorker.class)
        //         .setInputData(new Data.Builder()
        //             .putString("endpoint", endpoint).build())
        //         .build());
        Log.i("ConfigSyncScheduler", "queued sync against " + endpoint);
    }
}
