// examples/vault-target/VaultApp.java
//
// The target application's Application subclass. Every one of the four
// well-known startup slots logs a monotonic timestamp to logcat under the tag
// "ch66seq", so that the ordering of application startup against
// Instrumentation.onCreate() can be READ OFF A DEVICE rather than argued about.
//
// The four slots, in the order the framework runs them:
//
//   1. Application()                 - constructor, no Context yet
//   2. attachBaseContext(Context)    - Context attached; where packers unpack
//   3. ContentProvider.onCreate()    - see SeedProvider.java
//   4. Application.onCreate()        - where most apps put their init
//
// Chapter 66 section 3.6 shows where Instrumentation.onCreate() lands in that
// list. The answer is not the one the framework's own javadoc implies.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch66.vault;

import android.app.Application;
import android.content.Context;
import android.os.SystemClock;
import android.util.Log;

public class VaultApp extends Application {

    public static final String SEQ = "ch66seq";

    /** Set by attachBaseContext, read by the probe to prove ordering. */
    public static volatile long sAttachBaseContextAtNs = 0L;
    /** Set on ENTRY to onCreate, still 0 if instrumentation got control first. */
    public static volatile long sApplicationOnCreateAtNs = 0L;

    /**
     * Set on EXIT from onCreate, after VaultStore.seed() has written every file.
     *
     * Two markers, not one, and the difference is a lesson the chapter's first
     * measured run learned the hard way: a probe that waits for
     * sApplicationOnCreateAtNs and then reads shared_prefs gets ENOENT, because
     * that marker is set at the START of the work it is waiting for. Waiting on
     * a flag raised before the job is waiting for nothing. See section 11.2.
     */
    public static volatile long sSeedCompleteAtNs = 0L;

    public VaultApp() {
        super();
        Log.i(SEQ, "1 Application() constructor      t=" + SystemClock.elapsedRealtimeNanos());
    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        sAttachBaseContextAtNs = SystemClock.elapsedRealtimeNanos();
        Log.i(SEQ, "2 Application.attachBaseContext  t=" + sAttachBaseContextAtNs);
        // A packer would decrypt and load its real DEX here. A pinning library
        // would install its TrustManager here. Both are already finished by the
        // time an instrumentation gets control -- that is the point.
    }

    @Override
    public void onCreate() {
        super.onCreate();
        sApplicationOnCreateAtNs = SystemClock.elapsedRealtimeNanos();
        Log.i(SEQ, "4 Application.onCreate           t=" + sApplicationOnCreateAtNs);
        VaultStore.seed(this);
        // The first telemetry event the app ever emits. An instrumentation that
        // swapped VaultStore.sSink during its own onCreate() sees this one,
        // because Instrumentation.onCreate runs before Application.onCreate.
        VaultStore.emit("startup", VaultStore.currentSessionToken());
        sSeedCompleteAtNs = SystemClock.elapsedRealtimeNanos();
        Log.i(SEQ, "5 seed complete                  t=" + sSeedCompleteAtNs
                + " premium=" + LicenseGate.isPremium()
                + " session=" + VaultStore.currentSessionToken());
    }
}
