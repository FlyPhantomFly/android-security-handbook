// labs/ctf-vault/CtfApp.java
//
// DELIBERATELY VULNERABLE CTF FIXTURE -- chapter 66, lab 04.
// Install on a device you own. Uninstall when you are finished.
//
// This class is the clock the whole challenge runs on. Three things happen in a
// fixed order, and an entrant who has done lab 03 knows exactly where
// Instrumentation.onCreate() falls among them.
//
//   attachBaseContext()  decode fragment 2 into Secrets.sVolatile
//        ...             EarlyProvider.onCreate() writes fragment 1 to a file
//        ...             <-- Instrumentation.onCreate() happens HERE
//   onCreate() line 1    wipe Secrets.sVolatile
//   onCreate() line 2    read Gate.sUnlocked, decode fragment 3 or refuse
//   onCreate() line 3    write the decoy into SharedPreferences
//
// It logs nothing useful on purpose. The tag "ch66ctf" carries only progress
// markers, so an entrant can confirm the app ran without being handed the answer.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch66.ctf;

import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.SystemClock;
import android.util.Log;

public class CtfApp extends Application {

    public static final String TAG = "ch66ctf";

    /** Set on EXIT from onCreate. Read the fixture's own source before trusting it. */
    public static volatile long sStartupCompleteAtNs = 0L;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        Secrets.sVolatile = Secrets.decode(Secrets.BLOB_2, Secrets.KEY_2);
        Log.i(TAG, "stage 1: attachBaseContext");
    }

    @Override
    public void onCreate() {
        super.onCreate();

        // Line one. Whatever was in sVolatile is gone from this point on.
        Secrets.sVolatile = null;
        Log.i(TAG, "stage 3: onCreate, volatile wiped");

        // Line two. The gate is consulted exactly once, right here.
        if (Gate.isUnlocked()) {
            Secrets.sPart3 = Secrets.decode(Secrets.BLOB_3, Secrets.KEY_3);
            Log.i(TAG, "stage 3: gate was OPEN");
        } else {
            Secrets.sPart3 = "denied";
            Log.i(TAG, "stage 3: gate was CLOSED");
        }

        // Line three. The decoy, in the most obvious place anyone will look.
        SharedPreferences p = getSharedPreferences("ctf", Context.MODE_PRIVATE);
        p.edit()
                .putString("flag", Secrets.decode(Secrets.DECOY, Secrets.KEY_DECOY))
                .putString("hint", "three fragments, joined with underscores, wrapped in CTF{}")
                .commit();

        sStartupCompleteAtNs = SystemClock.elapsedRealtimeNanos();
        Log.i(TAG, "stage 4: startup complete t=" + sStartupCompleteAtNs);
    }
}
