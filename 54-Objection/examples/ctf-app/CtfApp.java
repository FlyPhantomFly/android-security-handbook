// examples/ctf-app/CtfApp.java
//
// PURPOSE
//   DEFENCE 1 of the chapter 54 CTF: run the guard as early as it is possible
//   to run anything, and CACHE the result.
//
//   attachBaseContext is the first application code the system calls -- before
//   Application.onCreate, before any Activity, before any static initialiser of
//   any Activity class. An instrumentation session that ATTACHES to a running
//   process has already missed it. A session that SPAWNS the process is early
//   enough only if the hooks are installed at script-load time; a command typed
//   into a REPL seconds after the process resumed is not.
//
//   The second half of the defence is the more interesting one: the verdict is
//   stored in a static field. Even if you re-launch the Activity to "re-trigger
//   the check", the check does not run again -- VaultActivity reads a memory of
//   a decision, not a decision. Hooking the decider after the fact changes
//   nothing.
//
//   That is why lab-04's route 2 attacks the CACHE rather than the guard, and
//   why route 2 works on attach while route 1 does not.
//
// WHAT THIS WILL *NOT* TELL YOU
//   Whether the device is rooted. It records what four Java-layer probes could
//   see at one instant during start-up. On a Magisk device with DenyList active
//   they may all see nothing, exactly as the chapter's target-app measured.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch54.ctf;

import android.app.Application;
import android.content.Context;
import android.util.Log;

public class CtfApp extends Application {

    /**
     * The cached verdict. true means "the device looked clean at start-up".
     *
     * Deliberately public and static: it is the widest, latest window in the
     * whole challenge, and finding it is one of the three intended solutions.
     */
    public static boolean secure = true;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);

        // Earliest possible application code. Nothing of the app has run yet.
        secure = Guard.earlyVerdict();

        Log.i(Guard.TAG, "early verdict recorded: " + secure);
    }
}
