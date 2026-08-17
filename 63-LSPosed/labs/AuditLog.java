/*
 * labs/AuditLog.java
 *
 * Chapter 63 - LSPosed.  A supporting class for the lab application
 * com.pentest.ch63.vault, built in Lab 02.
 *
 * In an Android project this file lives at:
 *     app/src/main/java/com/pentest/ch63/vault/AuditLog.java
 *
 * WHY IT EXISTS
 *   It gives the labs three things VaultGate alone cannot:
 *
 *     1. OVERLOADS.  record() is declared four times with four different
 *        signatures.  findAndHookMethod needs the exact one; hookAllMethods
 *        takes the name and gets all four.  Lab 02 uses this to make the
 *        difference concrete rather than theoretical.
 *
 *     2. A STATIC SIDE EFFECT you can count.  sRecordCount increments on every
 *        call.  A hook that forces a return value changes nothing here; a hook
 *        that lets the original run does.  That is how you prove a hook is a
 *        HOOK and not a REPLACEMENT -- the managed-layer version of chapter 65's
 *        guard_counter reading 4 after four calls.
 *
 *     3. A method that runs LATE.  flushOnDemand() is only ever called from a
 *        ContentProvider, which initialises BEFORE Application.onCreate.  Lab 03
 *        uses it to show why a hook installed from onCreate is already too late
 *        and one installed from handleLoadPackage is not.
 *
 * ETHICS
 *   Teaching fixture.  Not derived from any real application.
 */

package com.pentest.ch63.vault;

import android.util.Log;

public final class AuditLog {

    private static final String TAG = "AuditLog";

    /** The countable side effect.  Public so a lab can read it without a hook. */
    public static int sRecordCount = 0;

    /** Set by flushOnDemand(), which runs from a ContentProvider. */
    public static boolean sFlushedEarly = false;

    private AuditLog() { }

    // ------------------------------------------------------------------
    // Four overloads.  findAndHookMethod needs the exact parameter types;
    // XposedBridge.hookAllMethods(clazz, "record", cb) takes all four at once.
    // ------------------------------------------------------------------

    public static void record(String event) {
        sRecordCount++;
        Log.i(TAG, "[" + sRecordCount + "] " + event);
    }

    public static void record(String event, String outcome) {
        sRecordCount++;
        Log.i(TAG, "[" + sRecordCount + "] " + event + " -> " + outcome);
    }

    public static void record(String event, String outcome, int detail) {
        sRecordCount++;
        Log.i(TAG, "[" + sRecordCount + "] " + event + " -> " + outcome + " (" + detail + ")");
    }

    public static void record(String event, Throwable t) {
        sRecordCount++;
        Log.w(TAG, "[" + sRecordCount + "] " + event, t);
    }

    // ------------------------------------------------------------------
    // The early one.
    // ------------------------------------------------------------------

    /**
     * Called from AuditProvider.onCreate().
     *
     * A ContentProvider declared in the application's own manifest is created
     * by ActivityThread BEFORE Application.onCreate runs.  That ordering is why
     * the androidx.startup pattern works, and why an SDK that initialises from a
     * provider is invisible to a hook installed in onCreate.
     *
     * handleLoadPackage runs before ALL of this, which is the whole reason a
     * module can see initialisation that a late Frida attach cannot.
     */
    public static void flushOnDemand() {
        sFlushedEarly = true;
        Log.i(TAG, "flushOnDemand ran (from a ContentProvider, before Application.onCreate)");
    }

    /** Exposed so a lab can prove the original body ran. */
    public static int recordCount() {
        return sRecordCount;
    }
}
