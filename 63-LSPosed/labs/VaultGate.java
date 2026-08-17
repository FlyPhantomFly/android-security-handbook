/*
 * labs/VaultGate.java
 *
 * Chapter 63 - LSPosed.  The deliberately vulnerable target that every module
 * in this chapter hooks.  Part of the lab application com.pentest.ch63.vault,
 * which YOU build (Lab 02) and which exists only to be attacked.
 *
 * In an Android project this file lives at:
 *     app/src/main/java/com/pentest/ch63/vault/VaultGate.java
 *
 * WHAT IS WRONG WITH IT, DELIBERATELY
 *   Every defect below is one this chapter's README analyses as a vulnerability
 *   class.  They are here in one class so that a single module can demonstrate
 *   all of them.
 *
 *     1. sDeviceOk       - a security decision CACHED in a static field.
 *                          README section 5.3.  One setStaticObjectField beats
 *                          it forever, and a module runs before the first
 *                          evaluation would have happened.
 *     2. matches()       - the expected PIN is an ARGUMENT.  A hook that reads
 *                          argument 1 learns the secret, which reproduces on a
 *                          clean device.  README section 6.2.1.
 *     3. loadExpectedPin - the PIN is XOR-"encoded" in the APK.  That is not
 *                          encryption; it delays a static analyst by about
 *                          ninety seconds and a dynamic one by zero.
 *     4. isRooted()      - a client-side check whose result is trusted, made in
 *                          Java, where it is the easiest possible thing to hook.
 *     5. mFailedAttempts - lockout state in a field the attacker can write.
 *
 * WHAT IS *NOT* WRONG WITH IT
 *   Nothing here is a bug in the sense of a crash.  It compiles, it runs, and
 *   on an unrooted device with no instrumentation it behaves correctly.  That is
 *   the point: these are DESIGN defects, invisible to a linter, and every one of
 *   them is in shipping software today.
 *
 * ETHICS
 *   This is a teaching fixture.  It is not derived from any real application.
 *   Do not point the modules that hook it at software you do not own.
 */

package com.pentest.ch63.vault;

import android.util.Log;

import java.io.File;

public final class VaultGate {

    private static final String TAG = "VaultGate";

    /**
     * DEFECT 1.  A nullable Boolean is the tell for a lazily-computed cache.
     * The check is expensive, so somebody cached it -- correct advice, applied
     * to something that is not a pure function and not a performance problem.
     *
     * A module sets this to TRUE in handleLoadPackage, before any of the
     * application's own code runs.  No hook is installed anywhere.
     */
    static Boolean sDeviceOk = null;

    /** DEFECT 5.  Lockout state the attacker's process can write. */
    private int mFailedAttempts = 0;

    /** Purely so the lab has something observable that is not the return value. */
    private int mSuccessfulUnlocks = 0;

    /**
     * The decision.  This is the PRODUCER in chapter 65's producer/consumer
     * framing: hook it and every caller changes.
     */
    public boolean isUnlocked(String pin) {
        if (sDeviceOk == null) {
            sDeviceOk = Boolean.valueOf(!isRooted());
            Log.i(TAG, "device posture evaluated once: ok=" + sDeviceOk);
        }
        if (!sDeviceOk.booleanValue()) {
            Log.w(TAG, "refusing: device posture");
            return false;
        }
        if (mFailedAttempts >= 3) {
            Log.w(TAG, "refusing: locked out after " + mFailedAttempts + " attempts");
            return false;
        }
        if (matches(pin, loadExpectedPin())) {
            mFailedAttempts = 0;
            mSuccessfulUnlocks++;
            AuditLog.record("unlock", "ok", mSuccessfulUnlocks);
            return true;
        }
        mFailedAttempts++;
        AuditLog.record("unlock", "denied", mFailedAttempts);
        return false;
    }

    /**
     * DEFECT 2.  The expected value arrives as an argument, so it is in a
     * register at the moment of the call.  A hook on this method learns the
     * secret without changing anything -- which is a better finding than a
     * forced return value, because the secret reproduces on a clean device and
     * the forced return value does not.
     *
     * Note also: this is `private`.  XposedHelpers ignores access modifiers
     * entirely.  `private` is a compiler concept, not a security control.
     */
    private boolean matches(String entered, String expected) {
        return entered != null && entered.equals(expected);
    }

    /**
     * DEFECT 3.  "Obfuscated" with a single-byte XOR.  The plaintext must exist
     * in memory at the moment of the comparison, which is exactly where the hook
     * in DEFECT 2 sits.
     *
     * The encoded bytes below decode to a ten-character PIN.  Work it out with a
     * pencil if you like -- that is the ninety seconds this buys.
     */
    private String loadExpectedPin() {
        final byte[] enc = {
            0x55, 0x5F, 0x59, 0x5C, 0x40, 0x1B, 0x0C, 0x18, 0x01, 0x19
        };
        final byte key = 0x6D;
        char[] out = new char[enc.length];
        for (int i = 0; i < enc.length; i++) {
            out[i] = (char) ((enc[i] ^ key) & 0xFF);
        }
        return new String(out);
    }

    /**
     * DEFECT 4.  A client-side root check whose result is trusted, implemented
     * in Java, where it is the easiest layer in the process to hook.
     *
     * Note what it does NOT do, and why chapter 63 section 5.5 calls this shape
     * broken rather than merely weak:
     *
     *   - File.exists() maps BOTH ENOENT and EACCES to false.  On the reference
     *     device /data/adb is present and EACCES to every application, so this
     *     returns false there whether or not anything is installed in it.
     *   - The package check is defeated by a renamed manager, and from API 30
     *     it needs a <queries> declaration or it throws for a package that IS
     *     installed.
     */
    private boolean isRooted() {
        String[] paths = {
            "/system/xbin/su",
            "/system/bin/su",
            "/sbin/su",
            "/data/adb/magisk",
            "/data/adb/lspd",
        };
        for (String p : paths) {
            if (new File(p).exists()) {
                Log.w(TAG, "root indicator: " + p);
                return true;
            }
        }
        return false;
    }

    /** Exposed so a lab can prove the ORIGINAL body executed, not just that a
     *  hook returned something.  Chapter 65 uses the same trick with a native
     *  counter: find a side effect you can count, not a return value you forced. */
    public int successfulUnlocks() {
        return mSuccessfulUnlocks;
    }

    /** Exposed for the same reason, on the failure path. */
    public int failedAttempts() {
        return mFailedAttempts;
    }
}
