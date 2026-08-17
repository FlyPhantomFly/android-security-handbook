/*
 * examples/guarded-app/NativeGuard.java
 *
 * The Java side of the native tier.
 *
 * WHY A NATIVE TIER EXISTS IN A DEMO APP
 *   Because the timing is the lesson. Everything in Guard.java runs when
 *   MainActivity asks it to - which is after the process is alive, after ART
 *   is up, and comfortably after a Frida script that attached has installed
 *   its hooks. Everything in libch67guard.so runs from JNI_OnLoad and from a
 *   .init_array constructor, which is BEFORE any of that. An attacker who
 *   attaches rather than spawns never gets to see the second one happen; they
 *   only see the process die.
 *
 *   That single sentence is what ../../53-Frida/README.md sends readers here
 *   for, and it is why this chapter's harness
 *   (../../scripts/early-instrument.js) exists at all.
 *
 * EVERY METHOD HERE IS SAFE IF THE LIBRARY IS MISSING
 *   build.sh only builds the .so when an NDK is present. Without it the app
 *   still runs, with the native tier reported as absent - which is itself a
 *   triage outcome you should be able to recognise.
 */
package com.pentest.ch67.guarded;

import android.util.Log;

public final class NativeGuard {

    private static boolean loaded = false;
    private static String loadError = "not attempted";

    static {
        try {
            System.loadLibrary("ch67guard");
            loaded = true;
            loadError = "";
        } catch (Throwable t) {
            // UnsatisfiedLinkError on a build with no NDK available, or on an
            // ABI we did not package. Not fatal: the Java tier still runs.
            loaded = false;
            loadError = String.valueOf(t);
            Log.w(Guard.TAG, "native tier absent: " + t);
        }
    }

    private NativeGuard() { }

    public static boolean isLoaded() { return loaded; }

    public static String loadError() { return loadError; }

    /**
     * Returns a human-readable report of what the native tier observed at load
     * time, or a placeholder when the library is absent.
     *
     * The native checks have ALREADY RUN by the time you can call this. It
     * reports history; it does not perform the check.
     */
    public static String report() {
        if (!loaded) return "native tier absent (" + loadError + ")";
        try {
            return nativeReport();
        } catch (Throwable t) {
            return "native report failed: " + t;
        }
    }

    /** Fires abort() in native code. Used by Guard.Response.NATIVE_ABORT. */
    public static void abortNow() {
        if (!loaded) return;
        try {
            nativeAbort();
        } catch (Throwable ignored) {
            // If the symbol is missing, the caller falls back to System.exit.
        }
    }

    private static native String nativeReport();
    private static native void nativeAbort();
}
