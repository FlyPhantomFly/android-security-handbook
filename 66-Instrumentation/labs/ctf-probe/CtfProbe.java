// labs/ctf-probe/CtfProbe.java
//
// SKELETON for chapter 66, lab 04. This compiles, installs and runs as shipped,
// and it deliberately solves NOTHING. Your job is to fill in the four TODOs.
//
// Build and run it with:
//     # host
//     cd 66-Instrumentation/labs
//     OUTDIR=/tmp/ch66ctf ./build-ctf.sh --install
//     adb shell am instrument -w -r \
//         com.pentest.ch66.ctf.test/com.pentest.ch66.ctf.probe.CtfProbe
//
// WHAT YOU ARE ALLOWED TO USE
//     Anything in the platform SDK, plus reflection. You may read the CTF app's
//     sources in ../ctf-vault -- they are shipped on purpose, because the
//     challenge is not "guess what the app does", it is "arrange to be in the
//     right place at the right time".
//
// WHAT YOU MUST NOT DO
//     Do not add com.pentest.ch66.ctf classes to this APK. Your DEX is FIRST on
//     the shared class path (chapter 66 section 3.7), so a duplicate
//     fully-qualified name shadows the target's and every field you read is your
//     own copy's default value. It will look like it works. It will be a lie.
//     Resolve everything by reflection, as the helpers below do.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch66.ctf.probe;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public class CtfProbe extends Instrumentation {

    private static final String TAG = "ch66solve";
    private static final String PKG = "com.pentest.ch66.ctf";

    private final Map<String, String> mOut = new LinkedHashMap<>();

    /** Whatever you manage to capture during onCreate goes in here. */
    private String mFragment2 = "not-captured";

    // ===================================================================== //
    //  onCreate -- runs BEFORE the target's Application.onCreate().
    //  Everything that is time-sensitive belongs here, not in onStart().
    // ===================================================================== //
    @Override
    public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        Log.i(TAG, "onCreate entered at t=" + SystemClock.elapsedRealtimeNanos());

        ClassLoader cl = getContext().getClassLoader();

        // ---------------------------------------------------------------- //
        // TODO 1 -- fragment 2.
        //
        // CtfApp.attachBaseContext() decoded it into a static field. The first
        // line of CtfApp.onCreate() sets that field to null. Read ../ctf-vault
        // to find the class and field name, then capture the value into
        // mFragment2 -- HERE, at this point in the file, not in onStart().
        //
        // Hint: readStatic(cl, PKG + ".Xxxx", "yyyy") is written for you below.
        // ---------------------------------------------------------------- //

        // ---------------------------------------------------------------- //
        // TODO 2 -- fragment 3.
        //
        // CtfApp.onCreate() consults a boolean exactly once and decodes
        // fragment 3 only if it is true. Nothing in the app ever sets it.
        // Set it -- again, HERE, because in three milliseconds it will be too
        // late and the write will succeed anyway.
        //
        // Hint: writeStatic(cl, ..., ..., Boolean.TRUE).
        // ---------------------------------------------------------------- //

        start();
    }

    // ===================================================================== //
    //  onStart -- runs on the instrumentation thread, racing the application.
    //  Everything that needs the app to have FINISHED belongs here, after a
    //  proper wait.
    // ===================================================================== //
    @Override
    public void onStart() {
        ClassLoader cl = getContext().getClassLoader();

        // Wait for the application to finish starting. Read ../ctf-vault and
        // pick the marker that is set when the work is DONE, not when it begins.
        // Chapter 66 section 11.2 records what happens if you pick wrong: every
        // read comes back empty and the run still reports success.
        long deadline = SystemClock.elapsedRealtime() + 10_000L;
        while (SystemClock.elapsedRealtime() < deadline) {
            String marker = readStatic(cl, PKG + ".CtfApp", "sStartupCompleteAtNs");
            if (!"0".equals(marker) && !marker.startsWith("ERROR")) {
                break;
            }
            SystemClock.sleep(25);
        }

        // ---------------------------------------------------------------- //
        // TODO 3 -- fragment 1.
        //
        // EarlyProvider.onCreate() wrote it to a file inside the app's private
        // files directory, ENCODED. You need two things: the bytes, and the key.
        // The bytes are reachable because you are running as this uid -- try
        // reading the same path from `adb shell` first, so you can feel the
        // difference. The key is in the DEX; recover it however you like.
        //
        // Hint: getTargetContext().getFilesDir(), and readBytes() below.
        // ---------------------------------------------------------------- //
        String fragment1 = "not-recovered";

        // ---------------------------------------------------------------- //
        // TODO 4 -- fragment 3, read back, and assemble.
        // ---------------------------------------------------------------- //
        String fragment3 = readStatic(cl, PKG + ".Secrets", "sPart3");

        mOut.put("fragment1", fragment1);
        mOut.put("fragment2", mFragment2);
        mOut.put("fragment3", fragment3);
        mOut.put("flag", "CTF{" + fragment1 + "_" + mFragment2 + "_" + fragment3 + "}");

        Bundle b = new Bundle();
        for (Map.Entry<String, String> e : mOut.entrySet()) {
            b.putString(e.getKey(), e.getValue());
            Log.i(TAG, e.getKey() + " = " + e.getValue());
        }
        finish(Activity.RESULT_OK, b);
    }

    // ===================================================================== //
    //  Helpers. Nothing here needs changing.
    // ===================================================================== //

    /** Read a static field of an arbitrary class by name. Never throws. */
    static String readStatic(ClassLoader cl, String className, String fieldName) {
        try {
            Field f = Class.forName(className, true, cl).getDeclaredField(fieldName);
            f.setAccessible(true);
            return String.valueOf(f.get(null));
        } catch (Throwable t) {
            return "ERROR " + t.getClass().getSimpleName() + ": " + t.getMessage();
        }
    }

    /** Write a static field of an arbitrary class by name. Never throws. */
    static String writeStatic(ClassLoader cl, String className, String fieldName, Object value) {
        try {
            Field f = Class.forName(className, true, cl).getDeclaredField(fieldName);
            f.setAccessible(true);
            f.set(null, value);
            return "ok";
        } catch (Throwable t) {
            return "ERROR " + t.getClass().getSimpleName() + ": " + t.getMessage();
        }
    }

    /** Read a whole file as bytes, or return null. */
    static byte[] readBytes(File f) {
        try (FileInputStream in = new FileInputStream(f)) {
            byte[] buf = new byte[(int) Math.max(f.length(), 1)];
            int n = in.read(buf);
            byte[] out = new byte[Math.max(n, 0)];
            System.arraycopy(buf, 0, out, 0, out.length);
            return out;
        } catch (Throwable t) {
            Log.w(TAG, "readBytes " + f + ": " + t);
            return null;
        }
    }

    /** XOR every byte with key and interpret the result as UTF-8. */
    static String xorDecode(byte[] blob, int key) {
        if (blob == null) {
            return "no-bytes";
        }
        byte[] out = new byte[blob.length];
        for (int i = 0; i < blob.length; i++) {
            out[i] = (byte) (blob[i] ^ key);
        }
        return new String(out, StandardCharsets.UTF_8);
    }
}
