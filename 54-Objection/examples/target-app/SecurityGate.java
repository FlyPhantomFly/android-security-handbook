// examples/target-app/SecurityGate.java
//
// PURPOSE
//   Five root-detection checks, each isolated so that a bypass can be
//   attributed to exactly one of them. This class is the measuring instrument
//   the whole chapter is built on.
//
//   Each check returns true when it believes the device is rooted. Each logs
//   its own verdict under a distinct tag so that `adb logcat` gives you a
//   per-check result rather than a single aggregate boolean -- which is exactly
//   the information `android root disable` does NOT give you.
//
// THE MAPPING THIS CLASS IS DESIGNED TO EXPOSE
//   objection 1.11.0's `android root disable` installs exactly three hooks
//   (read them yourself in objection/agent.js, module "android/root"):
//
//     java.lang.String.contains(String)  -> false when the argument is "test-keys"
//     java.lang.Runtime.exec(String)     -> throws IOException when the command endsWith("su")
//     java.io.File.exists()              -> false when the absolute path is one of 13 hard-coded strings
//
//   Checks A, C and E sit inside that envelope. Checks B and D sit outside it.
//   Nothing about the app tells you which is which; you have to read the agent.
//
// WHAT THIS WILL *NOT* TELL YOU
//   * Nothing here is a NATIVE check. A real hardened app does its stat() in C
//     where no Java hook can see it -- see 37-RootDetection section 3.12. This
//     class deliberately stays in Java, because the point being measured is the
//     coverage of a Java-layer canned script, not the Java/native boundary.
//   * A "not rooted" verdict from this class means the five checks were
//     defeated. It does not mean the device is not rooted.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch54.target;

import android.os.Build;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;

public final class SecurityGate {

    public static final String TAG = "CH54";

    private SecurityGate() {
    }

    // ---------------------------------------------------------------- A ----
    // File.exists() against a path that IS in objection's commonPaths list.
    // Expected to be neutralised by `android root disable`.
    public static boolean checkA_suBinaryKnownPath() {
        boolean found = new File("/system/xbin/su").exists();
        Log.i(TAG, "A su-known-path        rooted=" + found);
        return found;
    }

    // ---------------------------------------------------------------- B ----
    // File.exists() against a path that is NOT in objection's list.
    // /sbin/magisk is absent from commonPaths, so the canned hook falls through
    // to the real File.exists() and this check keeps working.
    public static boolean checkB_magiskUnknownPath() {
        boolean found = new File("/sbin/magisk").exists()
                || new File("/data/adb/magisk").exists();
        Log.i(TAG, "B magisk-unknown-path  rooted=" + found);
        return found;
    }

    // ---------------------------------------------------------------- C ----
    // Runtime.exec(String) -- the single-String overload objection hooks.
    // When objection is active this throws IOException("objection anti-root")
    // and the catch block reports "not rooted".
    public static boolean checkC_execSuStringOverload() {
        boolean rooted = false;
        try {
            Process p = Runtime.getRuntime().exec("/system/bin/su");
            p.destroy();
            rooted = true;
        } catch (Exception e) {
            // The exception message is worth logging: under objection it reads
            // "objection anti-root", which is a fingerprint of the tool itself.
            Log.i(TAG, "C exec-string threw: " + e.getMessage());
        }
        Log.i(TAG, "C exec-su-String       rooted=" + rooted);
        return rooted;
    }

    // ---------------------------------------------------------------- D ----
    // Runtime.exec(String[]) -- the ARRAY overload. objection hooks only
    // exec.overload("java.lang.String"), so this path is untouched.
    // Java overload resolution is per-signature, and so is a Frida hook.
    public static boolean checkD_execWhichArrayOverload() {
        boolean rooted = false;
        try {
            Process p = Runtime.getRuntime()
                    .exec(new String[]{"/system/bin/which", "su"});
            BufferedReader r = new BufferedReader(
                    new InputStreamReader(p.getInputStream()));
            String line = r.readLine();
            r.close();
            p.destroy();
            rooted = (line != null && line.contains("su"));
        } catch (Exception e) {
            Log.i(TAG, "D exec-array threw: " + e.getMessage());
        }
        Log.i(TAG, "D which-su-String[]    rooted=" + rooted);
        return rooted;
    }

    // ---------------------------------------------------------------- E ----
    // Build.TAGS contains "test-keys". objection hooks String.contains and
    // special-cases exactly that argument.
    public static boolean checkE_buildTags() {
        String tags = Build.TAGS;
        boolean rooted = tags != null && tags.contains("test-keys");
        Log.i(TAG, "E build-tags           rooted=" + rooted + " (TAGS=" + tags + ")");
        return rooted;
    }

    /**
     * Runs all five checks and returns how many reported "rooted".
     * Every check runs; none short-circuits. Short-circuiting would destroy the
     * per-check attribution this class exists to provide.
     */
    public static int evaluate() {
        int score = 0;
        if (checkA_suBinaryKnownPath())      score++;
        if (checkB_magiskUnknownPath())      score++;
        if (checkC_execSuStringOverload())   score++;
        if (checkD_execWhichArrayOverload()) score++;
        if (checkE_buildTags())              score++;
        Log.i(TAG, "VERDICT score=" + score + "/5 rooted=" + (score > 0));
        return score;
    }
}
