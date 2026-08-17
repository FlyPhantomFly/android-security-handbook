// examples/ctf-app/Guard.java
//
// PURPOSE
//   Defences 2, 3 and 4 of the chapter 54 CTF. Each probe was chosen because it
//   sits in a different blind spot of a canned root bypass. Together they defeat
//   every default command objection offers, and none of them is exotic -- all
//   four appear in real applications.
//
//   Mapped against the three hooks `android root disable` installs
//   (java.lang.String.contains, java.lang.Runtime.exec(String),
//    java.io.File.exists on 13 hard-coded paths):
//
//     magiskPath()  File.exists() on paths that are NOT among the thirteen.
//                   The canned hook matches with indexOf(path) >= 0 -- exact
//                   string equality -- so a path that differs by one character
//                   falls straight through to the real implementation.
//
//     whichSu()     ProcessBuilder, not Runtime.exec(String). The canned hook
//                   sits on the TOP of the JDK's delegation chain
//                   (exec(String) -> exec(String[]) -> ProcessBuilder.start()),
//                   so entering two frames lower misses it entirely.
//
//     mounts()      procfs, read with a FileReader. Not a File.exists() call,
//                   not an exec, not a String.contains. No canned root command
//                   touches this family at all.
//
//     testKeys()    String.indexOf, not String.contains. The one string hook a
//                   canned tool installs is on the wrong method. Two apps asking
//                   the identical question land inside or outside the envelope
//                   purely on which String method the developer happened to type.
//
// WHAT THIS WILL *NOT* TELL YOU
//   * Nothing here is native. A real hardened app does at least one of these in
//     C, where no Java hook of any kind can see it -- see 37-RootDetection 3.12.
//     The CTF stays in Java on purpose, so that every defence is beatable with
//     the skills this chapter teaches. Lab-04's extension work moves one native.
//   * A "clean" verdict does not mean the device is clean. It means these four
//     probes saw nothing, which on a Magisk DenyList device is expected.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch54.ctf;

import android.os.Build;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;

public final class Guard {

    static final String TAG = "CH54CTF";

    private Guard() {
    }

    // ------------------------------------------------------------ DEFENCE 2 --
    // Paths deliberately absent from every canned list.
    static boolean magiskPath() {
        return new File("/sbin/magisk").exists()
            || new File("/data/adb/magisk").exists()
            || new File("/data/adb/modules").exists();
    }

    // ------------------------------------------------------------ DEFENCE 3 --
    // ProcessBuilder rather than Runtime.exec(String).
    static boolean whichSu() {
        try {
            Process p = new ProcessBuilder("/system/bin/which", "su").start();
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = r.readLine();
            r.close();
            p.destroy();
            return line != null && line.length() > 0;
        } catch (Exception e) {
            return false;
        }
    }

    // ------------------------------------------------------------ DEFENCE 4 --
    // procfs. The interesting thing about beating this one is that you cannot
    // usefully hook "reading /proc/self/mounts" -- you have to filter the LINES,
    // which requires knowing what the app is looking for. A canned tool cannot
    // make that move.
    static boolean mounts() {
        try {
            BufferedReader r = new BufferedReader(new FileReader("/proc/self/mounts"));
            String line;
            boolean hit = false;
            while ((line = r.readLine()) != null) {
                if (line.contains("magisk") || line.contains("KSU")) {
                    hit = true;
                    break;
                }
            }
            r.close();
            return hit;
        } catch (Exception e) {
            return false;
        }
    }

    // ------------------------------------------------------------- bonus -----
    // indexOf, not contains.
    static boolean testKeys() {
        String t = Build.TAGS;
        return t != null && t.indexOf("test-keys") >= 0;
    }

    /**
     * Returns true when the device looked CLEAN.
     *
     * Note the single-pipe `|` rather than `||`: every probe runs every time, so
     * the log line below is a complete per-check record rather than a
     * short-circuited one. A challenge that hid three of its four checks behind
     * the first would be a worse teaching artefact, not a harder one.
     */
    static boolean earlyVerdict() {
        boolean bad = magiskPath() | whichSu() | mounts() | testKeys();

        Log.i(TAG, "guard: magisk=" + magiskPath()
                 + " which=" + whichSu()
                 + " mounts=" + mounts()
                 + " tags=" + testKeys());

        return !bad;
    }
}
