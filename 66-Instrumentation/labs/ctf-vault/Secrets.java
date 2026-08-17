// labs/ctf-vault/Secrets.java
//
// DELIBERATELY VULNERABLE CTF FIXTURE -- chapter 66, lab 04.
// Install on a device you own. Uninstall when you are finished.
//
// The three flag fragments live here, each XOR-encoded with its own key so that
// `strings` over the DEX does not simply hand them over. They are not encrypted
// and they are not meant to be: the challenge is about WHEN and FROM WHERE the
// runtime values are reachable, not about breaking a cipher. An entrant who
// recovers the blobs statically has done real work and should be told so -- but
// they still have to assemble the flag, and the assembly rule is only visible at
// runtime.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch66.ctf;

import java.nio.charset.StandardCharsets;

public final class Secrets {

    // -- fragment 1 -------------------------------------------------------- //
    // Written to a file by EarlyProvider.onCreate(), which runs BEFORE any
    // instrumentation gets control. It is therefore already on disk when you
    // arrive -- and it is inside the app's private data directory, so `adb
    // shell` cannot read it. This fragment tests VANTAGE.
    static final byte[] BLOB_1 = {
        (byte) 0x38, (byte) 0x3F, (byte) 0x3C, (byte) 0x35, (byte) 0x28, (byte) 0x3F
    };
    static final int KEY_1 = 0x5A;

    // -- fragment 2 -------------------------------------------------------- //
    // Decoded into sVolatile by CtfApp.attachBaseContext(), and WIPED on the
    // first line of CtfApp.onCreate(). Instrumentation.onCreate() runs between
    // those two events. This fragment tests ORDERING, and it is the one that
    // punishes a probe that does its work in onStart() without thinking.
    static final byte[] BLOB_2 = {
        (byte) 0x52, (byte) 0x43, (byte) 0x43, (byte) 0x5F, (byte) 0x5A, (byte) 0x50,
        (byte) 0x52, (byte) 0x47, (byte) 0x5A, (byte) 0x5C, (byte) 0x5D
    };
    static final int KEY_2 = 0x33;

    // -- fragment 3 -------------------------------------------------------- //
    // Decoded into sPart3 by CtfApp.onCreate(), but ONLY if Gate.sUnlocked is
    // true at that moment. Nothing in the app ever sets it. This fragment tests
    // whether you understood that you can WRITE the process, not merely read it.
    static final byte[] BLOB_3 = {
        (byte) 0x33, (byte) 0x32, (byte) 0x3F, (byte) 0x2E,
        (byte) 0x39, (byte) 0x3D, (byte) 0x28, (byte) 0x39
    };
    static final int KEY_3 = 0x5C;

    // -- decoy ------------------------------------------------------------- //
    // Written to SharedPreferences under the key "flag" during onCreate. It is
    // the first thing a storage sweep finds and it is worth nothing.
    static final byte[] DECOY = {
        (byte) 0x52, (byte) 0x45, (byte) 0x57, (byte) 0x6A, (byte) 0x62, (byte) 0x79,
        (byte) 0x25, (byte) 0x7D, (byte) 0x7D, (byte) 0x21, (byte) 0x66, (byte) 0x4E,
        (byte) 0x63, (byte) 0x22, (byte) 0x25, (byte) 0x75, (byte) 0x6C
    };
    static final int KEY_DECOY = 0x11;

    /** Live only between attachBaseContext and the first line of onCreate. */
    public static volatile String sVolatile = null;

    /** Set during onCreate. Real only if the gate was open at that instant. */
    public static volatile String sPart3 = "unset";

    private Secrets() {
    }

    static String decode(byte[] blob, int key) {
        byte[] out = new byte[blob.length];
        for (int i = 0; i < blob.length; i++) {
            out[i] = (byte) (blob[i] ^ key);
        }
        return new String(out, StandardCharsets.UTF_8);
    }

    static byte[] encoded(byte[] blob) {
        return blob.clone();
    }
}
