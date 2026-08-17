// examples/victim-app/Vault.java
//
// AUTHORISED TESTING ONLY -- part of the deliberately vulnerable chapter 31
// victim app. Install on a device you own.
//
// The "secret" this chapter's labs go after. It lives in the app's private
// files directory, which the app sandbox (chapter 21) protects perfectly well:
// no other uid can read it. Every attack in this chapter therefore has to make
// the VICTIM read it and put it somewhere the attacker can see.
//
// Nothing here is cryptography. It is a stand-in for whatever the real app
// keeps behind its login screen -- a session token, a card number, a health
// record. Treating it as a flag keeps the labs checkable.

package com.pentest.ch31.victim;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;

public final class Vault {

    /** Single log tag for the whole victim app, so `logcat -s CH31` shows everything. */
    public static final String TAG = "CH31";

    private static final String FILE = "vault.txt";

    /** The value the labs treat as the prize. Seeded on first launch. */
    private static final String SEED = "CH31{fragment_injection_skipped_the_login_screen}";

    /**
     * Stage two of the CTF (labs/lab-05).
     *
     * STAGE_KEY is deliberately NOT logged anywhere. AdminFragment renders it on
     * screen and nothing else does, which forces the CTF to confront the point
     * of README section 5.7: an injected Fragment makes the VICTIM display
     * something. It does not hand it to the attacker. Getting it out is a
     * separate step, and here that step is "look at the screen".
     */
    public static final String STAGE_KEY = "understudy-2f41";

    /** Released by VaultFragment only when STAGE_KEY arrives in its arguments. */
    public static final String FLAG2 = "CH31{arguments_are_attacker_input_too}";

    private Vault() { }

    /** Create the private file if it is not there yet. Called from MainActivity. */
    public static void seed(Context ctx) {
        File f = new File(ctx.getFilesDir(), FILE);
        if (f.exists()) {
            return;
        }
        FileOutputStream out = null;
        try {
            out = new FileOutputStream(f);
            out.write(SEED.getBytes("UTF-8"));
            Log.i(TAG, "Vault.seed: wrote " + f.getAbsolutePath());
        } catch (IOException e) {
            Log.e(TAG, "Vault.seed failed", e);
        } finally {
            closeQuietly(out);
        }
    }

    /**
     * Read the secret. Any code running inside this app's process may call this.
     * That is the whole point: a Fragment loaded by injection is inside the
     * process, so the sandbox does not stand between it and this file.
     */
    public static String read(Context ctx) {
        File f = new File(ctx.getFilesDir(), FILE);
        InputStream in = null;
        try {
            in = new java.io.FileInputStream(f);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[512];
            int n;
            while ((n = in.read(buf)) > 0) {
                bos.write(buf, 0, n);
            }
            return new String(bos.toByteArray(), "UTF-8");
        } catch (IOException e) {
            return "(vault unreadable: " + e.getMessage() + ")";
        } finally {
            closeQuietly(in);
        }
    }

    private static void closeQuietly(java.io.Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (IOException ignored) {
                // nothing useful to do here
            }
        }
    }
}
