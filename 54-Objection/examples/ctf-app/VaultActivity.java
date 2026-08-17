// examples/ctf-app/VaultActivity.java
//
// PURPOSE
//   The thing you are trying to open, in the chapter 54 CTF.
//
//   Three properties make this more than a boolean gate:
//
//   1. The flag is NOT a string constant. It is AES-decrypted at reveal() time,
//      so `strings`, a DEX dump and a heap search before unlock all come up
//      empty. That closes the laziest route without closing any interesting one.
//
//   2. The gate reads CtfApp.secure -- a CACHED verdict, computed in
//      attachBaseContext long before this Activity existed. Re-launching the
//      Activity does not re-run the guard. Hooking the guard after the fact
//      therefore changes nothing, which is what makes lab-04 harder than
//      "set return_value true".
//
//   3. reveal() is private and static -- and Frida does not care about `private`.
//      Calling it directly is intended route 3, and it never defeats a single
//      check. That is the lesson: the shortest path past a gate is often not
//      through it.
//
// BEFORE YOU BUILD
//   BLOB below is a placeholder. Generate your own so your flag is unique --
//   the helper is in labs/lab-04-ctf-the-confident-tool.md, Part 0.1. It uses
//   AES-128-CBC, key bytes 0x41..0x50, and a 16-byte zero IV, matching reveal().
//
//   Building with the placeholder in place compiles fine and fails at runtime
//   with a Base64 or padding error, which is the expected symptom.
//
// WHAT THIS WILL *NOT* TELL YOU
//   That a hard-coded key is realistic. It is not -- a real app would derive or
//   attest it. The crypto here exists only to keep the flag out of a strings
//   dump, not to model key management. 34-Cryptography and 49-KeyStore own that.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch54.ctf;

import android.app.Activity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class VaultActivity extends Activity {

    // Replace with your own ciphertext -- see lab-04 Part 0.1.
    private static final String BLOB = "<paste your base64 ciphertext here>";

    /**
     * Derives the flag. Private and static, which stops nobody with a hook.
     */
    private static String reveal() throws Exception {
        byte[] key = new byte[16];
        for (int i = 0; i < 16; i++) {
            key[i] = (byte) (0x41 + i);
        }
        byte[] iv = new byte[16];

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));

        return new String(c.doFinal(Base64.decode(BLOB, Base64.DEFAULT)), "UTF-8");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TextView tv = new TextView(this);
        tv.setPadding(48, 96, 48, 48);

        try {
            // The gate reads a CACHED verdict, not a live check.
            if (!CtfApp.secure) {
                throw new IllegalStateException("not secure");
            }
            tv.setText(reveal());
            Log.i(Guard.TAG, "vault opened");
        } catch (Exception e) {
            tv.setText("This device is not secure.");
            // Deliberately vague: the message names no check, so the app is not
            // a free oracle telling you which defence refused. Working that out
            // is the lab.
            Log.i(Guard.TAG, "vault refused: " + e.getClass().getSimpleName());
        }

        setContentView(tv);
    }
}
