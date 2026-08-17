/*
 * labs/ctf-app/VaultActivity.java
 * ---------------------------------------------------------------------------
 * CH38 CTF target — the visible half.
 *
 * The vault does not open for several seconds after launch, and when it does it
 * simply prints whatever the decryption produced. On a healthy install that is
 * a flag. On any other install it is 42 bytes of noise, with no message, no
 * exception, and no log line saying anything went wrong.
 *
 * The delay is not decoration. Chapter 38 section 3.14 argues that separating
 * the consequence from the detection in TIME and in CODE is the most effective
 * cheap measure a defender has, because it destroys the attacker's feedback
 * loop. Here you get to be on the receiving end of it.
 *
 * Read labs/lab-04-ctf-silent-integrity.md first. Read Guard.java last.
 *
 * AUTHORISED TESTING ONLY.
 * ---------------------------------------------------------------------------
 */

package com.pentest.ch38.ctf;

import android.app.Activity;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.security.MessageDigest;

public class VaultActivity extends Activity {

    static final String TAG = "CH38CTF";

    /**
     * The vault contents, XOR'd with a keystream derived from Guard.vaultKey().
     *
     * 42 bytes. Nothing about this array tells you what it should decrypt to,
     * and nothing in the app validates the result -- there is no checksum, no
     * magic prefix, and no "if it does not start with CH38 then complain".
     * That absence is deliberate.
     */
    private static final byte[] VAULT = {
        (byte) 0x9a, (byte) 0x47, (byte) 0xe0, (byte) 0x22, (byte) 0x1b, (byte) 0xd2,
        (byte) 0x12, (byte) 0xfc, (byte) 0xbd, (byte) 0x71, (byte) 0x86, (byte) 0xb6,
        (byte) 0x0b, (byte) 0x73, (byte) 0xcd, (byte) 0x5d, (byte) 0x22, (byte) 0x64,
        (byte) 0xff, (byte) 0xea, (byte) 0x7f, (byte) 0x8d, (byte) 0xa4, (byte) 0xfd,
        (byte) 0xf2, (byte) 0xac, (byte) 0xc8, (byte) 0x80, (byte) 0x5e, (byte) 0x3f,
        (byte) 0x47, (byte) 0xf7, (byte) 0xff, (byte) 0xb4, (byte) 0xcf, (byte) 0xd3,
        (byte) 0x9e, (byte) 0x03, (byte) 0xbc, (byte) 0x96, (byte) 0x6a, (byte) 0x3f
    };

    private TextView out;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ScrollView sv = new ScrollView(this);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(32, 64, 32, 64);

        TextView title = new TextView(this);
        title.setText("Vault");
        title.setTextSize(24);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        col.addView(title, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        out = new TextView(this);
        out.setTypeface(Typeface.MONOSPACE);
        out.setTextSize(13);
        out.setTextIsSelectable(true);
        out.setText("Opening…");
        col.addView(out, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        sv.addView(col);
        setContentView(sv);

        // Six seconds. Long enough that nobody correlates it with anything that
        // happened during process start, which is the point.
        new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
            @Override public void run() { open(); }
        }, 6000L);
    }

    private void open() {
        byte[] key = Guard.vaultKey();
        byte[] plain = xorStream(VAULT, key);

        // Printed as-is. No validation, no complaint, no hint.
        String shown = new String(plain, java.nio.charset.Charset.forName("UTF-8"));
        out.setText(shown + "\n\n(" + Guard.hex(plain) + ")");
        Log.i(TAG, "vault=" + shown);
        Log.i(TAG, "raw=" + Guard.hex(plain));
    }

    /**
     * Keystream: SHA-256(key || counter), concatenated. Simple on purpose --
     * the challenge is not the cryptography, and an offline solver needs to be
     * able to reimplement this in ten lines of Python.
     */
    static byte[] xorStream(byte[] data, byte[] key) {
        try {
            byte[] out = new byte[data.length];
            int pos = 0;
            byte counter = 0;
            while (pos < data.length) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(key);
                md.update(counter);
                byte[] block = md.digest();
                for (int i = 0; i < block.length && pos < data.length; i++, pos++) {
                    out[pos] = (byte) (data[pos] ^ block[i]);
                }
                counter++;
            }
            return out;
        } catch (Exception e) {
            return new byte[data.length];
        }
    }
}
