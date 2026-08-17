/*
 * examples/guarded-app/Vault.java
 *
 * Seam 5: the gated code path.
 *
 * The chapter's central claim is that a protection is a pipeline, and that the
 * last stage - the code the control was protecting - is a legitimate place to
 * attack, often the cheapest one. This class exists to make that concrete.
 *
 * Three doors into the same secret:
 *
 *   open(Verdict)   the front door. Runs the branch, then decrypts.
 *   openUnchecked() the same decryption with no branch in front of it. There
 *                   is no bypass here and no hook: an instrumented process can
 *                   simply call it. This is "altitude D" from
 *                   ../../20-Security-Architecture/labs/lab-03-integrity-gate-bypass.md.
 *   poison()        what the POISON response does. Nothing crashes; the secret
 *                   just comes out wrong from then on. It is the response that
 *                   costs an attacker the most time, and the one that costs a
 *                   real user the most trust when it misfires.
 *
 * The obfuscation on the secret is intentionally weak (a repeating XOR key
 * plus a position term). It is here so that `strings` on the DEX does not hand
 * the answer over, not because it resists anything. Chapter 40 covers what
 * real string protection looks like and what it costs.
 */
package com.pentest.ch67.guarded;

import android.util.Log;

public final class Vault {

    private static volatile boolean poisoned = false;

    private static final byte[] KEY = {
        (byte) 0x5A, (byte) 0x3C, (byte) 0x77, (byte) 0x11,
        (byte) 0x2E, (byte) 0xA9, (byte) 0x40, (byte) 0x08
    };

    private static final byte[] BLOB = {
        (byte) 0x19, (byte) 0x73, (byte) 0x4F, (byte) 0x33, (byte) 0x49, (byte) 0xE9,
        (byte) 0x06, (byte) 0x08, (byte) 0x51, (byte) 0x6D, (byte) 0x45, (byte) 0x03,
        (byte) 0x09, (byte) 0xC3, (byte) 0x46, (byte) 0x52, (byte) 0x75, (byte) 0x29,
        (byte) 0x39, (byte) 0xA4, (byte) 0xCE, (byte) 0x09, (byte) 0xBB, (byte) 0xC7,
        (byte) 0xAD, (byte) 0xA2, (byte) 0xB2, (byte) 0xF3, (byte) 0x84, (byte) 0x52,
        (byte) 0xE6, (byte) 0x8E, (byte) 0xDB, (byte) 0x84, (byte) 0xF5, (byte) 0xD4,
        (byte) 0xB1, (byte) 0xC1, (byte) 0x37
    };

    private Vault() { }

    /** The POISON response calls this. Note that it does not throw. */
    public static void poison() {
        poisoned = true;
    }

    /** Front door: enforce, then decrypt. */
    public static String open(Guard.Verdict v) {
        Guard.enforce(v);
        Log.i(Guard.TAG, "vault " + Guard.SEAM_GATED + ": decrypting");
        return decrypt();
    }

    /**
     * Back door. Same bytes, same key, no branch.
     *
     * Nothing about this method is a bug in the demo - it is exactly what a
     * real app looks like once you notice that the check and the payload are
     * two separate pieces of code and only one of them is guarded.
     */
    public static String openUnchecked() {
        Log.i(Guard.TAG, "vault " + Guard.SEAM_GATED + ": decrypting (unchecked entry)");
        return decrypt();
    }

    private static String decrypt() {
        byte[] out = new byte[BLOB.length];
        for (int i = 0; i < BLOB.length; i++) {
            int b = BLOB[i] ^ KEY[i % KEY.length] ^ ((i * 7) & 0xFF);
            if (poisoned) b ^= 0x20;    // silently wrong, never obviously broken
            out[i] = (byte) b;
        }
        return new String(out);
    }
}
