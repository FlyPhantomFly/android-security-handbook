// examples/02-correct-aes-gcm.java
//
// WHAT THIS IS
//   Correct AES-256-GCM with a caller-supplied key. This is the reference
//   implementation the rest of the chapter compares against: when you write the
//   "secure replacement" paragraph of a finding, this is the code you paste.
//
//   Use it when the key comes from somewhere legitimate — a KDF over a user
//   password (03-pbkdf2-and-argon2.kt), a server-delivered key, or a key unwrapped
//   from an AndroidKeyStore-held wrapping key. NOT from a constant.
//
//   If the key can live in the AndroidKeyStore instead, prefer
//   04-keystore-backed-vault.kt: a key that never enters the app's process cannot
//   be extracted from the app's process.
//
// WHY IT MATTERS
//   GCM is an AEAD — Authenticated Encryption with Associated Data — which means
//   one primitive gives you confidentiality AND integrity AND the ability to bind
//   the ciphertext to its context. That single property removes most of the
//   catalogue in README section 5.2 at a stroke: no padding oracle (there is no
//   padding), no bit-flipping (the tag catches it), no "did we remember the MAC"
//   (it is not optional).
//
//   Everything that remains is nonce discipline, and that is what this file is
//   really about.
//
// HOW TO RUN
//   Drop into any Android module, or run on a desktop JVM (the class uses no
//   Android APIs, deliberately, so it is unit-testable):
//       # host
//       javac AesGcm.java && java -cp . com.example.secure.AesGcm
//
//   Verify it under instrumentation to see what correct output looks like, so you
//   can recognise it in someone else's app:
//       # host
//       frida -U -f com.example.secure -l ../scripts/frida-jca-universal-hook.js
//   You should see a DIFFERENT provider-generated IV on every call, and no
//   findings raised.
//
// REQUIREMENTS
//   API 19+ for GCMParameterSpec. AES-GCM is hardware-accelerated on essentially
//   every ARMv8 device via the cryptographic extension instructions, so there is
//   no performance argument for CBC on modern hardware.
//
// AUTHORISED USE. This file is safe to ship.

package com.example.secure;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class AesGcm {

    private static final int NONCE_BYTES = 12;   // 96 bits: the only length used directly as J0
    private static final int TAG_BITS    = 128;  // NOTE: bits, not bytes. 16 here would be a bug.
    private static final int TAG_BYTES   = TAG_BITS / 8;

    private AesGcm() {}

    // ======================================================================= //
    //  THE WARNING THAT MATTERS MORE THAN THE CODE                            //
    // ======================================================================= //
    //
    //  GCM is CTR mode plus a GHASH authenticator. CTR generates a keystream by
    //  encrypting a counter block built from the nonce, and XORs that keystream
    //  against the plaintext.
    //
    //  Encrypt two different messages with the same (key, nonce):
    //
    //      C1 = P1 XOR KS        C2 = P2 XOR KS
    //      C1 XOR C2 = P1 XOR P2
    //
    //  The keystream cancels. An attacker who never learns the key recovers the
    //  XOR of the two plaintexts, and if any part of either plaintext is known or
    //  guessable — a JSON prefix, a field name, an HTTP header — the corresponding
    //  bytes of the other fall out immediately.
    //
    //  That is the CTR consequence, and it is bad. The GCM consequence is worse.
    //  GHASH is a polynomial evaluation over GF(2^128) whose only secret is the
    //  authentication subkey H = E_K(0^128). Two ciphertexts under the same nonce
    //  give an attacker a polynomial equation in H; with a small number of such
    //  pairs H is solvable. Once H is known the attacker can forge a VALID
    //  AUTHENTICATION TAG for any message of their choosing under that key —
    //  permanently, for every message, past and future. This is the "forbidden
    //  attack" (Joux; demonstrated at scale against TLS by Boeck et al., WOOT 2016).
    //
    //  So: nonce reuse under GCM is not a weakening. It is a total break of both
    //  confidentiality and authenticity.
    //
    //  The engineering conclusion is blunt. NEVER supply the nonce yourself on
    //  encryption. Let the provider generate it, and read it back with getIV().
    //  A nonce you generate is a nonce you can accidentally reuse — after a
    //  restore-from-backup, after a counter resets on reinstall, after a fork, or
    //  because a test fixture hardcoded one and the fixture reached production.
    //
    //  If you genuinely must generate nonces yourself (for example, to make them
    //  deterministic across a distributed system), see the counter-based guidance
    //  at the bottom of this file, and consider AES-GCM-SIV instead, which is
    //  designed to be nonce-misuse resistant.

    /**
     * Encrypt. Returns nonce || ciphertext || tag as a single byte array.
     *
     * @param key            an AES key. 256-bit is the default recommendation;
     *                       128-bit is fine and faster. Both are unbroken.
     * @param plaintext      the data to protect.
     * @param associatedData authenticated but NOT encrypted. Put the context here:
     *                       the record's owner, its type, its schema version. The
     *                       exact same bytes must be supplied on decryption or the
     *                       tag check fails. This is how you stop an attacker
     *                       relocating a valid ciphertext from one row, field or
     *                       user to another — encryption alone does not, because
     *                       the key is the same everywhere. May be null.
     */
    public static byte[] seal(SecretKey key, byte[] plaintext, byte[] associatedData)
            throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");

        // Do NOT pass a GCMParameterSpec here. Letting the provider generate the
        // nonce guarantees it comes from SecureRandom and is fresh for every call.
        // This single line eliminates finding F-04 structurally: there is no code
        // path in which this method can reuse a nonce.
        c.init(Cipher.ENCRYPT_MODE, key);

        byte[] nonce = c.getIV();
        if (nonce.length != NONCE_BYTES) throw new IllegalStateException("unexpected nonce length");

        if (associatedData != null) c.updateAAD(associatedData);

        byte[] ct = c.doFinal(plaintext);          // ciphertext || 16-byte tag

        return ByteBuffer.allocate(NONCE_BYTES + ct.length).put(nonce).put(ct).array();
    }

    /**
     * Decrypt. Consumes nonce || ciphertext || tag.
     *
     * Throws on any tampering, and returns nothing on failure. There is no
     * "partial success" and no "decrypted but the tag was wrong" — if you catch
     * AEADBadTagException and return the plaintext anyway, you have removed the
     * only integrity guarantee in the design and reintroduced a decryption oracle.
     */
    public static byte[] open(SecretKey key, byte[] sealed, byte[] associatedData)
            throws GeneralSecurityException {
        if (sealed.length < NONCE_BYTES + TAG_BYTES) {
            throw new IllegalArgumentException("too short to be a sealed record");
        }
        ByteBuffer bb = ByteBuffer.wrap(sealed);
        byte[] nonce = new byte[NONCE_BYTES];
        bb.get(nonce);
        byte[] ct = new byte[bb.remaining()];
        bb.get(ct);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
        if (associatedData != null) c.updateAAD(associatedData);

        // Throws AEADBadTagException if the tag does not verify. Do not catch it
        // and return partial data — that would reintroduce an oracle.
        return c.doFinal(ct);
    }

    /**
     * Generate a fresh 256-bit AES key in software.
     *
     * This is the right way to do it IF the key must exist in the app's memory —
     * for example because it will be wrapped and sent elsewhere. If the key only
     * ever needs to be used locally, do not generate it here at all: generate it
     * inside the AndroidKeyStore, where the app process never sees the bytes.
     * See 04-keystore-backed-vault.kt.
     */
    public static SecretKey freshKey() throws GeneralSecurityException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, new SecureRandom());        // no setSeed(); the default source is correct
        return kg.generateKey();
    }

    /**
     * Wrap raw key bytes that arrived from somewhere legitimate (a KDF, a server,
     * an unwrap operation). Copies defensively so the caller can zero its buffer.
     */
    public static SecretKey keyFromBytes(byte[] raw) {
        if (raw.length != 16 && raw.length != 24 && raw.length != 32) {
            throw new IllegalArgumentException("AES key must be 16, 24 or 32 bytes, got "
                                               + raw.length);
        }
        return new SecretKeySpec(raw.clone(), "AES");
    }

    /**
     * Best-effort zeroing of a key buffer.
     *
     * Honest caveat, because this is often oversold: on ART this reduces the
     * window during which the bytes sit in the heap, but it does not guarantee
     * removal. The concurrent copying collector may already have relocated the
     * array, leaving a stale copy in a region that has not been reused, and a heap
     * dump taken before this call sees the key regardless. It is worth doing; it
     * is not a control you should claim in a design document.
     */
    public static void wipe(byte[] secret) {
        if (secret != null) Arrays.fill(secret, (byte) 0);
    }

    // ======================================================================= //
    //  Demonstration                                                          //
    // ======================================================================= //

    public static void main(String[] args) throws Exception {
        SecretKey key = freshKey();

        byte[] aad = "v1|user=42|field=note".getBytes("UTF-8");
        byte[] pt  = "the quick brown fox jumps over the lazy dog".getBytes("UTF-8");

        byte[] a = seal(key, pt, aad);
        byte[] b = seal(key, pt, aad);

        System.out.println("record A : " + hex(a));
        System.out.println("record B : " + hex(b));
        System.out.println();
        System.out.println("Same plaintext, same key, same AAD — and the two records differ,");
        System.out.println("because the provider generated a fresh nonce for each. If they were");
        System.out.println("identical you would be looking at F-03 or F-04.");
        System.out.println();

        System.out.println("decrypt A: " + new String(open(key, a, aad), "UTF-8"));

        // Tamper with one byte of the ciphertext body.
        byte[] tampered = a.clone();
        tampered[NONCE_BYTES + 3] ^= 0x01;
        try {
            open(key, tampered, aad);
            System.out.println("FAIL: tampering was not detected");
        } catch (GeneralSecurityException e) {
            System.out.println("tamper   : rejected (" + e.getClass().getSimpleName() + ")");
        }

        // Supply the wrong associated data. The ciphertext is untouched.
        try {
            open(key, a, "v1|user=43|field=note".getBytes("UTF-8"));
            System.out.println("FAIL: relocation was not detected");
        } catch (GeneralSecurityException e) {
            System.out.println("wrong AAD: rejected (" + e.getClass().getSimpleName() + ")");
        }

        System.out.println();
        System.out.println("That last result is the one worth internalising. The ciphertext was");
        System.out.println("valid and the key was correct; only the CONTEXT was wrong, and the");
        System.out.println("decryption still failed. Ask of every scheme you review: what is the");
        System.out.println("ciphertext bound to?");
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}

/*
 * ---------------------------------------------------------------------------
 * IF YOU MUST GENERATE NONCES YOURSELF
 *
 * There is one legitimate reason: a distributed system where several writers
 * share a key and you need a guarantee stronger than "each writer picks at
 * random". The standard construction (NIST SP 800-38D, section 8.2.1) is
 * deterministic:
 *
 *     nonce = fixed_field (4 bytes, unique per writer)
 *           || invocation_field (8 bytes, a counter that never repeats)
 *
 * The counter MUST be persisted before use and MUST survive process death,
 * crashes, restores from backup and reinstalls. If it can ever go backwards, you
 * have a nonce collision, and you are back at the total break described above.
 * On a mobile device — where "restore this phone from a backup taken last week"
 * is a normal user action — persisting a monotonic counter safely is genuinely
 * hard.
 *
 * Two safer options:
 *
 *   1. Random 96-bit nonces with a rekey budget. Birthday-bound: with random
 *      nonces the collision probability reaches roughly 2^-32 after about 2^32
 *      messages under one key. Rotate the key well before that. For an app
 *      encrypting user records this bound is never approached; for a system
 *      encrypting every network packet it is.
 *
 *   2. AES-GCM-SIV (RFC 8452), which derives the nonce from the message so that
 *      reuse degrades to "identical plaintexts are detectable" rather than "total
 *      break". Available through Tink; see 05-tink-envelope.kt.
 *
 * The rule of thumb: if you are writing nonce-management code, stop and check
 * whether Tink already solved the problem you are solving.
 * ---------------------------------------------------------------------------
 */
