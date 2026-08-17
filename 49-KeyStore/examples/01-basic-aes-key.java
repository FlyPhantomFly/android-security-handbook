/*
 * 01-basic-aes-key.java — the minimum CORRECT AES-GCM Keystore usage.
 *
 * WHAT IT DOES
 *   Generates a 256-bit AES key inside the Android Keystore if it does not
 *   already exist, encrypts a byte array returning IV||ciphertext, and decrypts
 *   it again. Nothing else. This is the baseline every other example builds on.
 *
 * WHY IT MATTERS
 *   Two reasons.
 *
 *   First, this is the shape you will recommend in remediation text, so you
 *   should be able to write it from memory. A remediation that says "use the
 *   Keystore" without code is advice; a remediation with code is a fix.
 *
 *   Second, compare it line by line with the WRONG version at the bottom of this
 *   file. The broken form is four lines shorter and looks like it does the same
 *   thing, which is exactly why it is the most common real mistake in this area.
 *
 * VERIFICATION
 *   Compiles clean under `javac 24 -Xlint:all` against `android-35`. It did not
 *   before: the StrongBox path called a three-argument
 *   `KeyGenParameterSpec.Builder(spec, alias, purposes)` constructor that does
 *   not exist -- the class has exactly one public constructor, Builder(String,
 *   int) -- and then returned through a `(SecretKey) KeyStore.getInstance(...)
 *   instanceof Object ? reload() : null` expression that would have thrown
 *   ClassCastException had it ever run. Both are gone; newSpecBuilder() now
 *   hands each attempt its own builder, because a Builder is single-use.
 *
 *   Not verified: nothing here has been RUN. Whether a given device actually
 *   provides StrongBox, and what it reports afterwards, is what logActualLevel()
 *   exists to tell you on real hardware.
 *
 * WHAT THIS EXAMPLE DELIBERATELY DOES NOT DO
 *   There is no authentication binding here. That is correct for this example's
 *   stated purpose — a local cache — and WRONG for a session token, a payment
 *   credential, or anything the user would expect a biometric prompt to protect.
 *   For that, see 02-auth-bound-key.java.
 *
 *   Being explicit about the threat model an example addresses is part of the
 *   example. "Use the Keystore" is not a security control on its own; the
 *   configuration is the control.
 *
 * HOW TO RUN
 *   Drop into an Android app (minSdk 23) and call:
 *
 *       byte[] blob = BasicAesKey.encrypt(context, "hello".getBytes("UTF-8"));
 *       byte[] back  = BasicAesKey.decrypt(context, blob);
 *
 *   Then confirm what the DEVICE actually produced, which is a different fact
 *   from what this code requested:
 *
 *       # host
 *       frida -U -n com.example.app -l ../scripts/enumerate-keystore.js
 *       # in the REPL:  ks.one("basic_aes_key_v1")
 *
 * REQUIREMENTS
 *   Android 6.0 (API 23) or later — KeyGenParameterSpec and symmetric Keystore
 *   keys arrived together in Marshmallow. No permissions. No dependencies.
 *
 * See ../README.md sections 3.5 and 9.1.
 */

package com.example.keystorelab;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.security.KeyStore;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

public final class BasicAesKey {

    private static final String TAG = "KEYSTORELAB";

    /** The Keystore provider name. This string is a platform constant; it cannot be obfuscated. */
    private static final String PROVIDER = "AndroidKeyStore";

    /**
     * Versioned alias.
     *
     * Version the alias from day one. When you need to change the key's policy —
     * add authentication binding, move to StrongBox, change the size — you
     * cannot mutate an existing key: the authorization list is baked into the
     * blob at creation and is authenticated. You must create a new key under a
     * new alias, migrate the data, and DELETE the old alias.
     *
     * That final deletion is the step teams forget, which is why a Keystore
     * inventory on a mature app so often shows a dozen orphaned aliases, and why
     * the orphan is usually the weakest key on the device.
     */
    private static final String ALIAS = "basic_aes_key_v1";

    /**
     * AES-GCM. GCM is an AEAD mode: it provides confidentiality AND integrity in
     * one pass, so ciphertext cannot be silently modified. Prefer it to CBC,
     * which needs a separate MAC that developers routinely forget or apply in
     * the wrong order.
     */
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    /** GCM authentication tag length in BITS. 128 is the maximum and the only sensible choice. */
    private static final int TAG_BITS = 128;

    /** GCM's standard nonce length in BYTES. KeyMint generates it; we only need to know its size. */
    private static final int IV_BYTES = 12;

    private BasicAesKey() { }

    // ---------------------------------------------------------------- keys --

    /**
     * Generate the key if it does not exist. Idempotent, so it is safe to call
     * on every use.
     */
    public static SecretKey getOrCreateKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(PROVIDER);
        ks.load(null);                              // AndroidKeyStore takes no password

        if (ks.containsAlias(ALIAS)) {
            return (SecretKey) ks.getKey(ALIAS, null);
        }

        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER);
        //                                                                        ^^^^^^^^
        // The provider argument is what makes this a Keystore key. Omit it and
        // you get a SOFTWARE key whose material lands in this process's heap —
        // which is Finding 2 in section 5.2.

        // Prefer a discrete secure element where one exists — but RECORD which
        // you actually got. Silently downgrading and then claiming StrongBox
        // protection is Finding 8.
        //
        // Note that each attempt needs its OWN builder. KeyGenParameterSpec.Builder
        // has exactly one public constructor, Builder(String alias, int purposes);
        // there is no constructor that takes an already-built spec and no reset()
        // method, so a builder cannot be reused to produce a second, differently
        // configured spec. newSpecBuilder() below exists for that reason.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                kg.init(newSpecBuilder()
                        .setIsStrongBoxBacked(true)
                        .build());
                kg.generateKey();
                logActualLevel();
                return reload();
            } catch (Exception strongBoxUnavailable) {
                // Fall through to the TEE path. This catch is CORRECT
                // engineering; what makes it a finding is failing to record the
                // outcome and then telling a server, or a user, that the key is
                // in StrongBox.
                //
                // The key may have been partially created before the failure, so
                // the TEE path below re-initialises and regenerates under the
                // same alias, which overwrites whatever is there.
                Log.i(TAG, "StrongBox unavailable, falling back to TEE: "
                        + strongBoxUnavailable.getClass().getSimpleName());
            }
        }

        kg.init(newSpecBuilder().build());
        kg.generateKey();
        logActualLevel();
        return reload();
    }

    /**
     * A freshly configured builder carrying every constraint this key needs.
     *
     * Returned rather than stored because a Builder is single-use: see the note
     * in getOrCreateKey().
     */
    private static KeyGenParameterSpec.Builder newSpecBuilder() {
        return new KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)

                // Only GCM. Every mode you do not list is REFUSED by KeyMint, on
                // the far side of the trust boundary — so an attacker with code
                // execution in this process still cannot use this key in ECB.
                // Constraining purposes and modes is genuinely load-bearing, not
                // decoration.
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)

                // TRUE is the default; it is set explicitly here because it is
                // the single most important cryptographic property of this key.
                // It forbids a caller-supplied IV and forces KeyMint to generate
                // a fresh one per operation.
                //
                // Setting it to FALSE lets the caller choose the IV, and a
                // repeated GCM nonce is catastrophic rather than merely weak: it
                // leaks the XOR of two plaintexts and permits forgery of further
                // messages under the same key. That is Finding 7, and it is the
                // mechanism behind published TEE key-recovery research.
                .setRandomizedEncryptionRequired(true);
    }

    private static SecretKey reload() throws Exception {
        KeyStore ks = KeyStore.getInstance(PROVIDER);
        ks.load(null);
        return (SecretKey) ks.getKey(ALIAS, null);
    }

    /**
     * Read back what the device ACTUALLY produced.
     *
     * KeyGenParameterSpec is what you asked for. KeyInfo is what you got. They
     * differ on real hardware more often than anyone expects, and an app that
     * never checks cannot honestly claim hardware backing. Log it in debug
     * builds; report it to your server in production if the server's policy
     * depends on it.
     */
    private static void logActualLevel() {
        try {
            SecretKey key = reload();
            SecretKeyFactory f = SecretKeyFactory.getInstance(key.getAlgorithm(), PROVIDER);
            KeyInfo info = (KeyInfo) f.getKeySpec(key, KeyInfo.class);

            if (Build.VERSION.SDK_INT >= 31) {
                int level = info.getSecurityLevel();
                Log.i(TAG, "securityLevel=" + level
                        + "  (0=SOFTWARE 1=TRUSTED_ENVIRONMENT 2=STRONGBOX)");
                if (level == KeyProperties.SECURITY_LEVEL_SOFTWARE) {
                    Log.w(TAG, "This key is SOFTWARE-backed on this device. Do not claim "
                            + "hardware protection for whatever it protects.");
                }
            } else {
                Log.i(TAG, "isInsideSecureHardware=" + info.isInsideSecureHardware()
                        + "   (a floor, not a grade)");
            }
            Log.i(TAG, "origin=" + info.getOrigin() + "  (0=GENERATED, 2=IMPORTED)");

            // The one-line proof that this is a genuine Keystore key.
            Log.i(TAG, "getEncoded()=" + key.getEncoded() + "   (null is CORRECT)");
        } catch (Exception e) {
            Log.w(TAG, "could not read back KeyInfo", e);
        }
    }

    // ------------------------------------------------------------- crypto --

    /**
     * Encrypt. Returns IV || ciphertext||tag as one array.
     *
     * The IV is NOT a secret and does not need protecting — but it MUST be
     * unique per encryption under the same key, which is exactly what
     * setRandomizedEncryptionRequired(true) guarantees by refusing to let us
     * choose it. Note that we do not pass a GCMParameterSpec on encryption; we
     * read the IV back out of the Cipher afterwards.
     */
    public static byte[] encrypt(Context ctx, byte[] plaintext) throws Exception {
        Cipher c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.ENCRYPT_MODE, getOrCreateKey());

        byte[] iv = c.getIV();                       // generated inside KeyMint
        byte[] ct = c.doFinal(plaintext);

        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return out;
    }

    /** Decrypt a blob produced by {@link #encrypt}. */
    public static byte[] decrypt(Context ctx, byte[] blob) throws Exception {
        if (blob == null || blob.length <= IV_BYTES) {
            throw new IllegalArgumentException("blob too short");
        }
        byte[] iv = new byte[IV_BYTES];
        byte[] ct = new byte[blob.length - IV_BYTES];
        System.arraycopy(blob, 0, iv, 0, IV_BYTES);
        System.arraycopy(blob, IV_BYTES, ct, 0, ct.length);

        Cipher c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.DECRYPT_MODE, getOrCreateKey(), new GCMParameterSpec(TAG_BITS, iv));
        // If the ciphertext or the IV has been tampered with, doFinal throws
        // AEADBadTagException. Do NOT catch that and return null or a default —
        // an integrity failure is a security event, not a missing value.
        return c.doFinal(ct);
    }

    /** Delete the key. Call this on logout, and on every rotation. */
    public static void deleteKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(PROVIDER);
        ks.load(null);
        if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS);
    }
}

/*
 * =====================================================================
 * THE WRONG VERSION — for comparison. Do not ship this.
 * =====================================================================
 *
 * This is Finding 1 from section 5.2, and it is the single most common real
 * mistake in this entire subject area.
 *
 *     public final class BrokenAesKey {
 *
 *         // "It's obfuscated, and ProGuard renames everything anyway."
 *         private static final byte[] KEY = {
 *             (byte) 0x2f, (byte) 0x91, (byte) 0xc4, (byte) 0x0d,
 *             (byte) 0x77, (byte) 0xa3, (byte) 0x18, (byte) 0xbe,
 *             (byte) 0x5c, (byte) 0x02, (byte) 0xe9, (byte) 0x46,
 *             (byte) 0x31, (byte) 0xfa, (byte) 0x8d, (byte) 0x70
 *         };
 *
 *         private static final byte[] IV = new byte[16];   // all zeros
 *
 *         static byte[] encrypt(byte[] pt) throws Exception {
 *             SecretKey k = new SecretKeySpec(KEY, "AES");          // <-- never
 *             Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");//     touches
 *             c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(IV)); //   the
 *             return c.doFinal(pt);                                 //   Keystore
 *         }
 *     }
 *
 * WHY DEVELOPERS WRITE IT
 *   It is shorter, it works on every API level with no version checks, it never
 *   throws KeyPermanentlyInvalidatedException, it needs no migration story, and
 *   it produces the same ciphertext on the server and on the client — which is
 *   often the actual requirement that led them here. It also survives a code
 *   review by anyone who reads "AES-128" and stops.
 *
 * WHY IT IS CATEGORICALLY WORSE THAN ANYTHING ELSE IN THIS CHAPTER
 *   The key is in the APK, and the APK is mode 0644, readable by every app on
 *   every device (see ../../21-App-Sandbox/ section 3.3). So:
 *     - No device access is required. Download the APK, extract the key.
 *     - It works against EVERY installation simultaneously, not one device.
 *     - It cannot be rotated without shipping a new build and migrating data.
 *     - Obfuscation changes the cost of finding it, never the fact that it is
 *       there. And the fixed all-zero IV means identical plaintexts produce
 *       identical ciphertexts, so you often do not even need the key to learn
 *       something.
 *
 * DETECTION — STATIC
 *   # host
 *   jadx -d out target.apk
 *   grep -rn 'SecretKeySpec' out/sources/          # start here, before anything else
 *   grep -rnE 'new byte\[\]\s*\{' out/sources/ | grep -i key
 *   strings work/assets/* work/res/raw/* | grep -iE 'key|secret'
 *
 *   In Smali the fingerprint is unmistakable and survives obfuscation:
 *       new-instance v1, Ljavax/crypto/spec/SecretKeySpec;
 *       invoke-direct {v1, v2, v3}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
 *
 * DETECTION — DYNAMIC
 *   # host
 *   frida -U -f com.target.app -l ../scripts/hook-secretkeyspec.js
 *
 *   That hook catches it even when the key is XOR'd together at runtime,
 *   decrypted from an asset, or built in native code and passed up through JNI —
 *   because every path has to become a byte[] at that constructor.
 *
 * THE FIX
 *   The class above. And if the key genuinely must originate on a server, use
 *   secure key import (KeyStore.WrappedKeyEntry, API 28+) so the plaintext key
 *   material never exists in the app's heap at all.
 *
 * SEVERITY
 *   High, and unusually easy to state precisely: an attacker who obtains the APK
 *   — which requires no device access, no root, no user interaction and no
 *   privilege of any kind — recovers a key that decrypts the protected data for
 *   every installation of the application.
 */
