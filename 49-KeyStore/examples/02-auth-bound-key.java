/*
 * 02-auth-bound-key.java — a key that CANNOT be used without a live user
 *                          authentication, and the CryptoObject pattern that
 *                          makes that true.
 *
 * WHAT IT DOES
 *   Generates an AES-GCM key with per-use authentication binding, then decrypts
 *   with it by:
 *     1. creating a Cipher and initialising it with the key,
 *     2. wrapping that exact Cipher in a BiometricPrompt.CryptoObject,
 *     3. showing the prompt,
 *     4. using the Cipher THE CALLBACK HANDS BACK — not the one we created.
 *
 *   Step 4 is the whole pattern. Everything else is scaffolding.
 *
 * WHY IT MATTERS
 *   This is the difference between a biometric prompt that is a security control
 *   and one that is a picture of a fingerprint.
 *
 *   The WRONG pattern, which is extremely common:
 *
 *       prompt.authenticate(promptInfo);                    // no CryptoObject
 *       // ... in onAuthenticationSucceeded():
 *       String token = decryptTokenWithKeystoreKey();       // unrelated call
 *
 *   Here the prompt's result is a BOOLEAN IN THE APP'S OWN MEMORY, and the key
 *   has no idea any authentication happened. An attacker with code execution in
 *   the process hooks onAuthenticationSucceeded, calls it, and the app decrypts.
 *   The sensor was never involved. This takes about four lines of Frida and it
 *   works every time.
 *
 *   The RIGHT pattern binds the authentication to ONE cryptographic operation.
 *   The hardware issues an authentication token tied to a specific operation
 *   handle, KeyMint refuses to begin() any other operation with that key, and
 *   there is no window in which unrelated code can ride along. Faking the
 *   callback achieves nothing, because the Cipher the callback would have handed
 *   back was never authorised.
 *
 *   THE TIMEOUT IS THE OTHER HALF OF THE STORY
 *     setUserAuthenticationParameters(0, ...)   per-use. The strong form.
 *     setUserAuthenticationParameters(30, ...)  a THIRTY-SECOND FREE WINDOW in
 *                                               which any code in the process
 *                                               can use the key with no prompt,
 *                                               triggered by ANY authentication
 *                                               including an unrelated device
 *                                               unlock.
 *
 *   A tester who reports "the key is auth-bound" without stating the timeout has
 *   reported almost nothing.
 *
 *   See ../README.md sections 3.5.3 and 9.2, ../labs/lab-02-extraction-vs-use.md,
 *   and ../../48-Biometrics/README.md for the prompt-side attack in full.
 *
 * HOW TO RUN
 *   Add to an Android app (minSdk 30 for the modern API; see the note on
 *   setUserAuthenticationValidityDurationSeconds for 23–29) with:
 *
 *       implementation "androidx.biometric:biometric:1.1.0"
 *
 *   Then from a FragmentActivity:
 *
 *       AuthBoundKey.decryptWithBiometric(this, storedBlob, plaintext -> {
 *           // use the plaintext, then forget it
 *       });
 *
 *   Verify the binding is real — this is the test, not the code review:
 *       # host
 *       frida -U -n com.example.app -l ../scripts/hook-cipher-keystore.js
 *       # in the REPL:
 *       cy.decrypt("auth_bound_key_v1", "<ivHex>", "<ctHex>")
 *   A correctly bound key throws UserNotAuthenticatedException there. That
 *   failure is a POSITIVE result for the app and belongs in the report as one.
 *
 * REQUIREMENTS
 *   Android 6.0 (API 23) minimum; API 30+ for setUserAuthenticationParameters.
 *   androidx.biometric for BiometricPrompt. A device with an enrolled biometric
 *   and a secure lock screen — key generation FAILS without one, which is itself
 *   a behaviour your app must handle rather than swallow.
 */

package com.example.keystorelab;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Log;

import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

public final class AuthBoundKey {

    private static final String TAG = "KEYSTORELAB";
    private static final String PROVIDER = "AndroidKeyStore";
    private static final String ALIAS = "auth_bound_key_v1";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int TAG_BITS = 128;
    private static final int IV_BYTES = 12;

    public interface Callback {
        void onPlaintext(byte[] plaintext);
        void onFailure(String reason, boolean keyInvalidated);
    }

    private AuthBoundKey() { }

    // ------------------------------------------------------------ key gen --

    /**
     * Generate an AES key that KeyMint will refuse to use without a fresh,
     * hardware-attested user authentication tied to the specific operation.
     *
     * Throws if there is no secure lock screen or no enrolled biometric. That is
     * correct — there is nothing to bind to. Handle it by telling the user what
     * to set up, not by silently generating an unbound key, which is Finding 4
     * wearing a disguise.
     */
    public static SecretKey createKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(PROVIDER);
        ks.load(null);
        if (ks.containsAlias(ALIAS)) {
            return (SecretKey) ks.getKey(ALIAS, null);
        }

        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER);

        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)

                // ============================================================
                // THE CONTROL
                // ============================================================
                .setUserAuthenticationRequired(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // timeout = 0 means PER-USE binding: the authorisation is tied to
            // one operation handle and expires with it. This is the strong form
            // and it is what makes the CryptoObject below meaningful.
            //
            // AUTH_BIOMETRIC_STRONG only. Adding AUTH_DEVICE_CREDENTIAL would
            // let a shoulder-surfed PIN satisfy the key — sometimes acceptable,
            // but it must be a decision, not a default.
            b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
        } else {
            // API 23-29: the deprecated form. -1 is the per-use equivalent.
            // ANY POSITIVE VALUE HERE IS A TIME WINDOW, and a 30 you copied from
            // a 2017 blog post is a thirty-second free pass for any code in the
            // process. This is Finding 4's most common shape.
            b.setUserAuthenticationValidityDurationSeconds(-1);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            // TRUE is the default; set explicitly because opting OUT is Finding 5.
            //
            // With true, enrolling a new fingerprint or face permanently
            // invalidates this key. That is exactly what you want: it means an
            // attacker who has the device and the PIN cannot enrol their own
            // biometric and inherit the key. The cost is that legitimate users
            // who add a finger must re-authenticate to the server — which is the
            // correct trade, and the reason the platform made it the default.
            b.setInvalidatedByBiometricEnrollment(true);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            // Unusable while the screen is locked, even for background work.
            // Rarely used, genuinely strong, and free.
            b.setUnlockedDeviceRequired(true);
        }

        kg.init(b.build());
        kg.generateKey();
        logBinding();
        return (SecretKey) reload();
    }

    private static SecretKey reload() throws Exception {
        KeyStore ks = KeyStore.getInstance(PROVIDER);
        ks.load(null);
        return (SecretKey) ks.getKey(ALIAS, null);
    }

    /** Read back the binding that was actually applied. Never trust the spec alone. */
    private static void logBinding() {
        try {
            SecretKey k = reload();
            KeyInfo i = (KeyInfo) SecretKeyFactory
                    .getInstance(k.getAlgorithm(), PROVIDER)
                    .getKeySpec(k, KeyInfo.class);
            Log.i(TAG, "isUserAuthenticationRequired = " + i.isUserAuthenticationRequired());
            Log.i(TAG, "authValidityDurationSeconds  = "
                    + i.getUserAuthenticationValidityDurationSeconds()
                    + "   (-1 or 0 = per-use; anything positive is a WINDOW)");
            Log.i(TAG, "invalidatedByBiometricEnrollment = "
                    + i.isInvalidatedByBiometricEnrollment());
            if (Build.VERSION.SDK_INT >= 31) {
                Log.i(TAG, "securityLevel = " + i.getSecurityLevel());
            }
        } catch (Exception e) {
            Log.w(TAG, "could not read back KeyInfo", e);
        }
    }

    // ---------------------------------------------------------- decryption --

    /**
     * THE PATTERN.
     *
     * Note carefully what is NOT here: there is no boolean, no "if
     * (authenticated)", and no decryption anywhere except inside
     * onAuthenticationSucceeded using the Cipher THE RESULT gives back. There is
     * nothing for an attacker to flip.
     */
    public static void decryptWithBiometric(FragmentActivity activity,
                                            byte[] blob,
                                            Callback cb) {
        // 0. Is there anything to authenticate with?
        int can = BiometricManager.from(activity)
                .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);
        if (can != BiometricManager.BIOMETRIC_SUCCESS) {
            cb.onFailure("no strong biometric available (code " + can + ")", false);
            return;
        }

        if (blob == null || blob.length <= IV_BYTES) {
            cb.onFailure("blob too short", false);
            return;
        }

        final byte[] iv = new byte[IV_BYTES];
        final byte[] ct = new byte[blob.length - IV_BYTES];
        System.arraycopy(blob, 0, iv, 0, IV_BYTES);
        System.arraycopy(blob, IV_BYTES, ct, 0, ct.length);

        final Cipher cipher;
        try {
            // 1. Create the Cipher and initialise it with the auth-bound key.
            //    This SUCCEEDS even without authentication — init does not begin
            //    the operation. The refusal comes later, at doFinal.
            cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, createKey(), new GCMParameterSpec(TAG_BITS, iv));
        } catch (KeyPermanentlyInvalidatedException e) {
            // The user enrolled a new biometric, removed the lock screen, or the
            // device was reset. The key is GONE — there is no recovery. Delete
            // the alias, discard the ciphertext, and re-authenticate to the
            // server. Do NOT fall back to an unbound key: that converts a
            // correctly designed control into Finding 4.
            Log.w(TAG, "key permanently invalidated", e);
            try { deleteKey(); } catch (Exception ignored) { }
            cb.onFailure("key invalidated by biometric enrolment or lock-screen change", true);
            return;
        } catch (Exception e) {
            cb.onFailure(e.getClass().getSimpleName() + ": " + e.getMessage(), false);
            return;
        }

        BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock your session")
                .setSubtitle("Authenticate to decrypt your stored credentials")
                .setNegativeButtonText("Cancel")
                // Must match the key's AUTH_BIOMETRIC_STRONG. Adding
                // DEVICE_CREDENTIAL here when the key does not allow it produces
                // a confusing runtime failure.
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setConfirmationRequired(true)
                .build();

        BiometricPrompt prompt = new BiometricPrompt(activity,
                ContextCompat.getMainExecutor(activity),
                new BiometricPrompt.AuthenticationCallback() {

            @Override
            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                try {
                    // ====================================================
                    // 2. USE THE CIPHER FROM THE RESULT. Not `cipher`.
                    //
                    // The Cipher inside result.getCryptoObject() carries the
                    // hardware authorisation for exactly this operation. Using
                    // any other Cipher — including the identical-looking one we
                    // created above — throws UserNotAuthenticatedException.
                    //
                    // This is what makes hooking the callback useless: an
                    // attacker who calls onAuthenticationSucceeded() by hand has
                    // no authorised CryptoObject to pass, and getCryptoObject()
                    // returns null.
                    // ====================================================
                    BiometricPrompt.CryptoObject co = result.getCryptoObject();
                    if (co == null || co.getCipher() == null) {
                        cb.onFailure("no CryptoObject in result — refusing to proceed", false);
                        return;
                    }
                    byte[] pt = co.getCipher().doFinal(ct);
                    cb.onPlaintext(pt);
                    // The caller must zero `pt` when finished. A byte[] can be
                    // overwritten; a String cannot, and is interned besides —
                    // see ../../13-ART/faq.md question 13.
                } catch (Exception e) {
                    Log.e(TAG, "decrypt failed after successful auth", e);
                    cb.onFailure(e.getClass().getSimpleName(), false);
                }
            }

            @Override
            public void onAuthenticationError(int code, CharSequence msg) {
                cb.onFailure("auth error " + code + ": " + msg, false);
            }

            @Override
            public void onAuthenticationFailed() {
                // A single non-matching sample. The prompt stays up; do nothing.
            }
        });

        // 3. Hand the prompt the Cipher. THIS ARGUMENT IS THE ENTIRE CONTROL.
        //    prompt.authenticate(info) — with no second argument — is the
        //    broken form, and it is what you will find in most apps.
        prompt.authenticate(info, new BiometricPrompt.CryptoObject(cipher));
    }

    // ---------------------------------------------------------- encryption --

    /**
     * Encryption also requires authentication, because this key was created with
     * PURPOSE_ENCRYPT and PURPOSE_DECRYPT and the binding applies to both.
     *
     * If your design needs to STORE without a prompt and only prompt to READ —
     * which is a very common and reasonable requirement — use an asymmetric key:
     * an unbound public key for encryption, and an auth-bound private key for
     * decryption. That is the correct shape, and seeing it in a target is a sign
     * of a team that understood the problem.
     */
    public static void encryptWithBiometric(FragmentActivity activity,
                                            byte[] plaintext,
                                            Callback cb) {
        try {
            Cipher c = Cipher.getInstance(TRANSFORMATION);
            c.init(Cipher.ENCRYPT_MODE, createKey());
            final byte[] iv = c.getIV();

            BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Confirm to save")
                    .setNegativeButtonText("Cancel")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .build();

            new BiometricPrompt(activity, ContextCompat.getMainExecutor(activity),
                    new BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult r) {
                    try {
                        byte[] ct = r.getCryptoObject().getCipher().doFinal(plaintext);
                        byte[] out = new byte[iv.length + ct.length];
                        System.arraycopy(iv, 0, out, 0, iv.length);
                        System.arraycopy(ct, 0, out, iv.length, ct.length);
                        cb.onPlaintext(out);       // the caller stores this blob
                    } catch (Exception e) {
                        cb.onFailure(e.getClass().getSimpleName(), false);
                    }
                }
                @Override
                public void onAuthenticationError(int code, CharSequence msg) {
                    cb.onFailure("auth error " + code, false);
                }
            }).authenticate(info, new BiometricPrompt.CryptoObject(c));

        } catch (Exception e) {
            cb.onFailure(e.getClass().getSimpleName() + ": " + e.getMessage(), false);
        }
    }

    public static void deleteKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(PROVIDER);
        ks.load(null);
        if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS);
    }
}

/*
 * =====================================================================
 * THE BROKEN VERSION — Finding 4 and Finding 6, and what to look for
 * =====================================================================
 *
 *     // 1. A key with no binding at all. Note that this is what you get by
 *     //    OMITTING setUserAuthenticationRequired — the default is false, so
 *     //    the bug is an ABSENCE and you cannot grep for it. Hook the Builder
 *     //    instead: ../scripts/hook-keygenparameterspec.js reports options that
 *     //    were never called.
 *     new KeyGenParameterSpec.Builder(alias, PURPOSE_ENCRYPT | PURPOSE_DECRYPT)
 *         .setBlockModes(BLOCK_MODE_GCM)
 *         .setEncryptionPaddings(ENCRYPTION_PADDING_NONE)
 *         .build();
 *
 *     // 2. A prompt with no CryptoObject. The result is a boolean in memory.
 *     prompt.authenticate(promptInfo);
 *
 *     @Override public void onAuthenticationSucceeded(AuthenticationResult r) {
 *         String token = decryptToken();     // unrelated to the prompt entirely
 *         proceed(token);
 *     }
 *
 * WHY DEVELOPERS WRITE IT
 *   Because it works, and because the UX is identical. The user sees a
 *   fingerprint prompt and the app unlocks. Nothing in testing distinguishes it
 *   from the correct version. The CryptoObject overload is also genuinely more
 *   awkward — you must create the Cipher first, handle
 *   KeyPermanentlyInvalidatedException, and restructure the flow so decryption
 *   happens inside the callback.
 *
 * DETECTION — STATIC
 *   # host
 *   grep -rn 'authenticate(' out/sources/ | grep -v CryptoObject
 *   grep -rn 'CryptoObject' out/sources/            # absent = broken
 *   grep -rn 'setUserAuthenticationRequired' out/sources/
 *   grep -rn 'KeyPermanentlyInvalidatedException' out/sources/   # absent is a hint too
 *
 * DETECTION — DYNAMIC, and this is the demonstration that settles arguments
 *   # host
 *   frida -U -n com.target.app -l ../scripts/hook-cipher-keystore.js
 *   # then, with no prompt shown at all:
 *   cy.decrypt("<alias>", "<ivHex>", "<ctHex>")
 *
 *   If that prints the plaintext, the biometric was decorative. If it throws
 *   UserNotAuthenticatedException, the binding is real — report THAT, because a
 *   control that worked is information the client cannot get any other way.
 *
 *   The complementary attack, for the case where the key is genuinely bound but
 *   the app's own logic is not, is to hook the callback:
 *
 *     Java.use('androidx.biometric.BiometricPrompt$AuthenticationCallback')
 *         .onAuthenticationSucceeded.implementation = function (r) { ... };
 *
 *   See ../../48-Biometrics/README.md section 7 for that technique in full.
 *
 * SEVERITY
 *   Medium to High, and the prerequisite must be stated: an attacker with code
 *   execution in the application's process — typically requiring a rooted or
 *   otherwise compromised device — can use the protected key without any user
 *   authentication. Note honestly that an attacker with code execution in the
 *   process could often obtain the same data by other routes; the finding is
 *   strongest when the app presents the biometric prompt to the USER as the
 *   control protecting a specific high-value action.
 */
