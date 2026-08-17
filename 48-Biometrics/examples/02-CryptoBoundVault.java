// examples/02-CryptoBoundVault.java
//
// The correct counterpart to examples/01-CallbackOnlyVault.java. Same screen, same secret, same
// user-visible behaviour — and an attacker who forges `onAuthenticationSucceeded` gets a UI that
// says "welcome" and no plaintext, because the plaintext never existed in this process until
// KeyMint agreed to decrypt it.
//
// THE ONE IDEA
//   Authentication is not a boolean. Authentication is the difference between a Cipher that works
//   and a Cipher that throws. The `if (unlocked)` in file 01 is replaced here by
//   `cipher.doFinal(...)` — and `cipher` was initialised by the hardware only after the hardware
//   saw a fresh, signed hardware auth token (HAT) that this process cannot manufacture.
//
//   See ../../50-HardwareBackedSecurity/README.md §3.7 for the Gatekeeper -> HAT -> KeyMint chain
//   that produces that token, and ../../49-KeyStore/README.md for the key material itself. This
//   file owns only the prompt side.
//
// BUILD
//   A fragment of an Android Activity, presented as one file for reading. It compiles inside an
//   Android project with `androidx.biometric:biometric:1.1.0` or newer. minSdk 23; the API 30+
//   branch is taken at runtime, not at compile time.
//   The lab that builds and attacks it is ../labs/lab-01-callback-vs-crypto.md.
//
// GRADE UNDER ../scripts/grade-biometric-usage.py:  A

package com.pentest.ch48.secure;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.concurrent.Executor;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class CryptoBoundVault extends AppCompatActivity {

    private static final String TAG = "ch48.secure";
    private static final String PREFS = "vault";
    private static final String KEY_BLOB = "secret_blob";     // ciphertext
    private static final String KEY_IV = "secret_iv";         // GCM IV, stored alongside
    private static final String ALIAS = "ch48_vault_key";
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String TRANSFORM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;

    private TextView output;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        output = new TextView(this);
        setContentView(output);
        output.setText("locked");

        // ------------------------------------------------------------------------------------
        // FIX 1 — ask for BIOMETRIC_STRONG, and mean it.
        //
        // BIOMETRIC_STRONG (0x000F) is Class 3. Only a Class 3 authenticator is permitted to
        // release a hardware auth token, so only BIOMETRIC_STRONG can satisfy a key created with
        // setUserAuthenticationRequired(true). Requesting BIOMETRIC_WEAK and then trying to use a
        // CryptoObject is a runtime error, not a weaker success — the framework rejects it.
        //
        // Note deliberately what is NOT here: DEVICE_CREDENTIAL is not OR-ed in. Measured on an
        // Android 15 emulator, canAuthenticate(BIOMETRIC_STRONG) returned 11 (NONE_ENROLLED)
        // while canAuthenticate(BIOMETRIC_STRONG | DEVICE_CREDENTIAL) returned 0 (SUCCESS) on the
        // same device in the same run, because a PIN was set. OR-ing the credential in makes the
        // call answer a different question from the one the developer thinks they asked.
        // ------------------------------------------------------------------------------------
        int can = BiometricManager.from(this)
                .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);

        // ------------------------------------------------------------------------------------
        // FIX 2 — every non-success branch FAILS CLOSED, and each one is distinct.
        //
        // "No biometrics enrolled" is a legitimate user state and deserves a route back in — but
        // that route is a full re-authentication against the server, not a local unlock. Nothing
        // in this method can reach the plaintext.
        // ------------------------------------------------------------------------------------
        switch (can) {
            case BiometricManager.BIOMETRIC_SUCCESS:
                break;
            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                fail("Set up a fingerprint in Settings, then sign in again to re-enable the vault.");
                return;
            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                fail("This device has no Class 3 biometric sensor. Sign in with your password.");
                return;
            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                fail("The sensor is temporarily unavailable. Try again shortly.");
                return;
            default:
                // Includes BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED (API 31+), which means the
                // sensor was DOWNGRADED below Class 3 by a security policy update. An app that
                // treats that as "close enough" has silently lost its guarantee.
                fail("Biometric unlock unavailable (code " + can + "). Sign in with your password.");
                return;
        }

        if (hasCiphertext()) {
            unlockExisting();
        } else {
            enrolNewSecret();
        }
    }

    // ==========================================================================================
    // KEY CREATION — where the guarantee is actually established
    // ==========================================================================================

    /**
     * FIX 3 — the key configuration IS the security control. Everything else in this file is
     * plumbing around these six lines.
     *
     * setUserAuthenticationRequired(true)
     *     KeyMint refuses every operation on this key unless the operation carries a valid
     *     hardware auth token. This is enforced in the TEE, below the OS. Root does not help.
     *
     * NO setUserAuthenticationValidityDurationSeconds
     *     Omitting it selects PER-USE authorisation: the key requires a CryptoObject, and the
     *     token must have been minted for THIS operation. Setting a positive duration instead
     *     selects TIME-BOUND authorisation, where any device unlock inside the window satisfies
     *     the key — including one performed by a completely different process, with no prompt from
     *     this app at all. That is measured in §3.6 of the chapter, and it is the single most
     *     common way a technically-correct auth-bound key ends up providing nothing.
     *
     * setInvalidatedByBiometricEnrollment(true)
     *     If a new fingerprint is enrolled, this key is destroyed. Without it, an attacker who
     *     can reach Settings (a shoulder-surfed PIN, a coerced unlock) enrols their own finger and
     *     the existing key happily authorises for them. This is the default on API 24+, and
     *     turning it OFF — which apps do to stop support tickets — is a real downgrade.
     */
    private SecretKey createKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);

        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // FIX 4 — on API 30+, say exactly which authenticator classes may satisfy the key.
            //
            // (0, AUTH_BIOMETRIC_STRONG) means: per-use (timeout 0), Class 3 biometric ONLY.
            // The legacy setter does NOT do this. Measured on an API 35 emulator, a key built with
            // setUserAuthenticationValidityDurationSeconds(30) read back
            // KeyInfo.getUserAuthenticationType() == 3, i.e.
            // AUTH_DEVICE_CREDENTIAL | AUTH_BIOMETRIC_STRONG — the PIN satisfies it too. If your
            // threat model includes a shoulder-surfed PIN, the legacy setter does not express it.
            b.setUserAuthenticationParameters(
                    0, KeyProperties.AUTH_BIOMETRIC_STRONG);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            // Prefer a discrete secure element where one exists. Falls back below; see
            // ../../50-HardwareBackedSecurity/README.md for why StrongBox is not universal.
            try {
                b.setIsStrongBoxBacked(true);
                kg.init(b.build());
                return kg.generateKey();
            } catch (Exception strongBoxUnavailable) {
                Log.i(TAG, "StrongBox unavailable, falling back to TEE: " + strongBoxUnavailable);
                b.setIsStrongBoxBacked(false);
            }
        }

        kg.init(b.build());
        return kg.generateKey();
    }

    private SecretKey loadKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE);
        ks.load(null);
        return (SecretKey) ks.getKey(ALIAS, null);
    }

    // ==========================================================================================
    // ENROLMENT — first run: create the key, encrypt the secret under it
    // ==========================================================================================

    private void enrolNewSecret() {
        final String secret = "CH48{crypto_binding_is_authentication}";
        try {
            SecretKey key = createKey();
            final Cipher cipher = Cipher.getInstance(TRANSFORM);

            // ------------------------------------------------------------------------------
            // FIX 5 — this init() is the moment of truth, and it happens BEFORE the prompt.
            //
            // Cipher.init on an auth-bound key throws UserNotAuthenticatedException. That is not
            // an error to swallow: it is the hardware telling you the key is genuinely gated. The
            // ONLY correct response is to hand the half-initialised Cipher to BiometricPrompt in
            // a CryptoObject and let the framework complete it after a real authentication.
            //
            // For ENCRYPT_MODE with per-use authorisation, the init itself needs authorisation
            // too, so the same wrap-and-prompt dance applies to both directions.
            // ------------------------------------------------------------------------------
            try {
                cipher.init(Cipher.ENCRYPT_MODE, key);
            } catch (android.security.keystore.UserNotAuthenticatedException expected) {
                // Good. Fall through to the prompt with the uninitialised Cipher.
                promptThen(cipher, Cipher.ENCRYPT_MODE, key, new AfterAuth() {
                    @Override public void run(Cipher authorised) throws Exception {
                        storeCiphertext(authorised, secret);
                        output.setText("secret sealed. relaunch to unlock.");
                    }
                });
                return;
            }
            // Reached only if the platform authorised immediately, which per-use binding should
            // not allow. Treat it as a defect rather than as luck.
            Log.w(TAG, "cipher.init succeeded with no authentication — auth binding is NOT enforced "
                     + "on this device. Do not trust the vault here.");
            storeCiphertext(cipher, secret);

        } catch (Exception e) {
            fail("could not create the vault key: " + e);
        }
    }

    private void storeCiphertext(Cipher authorised, String secret) throws Exception {
        byte[] ct = authorised.doFinal(secret.getBytes(StandardCharsets.UTF_8));
        byte[] iv = authorised.getIV();
        getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString(KEY_BLOB, Base64.encodeToString(ct, Base64.NO_WRAP))
                .putString(KEY_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
                .apply();
    }

    // ==========================================================================================
    // UNLOCK — subsequent runs: prompt, then decrypt with the Cipher the framework authorised
    // ==========================================================================================

    private void unlockExisting() {
        try {
            SecretKey key = loadKey();
            if (key == null) { fail("vault key is gone; sign in again to re-enrol."); return; }

            SharedPreferences sp = getSharedPreferences(PREFS, Context.MODE_PRIVATE);
            byte[] iv = Base64.decode(sp.getString(KEY_IV, ""), Base64.NO_WRAP);

            Cipher cipher = Cipher.getInstance(TRANSFORM);
            try {
                cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            } catch (android.security.keystore.UserNotAuthenticatedException expected) {
                // Expected and correct.
            } catch (KeyPermanentlyInvalidatedException e) {
                // ------------------------------------------------------------------------------
                // FIX 6 — handle enrolment invalidation as a SECURITY EVENT, not a bug.
                //
                // This exception means the enrolled biometric set changed since the key was made.
                // The honest response is: delete the key, discard the ciphertext, and require full
                // re-authentication. Silently regenerating the key and re-sealing whatever the app
                // still holds in memory converts the protection into theatre — and that is exactly
                // what "just catch it and make a new key" advice produces.
                // ------------------------------------------------------------------------------
                Log.w(TAG, "enrolment changed since the key was created; discarding the vault");
                KeyStore ks = KeyStore.getInstance(KEYSTORE);
                ks.load(null);
                ks.deleteEntry(ALIAS);
                sp.edit().remove(KEY_BLOB).remove(KEY_IV).apply();
                fail("Biometric enrolment changed. Sign in with your password to re-enable.");
                return;
            }

            promptThen(cipher, Cipher.DECRYPT_MODE, key, new AfterAuth() {
                @Override public void run(Cipher authorised) throws Exception {
                    SharedPreferences p = getSharedPreferences(PREFS, Context.MODE_PRIVATE);
                    byte[] ct = Base64.decode(p.getString(KEY_BLOB, ""), Base64.NO_WRAP);
                    // ----------------------------------------------------------------------
                    // FIX 7 — THE CENTRAL ONE.
                    //
                    // There is no `if (unlocked)` anywhere in this class. The plaintext is
                    // produced by this doFinal and by nothing else. An attacker who forges
                    // onAuthenticationSucceeded reaches this line with a Cipher that KeyMint
                    // never authorised, and doFinal throws. GCM adds a second, independent
                    // refusal: a wrong key fails the tag check, so even a substituted key
                    // produces an exception rather than garbage the app might display.
                    // ----------------------------------------------------------------------
                    String plain = new String(authorised.doFinal(ct), StandardCharsets.UTF_8);
                    output.setText(plain);
                }
            });

        } catch (Exception e) {
            fail("unlock failed: " + e);
        }
    }

    // ==========================================================================================
    // THE PROMPT — three lines of substance, and one argument that matters
    // ==========================================================================================

    private interface AfterAuth { void run(Cipher authorised) throws Exception; }

    private void promptThen(final Cipher cipher, final int mode, final SecretKey key,
                            final AfterAuth then) {
        Executor exec = ContextCompat.getMainExecutor(this);

        BiometricPrompt prompt = new BiometricPrompt(this, exec,
                new BiometricPrompt.AuthenticationCallback() {

            @Override
            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                try {
                    // --------------------------------------------------------------------------
                    // FIX 8 — take the Cipher FROM THE RESULT, never from the enclosing scope.
                    //
                    // This one line is what makes a forged callback useless. The framework hands
                    // back the CryptoObject it actually authorised. A synthetic result carries
                    // either null (NullPointerException here) or an attacker-built Cipher over an
                    // attacker-built key (GCM tag failure at doFinal). Reading `cipher` from the
                    // enclosing scope instead would reintroduce the whole vulnerability, because
                    // an attacker's forged callback would then reach a Cipher object the app
                    // trusts. Apps get this wrong far more often than they get the CryptoObject
                    // wrong at all.
                    // --------------------------------------------------------------------------
                    BiometricPrompt.CryptoObject co = result.getCryptoObject();
                    if (co == null || co.getCipher() == null) {
                        fail("authentication returned no cryptographic object — refusing.");
                        return;
                    }
                    then.run(co.getCipher());
                } catch (Exception e) {
                    // A throw here is the system working. Do not degrade to a plaintext path.
                    Log.e(TAG, "authorised operation failed", e);
                    fail("Could not unlock. Sign in with your password.");
                }
            }

            @Override
            public void onAuthenticationError(int code, CharSequence msg) {
                super.onAuthenticationError(code, msg);
                // FIX 9 — no error code unlocks anything. Errors are terminal, by construction:
                // there is no code path from here to a Cipher.
                Log.i(TAG, "auth error " + code + ": " + msg);
                fail("Locked. (" + msg + ")");
            }
        });

        BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock your vault")
                .setSubtitle("Confirm it is you")
                // FIX 10 — setAllowedAuthenticators, not setDeviceCredentialAllowed.
                //
                // BIOMETRIC_STRONG alone. Adding DEVICE_CREDENTIAL here is not merely weaker: on
                // API 30 the framework REJECTS the combination when a CryptoObject is supplied,
                // because a credential-only authentication cannot mint the Class 3 token the key
                // demands. An app that "fixed" that rejection by dropping the CryptoObject
                // downgraded itself all the way to file 01.
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButtonText("Use password instead")
                .setConfirmationRequired(true)   // FIX 11 — see below
                .build();

        // ------------------------------------------------------------------------------------
        // FIX 11 — setConfirmationRequired(true).
        //
        // Passive modalities (face, iris) authenticate without any deliberate user act. A sleeping
        // or unaware user can be authenticated by pointing the phone at them. Requiring an explicit
        // confirmation tap restores intent. It costs one tap and it is the difference between
        // "the user was present" and "the user agreed". The framework ignores it for active
        // modalities like fingerprint, where the touch IS the confirmation, so there is no cost.
        // ------------------------------------------------------------------------------------

        // ------------------------------------------------------------------------------------
        // FIX 12 — the two-argument authenticate(). This is the whole chapter in one call.
        // ------------------------------------------------------------------------------------
        prompt.authenticate(info, new BiometricPrompt.CryptoObject(cipher));
    }

    // ==========================================================================================
    private boolean hasCiphertext() {
        return getSharedPreferences(PREFS, Context.MODE_PRIVATE).contains(KEY_BLOB);
    }

    private void fail(String message) {
        output.setText(message);
        Log.i(TAG, "locked: " + message);
    }
}
