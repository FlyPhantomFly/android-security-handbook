// examples/01-CallbackOnlyVault.java
//
// ============================================================================================
//  DELIBERATELY VULNERABLE. DO NOT SHIP. DO NOT INSTALL ON A DEVICE YOU DO NOT OWN.
// ============================================================================================
//
// This is the single most common biometric implementation in production Android, and it provides
// no security at all against an attacker with code execution in the process.
//
// Read it next to examples/02-CryptoBoundVault.java, which protects the same secret correctly.
// The two files are deliberately the same length and the same shape so the difference is visible
// rather than buried.
//
// WHAT IS WRONG, IN ONE SENTENCE
//   The secret is protected by an `if` statement, and `onAuthenticationSucceeded` is a public Java
//   method that anyone with Frida can call.
//
// BUILD
//   This is a fragment of an Android Activity. It compiles inside an Android project with
//   `androidx.biometric:biometric:1.2.0-alpha05` (or any 1.1+) on the classpath. It is presented as
//   a single file for reading; the labs build it into a real APK.
//   The lab that builds and attacks it is ../labs/lab-01-callback-vs-crypto.md.
//
// GRADE UNDER ../scripts/grade-biometric-usage.py:  D

package com.pentest.ch48.vulnerable;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executor;

public class CallbackOnlyVault extends AppCompatActivity {

    private static final String TAG = "ch48.vulnerable";
    private static final String PREFS = "vault";
    private static final String KEY_SECRET = "secret_blob";

    private TextView output;

    // ------------------------------------------------------------------------------------------
    // MISTAKE 1 — the gate is a field.
    //
    // Every security decision in this class reads this boolean. It lives in the app's own heap, in
    // a process the user (and therefore an attacker with root, an emulator, or a repackaged build)
    // fully controls. `Java.use(...).unlocked.value = true` is a one-line bypass.
    // ------------------------------------------------------------------------------------------
    private boolean unlocked = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        output = new TextView(this);
        setContentView(output);

        seedSecretIfAbsent();
        promptForBiometric();
    }

    // ------------------------------------------------------------------------------------------
    // MISTAKE 2 — the secret is stored in a form that needs no key to read.
    //
    // Base64 is an encoding, not encryption. Anyone who can read the SharedPreferences XML has the
    // secret, and they never have to defeat the prompt at all. This is why the honest severity of
    // a "biometric bypass" here is usually driven by the STORAGE weakness, not the prompt: see
    // ../../33-Storage/README.md.
    // ------------------------------------------------------------------------------------------
    private void seedSecretIfAbsent() {
        SharedPreferences sp = getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        if (!sp.contains(KEY_SECRET)) {
            String secret = "CH48{callback_only_is_not_authentication}";
            sp.edit()
              .putString(KEY_SECRET, Base64.encodeToString(
                      secret.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP))
              .apply();
        }
    }

    private void promptForBiometric() {
        BiometricManager bm = BiometricManager.from(this);

        // --------------------------------------------------------------------------------------
        // MISTAKE 3 — asking for BIOMETRIC_WEAK.
        //
        // BIOMETRIC_WEAK (0x00FF) is a SUPERSET of BIOMETRIC_STRONG (0x000F): it accepts Class 2
        // sensors, which the CDD explicitly permits to have a spoof-acceptance rate up to an order
        // of magnitude worse than Class 3, and which are NOT allowed to release a hardware auth
        // token. A Class 2 authenticator therefore CANNOT unlock a keystore key even if this app
        // wanted it to. Asking for WEAK forecloses the strong design.
        // --------------------------------------------------------------------------------------
        int can = bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK);

        // --------------------------------------------------------------------------------------
        // MISTAKE 4 — treating "cannot authenticate" as "let them in".
        //
        // This fail-open branch is the bug an attacker reaches for FIRST, because it needs no
        // hooking at all. Disabling the sensor, or simply testing on a device with nothing
        // enrolled, walks straight past the gate. Measured on an Android 15 emulator with no
        // enrolment: canAuthenticate(BIOMETRIC_WEAK) returns 11 (ERROR_NONE_ENROLLED).
        // --------------------------------------------------------------------------------------
        if (can != BiometricManager.BIOMETRIC_SUCCESS) {
            Log.w(TAG, "no biometrics available (" + can + ") — unlocking anyway");
            unlocked = true;
            revealSecret();
            return;
        }

        Executor exec = ContextCompat.getMainExecutor(this);

        BiometricPrompt prompt = new BiometricPrompt(this, exec,
                new BiometricPrompt.AuthenticationCallback() {

            @Override
            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);

                // ------------------------------------------------------------------------------
                // MISTAKE 5 — THE CENTRAL ONE.
                //
                // This method is `public void onAuthenticationSucceeded(AuthenticationResult)`.
                // It is a normal Java method on a normal object. Nothing about it is privileged,
                // nothing about it is verified, and the AuthenticationResult it receives is an
                // ordinary object anyone can construct.
                //
                // From Frida:
                //     Java.choose('com.pentest.ch48.vulnerable.CallbackOnlyVault$1', {
                //         onMatch: function (cb) { cb.onAuthenticationSucceeded(null); },
                //         onComplete: function () {}
                //     });
                //
                // The `result` parameter is never read here, so even `null` works. The app has no
                // way to tell this call from a real one, because there is nothing in the call that
                // came from the hardware.
                //
                // Contrast 02-CryptoBoundVault.java, where result.getCryptoObject().getCipher() is
                // the ONLY route to the plaintext, and that Cipher was initialised by KeyMint
                // against a hardware auth token this process cannot forge.
                // ------------------------------------------------------------------------------
                unlocked = true;
                revealSecret();
            }

            @Override
            public void onAuthenticationError(int code, CharSequence msg) {
                super.onAuthenticationError(code, msg);
                Log.e(TAG, "auth error " + code + ": " + msg);

                // --------------------------------------------------------------------------------
                // MISTAKE 6 — a fail-open error path.
                //
                // ERROR_NO_BIOMETRICS / ERROR_HW_NOT_PRESENT reach here. Developers add this branch
                // so support tickets stop, and it converts every error into an unlock. An attacker
                // does not need Frida for this one; they need a spoon and the sensor covered until
                // ERROR_LOCKOUT fires.
                // --------------------------------------------------------------------------------
                if (code == BiometricPrompt.ERROR_NO_BIOMETRICS
                        || code == BiometricPrompt.ERROR_HW_NOT_PRESENT
                        || code == BiometricPrompt.ERROR_LOCKOUT) {
                    Log.w(TAG, "falling back to open");
                    unlocked = true;
                    revealSecret();
                }
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Log.i(TAG, "a finger was presented and rejected");
            }
        });

        BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock your vault")
                .setSubtitle("Confirm it is you")
                .setNegativeButtonText("Cancel")
                .build();

        // ------------------------------------------------------------------------------------------
        // MISTAKE 7 — the one-argument authenticate().
        //
        // There are two overloads:
        //     authenticate(PromptInfo)                     <- this one. No binding. UI only.
        //     authenticate(PromptInfo, CryptoObject)       <- the one that can be real.
        //
        // In a decompiled APK this single missing argument is the whole audit. It is visible in
        // smali as the method descriptor:
        //     ->authenticate(Landroidx/biometric/BiometricPrompt$PromptInfo;)V
        // versus
        //     ->authenticate(Landroidx/biometric/BiometricPrompt$PromptInfo;
        //                    Landroidx/biometric/BiometricPrompt$CryptoObject;)V
        // ------------------------------------------------------------------------------------------
        prompt.authenticate(info);
    }

    // ------------------------------------------------------------------------------------------
    // MISTAKE 8 — the reveal reads a boolean.
    //
    // No cryptography happens anywhere in this class. There is no key, so there is nothing for the
    // hardware to refuse. Whatever an attacker does to `unlocked`, the plaintext is one Base64
    // decode away.
    // ------------------------------------------------------------------------------------------
    private void revealSecret() {
        if (!unlocked) {
            output.setText("locked");
            return;
        }
        SharedPreferences sp = getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String blob = sp.getString(KEY_SECRET, "");
        String plain = new String(Base64.decode(blob, Base64.NO_WRAP), StandardCharsets.UTF_8);
        output.setText(plain);
        Log.i(TAG, "revealed: " + plain);
    }
}
