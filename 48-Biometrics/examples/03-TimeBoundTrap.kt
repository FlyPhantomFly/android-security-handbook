// examples/03-TimeBoundTrap.kt
//
// The case that passes every checklist and still fails.
//
// This app does what the guidance says. It creates an AndroidKeyStore key. It calls
// setUserAuthenticationRequired(true). It passes a CryptoObject to authenticate(). A static
// scanner grades it as "biometric authentication is bound to a cryptographic operation" and moves
// on. A reviewer reading the diff nods.
//
// And it is bypassable without touching the app at all.
//
// THE DEFECT IS ONE ARGUMENT
//     .setUserAuthenticationValidityDurationSeconds(86400)
//
// That selects TIME-BOUND authorisation. KeyMint will authorise an operation on this key whenever
// the most recent user authentication — ANY user authentication, by ANY process, of the accepted
// authenticator classes — happened within the window. The window here is 24 hours. The user
// unlocked their phone this morning. The key is open.
//
// MEASURED, not argued. On an Android 15 / API 35 emulator, three keys were created in one run,
// identical except for the window, and used with no authentication performed by the probe:
//
//     validity 1s      -> UserNotAuthenticatedException
//     validity 30s     -> UserNotAuthenticatedException
//     validity 86400s  -> OK, encrypted 20 bytes with NO authentication
//
// Then a single `locksettings verify --old 1234` was issued from adb — a credential check by a
// completely unrelated process — and the same three keys were retried:
//
//     validity 1s      -> UserNotAuthenticatedException   (the run took longer than 1 second)
//     validity 30s     -> OK
//     validity 86400s  -> OK
//
// Nothing about the app changed. No prompt was shown. The key opened because someone, somewhere on
// the device, authenticated. That is what "time-bound" means, and it is why this file is graded B
// rather than A by ../scripts/grade-biometric-usage.py.
//
// ============================================================================================
//  DELIBERATELY WEAK. Read it next to examples/02-CryptoBoundVault.java, which fixes it by
//  DELETING one line. DO NOT SHIP. Install only on a device you own.
// ============================================================================================
//
// The lab that reproduces the measurement above is ../labs/lab-02-auth-bound-keys.md.
//
// GRADE UNDER ../scripts/grade-biometric-usage.py:  B

package com.pentest.ch48.timebound

import android.content.Context
import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import android.util.Log
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private const val TAG = "ch48.timebound"
private const val ALIAS = "ch48_timebound_key"
private const val KEYSTORE = "AndroidKeyStore"
private const val TRANSFORM = "AES/GCM/NoPadding"
private const val GCM_TAG_BITS = 128

// The number that ruins everything. A day, chosen because the product manager said users complained
// about "having to scan constantly". Every value above roughly a minute has the same character;
// this one just makes it obvious.
private const val VALIDITY_SECONDS = 86_400

class TimeBoundTrapActivity : AppCompatActivity() {

    private lateinit var output: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        output = TextView(this)
        setContentView(output)

        val can = BiometricManager.from(this)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        if (can != BiometricManager.BIOMETRIC_SUCCESS) {
            output.text = "biometrics unavailable ($can)"
            return
        }

        if (hasCiphertext()) unlock() else seal("CH48{a_day_long_window_is_not_a_gate}")
    }

    // ----------------------------------------------------------------------------------------
    // The key. Everything here is correct except one line.
    // ----------------------------------------------------------------------------------------
    private fun createKey(): SecretKey {
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)          // correct
            .setInvalidatedByBiometricEnrollment(true)    // correct... but see the note below

            // >>> THE DEFECT <<<
            //
            // Deleting this single line converts the key from time-bound to per-use and turns this
            // file into examples/02-CryptoBoundVault.java's key. Nothing else has to change.
            //
            // Two consequences, both measured:
            //
            //  1. The key is satisfied by ANY authentication in the window, from any process. The
            //     app's own prompt becomes decorative in exactly the way this chapter is about —
            //     the CryptoObject is present, so a scanner sees binding, but the binding is to
            //     "someone unlocked this phone today", not to "this user approved this operation".
            //
            //  2. setInvalidatedByBiometricEnrollment(true) above is silently IGNORED. Measured on
            //     API 35: a key created with validity 30s and that flag set to `true` read back
            //     KeyInfo.isInvalidatedByBiometricEnrollment() == false. The builder accepted a
            //     security-relevant flag and discarded it without an error, a warning, or a log
            //     line. An attacker who enrols their own fingerprint keeps this key.
            //
            .setUserAuthenticationValidityDurationSeconds(VALIDITY_SECONDS)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // The modern spelling of the same mistake. setUserAuthenticationParameters(timeout,
            // types) with a non-zero timeout is time-bound too — the API is clearer, not safer.
            //
            // Note what the legacy setter implies about `types` when you do not say: measured on
            // API 35, a key built with setUserAuthenticationValidityDurationSeconds(30) reported
            // KeyInfo.getUserAuthenticationType() == 3, i.e.
            // AUTH_DEVICE_CREDENTIAL or AUTH_BIOMETRIC_STRONG. The device PIN satisfies this
            // "biometric" key. The line below reproduces that default explicitly so the reader can
            // see it rather than inherit it.
            builder.setUserAuthenticationParameters(
                VALIDITY_SECONDS,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            )
        }

        kg.init(builder.build())
        return kg.generateKey()
    }

    private fun loadKey(): SecretKey? {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        return ks.getKey(ALIAS, null) as SecretKey?
    }

    // ----------------------------------------------------------------------------------------
    private fun seal(secret: String) {
        val key = createKey()
        val cipher = Cipher.getInstance(TRANSFORM)
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key)
            // ------------------------------------------------------------------------------
            // AND HERE IS THE TELL.
            //
            // For a per-use key this init ALWAYS throws and the code below is unreachable. For a
            // time-bound key it frequently succeeds — whenever the user unlocked recently — and
            // the app proceeds without ever showing a prompt.
            //
            // Developers read that as "the biometric was already satisfied, nice". It is the
            // opposite: it is the moment the app discovers that its own prompt is optional.
            // If you are auditing and you see a try/catch around Cipher.init where the TRY branch
            // does real work, the key is time-bound. That is a static signature you can grep for.
            // ------------------------------------------------------------------------------
            Log.w(TAG, "cipher.init succeeded with NO prompt — the window is open right now")
            store(cipher, secret)
            output.text = "sealed without ever prompting"
        } catch (expected: UserNotAuthenticatedException) {
            promptThen(cipher) { authorised ->
                store(authorised, secret)
                output.text = "sealed after a prompt"
            }
        }
    }

    private fun unlock() {
        val key = loadKey() ?: run { output.text = "no key"; return }
        val sp = getSharedPreferences("vault", Context.MODE_PRIVATE)
        val iv = Base64.decode(sp.getString("iv", ""), Base64.NO_WRAP)
        val ct = Base64.decode(sp.getString("blob", ""), Base64.NO_WRAP)
        val cipher = Cipher.getInstance(TRANSFORM)
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            // Same tell, in the direction that matters: the secret is decrypted with no prompt,
            // because the user unlocked their phone at some point in the last 24 hours.
            output.text = String(cipher.doFinal(ct))
            Log.w(TAG, "decrypted with NO authentication — time window still open")
        } catch (expected: UserNotAuthenticatedException) {
            promptThen(cipher) { authorised ->
                output.text = String(authorised.doFinal(ct))
            }
        }
    }

    private fun store(c: Cipher, secret: String) {
        val ct = c.doFinal(secret.toByteArray())
        getSharedPreferences("vault", Context.MODE_PRIVATE).edit()
            .putString("blob", Base64.encodeToString(ct, Base64.NO_WRAP))
            .putString("iv", Base64.encodeToString(c.iv, Base64.NO_WRAP))
            .apply()
    }

    private fun hasCiphertext() =
        getSharedPreferences("vault", Context.MODE_PRIVATE).contains("blob")

    private fun promptThen(cipher: Cipher, then: (Cipher) -> Unit) {
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    // Correct in shape — the Cipher comes from the result, not the closure. The
                    // weakness in this file is entirely in the KEY, not in the prompt handling.
                    // That is what makes it instructive: prompt-side review would pass it.
                    val c = result.cryptoObject?.cipher
                    if (c == null) { output.text = "no crypto object"; return }
                    then(c)
                }

                override fun onAuthenticationError(code: Int, msg: CharSequence) {
                    output.text = "error $code: $msg"
                }
            }
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock")
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }
}
