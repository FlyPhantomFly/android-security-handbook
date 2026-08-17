/*
 * 05-secure-token-store.kt — the complete correct pattern, end to end.
 *
 * WHAT IT DOES
 *   Two things most real applications actually need.
 *
 *   PART 1 — SecureTokenStore. Stores an access token and a refresh token with
 *   different protection appropriate to their different values:
 *     - the access token is short-lived, so it is encrypted with an unbound key
 *       and can be read without a prompt;
 *     - the refresh token is the credential that matters, so it is encrypted
 *       with a PER-USE authentication-bound key and cannot be read without a
 *       live biometric authentication.
 *   Both use versioned aliases, StrongBox where available with an HONESTLY
 *   RECORDED fallback, AES-GCM with a KeyMint-generated IV, and — critically —
 *   no plaintext copy anywhere.
 *
 *   PART 2 — RequestSigner. An HMAC key used to sign outgoing requests, with a
 *   rotation scheme that creates sig_key_v{n+1}, migrates, and DELETES
 *   sig_key_v{n}. The deletion is the step teams forget, which is why a Keystore
 *   inventory on a mature app so often shows a dozen orphaned aliases — and the
 *   orphan is usually the weakest key on the device.
 *
 * WHY IT MATTERS
 *   Every individual technique here appears in examples 01 to 03. What this file
 *   adds is the part that is actually hard: the DECISIONS.
 *
 *     - Which secrets get authentication binding, and which do not? Binding
 *       everything produces an app users abandon; binding nothing produces
 *       Finding 4.
 *     - What happens when the key is invalidated mid-session?
 *     - What happens on a device with no secure hardware at all?
 *     - How do you rotate without orphaning?
 *     - Where does the plaintext live, and for how long?
 *
 *   And the discipline that makes the whole thing worth anything:
 *
 *     THERE IS NO SECOND COPY. The single most common way a Keystore
 *     implementation is rendered decorative is that the same value is ALSO
 *     sitting in an unencrypted preference, a log line, an analytics payload, a
 *     WebView cookie store, or a "debug" file on shared storage. That is
 *     Finding 3, it is trivially exploitable, and no amount of hardware crypto
 *     addresses it. Every method below that handles a token is written to make
 *     a second copy hard to create by accident.
 *
 *   See ../README.md sections 9.4 and 9.5, and ../labs/lab-04-ctf-broken-vault.md.
 *
 * HOW TO RUN
 *   Add to an Android app (minSdk 23, targetSdk 34) with:
 *       implementation "androidx.biometric:biometric:1.1.0"
 *
 *   Then:
 *       val store = SecureTokenStore(context)
 *       store.saveAccessToken(accessToken)
 *       val access = store.readAccessToken()                 // no prompt
 *
 *       store.saveRefreshToken(activity, refreshToken) { ok -> ... }
 *       store.readRefreshToken(activity) { result -> ... }   // biometric prompt
 *
 *       val signer = RequestSigner(context)
 *       val mac = signer.sign(requestBytes)
 *       signer.rotate()                                       // creates v+1, deletes v
 *
 *   Verify it from the outside, which is the only verification that counts:
 *       # host
 *       frida -U -n com.example.app -l ../scripts/enumerate-keystore.js
 *       frida -U -n com.example.app -l ../scripts/hook-cipher-keystore.js
 *
 * REQUIREMENTS
 *   Android 6.0 (API 23) minimum. API 30+ for setUserAuthenticationParameters,
 *   API 28+ for StrongBox and setUnlockedDeviceRequired. Every version-gated
 *   call is guarded. A secure lock screen with an enrolled biometric is required
 *   for the refresh-token key; its absence is handled explicitly rather than by
 *   silently generating an unbound key.
 *
 * AUTHORISED TESTING ONLY.
 */

package com.example.keystorelab

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

private const val TAG = "KEYSTORELAB"
private const val PROVIDER = "AndroidKeyStore"
private const val GCM = "AES/GCM/NoPadding"
private const val TAG_BITS = 128
private const val IV_BYTES = 12

/** What security level a key ACTUALLY got. Never assume; always read it back. */
enum class Backing { STRONGBOX, TEE, SOFTWARE, UNKNOWN }

/** Result of an operation that may fail in a security-relevant way. */
sealed class TokenResult {
    data class Success(val value: ByteArray) : TokenResult()
    /** The key is gone forever — biometric enrolled, lock screen removed, factory reset. */
    object KeyInvalidated : TokenResult()
    data class Failure(val reason: String) : TokenResult()
}

// ===========================================================================
// PART 1 — the token store
// ===========================================================================

class SecureTokenStore(private val context: Context) {

    /**
     * Versioned aliases, from day one.
     *
     * A key's authorization list is baked into its blob at creation and is
     * authenticated, so it CANNOT be changed. Adding authentication binding,
     * moving to StrongBox, or changing the key size all require a NEW key under
     * a NEW alias, a migration, and the deletion of the old one.
     *
     * Teams that did not version their aliases end up unable to change anything
     * without a data-loss migration, which is why so many apps are stuck with
     * the key policy they chose in 2019.
     */
    private val accessAlias = "tokenstore_access_v2"
    private val refreshAlias = "tokenstore_refresh_v2"

    /**
     * A prefs file that holds ONLY ciphertext. Nothing readable is ever written
     * here, and nothing from here is ever cached in a field.
     */
    private val prefs: SharedPreferences =
        context.getSharedPreferences("tokenstore_ciphertext_v2", Context.MODE_PRIVATE)

    /** What we actually got, per alias. Reported to the server; never guessed. */
    private val backing = mutableMapOf<String, Backing>()

    // ------------------------------------------------------------ key setup

    /**
     * Create a key, preferring StrongBox, and RECORD WHICH LEVEL WE GOT.
     *
     * The try/catch fallback here is correct engineering. What turns it into
     * Finding 8 is failing to record the outcome and then telling a server — or
     * a user, or a compliance document — that the key is in StrongBox.
     */
    private fun createKey(alias: String, authBound: Boolean): SecretKey {
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        if (ks.containsAlias(alias)) return ks.getKey(alias, null) as SecretKey

        fun spec(strongBox: Boolean): KeyGenParameterSpec =
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            ).apply {
                setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                setKeySize(256)

                // Explicit, though it is the default. A caller-supplied IV that
                // repeats destroys GCM outright — both confidentiality and
                // integrity — so this is the one line to be loudest about.
                setRandomizedEncryptionRequired(true)

                if (authBound) {
                    setUserAuthenticationRequired(true)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        // timeout 0 = PER-USE. Any positive value is a window in
                        // which any code in the process can use the key with no
                        // prompt, triggered by any unrelated device unlock.
                        setUserAuthenticationParameters(
                            0, KeyProperties.AUTH_BIOMETRIC_STRONG
                        )
                    } else {
                        @Suppress("DEPRECATION")
                        setUserAuthenticationValidityDurationSeconds(-1)
                    }
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        // TRUE is the default. Opting out is Finding 5: an
                        // attacker who reaches the settings screen enrols their
                        // own finger and inherits the key.
                        setInvalidatedByBiometricEnrollment(true)
                    }
                }

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    // Unusable while the screen is locked, even in background
                    // work. Free, strong, and rarely used.
                    setUnlockedDeviceRequired(true)
                    if (strongBox) setIsStrongBoxBacked(true)
                }
            }.build()

        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                kg.init(spec(strongBox = true))
                kg.generateKey()
                backing[alias] = readBacking(alias)
                Log.i(TAG, "$alias created, backing=${backing[alias]}")
                return ks.apply { load(null) }.getKey(alias, null) as SecretKey
            } catch (e: StrongBoxUnavailableException) {
                Log.i(TAG, "StrongBox unavailable for $alias; falling back to TEE")
            } catch (e: Exception) {
                Log.i(TAG, "StrongBox attempt failed for $alias: ${e.javaClass.simpleName}")
            }
        }

        kg.init(spec(strongBox = false))
        kg.generateKey()
        backing[alias] = readBacking(alias)
        Log.i(TAG, "$alias created, backing=${backing[alias]}")

        // An honest system reports the level it got. If your server's policy
        // requires hardware backing, THIS is where you refuse to proceed —
        // not after silently storing a credential under a software key.
        if (backing[alias] == Backing.SOFTWARE) {
            Log.w(TAG, "$alias is SOFTWARE-backed on this device. Do not claim " +
                    "hardware protection for what it holds. Report the level to " +
                    "the server and let the SERVER decide the policy.")
        }

        return KeyStore.getInstance(PROVIDER).apply { load(null) }
            .getKey(alias, null) as SecretKey
    }

    /** Read the ACTUAL security level. KeyGenParameterSpec is a request, not a fact. */
    private fun readBacking(alias: String): Backing = runCatching {
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        val key = ks.getKey(alias, null) as SecretKey
        val info = SecretKeyFactory.getInstance(key.algorithm, PROVIDER)
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        if (Build.VERSION.SDK_INT >= 31) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> Backing.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> Backing.TEE
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> Backing.SOFTWARE
                else -> Backing.UNKNOWN
            }
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) Backing.TEE else Backing.SOFTWARE
        }
    }.getOrDefault(Backing.UNKNOWN)

    /** Report this to the server. Never let the CLIENT decide it is good enough. */
    fun securityLevel(alias: String): Backing =
        backing[alias] ?: readBacking(alias).also { backing[alias] = it }

    // ------------------------------------------------ access token (unbound)

    /**
     * The access token is short-lived — minutes — so an unbound key is a
     * defensible choice: prompting on every API call is unusable, and the blast
     * radius of a stolen access token is bounded by its expiry.
     *
     * Write that reasoning down. "No auth binding" is a finding when it is an
     * accident and a design decision when it is documented, and the difference
     * is visible to anyone reviewing the code.
     */
    fun saveAccessToken(token: ByteArray) {
        try {
            val c = Cipher.getInstance(GCM)
            c.init(Cipher.ENCRYPT_MODE, createKey(accessAlias, authBound = false))
            val ct = c.doFinal(token)
            prefs.edit()
                .putString("access_iv", b64(c.iv))
                .putString("access_ct", b64(ct))
                .apply()
        } finally {
            // Overwrite the caller's copy. A ByteArray can be zeroed; a String
            // cannot — it is immutable and often interned, so it may sit in the
            // heap for the process lifetime and turn up in any heap dump.
            token.fill(0)
        }
        // NOTE WHAT IS ABSENT: no prefs.putString("access_token", ...), no
        // Log.d with the value, no field caching it, no analytics event. Every
        // one of those would be Finding 3 and would make all the above pointless.
    }

    fun readAccessToken(): TokenResult {
        val ivB64 = prefs.getString("access_iv", null) ?: return TokenResult.Failure("absent")
        val ctB64 = prefs.getString("access_ct", null) ?: return TokenResult.Failure("absent")
        return try {
            val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
            val key = ks.getKey(accessAlias, null) as? SecretKey
                ?: return TokenResult.Failure("key missing")
            val c = Cipher.getInstance(GCM)
            c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, unb64(ivB64)))
            TokenResult.Success(c.doFinal(unb64(ctB64)))
        } catch (e: KeyPermanentlyInvalidatedException) {
            clearAccess()
            TokenResult.KeyInvalidated
        } catch (e: Exception) {
            // An AEADBadTagException here means the ciphertext was TAMPERED
            // WITH. Do not swallow it and return a default — that converts an
            // integrity failure into a silent success.
            Log.w(TAG, "access token decrypt failed", e)
            TokenResult.Failure(e.javaClass.simpleName)
        }
    }

    // ---------------------------------------- refresh token (per-use bound)

    /**
     * The refresh token is the credential that matters: long-lived, and it mints
     * new access tokens. It gets per-use binding, which means it CANNOT be read
     * without a live biometric authentication tied to that one operation.
     *
     * This is what makes the difference between "we use the Keystore" and a
     * control that actually resists an attacker with code execution in the
     * process — because for THIS key, that attacker gets
     * UserNotAuthenticatedException.
     */
    fun saveRefreshToken(
        activity: FragmentActivity,
        token: ByteArray,
        onDone: (Boolean) -> Unit
    ) {
        if (!biometricAvailable()) {
            // Do NOT silently fall back to an unbound key. That is exactly how a
            // deliberate control degrades into Finding 4 without anyone
            // noticing. Tell the user, or decline to store the refresh token at
            // all and require a full re-login each session.
            Log.w(TAG, "no strong biometric — refusing to store the refresh token " +
                    "under a weaker key")
            token.fill(0)
            onDone(false)
            return
        }

        val cipher = try {
            Cipher.getInstance(GCM).apply {
                init(Cipher.ENCRYPT_MODE, createKey(refreshAlias, authBound = true))
            }
        } catch (e: Exception) {
            token.fill(0); onDone(false); return
        }

        prompt(activity, "Confirm to save your session", cipher) { result ->
            when (result) {
                is TokenResult.Success -> onDone(true)
                else -> onDone(false)
            }
        }.let { /* the prompt drives the rest */ }

        // The actual encryption happens inside the prompt callback, using the
        // Cipher THE RESULT returns. See prompt() below.
        pendingEncrypt = token
    }

    fun readRefreshToken(activity: FragmentActivity, onResult: (TokenResult) -> Unit) {
        val ivB64 = prefs.getString("refresh_iv", null)
        val ctB64 = prefs.getString("refresh_ct", null)
        if (ivB64 == null || ctB64 == null) {
            onResult(TokenResult.Failure("absent")); return
        }

        val cipher = try {
            val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
            val key = ks.getKey(refreshAlias, null) as? SecretKey
                ?: return onResult(TokenResult.Failure("key missing"))
            Cipher.getInstance(GCM).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, unb64(ivB64)))
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            // The user enrolled a new biometric or changed the lock screen.
            // There is no recovery: delete the alias, discard the ciphertext,
            // and require a full re-login. Falling back to an unbound key here
            // would be the single worst thing this class could do.
            clearRefresh()
            onResult(TokenResult.KeyInvalidated); return
        } catch (e: Exception) {
            onResult(TokenResult.Failure(e.javaClass.simpleName)); return
        }

        pendingCiphertext = unb64(ctB64)
        prompt(activity, "Unlock your session", cipher, onResult)
    }

    private var pendingCiphertext: ByteArray? = null
    private var pendingEncrypt: ByteArray? = null

    /**
     * The CryptoObject pattern.
     *
     * The Cipher handed to BiometricPrompt is the one the hardware authorises,
     * and the Cipher inside the RESULT is the one that carries that
     * authorisation. Using any other Cipher — including an identical-looking one
     * created a line earlier — throws UserNotAuthenticatedException.
     *
     * This is what makes hooking onAuthenticationSucceeded useless: an attacker
     * who calls it by hand has no authorised CryptoObject to pass.
     */
    private fun prompt(
        activity: FragmentActivity,
        title: String,
        cipher: Cipher,
        onResult: (TokenResult) -> Unit
    ) {
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setConfirmationRequired(true)
            .build()

        BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {

                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    val authorised = result.cryptoObject?.cipher
                    if (authorised == null) {
                        // Refuse rather than falling back to the unauthorised
                        // Cipher. A null CryptoObject here means something is
                        // wrong; proceeding anyway would silently remove the
                        // binding.
                        onResult(TokenResult.Failure("no CryptoObject in result"))
                        return
                    }
                    try {
                        val enc = pendingEncrypt
                        if (enc != null) {
                            val ct = authorised.doFinal(enc)
                            prefs.edit()
                                .putString("refresh_iv", b64(authorised.iv))
                                .putString("refresh_ct", b64(ct))
                                .apply()
                            enc.fill(0)
                            pendingEncrypt = null
                            onResult(TokenResult.Success(ByteArray(0)))
                        } else {
                            val ct = pendingCiphertext
                                ?: return onResult(TokenResult.Failure("no ciphertext"))
                            pendingCiphertext = null
                            onResult(TokenResult.Success(authorised.doFinal(ct)))
                        }
                    } catch (e: Exception) {
                        onResult(TokenResult.Failure(e.javaClass.simpleName))
                    }
                }

                override fun onAuthenticationError(code: Int, msg: CharSequence) {
                    pendingEncrypt?.fill(0); pendingEncrypt = null
                    pendingCiphertext = null
                    onResult(TokenResult.Failure("auth error $code: $msg"))
                }
            }
        ).authenticate(info, BiometricPrompt.CryptoObject(cipher))
        //                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        //  THIS ARGUMENT IS THE ENTIRE CONTROL. authenticate(info) alone —
        //  which is what most apps do — reduces the prompt to a boolean in
        //  the attacker's own process.
    }

    private fun biometricAvailable(): Boolean =
        BiometricManager.from(context)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS

    // ---------------------------------------------------------------- clear

    /** Logout must destroy the KEYS, not just the ciphertext. */
    fun logout() {
        clearAccess()
        clearRefresh()
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        listOf(accessAlias, refreshAlias).forEach {
            runCatching { if (ks.containsAlias(it)) ks.deleteEntry(it) }
        }
        backing.clear()
    }

    private fun clearAccess() =
        prefs.edit().remove("access_iv").remove("access_ct").apply()

    private fun clearRefresh() =
        prefs.edit().remove("refresh_iv").remove("refresh_ct").apply()

    private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)
    private fun unb64(s: String) = Base64.decode(s, Base64.NO_WRAP)
}

// ===========================================================================
// PART 2 — request signing with rotation
// ===========================================================================

/**
 * An HMAC-SHA256 key that signs outgoing requests, with a rotation scheme.
 *
 * WHY HMAC AND NOT AES: signing a request proves it came from this installation
 * and was not modified in transit, which is a different job from confidentiality.
 * The key never leaves the hardware, so an attacker cannot mint valid signatures
 * offline — though of course they can ask this process to sign, which is the
 * usual extraction-versus-use point.
 *
 * WHY ROTATION MATTERS TO YOU AS A TESTER: the migration is where the mistakes
 * are. Teams create sig_key_v3, migrate, and never delete sig_key_v2 — so the
 * device accumulates keys, and the OLD ones frequently have weaker policy,
 * because the whole reason for rotating was to strengthen it. Run
 * ../scripts/enumerate-keystore.js on any mature app and count the aliases.
 */
class RequestSigner(private val context: Context) {

    private val meta = context.getSharedPreferences("signer_meta", Context.MODE_PRIVATE)

    private fun aliasFor(version: Int) = "sig_key_v$version"

    private fun currentVersion(): Int = meta.getInt("version", 0)

    private fun keyFor(version: Int): SecretKey {
        val alias = aliasFor(version)
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }

        val kg = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_HMAC_SHA256, PROVIDER
        )
        kg.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                // PURPOSE_SIGN only. KeyMint will refuse a decrypt operation with
                // this key at begin(), on the far side of the trust boundary —
                // so an attacker with code execution in this process still
                // cannot repurpose it. Purpose restriction is genuinely
                // load-bearing, not decoration.
                .setDigests(KeyProperties.DIGEST_SHA256)
                .apply {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        setUnlockedDeviceRequired(true)
                    }
                }
                .build()
        )
        kg.generateKey()
        Log.i(TAG, "created $alias")
        return KeyStore.getInstance(PROVIDER).apply { load(null) }
            .getKey(alias, null) as SecretKey
    }

    fun sign(payload: ByteArray): ByteArray {
        val v = currentVersion().let { if (it == 0) 1.also { n -> meta.edit().putInt("version", n).apply() } else it }
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(keyFor(v))
        return mac.doFinal(payload)
    }

    /** The version the server should use to select the verification key. */
    fun keyVersion(): Int = currentVersion()

    /**
     * Rotate: create v+1, publish it, migrate, THEN DELETE v.
     *
     * The deletion is the step that gets skipped. Everything before it feels
     * like progress; deletion feels like risk. So the old key stays, and the
     * next inventory finds it.
     */
    fun rotate(publishNewKeyToServer: (version: Int) -> Boolean) {
        val old = currentVersion()
        val new = old + 1

        keyFor(new)                                   // create

        if (!publishNewKeyToServer(new)) {
            // Registration failed. Roll back by deleting the key we just made,
            // rather than leaving an unused alias behind — which is exactly how
            // orphans accumulate.
            runCatching {
                KeyStore.getInstance(PROVIDER).apply { load(null) }
                    .deleteEntry(aliasFor(new))
            }
            Log.w(TAG, "rotation aborted: server did not accept sig_key_v$new")
            return
        }

        meta.edit().putInt("version", new).apply()    // switch over

        // *** THE STEP EVERYONE FORGETS ***
        if (old > 0) {
            runCatching {
                val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
                if (ks.containsAlias(aliasFor(old))) {
                    ks.deleteEntry(aliasFor(old))
                    Log.i(TAG, "deleted ${aliasFor(old)}")
                }
            }.onFailure { Log.w(TAG, "failed to delete ${aliasFor(old)}", it) }
        }
    }

    /**
     * Housekeeping. Run at startup: delete every sig_key_v* below the current
     * version. If this ever finds anything, a previous rotation left an orphan
     * behind and you should work out why.
     */
    fun reapOrphans() {
        val current = currentVersion()
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        ks.aliases().toList()
            .filter { it.startsWith("sig_key_v") }
            .mapNotNull { a -> a.removePrefix("sig_key_v").toIntOrNull()?.let { a to it } }
            .filter { (_, v) -> v < current }
            .forEach { (alias, _) ->
                runCatching { ks.deleteEntry(alias) }
                Log.w(TAG, "reaped orphaned $alias — a previous rotation did not clean up")
            }
    }
}

/*
 * =====================================================================
 * HOW TO TEST THIS FILE — the checks a reviewer should run
 * =====================================================================
 *
 * 1. INVENTORY. What aliases exist, and what is each one's ACTUAL level?
 *      frida -U -n com.example.app -l ../scripts/enumerate-keystore.js
 *      ks.table()
 *    Expect tokenstore_access_v2 (auth=false) and tokenstore_refresh_v2
 *    (auth=true, timeout 0). Any sig_key_v* below the current version is a
 *    rotation bug.
 *
 * 2. THE CENTRAL DEMONSTRATION. Can the keys be used without the user?
 *      frida -U -n com.example.app -l ../scripts/hook-cipher-keystore.js
 *      cy.decrypt("tokenstore_access_v2", "<iv>", "<ct>")     -> SUCCEEDS
 *      cy.decrypt("tokenstore_refresh_v2", "<iv>", "<ct>")    -> UserNotAuthenticated
 *
 *    Both results belong in the report. The first is the honest limit of an
 *    unbound key and is a documented design decision here. The second is a
 *    control that WORKED, and reporting it is what makes the rest of the report
 *    credible.
 *
 * 3. THE SECOND-COPY HUNT. This is the check that most often finds something.
 *      adb shell run-as com.example.app ls -laR /data/data/com.example.app/
 *      adb logcat -d | grep -iE 'token|bearer|refresh'
 *      adb shell run-as com.example.app sh -c 'cat shared_prefs/[*].xml'
 *      # (drop the brackets when you type it -- they are here only because a
 *      #  bare slash-star would OPEN A NESTED BLOCK COMMENT. Kotlin block
 *      #  comments nest, unlike Java's, so an unbalanced slash-star inside one
 *      #  swallows the rest of the file and the compiler reports the error at
 *      #  EOF, hundreds of lines from the cause.
 *      #  The inner sh -c also matters: the glob must be expanded by the shell
 *      #  run-as starts, not by the device shell before privileges drop.)
 *      # and shared storage, WebView cookies, analytics queues, crash-report
 *      # breadcrumbs, and any "debug" export
 *    Anything readable that matches the token makes everything above decorative.
 *    That is Finding 3.
 *
 * 4. KEY CONFIGURATION AS CREATED.
 *      frida -U -f com.example.app -l ../scripts/hook-keygenparameterspec.js
 *    Confirm setRandomizedEncryptionRequired is not false, the refresh key's
 *    timeout is 0, and setInvalidatedByBiometricEnrollment is not false.
 *
 * 5. THE INVALIDATION PATH. Enrol a new fingerprint, then read the refresh
 *    token. It must return KeyInvalidated and require a full re-login. An app
 *    that silently falls back to an unbound key here has thrown away the whole
 *    design, and this is a genuinely common regression because it only shows up
 *    when a real user adds a finger.
 *
 * 6. LOGOUT. After logout(), confirm both aliases are GONE — not just the
 *    ciphertext:
 *      ks.list()
 */
