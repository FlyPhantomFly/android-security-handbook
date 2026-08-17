// 47-Authentication/examples/05-EnterpriseAuthSession.kt
//
// PURPOSE
//   The enterprise-grade shape: a session that is DEVICE-BOUND, supports SILENT
//   RE-AUTHENTICATION, enforces THREE distinct lifetimes, and requires STEP-UP
//   for sensitive operations - where the step-up produces something the SERVER
//   can verify rather than a boolean the app sets.
//
//   VERIFICATION: compiles clean under kotlinc 1.9.24 against android-35. It did
//   not before this was checked: `Api` was a non-generic sealed interface whose
//   `Ok<T>` member therefore erased its payload, so `refresh()` returned a value
//   the caller could not read and `r.value.accessToken` did not resolve. `Api`
//   now carries its type parameter. Nothing here has been RUN -- EnterpriseApi,
//   DeviceBinding and the biometric surfaces are interfaces you supply.
//
//   This is the reference implementation the rest of the chapter argues towards.
//   It is longer than the others because the properties it provides genuinely
//   require this much machinery; anything shorter is one of the earlier examples
//   with better naming.
//
// THE FOUR PROPERTIES, AND WHY EACH ONE COSTS WHAT IT COSTS
//
//   1. DEVICE BINDING. Each request is signed by a hardware-backed key that
//      cannot leave the device. A stolen credential is useless elsewhere.
//      COST: the server must verify a signature per request, and key loss (app
//      reinstall, device wipe) forces a full re-login.
//
//   2. SILENT RE-AUTH. The app exchanges a long-lived credential for a short
//      one without user interaction. COST: the long-lived credential is now the
//      thing worth stealing, which is what property 1 is for.
//
//   3. THREE LIFETIMES. Idle, absolute, and elevation. COST: users get logged
//      out, and product will push back. Have the numbers ready.
//
//   4. STEP-UP THAT THE SERVER CAN SEE. The local prompt gates a KEY, and the
//      key signs a server challenge. COST: more round trips.
//
// BOUNDARIES - this file deliberately does not reimplement its neighbours
//   49-KeyStore  : key generation, attestation, the extraction-vs-use argument
//   48-Biometrics: the prompt itself, sensor classes, CryptoObject internals
//   46-Tokens    : the token format, DPoP, refresh rotation and reuse detection
//   36-CertPinning: transport trust
//
// MEASURED CONTEXT - AN HONEST LIMIT
//   The device used for this chapter has NO SCREEN LOCK SET (dumpsys
//   lock_settings reports CredentialType: None, SID: 0). A key created with
//   setUserAuthenticationRequired(true) CANNOT BE GENERATED on such a device -
//   there is no Gatekeeper SID to bind to. The step-up path below is therefore
//   derived from the API contracts and AOSP sources, and was NOT executed here.
//   See README section 7.9. `assertStepUpIsPossible()` below exists precisely
//   because this failure is silent-looking and confusing when you meet it.

package com.pentest.ch47.enterprise

import android.app.KeyguardManager
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.util.concurrent.atomic.AtomicReference

private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val BINDING_KEY_ALIAS = "ch47_device_binding_v1"
private const val STEP_UP_KEY_ALIAS = "ch47_step_up_v1"

// ---------------------------------------------------------------------------
// 1. DEVICE BINDING
// ---------------------------------------------------------------------------

class DeviceBinding(private val context: Context) {

    /**
     * Create the per-install binding key.
     *
     * `setAttestationChallenge` is what turns this from "a key on a device" into
     * "a key the SERVER can prove is in real secure hardware". Without it the
     * server has a public key and no reason to believe anything about where the
     * private half lives - a software key pair in app storage would look
     * identical.
     *
     * 50-HardwareBackedSecurity measured why this matters and it is worth
     * restating because it is counter-intuitive: on that chapter's test device,
     * `ro.boot.verifiedbootstate` reported `green` while a TEE-signed attestation
     * from the SAME DEVICE, SECONDS APART, reported verifiedBootState=Unverified
     * and deviceLocked=false. THE PROPERTY LIES; THE HARDWARE DOES NOT. Any
     * integrity signal read from getprop is attacker-controlled data.
     *
     * And the honest counterweight, also measured there: on an emulator every
     * key is SOFTWARE, hardwareEnforced is empty, AND THE ATTESTATION CHAIN
     * STILL VERIFIES PERFECTLY. A valid chain proves the chain, not the
     * hardware. The server must inspect the security level inside it.
     */
    fun createBindingKey(serverChallenge: ByteArray) {
        val spec = KeyGenParameterSpec.Builder(
            BINDING_KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            // The server chooses this. A client-chosen challenge makes the
            // attestation replayable and therefore worthless.
            .setAttestationChallenge(serverChallenge)
            // Deliberately NOT setUserAuthenticationRequired here: the binding
            // key must work for silent re-auth in the background. The step-up
            // key below is the one that requires a user.
            .build()

        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            .apply { initialize(spec) }
            .generateKeyPair()
    }

    /**
     * Sign a canonical representation of the request.
     *
     * WHAT GOES INTO THE SIGNATURE IS THE WHOLE SECURITY ARGUMENT, and getting
     * it wrong is the most common defect in hand-rolled request signing:
     *
     *   - method and path       : or the signature is valid for a different call
     *   - a body hash           : or the body can be swapped
     *   - a timestamp           : or it is replayable forever
     *   - a nonce               : or it is replayable within the clock skew
     *
     * The server must reject a timestamp outside a narrow window AND remember
     * nonces for that window. A timestamp check without nonce tracking allows
     * replay inside the window, which is usually enough.
     *
     * 46-Tokens covers the standardised form of this (DPoP) and should be
     * preferred to anything hand-rolled. This exists to show what the standard
     * is doing, and because you WILL meet hand-rolled versions in the field -
     * 57-Ghidra's reference table points at this chapter for exactly that.
     */
    fun signRequest(method: String, path: String, bodySha256: ByteArray,
                    timestampSeconds: Long, nonce: String): ByteArray {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val key = ks.getKey(BINDING_KEY_ALIAS, null) as PrivateKey

        val canonical = buildString {
            append(method.uppercase()).append('\n')
            append(path).append('\n')
            append(bodySha256.toHexString()).append('\n')
            append(timestampSeconds).append('\n')
            append(nonce)
        }

        return Signature.getInstance("SHA256withECDSA").run {
            initSign(key)
            update(canonical.toByteArray(Charsets.UTF_8))
            sign()
        }
    }

    private fun ByteArray.toHexString(): String =
        joinToString("") { "%02x".format(it) }
}

// ---------------------------------------------------------------------------
// 2 & 3. SILENT RE-AUTH AND THE THREE LIFETIMES
// ---------------------------------------------------------------------------

data class SessionLimits(
    /** Time since last use. Protects an unattended unlocked device. */
    val idleTimeoutSeconds: Long = 15 * 60,
    /** Time since login, regardless of activity. Bounds slow use of a theft. */
    val absoluteLifetimeSeconds: Long = 12 * 60 * 60,
    /** Time since step-up. Bounds use of an elevation the user did not intend. */
    val elevationWindowSeconds: Long = 5 * 60
)

/**
 * Local view of the session.
 *
 * READ THE WARNING. Every field here is a CACHE of a server-side fact. The
 * server enforces all three lifetimes independently. These values exist so the
 * app can prompt at the right moment instead of discovering expiry through a
 * 401 mid-payment - they are a user-experience optimisation and NOTHING ELSE.
 *
 * If you delete every check in this class the app becomes slightly worse to use
 * and NO LESS SECURE. That is the test of whether client-side session state has
 * been implemented correctly, and it is worth applying to any codebase you
 * review: ask what breaks if the client's copy is set to "never expires".
 */
class SessionClock(private val limits: SessionLimits, private val now: () -> Long) {

    private val issuedAt = AtomicReference<Long?>(null)
    private val lastUsed = AtomicReference<Long?>(null)
    private val elevatedAt = AtomicReference<Long?>(null)

    fun onSessionEstablished() {
        val t = now()
        issuedAt.set(t); lastUsed.set(t); elevatedAt.set(null)
    }

    fun onRequest() = lastUsed.set(now())

    fun onStepUpCompleted() = elevatedAt.set(now())

    fun localState(): LocalSessionView {
        val issued = issuedAt.get() ?: return LocalSessionView.Anonymous
        val used = lastUsed.get() ?: issued
        val t = now()
        return when {
            t - issued > limits.absoluteLifetimeSeconds -> LocalSessionView.ExpectExpired
            t - used   > limits.idleTimeoutSeconds      -> LocalSessionView.ExpectIdle
            else -> {
                val e = elevatedAt.get()
                if (e != null && t - e <= limits.elevationWindowSeconds) {
                    LocalSessionView.ExpectElevated
                } else {
                    LocalSessionView.ExpectActive
                }
            }
        }
    }
}

enum class LocalSessionView { Anonymous, ExpectActive, ExpectElevated, ExpectIdle, ExpectExpired }

/**
 * Silent re-authentication.
 *
 * The correct shape has one property that is easy to get wrong: IT MUST BE ABLE
 * TO FAIL. An implementation that treats the mere presence of a local refresh
 * token as proof - because the network was unavailable - has turned the
 * long-lived credential into a client-side gate, which is defect V1 of
 * 01-VulnerableLogin.java wearing better clothes.
 */
class SilentReauth(
    private val api: EnterpriseApi,
    private val store: SecureCredentialStore,
    private val binding: DeviceBinding,
    private val clock: SessionClock
) {

    suspend fun ensureFreshAccessCredential(): ReauthOutcome {
        val refresh = store.readRefreshToken() ?: return ReauthOutcome.NeedFullLogin

        // The refresh call is itself device-bound, so a stolen refresh token
        // cannot be redeemed from anywhere else. This is the property that makes
        // a long-lived refresh token an acceptable design rather than a liability.
        val nonce = api.nonce()
        val signature = binding.signRequest(
            method = "POST", path = "/auth/refresh",
            bodySha256 = sha256(refresh), timestampSeconds = epochSeconds(), nonce = nonce
        )

        return when (val r = api.refresh(refresh, signature, nonce)) {
            is Api.Ok -> {
                // Rotation: the server issued a NEW refresh token and invalidated
                // the old one. If the old one is ever presented again the server
                // must treat that as evidence a copy exists and revoke the whole
                // family. See 46-Tokens section 3.9 - rotation bounds the window,
                // REUSE DETECTION is where the value is.
                store.writeRefreshToken(r.value.newRefreshToken)
                store.writeAccessToken(r.value.accessToken)
                clock.onSessionEstablished()
                ReauthOutcome.Refreshed
            }
            Api.Unauthorized -> {
                // The server said no. Delete the credential and make the user log
                // in. Do NOT retry, and do NOT fall back to a cached state.
                store.clearAll()
                ReauthOutcome.NeedFullLogin
            }
            Api.Offline -> ReauthOutcome.Offline   // read-only degradation, no more
        }
    }
}

sealed interface ReauthOutcome {
    data object Refreshed : ReauthOutcome
    data object NeedFullLogin : ReauthOutcome
    data object Offline : ReauthOutcome
}

// ---------------------------------------------------------------------------
// 4. STEP-UP THE SERVER CAN VERIFY
// ---------------------------------------------------------------------------

class StepUp(private val context: Context, private val api: EnterpriseApi) {

    /**
     * Call this before offering a step-up-protected feature.
     *
     * On a device with no screen lock, `setUserAuthenticationRequired(true)` key
     * generation fails, and the failure is confusing because it appears at
     * generateKeyPair() rather than at build() and does not obviously mention the
     * lock screen. This was measured: the chapter's test device reports
     * CredentialType: None and SID: 0, and cannot host such a key at all.
     *
     * An app that ignores this and lets the user reach the transfer screen will
     * throw at the worst possible moment.
     */
    fun assertStepUpIsPossible(): StepUpAvailability {
        val km = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        return if (!km.isDeviceSecure) {
            StepUpAvailability.NoDeviceCredential
        } else {
            StepUpAvailability.Available
        }
    }

    /**
     * Create the step-up key.
     *
     * The differences from the binding key are the whole point:
     *   setUserAuthenticationRequired(true)  - unusable until a prompt succeeds
     *   setUserAuthenticationParameters(...) - how long one success is good for
     *   setInvalidatedByBiometricEnrollment  - adding a new fingerprint destroys
     *                                          the key, so an attacker who
     *                                          enrols their own finger gets a
     *                                          key that no longer exists
     */
    fun createStepUpKey() {
        val builder = KeyGenParameterSpec.Builder(
            STEP_UP_KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        // API 30+ form. Older devices use setUserAuthenticationValidityDurationSeconds.
        // 49-KeyStore documents the version split; note that chapter also measured
        // setMaxUsageCount throwing NoSuchMethodError on an API 30 device AT ITS OWN
        // DOCUMENTED API LEVEL, so verify anything version-gated on the target.
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                0,   // 0 = every use requires a fresh authentication
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            )
        }

        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            .apply { initialize(builder.build()) }
            .generateKeyPair()
    }

    /**
     * The step-up itself.
     *
     * Compare with the BROKEN version in README section 5.12:
     *
     *     biometricPrompt.authenticate(promptInfo)
     *     // in onAuthenticationSucceeded:
     *     api.transfer(to, amount)          // the server has no idea
     *
     * Both versions prompt. The difference is that here the prompt unlocks a KEY,
     * the key signs a SERVER-ISSUED challenge, and the server verifies the
     * signature. Hooking onAuthenticationSucceeded in this version yields
     * nothing, because the callback is not what authorises the transfer - the
     * signature is, and it cannot be produced without the key, and the key
     * cannot be used without a real authentication.
     *
     * The prompt mechanics (BiometricPrompt, CryptoObject, sensor classes, and
     * how the prompt itself is attacked) belong to 48-Biometrics. This function
     * shows only where it sits in the FLOW.
     */
    suspend fun performStepUp(
        operation: SensitiveOperation,
        prompt: SuspendingBiometricPrompt
    ): StepUpResult {

        val challenge = api.beginStepUp(operation.describe())

        val signature = Signature.getInstance("SHA256withECDSA").apply {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            initSign(ks.getKey(STEP_UP_KEY_ALIAS, null) as PrivateKey)
        }

        val authenticated = prompt.authenticate(signature)
            ?: return StepUpResult.UserCancelled

        // The challenge includes the operation's parameters, so the signature
        // authorises THIS transfer of THIS amount to THIS recipient - not "a
        // transfer". An app that signs an opaque nonce has built a confirmation
        // that can be redirected: the user approves a GBP 5 payment and the
        // client submits GBP 5000. Sign what the user was shown.
        authenticated.update(challenge.signedBytes())
        val sig = authenticated.sign()

        return when (api.completeStepUp(challenge.id, sig)) {
            is Api.Ok -> StepUpResult.Authorised
            else      -> StepUpResult.Rejected
        }
    }
}

enum class StepUpAvailability { Available, NoDeviceCredential }
sealed interface StepUpResult {
    data object Authorised : StepUpResult
    data object Rejected : StepUpResult
    data object UserCancelled : StepUpResult
}

// ---------------------------------------------------------------------------
// Contracts referenced above
// ---------------------------------------------------------------------------

interface SecureCredentialStore {
    fun readRefreshToken(): String?
    fun writeRefreshToken(v: String)
    fun writeAccessToken(v: String)
    fun clearAll()
}

interface SuspendingBiometricPrompt {
    /** Returns the unlocked Signature, or null if the user cancelled. */
    suspend fun authenticate(signature: Signature): Signature?
}

interface SensitiveOperation { fun describe(): Map<String, String> }

interface StepUpChallenge {
    val id: String
    fun signedBytes(): ByteArray
}

/**
 * What a successful refresh returns. BOTH tokens come back, because rotation
 * means the server has just invalidated the refresh token you presented.
 */
data class RefreshedTokens(val accessToken: String, val newRefreshToken: String)

/**
 * Api carries its payload type. It has to: `Ok` is generic, so a bare `Api`
 * return type erases the payload and leaves the caller holding a value it
 * cannot read. The type parameter is `out` so that Unauthorized and Offline,
 * which carry nothing, are usable as any Api<T> via Nothing.
 */
sealed interface Api<out T> {
    data class Ok<out T>(val value: T) : Api<T>
    data object Unauthorized : Api<Nothing>
    data object Offline : Api<Nothing>
}

interface EnterpriseApi {
    suspend fun nonce(): String
    suspend fun refresh(refreshToken: String, signature: ByteArray, nonce: String): Api<RefreshedTokens>
    suspend fun beginStepUp(operation: Map<String, String>): StepUpChallenge
    suspend fun completeStepUp(challengeId: String, signature: ByteArray): Api<Unit>
}

private fun sha256(s: String): ByteArray =
    java.security.MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))

private fun epochSeconds(): Long = System.currentTimeMillis() / 1000

// ===========================================================================
// WHAT AN ATTACKER WITH FULL CODE EXECUTION STILL GETS - stated honestly
// ===========================================================================
//
// This design does NOT make the app unbreakable, and a report that implies it
// does is wrong. With root and Frida on the device, an attacker can:
//
//   * USE the binding key (not extract it) to sign anything, for as long as they
//     have code execution in the process. 49-KeyStore's extraction-versus-use
//     distinction is exactly this.
//   * Read the access token from memory.
//   * Drive the app's own UI.
//
// What they CANNOT do, and this is the whole return on the investment:
//
//   * Move the session to another device. The key does not leave.
//   * Use a stolen refresh token from anywhere else.
//   * Complete a step-up without a real user authentication on THAT device,
//     because the key is auth-bound in hardware.
//   * Keep access after the server revokes, for longer than the access token's
//     lifetime.
//
// That is the correct framing for the report: the design converts "steal a
// credential once" into "maintain code execution on a specific device
// continuously", which is a completely different and far more expensive attack.
