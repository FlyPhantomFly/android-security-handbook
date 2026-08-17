/*
 * ServerVerifiedGate.kt
 * ===========================================================================
 * THE RIGHT WAY -- client half. This is the direct replacement for
 * LocalIntegrityGate.java in this directory. Same product feature, same
 * signals, same user experience on a healthy device; completely different
 * trust structure.
 *
 * READ THE DIFF, NOT THE FILE. Three things changed, and only three:
 *
 *   1. The client no longer *decides*. `LocalIntegrityGate.evaluate()` returned
 *      a Verdict. Nothing here returns a verdict. The client obtains evidence
 *      and forwards it; the server decides and says what the client may do.
 *
 *   2. The nonce comes from the server. A nonce the client invents is a nonce
 *      an attacker can replay a captured token against forever. See
 *      integrity-backend.js and README section 3.6.
 *
 *   3. The protected asset is no longer on the device before authorisation.
 *      LocalIntegrityGate guarded a ciphertext that shipped in the APK
 *      alongside its key. Here the payload is *returned by the server* in the
 *      allow response, so a bypassed client gets an error page instead of a
 *      secret. This is the change that actually matters, and it is the one
 *      that gets left out of "we hardened our integrity checks" work.
 *
 * WHAT THIS FILE DELIBERATELY STILL DOES
 *   It still collects the local platform signals. They are useful -- as
 *   *evidence* attached to the request, contributing to a server-side risk
 *   score, and as support diagnostics. Sending forgeable evidence to a server
 *   that treats it as forgeable evidence is fine. Acting on it locally is not.
 *
 * WHAT IT IS NOT
 *   It is not unbypassable. An attacker still controls this process and can
 *   still make `unlockVault()` return whatever they like. The difference is
 *   that doing so now yields nothing, because the secret was never here. That
 *   is the whole of the argument in chapter 20 section 3.9, expressed as code.
 *
 * PAIRS WITH
 *   examples/integrity-backend.js  -- the server that issues the nonce,
 *                                     verifies the token and holds the asset
 *   scripts/verify-integrity-token.py -- the same check chain as a CLI
 *   labs/lab-04-ctf-the-lying-phone.md -- the lab that derives why
 *
 * REQUIRES
 *   com.google.android.play:integrity:<current>, and a Google Cloud project
 *   number linked to the app in Play Console. On a device without Play
 *   services the token request fails; see `IntegrityUnavailable` below for the
 *   only correct way to handle that.
 * ===========================================================================
 */
package com.archlab.gate

import android.content.Context
import android.os.Build
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.suspendCancellableCoroutine
import java.lang.reflect.Method
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** What the SERVER told us we may do. The client computes none of this. */
sealed class Authorisation {
    /** Server allowed the operation and handed back the payload it protects. */
    data class Allowed(val payload: String) : Authorisation()

    /** Server wants additional proof -- re-auth, biometric, out-of-band. */
    data class StepUp(val challenge: String, val reason: String) : Authorisation()

    /** Server refused. `reason` is for logs; show the user something kind. */
    data class Denied(val reason: String) : Authorisation()

    /** We could not obtain a token at all. NOT the same as "denied", and not
     *  the same as "allowed". See the note on this class below. */
    data class IntegrityUnavailable(val cause: String) : Authorisation()
}

/**
 * Platform signals, collected as evidence and never evaluated here.
 *
 * Note there is no `isTrusted` field and no comparison against an expected
 * value anywhere in this class. That absence is the design.
 */
data class DeviceEvidence(
    val verifiedBootState: String,
    val bootloaderLocked: String,
    val verityMode: String,
    val buildTags: String,
    val debuggable: String,
    val cryptoState: String,
    val securityPatch: String,
    val sdkInt: Int,
    val fingerprint: String
) {
    fun asMap(): Map<String, String> = mapOf(
        "verifiedBootState" to verifiedBootState,
        "bootloaderLocked" to bootloaderLocked,
        "verityMode" to verityMode,
        "buildTags" to buildTags,
        "debuggable" to debuggable,
        "cryptoState" to cryptoState,
        "securityPatch" to securityPatch,
        "sdkInt" to sdkInt.toString(),
        "fingerprint" to fingerprint
    )

    companion object {
        private fun prop(key: String): String = try {
            val cls = Class.forName("android.os.SystemProperties")
            val get: Method = cls.getMethod("get", String::class.java, String::class.java)
            get.invoke(null, key, "") as String
        } catch (t: Throwable) {
            ""
        }

        fun collect(): DeviceEvidence = DeviceEvidence(
            verifiedBootState = prop("ro.boot.verifiedbootstate"),
            bootloaderLocked = prop("ro.boot.flash.locked"),
            verityMode = prop("ro.boot.veritymode"),
            buildTags = Build.TAGS ?: "",
            debuggable = prop("ro.debuggable"),
            cryptoState = prop("ro.crypto.state"),
            securityPatch = Build.VERSION.SECURITY_PATCH ?: "",
            sdkInt = Build.VERSION.SDK_INT,
            fingerprint = Build.FINGERPRINT ?: ""
        )
    }
}

/** The backend contract. Every security decision is behind one of these calls. */
interface GateApi {
    /** Server generates, stores and binds a single-use nonce to this operation. */
    suspend fun requestNonce(sessionId: String, operation: String): String

    /** Server decodes the token, checks the bindings, applies policy, and --
     *  on allow -- returns the protected payload in the same response. */
    suspend fun authorise(
        sessionId: String,
        operation: String,
        token: String,
        evidence: Map<String, String>
    ): Authorisation
}

class ServerVerifiedGate(
    private val context: Context,
    private val cloudProjectNumber: Long,
    private val api: GateApi
) {

    /**
     * The entire client-side flow. Four steps, no branches on device state.
     *
     * Compare with LocalIntegrityGate.evaluate(), which had nine comparisons
     * and a scoring function. All nine comparisons still happen -- on the
     * server, over evidence, where an attacker cannot reach the comparison.
     */
    suspend fun unlockVault(sessionId: String): Authorisation {
        val operation = "vault.unlock"

        // 1. Nonce from the server. Unpredictable, single-use, bound to this
        //    session and this operation. Never `SecureRandom` on the device.
        val nonce = try {
            api.requestNonce(sessionId, operation)
        } catch (t: Throwable) {
            return Authorisation.IntegrityUnavailable("nonce fetch failed: ${t.message}")
        }

        // 2. Token from Play. Opaque to us -- we cannot read it and must not try.
        val token = try {
            requestToken(nonce)
        } catch (t: Throwable) {
            return Authorisation.IntegrityUnavailable("token request failed: ${t.message}")
        }

        // 3. Hand the token and the evidence to the server. No inspection, no
        //    parsing, no local decoding. If you find yourself importing a JWT
        //    library into the app, stop: you are rebuilding the bug.
        return try {
            api.authorise(sessionId, operation, token, DeviceEvidence.collect().asMap())
        } catch (t: Throwable) {
            Authorisation.IntegrityUnavailable("authorise call failed: ${t.message}")
        }

        // 4. There is no step 4. The caller renders whatever the server said.
    }

    private suspend fun requestToken(nonce: String): String =
        suspendCancellableCoroutine { cont ->
            val manager = IntegrityManagerFactory.create(context.applicationContext)
            manager.requestIntegrityToken(
                IntegrityTokenRequest.builder()
                    .setNonce(nonce)
                    .setCloudProjectNumber(cloudProjectNumber)
                    .build()
            )
                .addOnSuccessListener { resp -> cont.resume(resp.token()) }
                .addOnFailureListener { e -> cont.resumeWithException(e) }
        }
}

/*
 * ---------------------------------------------------------------------------
 * THE FAILURE PATH, which is where this design is usually undone
 * ---------------------------------------------------------------------------
 *
 * `IntegrityUnavailable` is returned when the device has no Play services, the
 * network is down, or Play's rate limit is hit. Three ways teams handle it:
 *
 *   (a) Treat it as allow.  Now every attacker turns off the network, or runs
 *       on a device without GMS, and walks straight through. This converts a
 *       sound design back into LocalIntegrityGate with extra steps, and it is
 *       the single most common way a correct integrity design is defeated in
 *       the field. If you test one thing on a client's app, test this.
 *
 *   (b) Treat it as deny.  Correct for high-value operations. Costs you every
 *       user on a GMS-less device, which may be a business decision rather
 *       than yours to make -- but say so explicitly rather than drifting into
 *       (a) by accident.
 *
 *   (c) Treat it as "unknown" and fall back to a different authorisation
 *       route: step-up authentication, a lower transaction limit, an
 *       out-of-band confirmation. This is what mature implementations do, and
 *       it is why `Authorisation` has a `StepUp` case and not just a boolean.
 *
 * Note that (a) is invisible in a code review of the happy path. It lives in a
 * catch block. Chapter 20 section 9.4's Pentester's Note says the same thing
 * about hardware-backed keys: find the catch block; that is where the finding
 * is.
 * ---------------------------------------------------------------------------
 */
