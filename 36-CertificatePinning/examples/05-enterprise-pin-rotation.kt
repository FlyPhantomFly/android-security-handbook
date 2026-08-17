// 36-CertificatePinning/examples/05-enterprise-pin-rotation.kt
//
// EXAMPLE 5 of 5 -- ENTERPRISE.  Pinning that can be rotated, monitored, and
// switched off without an app release.
//
// THE PROBLEM THIS SOLVES
//   Every pin in examples 1 to 4 is a constant compiled into the APK. That is
//   fine until the day it is wrong -- and it will be wrong, because it depends
//   on a key whose lifecycle is owned by a different team, on a schedule you do
//   not control, with a renewal process that may replace the key without
//   telling anybody.
//
//   On that day, an app with hard-coded pins cannot reach its own API, and the
//   only fix is a store release that takes hours to build, days to review, and
//   weeks to reach the long tail of users. Users who cannot reach your API
//   sometimes cannot reach your update either.
//
//   Organisations that pin at scale therefore do not ship pins. They ship a
//   pinning ENGINE and deliver the pins.
//
// THE DESIGN, IN ONE PARAGRAPH
//   Pins are fetched from a signed configuration document, cached, and applied.
//   The configuration is signed with a long-lived key held offline -- so the
//   channel that delivers the pins does not have to be pinned itself, avoiding
//   the obvious circularity. A small set of BOOTSTRAP pins is compiled in and
//   used only until the first successful fetch. Every pin failure is reported
//   before it is enforced, so a bad rollout is visible in telemetry before it
//   is visible in the app store reviews. And there is a kill switch.
//
// THE HONEST CAVEAT, STATED UP FRONT
//   This design moves the security of your pinning to the security of the
//   configuration signing key. That is a real trade and it must be a conscious
//   one. If an attacker can sign a configuration, they can install their own
//   pin, and they have defeated pinning entirely without touching a single
//   certificate. The signing key belongs in an HSM with the same care as the
//   TLS key -- arguably more, because it is not rotated by an automated process
//   that would notice.
//
// AUTHORISED TESTING ONLY -- this half is defensive engineering.

package com.pentest.ch36.enterprise

import android.util.Base64
import android.util.Log
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import org.json.JSONObject
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.atomic.AtomicReference

private const val TAG = "ch36-rotation"

// ---------------------------------------------------------------------------
// The delivered document
// ---------------------------------------------------------------------------

/**
 * A pin configuration as delivered, after signature verification.
 *
 * @param version      monotonic. A client MUST refuse a version lower than the
 *                     one it already holds, or an attacker replays an old
 *                     document to reinstate a retired pin. This is the single
 *                     most commonly omitted field in home-grown versions of
 *                     this design.
 * @param notAfter     epoch millis. Past this, the document is stale and the
 *                     client falls back to bootstrap pins, NOT to no pinning.
 * @param enforce      the kill switch. When false, pins are computed and
 *                     REPORTED but not enforced. This is what a staged
 *                     rollout runs in for its first week.
 * @param pinsByHost   host to set of base64 SHA-256 SPKI digests.
 */
data class PinConfig(
    val version: Long,
    val notAfter: Long,
    val enforce: Boolean,
    val pinsByHost: Map<String, Set<String>>
) {
    fun isStale(now: Long = System.currentTimeMillis()) = now > notAfter

    companion object {
        /**
         * Parse and validate. Every check here exists because omitting it
         * produces a config that looks fine and silently disables pinning.
         */
        fun parse(json: String): PinConfig {
            val o = JSONObject(json)
            val version = o.getLong("version")
            val notAfter = o.getLong("notAfter")
            val enforce = o.getBoolean("enforce")

            val hosts = o.getJSONObject("pins")
            val map = mutableMapOf<String, Set<String>>()
            val it = hosts.keys()
            while (it.hasNext()) {
                val host = it.next()
                val arr = hosts.getJSONArray(host)
                val set = mutableSetOf<String>()
                for (i in 0 until arr.length()) set.add(arr.getString(i))

                require(set.size >= 2) {
                    "host $host has ${set.size} pin(s): a delivered config must " +
                    "still carry a backup, because delivery can fail too"
                }
                set.forEach {
                    require(it.length == 44 && it.endsWith("=")) {
                        "not a base64 SHA-256 digest for $host: $it"
                    }
                }
                map[host] = set
            }
            require(map.isNotEmpty()) { "empty pin map: refusing to accept a config that pins nothing" }
            return PinConfig(version, notAfter, enforce, map)
        }
    }
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

/**
 * Verifies the configuration signature.
 *
 * THE CIRCULARITY, AND HOW THIS BREAKS IT
 *   To fetch pins you need a connection. To trust the connection you want
 *   pins. Trying to solve that by pinning the config endpoint just moves the
 *   problem: now THAT pin cannot be rotated.
 *
 *   The way out is to stop caring about the transport. The document is signed
 *   with an offline key whose public half is compiled into the app. The
 *   document can be served over plain HTTP from a CDN an attacker controls and
 *   the design still holds -- they can withhold it or replay an old version
 *   (hence [PinConfig.version]), but they cannot forge one.
 *
 *   This is the same reasoning as code signing, and the same reasoning behind
 *   the update mechanism in chapter 62-Magisk. Sign the artefact, not the pipe.
 *
 * The verification key is a constant here for readability. In production it
 * lives in the APK as a resource and its rotation is handled by shipping a new
 * app version -- which is acceptable precisely because it is not on the
 * critical path for TLS.
 */
object ConfigVerifier {

    /** SPKI DER of the offline signing key, base64. Replace before use. */
    private const val SIGNING_PUBKEY_B64 =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    /**
     * @param document the exact bytes that were signed. Sign and verify the
     *                 BYTES, never a re-serialised object: any JSON library
     *                 that reorders keys or normalises whitespace produces a
     *                 different byte sequence and a signature that fails for
     *                 no visible reason.
     */
    fun verify(document: ByteArray, signature: ByteArray): Boolean {
        return try {
            val spec = X509EncodedKeySpec(Base64.decode(SIGNING_PUBKEY_B64, Base64.DEFAULT))
            val key = KeyFactory.getInstance("EC").generatePublic(spec)
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key)
                update(document)
                verify(signature)
            }
        } catch (e: Exception) {
            // Fail closed, loudly. A configuration that does not verify is
            // discarded; the previous good one stays in force.
            Log.e(TAG, "config signature verification failed: ${e.message}")
            false
        }
    }
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

class RotatablePinning(
    /**
     * Compiled-in pins, used only until the first verified config arrives, and
     * again if the delivered config goes stale.
     *
     * These should be for the LONGEST-LIVED key in the chain -- typically your
     * own private intermediate, or the CA root -- because they must remain
     * valid across the whole support window of any released app version. This
     * is the one place where pinning something other than the leaf is clearly
     * the right call.
     */
    private val bootstrapPins: Map<String, Set<String>>,
    private val telemetry: (event: String, detail: Map<String, String>) -> Unit
) {

    private val current = AtomicReference<PinConfig?>(null)

    /** Apply a freshly fetched document. Returns true if it was accepted. */
    fun applyConfig(document: ByteArray, signature: ByteArray): Boolean {
        if (!ConfigVerifier.verify(document, signature)) {
            telemetry("pinconfig_signature_invalid", emptyMap())
            return false
        }

        val parsed = try {
            PinConfig.parse(String(document, Charsets.UTF_8))
        } catch (e: Exception) {
            telemetry("pinconfig_parse_failed", mapOf("error" to (e.message ?: "?")))
            return false
        }

        val existing = current.get()
        if (existing != null && parsed.version <= existing.version) {
            // Rollback protection. Without this, an attacker who can serve an
            // old document reinstates a pin for a key they have compromised.
            telemetry("pinconfig_rollback_refused",
                      mapOf("have" to existing.version.toString(),
                            "offered" to parsed.version.toString()))
            return false
        }

        current.set(parsed)
        telemetry("pinconfig_applied",
                  mapOf("version" to parsed.version.toString(),
                        "enforce" to parsed.enforce.toString(),
                        "hosts" to parsed.pinsByHost.keys.joinToString(",")))
        return true
    }

    /** The pins in force for a host right now, and whether they are enforced. */
    fun effectivePins(host: String): Pair<Set<String>, Boolean> {
        val cfg = current.get()
        if (cfg == null || cfg.isStale()) {
            if (cfg != null) telemetry("pinconfig_stale", mapOf("version" to cfg.version.toString()))
            // Fall back to bootstrap, still enforcing. Falling back to NO
            // pinning would mean an attacker who can block the config fetch
            // has also disabled pinning, which is a trivially winnable game.
            return Pair(bootstrapPins[host] ?: emptySet(), true)
        }
        return Pair(cfg.pinsByHost[host] ?: emptySet(), cfg.enforce)
    }

    /**
     * Build an OkHttp client for a host.
     *
     * REPORT-ONLY MODE is the feature that makes this whole design safe to
     * operate, and it is what distinguishes an organisation that pins
     * successfully from one that tried once and gave up.
     *
     * When `enforce` is false, the pins are computed and every mismatch is
     * reported, but the connection proceeds. You roll a new pin set out in
     * report-only, watch the mismatch rate, and flip enforcement on only when
     * it is zero across every region, every carrier and every OEM. A pin set
     * that is wrong for 3% of users is invisible in a staging environment and
     * catastrophic in production; report-only is how you find that 3% before
     * they find your support queue.
     */
    fun clientFor(host: String): OkHttpClient {
        val (pins, enforce) = effectivePins(host)

        if (pins.isEmpty()) {
            telemetry("pinning_absent", mapOf("host" to host))
            return OkHttpClient.Builder().build()
        }

        if (!enforce) {
            // Report-only: an interceptor computes the pins for the chain that
            // was actually negotiated and reports, without refusing anything.
            return OkHttpClient.Builder()
                .addNetworkInterceptor { chain ->
                    val peer = chain.connection()?.handshake()?.peerCertificates.orEmpty()
                    val presented = peer.filterIsInstance<X509Certificate>().map(::spkiPin)
                    val matched = presented.any { it in pins }
                    if (!matched) {
                        telemetry("pin_would_have_failed",
                                  mapOf("host" to host,
                                        "presented" to presented.joinToString(),
                                        "expected" to pins.joinToString()))
                        Log.w(TAG, "REPORT-ONLY: pin would have rejected $host")
                    }
                    chain.proceed(chain.request())
                }
                .build()
        }

        val builder = CertificatePinner.Builder()
        pins.forEach { builder.add(host, "sha256/$it") }
        return OkHttpClient.Builder()
            .certificatePinner(builder.build())
            .addNetworkInterceptor { chain ->
                // Enforcing. Success is worth counting too: a sudden drop in
                // successful pinned connections is the earliest signal that a
                // rotation went wrong somewhere you cannot see.
                telemetry("pin_ok", mapOf("host" to host))
                chain.proceed(chain.request())
            }
            .build()
    }
}

/** Same computation as example 3 and as scripts/spki-pin.sh. */
fun spkiPin(certificate: X509Certificate): String =
    Base64.encodeToString(
        MessageDigest.getInstance("SHA-256").digest(certificate.publicKey.encoded),
        Base64.NO_WRAP
    )

// ---------------------------------------------------------------------------
// What this looks like to a pentester
// ---------------------------------------------------------------------------
//
// An app built this way behaves differently from a statically pinned one, in
// ways worth recognising:
//
//   * The pin is NOT in the APK. `pinning-surface.py` finds only the bootstrap
//     pins, and there may be no `sha256/` literal at all if the bootstrap set
//     is stored as raw bytes. Absence of a pin string is not absence of
//     pinning.
//
//   * Pinning behaviour changes between runs, and between users, because the
//     config changed or the rollout is staged. "It worked yesterday" is a real
//     observation, not a mistake -- see faq.md.
//
//   * The config fetch itself is a target. It is usually NOT pinned (by
//     design, per the circularity argument above), so you can intercept it.
//     You cannot forge it, but you can serve an old one, and how the app
//     handles that -- whether it implements the version check above -- is
//     worth testing specifically. Replaying an old config is a legitimate and
//     under-tested attack.
//
//   * The kill switch is the highest-value finding in the whole design. If
//     `enforce` can be flipped by anything other than a signature-verified
//     document -- a plain HTTP response, a shared preference, a debug intent,
//     a remote-config SDK with weaker authentication -- then pinning can be
//     disabled remotely, and the entire control is worth nothing. Look for it.
