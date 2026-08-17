// 36-CertificatePinning/examples/03-spki-pin-with-backup/SpkiPinner.kt
//
// EXAMPLE 3 of 5 -- ADVANCED.  A correctly implemented SPKI pin with a backup,
// written by hand rather than delegated to a library, so that every decision is
// visible.
//
// WHY WRITE IT BY HAND AT ALL
//   In production you should use okhttp3.CertificatePinner or a <pin-set>.
//   Both are audited, both handle the chain-cleaning subtleties, and neither
//   can be got wrong in the ways below. This file exists because you cannot
//   assess someone else's hand-rolled pin -- and you WILL meet hand-rolled
//   pins, constantly -- unless you know exactly what a correct one looks like.
//
//   Read it as a reference implementation to compare a target against, and as
//   the answer to "the developer says they pin; is what they wrote a pin?"
//
// WHAT MAKES IT CORRECT
//   1. It hashes the SubjectPublicKeyInfo, not the certificate. The pin
//      therefore survives certificate renewal on the same key pair.
//   2. It uses X509TrustManagerExtensions, so the platform performs full chain
//      validation FIRST and hands back the CLEANED chain. Pinning against an
//      unvalidated chain is the classic hand-rolled bug.
//   3. It carries a backup pin for a key that has never been used.
//   4. It compares in constant time, and it fails closed.
//   5. It states, in code, what happens when every pin is wrong.
//
// AUTHORISED TESTING ONLY -- though this half is the remediation, not the attack.

package com.pentest.ch36.spki

import android.net.http.X509TrustManagerExtensions
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

private const val TAG = "ch36-spki"

/**
 * A pin set for one host.
 *
 * @param host        the hostname these pins apply to. Compared exactly; there
 *                    is no wildcard handling here on purpose, because wildcard
 *                    matching is where hand-rolled pinners quietly fail open.
 * @param pins        base64 SHA-256 SPKI digests. ANY match accepts.
 * @param expiresAt   epoch millis after which this pin set stops being
 *                    enforced. See the long comment on [isExpired].
 */
data class PinSet(
    val host: String,
    val pins: Set<String>,
    val expiresAt: Long
) {
    init {
        require(pins.isNotEmpty()) { "a pin set with no pins accepts everything" }
        require(pins.size >= 2) {
            // Enforced as a precondition, not documented as a suggestion.
            // A single-pin set is a single point of failure with no server-side
            // remedy, and making it a hard error at construction time is the
            // only place the mistake can be caught before it ships.
            "a pin set needs a backup pin: ${pins.size} configured for $host"
        }
        pins.forEach {
            require(it.length == 44 && it.endsWith("=")) {
                "not a base64 SHA-256 digest: '$it' (44 chars ending in '='). " +
                "If this is 64 hex characters you have a fingerprint, not a pin."
            }
        }
    }

    /**
     * Pin expiry is a safety valve, not a security feature, and it is worth
     * being explicit about the trade it makes.
     *
     * After the expiry the pin set is IGNORED and the connection falls back to
     * ordinary platform trust validation. That is strictly weaker. It is also
     * the difference between "our app stopped working for everyone and the only
     * fix is a store update" and "our app degraded to normal TLS until we
     * shipped a fix".
     *
     * Android's own <pin-set expiration="..."> behaves exactly this way, which
     * is a strong signal that the platform authors reached the same conclusion.
     * Choose a date that is shorter than your slowest realistic app-update
     * rollout, not longer.
     */
    fun isExpired(now: Long = System.currentTimeMillis()): Boolean = now > expiresAt
}

/**
 * Computes the pin for a certificate.
 *
 * `certificate.publicKey.encoded` returns the DER-encoded SubjectPublicKeyInfo
 * -- the "X.509" encoding, which for a public key means the AlgorithmIdentifier
 * plus the BIT STRING. This is the same byte sequence that
 *
 *     openssl x509 -pubkey -noout | openssl pkey -pubin -outform der
 *
 * produces, which is why ../../scripts/spki-pin.sh and this function agree.
 *
 * NO_WRAP matters: Base64.DEFAULT appends a newline, and a pin with a trailing
 * newline never matches a pin without one. That has cost people entire days.
 */
fun spkiPin(certificate: X509Certificate): String {
    val spki = certificate.publicKey.encoded
    val digest = MessageDigest.getInstance("SHA-256").digest(spki)
    return Base64.encodeToString(digest, Base64.NO_WRAP)
}

/**
 * The pinning trust manager.
 *
 * The order of operations is the whole design, and it is the opposite of what
 * most hand-rolled implementations do:
 *
 *   1. Ask the PLATFORM to validate the chain. If it refuses -- expired,
 *      untrusted root, bad signature, wrong key usage -- we refuse too, and we
 *      never look at the pins. Validation is hard and the platform already
 *      does it correctly; replacing it with a pin check is how you end up
 *      accepting an expired certificate that happens to have a pinned key.
 *
 *   2. Use the CLEANED chain the platform returns. `X509TrustManagerExtensions
 *      .checkServerTrusted` gives back the chain it actually built, which may
 *      differ from what the server sent: reordered, with a cross-signed root
 *      substituted, or with a superfluous certificate dropped. Pinning against
 *      the raw wire chain means an attacker chooses which certificates you
 *      inspect. Pinning against the cleaned chain means the platform does.
 *
 *   3. Only then compare pins, over every certificate in the cleaned chain,
 *      accepting on the first match.
 *
 * Step 2 is the one that is almost always missing in the wild, and it is
 * invisible in testing because a legitimate server sends a clean chain anyway.
 */
class SpkiPinningTrustManager(
    private val pinSets: Map<String, PinSet>,
    private val delegate: X509TrustManager = platformTrustManager(),
    private val onPinFailure: (host: String, presented: List<String>) -> Unit = { _, _ -> }
) : X509TrustManager {

    private val extensions = X509TrustManagerExtensions(delegate)

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        delegate.checkClientTrusted(chain, authType)
    }

    /**
     * The two-argument overload has no hostname, so it cannot know which pin
     * set applies.
     *
     * Delegating to the platform and NOT pinning here is deliberate and it is
     * the honest choice, but it is also a real hole worth understanding: any
     * code path that reaches a trust manager through this overload is
     * unpinned. In practice OkHttp and HttpsURLConnection both use the
     * hostname-aware path on modern Android, so this is rarely reached -- but
     * "rarely" is doing work in that sentence, and an assessment should check
     * rather than assume.
     *
     * The alternative -- throwing here -- breaks legitimate callers. The
     * alternative to THAT is to route everything through the extensions API,
     * which is what OkHttp's own platform integration does.
     */
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        delegate.checkServerTrusted(chain, authType)
        Log.w(TAG, "checkServerTrusted called WITHOUT a hostname: not pinned on this path")
    }

    /**
     * The path that actually pins. OkHttp and the platform call this via
     * X509TrustManagerExtensions when a hostname is known.
     */
    @Throws(CertificateException::class)
    fun checkServerTrusted(
        chain: Array<out X509Certificate>,
        authType: String,
        host: String
    ): List<X509Certificate> {

        // Step 1 and 2: platform validation, cleaned chain back.
        val cleaned: List<X509Certificate> =
            extensions.checkServerTrusted(chain, authType, host)

        val pinSet = pinSets[host]
        if (pinSet == null) {
            // Not pinned. This is an ACCEPT, and it is correct: "no pins for
            // this host" means "not pinned", not "denied". It is also the
            // finding worth writing up -- see README section 5.3. Log it so the
            // gap is visible to the developer rather than only to the tester.
            Log.i(TAG, "no pin set for $host: platform validation only")
            return cleaned
        }

        if (pinSet.isExpired()) {
            Log.w(TAG, "pin set for $host EXPIRED: falling back to platform validation")
            return cleaned
        }

        val presented = cleaned.map { spkiPin(it) }
        for (pin in presented) {
            if (pinSet.pins.any { constantTimeEquals(it, pin) }) {
                Log.i(TAG, "pin matched for $host")
                return cleaned
            }
        }

        // Fail closed. Report before throwing -- a pin failure that nobody
        // learns about is a pin failure you find out about from app reviews.
        onPinFailure(host, presented)
        throw CertificateException(
            "pin mismatch for $host. presented=${presented.joinToString()} " +
            "expected=${pinSet.pins.joinToString()}"
        )
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers

    /**
     * Constant-time string comparison.
     *
     * Honest note on why this is here: a timing side channel on a PUBLIC hash
     * is not a meaningful attack. The pin is not a secret; it is derivable by
     * anyone who can connect to the server. This is included because
     * hand-rolled pinners are frequently criticised for using `==`, and it is
     * worth knowing that the criticism is mostly cargo cult. It costs nothing,
     * so it stays -- but do not report a `String.equals` pin comparison as a
     * timing vulnerability, because it is not one.
     */
    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].code xor b[i].code)
        return diff == 0
    }
}

/** The platform's default X509TrustManager: the system trust store, unmodified. */
fun platformTrustManager(): X509TrustManager {
    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    tmf.init(null as KeyStore?)
    return tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
}

/**
 * Wiring it into an SSLContext.
 *
 * Note that this REPLACES the platform trust manager for this context, which
 * means it also replaces anything declared in network_security_config.xml for
 * these connections. That interaction surprises people: an app can have a
 * perfectly good <pin-set> in XML that never runs, because a custom SSLContext
 * bypassed the platform trust manager that would have enforced it. See
 * README section 3.6 and chapter 44.
 */
fun pinnedSslContext(pinSets: Map<String, PinSet>): SSLContext {
    val tm = SpkiPinningTrustManager(pinSets)
    return SSLContext.getInstance("TLS").apply {
        init(null, arrayOf(tm), null)
    }
}

/** Example configuration. Replace with values from ../../scripts/spki-pin.sh. */
fun exampleConfiguration(): Map<String, PinSet> = mapOf(
    "api.example.com" to PinSet(
        host = "api.example.com",
        pins = setOf(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",   // production key
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="    // offline backup key
        ),
        // Six months. Shorter than any realistic worst-case update rollout.
        expiresAt = System.currentTimeMillis() + 180L * 24 * 60 * 60 * 1000
    )
)
