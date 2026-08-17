/*
 * CallbackActivity.kt — the return leg of the flow, and the id_token validator.
 *
 * PURPOSE
 *   Shows every check that must happen when the authorisation server's redirect arrives, in the
 *   order it must happen, with the reason each one exists. Most real-world OAuth bugs on Android
 *   are omissions from this file rather than from the request-building half.
 *
 * THE CHECKS, IN ORDER
 *   1. Handle an `error` response — it is a legitimate outcome, not an exception.
 *   2. Require both `code` and `state`.
 *   3. Load the pending request; a callback with no pending request is an injection attempt.
 *   4. Compare `state` in constant time; a mismatch is fatal.
 *   5. Consume the pending record so it cannot be replayed.
 *   6. Exchange the code over the back channel, presenting the verifier.
 *   7. Validate the id_token completely before trusting a single claim in it.
 *
 * Chapter 45 — OAuth 2.0 and OpenID Connect on Android, sections 3.11, 3.12, 9.1
 */

package com.example.oauthdemo

import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.security.interfaces.RSAPublicKey
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.RSAPublicKeySpec
import java.math.BigInteger

class CallbackActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handle(intent?.data)
    }

    /**
     * `singleTask` / `singleTop` activities receive later redirects here rather than in onCreate.
     * Forgetting this override is a real bug: the second login of a session silently does nothing.
     */
    override fun onNewIntent(intent: android.content.Intent?) {
        super.onNewIntent(intent)
        handle(intent?.data)
    }

    private fun handle(data: Uri?) {
        if (data == null) return finishWithError("callback had no data")

        // ---------------------------------------------------------------------------------------
        // 1. An error response is a legitimate outcome. Ignoring it leaves the UI hanging, and
        //    swallowing it hides `access_denied`, `invalid_scope` and `login_required` from the
        //    user and from your own telemetry.
        // ---------------------------------------------------------------------------------------
        data.getQueryParameter("error")?.let { err ->
            val desc = data.getQueryParameter("error_description") ?: ""
            return finishWithError("authorisation server returned $err: $desc")
        }

        // ---------------------------------------------------------------------------------------
        // 2. Both parameters are mandatory. The ABSENCE of state must be fatal — treating a
        //    missing state as "nothing to compare, so pass" is exactly the bug an attacker needs.
        // ---------------------------------------------------------------------------------------
        val code = data.getQueryParameter("code")
            ?: return finishWithError("callback had no code")
        val state = data.getQueryParameter("state")
            ?: return finishWithError("callback had no state — rejecting")

        // ---------------------------------------------------------------------------------------
        // 3. A callback with no pending request in this app is an injected callback. Reject it.
        // ---------------------------------------------------------------------------------------
        val pending = PendingAuth.load(this)
            ?: return finishWithError("callback with no pending authorisation request")

        // ---------------------------------------------------------------------------------------
        // 4. Compare state. Constant-time comparison is used here out of habit rather than
        //    necessity — state is not a MAC — but the habit is what stops you using `==` on a
        //    value where timing does matter.
        //
        //    What this prevents: an attacker completes their OWN authorisation, captures the
        //    resulting code, and induces this app to consume it. Without this check, the user's
        //    app would hold the ATTACKER's tokens, and everything the user then saves would be
        //    written into the attacker's account, where the attacker can read it.
        // ---------------------------------------------------------------------------------------
        if (!MessageDigest.isEqual(state.toByteArray(), pending.state.toByteArray())) {
            PendingAuth.clear(this)
            return finishWithError("state mismatch — possible CSRF / code injection")
        }

        // ---------------------------------------------------------------------------------------
        // 5. Single use. Clear it now, before the network call, so a duplicate callback (a double
        //    tap, a browser retry, an attacker replay) cannot be consumed twice.
        // ---------------------------------------------------------------------------------------
        PendingAuth.clear(this)

        // ---------------------------------------------------------------------------------------
        // 6. Exchange. The verifier travels here, on the back channel, and nowhere else.
        // ---------------------------------------------------------------------------------------
        TokenExchange.exchange(
            code = code,
            codeVerifier = pending.codeVerifier,
            expectedNonce = pending.nonce,
            onSuccess = { tokens -> onLoggedIn(tokens) },
            onError = { msg -> finishWithError(msg) }
        )
    }

    private fun onLoggedIn(tokens: JSONObject) {
        // Where these land matters as much as how they were obtained. Keystore-wrapped storage,
        // not plaintext SharedPreferences. See chapter 46-Tokens.
        TokenStore.persist(this, tokens)
        startActivity(android.content.Intent(this, MainActivity::class.java))
        finish()
    }

    private fun finishWithError(message: String) {
        Log.w("OAuth", message)          // never log the code, the verifier, or any token
        setResult(RESULT_CANCELED)
        finish()
    }
}

// ================================================================================================
// 7. id_token validation — OIDC Core section 3.1.3.7.
//
// Every step below is mandatory. The two that get skipped in production are signature verification
// and the `aud` check, and both are fatal:
//
//   * No signature check: an attacker edits the JSON payload to any identity, base64-encodes it,
//     and becomes that user. A text editor is the entire exploit.
//
//   * No `aud` check: the attacker registers their own trivial app with the same identity provider,
//     gets the victim to sign into it, receives a GENUINELY signed id_token for the victim, and
//     replays it here. Every signature check passes. `aud` is the only claim that names which
//     client the token was minted for, and it is the only thing that catches this.
//
// This implementation is deliberately explicit rather than short, so each check is visible. In
// production use a maintained library (Nimbus JOSE+JWT, or let AppAuth do it).
// ================================================================================================
object IdTokenValidator {

    /** OUR allow-list. The token's own `alg` header is a hint, never an instruction. */
    private val ALLOWED_ALGS = setOf("RS256", "RS384", "RS512", "ES256", "PS256")

    private const val CLOCK_SKEW_SECONDS = 120L

    /** Returns null when the token is valid, or a human-readable reason when it is not. */
    fun validate(idToken: String, expectedNonce: String): String? {

        // --- 1. Structure ---------------------------------------------------------------------
        val parts = idToken.split(".")
        if (parts.size != 3) return "not a three-segment JWT"

        val header = try {
            JSONObject(String(b64url(parts[0]), Charsets.UTF_8))
        } catch (e: Exception) { return "unparseable header" }

        val claims = try {
            JSONObject(String(b64url(parts[1]), Charsets.UTF_8))
        } catch (e: Exception) { return "unparseable payload" }

        // --- 2. Algorithm, from OUR list ------------------------------------------------------
        // Trusting the token to tell you how to verify the token is circular. `alg: none` is the
        // degenerate case; algorithm confusion (RS256 -> HS256) is the interesting one. See
        // chapter 46-Tokens section 3.6.
        val alg = header.optString("alg")
        if (alg !in ALLOWED_ALGS) return "alg '$alg' is not in the allow-list"

        // --- 3 and 4. Key selection and signature verification --------------------------------
        val kid = header.optString("kid").takeIf { it.isNotEmpty() }
        val key = Jwks.publicKeyFor(kid) ?: return "no JWKS key matched kid=$kid"

        val signingInput = "${parts[0]}.${parts[1]}".toByteArray(Charsets.US_ASCII)
        val signature = b64url(parts[2])
        val verifier = Signature.getInstance(
            when {
                alg.startsWith("RS") -> "SHA${alg.substring(2)}withRSA"
                alg.startsWith("PS") -> "SHA${alg.substring(2)}withRSAandMGF1"
                else -> "SHA${alg.substring(2)}withECDSA"
            }
        )
        verifier.initVerify(key)
        verifier.update(signingInput)
        if (!verifier.verify(signature)) return "signature verification failed"

        // --- 5. Issuer ------------------------------------------------------------------------
        // Exact string match against the issuer from the discovery document. Not startsWith,
        // not contains.
        if (claims.optString("iss") != OAuthConfig.ISSUER) {
            return "iss '${claims.optString("iss")}' != '${OAuthConfig.ISSUER}'"
        }

        // --- 6. Audience — THE CHECK THAT GETS SKIPPED ----------------------------------------
        val audiences: List<String> = when (val aud = claims.opt("aud")) {
            is String -> listOf(aud)
            is JSONArray -> (0 until aud.length()).map { aud.getString(it) }
            else -> return "no aud claim"
        }
        if (OAuthConfig.CLIENT_ID !in audiences) {
            return "aud $audiences does not contain our client_id — this token was minted for a " +
                   "different client and must not be accepted"
        }
        // When there are multiple audiences, `azp` must name us specifically.
        if (audiences.size > 1 && claims.optString("azp") != OAuthConfig.CLIENT_ID) {
            return "multiple audiences and azp != our client_id"
        }

        // --- 7 and 8. Time --------------------------------------------------------------------
        val now = System.currentTimeMillis() / 1000
        val exp = claims.optLong("exp", 0)
        if (exp == 0L) return "no exp claim"
        if (now > exp + CLOCK_SKEW_SECONDS) return "token expired at $exp"

        val iat = claims.optLong("iat", 0)
        if (iat == 0L) return "no iat claim"
        if (iat > now + CLOCK_SKEW_SECONDS) return "iat is in the future"

        val nbf = claims.optLong("nbf", 0)
        if (nbf != 0L && now + CLOCK_SKEW_SECONDS < nbf) return "token not yet valid"

        // --- 9. Nonce -------------------------------------------------------------------------
        // The nonce sits INSIDE the signature, so an attacker who rewrites the redirect cannot
        // change it. This is what binds this specific token to this specific request, and it is
        // the difference between nonce and state.
        val nonce = claims.optString("nonce")
        if (nonce.isEmpty()) return "no nonce claim"
        if (!MessageDigest.isEqual(nonce.toByteArray(), expectedNonce.toByteArray())) {
            return "nonce mismatch — this id_token belongs to a different authorisation request"
        }

        // --- 10. Policy -----------------------------------------------------------------------
        // acr / amr / auth_time are where step-up authentication is enforced. If you asked for
        // max_age or acr_values, check them here or the request was decorative.

        // --- 11. Identity ---------------------------------------------------------------------
        // Use `sub`, never `email`. `sub` is the issuer's stable, unique identifier. `email` is
        // mutable, re-assignable and sometimes unverified — linking accounts by email lets an
        // attacker register the victim's address at a sloppy issuer and land in their account.
        if (claims.optString("sub").isEmpty()) return "no sub claim"

        return null      // valid
    }

    private fun b64url(segment: String): ByteArray =
        Base64.decode(segment, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
}

/**
 * Minimal JWKS handling. In production, cache the document, respect its cache headers, refetch on
 * an unknown `kid`, and rate-limit the refetch so an attacker cannot use unknown kids to make you
 * hammer the issuer.
 */
object Jwks {
    private var cache: Map<String, RSAPublicKey> = emptyMap()

    fun publicKeyFor(kid: String?): RSAPublicKey? {
        if (cache.isEmpty()) refresh()
        return if (kid != null) cache[kid] else cache.values.firstOrNull()
    }

    private fun refresh() {
        // Fetch ${OAuthConfig.ISSUER}/.well-known/openid-configuration, read jwks_uri, fetch it
        // over TLS, and build the key map. Omitted here for length; the security-relevant points:
        //   * fetch over TLS and validate the chain — this is the root of all trust in the token
        //   * select by kid; do not try every key until one works
        //   * never accept a key supplied in the token itself (`jwk`, `jku`, `x5u` headers)
    }

    fun rsaKey(nB64: String, eB64: String): RSAPublicKey {
        val n = BigInteger(1, Base64.decode(nB64, Base64.URL_SAFE or Base64.NO_PADDING))
        val e = BigInteger(1, Base64.decode(eB64, Base64.URL_SAFE or Base64.NO_PADDING))
        return KeyFactory.getInstance("RSA")
            .generatePublic(RSAPublicKeySpec(n, e)) as RSAPublicKey
    }
}
