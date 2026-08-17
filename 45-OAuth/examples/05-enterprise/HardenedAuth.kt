/*
 * HardenedAuth.kt — an enterprise-grade Android OAuth deployment, and the review checklist it
 * implies.
 *
 * PURPOSE
 *   Reviewing a hardened deployment is a CONFORMANCE exercise, not a bug hunt. The value you add is
 *   finding the one row that was assumed rather than implemented — in practice, most often
 *   "logout revokes server-side" or "refresh reuse is detected".
 *
 *   Every control below names, in its comment, WHERE IT IS ENFORCED and HOW YOU VERIFY IT. That
 *   discipline is the point of the file. A control enforced inside a process the attacker owns is
 *   a usability feature, not a security boundary.
 *
 * WHAT MAKES THIS "ENTERPRISE" RATHER THAN MERELY CORRECT
 *   PAR, DPoP with a Keystore-bound key, step-up authentication, managed configuration from MDM,
 *   short token lifetimes with rotating refresh tokens, and real server-side logout.
 *
 * BUILD
 *   implementation("net.openid:appauth:0.11.1")
 *   implementation("androidx.security:security-crypto:1.1.0-alpha06")
 *   implementation("com.nimbusds:nimbus-jose-jwt:9.37")   // DPoP proof construction
 *
 * Chapter 45 — OAuth 2.0 and OpenID Connect on Android, section 9.5
 */

package com.example.enterprise.auth

import android.content.Context
import android.content.RestrictionsManager
import android.net.Uri
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationService
import net.openid.appauth.AuthorizationServiceConfiguration
import net.openid.appauth.ResponseTypeValues
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey

// =================================================================================================
// 1. Configuration comes from managed configuration (MDM), not from constants.
//
//    ENFORCED BY   the device policy controller; the app cannot be pointed at a rogue issuer by
//                  anything short of a device compromise.
//    VERIFY WITH   adb shell dumpsys device_policy | grep -A20 <pkg>
//                  and by confirming the app refuses to start with no managed config in a managed
//                  profile.
// =================================================================================================
class ManagedOAuthConfig(context: Context) {

    private val restrictions =
        (context.getSystemService(Context.RESTRICTIONS_SERVICE) as RestrictionsManager)
            .applicationRestrictions

    val issuer: String = restrictions.getString("oauth_issuer")
        ?: throw IllegalStateException("no managed OAuth issuer — refusing to start")

    val clientId: String = restrictions.getString("oauth_client_id")
        ?: throw IllegalStateException("no managed client_id — refusing to start")

    val tenantId: String? = restrictions.getString("tenant_id")

    /**
     * A VERIFIED App Link. Not a custom scheme.
     *
     * ENFORCED BY  the platform, via /.well-known/assetlinks.json fetched over TLS.
     * VERIFY WITH  adb shell pm get-app-links <pkg>   — must show `verified`, not `legacy_failure`.
     *
     * `android:autoVerify="true"` in the manifest is the app ASKING for verification. It is not
     * verification, and a silent verification failure downgrades the app to disambiguation without
     * anyone noticing.
     */
    val redirectUri: String = "https://login.corp.example.com/android/callback"
}

// =================================================================================================
// 2. The DPoP proof key — the control that makes a stolen token useless.
//
//    A bearer token confers authority on whoever presents it, so its security reduces to keeping a
//    string secret across every system that touches it. DPoP (RFC 9449) binds the token to a key:
//    the client signs a proof over the method, URI and a timestamp for every request, and the
//    authorisation server binds the access token to that key's thumbprint.
//
//    The Android-specific part is why this is worth the complexity: the key is generated INSIDE the
//    Keystore, marked non-exportable, and StrongBox-backed where hardware allows. The private key
//    never enters the app's address space, so an attacker with full code execution on a rooted
//    device can USE it while the device is in their hands but cannot EXFILTRATE it. A stolen
//    DPoP-bound token is useless off-device — a property bearer tokens can never have.
//
//    ENFORCED BY  the TEE / StrongBox for key confidentiality; the authorisation server and the
//                 resource server for the binding check.
//    VERIFY WITH  a `DPoP` header on /token and on API calls; key attestation for the key's
//                 provenance; and by replaying a captured access token from another machine
//                 without the proof — it must fail.
// =================================================================================================
object DpopKey {

    private const val ALIAS = "dpop_signing_key_v1"
    private const val KEYSTORE = "AndroidKeyStore"

    fun ensureExists(context: Context) {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (ks.containsAlias(ALIAS)) return

        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            // The user must authenticate before the key can be used. This is what makes the
            // biometric prompt a real control rather than a UI gate: the SERVER sees a signature
            // that could only be produced after authentication, rather than the app's word for it.
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                60,                                 // seconds the authentication remains valid
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            )
            // Invalidate the key if biometrics are re-enrolled — otherwise an attacker who can add
            // their own fingerprint inherits the key.
            .setInvalidatedByBiometricEnrollment(true)
            // Attestation lets the server verify the key really is hardware-backed on a device with
            // a verified boot state, rather than a software key claiming to be one.
            .setAttestationChallenge(SecureRandom().generateSeed(32))
            .apply {
                // StrongBox is a separate secure element. Not every device has one, so fall back.
                if (android.os.Build.VERSION.SDK_INT >= 28) {
                    try { setIsStrongBoxBacked(true) } catch (e: Exception) { /* no StrongBox */ }
                }
            }
            .build()

        try {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE).run {
                initialize(spec)
                generateKeyPair()
            }
        } catch (e: Exception) {
            // StrongBox unavailable at generation time; retry without it rather than failing.
            Log.i("DPoP", "StrongBox unavailable, using TEE: ${e.message}")
            generateWithoutStrongBox()
        }
    }

    private fun generateWithoutStrongBox() { /* same spec, setIsStrongBoxBacked omitted */ }

    /**
     * Builds a DPoP proof JWT for one request. RFC 9449 section 4.2.
     *
     * The proof covers the HTTP method and URI, so it cannot be replayed against a different
     * endpoint, and carries a `jti` and `iat` so the server can detect replay within a window.
     */
    fun proofFor(method: String, url: String, accessToken: String? = null): String {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val entry = ks.getEntry(ALIAS, null) as KeyStore.PrivateKeyEntry
        val publicKey = entry.certificate.publicKey as ECPublicKey

        val jwk = JSONObject().apply {
            put("kty", "EC"); put("crv", "P-256")
            put("x", b64url(publicKey.w.affineX.toByteArray().takeLast(32).toByteArray()))
            put("y", b64url(publicKey.w.affineY.toByteArray().takeLast(32).toByteArray()))
        }

        val header = JSONObject().apply {
            put("typ", "dpop+jwt"); put("alg", "ES256"); put("jwk", jwk)
        }

        val payload = JSONObject().apply {
            put("jti", b64url(ByteArray(16).also { SecureRandom().nextBytes(it) }))
            put("htm", method)
            put("htu", url.substringBefore('?'))      // no query, per RFC 9449
            put("iat", System.currentTimeMillis() / 1000)
            // When presenting an access token, bind the proof to it as well.
            accessToken?.let {
                put("ath", b64url(MessageDigest.getInstance("SHA-256")
                    .digest(it.toByteArray(Charsets.US_ASCII))))
            }
        }

        val signingInput =
            "${b64url(header.toString().toByteArray())}.${b64url(payload.toString().toByteArray())}"
        val sig = Signature.getInstance("SHA256withECDSA").run {
            initSign(entry.privateKey)                 // requires recent user authentication
            update(signingInput.toByteArray(Charsets.US_ASCII))
            sign()
        }
        return "$signingInput.${b64url(derToJose(sig))}"
    }

    private fun b64url(b: ByteArray) =
        Base64.encodeToString(b, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    /** ECDSA signatures come out of the JCA in DER; JOSE wants raw r||s. */
    private fun derToJose(der: ByteArray): ByteArray { /* omitted for length */ return der }
}

// =================================================================================================
// 3. The authorisation request.
// =================================================================================================
class HardenedAuth(private val context: Context, private val config: ManagedOAuthConfig) {

    private val authService = AuthorizationService(context)

    /**
     * A normal sign-in: least privilege, S256 PKCE, verified App Link redirect, fresh nonce.
     *
     * ENFORCEMENT NOTE — everything in this method is a client-side HINT. The corresponding server
     * enforcement must be verified separately:
     *   * PKCE            -> the token endpoint must reject a missing/incorrect verifier (lab 02)
     *   * scope           -> the AS must refuse to grant more than the client is entitled to
     *   * redirect_uri    -> the AS must exact-match, and the platform must have VERIFIED the link
     *   * prompt/max_age  -> the AS must actually honour them; check auth_time in the id_token
     */
    fun buildRequest(asConfig: AuthorizationServiceConfiguration): AuthorizationRequest =
        AuthorizationRequest.Builder(
            asConfig,
            config.clientId,
            ResponseTypeValues.CODE,
            Uri.parse(config.redirectUri)
        )
            // Least privilege at login. `payments.initiate` is requested later, per operation,
            // by stepUpForPayment() below.
            .setScopes("openid", "profile")
            .setNonce(randomUrlSafe(32))
            .setCodeVerifier(randomUrlSafe(64))          // AppAuth computes the S256 challenge
            // No silent SSO for a banking session — force a fresh authentication.
            .setPrompt(AuthorizationRequest.Prompt.LOGIN)
            .setAdditionalParameters(
                mapOf(
                    // Require a given assurance level from the identity provider.
                    "acr_values" to "urn:mace:incommon:iap:silver",
                    // Re-authenticate if the IdP session is older than five minutes.
                    "max_age" to "300"
                ) + (config.tenantId?.let { mapOf("tenant" to it) } ?: emptyMap())
            )
            .build()

    /**
     * Step-up authentication for a sensitive operation.
     *
     * The critical framing: BIOMETRICS ARE A LOCAL GATE, NOT AN AUTHENTICATION FACTOR TO THE SERVER.
     * An architecture where the app decides locally that biometrics succeeded and then uses a stored
     * token has a client-side authorisation check, bypassed with a one-line Frida hook. What makes
     * step-up real is that the SERVER issues a new, narrowly-scoped token only after a fresh
     * authorisation with a higher `acr`, and that the DPoP key required an authenticated unlock.
     *
     * ENFORCED BY  the authorisation server (acr/max_age) and the resource server (scope check).
     * VERIFY WITH  a proxy: initiating a transfer must produce a SECOND /authorize round trip, and
     *              the resulting token must carry the elevated scope and a fresh auth_time.
     */
    fun stepUpForPayment(asConfig: AuthorizationServiceConfiguration): AuthorizationRequest =
        AuthorizationRequest.Builder(
            asConfig, config.clientId, ResponseTypeValues.CODE, Uri.parse(config.redirectUri)
        )
            .setScopes("openid", "payments.initiate")
            .setNonce(randomUrlSafe(32))
            .setCodeVerifier(randomUrlSafe(64))
            .setPrompt(AuthorizationRequest.Prompt.LOGIN)
            .setAdditionalParameters(
                mapOf(
                    "acr_values" to "urn:mace:incommon:iap:gold",   // stronger than sign-in
                    "max_age" to "0"                                // authenticate NOW
                )
            )
            .build()

    /**
     * Pushed Authorization Requests (RFC 9126).
     *
     * The parameters are POSTed to /par over the back channel and the browser receives only
     * `client_id` and an opaque one-time `request_uri`. There is then nothing in the front-channel
     * URL to tamper with, which removes an entire class of attack rather than mitigating it.
     *
     * VERIFY WITH  require_pushed_authorization_requests: true in the discovery document, and by
     *              confirming a plain /authorize request without a request_uri is REJECTED.
     */
    fun usePar(asConfig: AuthorizationServiceConfiguration): Boolean =
        asConfig.discoveryDoc?.docJson
            ?.optBoolean("require_pushed_authorization_requests", false) == true

    private fun randomUrlSafe(bytes: Int): String {
        val b = ByteArray(bytes)
        SecureRandom().nextBytes(b)
        return Base64.encodeToString(b, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            .take(128)
    }
}

/*
 * =================================================================================================
 * THE REVIEW CHECKLIST
 *
 * Reviewing this deployment means confirming each row rather than hunting for a single bug. The row
 * that was assumed rather than implemented is your finding.
 *
 *  Control                 Expectation                              How you verify it
 *  ----------------------  ---------------------------------------  ---------------------------------
 *  Grant                   auth code + PKCE S256 only               discovery + captured request
 *  PKCE ENFORCEMENT        server rejects missing/wrong verifier    lab 02 variants B and C
 *  Redirect                verified App Link                        adb shell pm get-app-links
 *  Scheme exclusivity      no competing claimant                    cmd package query-activities
 *  PAR                     require_pushed_authorization_requests    discovery document
 *  Sender constraining     DPoP or mTLS-bound tokens                DPoP header on /token and APIs
 *  Key provenance          hardware-backed, non-exportable          key attestation certificate
 *  Token lifetime          access minutes; refresh rotated          decode exp; refresh twice
 *  Refresh reuse detection old refresh token revokes the chain      present RT_OLD after rotating
 *  Step-up auth            second /authorize for sensitive ops      proxy a transfer
 *  acr honoured            elevated acr appears in the id_token     decode the second id_token
 *  Logout                  revocation_endpoint called AND effective use tokens after logging out
 *  Scope escalation        refresh cannot widen scope               refresh with extra scopes
 *  Storage                 Keystore-wrapped, allowBackup=false      chapter 46-Tokens
 *  MDM                     issuer and tenant from managed config    dumpsys device_policy
 *  User agent              Custom Tab, never a WebView              scripts/detect-webview-oauth.js
 *
 * In practice the two rows that most often fail on an otherwise excellent deployment are
 * "logout revokes server-side" and "refresh reuse is detected", because both are invisible from the
 * client, both work fine when nothing is wrong, and neither has a user-visible symptom.
 * =================================================================================================
 */
