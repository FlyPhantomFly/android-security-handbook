/*
 * MinimalPkce.kt — a correct, dependency-free authorisation-code + PKCE flow.
 *
 * PURPOSE
 *   Every step is visible. This is a teaching artefact: you should be able to write it from memory,
 *   because that is what it takes to understand what AppAuth does for you and to spot what a target
 *   app has left out.
 *
 * THIS IS NOT WHAT YOU SHOULD SHIP.
 *   Ship AppAuth-Android (see ../02-appauth/AppAuthLogin.kt). Hand-rolled OAuth clients get the
 *   small details wrong — the ASCII-vs-raw-bytes hashing, the base64 padding, the state comparison,
 *   surviving process death while the Custom Tab is in the foreground — and each of those is a real
 *   bug seen in production apps.
 *
 * BUILD
 *   Drop into an Android module with:
 *     implementation("androidx.browser:browser:1.8.0")
 *     implementation("androidx.security:security-crypto:1.1.0-alpha06")
 *     implementation("com.squareup.okhttp3:okhttp:4.12.0")
 *   and the manifest entry from AndroidManifest-snippet.xml in this directory.
 *
 * Chapter 45 — OAuth 2.0 and OpenID Connect on Android, section 9.1
 */

package com.example.oauthdemo

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.browser.customtabs.CustomTabsIntent
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.Executors

// --------------------------------------------------------------------------------------------
// Configuration. In a real app these come from BuildConfig or from a discovery document fetched
// at runtime; they are constants here so the flow is readable.
// --------------------------------------------------------------------------------------------
private object OAuthConfig {
    const val ISSUER = "https://login.example.com"
    const val AUTH_ENDPOINT = "$ISSUER/oauth2/authorize"
    const val TOKEN_ENDPOINT = "$ISSUER/oauth2/token"
    const val REVOKE_ENDPOINT = "$ISSUER/oauth2/revoke"

    /** Public identifier, not a credential. It is fine that anyone can read this from the APK. */
    const val CLIENT_ID = "android-demo-client"

    /**
     * A VERIFIED App Link, not a custom scheme.
     *
     * A custom scheme such as `oauthdemo://cb` can be claimed by any other installed app, because
     * Android imposes no uniqueness on schemes. An https redirect whose host serves
     * /.well-known/assetlinks.json naming this package and signing certificate is enforced by the
     * platform. Confirm with: adb shell pm get-app-links com.example.oauthdemo
     */
    const val REDIRECT_URI = "https://login.example.com/android/callback"

    /** Least privilege at login. Request more later, in a separate flow, when the user needs it. */
    const val SCOPES = "openid profile accounts.read"
}

class MinimalPkceActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)
        findViewById<android.widget.Button>(R.id.btn_login).setOnClickListener { startAuth() }
    }

    // ------------------------------------------------------------------------------------------
    // Step 1 — generate the three secrets, then build and launch the authorisation request.
    // ------------------------------------------------------------------------------------------
    private fun startAuth() {
        // The code_verifier NEVER leaves this process on the front channel. Only its hash does.
        val codeVerifier = randomUrlSafe(64)      // 512 bits, comfortably above RFC 7636's minimum
        val state = randomUrlSafe(32)             // 256 bits — CSRF protection
        val nonce = randomUrlSafe(32)             // 256 bits — OIDC replay protection

        // The process can be killed while the Custom Tab is in the foreground, and the callback
        // will then arrive at a fresh process with empty memory. Persisting these is not optional.
        // They are secrets, so they go in EncryptedSharedPreferences, not plain preferences.
        PendingAuth.save(this, PendingAuth(state, codeVerifier, nonce))

        val uri = Uri.parse(OAuthConfig.AUTH_ENDPOINT).buildUpon()
            .appendQueryParameter("response_type", "code")     // code, never token
            .appendQueryParameter("client_id", OAuthConfig.CLIENT_ID)
            .appendQueryParameter("redirect_uri", OAuthConfig.REDIRECT_URI)
            .appendQueryParameter("scope", OAuthConfig.SCOPES)
            .appendQueryParameter("state", state)
            .appendQueryParameter("nonce", nonce)
            .appendQueryParameter("code_challenge", s256(codeVerifier))
            .appendQueryParameter("code_challenge_method", "S256")   // never `plain`
            .build()

        // A Custom Tab is an activity in the BROWSER's process, under the BROWSER's UID, with the
        // browser's cookie jar. This app cannot read the DOM, the cookies, or the typed password —
        // the app sandbox enforces that. A WebView would place all three inside this app's trust
        // boundary, which is why RFC 8252 s8.12 prohibits it.
        CustomTabsIntent.Builder()
            .setShowTitle(true)
            .build()
            .launchUrl(this, uri)
    }

    // ------------------------------------------------------------------------------------------
    // Cryptographic primitives. Three details in here cause real bugs when they are wrong.
    // ------------------------------------------------------------------------------------------

    /**
     * Generates [bytes] bytes of cryptographically secure entropy and returns it as a string of
     * unreserved URL characters.
     *
     * SecureRandom, not Random, not System.currentTimeMillis(), not a UUID derived from a device
     * identifier. A predictable nonce is not a nonce.
     *
     * NO_WRAP prevents newlines being inserted into the value; NO_PADDING strips the '=' characters
     * that RFC 7636 s4.1 forbids in a code_verifier.
     */
    private fun randomUrlSafe(bytes: Int): String {
        val b = ByteArray(bytes)
        SecureRandom().nextBytes(b)
        return Base64.encodeToString(b, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            .take(128)                             // RFC 7636 s4.1 caps the verifier at 128 chars
    }

    /**
     * RFC 7636 s4.2: code_challenge = BASE64URL(SHA256(ASCII(code_verifier))).
     *
     * The subtle part: hash the ASCII bytes of the base64url STRING, not the raw entropy that
     * produced it. Implementations that hash the wrong thing produce a challenge the server cannot
     * reproduce, and the usual "fix" is to fall back to `plain` — which destroys the protection.
     */
    private fun s256(verifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(verifier.toByteArray(Charsets.US_ASCII))
        return Base64.encodeToString(digest, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }
}

// ------------------------------------------------------------------------------------------
// The pending-request record. Stored encrypted, single-use, cleared on consumption.
// ------------------------------------------------------------------------------------------
data class PendingAuth(val state: String, val codeVerifier: String, val nonce: String) {

    companion object {
        private const val PREFS = "pending_auth"
        private const val K_STATE = "state"
        private const val K_VERIFIER = "code_verifier"
        private const val K_NONCE = "nonce"
        private const val K_CREATED = "created_at"

        /** Requests older than this are stale; a callback arriving later is suspicious. */
        private const val MAX_AGE_MS = 10 * 60 * 1000L

        private fun prefs(ctx: Context) = EncryptedSharedPreferences.create(
            ctx,
            PREFS,
            MasterKey.Builder(ctx).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

        fun save(ctx: Context, p: PendingAuth) {
            prefs(ctx).edit()
                .putString(K_STATE, p.state)
                .putString(K_VERIFIER, p.codeVerifier)
                .putString(K_NONCE, p.nonce)
                .putLong(K_CREATED, System.currentTimeMillis())
                .apply()
        }

        fun load(ctx: Context): PendingAuth? {
            val p = prefs(ctx)
            val created = p.getLong(K_CREATED, 0L)
            if (created == 0L || System.currentTimeMillis() - created > MAX_AGE_MS) {
                clear(ctx)
                return null
            }
            val state = p.getString(K_STATE, null) ?: return null
            val verifier = p.getString(K_VERIFIER, null) ?: return null
            val nonce = p.getString(K_NONCE, null) ?: return null
            return PendingAuth(state, verifier, nonce)
        }

        /** Single use. Call this the moment the record is consumed, success or failure. */
        fun clear(ctx: Context) = prefs(ctx).edit().clear().apply()
    }
}

// ------------------------------------------------------------------------------------------
// Step 3 — the back-channel token exchange. This request never touches the browser.
// ------------------------------------------------------------------------------------------
object TokenExchange {

    private val http = OkHttpClient()
    private val io = Executors.newSingleThreadExecutor()

    fun exchange(
        code: String,
        codeVerifier: String,
        expectedNonce: String,
        onSuccess: (JSONObject) -> Unit,
        onError: (String) -> Unit
    ) = io.execute {
        val body = FormBody.Builder()
            .add("grant_type", "authorization_code")
            .add("code", code)
            // The redirect_uri here MUST byte-for-byte match the one used at /authorize.
            // RFC 6749 s4.1.3 requires the server to check this.
            .add("redirect_uri", OAuthConfig.REDIRECT_URI)
            .add("client_id", OAuthConfig.CLIENT_ID)
            // The verifier. This is the whole point of PKCE, and the reason a stolen code is
            // worthless to anyone who does not hold this value.
            //
            // NOTE FOR TESTERS: whether the SERVER refuses this request when the verifier is
            // absent or wrong is invisible from here, and is the actual security property.
            // See chapter 45 section 7.5 and labs/lab-02-pkce-enforcement.md.
            .add("code_verifier", codeVerifier)
            // No client_secret. This is a public client and there is nothing to send.
            .build()

        val req = Request.Builder()
            .url(OAuthConfig.TOKEN_ENDPOINT)
            .post(body)
            .header("Accept", "application/json")
            .build()

        try {
            http.newCall(req).execute().use { resp ->
                val text = resp.body?.string().orEmpty()
                if (!resp.isSuccessful) {
                    onError("token endpoint returned ${resp.code}: $text")
                    return@execute
                }
                val json = JSONObject(text)

                // The id_token must be validated before it is trusted for anything. The full
                // algorithm is OIDC Core s3.1.3.7 — signature against a JWKS key chosen from our
                // own alg allow-list, then iss, aud, exp, iat/nbf, and nonce.
                json.optString("id_token").takeIf { it.isNotEmpty() }?.let { idToken ->
                    val problem = IdTokenValidator.validate(idToken, expectedNonce)
                    if (problem != null) {
                        onError("id_token rejected: $problem")
                        return@execute
                    }
                }
                onSuccess(json)
            }
        } catch (e: Exception) {
            onError("token exchange failed: ${e.message}")
        }
    }

    /** Correct logout: tell the server, do not merely forget locally. */
    fun revoke(refreshToken: String) = io.execute {
        val body = FormBody.Builder()
            .add("token", refreshToken)
            .add("token_type_hint", "refresh_token")
            .add("client_id", OAuthConfig.CLIENT_ID)
            .build()
        try {
            http.newCall(
                Request.Builder().url(OAuthConfig.REVOKE_ENDPOINT).post(body).build()
            ).execute().close()
        } catch (e: Exception) {
            Log.w("OAuth", "revocation failed — the refresh token is still live: ${e.message}")
        }
    }
}
