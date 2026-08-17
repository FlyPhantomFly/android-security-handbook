// examples/04-HardenedTokenStore.kt
//
// PURPOSE
//   03-BrokenTokenStore.java, written correctly. Same responsibilities, same public
//   surface, nine flaws gone. Read them side by side: the delta is the chapter.
//
//   It is also, deliberately, a demonstration that the correct version is not much
//   longer. Most of the extra lines are comments explaining what each control buys and —
//   more usefully — what it does not.
//
//   The nine fixes, matching 03's flaw numbers:
//     F1 -> the id_token is VERIFIED, by the server, and never trusted on the client
//     F2 -> the account key is (iss, sub), and the server derives it
//     F3 -> EncryptedSharedPreferences with a Keystore-held master key
//     F4 -> no key material in the APK at all
//     F5 -> nothing token-shaped ever reaches Log
//     F6 -> logout revokes server-side FIRST, then clears, and survives failure
//     F7 -> expiry comes from the `exp` claim; the server remains the authority
//     F8 -> the access token goes to the API; the id_token never does
//     F9 -> the callback URI is consumed and dropped, never forwarded
//
// BUILD
//   Android, minSdk 23 (EncryptedSharedPreferences requires the Keystore AES-GCM support
//   that lands at API 23). Gradle:
//       implementation "androidx.security:security-crypto:1.1.0-alpha06"
//       implementation "net.openid:appauth:0.11.1"
//       implementation "com.squareup.okhttp3:okhttp:4.12.0"
//
//   NOT compiled for this repository — it references Android and AppAuth classes that
//   need an SDK on the compile path. Reviewed line by line instead, and every API used
//   is a documented public one.
//
// WHAT THIS WILL NOT TELL YOU / WHAT IT DOES NOT BUY
//   Read this before recommending it, because overselling it is how a pentest report
//   loses credibility:
//   * It does NOT protect the token from a rooted device. An attacker with code
//     execution in this process calls the same getter and receives the same string.
//     EncryptedSharedPreferences raises the cost of reading the FILE; it does nothing
//     about reading the VALUE. 49-KeyStore section 1.3 is the canonical statement of
//     this and it is worth memorising.
//   * It does NOT make the token unstealable. It is still a bearer token. The only
//     thing that changes that is sender-constraining — see 05-DpopInterceptor.kt.
//   * It does NOT fix a server that accepts alg=none. Nothing on the client can.
//   * `setUserAuthenticationRequired` is deliberately NOT used here. It would tie the
//     master key to a recent biometric or PIN, which is right for a payment app and
//     wrong for one that must refresh in the background — the key becomes unusable and
//     the app silently logs the user out. Chapter 48 covers the trade properly.
//
// SAFETY
//   Nothing here mints or handles a token belonging to anyone. The only tokens this
//   code sees at runtime are ones the app's own user obtained.
//
// Chapter 46 — Tokens

package com.pentest.ch46

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.IOException

/**
 * Holds this app's OAuth tokens.
 *
 * Design rule this class exists to enforce: **the token is a value the app carries, not
 * a document the app reads.** Every method that would tempt a caller into interpreting
 * a token's contents is absent. The one place a claim is read — [accessTokenExpiry] —
 * reads it only to decide when to refresh, and treats the server's 401 as the real
 * authority.
 */
class HardenedTokenStore(context: Context) {

    private companion object {
        const val TAG = "TokenStore"
        const val PREFS = "auth_v2"
        const val K_ACCESS = "access_token"
        const val K_REFRESH = "refresh_token"

        /**
         * Refresh this far before `exp` rather than at `exp`. Without a margin, a request
         * that begins 200 ms before expiry arrives after it, and the user sees a spurious
         * failure. 60 seconds also absorbs modest clock skew between device and server.
         */
        const val REFRESH_MARGIN_SECONDS = 60L
    }

    // FIX for F3 and F4.
    //
    // The master key is generated INSIDE the Android Keystore. No key material exists in
    // the APK, in resources, in a native library, or in any string. `AES256_GCM` gives
    // an authenticated mode, so a modified preferences file fails to decrypt rather than
    // decrypting to attacker-chosen bytes.
    //
    // What this buys, stated precisely so it can be defended in a report: an attacker who
    // obtains a COPY of the preferences file — through a backup, an exported provider, a
    // world-readable path, a forensic image of the flash — cannot read it, because the
    // key never left the device and, on hardware-backed devices, never left the secure
    // element. That is a real and common threat and this closes it.
    //
    // What it does not buy: anything at all against an attacker running code in this
    // process. See the header.
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        PREFS,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    private val http = OkHttpClient()

    // ====================================================================== //
    // FIX for F1 and F2: the client does not decide who the user is.
    //
    // 03's `userIdFromIdToken` is not fixed here. It is DELETED, and that is the fix.
    //
    // A mobile client verifying an id_token is possible — fetch the JWKS, check alg
    // against an allow-list, check iss, aud, exp, nonce — and AppAuth's IdToken.validate
    // will do most of it. But it is answering a question the client should not be asking.
    // The client already knows who its user is: it is the person holding the phone who
    // just completed a login. What it needs from the server is a SESSION, and the server
    // is the party that must verify the token, because the server is the party that will
    // act on the answer.
    //
    // So: send the id_token to your backend once, over TLS, and let it verify (that is
    // 02-correct-verifier.py's job) and return a session. The account key it derives is
    // the pair (iss, sub) — never `email`, which is mutable, sometimes unverified, and
    // re-assignable, and which is therefore an account-takeover vector at any identity
    // provider that does not verify addresses.
    //
    // The mistake this deletion prevents is subtle: an app that verifies locally and then
    // tells the backend "the user is alice@example.com" has built a backend that trusts
    // the client's conclusion. The verification was real and completely worthless.
    // ====================================================================== //
    fun exchangeIdTokenForSession(idToken: String, backend: String): Result<String> {
        val body = FormBody.Builder().add("id_token", idToken).build()
        val request = Request.Builder().url("$backend/api/v1/session").post(body).build()
        return try {
            http.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    // No token in the message. See F5.
                    return Result.failure(IOException("session exchange: HTTP ${response.code}"))
                }
                val session = JSONObject(response.body?.string().orEmpty())
                Result.success(session.getString("session_id"))
            }
        } catch (e: IOException) {
            Result.failure(e)
        }
    }

    // ====================================================================== //
    // FIX for F5: no token, and no fragment of one, ever reaches a log.
    //
    // The rule that actually holds up in a large codebase is not "be careful what you
    // log". It is: make the token type unloggable. Wrap it so its toString() is safe,
    // and the mistake becomes impossible rather than merely discouraged. A Kotlin value
    // class costs nothing at runtime.
    // ====================================================================== //
    @JvmInline
    value class Token(private val raw: String) {
        fun expose(): String = raw
        override fun toString(): String = "Token(${raw.length} chars, redacted)"
    }

    fun saveTokens(accessToken: String, refreshToken: String?) {
        prefs.edit().apply {
            putString(K_ACCESS, accessToken)
            // A refresh token that arrives null on a refresh response means the server
            // is NOT rotating. Record that; it is a server-side finding, and it changes
            // the severity of everything else in this file, because a non-rotating
            // refresh token turns one theft into permanent access.
            if (refreshToken != null) {
                putString(K_REFRESH, refreshToken)
            } else {
                Log.i(TAG, "refresh response carried no new refresh_token: rotation is off")
            }
            // FIX for F7: no locally computed expiry is stored. See below.
        }.apply()
    }

    fun accessToken(): Token? = prefs.getString(K_ACCESS, null)?.let { Token(it) }

    fun refreshToken(): Token? = prefs.getString(K_REFRESH, null)?.let { Token(it) }

    // ====================================================================== //
    // FIX for F7: expiry comes from the token's own signed `exp`, and even that is only
    // a scheduling hint.
    //
    // Two levels of authority, in order:
    //   1. `exp` inside the signed payload. It cannot be edited without breaking the
    //      signature, so it is trustworthy in a way a SharedPreferences long is not.
    //      Use it to decide WHEN to refresh proactively.
    //   2. The server's 401. It is the only authority on whether a token still works,
    //      because a token can be revoked long before `exp` — see README section 3.10.
    //      Always handle the 401; never assume a non-expired token is a valid one.
    //
    // Note what this method does NOT do: it does not verify the signature. It is reading
    // an unauthenticated number for a scheduling decision, and that is fine — a forged
    // `exp` makes the app refresh at the wrong moment, which is a bug and not a breach.
    // Saying so explicitly is the difference between a considered decision and an
    // oversight, and a reviewer will ask.
    // ====================================================================== //
    fun secondsUntilRefreshNeeded(now: Long = System.currentTimeMillis() / 1000): Long? {
        val raw = prefs.getString(K_ACCESS, null) ?: return null
        val exp = expClaimOrNull(raw) ?: return 0            // no exp: refresh now
        return (exp - REFRESH_MARGIN_SECONDS - now).coerceAtLeast(0)
    }

    private fun expClaimOrNull(jwt: String): Long? = try {
        val parts = jwt.split(".")
        if (parts.size != 3) {
            null                                              // opaque token: nothing to read
        } else {
            val payload = String(
                android.util.Base64.decode(
                    parts[1],
                    android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP
                )
            )
            JSONObject(payload).optLong("exp").takeIf { it > 0 }
        }
    } catch (e: Exception) {
        null
    }

    // ====================================================================== //
    // FIX for F8: the ACCESS token goes to the API. The id_token never does.
    //
    // The id_token's `aud` is this client. It is a statement to this app about who
    // logged in. It is not a credential for any API, and an API that accepts one is an
    // API that is not checking `aud`.
    // ====================================================================== //
    fun authorizationHeader(): String? = accessToken()?.let { "Bearer ${it.expose()}" }

    // ====================================================================== //
    // FIX for F6: logout revokes first, clears second, and does the right thing when
    // the network is down.
    //
    // The order matters and is often reversed. If you clear local state first and the
    // revocation call then fails, you have lost the refresh token and can never revoke
    // it — the credential is now immortal AND unreachable. Revoke first, and clear
    // whatever happens, because a user who tapped "log out" must not be left logged in
    // locally.
    //
    // RFC 7009 defines /revoke. Revoking the REFRESH token is the important one: a
    // correctly implemented server invalidates the whole token family, which kills the
    // access tokens too. Revoking only the access token leaves the refresh token able to
    // mint more.
    //
    // Test this from the outside, always: capture a token, log out, replay it. A 200
    // means the revocation did not happen or was not honoured, and that is the finding
    // regardless of what this code looks like.
    // ====================================================================== //
    fun logout(revocationEndpoint: String, clientId: String): Boolean {
        val refresh = refreshToken()
        var revoked = false
        if (refresh != null) {
            val body = FormBody.Builder()
                .add("token", refresh.expose())
                .add("token_type_hint", "refresh_token")
                .add("client_id", clientId)
                .build()
            revoked = try {
                http.newCall(Request.Builder().url(revocationEndpoint).post(body).build())
                    .execute().use { it.isSuccessful }
            } catch (e: IOException) {
                // No token in the message.
                Log.w(TAG, "revocation failed: ${e.javaClass.simpleName}")
                false
            }
        }
        prefs.edit().clear().commit()   // commit, not apply: the user is leaving
        if (!revoked) {
            // Do not silently pretend. Queue it, and be honest in the UI if the token
            // could not be revoked — on a shared device that difference matters.
            Log.i(TAG, "local state cleared; server revocation NOT confirmed")
        }
        return revoked
    }

    // ====================================================================== //
    // FIX for F9: the callback URI is consumed here and goes no further.
    //
    // The code is extracted, used immediately for the token exchange, and the URI is
    // never logged, never put in an Intent extra, never handed to a WebView, and never
    // stored. AppAuth's RedirectUriReceiverActivity does this correctly by default,
    // which is one more reason to recommend the library rather than a hand-rolled flow.
    // 45-OAuth owns everything about the flow itself.
    // ====================================================================== //
    fun onCallback(intent: Intent): String? {
        val uri: Uri = intent.data ?: return null
        val code = uri.getQueryParameter("code")
        intent.data = null                    // do not let it travel with the Intent
        return code
    }
}
