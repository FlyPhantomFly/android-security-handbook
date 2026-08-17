/*
 * AppAuthLogin.kt — the same flow as ../01-minimal-pkce/, done with AppAuth-Android.
 *
 * PURPOSE
 *   This is what you should actually ship, and what a target app should look like. AppAuth is the
 *   OpenID Foundation's certified client library and the reference implementation of RFC 8252. It
 *   generates the verifier and challenge, validates `state` and `nonce`, validates the id_token,
 *   handles process death, and refuses to run the flow in a WebView at all.
 *
 * WHAT APPAUTH DOES *NOT* DO — read this before concluding an app is secure
 *   * It cannot make the authorisation SERVER enforce PKCE. That is the finding that matters and
 *     it is invisible from the client. See chapter 45 section 7.5 and labs/lab-02.
 *   * It cannot make your redirect a *verified* App Link. Check `pm get-app-links`.
 *   * It cannot make your backend validate `aud` on an id_token you forward to it.
 *   * It cannot encrypt your token storage. `AuthState.jsonSerializeString()` written to plain
 *     SharedPreferences is a finding, and it is extremely common.
 *   * It cannot stop the integrating developer bypassing it for one "quick" legacy flow.
 *
 * BUILD
 *   implementation("net.openid:appauth:0.11.1")
 *   implementation("androidx.security:security-crypto:1.1.0-alpha06")
 *   plus the manifest entry in AndroidManifest-snippet.xml.
 *
 * Chapter 45 — OAuth 2.0 and OpenID Connect on Android, sections 3.14 and 9.2
 */

package com.example.oauthdemo.appauth

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import net.openid.appauth.AuthState
import net.openid.appauth.AuthorizationException
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationResponse
import net.openid.appauth.AuthorizationService
import net.openid.appauth.AuthorizationServiceConfiguration
import net.openid.appauth.ClientAuthentication
import net.openid.appauth.EndSessionRequest
import net.openid.appauth.NoClientAuthentication
import net.openid.appauth.ResponseTypeValues
import net.openid.appauth.browser.AnyBrowserMatcher
import net.openid.appauth.browser.BrowserAllowList
import net.openid.appauth.browser.VersionedBrowserMatcher
import net.openid.appauth.AppAuthConfiguration

class AppAuthLogin : AppCompatActivity() {

    // ------------------------------------------------------------------------------------------
    // Configuration. BuildConfig fields, not hardcoded strings, so the values differ per flavour.
    // Note there is no client secret field — a public client has nothing to put in one.
    // ------------------------------------------------------------------------------------------
    private val issuer get() = Uri.parse(BuildConfig.OAUTH_ISSUER)
    private val clientId get() = BuildConfig.OAUTH_CLIENT_ID
    private val redirectUri get() = Uri.parse(BuildConfig.OAUTH_REDIRECT_URI)

    /**
     * The browser allow-list.
     *
     * AppAuth will not use a WebView, but it will use whatever browser is available. Restricting to
     * browsers that support Custom Tabs guarantees the flow runs out of process with a visible
     * origin. Using [AnyBrowserMatcher] is acceptable; using a *narrow* list can break users who
     * have an unusual default browser, so choose deliberately.
     */
    private val appAuthConfig = AppAuthConfiguration.Builder()
        .setBrowserMatcher(
            BrowserAllowList(
                VersionedBrowserMatcher.CHROME_CUSTOM_TAB,
                VersionedBrowserMatcher.FIREFOX_CUSTOM_TAB,
                VersionedBrowserMatcher.SAMSUNG_CUSTOM_TAB
            )
        )
        .build()

    private val authService by lazy { AuthorizationService(this, appAuthConfig) }
    private lateinit var authState: AuthState

    // ------------------------------------------------------------------------------------------
    // The result callback. AppAuth validates `state` internally before it hands you a response,
    // which is one of the main reasons to use it — that check is the one hand-rolled clients skip.
    // ------------------------------------------------------------------------------------------
    private val authLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val data = result.data ?: return@registerForActivityResult

        val resp = AuthorizationResponse.fromIntent(data)
        val ex = AuthorizationException.fromIntent(data)

        // Persist both outcomes. AuthState is the single source of truth for the session.
        authState = AuthState(resp, ex)

        if (resp == null) {
            showError(ex)
            return@registerForActivityResult
        }

        // createTokenExchangeRequest() carries the code and the code_verifier automatically —
        // you never handle the verifier yourself, which is exactly why it is never mishandled.
        authService.performTokenRequest(
            resp.createTokenExchangeRequest(),
            clientAuthentication()               // public client: NoClientAuthentication
        ) { tokenResp, tokenEx ->
            authState.update(tokenResp, tokenEx)

            if (tokenResp == null) {
                showError(tokenEx)
                return@performTokenRequest
            }

            // AppAuth validates the id_token — issuer, audience, expiry and nonce — when the
            // service configuration came from discovery. If you built the configuration by hand
            // from hardcoded endpoints, some of those checks are skipped, which is a good reason
            // to always use fetchFromIssuer().
            persistState()
            onLoggedIn()
        }
    }

    /**
     * A public client has no secret to present. Passing NoClientAuthentication is the correct and
     * explicit statement of that. If you ever find yourself reaching for ClientSecretPost or
     * ClientSecretBasic in an Android app, stop: the secret you are about to embed is published.
     */
    private fun clientAuthentication(): ClientAuthentication = NoClientAuthentication.INSTANCE

    // ------------------------------------------------------------------------------------------
    // Starting a login. Always fetch the discovery document rather than hardcoding endpoints:
    // it keeps the endpoints correct when the IdP changes them, and it is what enables AppAuth's
    // id_token validation.
    // ------------------------------------------------------------------------------------------
    private fun login() {
        AuthorizationServiceConfiguration.fetchFromIssuer(issuer) { config, ex ->
            if (config == null) {
                showError(ex)
                return@fetchFromIssuer
            }

            val req = AuthorizationRequest.Builder(
                config,
                clientId,
                ResponseTypeValues.CODE,          // code, never token
                redirectUri
            )
                // Least privilege at login. Request payments.write later, in its own flow, at the
                // moment the user initiates a payment — not at sign-in "just in case".
                .setScopes("openid", "profile", "accounts.read")

                // AppAuth generates the code_verifier and S256 challenge itself when you do not
                // supply one. Supplying your own is supported but there is no reason to.

                // A nonce is generated automatically for OIDC flows and checked on return.

                .setPrompt(AuthorizationRequest.Prompt.SELECT_ACCOUNT)
                .build()

            authLauncher.launch(authService.getAuthorizationRequestIntent(req))
        }
    }

    // ------------------------------------------------------------------------------------------
    // Using the session. Every API call goes through this, so token refresh lives in exactly one
    // place and cannot be forgotten at one call site.
    // ------------------------------------------------------------------------------------------
    private fun withFreshToken(action: (String) -> Unit) {
        authState.performActionWithFreshTokens(authService) { accessToken, _, ex ->
            if (accessToken == null) {
                forceReLogin(ex)
                return@performActionWithFreshTokens
            }
            action(accessToken)
        }
    }

    // ------------------------------------------------------------------------------------------
    // Logging out. Deleting the local token is NOT logout — the refresh token remains valid on the
    // server, indefinitely, and anyone who captured it keeps access. Both steps below are required.
    // ------------------------------------------------------------------------------------------
    private fun logout() {
        val config = authState.authorizationServiceConfiguration

        // 1. Revoke server-side (RFC 7009). AppAuth has no revocation helper, so this is a plain
        //    POST to the revocation_endpoint from the discovery document.
        authState.refreshToken?.let { rt ->
            RevocationClient.revoke(
                config?.discoveryDoc?.docJson?.optString("revocation_endpoint"), rt, clientId
            )
        }

        // 2. End the browser session at the IdP (OIDC RP-Initiated Logout), otherwise the next
        //    login completes silently from the browser cookie and the user believes they are still
        //    logged out.
        if (config?.endSessionEndpoint != null) {
            val endSession = EndSessionRequest.Builder(config)
                .setIdTokenHint(authState.idToken)
                .setPostLogoutRedirectUri(redirectUri)
                .build()
            startActivity(authService.getEndSessionRequestIntent(endSession))
        }

        // 3. Only now clear locally.
        clearState()
    }

    // ------------------------------------------------------------------------------------------
    // Storage. AuthState.jsonSerializeString() contains the access token, the refresh token and
    // the id_token. Writing it to plain SharedPreferences is a finding — it is world-readable to
    // anyone with root, recoverable from a backup, and trivially found by grepping for `eyJ`.
    // ------------------------------------------------------------------------------------------
    private fun prefs() = EncryptedSharedPreferences.create(
        this,
        "auth_state",
        MasterKey.Builder(this).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    private fun persistState() =
        prefs().edit().putString("state", authState.jsonSerializeString()).apply()

    private fun restoreState() {
        val json = prefs().getString("state", null)
        authState = if (json != null) AuthState.jsonDeserialize(json) else AuthState()
    }

    private fun clearState() {
        prefs().edit().clear().apply()
        authState = AuthState()
    }

    // ------------------------------------------------------------------------------------------
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)
        restoreState()
        findViewById<android.widget.Button>(R.id.btn_login).setOnClickListener { login() }
        findViewById<android.widget.Button>(R.id.btn_logout).setOnClickListener { logout() }
    }

    override fun onDestroy() {
        authService.dispose()
        super.onDestroy()
    }

    private fun onLoggedIn() {
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }

    private fun forceReLogin(ex: AuthorizationException?) {
        Log.w("OAuth", "refresh failed: ${ex?.errorDescription}")
        clearState()
        login()
    }

    private fun showError(ex: AuthorizationException?) {
        // Log the error code, never the response body — it may contain a code or a token.
        Log.w("OAuth", "auth error ${ex?.type}/${ex?.code}: ${ex?.error}")
    }
}

/**
 * Revocation helper. AppAuth deliberately does not ship one, which is a large part of why so many
 * apps never call the revocation endpoint at all.
 */
object RevocationClient {
    fun revoke(revocationEndpoint: String?, refreshToken: String, clientId: String) {
        if (revocationEndpoint.isNullOrEmpty()) {
            // Worth surfacing rather than swallowing: an IdP with no revocation endpoint cannot
            // support real logout, and that belongs in your threat model, not in a silent no-op.
            Log.w("OAuth", "no revocation_endpoint — server-side logout is impossible")
            return
        }
        Thread {
            try {
                val body = "token=$refreshToken&token_type_hint=refresh_token&client_id=$clientId"
                val conn = (java.net.URL(revocationEndpoint).openConnection()
                        as java.net.HttpURLConnection).apply {
                    requestMethod = "POST"
                    doOutput = true
                    setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                }
                conn.outputStream.use { it.write(body.toByteArray()) }
                Log.i("OAuth", "revocation returned ${conn.responseCode}")
                conn.disconnect()
            } catch (e: Exception) {
                Log.w("OAuth", "revocation failed; the refresh token is still live: ${e.message}")
            }
        }.start()
    }
}
