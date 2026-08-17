/*
 * VulnerableOAuth.java — a catalogue of every mobile OAuth anti-pattern, in one file.
 *
 * PURPOSE
 *   A reference for recognition, not a target to build. Each numbered block is a bug seen
 *   repeatedly in real Android applications, annotated with:
 *       * why a developer writes it (it is never stupidity — there is always a plausible reason)
 *       * how you detect it, statically and dynamically
 *       * how it is exploited
 *       * the secure fix, as code
 *       * honest severity
 *
 *   Compare this file against ../01-minimal-pkce/ and ../02-appauth/ line by line. The differences
 *   are the findings.
 *
 * DO NOT SHIP ANY PART OF THIS FILE.
 *
 * Chapter 45 — OAuth 2.0 and OpenID Connect on Android, sections 5 and 11
 */

package com.example.vulnerable;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.webkit.CookieManager;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.content.SharedPreferences;

import org.json.JSONObject;

import java.util.Random;

public class VulnerableOAuth extends Activity {

    private static final String TAG = "OAuthDemo";

    // =============================================================================================
    // BUG 1 — A client secret embedded in the APK.
    //
    // WHY DEVELOPERS WRITE IT
    //   The identity provider's web quickstart hands them a client_id and a client_secret. Nothing
    //   in that page says "not for mobile". The desktop sample works, so they copy it.
    //
    // DETECTION (static)
    //   grep -rn 'client_secret\|CLIENT_SECRET\|clientSecret' out/sources/ res/values/strings.xml
    //   Also check BuildConfig fields, native libraries, and assets.
    //
    // DETECTION (dynamic)
    //   The value appears in the /token request body in any proxy.
    //
    // EXPLOIT
    //   Unzip the APK. There is no exploitation step beyond that. The secret is published to every
    //   user of the app. With it, an attacker can impersonate the client to the authorisation
    //   server, which frequently unlocks grants the app itself does not use.
    //
    // FIX
    //   Delete it. Register the client as PUBLIC at the authorisation server and use
    //   authorisation code + PKCE. If something genuinely requires a secret, it belongs on a
    //   backend-for-frontend, not on the device.
    //
    // SEVERITY  High on its own; Critical when it enables ROPC or client_credentials.
    // =============================================================================================
    private static final String CLIENT_ID = "android-demo-client";
    private static final String CLIENT_SECRET = "s3cr3t_dGhpcyBpcyBub3QgYSBzZWNyZXQ";   // BUG 1

    // Splitting it up, obfuscating it, or moving it into a .so changes the extraction time from
    // seconds to minutes. It does not change the outcome.
    private static String reassembleSecret() {                                          // BUG 1b
        return "s3cr3t" + "_" + new String(Base64.decode("dGhpcw==", Base64.DEFAULT));
    }

    // =============================================================================================
    // BUG 2 — A custom URI scheme used as the redirect, assumed to be exclusive.
    //
    // WHY DEVELOPERS WRITE IT
    //   It works immediately, needs no server-side setup, and was the documented pattern for years.
    //   App Link verification requires control of a domain and a correctly served JSON file, which
    //   is usually owned by a different team.
    //
    // DETECTION (static)
    //   grep -A6 'android:scheme' AndroidManifest.xml | grep -v 'https\?"'
    //
    // DETECTION (dynamic)
    //   adb shell cmd package query-activities -a android.intent.action.VIEW -d "vulnapp://cb"
    //   More than one result means the scheme is contested.
    //
    // EXPLOIT
    //   Any installed app declares the same intent-filter and receives the authorisation code.
    //   See labs/lab-03-scheme-hijack.md.
    //
    // FIX
    //   An https redirect on a domain you control, serving /.well-known/assetlinks.json with your
    //   package name and signing fingerprint, declared with android:autoVerify="true", and then
    //   CONFIRMED with `adb shell pm get-app-links` showing `verified`.
    //
    // SEVERITY  Medium if the server enforces PKCE (the stolen code is inert);
    //           Critical if it does not (account takeover by any installed app).
    // =============================================================================================
    private static final String REDIRECT_URI = "vulnapp://oauth/callback";              // BUG 2

    private static final String AUTH_ENDPOINT = "https://login.example.com/oauth2/authorize";
    private static final String TOKEN_ENDPOINT = "https://login.example.com/oauth2/token";

    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        findViewById(R.id.btn_login).setOnClickListener(v -> startBrokenLogin());
    }

    // =============================================================================================
    // BUG 3 — The authorisation flow runs inside a WebView the app owns.
    //
    // WHY DEVELOPERS WRITE IT
    //   Product wants the login screen to match the app's branding, and does not want the user to
    //   "leave the app". A Custom Tab shows a browser toolbar; a WebView does not. The decision is
    //   made on a design review, not a security review, and nobody in the room knows what it costs.
    //
    // DETECTION (static)
    //   grep -rn 'loadUrl' out/sources/ | grep -iE 'authorize|oauth|openid'
    //   grep -rn 'setJavaScriptEnabled(true)\|addJavascriptInterface' out/sources/
    //
    // DETECTION (dynamic)
    //   frida -U -f <pkg> -l scripts/detect-webview-oauth.js
    //
    // EXPLOIT
    //   The app can read the password field with evaluateJavascript, read every request body with
    //   shouldInterceptRequest, and read the IdP session cookie with CookieManager. It can also
    //   render a perfect fake login page, because the user has no address bar.
    //
    // FIX
    //   androidx.browser CustomTabsIntent, or AppAuth, which refuses to use a WebView at all.
    //
    // SEVERITY  High. The finding is architectural: the user's identity-provider credential is
    //           inside the client's trust boundary, and theft would be undetectable.
    //           RFC 8252 section 8.12 prohibits embedded user agents.
    // =============================================================================================
    private void startBrokenLogin() {
        String url = AUTH_ENDPOINT
                + "?response_type=code"
                + "&client_id=" + CLIENT_ID
                + "&redirect_uri=" + REDIRECT_URI
                + "&scope=" + buildScopes()
                + "&state=" + weakState();
        // Note what is absent: code_challenge, code_challenge_method, nonce.

        webView = findViewById(R.id.webview);
        webView.getSettings().setJavaScriptEnabled(true);                               // BUG 3
        webView.setWebViewClient(new WebViewClient() {

            @Override
            public void onPageFinished(WebView view, String url) {
                // This is not hypothetical. Five lines is the whole credential harvest.
                view.evaluateJavascript(
                        "(function(){var p=document.querySelector('input[type=password]');" +
                        "return p?p.value:null;})()",
                        value -> Log.d(TAG, "harvested: " + value));                     // BUG 3b
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                if (url.startsWith(REDIRECT_URI)) {
                    handleCallback(Uri.parse(url));
                    return true;
                }
                return false;
            }
        });
        webView.loadUrl(url);                                                           // BUG 3

        // And the identity provider's session cookie is readable too.
        String idpSession = CookieManager.getInstance().getCookie("https://login.example.com");
        Log.d(TAG, "idp session: " + idpSession);                                       // BUG 3c
    }

    // =============================================================================================
    // BUG 4 — `state` generated from a predictable source, and never compared on return.
    //
    // WHY DEVELOPERS WRITE IT
    //   `state` is described in tutorials as "an opaque value you can use to maintain state", which
    //   reads like a convenience feature rather than a security control. So it gets a timestamp, and
    //   the return value gets used to route the response rather than to authorise it.
    //
    // DETECTION (static)
    //   grep -rn 'new Random(\|currentTimeMillis()\|UUID.randomUUID' near the state assignment.
    //   Then check whether the returned value is ever compared: search for the state field in the
    //   callback handler. Sending it and not comparing it is the common shape.
    //
    // DETECTION (dynamic)
    //   Capture three logins and compare the state values. A counter or timestamp is obvious.
    //
    // EXPLOIT
    //   The attacker completes their own authorisation, captures the code, and induces this app to
    //   consume it. The victim's app then holds the ATTACKER's tokens, and everything the victim
    //   saves is written into the attacker's account.
    //
    // FIX
    //   SecureRandom, at least 128 bits, persisted with the request, compared on return, and a
    //   MISSING state must be fatal rather than a pass.
    //
    // SEVERITY  High.
    // =============================================================================================
    private String weakState() {
        return String.valueOf(new Random().nextInt(9999))                               // BUG 4
                + System.currentTimeMillis();
    }

    // =============================================================================================
    // BUG 5 — Over-scoping at login.
    //
    // WHY DEVELOPERS WRITE IT
    //   Asking for everything up front avoids a second consent screen later, and nobody wants to
    //   ship a feature and discover the token lacks the scope for it. It is a velocity decision.
    //
    // DETECTION
    //   Build a two-column table: every scope, and the specific feature that requires it. Empty
    //   second cells are the finding. Then strip the scope from the request and show the app still
    //   works — a demonstrated unused scope is far stronger than an asserted one.
    //
    // EXPLOIT
    //   Not directly exploitable. It multiplies the impact of every other finding: an app whose
    //   only feature is showing a balance, holding payments.write, has converted an information
    //   disclosure into a funds-transfer capability.
    //
    // FIX
    //   Least privilege at login; step up with a second authorisation for sensitive operations.
    //
    // SEVERITY  Medium.
    // =============================================================================================
    private String buildScopes() {
        return "openid%20profile%20email%20accounts.read%20accounts.write"
                + "%20payments.initiate%20payments.write%20offline_access%20admin";      // BUG 5
    }

    // =============================================================================================
    // BUG 6 — The callback handler validates nothing.
    // =============================================================================================
    private void handleCallback(Uri data) {
        String code = data.getQueryParameter("code");
        // BUG 6a: `state` is read and discarded. No comparison. No rejection when absent.
        String state = data.getQueryParameter("state");
        Log.d(TAG, "got state " + state);

        // BUG 6b: an `error` response is not handled at all, so a failed login looks like a hang.

        exchangeCode(code);
    }

    // =============================================================================================
    // BUG 7 — The token exchange sends the client secret and no code_verifier.
    //
    // The absence of code_verifier here is only half the story. The other half is that a server
    // which ACCEPTS this request is where the real vulnerability lives — and you cannot see that
    // from this file. See chapter 45 section 7.5.
    // =============================================================================================
    private void exchangeCode(String code) {
        new Thread(() -> {
            try {
                String body = "grant_type=authorization_code"
                        + "&code=" + code
                        + "&redirect_uri=" + REDIRECT_URI
                        + "&client_id=" + CLIENT_ID
                        + "&client_secret=" + CLIENT_SECRET;                            // BUG 7
                // No code_verifier: this app has no PKCE at all.

                String response = Http.post(TOKEN_ENDPOINT, body);
                JSONObject tokens = new JSONObject(response);

                // BUG 8: the whole response, tokens included, is written to the log.
                //   WHY: it is the fastest way to debug, and the line survives the release build
                //        because nobody grepped for it.
                //   DETECT: adb logcat while performing a login; grep for 'eyJ'.
                //   EXPLOIT: pre-API-16 any app could read the log; today it needs adb or a crash
                //        reporter that uploads logs — which many apps have.
                //   FIX: never log a token. Use a redacting logger and fail the build on `Log.d`
                //        in release.
                //   SEVERITY: Medium, rising to High when a crash reporter uploads the log.
                Log.d(TAG, "tokens: " + tokens.toString());                             // BUG 8

                handleIdToken(tokens.optString("id_token"));
                storeTokens(tokens);
            } catch (Exception e) {
                Log.e(TAG, "exchange failed", e);
            }
        }).start();
    }

    // =============================================================================================
    // BUG 9 — The id_token is decoded, not validated.
    //
    // WHY DEVELOPERS WRITE IT
    //   The JWT payload is right there, base64-decodes in two lines, and contains exactly the
    //   fields they need. Signature verification requires fetching a JWKS, caching it, selecting by
    //   kid and picking an algorithm — hours of work that appears to add nothing, because the happy
    //   path already works.
    //
    // DETECTION (static)
    //   Look for Base64.decode on a `.split("\\.")[1]` with no Signature or JWT library nearby.
    //   grep -rn 'split("\\\\.")' out/sources/
    //
    // EXPLOIT
    //   Forge a token in a text editor. `{"sub":"admin","email":"victim@example.com"}`, base64url,
    //   any signature. If this app forwards the token to its own backend and the backend behaves
    //   the same way, that is full account takeover with no cryptography.
    //
    // FIX
    //   The full OIDC Core 3.1.3.7 algorithm. See ../01-minimal-pkce/CallbackActivity.kt.
    //
    // SEVERITY  Critical wherever the decoded claims drive an authorisation decision.
    // =============================================================================================
    private void handleIdToken(String idToken) {
        if (idToken == null || idToken.isEmpty()) return;
        String[] parts = idToken.split("\\.");
        String payload = new String(Base64.decode(parts[1], Base64.URL_SAFE));          // BUG 9
        Log.d(TAG, "identity: " + payload);
        // No signature check. No iss check. No aud check. No exp check. No nonce check.
        // Whatever this payload says, the app now believes.

        // BUG 9b: and the app sends the id_token to its own API as if it were a credential.
        //   The id_token's audience is THIS CLIENT, not the API. An API that accepts it is
        //   accepting a token minted for someone else. See chapter 45 section 3.12.
        Http.get("https://api.example.com/v1/me", "Authorization: Bearer " + idToken);
    }

    // =============================================================================================
    // BUG 10 — Tokens written to plaintext SharedPreferences, in a backup-enabled app.
    //
    // WHY DEVELOPERS WRITE IT
    //   SharedPreferences is the first storage API every Android developer learns, it is one line,
    //   and EncryptedSharedPreferences did not exist when most of these apps were written.
    //
    // DETECTION (static)
    //   grep -rn 'getSharedPreferences' near token handling; check allowBackup in the manifest.
    // DETECTION (dynamic)
    //   adb shell (root): grep -r 'eyJ' /data/data/<pkg>/shared_prefs/
    //   Or hook SharedPreferencesImpl$EditorImpl.putString — see scripts/oauth-flow-tracer.js.
    //
    // EXPLOIT
    //   Root, a backup, a device-extraction tool, or any other bug that yields file read.
    //
    // FIX
    //   EncryptedSharedPreferences with a Keystore master key, allowBackup="false", and a
    //   backup_rules.xml excluding the file. Better: keep the refresh token off the device
    //   entirely, behind a backend-for-frontend. See chapter 46-Tokens.
    //
    // SEVERITY  High for a refresh token; Medium for a short-lived access token.
    // =============================================================================================
    private void storeTokens(JSONObject tokens) {
        SharedPreferences prefs = getSharedPreferences("auth", MODE_PRIVATE);
        prefs.edit()
                .putString("access_token", tokens.optString("access_token"))
                .putString("refresh_token", tokens.optString("refresh_token"))          // BUG 10
                .putString("id_token", tokens.optString("id_token"))
                .apply();
    }

    // =============================================================================================
    // BUG 11 — Client-side-only logout.
    //
    // WHY DEVELOPERS WRITE IT
    //   From the user's point of view it works perfectly: the app returns to the login screen.
    //   Nothing in the UI reveals that the refresh token is still valid on the server.
    //
    // DETECTION (dynamic)
    //   Capture tokens, log out in the UI, then use the access token against the API and the
    //   refresh token against /token. If either works, logout is cosmetic.
    //
    // EXPLOIT
    //   A token captured before logout keeps working. On a shared or lost device, "I logged out"
    //   is false.
    //
    // FIX
    //   POST the refresh token to the revocation_endpoint (RFC 7009), confirm the response, and
    //   also end the IdP browser session (OIDC RP-Initiated Logout) so the next login is not silent.
    //
    // SEVERITY  Medium, rising with token lifetime.
    // =============================================================================================
    public void logout() {
        getSharedPreferences("auth", MODE_PRIVATE).edit().clear().apply();              // BUG 11
        startActivity(new Intent(this, VulnerableOAuth.class));
        // No call to the revocation endpoint. The refresh token outlives the "logout" indefinitely.
    }

    // =============================================================================================
    // BUG 12 — The ROPC grant, kept "for the legacy login screen".
    //
    // WHY DEVELOPERS WRITE IT
    //   It looks simpler than the whole browser round trip, it keeps the branded login screen, and
    //   it was how the app worked before SSO was added. It is then never removed, because a small
    //   number of users still depend on it.
    //
    // DETECTION (static)
    //   grep -rn 'grant_type=password' out/sources/
    // DETECTION (server-side, faster)
    //   curl -s https://idp/.well-known/openid-configuration | jq .grant_types_supported
    //
    // EXPLOIT
    //   The app holds the user's identity-provider password in memory and sends it to an endpoint.
    //   Every protection OAuth exists to provide is gone: no MFA, no federation, no consent, and a
    //   compromise of this app is a compromise of the user's IdP credential everywhere.
    //
    // FIX
    //   Delete it. Migrate the remaining users. Disable `password` at the authorisation server so
    //   it cannot come back.
    //
    // SEVERITY  Critical.
    // =============================================================================================
    private void legacyLogin(String username, String password) {
        String body = "grant_type=password"                                             // BUG 12
                + "&username=" + username
                + "&password=" + password
                + "&client_id=" + CLIENT_ID
                + "&client_secret=" + CLIENT_SECRET;
        Http.post(TOKEN_ENDPOINT, body);
    }

    /** Placeholder for whatever HTTP client the app uses. */
    static class Http {
        static String post(String url, String body) { return "{}"; }
        static String get(String url, String header) { return "{}"; }
    }
}

/*
 * =================================================================================================
 * SUMMARY — the findings this file contains, and where the enforcement point is for each fix.
 * =================================================================================================
 *
 *  #  Bug                                   Severity   Enforcement point for the fix
 * --  ------------------------------------  ---------  ----------------------------------------
 *  1  Client secret in the APK              High       Delete; register as a public client (AS)
 *  2  Custom scheme redirect                Med/Crit   Platform (verified App Link) + AS (PKCE)
 *  3  WebView authorisation flow            High       Client architecture
 *  4  Predictable, unvalidated `state`      High       Client
 *  5  Over-scoping                          Medium     AS scope policy + client request
 *  6  Callback validates nothing            High       Client
 *  7  No PKCE at all                        High       Client sends it; SERVER MUST ENFORCE IT
 *  8  Tokens in logcat                      Medium     Client + build-time lint
 *  9  id_token decoded, not validated       Critical   Every consumer, including your backend
 * 10  Plaintext token storage               High       Client (Keystore) or a BFF
 * 11  Client-side-only logout               Medium     Server (revocation endpoint)
 * 12  ROPC grant                            Critical   AS configuration
 *
 * The row that decides the severity of row 2 is row 7's server half, and that half cannot be seen
 * from this file, from the APK, or from any static tool. Test it. See labs/lab-02.
 */
