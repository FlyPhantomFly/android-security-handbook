// examples/03-BrokenTokenStore.java
//
// PURPOSE
//   The Android-side companion to 01-broken-verifier.py. That file is what a SERVER gets
//   wrong; this is what an APP gets wrong. Both halves are needed, because a token
//   finding is almost never purely one or the other: a token stored badly is only worth
//   stealing because the server accepts a replay, and a server that accepts a replay only
//   matters because the token was reachable.
//
//   Every method below is a pattern taken from real Android code. None of it is a
//   strawman, and none of it looks wrong at review time — which is the point. The
//   annotations name the specific mistake and the chapter section that covers it.
//
//   Nine flaws, numbered to match README section 5 and cheatsheet.md:
//     F1  the id_token is decoded, not verified                        (section 5.1)
//     F2  the account is keyed on `email` from an unverified payload   (section 5.6)
//     F3  the refresh token is written to SharedPreferences in plain   (section 3.8)
//     F4  the "encryption" is a hardcoded AES key                      (34-Cryptography)
//     F5  the token is logged                                          (section 5.11)
//     F6  logout clears local state and never calls /revoke            (section 3.10)
//     F7  expiry is trusted from a client-side field, not from `exp`   (section 5.5)
//     F8  the id_token is sent to the API as a bearer credential       (section 5.6)
//     F9  the callback URI, containing the code, is forwarded onward   (45-OAuth 5.1)
//
// BUILD
//   This is a teaching fixture, not a module. It refers to Android classes and to
//   org.json, so it compiles inside an Android project (minSdk 21+) and not standalone.
//   To compile it for real, drop it into an app module's src/main/java/com/pentest/ch46/
//   and add `implementation "androidx.security:security-crypto:1.1.0-alpha06"` only if
//   you are also going to fix it — the broken version needs nothing.
//
//   It has NOT been compiled for this repository. 30-Activities/examples/build.sh shows
//   the no-Gradle route (aapt2 -> javac -> d8 -> zipalign -> apksigner) if you want a
//   real APK to instrument with scripts/token-hooks.js.
//
// WHAT THIS WILL NOT TELL YOU
//   * It will not tell you a real app is broken this way. Read the target's own code.
//   * Fixing every flaw here does not make an app secure; it makes it not-wrong in these
//     nine specific ways. The server side (02-correct-verifier.py) is the other half.
//
// SAFETY
//   Do not ship this. Do not copy a method out of it. It exists to be read beside
//   04-HardenedTokenStore.kt, which is the same class written correctly.
//
// Chapter 46 — Tokens

package com.pentest.ch46;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.util.Base64;
import android.util.Log;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class BrokenTokenStore {

    private static final String TAG = "TokenStore";
    private static final String PREFS = "auth";

    // ---------------------------------------------------------------------- //
    // FLAW 4. A hardcoded AES key, compiled into the APK.
    //
    // The developer's intent was good: they knew plaintext in SharedPreferences was
    // bad, so they encrypted it. But a key inside the APK is not a secret — it is a
    // published constant with an obfuscation budget. Every installation shares it, so
    // one extraction decrypts every user's token store on every device, from a laptop,
    // with no device access. See 45-OAuth section 1's warning: any byte sequence in an
    // APK is public, and the only variable is how many minutes it costs.
    //
    // It gets worse in a way that is easy to miss: because the key is the same
    // everywhere, encrypting with it does not even bind the ciphertext to the device.
    // A token store copied off phone A decrypts on phone B.
    //
    // 34-Cryptography section 5.2 catalogues this; 49-KeyStore section 1.3 explains
    // what the correct answer costs and, importantly, what it does NOT buy you.
    // ---------------------------------------------------------------------- //
    private static final byte[] KEY = "MySuperSecretKey".getBytes(StandardCharsets.UTF_8);

    private final SharedPreferences prefs;

    public BrokenTokenStore(Context context) {
        // FLAW 3. Ordinary SharedPreferences. On a stock, locked, unrooted device this
        // is genuinely protected by the sandbox and by file-based encryption, and it is
        // NOT automatically a finding — see README section 5.10 for the honest framing.
        // It becomes one when combined with a long-lived token, a rooted device in the
        // threat model, allowBackup, or a second copy somewhere reachable.
        this.prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    // ====================================================================== //
    // FLAW 1 and FLAW 2: reading identity out of an id_token without verifying it.
    //
    // This is the single most consequential mistake in the file, and the reason it is
    // written out in full rather than summarised. Read what it does:
    //
    //   * splits on "."          — correct
    //   * base64url-decodes [1]  — correct
    //   * parses the JSON        — correct
    //   * reads "email"          — correct
    //   * checks the signature   — NEVER
    //
    // Four of the five steps are right, which is exactly why it survives review. Anyone
    // holding a text editor can write a JSON object, base64url it, and put anything they
    // like in `email`. The signature is the only thing that would have stopped them, and
    // it was never consulted.
    //
    // The second flaw compounds it: even with a verified signature, `email` is the wrong
    // account key. It is mutable, it can be re-assigned by some providers, and it may be
    // unverified — there is a whole `email_verified` claim whose existence is the
    // admission. The account key is the PAIR (iss, sub), because `sub` is unique only
    // within its issuer.
    // ====================================================================== //
    public String userIdFromIdToken(String idToken) {
        try {
            String[] parts = idToken.split("\\.");
            String payload = new String(
                    Base64.decode(parts[1], Base64.URL_SAFE | Base64.NO_WRAP),
                    StandardCharsets.UTF_8);
            JSONObject claims = new JSONObject(payload);

            // Not one line of this examines parts[2].
            return claims.getString("email");
        } catch (Exception e) {
            Log.e(TAG, "could not parse id_token", e);
            return null;
        }
    }

    // ====================================================================== //
    // FLAW 5: the token in a log line.
    //
    // This is the most common way a token that was stored perfectly escapes anyway.
    // A log line is readable by anything holding READ_LOGS, by every crash reporter
    // linked into the app, and by anyone with adb. The `BuildConfig.DEBUG` guard that
    // usually wraps it is not the protection people think: it is stripped in release
    // by R8 only if the guard is written as a compile-time constant condition, and
    // plenty of code paths log unconditionally through a wrapper that R8 cannot see
    // through. See 40-Obfuscation for what actually gets removed.
    // ====================================================================== //
    public void saveTokens(String accessToken, String refreshToken, long expiresInSeconds) {
        Log.d(TAG, "saveTokens access=" + accessToken + " refresh=" + refreshToken);

        prefs.edit()
                // FLAW 3, exploited: plaintext.
                .putString("access_token", accessToken)
                .putString("refresh_token", refreshToken)
                // FLAW 7: a client-computed expiry, stored separately from the token.
                //
                // The token carries `exp` inside its signed payload, where it cannot be
                // altered. This field is a long in SharedPreferences, where it can be
                // altered by anything that can write the file — and by the app's own
                // clock being wrong. Worse, the app will now decide the token is still
                // valid based on this number and skip the refresh, then send an expired
                // token and handle the 401 as a network error.
                //
                // The correct source of truth for expiry is the `exp` claim, and the
                // correct authority on whether a token is still good is the server.
                .putLong("expires_at", System.currentTimeMillis() + expiresInSeconds * 1000)
                .apply();
    }

    // ====================================================================== //
    // FLAW 4, exploited. ECB, no IV, no authentication tag, hardcoded key.
    //
    // Four separate problems in one method call. ECB leaks structure — identical
    // plaintext blocks give identical ciphertext, so an attacker learns where the
    // repeated parts of a JWT are. No authentication means an attacker can flip
    // ciphertext bytes and the app will decrypt whatever comes out without noticing.
    // And the key is public. 34-Cryptography section 3.3 covers modes; the honest
    // summary is that this is obfuscation with a `javax.crypto` import.
    // ====================================================================== //
    public String encryptForStorage(String token) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"));
            return Base64.encodeToString(
                    cipher.doFinal(token.getBytes(StandardCharsets.UTF_8)),
                    Base64.NO_WRAP);
        } catch (Exception e) {
            // And on failure it stores the plaintext, which turns a crypto error into
            // a silent downgrade. Any exception handler that falls back to the insecure
            // path is worth grepping for in every codebase you review.
            Log.w(TAG, "encryption failed, storing plaintext", e);
            return token;
        }
    }

    // ====================================================================== //
    // FLAW 7, exploited: "is my token still good?" answered locally.
    // ====================================================================== //
    public boolean isLoggedIn() {
        return prefs.contains("access_token")
                && prefs.getLong("expires_at", 0) > System.currentTimeMillis();
    }

    // ====================================================================== //
    // FLAW 6: logout that only forgets.
    //
    // This method makes the UI show a login screen. It does nothing whatsoever to the
    // tokens themselves, which remain valid at the authorisation server and at every
    // resource server until they expire. If the refresh token has a 90-day lifetime and
    // no rotation, "logging out" on a shared or resold device leaves a 90-day credential
    // in place for anybody who recovered a copy — and, on many filesystems, the deleted
    // preference value itself is still on the flash.
    //
    // The user's mental model of "log out" is "my session is over". Delivering
    // "the screen changed" instead is the gap, and it is a finding you can demonstrate
    // in ninety seconds: capture the token, log out, replay the token, get a 200.
    // README section 3.10 covers revocation; RFC 7009 defines the endpoint that should
    // have been called here.
    // ====================================================================== //
    public void logout() {
        prefs.edit().clear().apply();
        // No POST to /revoke. No call to the app's own /logout. Nothing.
    }

    // ====================================================================== //
    // FLAW 8: sending the id_token to the API.
    //
    // The two tokens look identical — both are JWTs, both come back in the same JSON
    // response — and the id_token often has friendlier claims in it, so it gets picked.
    // But an id_token's `aud` is the CLIENT, not the resource server. Sending it to an
    // API means the API is accepting a token that was never minted for it, which means
    // the API cannot be checking `aud`, which means it will accept any token that issuer
    // signs, including one minted for an attacker's own registered client.
    //
    // 45-OAuth section 3.12 has the table; this line is what the mistake looks like.
    // ====================================================================== //
    public String authorizationHeader() {
        return "Bearer " + prefs.getString("id_token", "");
    }

    // ====================================================================== //
    // FLAW 9: forwarding the callback URI.
    //
    // The redirect that carries the authorisation code arrives as an Intent. Passing
    // that whole URI to another component — a WebView, an analytics call, a deep-link
    // router, a "share" intent — carries `code=` with it. Anything that logs the URI,
    // or any component that turns out to be exported, now has the code. 45-OAuth owns
    // the flow; the reason it appears here is that the artefact being leaked is a
    // credential, and credentials are this chapter's subject.
    // ====================================================================== //
    public void onCallback(Intent intent) {
        Uri uri = intent.getData();
        if (uri == null) {
            return;
        }
        Log.i(TAG, "callback: " + uri);                       // code=... in the log
        Intent next = new Intent("com.pentest.ch46.CONTINUE");
        next.putExtra("callback_uri", uri.toString());        // and passed onward
        // context.sendBroadcast(next);  <- an implicit broadcast carrying the code
    }
}
