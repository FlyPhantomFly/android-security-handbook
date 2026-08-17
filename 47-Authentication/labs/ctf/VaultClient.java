// 47-Authentication/labs/ctf/VaultClient.java
//
// ============================================================================
//  DELIBERATELY VULNERABLE CTF CLIENT - FOR STUDY ONLY
//  Install only on a device you own. Do not copy any of this into anything.
// ============================================================================
//
// PURPOSE
//   The Android client for the lab-04 CTF backend (vault_auth.py). It is the
//   source of FLAG 1, and it is provided as SOURCE rather than as an APK for
//   three reasons: this repository does not commit binaries, an APK you did not
//   build is an APK you should not install, and reading the source is the point.
//
//   YOU DO NOT HAVE TO BUILD IT. lab-04 ships `vault_prefs.xml`, a faithful
//   capture of exactly what this code writes to disk, so FLAG 1 is solvable
//   from the artefact alone. Building it is the better exercise; the artefact
//   exists so the CTF is not gated on a working Android toolchain.
//
// BUILD (optional)
//   The no-Gradle recipe used elsewhere in this repository works here:
//   aapt2 link -> javac --release 8 -> d8 -> zipalign -> apksigner, building
//   OUT OF TREE so no .apk/.dex/.class reaches the repository. See
//   30-Activities/examples/build.sh for a working implementation, including its
//   automatic fallback to `su -c 'pm install'` when a device returns
//   INSTALL_FAILED_USER_RESTRICTED.
//
// WHAT IS WRONG WITH IT
//   Four things, and only the first carries a flag. The other three are here so
//   that a player who reads this file learns to distinguish "a defect" from "a
//   defect that matters", which is the whole argument of chapter 47 section 5.

package com.pentest.ch47.vault;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;

import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class VaultClient {

    private static final String TAG  = "vault";
    // The emulator's alias for the host loopback. On a physical device use
    // `adb reverse tcp:9047 tcp:9047` and keep 127.0.0.1.
    private static final String BASE = "http://10.0.2.2:9047";

    // -----------------------------------------------------------------------
    // DEFECT 1  -  THE ONE THAT CARRIES FLAG 1
    // -----------------------------------------------------------------------
    //
    // The vault feature encrypts documents locally with a passphrase the user
    // types once. To support "stay signed in", the app writes that passphrase to
    // SharedPreferences so it can re-derive the key on the next cold start
    // without prompting.
    //
    // This is the [V2] defect of examples/01-VulnerableLogin.java in its most
    // damaging form: the stored value is not a revocable session credential, it
    // is a SECRET THE USER CHOSE, and users reuse secrets.
    //
    // The developer's reasoning was sound at every step and wrong at the end:
    //   "we need the key on next launch"  -> true
    //   "the key comes from the passphrase" -> true
    //   "so store the passphrase"          -> the mistake
    // The correct move is to store the KEY, wrapped by a Keystore key, and never
    // the passphrase - see 49-KeyStore, and examples/05-EnterpriseAuthSession.kt
    // for the auth-bound variant.
    //
    public static class VaultStore {

        private final SharedPreferences prefs;

        public VaultStore(Context ctx) {
            this.prefs = ctx.getSharedPreferences("vault_prefs", Context.MODE_PRIVATE);
        }

        public void rememberVault(String username, String passphrase, String token) {
            prefs.edit()
                 .putBoolean("is_unlocked", true)          // defect 2, below
                 .putString("username", username)
                 .putString("vault_passphrase", passphrase) // <-- FLAG 1
                 .putString("session_token", token)
                 .apply();
        }

        // ---------------------------------------------------------------
        // DEFECT 2  -  a local gate, and it is NOT worth a flag
        // ---------------------------------------------------------------
        //
        // `is_unlocked` gates the vault UI. Flipping it with one Frida hook, or
        // by editing the XML, gets you into the vault screen.
        //
        // AND IT GETS YOU NOTHING, because every document is fetched from the
        // server with the session token attached, and the server evaluates that
        // token independently. The screen renders empty.
        //
        // This is deliberately in the CTF as a DECOY. A player who reports it as
        // a critical bypass has made exactly the mistake README section 5.1's
        // severity table is about: the finding is Informational when the server
        // re-checks, and the way you find that out is to replay a request with
        // curl instead of admiring the UI.
        public boolean isUnlocked() {
            return prefs.getBoolean("is_unlocked", false);
        }

        public String token() {
            return prefs.getString("session_token", null);
        }
    }

    public static class UnlockActivity extends AppCompatActivity {

        private VaultStore store;

        @Override
        protected void onCreate(Bundle b) {
            super.onCreate(b);
            store = new VaultStore(this);

            // ---------------------------------------------------------------
            // DEFECT 3  -  no FLAG_SECURE on a screen that displays a secret
            // ---------------------------------------------------------------
            //
            // The vault screen renders document bodies, which include recovery
            // material. There is no
            //     getWindow().setFlags(FLAG_SECURE, FLAG_SECURE);
            // anywhere in this file.
            //
            // Note that you cannot find this by grepping the APK for
            // "FLAG_SECURE" - README section 3.10 proves the identifier is
            // inlined away by javac and never reaches the DEX. Confirm it with
            // `adb shell screencap` on the vault screen, or with the
            // Window.setFlags hook in scripts/auth-hooks.js.

            if (store.isUnlocked()) {
                startActivity(new Intent(this, VaultActivity.class));
                finish();
            }
        }

        private void unlock(String username, String passphrase) {
            new Thread(() -> {
                try {
                    JSONObject req = new JSONObject();
                    req.put("username", username);
                    req.put("password", passphrase);

                    // -----------------------------------------------------------
                    // DEFECT 4  -  the MFA branch is a client-side decision
                    // -----------------------------------------------------------
                    //
                    // The server returns {"mfa_required": true, "mfa_token": ...}
                    // and this code correctly shows the OTP screen.
                    //
                    // The bug is NOT here. It is on the server, which never checks
                    // what that token was issued FOR. Nothing you change in this
                    // file fixes it, and nothing you change in this file is needed
                    // to exploit it - the token works from curl.
                    //
                    // That is FLAG 3, and it is a server finding reached through a
                    // mobile client.
                    JSONObject res = post("/api/v1/login", req, null);

                    if (res.optBoolean("mfa_required", false)) {
                        startActivity(new Intent(this, OtpActivity.class)
                                .putExtra("mfa_token", res.optString("mfa_token")));
                        return;
                    }

                    if (res.optBoolean("ok", false)) {
                        store.rememberVault(username, passphrase, res.optString("token"));
                        startActivity(new Intent(this, VaultActivity.class));
                        finish();
                    }
                } catch (Exception e) {
                    Log.e(TAG, "unlock failed", e);
                }
            }).start();
        }
    }

    public static class VaultActivity extends AppCompatActivity { }

    public static class OtpActivity extends AppCompatActivity { }

    /**
     * The "close my account" button.
     *
     * It calls the server, receives "Your account has been closed and your data
     * deleted", clears local state, and returns the user to the sign-in screen.
     * From inside the product the feature works perfectly.
     *
     * FLAG 4 is what the server actually did.
     */
    public static class SettingsActivity extends AppCompatActivity {
        private void closeAccount(String token) {
            new Thread(() -> {
                try {
                    JSONObject r = post("/api/v1/account/close", new JSONObject(), token);
                    Log.i(TAG, "close -> " + r);
                    getSharedPreferences("vault_prefs", Context.MODE_PRIVATE)
                            .edit().clear().apply();
                } catch (Exception e) {
                    Log.e(TAG, "close failed", e);
                }
            }).start();
        }
    }

    // -----------------------------------------------------------------------

    private static JSONObject post(String path, JSONObject body, String token)
            throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(BASE + path).openConnection();
        c.setRequestMethod("POST");
        c.setRequestProperty("Content-Type", "application/json");
        if (token != null) {
            c.setRequestProperty("Authorization", "Bearer " + token);
        }
        c.setDoOutput(true);
        try (OutputStream os = c.getOutputStream()) {
            os.write(body.toString().getBytes(StandardCharsets.UTF_8));
        }
        StringBuilder sb = new StringBuilder();
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(c.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line);
            }
        }
        return new JSONObject(sb.toString());
    }
}
