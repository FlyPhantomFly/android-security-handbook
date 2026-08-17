// 47-Authentication/examples/01-VulnerableLogin.java
//
// ============================================================================
//  DELIBERATELY VULNERABLE - FOR STUDY ONLY
//  Do not copy any part of this into a real application.
//  Install only on a device you own. See labs/README-safety in the labs folder.
// ============================================================================
//
// PURPOSE
//   The canonical Android client-side authentication gate, written the way it is
//   actually written in the field: not carelessly, but by a competent developer
//   applying a mental model that works on the web and does not work here.
//
//   It contains SEVEN distinct defects, numbered [V1]..[V7] in the comments.
//   README.md section 9.1 walks through them; labs/lab-01 asks you to find them
//   before reading that list.
//
// HOW TO READ IT
//   Every defect is a decision that made the app work. Ask, for each one, what
//   the developer was trying to achieve. That is the only way to learn to
//   recognise the pattern rather than the code.
//
// BUILD
//   This is an excerpt-shaped single file, not a complete project. It compiles
//   against the Android SDK plus AndroidX AppCompat as part of the lab app in
//   labs/authlab/. It is presented as one file so the whole defect set is
//   visible at once.

package com.pentest.ch47.vulnerable;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class VulnerableLogin {

    private static final String TAG  = "ch47";
    private static final String BASE = "https://api.vulnbank.example.invalid";

    // -----------------------------------------------------------------------
    // The session store. Everything wrong with this design is visible here.
    // -----------------------------------------------------------------------
    public static class SessionManager {

        private final SharedPreferences prefs;

        public SessionManager(Context ctx) {
            this.prefs = ctx.getSharedPreferences("app_prefs", Context.MODE_PRIVATE);
        }

        // [V1] THE GATE.
        //
        // A boolean on disk IS the authentication decision. Anything that can
        // write this file - root, an ADB backup restore, `run-as` on a debuggable
        // build, or one Frida hook on SharedPreferencesImpl.getBoolean - becomes
        // an authenticated user as far as this app is concerned.
        //
        // Why it gets written: it is the shortest code that produces the right
        // user experience, and on a server-rendered web app the equivalent check
        // genuinely does gate the data.
        public boolean isLoggedIn() {
            return prefs.getBoolean("is_logged_in", false);
        }

        // [V2] THE PASSWORD IS PERSISTED.
        //
        // The product requirement was "keep me signed in". The password is what
        // the developer had in hand at that moment, and re-sending it on the next
        // launch works. But a password is a credential the USER owns and reuses
        // across services; a session token is a credential the SERVICE owns and
        // can destroy. Persistent login must only ever store the second kind.
        public void persist(String username, String password, String token) {
            prefs.edit()
                 .putBoolean("is_logged_in", true)
                 .putString("username", username)
                 .putString("password", password)          // <-- V2
                 .putString("auth_token", token)
                 .apply();
        }

        // [V3] LOGOUT IS LOCAL ONLY.
        //
        // The app genuinely forgets the credential. The SERVER is never told, so
        // the token keeps working for its full lifetime. Every functional test
        // passes; the defect is invisible from inside the product.
        public void logout() {
            prefs.edit().clear().apply();
        }

        public String token() {
            return prefs.getString("auth_token", null);
        }
    }

    // -----------------------------------------------------------------------
    // The login screen.
    // -----------------------------------------------------------------------
    public static class LoginActivity extends AppCompatActivity {

        private SessionManager session;

        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            // setContentView(R.layout.activity_login);
            session = new SessionManager(this);

            // [V4] NO FLAG_SECURE ON A CREDENTIAL SCREEN.
            //
            // Note that there is nothing here to grep for. The DEFECT is an
            // ABSENCE, and README section 3.10 proves that the presence cannot be
            // detected by a string scan either - FLAG_SECURE is a compile-time
            // constant that javac inlines away. This is why the detection in
            // section 7.4 is a runtime hook on Window.setFlags.
            //
            // The fix would be, in onCreate BEFORE the window is drawn:
            //   getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
            //                        WindowManager.LayoutParams.FLAG_SECURE);
        }

        private void onSignInClicked(EditText userField, EditText passField) {
            // [V5] THE PASSWORD BECOMES AN IMMUTABLE String.
            //
            // A String cannot be erased; it lives on the heap until a GC cycle
            // chooses to reclaim it, and chapter 19 measured that freed memory on
            // Android is NOT zeroed and that there is NO allocator quarantine. The
            // Editable returned by getText() exists precisely so you can clear it.
            String user = userField.getText().toString();
            String pass = passField.getText().toString();

            new Thread(() -> doLogin(user, pass)).start();
        }

        private void doLogin(String user, String pass) {
            try {
                JSONObject body = new JSONObject();
                body.put("username", user);
                body.put("password", pass);

                // [V6] THE CREDENTIAL IS LOGGED.
                //
                // A debug branch that shipped, or an HTTP logging interceptor left
                // at BODY level in a release build. This is the single most common
                // real credential leak in Android applications, and it is found in
                // one command: `adb logcat | grep -i password`.
                Log.d(TAG, "login request body=" + body.toString());

                JSONObject response = postJson(BASE + "/api/v1/login", body, null);

                // [V7] THE CLIENT DECIDES WHETHER MFA HAPPENED.
                //
                // The server correctly said "MFA is required" - and issued a usable
                // session token in the same response. So the branch below is
                // ADVISORY. One proxy rule rewriting true to false, or one Frida
                // hook on this field, and the second factor never happens.
                //
                // The correct design: the pre-MFA response carries a token scoped
                // to exactly one operation (verify_mfa) and nothing else.
                if (response.optBoolean("mfa_required", false)) {
                    startActivity(new Intent(this, OtpActivity.class)
                            .putExtra("token", response.optString("token")));
                    return;
                }

                if (response.optBoolean("ok", false)) {
                    session.persist(user, pass, response.optString("token"));
                    startActivity(new Intent(this, DashboardActivity.class));
                    finish();
                } else {
                    runOnUiThread(() ->
                        // The error message is passed straight through from the
                        // server. If the server distinguishes "no such user" from
                        // "wrong password", this screen is the enumeration oracle.
                        Toast.makeText(this, response.optString("error"),
                                       Toast.LENGTH_SHORT).show());
                }
            } catch (Exception e) {
                Log.e(TAG, "login failed", e);
            }
        }
    }

    // -----------------------------------------------------------------------
    // The screen the gate is supposed to protect.
    // -----------------------------------------------------------------------
    public static class DashboardActivity extends AppCompatActivity {

        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            SessionManager session = new SessionManager(this);

            // The gate, again. Note what it does NOT do: it does not ask the
            // server anything. The question "am I logged in?" is answered
            // entirely on the attacker's own device.
            if (!session.isLoggedIn()) {
                startActivity(new Intent(this, LoginActivity.class));
                finish();
                return;
            }
            loadDashboard(session.token());
        }

        private void loadDashboard(String token) {
            // Whether this is a REAL vulnerability or merely a UI bypass depends
            // entirely on what the server does with a request bearing no token,
            // or a token belonging to a different user. That is the test in
            // README section 7.1 step 2, and it is the one that sets the severity.
            new Thread(() -> {
                try {
                    JSONObject r = postJson(BASE + "/api/v1/dashboard",
                                            new JSONObject(), token);
                    Log.d(TAG, "dashboard=" + r);
                } catch (Exception e) {
                    Log.e(TAG, "dashboard failed", e);
                }
            }).start();
        }
    }

    public static class OtpActivity extends AppCompatActivity {

        @Override
        protected void onCreate(Bundle b) {
            super.onCreate(b);
            // The worst variant, and it is not rare: the server returned the code
            // so the app can validate it offline for instant feedback. Anyone who
            // can read one HTTP response owns every account whose email they know.
            //
            //   String expected = getIntent().getStringExtra("code");
            //   if (entered.equals(expected)) { grantSession(); }
            //
            // See README section 5.6, flaws 1 and 2.
        }
    }

    // -----------------------------------------------------------------------
    // Minimal HTTP helper - not the point of the example, included so the file
    // is self-contained and readable.
    // -----------------------------------------------------------------------
    private static JSONObject postJson(String url, JSONObject body, String token)
            throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
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
