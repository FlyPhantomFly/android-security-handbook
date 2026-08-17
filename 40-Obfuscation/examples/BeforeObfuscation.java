/*
 * BeforeObfuscation.java
 * ===========================================================================
 * WHAT THIS IS
 *   The "before" half of a before/after pair. This is ordinary, readable
 *   application source, deliberately written to exercise every technique in
 *   chapter 40 section 3 so that AfterObfuscation.java can show you what each
 *   one does to it.
 *
 *   Read this file first. Then read AfterObfuscation.java side by side with
 *   it. The comparison is the point; neither file teaches much alone.
 *
 * WHY IT MATTERS
 *   Compiled Java retains an extraordinary amount of source information. The
 *   DEX format inherits, from the .class format, the fully qualified class
 *   name, every field name, every method name, every parameter type, the
 *   generic signature, and — with debug info enabled, which is the default —
 *   the original source filename and a line-number table.
 *
 *   Decompiling an unobfuscated Android app therefore produces something very
 *   close to the original source. That is the problem obfuscation was invented
 *   to address, and this file is what that problem looks like.
 *
 *   The other half of the lesson is what obfuscation CANNOT remove. Every
 *   string constant below survives every renaming pass ever written, and after
 *   renaming those strings are the only remaining semantics in the program.
 *   That is why the methodology recovers strings first.
 *
 * HOW TO USE IT
 *   # host — build it twice and compare
 *   ./gradlew assembleDebug                       # minifyEnabled false
 *   ./gradlew assembleRelease                     # minifyEnabled true
 *   jadx -d out_debug   app-debug.apk
 *   jadx -d out_release app-release.apk
 *   diff -r out_debug/sources out_release/sources | head -50
 *
 *   Then apply the string encryption from StringEncryption.java and diff
 *   again. Then flatten classifyRisk() by hand and diff again. Each step is a
 *   row in the cost table in section 1.
 *
 * REQUIREMENTS
 *   Android Gradle Plugin with R8 available. Nothing else.
 *
 * AUTHORISED TESTING ONLY — this is teaching material for chapter 40.
 * ===========================================================================
 */

package com.obflab.demo;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class PaymentService {

    // -----------------------------------------------------------------------
    // Constants.
    //
    // EVERY ONE of these strings survives identifier renaming untouched. R8
    // renames the class to `a` and the methods to `a`, `b`, `c` — and leaves
    // this block byte-for-byte intact in the DEX string pool.
    //
    // That is why `strings classes.dex | grep https` is the second command you
    // run on any target, and why an app with ZERO URLs in its string pool is
    // announcing that it encrypts them.
    // -----------------------------------------------------------------------

    private static final String TAG = "PaymentService";

    private static final String BASE_URL      = "https://api.obflab.example.com/v2";
    private static final String LOGIN_PATH    = "/auth/login";
    private static final String TRANSFER_PATH = "/payments/transfer";
    private static final String BALANCE_PATH  = "/accounts/balance";

    // A hardcoded credential. Obfuscating this is NOT a remediation; see the
    // Pentester's Note in section 1 of the chapter.
    private static final String API_KEY = "sk_live_EXAMPLE_NOT_A_REAL_KEY_ch40";

    private static final String PREFS_NAME    = "payment_prefs";
    private static final String KEY_AUTH      = "auth_token";
    private static final String KEY_DEVICE_ID = "device_id";

    private static final String CIPHER_SPEC = "AES/CBC/PKCS5Padding";
    private static final String KEY_ALGO    = "AES";
    private static final String HASH_ALGO   = "SHA-256";

    private final Context context;
    private final SharedPreferences prefs;

    public PaymentService(Context context) {
        this.context = context.getApplicationContext();
        this.prefs = this.context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    // -----------------------------------------------------------------------
    // Ordinary network code.
    //
    // After renaming, `login` becomes `a` — but the string "/auth/login" is
    // still right there in the method body, so you can rename it back with
    // complete confidence. Section 6.1 Phase 6.
    // -----------------------------------------------------------------------

    public String login(String username, String password) {
        try {
            JSONObject body = new JSONObject();
            body.put("username", username);
            body.put("password", password);
            body.put("device_id", getOrCreateDeviceId());

            String response = post(BASE_URL + LOGIN_PATH, body.toString());
            if (response == null) return null;

            JSONObject parsed = new JSONObject(response);
            String token = parsed.optString("access_token", null);
            if (token != null) {
                prefs.edit().putString(KEY_AUTH, token).apply();
            }
            return token;
        } catch (Exception e) {
            Log.w(TAG, "login failed", e);
            return null;
        }
    }

    public boolean transfer(String destinationAccount, long amountMinorUnits) {
        try {
            JSONObject body = new JSONObject();
            body.put("to", destinationAccount);
            body.put("amount", amountMinorUnits);
            body.put("signature", signRequest(destinationAccount, amountMinorUnits));

            String response = post(BASE_URL + TRANSFER_PATH, body.toString());
            return response != null && new JSONObject(response).optBoolean("ok", false);
        } catch (Exception e) {
            Log.w(TAG, "transfer failed", e);
            return false;
        }
    }

    public long balanceMinorUnits() {
        try {
            String response = get(BASE_URL + BALANCE_PATH);
            if (response == null) return -1L;
            return new JSONObject(response).optLong("balance_minor", -1L);
        } catch (Exception e) {
            return -1L;
        }
    }

    // -----------------------------------------------------------------------
    // Control flow worth flattening.
    //
    // This is the method AfterObfuscation.java shows flattened. Note how
    // readable it is now: nested ifs, an early return, one loop, a clear
    // relationship between the branches. Flattening destroys the ORDER and
    // leaves every one of these blocks intact but scattered.
    // -----------------------------------------------------------------------

    public String classifyRisk(int score, boolean newDevice, int recentFailures) {
        if (score < 0) {
            return "invalid";
        }

        String band;
        if (score < 30) {
            band = "high";
        } else if (score < 70) {
            band = "medium";
        } else {
            band = "low";
        }

        if (newDevice && !"low".equals(band)) {
            band = "high";
        }

        for (int i = 0; i < recentFailures; i++) {
            if ("low".equals(band)) {
                band = "medium";
            } else if ("medium".equals(band)) {
                band = "high";
            }
        }

        return band.toUpperCase();
    }

    // -----------------------------------------------------------------------
    // Crypto.
    //
    // Direct API calls. AfterObfuscation.java shows the same logic routed
    // through reflection, which removes the static cross-references — and
    // replaces them with strings, which survive renaming, which is why
    // reflection is opaque to static analysis and transparent to dynamic
    // analysis (section 3.4).
    // -----------------------------------------------------------------------

    private String signRequest(String destination, long amount) throws Exception {
        byte[] key = deriveKey(getAuthToken());

        MessageDigest md = MessageDigest.getInstance(HASH_ALGO);
        md.update(destination.getBytes("UTF-8"));
        md.update(Long.toString(amount).getBytes("UTF-8"));
        md.update(key);

        return toHex(md.digest());
    }

    private byte[] deriveKey(String token) throws Exception {
        MessageDigest md = MessageDigest.getInstance(HASH_ALGO);
        md.update(token == null ? new byte[0] : token.getBytes("UTF-8"));
        md.update(API_KEY.getBytes("UTF-8"));
        byte[] full = md.digest();
        byte[] key = new byte[16];
        System.arraycopy(full, 0, key, 0, 16);
        return key;
    }

    public byte[] encryptLocal(byte[] plaintext, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_SPEC);
        cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(deriveKey(getAuthToken()), KEY_ALGO),
                    new IvParameterSpec(iv));
        return cipher.doFinal(plaintext);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private String getAuthToken() {
        return prefs.getString(KEY_AUTH, null);
    }

    private String getOrCreateDeviceId() {
        String id = prefs.getString(KEY_DEVICE_ID, null);
        if (id == null) {
            id = java.util.UUID.randomUUID().toString();
            prefs.edit().putString(KEY_DEVICE_ID, id).apply();
        }
        return id;
    }

    private String post(String urlString, String body) {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(urlString).openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Authorization", "Bearer " + API_KEY);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            OutputStream os = conn.getOutputStream();
            os.write(body.getBytes("UTF-8"));
            os.close();

            return readAll(conn);
        } catch (Exception e) {
            Log.w(TAG, "post failed: " + urlString, e);
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private String get(String urlString) {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(urlString).openConnection();
            conn.setRequestProperty("Authorization", "Bearer " + API_KEY);
            return readAll(conn);
        } catch (Exception e) {
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private String readAll(HttpURLConnection conn) throws Exception {
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), "UTF-8"));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        reader.close();
        return sb.toString();
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // A small model class.
    //
    // Note the Parcelable-style CREATOR field and the annotation: both are in
    // the survivors list. A serialisation library's annotations carry the
    // ORIGINAL field names into the compiled output, which frequently means a
    // heavily obfuscated app hands you its data model for free.
    // -----------------------------------------------------------------------

    public static final class Transaction {
        public final String id;
        public final long amountMinorUnits;
        public final String counterparty;

        public Transaction(String id, long amountMinorUnits, String counterparty) {
            this.id = id;
            this.amountMinorUnits = amountMinorUnits;
            this.counterparty = counterparty;
        }

        public JSONObject toJson() throws Exception {
            JSONObject o = new JSONObject();
            o.put("id", id);
            o.put("amount_minor", amountMinorUnits);
            o.put("counterparty", counterparty);
            return o;
        }
    }

    public List<Transaction> recentTransactions() {
        List<Transaction> out = new ArrayList<>();
        String response = get(BASE_URL + "/accounts/transactions?limit=20");
        if (response == null) return out;
        try {
            org.json.JSONArray arr = new org.json.JSONArray(response);
            for (int i = 0; i < arr.length(); i++) {
                JSONObject o = arr.getJSONObject(i);
                out.add(new Transaction(o.getString("id"),
                                        o.getLong("amount_minor"),
                                        o.getString("counterparty")));
            }
        } catch (Exception e) {
            Log.w(TAG, "parse failed", e);
        }
        return out;
    }
}

/*
 * ===========================================================================
 * WHAT AN ANALYST GETS FROM THIS FILE, UNOBFUSCATED
 *
 *   - Every class, method and field name, verbatim.
 *   - Every endpoint.
 *   - The credential.
 *   - The exact cipher configuration and key derivation.
 *   - The complete risk-classification logic.
 *   - The data model, including the server's JSON field names.
 *
 *   Time to acquire all of that: about five minutes with jadx-gui.
 *
 * WHAT REMAINS AFTER R8 RENAMING
 *
 *   Everything in the list above EXCEPT the names. All of the strings, all of
 *   the framework calls, the manifest-declared entry points, and the structure
 *   are unchanged. An analyst renames from the strings and is back to the same
 *   understanding in an hour or two.
 *
 * WHAT REMAINS AFTER RENAMING PLUS STRING ENCRYPTION
 *
 *   The structure and the framework calls. That is a genuinely large step: it
 *   is the difference between "grep for the endpoint" and "instrument the
 *   process". Half a day, not five minutes — and then it collapses back to the
 *   previous row, because one script recovers all the strings at once.
 *
 * See AfterObfuscation.java for each of those states rendered as code.
 * ===========================================================================
 */
