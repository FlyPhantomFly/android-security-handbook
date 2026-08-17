# Lab 02 — The false-positive gauntlet

> **Objective.** Work a queue of **27 leads** in which **20 are wrong**, and reject each of them
> correctly, with a reason. You are scored on the rejections, not on the findings.

**Difficulty:** intermediate. This is the lab this chapter exists for.
**Time:** 90 minutes to work it honestly. Twenty minutes if you cheat, and you will score badly.
**Prerequisites:** [Lab 01](lab-01-first-static-pass.md). `bash`, `python3`, `base64`. No device, no
APK, no internet — the lab builds its own tree.

---

## 0. Why this lab exists

Every measurement in this repository points the same way:

| Measurement | Source |
|---|---|
| 132 high-confidence secret hits on real Chrome data; **132 false positives** | [33-Storage](../../33-Storage/README.md) |
| 15 of 17 high-confidence leads rejected on a real commercial app (**88%**) | [README §9.4](../README.md#94-real-application--the-false-positive-arithmetic-measured) |
| 12 of 14 apps present a pinning surface; **4** actually pin | [36-CertificatePinning](../../36-CertificatePinning/README.md) |
| 136 of 137 `password` hits are library or generated code | [README §3.4](../README.md#34-stage-4--enumerate) |

Finding things is not the hard part. **Correctly not-reporting things is the hard part**, and it is
almost never taught, because a lab that ends in "you were right to ignore that" feels
anticlimactic. This one ends there twenty times.

---

## 1. Build the tree

Save the following as `build-gauntlet.sh` and run it. It creates a 19-file decompiled-style tree
under `./out` — a small application with eleven of its own classes and five bundled library classes.

```bash
#!/usr/bin/env bash
# build-gauntlet.sh -- create the Lab 02 practice tree.
# Run:  bash build-gauntlet.sh        (creates ./out)
set -eu
rm -rf out
mk() { mkdir -p "$(dirname "$1")"; cat > "$1"; }

mk out/resources/AndroidManifest.xml <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.gauntlet.app"
    android:versionCode="42" android:versionName="4.2.0">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <application
        android:label="@string/app_name"
        android:debuggable="false"
        android:allowBackup="true"
        android:networkSecurityConfig="@xml/network_security_config">
        <activity android:name="com.gauntlet.app.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity android:name="com.gauntlet.app.web.HelpActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="gauntlet" android:host="help"/>
            </intent-filter>
        </activity>
        <service android:name="com.gauntlet.app.sync.SyncService" android:exported="false"/>
    </application>
</manifest>
EOF

mk out/resources/res/values/strings.xml <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Gauntlet</string>
    <string name="maps_api_key">AIzaSy.EXAMPLE.NOT.A.REAL.KEY.ch52a</string>
    <string name="support_url">https://support.gauntlet.example/help</string>
</resources>
EOF

mk out/resources/res/xml/network_security_config.xml <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false"/>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">api-internal.gauntlet.example</domain>
    </domain-config>
</network-security-config>
EOF

mk out/sources/com/gauntlet/app/BuildConfig.java <<'EOF'
package com.gauntlet.app;
public final class BuildConfig {
    public static final boolean DEBUG = false;
    public static final String BUILD_SHA = "9f2c4a1d8e5b7c3f0a6d2e9b4c8f1a7d3e5b9c02";
    public static final String VERSION_NAME = "4.2.0";
}
EOF

mk out/sources/com/gauntlet/app/pay/PaymentClient.java <<'EOF'
package com.gauntlet.app.pay;

import okhttp3.OkHttpClient;
import okhttp3.Request;

public final class PaymentClient {
    private static final String SECRET_KEY = "sk_live_EXAMPLE_NOT_A_REAL_KEY_ch52QR";
    private final OkHttpClient client = new OkHttpClient();

    public String charge(String amountMinor, String currency) throws Exception {
        Request req = new Request.Builder()
            .url("https://api.stripe.com/v1/charges")
            .addHeader("Authorization", "Bearer " + SECRET_KEY)
            .build();
        return client.newCall(req).execute().body().string();
    }
}
EOF

mk out/sources/com/gauntlet/app/crypto/Vault.java <<'EOF'
package com.gauntlet.app.crypto;

import android.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class Vault {
    private static final String KEY_B64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU=";
    private static final String WELCOME = "V2VsY29tZSB0byB0aGUgR2F1bnRsZXQgYXBwbGljYXRpb24h";

    public byte[] seal(byte[] plain) throws Exception {
        SecretKeySpec key = new SecretKeySpec(Base64.decode(KEY_B64, 0), "AES");
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec("0123456789abcdef".getBytes()));
        return c.doFinal(plain);
    }

    public String banner() {
        return new String(Base64.decode(WELCOME, 0));
    }
}
EOF

mk out/sources/com/gauntlet/app/api/Endpoints.java <<'EOF'
package com.gauntlet.app.api;

public enum Endpoints {
    PRODUCTION("https://api.gauntlet.example"),
    STAGING("https://staging.gauntlet-internal.example"),
    QA1("https://qa1.qa.gauntlet-internal.example"),
    QA2("https://qa2.qa.gauntlet-internal.example"),
    TELEMETRY("http://api-internal.gauntlet.example/v1/events");

    private final String baseUrl;
    Endpoints(String baseUrl) { this.baseUrl = baseUrl; }
    public String base() { return baseUrl; }
}
EOF

mk out/sources/com/gauntlet/app/net/LegacyTrust.java <<'EOF'
package com.gauntlet.app.net;

import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

public final class LegacyTrust implements X509TrustManager {
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
EOF

mk out/sources/com/gauntlet/app/web/HelpActivity.java <<'EOF'
package com.gauntlet.app.web;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;

public final class HelpActivity extends Activity {
    private WebView web;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        web = new WebView(this);
        web.getSettings().setJavaScriptEnabled(true);
        web.addJavascriptInterface(new HelpBridge(this), "AndroidHelp");
        String target = getIntent().getStringExtra("url");
        web.loadUrl(target != null ? target : "https://support.gauntlet.example/help");
        setContentView(web);
    }
}
EOF

mk out/sources/com/gauntlet/app/legacy/OldPrefs.java <<'EOF'
package com.gauntlet.app.legacy;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;

public final class OldPrefs {
    public static SharedPreferences open(Context ctx) {
        if (Build.VERSION.SDK_INT < 17) {
            return ctx.getSharedPreferences("legacy", Context.MODE_WORLD_READABLE);
        }
        return ctx.getSharedPreferences("legacy", Context.MODE_PRIVATE);
    }
}
EOF

mk out/sources/com/gauntlet/app/goals/KeyResultTracker.java <<'EOF'
package com.gauntlet.app.goals;

import android.os.Bundle;

public final class KeyResultTracker {
    public void trackProgress(String itemId, float value) {
        Bundle bundle = new Bundle();
        bundle.putString("key result type", "Range");
        bundle.putString("key_result_id", itemId);
        analytics().logEvent("goal_key_result_progress", bundle);
    }
}
EOF

mk out/sources/com/gauntlet/app/debug/DebugConfig.java <<'EOF'
package com.gauntlet.app.debug;

import com.gauntlet.app.BuildConfig;

public final class DebugConfig {
    private static final String EMULATOR_HOST = "10.0.2.2";

    public static String backendFor(String flavour) {
        if (BuildConfig.DEBUG) {
            return "http://" + EMULATOR_HOST + ":8080/";
        }
        return "https://api.gauntlet.example";
    }

    // TODO: remove the hardcoded token before shipping -- ticket GAU-4471
}
EOF

mk out/sources/com/gauntlet/app/sync/SyncService.java <<'EOF'
package com.gauntlet.app.sync;

import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.IBinder;

public final class SyncService extends Service {
    private final BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override public void onReceive(android.content.Context c, Intent i) { }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        IntentFilter f = new IntentFilter();
        f.addAction("com.gauntlet.app.SYNC_NOW");
        f.addAction(Intent.ACTION_POWER_CONNECTED);
        registerReceiver(receiver, f);
        try {
            Class.forName("com.gauntlet.app.sync.OptionalUploader")
                 .getDeclaredMethod("start")
                 .invoke(null);
        } catch (Exception ignored) { }
    }

    @Override public IBinder onBind(Intent intent) { return null; }
}
EOF

mk 'out/sources/com/gauntlet/app/ui/ComposableSingletons$HelpScreenKt.java' <<'EOF'
package com.gauntlet.app.ui;

public final class ComposableSingletons$HelpScreenKt {
    public static final String PREVIEW_AVATAR = "http://test.com/avatar.png";
    public static final String PREVIEW_BODY = "http://www.google.com/lol";
    public static final String PREVIEW_USER = "Test User";
}
EOF

mk out/sources/androidx/appcompat/widget/SearchView.java <<'EOF'
package androidx.appcompat.widget;

public class SearchView {
    private static final String LOG_TAG = "SearchView";

    private void updateInputType(int inputType) {
        if ((inputType & 0x00000080) != 0) {
            android.util.Log.d(LOG_TAG, "password input type detected: " + inputType);
        }
    }
}
EOF

mk out/sources/androidx/core/graphics/CacheKey.java <<'EOF'
package androidx.core.graphics;

import java.security.MessageDigest;

public final class CacheKey {
    public static String of(String url) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new String(md.digest(url.getBytes()));
    }
}
EOF

mk out/sources/okhttp3/internal/tls/OkHostnameVerifier.java <<'EOF'
package okhttp3.internal.tls;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public final class OkHostnameVerifier implements HostnameVerifier {
    @Override
    public boolean verify(String host, SSLSession session) {
        return verifyHostname(host, session) || verifyIpAddress(host, session);
    }
}
EOF

mk out/sources/okhttp3/CertificatePinner.java <<'EOF'
package okhttp3;

public final class CertificatePinner {
    public static final CertificatePinner DEFAULT = new Builder().build();
    public static final class Builder {
        public Builder add(String pattern, String... pins) { return this; }
        public CertificatePinner build() { return new CertificatePinner(); }
    }
}
EOF

mk out/sources/org/slf4j/impl/StaticLoggerBinder.java <<'EOF'
package org.slf4j.impl;

public final class StaticLoggerBinder {
    private static final String HELP = "http://www.slf4j.org/codes.html#StaticLoggerBinder";
    private static final String MISMATCH = "http://www.slf4j.org/codes.html#loggerNameMismatch";
    private static final String MULTI = "http://www.slf4j.org/codes.html#multiple_bindings";
}
EOF

echo "tree built: $(find out -type f | wc -l) files"
```

```bash
# host
bash build-gauntlet.sh
# tree built: 19 files
```

> **Everything in this tree is invented.** The Stripe key, the Google API key and the hostnames are
> fabricated and resolve to nothing. Do not paste any of them into a real service.

---

## 2. Sweep it

```bash
# host
python3 -B ../scripts/static-sweep.py ./out | tee sweep.txt
```

You should get exactly this header:

```
  files scanned      19   (0 unreadable or over the size cap)
      app            11
      third-party    5
      generated      1
      resource       2
  raw hits           41
  killed by a rule's own validator  5
  distinct leads     28
  shown here         27   (min-confidence 0.00)
  demoted as noise   1
  blind-spot notices 2
```

If your numbers differ, your catalogue differs — check `--print-catalogue`.

Note the aggregation ratio here is only **1.5×**, against 816× on a real app. That is deliberate:
this tree has no framework bulk, so nothing collapses. **This lab is about the other half of triage.**

---

## 3. The queue

Twenty-seven leads. Here they are, exactly as the tool ranked them:

| ID | Conf | Rule | Value |
|---|---|---|---|
| L001 | 0.95 | CRED-04 | `sk_live_EXAMPLE_NOT_A_REAL_KEY_ch52…` |
| L002 | 0.95 | CRY-02 | IV constructed from a literal |
| L003 | 0.95 | NET-01 | `http://api-internal.gauntlet.example/v1/events` |
| L004 | 0.95 | NET-01 | `http://test.com/avatar.png` |
| L005 | 0.95 | NET-01 | `http://www.google.com/lol` |
| L006 | 0.95 | STO-04 | WebView JavaScript bridge |
| L007 | 0.90 | STO-01 | world-accessible file mode constant |
| L008 | 0.90 | TLS-01 | custom TrustManager |
| L009 | 0.90 | TLS-04 | pinning surface present |
| L010 | 0.75 | CRED-09 | `QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU=` |
| L011 | 0.75 | CRED-09 | `V2VsY29tZSB0byB0aGUgR2F1bnRsZXQgYXBwbGljYXRpb24h` |
| L012 | 0.75 | NET-02 | `https://api.stripe.com/v1/charges` |
| L013 | 0.75 | NET-02 | `https://qa1.qa.gauntlet-internal.example` |
| L014 | 0.75 | NET-02 | `https://qa2.qa.gauntlet-internal.example` |
| L015 | 0.75 | NET-02 | `https://staging.gauntlet-internal.example` |
| L016 | 0.75 | NET-03 | `10.0.2.2` |
| L017 | 0.65 | CRED-03 | `AIzaSy.EXAMPLE.NOT.A.REAL.KEY.ch52a` |
| L018 | 0.65 | NET-02 | `https://api.gauntlet.example` |
| L019 | 0.60 | DBG-03 | developer note left in shipped code |
| L020 | 0.55 | NET-01 | `http://www.slf4j.org/codes.html#StaticLoggerBinder` |
| L021 | 0.55 | NET-01 | `http://www.slf4j.org/codes.html#loggerNameMismatch` |
| L022 | 0.55 | NET-01 | `http://www.slf4j.org/codes.html#multiple_bindings` |
| L023 | 0.55 | NET-02 | `https://support.gauntlet.example/help` |
| L024 | 0.50 | STO-03 | `putString("key result type"` |
| L025 | 0.50 | STO-03 | `putString("key_result_id"` |
| L026 | 0.10 | CRY-04 | MD5 or SHA-1 in use |
| L027 | 0.05 | CRED-10 | `9f2c4a1d8e5b7c3f0a6d2e9b4c8f1a7d3e5b9c02` |

**Eighteen of the twenty-seven are in the HIGH band.** Twenty of the twenty-seven are wrong.

---

## 4. The task

Create `ledger.csv` with these columns and **fill in every row**:

```
lead_id,verdict,reason
```

`verdict` is one of `FINDING`, `INFORMATIONAL`, `REJECTED`, `DEFERRED`.
`reason` is **one sentence a stranger could check**. "Looks fine" is not a reason. "Library code" is
not a reason unless you say which library and why that settles it.

### The rules of the exercise

1. **Work top-down.** Do not skip to the ones you find interesting.
2. **Open the file for every lead.** Every single one. The whole tree is 19 files; there is no excuse.
3. **Read `res/xml/network_security_config.xml` before you judge any cleartext lead.** It is right
   there and it changes at least one answer.
4. **Read `AndroidManifest.xml` before you judge any component lead.** `minSdkVersion` changes one
   answer; `exported` changes another.
5. **Decode every base64 value before writing anything about it.**
6. **Do not look at section 6 until your ledger is complete.**

### Useful commands

```bash
# host
bash ../scripts/validate-lead.sh --tree ./out --value 'sk_live_EXAMPLE_NOT_A_REAL_KEY_ch52QR'
bash ../scripts/validate-lead.sh --tree ./out --value 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU='
echo 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU=' | base64 -d | xxd | head
cat out/resources/res/xml/network_security_config.xml
grep -n 'minSdkVersion' out/resources/AndroidManifest.xml
```

---

## 5. Hints, if you are stuck

<details>
<summary>Hint 1 — three leads hinge on something outside the file that produced them</summary>

- One cleartext URL is **confirmed** by a file in `res/xml/`.
- One storage lead is **dead** because of a number in `AndroidManifest.xml`.
- One base64 value is **harmless** and one is **not**, and the difference is what happens to the
  decoded bytes three lines later.
</details>

<details>
<summary>Hint 2 — two leads look identical and are not</summary>

`L008` and `L009` are both TLS leads at 0.90. One is in the app's own package and one is not, and
that is not the only difference — read the method bodies. One of them is the *correct*
implementation of the thing it looks like a bug in.
</details>

<details>
<summary>Hint 3 — four leads are the same finding</summary>

Do not write four rows of the report for what is one sentence to a developer. Say so in the ledger:
`FINDING (grouped with L0NN)`.
</details>

<details>
<summary>Hint 4 — one lead is a trap in two independent ways</summary>

Look at `KeyResultTracker`. Ask what the rule matched, and then ask whether the API it matched is
even the API the rule is about.
</details>

---

## 6. Answer key

**Do not read this until your ledger is complete.**

<details>
<summary>Open the answer key</summary>

### Findings — 7 of 27

| ID | Verdict | Why |
|---|---|---|
| **L001** | **FINDING (Critical)** | `sk_live_` is a Stripe **secret** key, in the app's own code, in an `Authorization: Bearer` header. Any user of the app can extract it and charge cards. The `sk_`/`pk_` and `live`/`test` prefixes are the entire triage: `pk_live_` would be Informational |
| **L003** | **FINDING (Medium)** | Cleartext endpoint in app code — **and confirmed exploitable** by `res/xml/network_security_config.xml`, which explicitly sets `cleartextTrafficPermitted="true"` for that exact domain. Without that file the platform would have blocked it and the finding would be Informational |
| **L006** | **FINDING (High)** | `addJavascriptInterface` plus `loadUrl(getIntent().getStringExtra("url"))` in an activity the manifest exports with a `BROWSABLE` deep link. Any app, and any web page, can direct this WebView at a page it controls and reach `HelpBridge`'s annotated methods |
| **L008** | **FINDING (High)** | `LegacyTrust.checkServerTrusted` has an **empty body** — it accepts every certificate. In the app's own package |
| **L010** | **FINDING (High)** | Decodes to 32 ASCII bytes used directly as an `AES` `SecretKeySpec`. A hardcoded symmetric key |
| **L013 / L014 / L015** | **FINDING (Low), grouped** | Three non-production hostnames in a production enum: internal estate disclosure. One finding, not three |
| **L002** | **FINDING (Medium)** | A fixed 16-byte IV literal with `AES/CBC`. Real, and it belongs to the same `Vault` class as L010 — grouping it with L010 is also acceptable and arguably better |

### Rejections — 20 of 27

| ID | Verdict | Reason |
|---|---|---|
| L004 | REJECTED | Compose preview fixture in `ComposableSingletons$HelpScreenKt`; not reachable from any code path |
| L005 | REJECTED | Same class, same reason. The joke URL ranked joint-first by confidence |
| L007 | REJECTED | `MODE_WORLD_READABLE` is inside `if (Build.VERSION.SDK_INT < 17)` and the manifest sets `minSdkVersion="24"`. **Dead code that cannot execute on any supported device** |
| L009 | REJECTED | OkHttp's own `CertificatePinner` class, referenced by its plumbing. No `.add()` call anywhere, so **the app does not pin** — record that as an observation, not as "pinning is implemented" |
| L011 | REJECTED | Decodes to `Welcome to the Gauntlet application!` — a UI string. Encoding is not encryption, and there is nothing to protect |
| L012 | REJECTED | `https://api.stripe.com/v1/charges` is the vendor's documented endpoint. Inventory, not a finding. (The **key** at L001 is the finding) |
| L016 | REJECTED | `10.0.2.2` is inside `if (BuildConfig.DEBUG)`, and `BuildConfig.DEBUG` is `false` in this artefact. R8 removes the branch in a release build; the decompiled tree still shows it |
| L017 | INFORMATIONAL / DEFERRED | A Google Maps API key in `strings.xml`. **These are designed to ship in clients.** The finding, if any, is "no application restriction and an over-broad scope" — which you cannot see from the artefact. Ask the client to show the key's restrictions in the Cloud console |
| L018 | REJECTED | The production endpoint. Inventory |
| L019 | REJECTED | A `TODO` comment that *mentions* a token. There is no token. Reporting a comment as a credential is a classic |
| L020–L022 | REJECTED | slf4j documentation URLs emitted in error messages. Three leads, one reason |
| L023 | REJECTED | The app's own public support page, over HTTPS |
| L024 | REJECTED | **Two independent errors in one lead.** The rule matched the word `key` in the OKR domain term "key result", and the call is `Bundle.putString` into an analytics event — not `SharedPreferences` at all |
| L025 | REJECTED | Same |
| L026 | REJECTED | MD5 in `androidx.core.graphics.CacheKey`, computing a cache key from a URL. A non-security use of a hash, in library code |
| L027 | REJECTED | 40 hex characters in `BuildConfig` — a git commit SHA. Generated code, and the value is public by construction |

### Blind spots you should have recorded

```
BLIND-01  receiver registered at runtime   1 occurrence, 1 in app code
BLIND-02  reflective dispatch              3 occurrences, 1 in app code
```

Both are in `SyncService`, which is the app's own code. Your report's limits section must say:

> The application registers a broadcast receiver at runtime in `SyncService.onCreate` for
> `com.gauntlet.app.SYNC_NOW` and `ACTION_POWER_CONNECTED`; neither is declared in the manifest and
> neither is visible to artefact-based analysis. The same method dispatches reflectively to
> `com.gauntlet.app.sync.OptionalUploader`, a class that is **not present in this tree** — which
> means either it is stripped in this build or it is loaded from elsewhere. Both require dynamic
> analysis to resolve.

That last observation is worth more than several of the findings. `Class.forName` naming a class that
does not exist in the tree is exactly the shape of a runtime-loaded component, and only a reader who
opened the file would notice it.

</details>

---

## 7. Scoring

<details>
<summary>Open the scoring rubric</summary>

Start at 0.

| Action | Points |
|---|---|
| Each of the 20 rejections, correct verdict **with a checkable reason** | **+2** each (max 40) |
| Each of the 7 findings identified | +2 each (max 14) |
| L007 rejected specifically because `minSdkVersion=24` > 17 | +4 bonus |
| L003 confirmed specifically via the network security config | +4 bonus |
| L010 and L011 distinguished by **decoding both** | +4 bonus |
| L024/L025 rejected for **both** reasons (wrong word sense *and* wrong API) | +4 bonus |
| Blind spots recorded, including the missing `OptionalUploader` class | +6 bonus |
| L013/L014/L015 grouped as one finding | +2 bonus |
| **Each false positive reported as a finding** | **−5** |
| L017 reported as a straight "hardcoded API key" finding | −5 |
| Any verdict with no reason, or a reason nobody could check | −2 each |
| Ledger incomplete | −2 per missing row |

| Score | Verdict |
|---|---|
| 70+ | You can be trusted with a client's report |
| 50–69 | Solid. Re-read the rows you got wrong; they are the same rows people get wrong on real apps |
| 30–49 | You are finding things and not validating them. Re-read [README §3.7](../README.md#37-stage-7--validate) |
| Under 30 | You reported the scanner output. This is exactly the failure the chapter is about, and it is fixable in an afternoon |

</details>

---

## 8. What to take away

1. **Eighteen of twenty-seven leads were HIGH confidence and twenty of twenty-seven were wrong.**
   Confidence is a queue order, not a verdict.
2. **Three answers came from files other than the one that produced the lead** — the network security
   config, the manifest's `minSdkVersion`, and the decoded content of a base64 string. A triager who
   never leaves the hit's own file will get all three wrong.
3. **Two leads were rejected because the code cannot run** (`SDK_INT < 17` with `minSdk 24`;
   `BuildConfig.DEBUG` false). Reachability is not only about call graphs.
4. **One lead was wrong twice over** — wrong sense of the word "key" *and* the wrong API entirely.
5. **The most valuable observation in the whole lab was not a lead at all**: a reflective call to a
   class that is not in the tree.
6. **The vendor's intent matters.** `sk_live_` is a finding on sight; `AIza…` is a question for the
   client. Both are "an API key in the app".

---

## 9. Going further

- Change one line of `build-gauntlet.sh` — set `minSdkVersion` to `16` — and re-run. L007 flips from
  a rejection to a real finding. Notice that **nothing in the file that produced the lead changed**.
- Add a `.add("api.gauntlet.example", "sha256/AAAA…")` call to `CertificatePinner.Builder` usage in
  app code and re-run. L009's rule fires identically; your verdict must change. That is the 12-of-14
  versus 4-of-14 gap from [36](../../36-CertificatePinning/README.md), reproduced in one line.
- Run the sweep with `--files app` and see which rejections disappear from the queue entirely. Then
  ask whether losing them was a good trade.
- Then do [Lab 03](lab-03-blind-spots.md), which measures the part of the application none of this
  could see.
