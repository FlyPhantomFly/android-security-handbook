# Lab 04 — CTF: the honest report

> **Objective.** Recover a four-fragment flag from a prepared tree, and produce a report.
> **Points are awarded for the flag and deducted for every unvalidated finding you submit.**
> It is possible to find the flag and still score zero.

**Difficulty:** the chapter's capstone. Everything from Labs 01–03 is in play.
**Time:** 60–90 minutes.
**Prerequisites:** Labs 01 and 02. `bash`, `python3`, `base64`. No device, no APK, no internet.

---

## 0. The premise

You have been handed a decompiled tree for `com.ctf52.vaultapp` and asked for a static assessment.
Somewhere in it is a flag of the form `CTF52{...}`, split into four fragments.

There are also **four decoy flags**, each of the same form, each in a place that a scanner will rank
highly and a careless triager will report.

**The scoring is deliberately asymmetric.** Finding the flag is worth less than not reporting the
decoys. That is the entire lesson of the chapter, expressed as arithmetic.

---

## 1. Build the tree

Save as `build-ctf.sh` and run it.

```bash
#!/usr/bin/env bash
# build-ctf.sh -- create the Lab 04 CTF tree.  Run: bash build-ctf.sh
set -eu
rm -rf out
mk() { mkdir -p "$(dirname "$1")"; cat > "$1"; }

mk out/resources/AndroidManifest.xml <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.ctf52.vaultapp"
    android:versionCode="7" android:versionName="1.7.0">
    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <application
        android:label="VaultApp"
        android:allowBackup="false"
        android:networkSecurityConfig="@xml/network_security_config">
        <activity android:name="com.ctf52.vaultapp.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity android:name="com.ctf52.vaultapp.export.ExportActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="vaultapp" android:host="export"/>
            </intent-filter>
        </activity>
        <provider
            android:name="androidx.startup.InitializationProvider"
            android:authorities="com.ctf52.vaultapp.androidx-startup"
            android:exported="false"/>
    </application>
</manifest>
EOF

mk out/resources/res/xml/network_security_config.xml <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<!-- fragment 4 of 4: X3IzcDBydA== -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false"/>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">telemetry.vaultapp.example</domain>
    </domain-config>
</network-security-config>
EOF

mk out/resources/res/values/strings.xml <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">VaultApp</string>
    <string name="privacy_url">https://vaultapp.example/privacy</string>
    <string name="analytics_key">AIzaSy.EXAMPLE.NOT.A.REAL.KEY.ch52b</string>
</resources>
EOF

mk out/sources/com/ctf52/vaultapp/MainActivity.java <<'EOF'
package com.ctf52.vaultapp;

import android.app.Activity;
import android.os.Bundle;
import com.ctf52.vaultapp.export.Exporter;

public final class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        new Exporter(this).prepare();
    }
}
EOF

mk out/sources/com/ctf52/vaultapp/export/ExportActivity.java <<'EOF'
package com.ctf52.vaultapp.export;

import android.app.Activity;
import android.os.Bundle;

public final class ExportActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String token = getIntent().getStringExtra("token");
        new Exporter(this).exportWith(token);
    }
}
EOF

mk out/sources/com/ctf52/vaultapp/export/Exporter.java <<'EOF'
package com.ctf52.vaultapp.export;

import android.content.Context;
import android.util.Base64;

public final class Exporter {
    // fragment 1 of 4
    private static final String PART_A = "djRsMWQ0dDM=";
    private final Context ctx;

    public Exporter(Context ctx) { this.ctx = ctx; }

    public void prepare() {
        String banner = new String(Base64.decode("VmF1bHRBcHAgaXMgcmVhZHk=", 0));
        android.util.Log.i("Exporter", banner);
    }

    public void exportWith(String token) {
        Uploader.send(ctx, token, new String(Base64.decode(PART_A, 0)));
    }
}
EOF

mk out/sources/com/ctf52/vaultapp/export/Uploader.java <<'EOF'
package com.ctf52.vaultapp.export;

import android.content.Context;

public final class Uploader {
    // fragment 2 of 4
    static final String PART_B = "X2IzZjByMw==";

    static void send(Context ctx, String token, String part) {
        Telemetry.post("http://telemetry.vaultapp.example/v1/export", token + part);
    }
}
EOF

mk out/sources/com/ctf52/vaultapp/export/OrphanUploader.java <<'EOF'
package com.ctf52.vaultapp.export;

import android.content.Context;

public final class OrphanUploader {
    // Looks exactly like Uploader. Nothing references this class.
    static final String PART_B = "Q1RGNTJ7ZDNhZF9jMGQzX2QwM3NfbjB0X2MwdW50fQ==";

    static void send(Context ctx, String token, String part) {
        Telemetry.post("http://telemetry.vaultapp.example/v1/export", token + part);
    }
}
EOF

mk out/sources/com/ctf52/vaultapp/export/Telemetry.java <<'EOF'
package com.ctf52.vaultapp.export;

public final class Telemetry {
    public static void post(String url, String body) {
    }
}
EOF

mk out/sources/com/ctf52/vaultapp/compat/LegacyStore.java <<'EOF'
package com.ctf52.vaultapp.compat;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;

public final class LegacyStore {
    // fragment 3 of 4 -- but read the branch conditions and the manifest first.
    private static final String OLD_PATH_PART = "Q1RGNTJ7c2M0bm4zcl9zNHlzX2gxZ2h9";
    private static final String NEW_PATH_PART = "X3kwdQ==";

    public static String partFor(Context ctx) {
        if (Build.VERSION.SDK_INT < 19) {
            SharedPreferences p =
                ctx.getSharedPreferences("legacy", Context.MODE_WORLD_READABLE);
            p.edit().putString("api_key", "sk_test_00000000000000000000").apply();
            return OLD_PATH_PART;
        }
        return NEW_PATH_PART;
    }
}
EOF

mk 'out/sources/com/ctf52/vaultapp/ui/ComposableSingletons$VaultScreenKt.java' <<'EOF'
package com.ctf52.vaultapp.ui;

public final class ComposableSingletons$VaultScreenKt {
    public static final String PREVIEW_URL = "http://test.example/preview";
    public static final String PREVIEW_BLOB = "Q1RGNTJ7Z3IzcF8xc18zbjB1Z2h9";
    public static final String PREVIEW_USER = "Test User";
}
EOF

mk out/sources/okhttp3/internal/http2/Settings.java <<'EOF'
package okhttp3.internal.http2;

public final class Settings {
    private static final String DOC = "http://www.slf4j.org/codes.html#replay";
    private static final String BLOB = "Q1RGNTJ7bDFicjRyeV9jMGQzfQ==";
    public int get(int id) { return id; }
}
EOF

mk out/sources/com/ctf52/vaultapp/BuildConfig.java <<'EOF'
package com.ctf52.vaultapp;
public final class BuildConfig {
    public static final boolean DEBUG = false;
    public static final String BUILD_SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
}
EOF

echo "tree built: $(find out -type f | wc -l) files"
```

```bash
# host
bash build-ctf.sh
# tree built: 13 files
```

Every value in this tree is invented. The keys resolve to nothing.

---

## 2. Run the sweep

```bash
# host
python3 -B ../scripts/static-sweep.py ./out | tee sweep.txt
```

Expected header:

```
  files scanned      13
      app            9
      third-party    1
      generated      1
      resource       2
  raw hits           20
  killed by a rule's own validator  1
  distinct leads     18
  shown here         17
  demoted as noise   1
  blind-spot notices 0
```

**Read the leads.** All four decoy flags are in that queue. **None of the four real fragments is.**

That is not a bug in the tool and it is the most important thing in this lab: the scanner surfaces
what has the *shape* of a secret, and three of the four real fragments are too short to have that
shape. The flag is recoverable only by reading code and following data.

---

## 3. The task

Produce two artefacts.

### 3.1 `flag.txt`

The complete flag, `CTF52{...}`, assembled from four fragments.

**Rules:**
- Each fragment is base64.
- Fragments concatenate in order 1, 2, 3, 4.
- The result is wrapped in `CTF52{...}` by you; the fragments themselves do not contain the braces.
- A decoy flag decodes to a complete `CTF52{...}` string on its own. **If your answer came out of a
  single base64 value, it is a decoy.**

### 3.2 `report.md`

A short assessment of `com.ctf52.vaultapp`, containing:

1. **Findings.** Real ones only, with severity and a one-line justification each.
2. **A ledger.** Every one of the 17 displayed leads, with a verdict and a checkable reason.
3. **A limits section.** What static analysis of this tree could not see, for this app specifically.

---

## 4. Rules of engagement

1. You may read every file. It is thirteen files.
2. You may use `static-sweep.py`, `validate-lead.sh`, `grep` and `base64`.
3. **You may not submit a finding you have not validated.** Each one costs you more than a fragment
   is worth.
4. The manifest and `res/xml/` are part of the tree. Two of the four fragments require them, directly
   or indirectly.

---

## 5. Where the fragments are — the questions, not the answers

Each fragment is guarded by one validation question. If you can answer the question, you can find the
fragment.

| Fragment | The question you must answer |
|---|---|
| **1 of 4** | Which classes can the *platform* start, and what do they call? |
| **2 of 4** | Two classes in the same package look identical. Which one is actually referenced? |
| **3 of 4** | One method has two branches. Which branch can execute **on this app's supported devices**? |
| **4 of 4** | The manifest is a set of pointers. Did you open the files it points at? |

Notice that these are questions 1 through 4 of the validation method, in order.

---

## 6. Hints

<details>
<summary>Hint 1 — you are looking for short base64, not long base64</summary>

The sweeper's `CRED-09` rule requires at least 20 characters. Three of the four fragments are shorter
than that. Try:

```bash
grep -rnoE '"[A-Za-z0-9+/]{6,}={0,2}"' out/sources/ | sort -u
```

Then decode everything it prints. Most will be nothing.
</details>

<details>
<summary>Hint 2 — fragment 2</summary>

```bash
grep -rn 'Uploader' out/sources/
```

Two classes. Count the references to each. A class that nothing references cannot contribute to
anything the app does — and it contains a value that decodes to a complete flag on its own, which
should make you suspicious rather than pleased.
</details>

<details>
<summary>Hint 3 — fragment 3</summary>

```bash
grep -n 'minSdkVersion' out/resources/AndroidManifest.xml
grep -n 'SDK_INT' out/sources/com/ctf52/vaultapp/compat/LegacyStore.java
```

Compare the two numbers. One branch of that method cannot run on any device the app supports. The
`MODE_WORLD_READABLE` call and the `sk_test_` key in that branch are in the same condition — which
tells you what to do with them in the ledger, too.
</details>

<details>
<summary>Hint 4 — fragment 4</summary>

The manifest names `android:networkSecurityConfig="@xml/network_security_config"`. Open the file.
Read all of it, including the parts that are not elements.
</details>

<details>
<summary>Hint 5 — the decoys</summary>

There are four, and each is in a place this chapter has named as a classic false positive:
a Compose preview class, a bundled library, dead code, and an unreferenced class. If your candidate
flag came from one of those, you have found a decoy — and rejecting it correctly is worth more than
the flag.
</details>

---

## 7. Answer key

**Do not open until `flag.txt` and `report.md` exist.**

<details>
<summary>The flag</summary>

```
CTF52{v4l1d4t3_b3f0r3_y0u_r3p0rt}
```

Assembled from:

| # | Location | Value | Decodes to |
|---|---|---|---|
| 1 | `export/Exporter.java`, `PART_A` — reachable from `MainActivity`, which the manifest declares | `djRsMWQ0dDM=` | `v4l1d4t3` |
| 2 | `export/Uploader.java`, `PART_B` — the class `Exporter.exportWith` actually calls | `X2IzZjByMw==` | `_b3f0r3` |
| 3 | `compat/LegacyStore.java`, `NEW_PATH_PART` — the branch that runs when `SDK_INT >= 19`, which is every device, because `minSdkVersion` is 26 | `X3kwdQ==` | `_y0u` |
| 4 | `res/xml/network_security_config.xml`, in an XML comment | `X3IzcDBydA==` | `_r3p0rt` |

```bash
for f in djRsMWQ0dDM= X2IzZjByMw== X3kwdQ== X3IzcDBydA==; do printf '%s' "$(echo $f | base64 -d)"; done; echo
# v4l1d4t3_b3f0r3_y0u_r3p0rt
```

</details>

<details>
<summary>The decoys</summary>

| Decoy | Where | Why it is a decoy | The lesson |
|---|---|---|---|
| `CTF52{gr3p_1s_3n0ugh}` | `ComposableSingletons$VaultScreenKt.PREVIEW_BLOB` | A Compose preview fixture, compiled into the build and reachable from nothing | Preview and test data ships, and ranks high |
| `CTF52{l1br4ry_c0d3}` | `okhttp3.internal.http2.Settings.BLOB` | Bundled library code | A finding about a library is a finding about the library |
| `CTF52{sc4nn3r_s4ys_h1gh}` | `LegacyStore.OLD_PATH_PART` | Inside `if (SDK_INT < 19)` while `minSdkVersion` is 26 — unreachable on every supported device | Reachability is not only about call graphs |
| `CTF52{d3ad_c0d3_d03s_n0t_c0unt}` | `OrphanUploader.PART_B` | A class nothing references; a copy of `Uploader` | Two classes can look identical and only one can matter |

</details>

<details>
<summary>The real findings — 3</summary>

| # | Finding | Severity | Why |
|---|---|---|---|
| F-01 | `ExportActivity` is exported with a `BROWSABLE` deep link and passes `getIntent().getStringExtra("token")` straight into `Exporter.exportWith`, which sends it to a remote endpoint | **High** | Any application, and any web page the user visits, can invoke `vaultapp://export?…` and cause the app to transmit an attacker-chosen token to the telemetry endpoint. Attacker-controlled input reaching a network sink through an exported component |
| F-02 | Telemetry is transmitted over cleartext HTTP to `telemetry.vaultapp.example`, **and** the network security config explicitly permits cleartext for that domain | **Medium** | The NSC is what makes this exploitable rather than blocked; without it the platform would refuse the request. Two files, one finding — this is why §8.6 says to open everything the manifest points at |
| F-03 | A Google API key is present in `res/values/strings.xml` | **Informational, pending scope** | These are designed to ship in clients. The finding, if any, is a missing application restriction, which is not visible from the artefact. Ask the client for the key's restrictions |

**Deliberately *not* findings:**

- `MODE_WORLD_READABLE` and the `sk_test_` key in `LegacyStore` — both inside the dead
  `SDK_INT < 19` branch. Record as an observation ("dead compatibility code containing a test
  credential; remove it") rather than as a finding.
- `TLS-04` "pinning surface present" — the tool matched the string `network_security_config`. The app
  configures **no pins at all**. The correct sentence is "the application does not implement
  certificate pinning", which is an observation about a missing control, not a finding about a
  broken one.
- The `slf4j` documentation URL, the privacy-policy URL, the preview URL, and the `BuildConfig` git
  SHA.

</details>

<details>
<summary>The limits section</summary>

> Static analysis of this tree cannot observe broadcast receivers registered at runtime, native
> methods bound with `RegisterNatives`, reflective dispatch targets, code loaded after installation,
> or server-side behaviour. **For this application, the sweep reported zero blind-spot markers**: no
> `registerReceiver`, no reflection, no `DexClassLoader`, no `System.loadLibrary`, and no native
> libraries in the tree. The application's behaviour therefore appears to be fully described by its
> artefact — with the standing exception of anything the telemetry endpoint returns, which was not
> assessed.
>
> This was verified independently of the tool:
>
> ```bash
> grep -rl 'registerReceiver\|Class.forName\|DexClassLoader\|loadLibrary' out/sources/ | wc -l   # 0
> ```

"zero blind-spot markers" is itself a claim worth verifying by hand, and that the
verification is one command. A report that asserts it without running that command has asserted
something it did not check.

</details>

---

## 8. Scoring

<details>
<summary>Open the scoring rubric</summary>

| Item | Points |
|---|---|
| Correct complete flag | **+20** |
| Each fragment located and its guard question answered in writing | +5 each (max 20) |
| Each of the three real findings, with correct severity and justification | +10 each (max 30) |
| F-02 justified **using the network security config**, not just the URL | +10 |
| The `MODE_WORLD_READABLE` / `sk_test_` pair correctly recorded as dead code | +10 |
| `TLS-04` correctly reported as "does not pin" rather than "pins" | +10 |
| Ledger complete: a verdict and a checkable reason for all 17 displayed leads | +15 |
| Limits section present, app-specific, and independently verified | +10 |
| **Each decoy flag submitted as the answer** | **−25** |
| **Each decoy reported as a finding in the report** | **−15** each |
| Any false positive from the ledger promoted into the findings section | −10 each |
| The Google API key reported as a straight "hardcoded credential" High | −10 |
| Any verdict with no reason | −3 each |
| Reporting "no issues found" anywhere | −10 |

| Score | Verdict |
|---|---|
| 110+ | You found the flag *and* wrote a report a client could act on |
| 80–109 | Strong. Check which validation question you skipped |
| 50–79 | You found things. Now go back and check what you claimed about them |
| Below 50 | Re-read [README §3.7](../README.md#37-stage-7--validate) and redo the ledger. This is a process gap, not a knowledge gap, and it closes in an afternoon |
| **Negative** | You submitted a decoy. This is the intended failure mode of the lab, it is the intended failure mode of the industry, and now you have felt it |

</details>

---

## 9. Debrief

Whatever you scored, answer these five in writing. They are worth more than the points.

1. **Which decoy nearly got you?** Everyone has one. For most people it is
   `CTF52{sc4nn3r_s4ys_h1gh}`, because the scanner really does say HIGH and the code really is there.
2. **How many of the 17 leads did you open the file for?** If the answer is fewer than 17, which ones
   did you skip and why did you feel entitled to?
3. **Fragment 4 was in an XML comment in a file the manifest points at.** How many of the manifest's
   pointers did you follow before you were told to?
4. **F-02 needed two files to justify.** How would you have written it from one?
5. **The tool surfaced every decoy and none of the real fragments.** What does that tell you about
   building your assessment around a scanner's output?

---

## 10. Where to go next

- Re-run the CTF tree through the sweeper with `--files app` and check which decoys disappear. Two of
  them do. Is that an improvement or a risk?
- Extend `build-ctf.sh`: add a fifth fragment reachable only through a reflective call, and see what
  happens to the caller closure in `validate-lead.sh --reach`.
- Take [Lab 02](lab-02-false-positive-gauntlet.md)'s tree and this one, sweep both, and diff the
  ledgers. The rules that produce rejections in *both* are your personal noise floor, and they are
  the first candidates for a validator.
- Then go and do this on a real app you have permission to test, and notice how much of the work is
  the part this lab scored you on.
