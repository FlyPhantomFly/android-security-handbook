# Lab 02 — Patch, Rebuild, Verify

**Difficulty:** Intermediate
**Time:** 2.5–4 hours
**Prerequisites:** [Lab 01](lab-01-read-smali-by-hand.md), [Chapter 14 §3.10, §5.2, §6.3](../README.md)
**Needs:** Android Studio or a Gradle command line, `apktool`, `zipalign`, `apksigner`, `adb`, and a
device or emulator. **Not rooted** — that is the point.

---

## Objective

Run the complete Smali patching round trip four times, on an app you built yourself, and **prove**
each time that the patch reached the device and changed observable behaviour. By the end you should
be able to:

- Decode, edit, rebuild, align, sign and install an APK without looking anything up.
- Make the four canonical patches: constant return, branch inversion, method short-circuit, and
  logging injection.
- Explain the difference between "the bytes changed", "the code ran" and "the behaviour changed", and
  demonstrate all three.
- Read a `VerifyError` in `logcat` and fix the instruction that caused it.

## Why this matters

The mechanics are not hard. What separates someone who can do this from someone who *thinks* they can
is the discipline of proof. "I patched the method" is not a result. Every step below ends with a
check, because on a real engagement the difference between a finding and an embarrassment is whether
you demonstrated the effect or assumed it.

The second reason is that this workflow needs **no root and no Frida**. On an engagement where the
client hands you a locked-down device, or the app detects Frida, this is what you have.

---

## Setup

### Step 1 — Build the vulnerable app

Create a minimal Android project. Any `minSdk` of 24 or higher, any template with an Activity. Then
replace the sources with these four files.

**`app/src/main/java/com/example/vault/Gate.java`**

```java
package com.example.vault;

import java.io.File;

public class Gate {

    // Patch target 1: a constant-return bypass.
    public static boolean checkPin(String pin) {
        return "1337".equals(pin);
    }

    // Patch target 2: a branch inversion.
    public static boolean isDeviceRooted() {
        String[] paths = {
            "/system/xbin/su", "/system/bin/su", "/sbin/su",
            "/system/app/Superuser.apk", "/data/local/tmp/su"
        };
        for (String p : paths) {
            if (new File(p).exists()) {
                return true;
            }
        }
        return false;
    }

    // Patch target 4: a value you want to see but the app never prints.
    public static String computeToken(String user, long nonce) {
        long h = 1125899906842597L;
        for (int i = 0; i < user.length(); i++) {
            h = 31 * h + user.charAt(i);
        }
        h ^= nonce;
        return Long.toHexString(h);
    }
}
```

**`app/src/main/java/com/example/vault/Pinner.java`**

```java
package com.example.vault;

import java.security.cert.Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

// Patch target 3: a real pinning implementation with a bypass flag.
public final class Pinner implements HostnameVerifier {

    private static final String PIN = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    private final boolean strict;

    public Pinner(boolean strict) {
        this.strict = strict;
    }

    @Override
    public boolean verify(String host, SSLSession session) {
        if (!strict) {
            return true;
        }
        try {
            Certificate[] chain = session.getPeerCertificates();
            return PIN.equals(sha256Pin(chain[0]));
        } catch (SSLPeerUnverifiedException e) {
            return false;
        }
    }

    static String sha256Pin(Certificate c) {
        return "sha256/" + Integer.toHexString(c.hashCode());
    }
}
```

**`app/src/main/java/com/example/vault/MainActivity.java`**

```java
package com.example.vault;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {

    private static final String TAG = "VAULT";

    private EditText input;
    private TextView out;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 96, 48, 48);

        input = new EditText(this);
        input.setHint("PIN");
        root.addView(input);

        Button unlock = new Button(this);
        unlock.setText("UNLOCK");
        root.addView(unlock);

        Button check = new Button(this);
        check.setText("SECURITY CHECK");
        root.addView(check);

        Button token = new Button(this);
        token.setText("COMPUTE TOKEN");
        root.addView(token);

        out = new TextView(this);
        out.setTextSize(18f);
        root.addView(out);

        setContentView(root);

        unlock.setOnClickListener(v -> {
            boolean ok = Gate.checkPin(input.getText().toString());
            out.setText(ok ? "UNLOCKED" : "WRONG PIN");
            Log.i(TAG, "checkPin -> " + ok);
        });

        check.setOnClickListener(v -> {
            boolean rooted = Gate.isDeviceRooted();
            if (rooted) {
                out.setText("DEVICE ROOTED - refusing to run");
            } else {
                out.setText("environment OK");
            }
            Log.i(TAG, "isDeviceRooted -> " + rooted);
        });

        token.setOnClickListener(v -> {
            // The token is computed and USED but never displayed.
            String t = Gate.computeToken(input.getText().toString(), 0x5A5A5A5AL);
            out.setText("token computed (" + t.length() + " chars)");
        });
    }
}
```

**`app/build.gradle.kts`** — the only settings that matter:

```kotlin
android {
    defaultConfig {
        minSdk = 24
        targetSdk = 34
    }
    buildTypes {
        release {
            isMinifyEnabled = false          // keep names readable for this lab
            isShrinkResources = false
        }
    }
}
```

Build a **release** APK and install it:

```bash
# host
./gradlew assembleRelease
adb install -r app/build/outputs/apk/release/app-release-unsigned.apk 2>/dev/null \
  || ./gradlew installRelease
```

> **If you cannot build an Android project**, every patch below works identically on any APK you have
> the right to modify. Adapt the class and method names. The mechanics are the point.

### Step 2 — Establish the baseline

**Before you change anything**, decode the app once and keep the result. You will diff against this,
not against the original APK.

```bash
# host
APK=app/build/outputs/apk/release/app-release.apk
apktool d -r -f "$APK" -o baseline/
cp -r baseline work
```

`-r` skips resource decoding. It is much faster and it removes the single most common cause of an
`apktool b` failure. `-f` overwrites.

> **Why a baseline.** A `baksmali` → `smali` round trip regenerates item ordering, debug info and
> layout, so a rebuilt-but-unmodified APK is **not byte-identical** to the original and its hash is
> different. Diffing your patched build against the untouched original drowns you in noise. Diff
> against the baseline.

### Step 3 — Confirm original behaviour

Install and click all three buttons. Record what happens:

```bash
# host
adb logcat -c
adb logcat -s VAULT:I
```

| Action | Expected before patching |
|---|---|
| Enter `0000`, tap UNLOCK | `WRONG PIN`, log `checkPin -> false` |
| Enter `1337`, tap UNLOCK | `UNLOCKED`, log `checkPin -> true` |
| Tap SECURITY CHECK on a stock device | `environment OK`, log `isDeviceRooted -> false` |
| Tap COMPUTE TOKEN | `token computed (N chars)` — the value itself is never shown |

Write these down. You are about to change every one of them.

---

## Patch 1 — Constant return

**Goal:** any PIN unlocks.

### Find it

```bash
# host
grep -rn 'checkPin' work/smali*/
```

Open `work/smali/com/example/vault/Gate.smali` and read `checkPin`. It will look close to:

```smali
.method public static checkPin(Ljava/lang/String;)Z
    .registers 3
    const-string v0, "1337"
    invoke-virtual {v0, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v1
    return v1
.end method
```

### Compute before you type

`.registers 3`, static, one incoming word. `first_param_reg = 3 - 1 = 2`, so `p0 == v2` and `v0`,
`v1` are locals. Both exist, so the patch needs no new registers.

### Patch

```smali
.method public static checkPin(Ljava/lang/String;)Z
    .registers 3
    const/4 v0, 0x1
    return v0
.end method
```

Note what was **not** done: `.registers` was left alone. It could have been reduced to 1, and there
is no reason to. Leaving it larger than necessary is always safe; making it smaller than the body
needs is not.

### Build, align, sign, install

```bash
# host
apktool b work/ -o patched.apk
zipalign -p -f -v 4 patched.apk aligned.apk
apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android \
    --out signed.apk aligned.apk
apksigner verify -v signed.apk
adb uninstall com.example.vault
adb install signed.apk
```

If you have no debug keystore, make one:

```bash
# host
keytool -genkeypair -v -keystore ~/.android/debug.keystore -storepass android \
    -alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=Android Debug,O=Android,C=US"
```

> **Order matters, twice.**
> `zipalign` **before** `apksigner` — v2+ signatures cover the whole file, so aligning afterwards
> invalidates them.
> `adb uninstall` **before** `adb install` — you signed with a different key, so Android considers
> this a different application and refuses an in-place update with
> `INSTALL_FAILED_UPDATE_INCOMPATIBLE`.

### Prove it — all three levels

**Level 1: the bytes on the device are the bytes you wrote.**

```bash
# host
adb shell pm path com.example.vault
# copy the path it prints
adb pull /data/app/~~XXXX/com.example.vault-YYYY/base.apk pulled.apk
unzip -o pulled.apk 'classes*.dex' -d pulled_dex/
baksmali d pulled_dex/classes.dex -o pulled_smali/ --classes com/example/vault/Gate
sed -n '/checkPin/,/end method/p' pulled_smali/com/example/vault/Gate.smali
```

**Level 2: the code ran.** `adb logcat -s VAULT:I` and tap UNLOCK.

**Level 3: the behaviour changed.** Enter `0000` and tap UNLOCK. The screen says `UNLOCKED`.

Only level 3 is a finding. Levels 1 and 2 are how you debug when level 3 does not happen.

---

## Patch 2 — Branch inversion

**Goal:** make the app believe the device is rooted when it is not — and then make it believe the
opposite. Doing it in both directions is the point of this patch, because branch polarity is the
thing people get backwards.

### Find it

```smali
.method public static isDeviceRooted()Z
    .registers 6
    ...
    invoke-virtual {v4}, Ljava/io/File;->exists()Z
    move-result v5
    if-eqz v5, :cond_N        # <-- the branch
    const/4 v0, 0x1
    return v0
    :cond_N
    ...
```

### Read the polarity out loud

`if-eqz v5, :cond_N` means **"if `v5` is zero, jump to `:cond_N`"**. `v5` holds the result of
`File.exists()`. So:

- `exists()` returned **false** (zero) → branch taken → continue the loop.
- `exists()` returned **true** → fall through → `return true`.

The Java source is `if (new File(p).exists()) { return true; }`, and the Smali therefore tests the
**opposite** of what the source says. That inversion is universal and it is why you read branch
polarity twice.

### Patch A — force "rooted"

```smali
    if-nez v5, :cond_N
```

Now the branch is taken when `exists()` returns **true**, so the `return true` becomes unreachable on
the path where a `su` binary actually exists — and reachable when it does not. Rebuild, install, tap
SECURITY CHECK, and confirm the screen now says `DEVICE ROOTED - refusing to run` on a stock device.

**That is the wrong direction for an attacker**, and you did it on purpose. The lesson: inverting a
branch without tracing which side is which produces exactly the outcome you did not want, and the app
still runs, so nothing tells you.

### Patch B — the direction you actually want

Revert Patch A and do it properly. The clean version is not a branch inversion at all:

```smali
.method public static isDeviceRooted()Z
    .registers 6
    const/4 v0, 0x0
    return v0
.end method
```

Two instructions, no polarity to get wrong, and no dependence on the loop's structure. Rebuild,
install, confirm `environment OK` and `isDeviceRooted -> false` in the log.

> **The general rule.** Prefer a constant return over a branch inversion whenever the method's entire
> purpose is to produce the value you want to control. Reach for branch surgery only when you need to
> keep *some* of the method's side effects.

---

## Patch 3 — Short-circuit a method that has real work in it

**Goal:** disable pinning without disturbing anything else in `Pinner`.

### Read it first

```bash
# host
sed -n '/method public verify/,/end method/p' work/smali/com/example/vault/Pinner.smali
python3 ../scripts/smali_frame.py work/smali/com/example/vault/Pinner.smali --method verify
```

The frame tool will tell you `first_param_reg`. Suppose it reports `.registers 7`, `ins_size 3`,
`first param reg v4`. Then `v0`–`v3` are free.

### Patch — insert at the top

```smali
.method public verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z
    .registers 7
    .param p1, "host"
    .param p2, "session"

    const/4 v0, 0x1              # <-- inserted
    return v0                    # <-- inserted

    iget-boolean v0, p0, Lcom/example/vault/Pinner;->strict:Z
    ...
```

Everything after `return v0` is now unreachable and that is fine — the verifier does not require
every instruction to be reachable, only that reachable ones are consistent.

### Why this shape and not another

| Alternative | Why it is worse here |
|---|---|
| Invert `if-nez v0, :cond_N` | Works, but depends on reading the polarity correctly and on `strict`'s value |
| Delete the whole body | Removes the `try` range and the handler; if you get the deletion boundaries wrong the assembler rejects an empty `try` |
| Patch the construction site to pass `false` | Also correct, and arguably better — but you have to find every construction site |
| **Insert two lines at the top** | Touches no existing register, no existing branch, no exception table. The safest edit available |

### Prove it

`Pinner` is not wired to any network call in this lab app, so prove it at the bytecode level and at
the log level:

```bash
# host
grep -A6 'method public verify' pulled_smali/com/example/vault/Pinner.smali
```

Then add a temporary logging line (Patch 4's technique) inside `verify` and call it from
`MainActivity` to see it fire. In a real engagement the proof is the intercepted traffic in Burp; see
chapter **36 — Certificate Pinning**.

---

## Patch 4 — Logging injection

**Goal:** print the token the app computes but never shows you.

### Find it

```smali
.method public static computeToken(Ljava/lang/String;J)Ljava/lang/String;
    .registers 8
    ...
    invoke-static {v0, v1}, Ljava/lang/Long;->toHexString(J)Ljava/lang/String;
    move-result-object v2
    return-object v2
.end method
```

### The rule that makes this non-trivial

The insertion goes **after `move-result-object`**, never between the invoke and it. Between them the
return value lives in a transient slot; putting an instruction there is a `VerifyError` at class
load.

### Patch

```smali
.method public static computeToken(Ljava/lang/String;J)Ljava/lang/String;
    .registers 10                                    # was 8 -- room for v3 and v4
    ...
    invoke-static {v0, v1}, Ljava/lang/Long;->toHexString(J)Ljava/lang/String;
    move-result-object v2

    const-string v3, "SMALIPATCH"
    invoke-static {v3, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    return-object v2
.end method
```

Four things had to be right:

1. **`.registers` raised** from 8 to 10, so `v3` exists with headroom.
2. **Raising `.registers` moved the parameters.** With `ins_size 3` (`String` + `long`), `p0` went
   from `v5` to `v7`. That is safe **only** because the body writes `p0`/`p1`/`p2`, not raw `v5`.
   Check first:
   ```bash
   # host
   python3 ../scripts/smali_frame.py work/smali/com/example/vault/Gate.smali --check
   ```
   Every `FRAGILE` line the tool reports inside `computeToken` is a raw `vN` that aliases a parameter
   and must be rewritten to its `pN` form **before** you change `.registers`.
3. **The insertion is after `move-result-object`.**
4. **No `move-result` after `Log.d`.** It returns an `int` we do not want, and discarding a return
   value by not collecting it is legal.

### Converting non-Strings

`Log.d` takes two `String`s. Anything else needs a conversion first:

```smali
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;
    invoke-static {v0}, Ljava/lang/String;->valueOf(Z)Ljava/lang/String;
    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;
    invoke-static {v0}, Ljava/util/Arrays;->toString([B)Ljava/lang/String;
```

each followed by `move-result-object` into the register you will pass. Note the `J` overload takes
**two** registers, because a `long` is two words.

### Prove it

```bash
# host
adb logcat -c && adb logcat -s SMALIPATCH:D VAULT:I
```

Tap COMPUTE TOKEN. The hex token appears in `logcat`. Change the PIN field text and tap again — the
token changes, which proves you are seeing the live value and not a constant you accidentally baked
in.

---

## Part E — Break it on purpose, then fix it

Do these deliberately. Each takes two minutes and immunises you against an hour of confusion later.

### E1 — Break the `move-result` rule

Move the two inserted lines in Patch 4 to sit *between* the `invoke-static` and the
`move-result-object`. Rebuild, install, tap COMPUTE TOKEN.

```bash
# host
adb logcat -c && adb logcat -s art:* AndroidRuntime:*
```

**Observe:** the app installs, launches, and the two other buttons still work. It dies only when you
touch the button that uses `Gate`. Read the rejection — it names the class, the method, and an
instruction offset.

**Fix:** move the insertion back below `move-result-object`.

### E2 — Use a register that does not exist

Change Patch 4's `.registers 10` back to `.registers 8` while leaving `v3` in the body.

**Observe:** `apktool b` fails. This one never reaches the device, because the assembler catches it.
That is the cheap failure; E1 is the expensive one.

### E3 — Use the wrong return family

In `checkPin`, replace `return v0` with `return-object v0`.

**Observe:** another `VerifyError` at class load. The register holds an `int`; `return-object`
declares it a reference; the method's descriptor says `Z`. Three-way disagreement.

**The lesson from E1–E3:** the assembler catches register-arithmetic mistakes, and the **verifier**
catches everything to do with types and instruction adjacency — at class load, on one screen, long
after install.

### E4 — Sign before aligning

```bash
# host
apktool b work/ -o p.apk
apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android --out s.apk p.apk
zipalign -p -f 4 s.apk bad.apk
apksigner verify -v bad.apk
```

**Observe:** verification fails, or `adb install` rejects it. Aligning moved bytes the signature
covers.

### E5 — Install over the original

Reinstall the original Gradle-built APK, then try `adb install signed.apk` **without** uninstalling.

**Observe:** `INSTALL_FAILED_UPDATE_INCOMPATIBLE`. The signing certificate is part of the app's
identity.

---

## Part F — Write it up

Produce a one-page finding for Patch 1, in the form a client will accept. It must contain:

1. **Title** — one line, naming the weakness and not the technique.
2. **Evidence** — the original Smali, the patched Smali, and the exact commands.
3. **Impact** — what an attacker gains, stated in terms of the client's business, not in terms of
   bytecode.
4. **Reproduction** — enough for someone else to repeat it.
5. **Remediation** — as code, not as advice. For Patch 1 the remediation is not "obfuscate the check";
   it is that the server must authorise every privileged operation, because any client-side check can
   be removed.
6. **Severity** — with a justification.

Compare yours against the worked example in
[`../examples/Pinner.smali`](../examples/Pinner.smali), at the bottom of the file.

---

## Success criteria

- [ ] All four patches installed and demonstrated at **level 3** — observable behaviour change.
- [ ] You ran the full pipeline from memory, in the right order, at least once.
- [ ] You produced and then fixed a `VerifyError`, and read it in `logcat`.
- [ ] You can state which mistakes the assembler catches and which the verifier catches.
- [ ] You can explain why `adb uninstall` is required.
- [ ] You diffed against a **round-tripped baseline**, not the original APK.
- [ ] You wrote a finding that does not contain the word "somehow".

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `apktool b` fails on resources | Re-decode with `-r`. You are not editing resources |
| `apktool b` fails naming a register | Raise `.locals`, or use a low register that is already free |
| `apksigner verify` reports no v2 signature | Old `apksigner`, or you signed with `jarsigner`. Use `apksigner` from build-tools 30+ |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | Different signing key. `adb uninstall` first |
| `INSTALL_PARSE_FAILED_NO_CERTIFICATES` | You installed the unaligned or unsigned intermediate. Install `signed.apk` |
| App installs, crashes on one screen | `VerifyError`. `adb logcat -s art:*` |
| App installs, runs, patch has no effect | You edited the wrong copy, the wrong tree (multidex — check `smali_classes2/`), or a method that is never called. Prove at level 1 first |
| `logcat` shows nothing from your tag | Wrong tag, or the level filter. Try `adb logcat | grep SMALIPATCH` |
| Everything works but the app crashes at launch after Patch 3 | You put the two lines above `.param` or above `.registers`. Directives come first |

## Next

[Lab 03 — Break the verifier on purpose](lab-03-break-the-verifier.md) turns the accidents of Part E
into a systematic tour of every rejection the verifier can produce, so none of them ever costs you an
hour again.
