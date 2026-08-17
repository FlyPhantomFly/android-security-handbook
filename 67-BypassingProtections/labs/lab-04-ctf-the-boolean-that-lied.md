# Lab 04 — CTF: the boolean that lied

> **Challenge.** An app holds a flag. It has one gate and one secret, and the two of them disagree
> about the same fact. Flip the gate and the secret comes out wrong. Satisfy the secret and the gate
> refuses. Both are true statements about the same boolean.
>
> Get the flag. Then get it again with no device at all.

**Difficulty:** CTF — the final exercise of chapter 67
**Time:** 90 minutes to 3 hours depending on how much you insist on doing it the hard way
**Root required:** no for the intended solution; helpful for two of the alternatives
**Flags:** two. `FLAG-A` on the device, `FLAG-B` offline.

---

## Rules

1. **You build the target.** Everything in this lab is source you compile yourself, in a scratch
   directory outside the repository. Nothing here is pointed at software you do not own.
2. **No reading the answers section until you have both flags** or have spent an hour stuck. The
   hints are graduated for exactly this.
3. **Record which device you used**, and record the time each stage took. The comparison is part of
   the exercise.

---

## Story

A developer read chapter 67 and took two lessons from it, in the wrong order.

The first lesson they took was the right one: *"a gate is bypassed; a dependency must be satisfied"*.
So they made the flag's decryption key **depend** on the environment rather than merely be guarded by
a check. There is no boolean to flip: if the environment is not what the key derivation expects, the
decryption produces garbage, silently, with no error.

The second lesson they took was a bad one, from a different document: *"ship a hidden developer mode
so support can diagnose problems in the field"*. So the vault is only reachable when the app is
running as a **debuggable build**.

Those two decisions are individually reasonable and jointly contradictory. Your job is to find the
contradiction and stand in it.

---

## Setup

### Step 0 — device identity

```bash
# host
adb devices -l && adb shell getprop ro.product.model && adb shell getprop ro.build.version.sdk
adb shell getenforce
```

This CTF was built and solved on **i9000S, Android 13 / API 33, arm64-v8a, Enforcing, not rooted**.

### Step 1 — the workspace

```bash
# host
mkdir -p /tmp/ch67-ctf && cd /tmp/ch67-ctf
export ANDROID_HOME=~/Android/Sdk
export SDK="$ANDROID_HOME"
export BT="$(ls -d $SDK/build-tools/* | sort -V | tail -1)"
export AJ="$(ls -d $SDK/platforms/*/android.jar | sort -V | tail -1)"
echo "$BT"; echo "$AJ"
```

### Step 2 — the manifest

`/tmp/ch67-ctf/AndroidManifest.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.pentest.ch67.ctf">
    <application android:label="CH67 CTF" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

### Step 3 — the challenge

`/tmp/ch67-ctf/MainActivity.java`:

```java
package com.pentest.ch67.ctf;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.graphics.Typeface;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.MessageDigest;

public class MainActivity extends Activity {

    static final String TAG = "CH67CTF";

    /*
     * The flag, XOR-encrypted with a key that is DERIVED FROM THE ENVIRONMENT.
     * There is no plaintext here and no boolean guarding it. If the derivation
     * produces the wrong key, decrypt() returns garbage and says nothing.
     */
    static final byte[] BLOB = {
        (byte) 0x8C, (byte) 0xAE, (byte) 0xA0, (byte) 0xAA, (byte) 0xB8, (byte) 0x33,
        (byte) 0xD7, (byte) 0xC5, (byte) 0x40, (byte) 0x60, (byte) 0x8C, (byte) 0x0E,
        (byte) 0x02, (byte) 0xCB, (byte) 0x08, (byte) 0x15, (byte) 0x39, (byte) 0x15,
        (byte) 0xE4, (byte) 0x4E, (byte) 0x6F, (byte) 0x61, (byte) 0xCF, (byte) 0x3F,
        (byte) 0xD0, (byte) 0xD5, (byte) 0xC4, (byte) 0x98, (byte) 0xDA, (byte) 0xC5,
        (byte) 0xC9, (byte) 0x92
    };

    static final String[] SU_PATHS = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/data/local/bin/su", "/data/adb/magisk"
    };

    TextView out;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (12 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);

        Button open = new Button(this);
        open.setText("Open the vault");
        root.addView(open);

        out = new TextView(this);
        out.setTypeface(Typeface.MONOSPACE);
        out.setTextIsSelectable(true);
        root.addView(out);
        setContentView(root);

        say("CH67 CTF. One gate, one secret, one boolean.");
        say("developer build: " + isDeveloperBuild());

        open.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { openVault(); }
        });
    }

    /* ---------------------------------------------------------------- */
    /* THE GATE.                                                        */
    /* ---------------------------------------------------------------- */

    /**
     * Support's "developer mode". The vault is only reachable from a
     * debuggable build.
     */
    static boolean isDeveloperBuild(ApplicationInfo ai) {
        return (ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    }

    boolean isDeveloperBuild() {
        return isDeveloperBuild(getApplicationInfo());
    }

    void openVault() {
        if (!isDeveloperBuild()) {
            say("REFUSED: vault is only available in a developer build.");
            Log.w(TAG, "gate refused");
            return;
        }
        String s = decrypt(deriveKey());
        say("VAULT: " + s);
        Log.i(TAG, "VAULT: " + s);
    }

    /* ---------------------------------------------------------------- */
    /* THE DEPENDENCY.                                                  */
    /*                                                                  */
    /* Note that this does NOT call isDeveloperBuild(). It reads the    */
    /* same fact from the same object, by a different route, on purpose.*/
    /* ---------------------------------------------------------------- */

    String canonicalEnvironment() {
        boolean dbg = (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;

        int tracer = -1;
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader("/proc/self/status"));
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    tracer = Integer.parseInt(line.substring(10).trim());
                    break;
                }
            }
        } catch (Throwable t) {
            tracer = -1;
        } finally {
            if (r != null) try { r.close(); } catch (Throwable ignored) { }
        }

        int su = 0;
        for (String p : SU_PATHS) { if (new File(p).exists()) su++; }

        String canon = "ch67|dbg=" + dbg + "|tracer=" + tracer + "|su=" + su;
        Log.d(TAG, "canonical=" + canon);      // remove this line for a harder CTF
        return canon;
    }

    byte[] deriveKey() {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(canonicalEnvironment().getBytes("UTF-8"));
        } catch (Throwable t) {
            return new byte[32];
        }
    }

    static String decrypt(byte[] key) {
        byte[] o = new byte[BLOB.length];
        for (int i = 0; i < BLOB.length; i++) {
            o[i] = (byte) (BLOB[i] ^ key[i % key.length]);
        }
        return new String(o);
    }

    void say(String s) { out.append(s); out.append("\n"); Log.i(TAG, s); }
}
```

> **Note on the `Log.d(TAG, "canonical=" + canon)` line.** It is there so that a first-time player
> can see the mechanism rather than brute-force it. **Delete it** before you hand the challenge to
> anybody else — with it removed, the CTF is considerably better, and the intended offline solution
> becomes the only comfortable route.

### Step 4 — build both variants

```bash
# host
cat > /tmp/ch67-ctf/mk.sh <<'EOF'
#!/usr/bin/env bash
# Build the CTF. Usage: ./mk.sh release | ./mk.sh debuggable
set -u
V="$1"; W="/tmp/ch67-ctf/out/$V"
rm -rf "$W"; mkdir -p "$W/src/com/pentest/ch67/ctf" "$W/classes"
p() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
cp /tmp/ch67-ctf/MainActivity.java "$W/src/com/pentest/ch67/ctf/"
if [ "$V" = "debuggable" ]; then
  sed 's#<application#<application android:debuggable="true"#' \
      /tmp/ch67-ctf/AndroidManifest.xml > "$W/AndroidManifest.xml"
else
  cp /tmp/ch67-ctf/AndroidManifest.xml "$W/AndroidManifest.xml"
fi
"$BT/aapt2" link -o "$(p "$W/base.apk")" -I "$(p "$AJ")" \
    --manifest "$(p "$W/AndroidManifest.xml")" --min-sdk-version 21 --target-sdk-version 33 || exit 1
javac --release 8 -nowarn -classpath "$(p "$AJ")" -d "$(p "$W/classes")" \
    "$W/src/com/pentest/ch67/ctf"/*.java 2>&1 | grep -vE 'obsolete|warning' || true
CF=(); while IFS= read -r f; do CF+=("$(p "$f")"); done < <(find "$W/classes" -name '*.class')
"$BT/d8" --lib "$(p "$AJ")" --min-api 21 --output "$(p "$W")" "${CF[@]}" || exit 1
( cd "$W" && python3 -B -c "
import shutil, zipfile
shutil.copy('base.apk','unaligned.apk')
z=zipfile.ZipFile('unaligned.apk','a',zipfile.ZIP_DEFLATED); z.write('classes.dex','classes.dex'); z.close()" ) || exit 1
KS=/tmp/ch67-ctf/out/ks
[ -f "$KS" ] || keytool -genkeypair -keystore "$(p "$KS")" -storepass android -keypass android \
    -alias c -dname "CN=CH67 CTF" -validity 10000 -keyalg RSA -keysize 2048 >/dev/null 2>&1
"$BT/zipalign" -f -p 4 "$(p "$W/unaligned.apk")" "$(p "$W/a.apk")" || exit 1
"$BT/apksigner" sign --ks "$(p "$KS")" --ks-pass pass:android --key-pass pass:android \
    --out "$(p "$W/$V.apk")" "$(p "$W/a.apk")" 2>&1 | grep -v WARNING
echo "built $W/$V.apk"
EOF
chmod +x /tmp/ch67-ctf/mk.sh
/tmp/ch67-ctf/mk.sh release
/tmp/ch67-ctf/mk.sh debuggable
```

---

## Stage 1 — meet the contradiction

```bash
# host
adb install -r /tmp/ch67-ctf/out/release/release.apk
adb shell am start -n com.pentest.ch67.ctf/.MainActivity
```

Tap **Open the vault**.

**C1.** What happened? Which of the five seams is the refusal at?

```bash
# host
adb install -r /tmp/ch67-ctf/out/debuggable/debuggable.apk
adb shell am start -n com.pentest.ch67.ctf/.MainActivity
```

Tap **Open the vault** again.

**C2.** What happened this time? Read it carefully — it is not an error message.

**C3.** State the contradiction in one sentence.

---

## Stage 2 — FLAG-A, on the device

You have two builds and one boolean read in two places. Get the flag.

**C4.** Before you write anything: which of the two builds do you want, and which of the two reads do
you want to change? There are two correct answers; find both.

**C5.** Write the bypass. Get `FLAG-A`.

**C6.** Now write the *other* bypass — the one against the other build — and confirm it also works.

**C7.** Which of your two bypasses is at a lower altitude? Which would survive R8 renaming? Which
would survive the developer merging the two reads into one method?

**C8.** Try the naive approach deliberately, so you have seen it fail: on the **release** build, hook
`getApplicationInfo` to return an `ApplicationInfo` with `FLAG_DEBUGGABLE` set. What comes out of the
vault, and why?

---

## Stage 3 — FLAG-B, with no device

The whole point of a dependency is that it is **computable**. Anything the app can derive from its
environment, you can derive too — if you know the environment.

**C9.** Read `canonicalEnvironment()`. On a clean, unrooted device with no debugger attached, what
exact string does it produce for the **release** build? Write it out character by character.

**C10.** Compute the key and decrypt `BLOB` offline. No device, no Frida, no root. That is `FLAG-B` —
and it is the same string as `FLAG-A`, which is the point.

**C11.** How long did C10 take compared with stages 1 and 2?

**C12.** The canonical string contains `tracer=0`. Under what circumstances would that be non-zero,
and what would happen to your offline computation? What does that tell you about how much entropy
this "dependency" really has?

---

## Stage 4 — fix it

You are the developer now.

**C13.** The single-line fix that kills the offline attack entirely. (Hint: what does the app have
that you do not, and cannot compute?)

**C14.** A second fix that kills stage 2 as well. State it in terms of the seam taxonomy.

**C15.** Rewrite `canonicalEnvironment()` so that a wrong answer is *detectable* by the app rather
than merely producing garbage. Then argue against your own change: why might silent garbage be the
better product decision?

**C16.** Compare your fixed design with [`examples/server-app/`](../examples/server-app/). Which of
your fixes does it already implement, and which one does it make unnecessary?

---

## Hints

<details>
<summary>Hint 1 — C3, the contradiction</summary>

The gate wants `FLAG_DEBUGGABLE` to be **set**. The key derivation bakes the *actual* value of
`FLAG_DEBUGGABLE` into the string it hashes. On the release build the key is right and the gate says
no; on the debuggable build the gate says yes and the key is wrong.

The same fact, read twice, is required to have two different values. That is not a bug in the
challenge — it is what happens whenever a developer uses a value both as a *gate* and as an
*input*, and it happens far more often in real code than you would expect.
</details>

<details>
<summary>Hint 2 — C4, which read to change</summary>

Notice that `openVault()` calls `isDeveloperBuild()`, while `canonicalEnvironment()` reads
`getApplicationInfo().flags` **directly**. They are two different call paths to the same fact.

That means you can change one without changing the other — which is exactly what you need, and
exactly what hooking `getApplicationInfo` would fail to do (see C8).

Two routes:
- **Release build**: make the *gate* say true, leave the derivation honest.
- **Debuggable build**: leave the gate honest, make the *derivation* read false.
</details>

<details>
<summary>Hint 3 — C5, the release-build bypass</summary>

```javascript
// frida -U -f com.pentest.ch67.ctf -l /tmp/ctf.js --no-pause
'use strict';
Java.perform(function () {
    const M = Java.use('com.pentest.ch67.ctf.MainActivity');
    // Hook ONLY the no-argument instance method - the gate. The static
    // overload taking an ApplicationInfo is not what openVault() calls, and
    // canonicalEnvironment() does not call either of them.
    M.isDeveloperBuild.overload().implementation = function () {
        console.log('[gate] forced true');
        return true;
    };
});
```

Then tap the button. If you get garbage, you hooked too much — check which overload you replaced.
</details>

<details>
<summary>Hint 4 — C8, why the naive approach fails</summary>

`getApplicationInfo()` is called by **both** `isDeveloperBuild()` and `canonicalEnvironment()`.
Hooking it satisfies the gate and simultaneously corrupts the key, because the derivation now reads
`dbg=true` on a build where it should read `dbg=false`.

You get past the gate and receive garbage. This is the single most instructive failure in the lab:
**a bypass at the wrong seam can be worse than no bypass**, because it succeeds visibly and fails
invisibly.
</details>

<details>
<summary>Hint 5 — C9/C10, the offline route</summary>

Everything in the canonical string is deterministic on a clean device:

- `dbg` — `false` for the release build,
- `tracer` — `0`, because nothing is ptrace-attached,
- `su` — `0`, because none of the five paths exists on a stock device.

So the string is fixed, the SHA-256 of it is fixed, and the XOR is trivial. Fourteen lines of Python
and no device.
</details>

<details>
<summary>Hint 6 — C13, the one-line fix</summary>

What does the app have that you cannot compute? Not the environment — you can read that. Not the
algorithm — it is in the DEX.

Something that only exists if a *server* chose to send it.
</details>

---

## Answers

<details>
<summary>Answers C1–C3 — the contradiction</summary>

**C1.** `REFUSED: vault is only available in a developer build.` The refusal is at **seam 4**, the
branch — `if (!isDeveloperBuild())`. It is loud, immediate and honest, which is why it is the easy
half.

**C2.** The vault "opens" and prints 32 bytes of garbage — mojibake, control characters, or
question-mark boxes depending on your renderer. It is not an error message and nothing in the app
suggests failure. This is the **dependency** failing, and it fails the way dependencies fail:
silently.

**C3.** The gate requires `FLAG_DEBUGGABLE` to be set; the key derivation hashes the actual value of
`FLAG_DEBUGGABLE`. Satisfying one guarantees breaking the other.
</details>

<details>
<summary>Answers C4–C8 — FLAG-A</summary>

**C4.** Two correct answers:
1. **Release build**, change the **gate**: hook `MainActivity.isDeveloperBuild()` (the no-argument
   overload) to return `true`. The derivation still reads `dbg=false`, which is correct for this
   build, so the key is right.
2. **Debuggable build**, change the **derivation**: hook the `/proc/self/status` read? No — hook
   `canonicalEnvironment()` to return the release-build string, or hook
   `ApplicationInfo.flags`-reading inside it. The gate is honestly satisfied.

Route 1 is cleaner because it changes one thing.

**C5 / C6.** Route 1 is in hint 3. Route 2:

```javascript
Java.perform(function () {
    const M = Java.use('com.pentest.ch67.ctf.MainActivity');
    M.canonicalEnvironment.implementation = function () {
        const real = this.canonicalEnvironment();
        console.log('[real canonical] ' + real);
        return 'ch67|dbg=false|tracer=0|su=0';
    };
});
```

Both produce:

```
VAULT: CH67{a_d3p3nd3ncy_1s_n0t_a_g4t3}
```

**C7.** Route 1 (the gate) is at **seam 4**; route 2 (the derivation) is at **seam 3**, since
`canonicalEnvironment` is an aggregation of reads. Neither is low. Both break under R8 renaming.

A genuinely low-altitude version of route 2 would hook the *reads* — the `FileReader` on
`/proc/self/status` and the `File.exists` calls — but note that it **cannot** change the `dbg` term,
because that is read directly from an object field with no interposable call. That limitation is
itself a finding about the design: one of the three terms is not attackable at seam 2 at all.

If the developer merged the two reads into one method, route 1 would stop working (it would corrupt
the key) and route 2 would become the only option.

**C8.** You get past the gate and the vault returns garbage. `getApplicationInfo()` is on both call
paths, so satisfying the gate corrupts the key. A bypass at the wrong seam succeeded visibly and
failed invisibly — which, in a real engagement where you did not know the right answer, would have
cost you an hour of debugging your own script.
</details>

<details>
<summary>Answers C9–C12 — FLAG-B</summary>

**C9.** `ch67|dbg=false|tracer=0|su=0`

**C10.**

```python
#!/usr/bin/env python3
import hashlib
canon = "ch67|dbg=false|tracer=0|su=0"
key = hashlib.sha256(canon.encode()).digest()
blob = bytes([
    0x8C,0xAE,0xA0,0xAA,0xB8,0x33,0xD7,0xC5,0x40,0x60,0x8C,0x0E,0x02,0xCB,0x08,0x15,
    0x39,0x15,0xE4,0x4E,0x6F,0x61,0xCF,0x3F,0xD0,0xD5,0xC4,0x98,0xDA,0xC5,0xC9,0x92])
print(''.join(chr(b ^ key[i % 32]) for i, b in enumerate(blob)))
# CH67{a_d3p3nd3ncy_1s_n0t_a_g4t3}
```

**C11.** Under five minutes, against 30–60 for stage 2 — and it needs no device, no root, no Frida
and no signing key. Exactly the lesson of [lab 03](lab-03-when-to-stop.md): fastest-to-first-result
and best are different questions.

**C12.** `tracer` is non-zero only while something is ptrace-attached — a debugger, `strace`, or a
Frida injection in progress. If the app were run under a debugger the derivation would produce a
different key, and your offline computation would be wrong.

But look at the entropy: `dbg` has 2 values, `tracer` is 0 in every ordinary case, `su` ranges 0–5.
That is perhaps four bits of real entropy. A "dependency" whose input space you can enumerate in a
loop is a **gate wearing a disguise**, and that is the deeper lesson of stage 3: making the key
depend on the environment only helps if the environment is not guessable.
</details>

<details>
<summary>Answers C13–C16 — the fix</summary>

**C13.** Mix in a value the app cannot compute and you cannot enumerate: a **server-issued nonce or
key fragment**. `key = SHA-256(canonical || serverSecret)`. Now the input space is not four bits, and
no amount of offline computation helps, because one term never existed on the device until the server
sent it.

**C14.** Stop reading the same fact twice at two seams. Better: remove the gate entirely and let the
dependency do the work — if the key derivation is correct, the vault opens; if not, it does not.
A gate that can be satisfied independently of the dependency is pure attack surface. In seam terms:
**delete seam 4 and rely on the fact that seam 5's output is worthless without the right input.**

**C15.** Add an authenticator: append a known constant to the plaintext before encryption, or use an
AEAD such as AES-GCM, and verify it after decryption. Then a wrong key is *detected* rather than
silently producing garbage.

The argument against your own change: silent garbage costs the attacker far more. A clear
"integrity check failed" message tells them immediately that they are on the wrong track and lets
them iterate in seconds; garbage may cost them an hour. Against a **real user** hitting a false
positive, the calculation inverts completely — silent garbage means silently wrong data with no
error, and that is a correctness incident, not a security control.

There is no universally right answer, which is why this is C15 and not a rule.

**C16.** [`examples/server-app/`](../examples/server-app/) already implements C13 in its strongest
form — it does not derive the secret at all, it **receives** it — and that makes C14 unnecessary,
because there is no local gate left to bypass. It also implements the nonce that C12 says you need,
and its comments say explicitly which attacks that does and does not stop.
</details>

---

## Scoreboard

| | Flag | Route | Typical time |
|---|---|---|---|
| **FLAG-A** | `CH67{a_d3p3nd3ncy_1s_n0t_a_g4t3}` | Hook the gate on the release build, or the derivation on the debuggable build | 30–60 min |
| **FLAG-B** | the same string | SHA-256 of a 28-character constant, XOR, no device | under 5 min |

If you got FLAG-B first, you were reading the code instead of poking the app, and you were right.

---

## Success criteria

- [ ] You built both variants and reproduced the contradiction yourself
- [ ] You obtained FLAG-A by **two** different routes and can say which seam each attacked
- [ ] You deliberately ran the `getApplicationInfo` bypass and watched it fail *visibly at the gate
      and invisibly at the key*
- [ ] You obtained FLAG-B with no device involved
- [ ] You can state how much real entropy the "dependency" had, and why that matters
- [ ] You wrote the one-line fix, and can explain why it makes the offline route impossible
- [ ] You compared your fixed design with the server-side example

---

## Clean up

```bash
# host
adb uninstall com.pentest.ch67.ctf
rm -rf /tmp/ch67-ctf
adb reverse --remove-all
```

---

## Where to go next

You have finished chapter 67. The natural continuations:

- [37-RootDetection](../../37-RootDetection/README.md) and
  [36-CertificatePinning](../../36-CertificatePinning/README.md) for the two controls this chapter
  treats as instances of a general method.
- [40-Obfuscation](../../40-Obfuscation/README.md) for the same adversarial structure applied to code.
- [49-KeyStore](../../49-KeyStore/README.md) for what a real dependency looks like: key material that
  never enters the process, however instrumented it is.
- [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) for where all of this is filed, and at what
  severity.
