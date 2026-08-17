# Lab 04 — CTF: The Lying Phone

**Difficulty:** Advanced / CTF
**Time:** 4–6 hours
**Chapter:** [20 — Security Architecture](../README.md) §3.1, §3.2, §3.6, §3.9, §5.9, §9.2, §9.3
**Prerequisites:** [Lab 01](lab-01-device-posture.md), [Lab 02](lab-02-vbmeta-and-verified-boot.md),
[Lab 03](lab-03-integrity-gate-bypass.md), [53 — Frida](../../53-Frida/README.md),
[34 — Cryptography](../../34-Cryptography/README.md), Node 16+ on the host, a rooted device or AVD

---

## The challenge

An application called **The Lying Phone** unlocks a vault in three stages. On a Play-installed device
with a locked bootloader it walks through all three and shows the contents. On your device it stops at
stage one.

```
Stage 1  BOOT STATE ......... FAILED
Stage 2  SYSTEM INTEGRITY ... locked
Stage 3  ATTESTATION ........ locked
```

Each stage releases a flag fragment of the form `ARCHLAB{...}`.

**Defeat all three. Then answer the question in Stage 4** — which is the reason this lab exists, and
which is worth more than the three fragments put together.

---

## Objective

Three checks. Three defeats. One conclusion.

By the end you will be able to look at any client-side integrity control and say, within about a
minute and before touching a tool, whether it is *badly implemented* or *structurally unsound* — and
those are completely different findings with completely different remediations. Most testers cannot
make that distinction, which is why most reports recommend "harden the checks" when the correct
recommendation is "delete the checks and move the decision".

## What this lab is *not*

It is not [37's CTF](../../37-RootDetection/labs/lab-04-ctf-decoupled.md). That challenge is about a
check whose *consequence is decoupled from its cause*: your methodology fails, you spend an afternoon
inside correct cryptography, and the lesson is about data-flow versus control-flow analysis. There is
no obfuscation here, no native code, no inline syscalls, and nothing hidden. Every check in this lab
announces itself, and you will find all three in under ten minutes.

The difficulty is not in *finding* the checks. It is in explaining, afterwards, why two of them were
never going to work and one of them could have.

There is also no root detection here — no `su` probes, no Magisk artefacts, no package enumeration.
That subject belongs to [37 — Root Detection](../../37-RootDetection/README.md). This lab is about the
platform's own assertions: what Verified Boot and dm-verity actually guarantee, who is entitled to
believe those guarantees, and where the belief has to happen.

---

## Rules

- **No reading the flag fragments out of the DEX.** They are in there, in plaintext, and finding them
  takes two minutes. Doing so skips the entire lab. (Keep the observation, though — Stage 4 asks you
  about it, and the answer matters.)
- **Stage 3 must be solved by producing a token the application accepts.** Hooking the verification
  method is forbidden. You already did that in Lab 03; doing it again teaches nothing, and the
  forgery is what sets up the closing question.
- **Solve stage 2 twice**, by two different mechanisms, and be able to say which one you would use on
  a real target and why.
- You must be able to state, for each stage, *what you had to control* in order to defeat it. Write
  it down as you go. Stage 4 is that list, re-read.
- No reading Stage 4 before you have all three fragments. It gives away the answer.

---

## Building the challenge

Build it. You cannot argue convincingly about a design you have never implemented, and the closing
question is an argument.

New Android project, Empty Views Activity, **Java**, minSdk 24, package
**`com.archlab.lyingphone`**.

### The manifest

```xml
<!-- app/src/main/AndroidManifest.xml -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android">

    <uses-permission android:name="android.permission.INTERNET" />

    <!-- Lab only. Cleartext to a loopback stub. On a real app this attribute
         alone is a finding; see the chapter's section 8.2. -->
    <application
        android:label="The Lying Phone"
        android:usesCleartextTraffic="true">
        <activity android:name=".LyingPhoneActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

### The three stages

**`app/src/main/java/com/archlab/lyingphone/Stages.java`**

```java
package com.archlab.lyingphone;

import android.util.Base64;

import org.json.JSONObject;

import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Three checks, in increasing order of how much they cost their author, and in
 * DECREASING order of how much they were ever going to be worth. Work out why
 * that ordering is the way round it is; that is stage 4.
 */
public final class Stages {

    // ---------------------------------------------------------------- flags
    // Yes, these are plaintext constants in the DEX. See the rules, and then
    // see stage 4's first question -- their being here is not an oversight.
    static final String FLAG_1 = "ARCHLAB{green_is_a_string_in_a_writable_page}";
    static final String FLAG_2 = "ARCHLAB{you_cannot_forge_the_hash_only_the_comparison}";
    static final String FLAG_3 = "ARCHLAB{the_client_verified_its_own_certificate}";

    // =====================================================================
    // STAGE 1 -- BOOT STATE
    // The bootloader really did verify the boot chain, and really did report
    // the outcome. Chapter section 3.1 and section 4.5 describe the whole path.
    // The question stage 4 will ask is not "is this true" but "who is entitled
    // to believe it".
    // =====================================================================

    public static boolean stageOne() {
        return "green".equals(prop("ro.boot.verifiedbootstate"))
            && "1".equals(prop("ro.boot.flash.locked"))
            && "enforcing".equals(prop("ro.boot.veritymode"));
    }

    // =====================================================================
    // STAGE 2 -- SYSTEM INTEGRITY
    // Hash a file on the read-only system partition and compare against a
    // digest recorded from a reference image. Note what this duplicates:
    // dm-verity already hashes every block of this partition, in the kernel,
    // against a root hash signed by the OEM (chapter section 3.2). This code
    // does the same job again, in user space, in the attacker's process,
    // against a constant that goes stale on the next OTA.
    // =====================================================================

    static final String WATCHED_FILE = "/system/etc/security/otacerts.zip";

    /**
     * Digest of the reference image's copy of WATCHED_FILE.
     *
     * FOR THE LAB: put ANY value here that your device does not produce -- the
     * point is that the comparison fails, not which image it came from. Compute
     * your device's real value with:
     *     adb shell sha256sum /system/etc/security/otacerts.zip
     * and then change one character of it.
     */
    static final String REFERENCE_DIGEST =
            "0000000000000000000000000000000000000000000000000000000000000000";

    public static boolean stageTwo() {
        InputStream in = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            in = new FileInputStream(WATCHED_FILE);
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                md.update(buf, 0, n);
            }
            return REFERENCE_DIGEST.equalsIgnoreCase(hex(md.digest()));
        } catch (Throwable t) {
            return false;
        } finally {
            try { if (in != null) in.close(); } catch (Throwable ignored) { }
        }
    }

    // =====================================================================
    // STAGE 3 -- ATTESTATION
    // A Play-Integrity-shaped flow: obtain a nonce, obtain a signed token from
    // an attestation provider, check the token, read the verdict.
    //
    // Everything about the SHAPE of this is right. Read it carefully before
    // stage 4 and decide, for yourself, exactly which lines are wrong -- there
    // are four defects and they are not equally serious.
    // =====================================================================

    /** The attestation provider. Reachable through `adb reverse tcp:8098 tcp:8098`. */
    static final String PROVIDER = "http://127.0.0.1:8098/token";

    /**
     * The key used to verify the token. It is in the APK because the app does
     * the verification itself -- which is the documented "classic" on-device
     * decryption pattern that chapter section 3.6 tells you never to use for a
     * security decision.
     */
    static final String VERIFY_KEY = "arch-lab-classic-decryption-key-v1";

    public static boolean stageThree() {
        try {
            // The nonce. Unpredictable, single-use, cryptographically strong --
            // and generated on this device, by this process. Hold that thought.
            byte[] raw = new byte[32];
            new SecureRandom().nextBytes(raw);
            String nonce = Base64.encodeToString(
                    raw, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);

            String token = fetch(PROVIDER + "?nonce=" + nonce);
            return verifyToken(token, nonce);
        } catch (Throwable t) {
            return false;
        }
    }

    /** Local token verification. Four defects live in this method. */
    static boolean verifyToken(String token, String expectedNonce) throws Exception {
        String[] p = token.trim().split("\\.");
        if (p.length != 3) {
            return false;
        }

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(
                VERIFY_KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] want = mac.doFinal(
                (p[0] + "." + p[1]).getBytes(StandardCharsets.US_ASCII));
        byte[] got = Base64.decode(p[2], Base64.URL_SAFE | Base64.NO_WRAP);
        if (!Arrays.equals(want, got)) {
            return false;
        }

        JSONObject payload = new JSONObject(new String(
                Base64.decode(p[1], Base64.URL_SAFE | Base64.NO_WRAP),
                StandardCharsets.UTF_8));

        // The nonce IS checked. Ask yourself what that check is worth, given
        // where the nonce came from.
        String nonce = payload.getJSONObject("requestDetails").getString("nonce");
        if (!expectedNonce.equals(nonce)) {
            return false;
        }

        // requestPackageName: not checked.
        // timestampMillis:    not checked.

        return payload.getJSONObject("deviceIntegrity")
                      .getJSONArray("deviceRecognitionVerdict")
                      .toString()
                      .contains("MEETS_DEVICE_INTEGRITY");
    }

    // ------------------------------------------------------------- helpers

    static String fetch(String spec) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(spec).openConnection();
        c.setConnectTimeout(3000);
        c.setReadTimeout(3000);
        try {
            InputStream in = c.getInputStream();
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            byte[] b = new byte[4096];
            int n;
            while ((n = in.read(b)) > 0) {
                bos.write(b, 0, n);
            }
            return bos.toString("UTF-8");
        } finally {
            c.disconnect();
        }
    }

    static String prop(String key) {
        try {
            Class<?> cls = Class.forName("android.os.SystemProperties");
            Method g = cls.getMethod("get", String.class, String.class);
            return (String) g.invoke(null, key, "");
        } catch (Throwable t) {
            return "";
        }
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }

    private Stages() { }
}
```

### The UI

**`app/src/main/java/com/archlab/lyingphone/LyingPhoneActivity.java`**

```java
package com.archlab.lyingphone;

import android.app.Activity;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public class LyingPhoneActivity extends Activity {

    private TextView out;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        out = new TextView(this);
        out.setTextSize(12f);
        out.setTypeface(Typeface.MONOSPACE);

        Button run = new Button(this);
        run.setText("Open vault");
        run.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                out.setText("working...");
                // Stage 3 does network I/O; keep it off the main thread.
                new Thread(new Runnable() {
                    @Override public void run() {
                        final String text = evaluate();
                        new Handler(Looper.getMainLooper()).post(new Runnable() {
                            @Override public void run() { out.setText(text); }
                        });
                    }
                }).start();
            }
        });

        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(24, 96, 24, 24);
        col.addView(run);
        col.addView(out);

        ScrollView sv = new ScrollView(this);
        sv.addView(col);
        setContentView(sv);

        out.setText("Ready.");
    }

    /** Sequential gating: each stage is only attempted if the previous passed. */
    private String evaluate() {
        StringBuilder sb = new StringBuilder();

        if (!Stages.stageOne()) {
            sb.append("Stage 1  BOOT STATE ......... FAILED\n");
            sb.append("Stage 2  SYSTEM INTEGRITY ... locked\n");
            sb.append("Stage 3  ATTESTATION ........ locked\n");
            return sb.toString();
        }
        sb.append("Stage 1  BOOT STATE ......... PASSED  ")
          .append(Stages.FLAG_1).append('\n');

        if (!Stages.stageTwo()) {
            sb.append("Stage 2  SYSTEM INTEGRITY ... FAILED\n");
            sb.append("Stage 3  ATTESTATION ........ locked\n");
            return sb.toString();
        }
        sb.append("Stage 2  SYSTEM INTEGRITY ... PASSED  ")
          .append(Stages.FLAG_2).append('\n');

        if (!Stages.stageThree()) {
            sb.append("Stage 3  ATTESTATION ........ FAILED\n");
            return sb.toString();
        }
        sb.append("Stage 3  ATTESTATION ........ PASSED  ")
          .append(Stages.FLAG_3).append('\n');

        sb.append("\nVault open.\n");
        return sb.toString();
    }
}
```

### The attestation provider

This stands in for **Play services plus Google's servers**. Run it on the host. It is deliberately
*honest*: it reports what your device actually is, which on a rooted or emulated device is an empty
verdict array.

**`provider-stub.js`** — host, scratch directory, no dependencies.

```javascript
// host — provider-stub.js
// node provider-stub.js
// adb reverse tcp:8098 tcp:8098      <- so the device's 127.0.0.1 reaches here
//
// Stands in for the attestation provider. Note the key: it is SHARED with the
// app, because the app verifies the token itself. Remember that when you get
// to stage 4 -- it is the single most consequential line in this file.
'use strict';
const http = require('node:http');
const crypto = require('node:crypto');

const KEY = 'arch-lab-classic-decryption-key-v1';
const PKG = 'com.archlab.lyingphone';

// The provider is honest. Your device does not meet device integrity, so this
// is what it says. Do not edit this array; forging the verdict is your job,
// not the provider's.
const VERDICTS = [];

const b64u = b => Buffer.from(b).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

http.createServer((req, res) => {
    const u = new URL(req.url, 'http://placeholder');
    const nonce = u.searchParams.get('nonce') || '';
    const header = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const payload = b64u(JSON.stringify({
        requestDetails: {
            requestPackageName: PKG,
            timestampMillis: Date.now(),
            nonce: nonce
        },
        deviceIntegrity: { deviceRecognitionVerdict: VERDICTS },
        appIntegrity: { appRecognitionVerdict: 'PLAY_RECOGNIZED' }
    }));
    const sig = b64u(crypto.createHmac('sha256', KEY)
        .update(header + '.' + payload).digest());
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end(header + '.' + payload + '.' + sig);
    console.log('minted token for nonce ' + nonce.slice(0, 12) + '...');
}).listen(8098, '127.0.0.1', () => console.log('provider stub on 127.0.0.1:8098'));
```

### Build, install, confirm

```bash
# host
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb reverse tcp:8098 tcp:8098
node provider-stub.js &
adb shell am start -n com.archlab.lyingphone/.LyingPhoneActivity
```

Tap **Open vault**. You should see stage 1 fail and everything below it locked. Now stop being the
developer.

---

## Stage 1 — Boot state

### What you are looking at

The bootloader verified the boot chain against a key burned into hardware and reported the outcome. On
a locked, unmodified device that outcome is `green`. Nothing about that is a lie, a trick, or a
strawman: it is Verified Boot working exactly as chapter §3.1 describes.

**Q1.** Before you touch anything: run [`scripts/integrity-observer.js`](../scripts/integrity-observer.js)
and confirm which three properties the app reads. How long did that take, and how much of stage 1
did it solve?

**Q2.** Trace one of those values backwards from the Java `String` the app receives to the physical
thing that produced it. Name every stage. (Chapter §4.5; you did this in
[Lab 01](lab-01-device-posture.md).) At which stage does the value stop being protected by anything?

**Q3.** Now the question the whole stage exists for. The bootloader's claim is **true**. The
transport is **honest**. So what, precisely, is the defect? Answer in one sentence that contains the
word "reader".

### Defeat it

Two routes; do at least one, and understand both.

```bash
# device root (Magisk) — route A: change the property for the whole device
resetprop ro.boot.verifiedbootstate green
resetprop ro.boot.flash.locked 1
resetprop ro.boot.veritymode enforcing
```

```javascript
// route B — lie to this process only.  frida -U -f com.archlab.lyingphone -l s1.js --no-pause
'use strict';
const SAFE = {
    'ro.boot.verifiedbootstate': 'green',
    'ro.boot.flash.locked': '1',
    'ro.boot.veritymode': 'enforcing'
};
Java.perform(function () {
    Java.use('android.os.SystemProperties').get
        .overload('java.lang.String', 'java.lang.String')
        .implementation = function (k, d) {
            if (Object.prototype.hasOwnProperty.call(SAFE, k)) {
                console.log('[s1] ' + k + ' -> ' + SAFE[k]);
                return SAFE[k];
            }
            return this.get(k, d);
        };
});
```

**Q4.** Route B hooks only the two-argument overload. Why is that sufficient here, and what would you
have to check on a real target before making that assumption?

**Q5.** Write down, in the exact words you will reuse in Stage 4: *what did you have to control in
order to defeat stage 1?*

Fragment 1 is now on screen. Record it.

---

## Stage 2 — System integrity

### What you are looking at

The app hashes a file on the read-only `system` partition and compares the digest against a constant.
SHA-256 is not broken. You cannot construct a file with a chosen digest. The comparison is
`equalsIgnoreCase` on a hex string, which is correct if unfashionable.

**Q6.** `system` is protected by dm-verity: every block is hashed into a Merkle tree whose root hash
is signed by the OEM and checked by the *kernel*, on every read (chapter §3.2). The app is therefore
re-implementing, in user space, a verification the kernel already performed. List three concrete ways
the app's version is **worse** than the kernel's. (There are more than three.)

**Q7.** Magisk does not modify `/system` — it works through mount namespaces and a patched boot image
(chapter §3.2, and [62 — Magisk](../../62-Magisk/README.md)). So on a Magisk device, is the *file*
the app reads the same file the kernel verified? Under what circumstances is it not, and what does
that do to the meaning of the app's digest?

**Q8.** Can you produce a file whose SHA-256 equals `REFERENCE_DIGEST`? Answer honestly, then explain
why the honest answer does not stop you.

### Defeat it, twice

**Mechanism 1 — control the answer.**

```javascript
// s2-digest.js — return the expected digest from the hash, without touching the file
'use strict';
Java.perform(function () {
    const S = Java.use('com.archlab.lyingphone.Stages');
    const MD = Java.use('java.security.MessageDigest');
    const expected = S.REFERENCE_DIGEST.value;

    // Turn the hex constant back into bytes and hand them out as "the digest".
    const bytes = [];
    for (let i = 0; i < expected.length; i += 2) {
        let v = parseInt(expected.substr(i, 2), 16);
        bytes.push(v > 127 ? v - 256 : v);      // Java bytes are signed
    }

    MD.digest.overload().implementation = function () {
        const real = this.digest();
        console.log('[s2] MessageDigest.digest() intercepted; real length ' +
                    real.length);
        return bytes;
    };
});
```

> **⚠️ Warning**
> That hook replaces the return of **every** `MessageDigest.digest()` in the process, including ones
> the framework makes. It works for a five-second CTF and it is exactly the kind of shotgun that
> [37's Lab 03](../../37-RootDetection/labs/lab-03-trace-and-neutralise.md) warns will break an app in
> ways indistinguishable from detection. Narrow it — check the caller, or hook
> `Stages.stageTwo` instead — before you use anything like it on a real target.

**Mechanism 2 — control the constant.** Patch the APK. Change `REFERENCE_DIGEST` to your device's real
digest, repackage, re-sign.

```bash
# host
adb shell sha256sum /system/etc/security/otacerts.zip
apktool d app-debug.apk -o lp_out
grep -rn '0000000000000000' lp_out/smali*/com/archlab/lyingphone/Stages.smali
# edit the const-string to your device's digest
apktool b lp_out -o lp_patched.apk
zipalign -f 4 lp_patched.apk lp_aligned.apk
apksigner sign --ks debug.keystore --ks-pass pass:android lp_aligned.apk
adb install -r lp_aligned.apk
```

**Q9.** Both mechanisms worked. Which would you use on a real engagement, and why? Consider: what
happens to mechanism 2 if the app also verifies its own signature (a subject in its own right —
tamper detection), and what happens to mechanism 1 if the check moves into a native library?

**Q10.** A third mechanism exists that you were not asked to use: on a Magisk device you can bind-mount
a file of your choosing over `/system/etc/security/otacerts.zip` *in the app's mount namespace only*.
Explain why that mechanism cannot help you here, and then describe the situation in which it would be
the *only* mechanism that works.

**Q11.** Same question as before, in the same words: *what did you have to control in order to defeat
stage 2?*

Fragment 2 is now on screen.

---

## Stage 3 — Attestation

### What you are looking at

Read `stageThree()` and `verifyToken()` before you do anything. This stage has the right *shape*: a
nonce, a signed token from an attestation provider, signature verification, a nonce check, a verdict.
Chapter §3.6's sequence diagram has ten steps and this code implements six of them.

**Q12.** There are **four** defects in this flow. Find all four before reading on, and rank them. For
each, state what an attacker gains from it. Write your ranking down — Stage 4 will ask you to revise
it, and you want a record of what you thought first.

<details>
<summary>Only open this once you have written four defects down</summary>

1. **The nonce is generated on the device.** `SecureRandom` is not the problem; the *location* is. A
   nonce exists to prove freshness *to the party that issued it*. A nonce you issued to yourself
   proves nothing to anyone.
2. **The verification key is in the APK.** It is symmetric, so "verify" and "mint" are the same
   capability. The moment the client can check the signature, the client can forge it.
3. **`requestPackageName` is not checked.** A token minted for any other application is accepted.
4. **`timestampMillis` is not checked.** A token from any point in the past is accepted forever.

Now rank them. Most people rank 2 first because it is the one they will use. Keep your ranking; you
will be asked to defend it against a different one in Stage 4.
</details>

### Defeat it

Remember the rule: **you may not hook `verifyToken`.** You must produce a token the application
accepts.

**Q13.** Extract the verification key from the APK. Which command, and how long did it take?

```bash
# host
jadx -d lp_jadx app-debug.apk
grep -rn 'VERIFY_KEY\|arch-lab' lp_jadx/sources/com/archlab/lyingphone/Stages.java
# or, without a decompiler at all:
strings -a lp_out/smali*/com/archlab/lyingphone/Stages.smali | grep arch-lab
```

**Q14.** You now hold the key. But the token must carry the nonce the app generated *this run*, and
you do not know it in advance. Name the three places you could obtain or influence that nonce, then
pick one.

<details>
<summary>Hint — the cheapest of the three</summary>

You do not need to intercept the nonce at all. The app sends it *to you*: the request arrives at your
provider stub with `?nonce=...`. You are already standing exactly where the nonce goes.

The other two routes, for completeness: hook `SecureRandom.nextBytes` to make the nonce predictable,
or hook `Stages.fetch` and mint the reply in-process. All three work. Only one requires no
instrumentation at all, and that is the one worth noticing — because it is the shape of the real
attack on this design.
</details>

**The forgery.** Modify your provider stub, or write a second one:

```javascript
// host — forge.js. Not a bypass: a mint. Same key, different verdict.
'use strict';
const http = require('node:http');
const crypto = require('node:crypto');

const KEY = 'arch-lab-classic-decryption-key-v1';   // straight from the APK

const b64u = b => Buffer.from(b).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

http.createServer((req, res) => {
    const nonce = new URL(req.url, 'http://x').searchParams.get('nonce') || '';
    const header = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const payload = b64u(JSON.stringify({
        requestDetails: {
            // Wrong package name ON PURPOSE. The app does not check it, and
            // proving that is worth a separate finding.
            requestPackageName: 'com.someone.else',
            timestampMillis: 0,                 // 1 January 1970. Also unchecked.
            nonce: nonce
        },
        deviceIntegrity: {
            deviceRecognitionVerdict: ['MEETS_STRONG_INTEGRITY']
        }
    }));
    const sig = b64u(crypto.createHmac('sha256', KEY)
        .update(header + '.' + payload).digest());
    res.end(header + '.' + payload + '.' + sig);
}).listen(8098, '127.0.0.1', () => console.log('forging on 127.0.0.1:8098'));
```

Kill the honest stub, run this, tap **Open vault**.

**Q15.** The forged token claims a different package and a timestamp of zero, and the app accepted it.
Write those as two separate findings, one sentence each, in the style of Lab 03's model finding.

**Q16.** Try it once more with a deliberately corrupted signature. What fails, and where? You have now
demonstrated that exactly one of the four checks in `verifyToken` is doing any work — and that the one
doing the work is defended by a key you have a copy of.

**Q17.** *What did you have to control in order to defeat stage 3?*

Fragment 3 is on screen. All three stages are defeated. Stop here and take a break before Stage 4;
it is a different kind of work.

---

## Stage 4 — The question

> **Do not skim this section. It is the reason the other three exist.**

You have defeated three checks. Now identify **which one of the three could not have been defeated,
had it been implemented correctly** — and explain why.

Everyone's first instinct is one of two wrong answers. Work through the derivation rather than
guessing.

### Step 1 — Re-read your three answers

You wrote down, after each stage, what you had to control. Put them in one table.

| Stage | What you had to control | Was it on your device? | Could a better implementation have taken it away from you? |
|---|---|---|---|
| 1 — boot state | | | |
| 2 — system file hash | | | |
| 3 — attestation token | | | |

Fill in columns two and three before reading further. Column four is the lab.

### Step 2 — Six questions that produce the answer

**Q18.** For stage 1: suppose the developer reads the check in native code with inline syscalls, adds
`ro.boot.vbmeta.digest`, cross-checks `/proc/cmdline`, and obfuscates every string. You now need an
hour instead of a minute. Has anything *structural* changed? State the invariant that survives every
one of those improvements.

**Q19.** For stage 2: suppose the developer hashes forty files instead of one, uses BLAKE2 instead of
SHA-256, moves it native, and refreshes the reference digests from a server. Same question. What
invariant survives?

**Q20.** Now state the invariant that stages 1 and 2 share, in one sentence, in a form that mentions
neither properties nor hashes. If your sentence names a *technique*, it is not general enough. Try
again until it names a *location*.

**Q21.** For stage 3: you forged a token. List the specific things you needed in order to do it. There
are exactly two. Now cross out any of them that a different implementation of the same design could
have denied you.

**Q22.** Suppose the token were signed with a **private** key you have never had — Google's — and the
app still verified it locally, in-process, with the corresponding public key baked into the APK. You
can no longer mint a token. Are you stopped? Describe precisely what you would do instead, and how
long it would take.

**Q23.** Suppose the token were signed with a key you have never had, the nonce were issued by a
server you do not control, and the verification happened on that server. Now describe what you would
do. Be honest about where the attack surface has moved to.

### Step 3 — The answer

> **📖 Definition — locally evaluated**
> A check is *locally evaluated* when both the observation and the decision that consumes it occur
> inside a process the adversary controls. The quality of the observation is irrelevant to this
> definition, which is exactly why the definition is useful.

**The only one of the three that could have resisted you is stage 3, the attestation token — and only
if it had been implemented as a *server-verified* token: a verdict signed by a key the device never
holds, bound to a nonce the server issued, decoded and checked on the server.**

The reasoning, in full:

**Stages 1 and 2 are locally evaluated by construction, and no implementation quality changes that.**
The device reports its boot state to itself and believes itself. The app hashes a file with code
running under a UID the device's owner controls, and compares the result with a constant that is in
the attacker's storage, inside a process whose memory the attacker can rewrite. Every improvement
available to the developer — native code, obfuscation, more signals, better hash functions, checking
the checker — moves the same decision to a slightly less convenient place *inside the same trust
domain*. There is no version of "check the boot state on the device" that the device's owner cannot
answer for. That is not a bug in the implementation; it is the definition of the situation.

Note carefully what this argument does *not* say. It does not say the boot state is meaningless — the
boot state is one of the most meaningful facts about a device in this entire chapter. It says that
**an application asking the device about the device gets an answer from the adversary**. The fact and
the reader of the fact are different problems.

**Stage 3 is different in kind, because the statement is produced outside the device.** The
attestation provider — Play services talking to Google's servers, or the TEE producing a key
attestation certificate — signs a claim with a private key that has never existed in the normal world
of your handset. That signature is a fact the attacker cannot manufacture. The question is only ever
*who checks it*, and this implementation answered that question wrongly in four ways at once:

| Defect | Why it is fatal on its own |
|---|---|
| Verification happens in the app | Whatever the check concludes, the attacker rewrites the conclusion. Even a perfect signature check is a branch in a process they own. |
| The key is symmetric and shipped in the APK | "Able to verify" and "able to forge" are the same capability. This is the one you used. |
| The nonce is generated on the device | Freshness is a claim made to the issuer. Self-issued, it proves nothing, so any captured token is replayable forever. |
| No package or timestamp binding | A token from any app, from any time, is accepted. |

Fix the first three and the attack you performed stops working, because you would need Google's
private key and the server's nonce — neither of which is on your device, and neither of which any
amount of local instrumentation can produce.

**The general rule, which is the thing to carry out of this chapter:**

> A device-integrity claim is worth something exactly when the party that *produces* it and the party
> that *verifies* it are both outside the attacker's control. The claim's content — boot state,
> partition hash, patch level — is not what makes it strong or weak. Its **endpoints** are.

That is why stage 3 is the only candidate. Stages 1 and 2 have both endpoints on the phone.

### Step 4 — The correct implementation, as code

Do not take the argument on trust. Run it.

The three roles must be physically separate: a **provider** that holds a private key, a **client** that
holds nothing, and a **backend** that holds the public key, the nonce store and the asset.
[`examples/integrity-backend.js`](../examples/integrity-backend.js) implements the provider and the
backend, and keeps them in separate commands so the separation is visible in your terminal history.

```bash
# host — scratch directory, not the repository
node /path/to/20-Security-Architecture/examples/integrity-backend.js keygen
node /path/to/20-Security-Architecture/examples/integrity-backend.js serve --port 8099
```

```bash
# host — play the client: ask for a nonce
curl -s -XPOST localhost:8099/v1/nonce -H 'content-type: application/json' \
     -d '{"sessionId":"s-1","operation":"vault.unlock"}'
```

```bash
# host — now try to do what you did in stage 3: forge a token.
# You have the algorithm, the format, the nonce, and the package name.
# You do not have the private key.
```

**Q24.** Try. Write the forged token by hand — you know the exact JSON, you have a valid nonce, and
the format is the same JWS you have been minting all afternoon. Submit it to `/v1/authorise` and read
which check rejects it.

```bash
# host — the honest path, for comparison. This is GOOGLE's role, not yours.
# The backend expects com.archlab.gate (it ships as Lab 03's remediation);
# change EXPECTED_PACKAGE in the file if you prefer to use this lab's package.
node /path/to/20-Security-Architecture/examples/integrity-backend.js mint \
     --nonce <NONCE> --package com.archlab.gate --verdict MEETS_DEVICE_INTEGRITY
```

```bash
# host — submit it once
curl -s -XPOST localhost:8099/v1/authorise -H 'content-type: application/json' \
     -d '{"sessionId":"s-1","operation":"vault.unlock","token":"<TOKEN>"}'
# then submit exactly the same token a second time
```

**Q25.** The first submission returns `ALLOW` and a payload. The second returns `DENY`. Name the line
of code that produced the difference, and explain why it had to be a *delete* rather than a *lookup*.

**Q26.** The `ALLOW` response contains the payload. Compare that with where the three flag fragments
in this lab lived. State the difference in one sentence. This is the same point Lab 03's Step 6 made,
arriving from the other direction.

**Q27.** Run the same check chain as a standalone tool —
[`scripts/verify-integrity-token.py`](../scripts/verify-integrity-token.py) — and watch each attack
die:

```bash
# host — scratch directory
python3 /path/to/20-Security-Architecture/scripts/verify-integrity-token.py selftest
```

Map each of the nine scenarios it prints onto one of the four defects in `verifyToken()`. Two of the
scenarios have no counterpart in this lab's app at all — which two, and what does their absence from
`verifyToken()` tell you about how that method was written?

The client half of the corrected design is
[`examples/ServerVerifiedGate.kt`](../examples/ServerVerifiedGate.kt). Read the comment block at the
bottom of that file before you finish — the failure path is where correct designs are undone in
production, and it is the first thing to test on any client that has got the rest of this right.

### Step 5 — The honest caveat

Do not leave this lab believing you have found something unbreakable. Chapter §3.6's warning is
explicit, and repeating it is part of the lesson:

> **⚠️ Warning**
> Server-side verification is not a guarantee. Attestation keyboxes have been extracted from devices
> and reused in software to produce valid-looking attestations from modified hardware; Google revokes
> the ones it learns about, which makes it an arms race rather than a proof. The defensible claim is
> not "this cannot be bypassed". It is: **an attacker who controls only their own device cannot defeat
> it, and must instead compromise something they do not control.** That is a categorically larger
> problem than hooking a method in a process they already own, and the whole value of the design is in
> that change of category — not in impossibility.

**Q28.** Rewrite the sentence "we use Play Integrity so rooted devices are blocked" into something you
would be willing to sign. Then write the version you would say to a board.

**Q29.** Return to your ranking from Q12. You almost certainly ranked "the key is in the APK" first,
because it is the defect you exploited. Argue the case that "verification happens in the app" should
be ranked first instead. Which ranking is right, and what does the disagreement reveal about the
difference between an attacker's priorities and an architect's?

**Q30.** One more, and it is the hardest. Stage 1's *signal* — Verified Boot state — is not the
problem; its *reader* is. Describe a design in which the boot state is a strong control, name the
mechanism that makes it strong, and say which chapter covers that mechanism. Then say what it has in
common with stage 3.

---

## Hints

<details>
<summary>Hint — nothing happens when I tap Open vault</summary>

Stage 3 does network I/O. If you put it on the main thread you get
`NetworkOnMainThreadException`, which the `catch (Throwable)` swallows into a silent `false`. The
activity above uses a worker thread; check yours does too.

Also confirm `adb reverse tcp:8098 tcp:8098` is active — it does not survive a device reconnect — and
that the stub is listening on `127.0.0.1`, not on a hostname.
</details>

<details>
<summary>Hint — stage 1 passes under Frida but not after resetprop</summary>

`resetprop` changes the property area for the whole device, but a process that already read the value
and cached it in a `static final` field will not see the change. Force-stop the app. If it still
fails, check whether `ro.boot.veritymode` exists on your device at all — many emulators do not set it,
and `""` will never equal `"enforcing"` no matter what you write.

That last case is worth noticing on real targets: a check comparing against a property that does not
exist on the device fails *closed* and produces a support ticket, not a security event.
</details>

<details>
<summary>Hint — the digest hook returns bytes but the comparison still fails</summary>

Two traps. Java `byte` is signed, so a hex pair above `0x7F` must be converted to a negative number
before you put it in the array — the script above does this and it is easy to omit. And
`MessageDigest.digest()` has more than one overload; make sure you replaced the no-argument one that
`stageTwo()` actually calls.

Check your work by logging the hex of what you return and comparing it, character by character, with
`REFERENCE_DIGEST`.
</details>

<details>
<summary>Hint — my forged token is rejected and I do not know which check failed</summary>

You are debugging blind because the app returns one boolean for four different failures. Do what the
developer should have done: add temporary observability *without* changing the decision.

```javascript
// s3-observe.js — watch, do not modify
Java.perform(function () {
    const S = Java.use('com.archlab.lyingphone.Stages');
    S.verifyToken.implementation = function (t, n) {
        console.log('[s3] token   = ' + t);
        console.log('[s3] nonce   = ' + n);
        const r = this.verifyToken(t, n);
        console.log('[s3] returns = ' + r);
        return r;
    };
});
```

This is observation, not the forbidden hook: it changes nothing. Decode the token's middle segment
with `base64 -d` and compare each field against what `verifyToken` reads. The usual culprit is
base64 padding — the app decodes with `URL_SAFE | NO_WRAP`, so your minter must produce unpadded
base64url, not standard base64.
</details>

---

## Debrief questions

Answer in writing. If you answer only one, answer number 3.

1. You defeated three checks in roughly one, twenty and forty minutes respectively. Rank them instead
   by *how much the developer spent building them*. What does the mismatch between the two orderings
   say about where hardening budget goes?
2. Three flag fragments were plaintext constants in the DEX and the rules forbade you from reading
   them. The Stage 4 payload was not in the APK at all. Explain, in terms a product owner
   understands, why that is the only difference in this lab that would have mattered in production.
3. Write the paragraph you would put at the top of a report for an app with exactly these three
   controls. It must be accurate about what each control achieves, must not say "the app can be run on
   a rooted device", and must give the client a defensible reason to fund one specific change.
4. A developer says: "we cannot use server verification because our app must work offline." Write your
   reply. It should not be "then you have no security", and it should not be "that is fine". Chapter
   §3.6 and the failure-path comment in `ServerVerifiedGate.kt` both bear on this.
5. Stage 2 duplicated work dm-verity already does, in a strictly worse way. Name two other places in
   mobile security where an app re-implements a platform guarantee inside its own process, and say
   what each one is worth.
6. You were forbidden from hooking `verifyToken`. Suppose you had been allowed. How long would stage 3
   have taken, and what would you have failed to learn? Relate this to the rule in
   [37's Lab 03](../../37-RootDetection/labs/lab-03-trace-and-neutralise.md) about running
   `objection android root disable` first.
7. Chapter §11.2 lists "testing Play Integrity by only checking that the app fails on a rooted device"
   as a pentester mistake. Using this lab, write the four tests that would have been correct instead,
   in the order you would run them.
8. The closing rule of this lab is about *endpoints*, not *content*. Apply it to something outside
   this chapter — a licence check, a feature flag, a price calculation, a rate limit — and state, in
   each case, where the two endpoints are.

---

## Success criteria

- [ ] You built all three stages and the provider stub, and saw the honest failure on your device
- [ ] You recovered all three flag fragments **without** reading them out of the DEX
- [ ] You defeated stage 1 and can name the exact point on the path from silicon to `String` at which
      the value stopped being protected
- [ ] You defeated stage 2 by two different mechanisms and can say which you would use on a real
      target
- [ ] You explained why bind-mounting a replacement system file cannot help with stage 2
- [ ] You defeated stage 3 by **minting a token**, not by hooking the verifier
- [ ] You identified all four defects in `verifyToken()` before reading the answer, and ranked them
- [ ] You demonstrated the missing package binding and the missing freshness check as separate
      findings
- [ ] You filled in the Stage 4 table, including column four, before reading Step 3
- [ ] You can state the shared invariant of stages 1 and 2 in one sentence that names a **location**,
      not a technique
- [ ] You identified stage 3 as the answer, and can explain why the other two are not candidates *by
      construction* rather than *by implementation quality*
- [ ] You stood up the correct implementation, attempted the same forgery against it, and can name the
      check that stopped you
- [ ] You submitted a valid token twice and can explain why the second attempt failed
- [ ] You can state the honest limit of server-side verification without either overclaiming or
      dismissing it
- [ ] You answered all eight debrief questions in writing, and question 3 in report-quality prose

---

## Note for instructors

Give participants the APK and the provider stub and nothing else. Do not tell them the lab is about
attestation; tell them "the vault does not open on this phone".

Budget the time deliberately: stages 1 to 3 take a competent participant about ninety minutes, and
Stage 4 takes as long as it takes. If the room finishes the three stages and you have twenty minutes
left, **stop and reschedule Stage 4 rather than rushing it.** A session that ends with three flags and
no conclusion has taught bypass technique, which the participants mostly had already, and has failed
to teach the only thing in this chapter that is hard.

The two failure modes to watch for in Stage 4:

- **"Stage 3, because it uses cryptography."** Wrong reasoning, right answer, and it will not
  generalise. Push back with: stage 2 also uses cryptography, and SHA-256 is not broken either. Make
  them locate the difference in *where the verification happens*, not in *what it is made of*.
- **"None of them, because you can always hook anything."** True and useless. Push back by asking what
  they would hook in Q23's scenario, where the signing key is Google's and the check is on a server
  they cannot reach. The answer is that they would attack something other than the device, which is
  exactly the change of category the lab is teaching.

End on debrief question 2. Three fragments sat in plaintext in the DEX the entire time, protected only
by a rule you asked participants to follow — and the Stage 4 payload was never on the device at all.
Everything else in this lab is technique; that contrast is the chapter.
