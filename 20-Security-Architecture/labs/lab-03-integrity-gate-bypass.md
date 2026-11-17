# Lab 03 — Breaking a client-side integrity gate

**Difficulty:** Intermediate
**Time:** 3–4 hours
**Chapter:** [20 — Security Architecture](../README.md) §3.1, §3.6, §3.9, §5.9, §6.1, §7.2
**Prerequisites:** [Lab 01](lab-01-device-posture.md), [Lab 02](lab-02-vbmeta-and-verified-boot.md),
a working Frida setup ([53 — Frida](../../53-Frida/README.md)), Android Studio or a Gradle
command line, and either a rooted device or an AVD

---

## Objective

Build an application that gates a feature on a **locally-evaluated** integrity result, discover the
check from the outside with [`scripts/integrity-observer.js`](../scripts/integrity-observer.js),
defeat it at four different altitudes, and then write the finding and its remediation to the standard
a client would pay for.

The bypass is the easy half and it is not the deliverable. The deliverable is the **written finding**:
a severity you can defend, an impact statement that survives a developer arguing with it, and a
remediation given as code rather than as the word "server-side".

## Why this lab exists

Chapter 20 §3.9 says client-side security decisions are among the most common findings in a mobile
engagement. That is easy to agree with and hard to *do*, because the actual work in this finding is
not technical. Any competent tester can make an app show the screen it did not want to show. Very few
can then explain to a developer — who has spent three sprints on those checks and is proud of them —
what the checks bought, what they did not, and what to change, without either dismissing the work or
overstating the fix.

There is also a specific trap this lab is built to spring. There are four places you can intervene in
a gate like this one, and they look interchangeable when all four produce the same screen. They are
not interchangeable. They differ in what they prove, in how much of the device they disturb, and
above all in what they let you *write*. Choosing the fastest one and stopping there is how testers end
up with a working bypass and an unwritable finding.

## What this lab is *not*

It is not root detection. The target probes no `su` binaries, no Magisk artefacts, no package lists,
and nothing in `/data/adb`. That subject — including native checks, the escalation ladder and the
tracer methodology — belongs to [37 — Root Detection](../../37-RootDetection/README.md), and if you
find yourself writing a `File.exists` denial hook here, you have wandered into
[37's Lab 03](../../37-RootDetection/labs/lab-03-trace-and-neutralise.md) by mistake.

This lab is about the **platform security model**: what Verified Boot, dm-verity, the bootloader lock
state and the patch level actually assert, where those assertions physically live at the moment an app
reads them, and why an application evaluating them *by itself* is a structurally unsound design no
matter how many of them it reads.

> **Mental Model**
> Root detection asks "are there traces of tampering on this device?" — a question about artefacts.
> This lab asks "can this process trust its own answer to any question about its environment?" — a
> question about trust boundaries. The first has better and worse implementations. The second has the
> same answer regardless of implementation quality, and that answer is no.

---

## Setup

### Device

Any of the following works:

- A rooted physical device (Magisk). Best, because the gate will produce a genuine `UNTRUSTED`
  verdict for genuine reasons.
- A standard AVD from Android Studio. Also produces `UNTRUSTED`, for different reasons — an emulator
  has no `ro.boot.verifiedbootstate`, is built with `test-keys`, and sets `ro.debuggable=1`. Note the
  difference; it matters in Step 2.
- A stock unrooted device *in addition* to one of the above, so that you can see the `TRUSTED` path.
  You cannot instrument it, and that is precisely the comparison you want.

```bash
# host — confirm the tooling before you build anything
adb devices -l
frida-ps -U | head -5
```

### Build the target

Create an empty Android project (Empty Views Activity, Java, minSdk 24), package
**`com.archlab.gate`**. Four files.

**1. The gate.** Copy [`examples/LocalIntegrityGate.java`](../examples/LocalIntegrityGate.java) into
`app/src/main/java/com/archlab/gate/`. Read its header comment now and the rest of it *later* — you
are about to spend an hour pretending you have never seen it.

**2. The protected asset.**

**`app/src/main/java/com/archlab/gate/SecretVault.java`**

```java
package com.archlab.gate;

import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The thing the gate protects. Ordinary, correct AES-256-GCM: there is no
 * cryptographic bug here.
 *
 * Look at where the inputs come from, though. Both of them shipped in the APK.
 * Keep that observation in your pocket until Step 6.
 */
public final class SecretVault {

    /** iv(12) || ciphertext || tag, base64. Produced by make-vault.py. */
    private static final String BLOB = "REPLACE_ME_WITH_GENERATED_BASE64";

    private static final String PASSPHRASE = "archlab-vault-v1";

    public static String open() {
        try {
            byte[] raw = Base64.decode(BLOB, Base64.NO_WRAP);
            byte[] iv  = new byte[12];
            System.arraycopy(raw, 0, iv, 0, 12);
            byte[] ct  = new byte[raw.length - 12];
            System.arraycopy(raw, 12, ct, 0, ct.length);

            byte[] key = MessageDigest.getInstance("SHA-256")
                    .digest(PASSPHRASE.getBytes(StandardCharsets.UTF_8));

            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                   new GCMParameterSpec(128, iv));

            return new String(c.doFinal(ct), StandardCharsets.UTF_8);
        } catch (Throwable t) {
            return null;
        }
    }

    private SecretVault() { }
}
```

**3. Generate the blob.** Run this on the host, from a scratch directory outside the repository, and
paste the output into `BLOB`.

```python
#!/usr/bin/env python3
# host — make-vault.py. Prints the BLOB constant for SecretVault.java.
# Requires: pip install cryptography
import base64, hashlib, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FLAG = b"ARCHLAB{a_verdict_is_not_an_authorisation}"

key = hashlib.sha256(b"archlab-vault-v1").digest()
iv  = os.urandom(12)
ct  = AESGCM(key).encrypt(iv, FLAG, None)

print("BLOB =", base64.b64encode(iv + ct).decode())
```

**4. The UI.** Deliberately plain, and deliberately honest — unlike a real target, it tells you what
it decided. You will remove that comfort in [Lab 04](lab-04-ctf-the-lying-phone.md).

**`app/src/main/java/com/archlab/gate/MainActivity.java`**

```java
package com.archlab.gate;

import android.app.Activity;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public class MainActivity extends Activity {

    private TextView out;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        out = new TextView(this);
        out.setTextSize(12f);
        out.setTypeface(Typeface.MONOSPACE);
        out.setText("Ready.");

        Button diag = new Button(this);
        diag.setText("Run diagnostics");
        diag.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                out.setText(LocalIntegrityGate.describe(
                        LocalIntegrityGate.evaluate(MainActivity.this)));
            }
        });

        Button unlock = new Button(this);
        unlock.setText("Unlock vault");
        unlock.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                LocalIntegrityGate.Assessment a =
                        LocalIntegrityGate.evaluate(MainActivity.this);
                switch (a.verdict) {
                    case TRUSTED:
                        String s = SecretVault.open();
                        out.setText(s == null ? "Vault error." : s);
                        break;
                    case DEGRADED:
                        out.setText("Read-only mode. Vault export is disabled "
                                  + "on this device.");
                        break;
                    default:
                        out.setText("This device does not meet the security "
                                  + "requirements for this feature.");
                }
            }
        });

        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(24, 96, 24, 24);
        col.addView(diag);
        col.addView(unlock);
        col.addView(out);

        ScrollView sv = new ScrollView(this);
        sv.addView(col);
        setContentView(sv);
    }
}
```

Build and install:

```bash
# host
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.archlab.gate/.MainActivity
```

> **Warning**
> `adb install` leaves the installer package name empty, so the gate's install-source signal will
> mismatch on *any* device, including a stock one. To see the `TRUSTED` path on your clean device,
> install with `adb install -i com.android.vending -r app-debug.apk`. Note what you just did: you set
> the "proof" of Play distribution from a shell. Write that down — it is the first of nine
> observations for Step 2's table, and you made it before running the app once.

Tap **Unlock vault**. You should see the refusal. Now forget you have the source.

---

## Steps

### Step 0 — Behave like a user, with no tools at all

Before instrumentation, spend five minutes doing what a curious user does.

```bash
# host — what does the app say about itself?
adb logcat -c
adb shell am force-stop com.archlab.gate
adb shell am start -n com.archlab.gate/.MainActivity
# tap both buttons
adb logcat -d -v brief | grep -i archlab
```

**Q0.** Tap **Run diagnostics**. The app hands you its entire reasoning. On a real target this screen
does not exist — but a surprising number of real targets have something equivalent behind a debug
menu, a support-bundle export, or a crash report. What did you learn in ten seconds that would
otherwise have cost you an hour, and what does that suggest about the first thing to look for on any
target that has a "send diagnostics" feature?

### Step 1 — Observe before you touch anything

Run the chapter's observer. It hooks the property reads, file probes, subprocess launches, package
queries and Play Integrity entry points, prints a Java stack trace for the security-relevant ones, and
**changes nothing**.

```bash
# host — spawn, never attach: the evaluation may run before you could attach
frida -U -f com.archlab.gate -l ../scripts/integrity-observer.js --no-pause | tee obs.log
```

Tap **Unlock vault**, then read `obs.log` in an editor rather than in a scrolling terminal.

**Q1.** How many `[prop]` lines appear, and how many of them are distinct property names? Which ones
carried a stack trace, and why those and not the others? (Read the regex in the script's section 1 if
you cannot see the rule.)

**Q2.** Take any one `[prop]` line that carried a stack trace. Read the trace from the bottom up.
Which class made the call, which method, and — the useful part — which method called *that*? You have
just located both the checker and its caller without opening a decompiler.

**Q3.** Are there any `[file]`, `[exec]` or `[integrity]` lines at all? State what each *absence* tells
you. Be precise: "no `[integrity]` lines" is a much stronger statement than "no `[file]` lines", and
you should be able to say why.

**Q4.** The observer reports `[build]` values once at startup rather than hooking reads of them.
`Build.TAGS` is a `public static final String` — explain why hooking a read of it is not
straightforward, and what you would do instead if you needed to know whether the app read it.

> **Pentester's Note**
> The reason the chapter tells you to run this before anything else is not thoroughness, it is
> *writability*. Every line in `obs.log` is a sentence you can put in a report: "the application reads
> `ro.boot.verifiedbootstate` from `com.archlab.gate.LocalIntegrityGate.evaluate`". A bypass you
> obtained by pasting someone's generic script produces no such sentences, which is why 37's Lab 03
> spends its whole length on this same point from the root-detection side.

### Step 2 — Build the signal inventory before you build the bypass

Produce this table from `obs.log` and from the diagnostics screen. One row per signal. Do not skip
the last two columns; they are the ones the finding is made of.

| Signal | Observed on your device | What it genuinely asserts | Where the value physically lives when the app reads it | Root can forge? | If forged, who else is affected? |
|---|---|---|---|---|---|
| `ro.boot.verifiedbootstate` | | | | | |
| `ro.boot.flash.locked` | | | | | |
| `ro.boot.veritymode` | | | | | |
| `Build.TAGS` | | | | | |
| `ro.debuggable` | | | | | |
| `ro.secure` | | | | | |
| `ro.crypto.state` | | | | | |
| `Build.VERSION.SECURITY_PATCH` | | | | | |
| installer package | | | | | |

**Q5.** Column four is the load-bearing one. For the six `ro.*` rows the answer is the same, and you
established it in [Lab 01](lab-01-device-posture.md): trace it. Where does the *value* live, which
process wrote it, and which kernel object backs the mapping? Chapter §4.5 walks the path.

**Q6.** Two rows in this table are different in kind from the other seven. `Build.TAGS` and
`Build.VERSION.SECURITY_PATCH` are `static final` fields of a framework class, initialised in the
app's own process at class-load time. Does that make them *more* or *less* forgeable than a property
read, and by what mechanism?

**Q7.** One row in the table is not a security signal at all in the sense the others are. The patch
level says nothing about tampering — an entirely honest, locked, verified device can be eighteen
months out of date. Why is it in the gate anyway, and is including it a mistake? Argue both sides
before you decide.

**Q8.** Now the question the whole inventory exists to answer: **is there any row for which the answer
in column five is "no"?** If your answer is no for every row, say what kind of signal *would* have
produced a "no", and where in the chapter it is described. You will build exactly that in
[Lab 04](lab-04-ctf-the-lying-phone.md).

### Step 3 — Locate the decision statically

You now know what is read. Find where the answer is *consumed*, because that is what you will
eventually recommend changing.

```bash
# host
adb shell pm path com.archlab.gate
adb pull /data/app/.../base.apk target.apk
jadx -d target_jadx target.apk
apktool d target.apk -o target_out
```

```bash
# host — the chapter's own recipe, §8.1
grep -rn --include='*.smali' -E 'ro\.(boot|debuggable|secure|crypto)' target_out/smali*/ | head -30
grep -rn --include='*.java' -E 'SystemProperties|verifiedbootstate|Verdict|TRUSTED' target_jadx/sources/ | head -30
```

**Q9.** Find the `switch` (or the `if`/`else` chain, depending on how the compiler rendered it) that
consumes the verdict. In Smali, an enum switch appears as a `packed-switch` or `sparse-switch` on an
`int` obtained from a synthetic `$SwitchMap` array. Write down the exact class and method containing
it. This is the single most important line in your finding, because it is the line the developer must
delete.

**Q10.** How many bytes of DEX separate the property read from the decision that uses it? Roughly is
fine. Now answer the version of the question that matters: how many **trust boundaries** separate
them? See chapter §2.2.

### Step 4 — Defeat it at four altitudes

Do all four. They are not alternatives; the comparison is the exercise.

#### Altitude A — falsify the inputs, device-wide

Do not touch the app at all. Change what the platform reports.

```bash
# device root (Magisk) — resetprop rewrites read-only properties in the
# property area without a reboot. See ../../62-Magisk/README.md.
resetprop ro.boot.verifiedbootstate green
resetprop ro.boot.flash.locked 1
resetprop ro.boot.veritymode enforcing
resetprop ro.debuggable 0
resetprop ro.secure 1
getprop ro.boot.verifiedbootstate
```

```bash
# host — restart the app so it re-reads
adb shell am force-stop com.archlab.gate
adb shell am start -n com.archlab.gate/.MainActivity
```

**Q11.** Does the vault open? Which signals remain mismatched, and what does the *residual* score tell
you about which properties resisted this technique and why?

**Q12.** Name three side effects of altitude A that you would not accept mid-engagement on a client's
loaned device. (Hint: how many other processes on this device just started reading a lie, and what
happens to your Lab 01 posture baseline?)

#### Altitude B — falsify the reads, process-wide

```javascript
// gate-b.js — frida -U -f com.archlab.gate -l gate-b.js --no-pause
// Lie to one process only. Nothing outside this app is affected.
'use strict';

const SAFE = {
    'ro.boot.verifiedbootstate': 'green',
    'ro.boot.flash.locked': '1',
    'ro.boot.veritymode': 'enforcing',
    'ro.debuggable': '0',
    'ro.secure': '1',
    'ro.crypto.state': 'encrypted'
};

Java.perform(function () {
    const SP = Java.use('android.os.SystemProperties');
    SP.get.overloads.forEach(function (ov) {
        ov.implementation = function () {
            const k = arguments[0] === null ? '' : arguments[0].toString();
            if (Object.prototype.hasOwnProperty.call(SAFE, k)) {
                console.log('[lie] ' + k + ' -> ' + SAFE[k]);
                return SAFE[k];
            }
            return ov.apply(this, arguments);
        };
    });

    // Build.TAGS is a static final String, read once at class init. Frida can
    // still write it, because JNI SetStaticObjectField does not care about
    // `final`. Do it before the gate runs -- which is why we spawn, not attach.
    try {
        Java.use('android.os.Build').TAGS.value = 'release-keys';
    } catch (e) {
        console.log('[!] could not rewrite Build.TAGS: ' + e);
    }
});
```

**Q13.** Six lies, six signals. Does the vault open? If not, which signals are still mismatched, and
which of them can this altitude *never* reach? (There are at least two.)

#### Altitude C — falsify the verdict

One hook, at the aggregation point you found in Step 3.

```javascript
// gate-c.js — frida -U -f com.archlab.gate -l gate-c.js --no-pause
'use strict';

Java.perform(function () {
    const Gate    = Java.use('com.archlab.gate.LocalIntegrityGate');
    const Verdict = Java.use('com.archlab.gate.LocalIntegrityGate$Verdict');

    Gate.evaluate.implementation = function (ctx) {
        const a = this.evaluate(ctx);           // run the real thing first
        console.log('[gate] real verdict = ' + a.verdict.value +
                    '  penalty score = ' + a.score.value);
        a.verdict.value = Verdict.TRUSTED.value;
        a.score.value = 0;
        return a;
    };
});
```

Note the shape: it calls the original, *logs what the app really concluded*, and then changes the
answer. That ordering is not stylistic. A hook that skips the original tells you nothing, and "what
the app really concluded" is a sentence in your report.

**Q14.** How many signals did this hook have to know about? Compare with altitude B. State the general
rule this illustrates about where to intervene in any scoring-style control.

**Q15.** `Assessment.verdict` and `Assessment.score` are `public final`. Explain why writing to them
works anyway. What does that tell you about `final` as a security property inside a process an
attacker controls?

#### Altitude D — do not defeat it at all

```javascript
// gate-d.js — frida -U -f com.archlab.gate -l gate-d.js --no-pause
// There is no bypass here. There is no hook here. We ask for the thing.
'use strict';

Java.perform(function () {
    setTimeout(function () {
        Java.perform(function () {
            console.log('[vault] ' + Java.use('com.archlab.gate.SecretVault').open());
        });
    }, 2000);
});
```

**Q16.** This produces the flag without touching the gate, without reading a property, and without
knowing that the gate exists. What, exactly, did the gate protect?

#### Compare the four

Fill this in from your own results before reading anyone's answer.

| | A — inputs | B — reads | C — verdict | D — skip |
|---|---|---|---|---|
| Hooks written | | | | |
| Signals you had to understand | | | | |
| Blast radius | | | | |
| Survives an app update? | | | | |
| Survives the developer adding three more checks? | | | | |
| What it proves in a report | | | | |
| What it tells you about the app's design | | | | |

### Step 5 — Verify at the decision, not at the UI

The vault is open. Prove it is open for the reason you think.

```javascript
// verify.js — run ALONGSIDE your bypass, not instead of it.
'use strict';

Java.perform(function () {
    const Gate = Java.use('com.archlab.gate.LocalIntegrityGate');
    const Vault = Java.use('com.archlab.gate.SecretVault');

    Gate.evaluate.implementation = function (ctx) {
        const a = this.evaluate(ctx);
        console.log('[verify] gate returned ' + a.verdict.value +
                    ' score=' + a.score.value);
        return a;
    };

    Vault.open.implementation = function () {
        const r = this.open();
        console.log('[verify] SecretVault.open() called, returned ' +
                    (r === null ? 'null' : (r.length + ' chars')));
        console.log(Java.use('android.util.Log').getStackTraceString(
            Java.use('java.lang.Exception').$new()));
        return r;
    };
});
```

**Q17.** Three ways the flag on screen could be a false success. For each, describe the observation
that rules it out. (One of them is specific to this lab's structure: what happens if your hook throws
inside `evaluate` and the caller sees a default?)

**Q18.** Exercise the whole app — rotate the screen, background and foreground it, tap **Run
diagnostics** after **Unlock vault**. Does the gate re-evaluate? On a real target, when would you
expect a re-evaluation, and why is "immediately before the sensitive operation" the answer a good
developer gives?

### Step 6 — The question that ends the lab

Do this on the host, with the device unplugged and the app not running.

```bash
# host — no device, no Frida, no bypass
unzip -o target.apk -d extracted > /dev/null
jadx -d target_jadx target.apk
grep -rn -A3 'BLOB\|PASSPHRASE' target_jadx/sources/com/archlab/gate/SecretVault.java
```

```python
#!/usr/bin/env python3
# host — pull-the-flag.py, run from a scratch directory
import base64, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BLOB = "PASTE_THE_BASE64_FROM_THE_DECOMPILED_SOURCE"
raw = base64.b64decode(BLOB)
key = hashlib.sha256(b"archlab-vault-v1").digest()
print(AESGCM(key).decrypt(raw[:12], raw[12:], None).decode())
```

**Q19.** You now have the flag without a device. Restate the gate's actual security contribution in
one sentence, using the word "cost" and not the word "prevent".

**Q20.** Suppose the developer fixes every complaint you have made about the *checks* — moves them to
native code, obfuscates the strings, adds hardware key attestation, hooks-detects Frida. Does the
script above stop working? Write the answer in one sentence; it is the thesis of chapter 20 and the
core of the finding you are about to write.

---

## Hints

<details>
<summary>Hint 1 — the observer prints nothing at all</summary>

You attached instead of spawning. `LocalIntegrityGate.evaluate` runs on the button tap here, but in
real targets the equivalent runs in `Application.onCreate`, before you can attach. Always
`frida -U -f <package> ... --no-pause`.

If you did spawn and still see nothing, check that `frida-server` on the device matches your client
version, and that the app is actually the one you rebuilt (`adb shell dumpsys package
com.archlab.gate | grep versionCode`).
</details>

<details>
<summary>Hint 2 — Q4, hooking a read of a static final String</summary>

`Build.TAGS` is a compile-time-constant-like field read through `sget-object`. There is no method to
hook, so Frida cannot intercept the *read*. Three options, in increasing cost:

1. Change the value before any read happens (spawn, then write the field) — which tells you nothing
   about who read it.
2. Hook the class initialiser or a nearby method and infer.
3. Instrument at the Smali level: patch `sget-object` to a call. That is a static-rewriting job, not
   a hooking job.

The general lesson: **hooks intercept calls, not memory accesses.** When a value is read rather than
called, you need either a rewrite or a data watchpoint. Chapter 20 §7.2's script logs the values once
for exactly this reason, and says so in its comment.
</details>

<details>
<summary>Hint 3 — Q13, the two signals altitude B can never reach</summary>

`SystemProperties.get` is not the only way a value reaches the gate. Look at your inventory and ask,
for each row, *which API produced it*. Two rows do not come from `SystemProperties` at all — one
comes from a framework constant and one from a Binder call to `PackageManagerService`. Hooking the
property API cannot touch either.

This is worth internalising beyond this lab: a hook covers a **mechanism**, not a **signal**, and one
control usually spans several mechanisms.
</details>

<details>
<summary>Hint 4 — `resetprop` does nothing on my device</summary>

`resetprop` is a Magisk utility, so it exists only on Magisk-rooted devices, and it must be run in a
root shell (`adb shell "su -c 'resetprop ...'"` — note the outer quotes — or from `adb shell` after
`su`). On an AVD with a
writable system but no Magisk you have no equivalent, and altitude A is unavailable — which is
itself worth noting in your comparison table under "prerequisites".

`ro.` properties are read-only *by convention enforced in `property_service`*, not by
hardware. `resetprop` writes the property area directly. Chapter §4.5 explains why that is possible.
</details>

<details>
<summary>Hint 5 — the enum switch in Smali</summary>

Java compiles `switch` over an enum into a lookup through a synthetic `int[]` field, typically named
`$SwitchMap$com$archlab$gate$LocalIntegrityGate$Verdict`, held in a synthetic class such as
`MainActivity$1`. Grep for `$SwitchMap` and you will land on it directly. The `packed-switch` that
follows is your decision point.
</details>

---

## Solutions

Do not open these until you have your own answers to Q0–Q20 written down.

<details>
<summary>Answers Q1–Q4 — reading the observer output</summary>

**Q1.** Expect roughly six to eight `[prop]` lines per evaluation, one per distinct key, and one more
set per tap because `evaluate()` is called again. Stack traces appear only for keys matching the
script's regex — `verifiedboot|debuggable|secure|tags|fingerprint|veritymode|crypto` — so
`ro.boot.flash.locked` produces a line with **no** trace even though it is arguably the most
important signal in the gate.

That gap is the lesson. The observer is a good default, not an oracle; its filter was written for the
common case and your target is not obliged to be the common case. When you find a property you care
about that carries no trace, widen the regex and re-run. Write the widened script down; that is how
the tool improves.

**Q2.** The trace, bottom-up, is `MainActivity$2.onClick` calling `LocalIntegrityGate.evaluate`
calling `LocalIntegrityGate.prop`. Three frames give you the checker (`prop`), the aggregator
(`evaluate`) and the consumer (`onClick`). Altitude B attacks the first, altitude C the second,
altitude D goes around all three.

**Q3.** No `[file]` lines means the app makes no filesystem probes for tampering artefacts — it is not
doing root detection at all, which contradicts what most testers assume when they see a device check
fail. No `[exec]` lines means no `getprop`/`which`/`mount` subprocesses.

The strong one is **no `[integrity]` lines**. Those hooks fire on
`IntegrityManagerFactory.create` and `IntegrityTokenRequest$Builder.setNonce`. Their absence means the
app never asks Play for a token, which means no server is ever told anything about this device, which
means the *entire* decision is local. You have proven the finding's core claim in one line of tool
output, before touching a decompiler.

**Q4.** See Hint 2. Hooks intercept calls; `sget-object` is not a call.

</details>

<details>
<summary>Answers Q5–Q8 — the inventory</summary>

**Q5.** Every `ro.*` value lives in the **property area**: a shared memory region created by `init`,
backed by files under `/dev/__properties__`, and mapped read-only into every process by Bionic.
`__system_property_get` reads it directly with no IPC — which is why property reads are fast, and why
there is no server to ask "is this value authentic". The values were written by `init` at first stage,
originally from `androidboot.*` fragments on the kernel command line placed there by the bootloader
(chapter §4.5).

Root can `mmap` and rewrite that region. Therefore: **the bootloader's honest report survives exactly
as far as the first process that can write the page it landed in.**

**Q6.** `Build.TAGS` and `Build.VERSION.SECURITY_PATCH` are `static final String` fields initialised
from properties when `android.os.Build` is class-loaded *inside the app's own process*. They are
therefore **more** forgeable, not less: they are plain fields in the attacker's heap, writable through
JNI `SetStaticObjectField`, which is what `Java.use('android.os.Build').TAGS.value = ...` does. `final`
is a compiler and verifier constraint, not a memory protection.

**Q7.** Both sides:

*For inclusion.* Patch currency is a real risk input and one of the few in the list that is
meaningful about an honest device. A locked, verified, entirely untampered handset running code with
eighteen months of unpatched bulletins is a genuine hazard to a high-value transaction, and chapter
§13.1 calls the patch delta the highest-impact finding on many fleet engagements.

*Against inclusion here.* It is measuring a different thing from the other eight — risk rather than
tampering — and folding it into the same score conflates them. Worse, it is folded in with a weight
somebody guessed. A device six months stale and a device with an unlocked bootloader are not
commensurable quantities, and adding them produces a number with no meaning.

The mature answer: keep the signal, remove it from the score, report it separately, and let the
*server* apply policy to it. That is what `ServerVerifiedGate.kt` does — it sends every signal as
evidence and computes nothing.

**Q8.** No row answers "no". Every value is either a property (writable by root) or a field in the
app's own heap (writable by anyone who can inject). A "no" requires a statement produced by a
component the attacker does not control and verified by another such component: a **key attestation
certificate** whose `verifiedBootState` and `deviceLocked` fields were signed inside the TEE (chapter
§3.1, §9.5, and [49 — KeyStore](../../49-KeyStore/README.md)), or a **Play Integrity token** decoded
server-side (§3.6). Both share one property this gate lacks entirely: the verification happens
somewhere the attacker is not.

</details>

<details>
<summary>Answers Q9–Q12 — the decision, and altitude A</summary>

**Q9.** `com.archlab.gate.MainActivity`, inside the anonymous `OnClickListener` for the unlock button
(`MainActivity$2.onClick`), switching on `Assessment.verdict`. In Smali it is a `packed-switch` on an
`int` fetched from `MainActivity$1.$SwitchMap$com$archlab$gate$LocalIntegrityGate$Verdict`.

**Q10.** A few hundred bytes of DEX, and **zero** trust boundaries. Both the producer and the consumer
are in the same process, the same UID, the same address space, running under the same Linux user that
the device's owner controls. That count — zero — is the finding.

**Q11.** On a Magisk device, rewriting the five properties usually leaves two signals mismatched: the
installer package (a Binder call to PackageManagerService, unaffected by property writes) and
`Build.TAGS` **if** the framework class was already loaded before your `resetprop` — though after a
force-stop and restart the class re-initialises and picks up the new value, so this one may flip.
That inconsistency is itself instructive: altitude A's effects depend on process lifetime, which makes
it the least deterministic of the four.

With `ro.build.tags` also reset and the app restarted, the residual score is typically just the
installer penalty (10), which is below `DEGRADED_AT` but above `TRUSTED_AT` — so you land in
`DEGRADED`, not `TRUSTED`, and the vault stays shut. Reinstalling with
`adb install -i com.android.vending` closes the last gap.

**Q12.** Three unacceptable side effects:

1. **Every process on the device now reads the lie.** Other apps, the framework, and your own
   tooling. If the client has an MDM agent installed, you have just fed it false posture data.
2. **Your Lab 01 baseline is now fiction.** The posture evidence you collected for the report no
   longer matches the device you are testing on, and you may not remember which values you changed.
   This is exactly why `device-posture.sh` has a `--test-device` flag.
3. **It is not reproducible for the client.** A finding that requires "first run these five
   `resetprop` commands" is a finding the client's own team cannot verify, and unverifiable findings
   get disputed and dropped.

There is a fourth that bites on real engagements: `resetprop` on some properties triggers
`property_service` watchers and can restart services or wedge the device. Do it on your own hardware,
not on a loaner.

</details>

<details>
<summary>Answers Q13–Q16 — altitudes B, C and D</summary>

**Q13.** The vault typically still does not open after `gate-b.js` alone. The two signals this
altitude can never reach through the property hook are:

- **the installer package name**, which comes from `PackageManager.getInstallSourceInfo` — a Binder
  round trip to `system_server`, not a property read; and
- **the patch age**, computed from `Build.VERSION.SECURITY_PATCH`, a static field, not a property
  read at that moment. (The script does rewrite `Build.TAGS`, so tags are covered; patch level is
  not.)

To finish at altitude B you would hook `ApplicationPackageManager.getInstallSourceInfo` and rewrite
`Build.VERSION.SECURITY_PATCH` too — four mechanisms for nine signals. Which is the point: **hooks
cover mechanisms, not signals.**

**Q14.** One. Altitude C needed to know nothing about any of the nine signals, only the name of the
method that aggregates them. The general rule: **intervene at the narrowest point through which all
of the control's information must pass.** In a scoring control that is the scorer; in a
challenge-response control it is the response; in a licence check it is the boolean.

The corollary is the cost, and it is the same one 37's Lab 03 makes: the aggregation hook tells you
nothing about *what* the app checked, so it produces a working bypass and an empty report. Do the
observer run first, then use altitude C to make the rest of the engagement fast.

**Q15.** `final` is enforced by `javac` and by the DEX verifier at *compile and load* time. It is not
a page permission. Frida writes the field through JNI `SetIntField` / `SetObjectField`, which the ART
runtime performs without consulting the `final` flag. More generally: inside a process the attacker
controls, every language-level guarantee — `private`, `final`, `static`, type safety — is a
convention between the compiler and well-behaved code. None of them is a security boundary. The only
boundaries on the device are the ones the *kernel* and the *TEE* enforce, which is chapter §2.2's
entire subject.

**Q16.** It protected the *rendering of a screen*. It did not protect the secret, because the secret
and the key that opens it both shipped inside the APK, on the attacker's storage, before the gate ran
once. The gate is a lock on a door in a building with no walls.

</details>

<details>
<summary>Answers Q17–Q20 — verification and the thesis</summary>

**Q17.** Three false successes:

1. **You broke the scorer.** If a hook throws inside `evaluate`, the exception propagates and the
   `onClick` handler may not reach the switch at all, or the app catches and defaults. Rule it out by
   logging the *real* return value with `verify.js` alongside the bypass, which is why the two are
   separate scripts.
2. **Residual device state.** Your `resetprop` changes from altitude A are still in effect and are
   doing the work you are attributing to your Frida script. Reboot between altitudes; that is the only
   reliable reset.
3. **You are looking at the wrong build.** Gradle installed a cached APK, or you rebuilt without
   reinstalling. Check `versionCode` and the APK's `lastUpdateTime`.

**Q18.** This target re-evaluates on every tap, because `evaluate()` is called inside the click
handler. Many real apps evaluate once in `Application.onCreate` and cache — which is strictly worse,
because a single cached boolean is a single point of attack, and because a device's state can change
during a session. The good pattern is to evaluate immediately before the sensitive operation and,
critically, to have the *server* be the thing that evaluates.

**Q19.** "The gate raises the cost of reaching this feature from zero to about ninety seconds for
anyone with Frida, and to about five minutes for anyone with only a decompiler; it prevents nothing."

**Q20.** No — the host script keeps working unchanged, because it never interacts with any of those
defences. Every improvement listed hardens the *decision*, and the flaw is not in the decision, it is
in the *location of the asset*. Protecting a secret that is already on the attacker's device with a
check that also runs on the attacker's device is a category error, and no amount of quality applied
to the check repairs it.

</details>

---

## The finding

This is the part of the lab that is actually graded. Write it before you read the model answer, then
compare structure, not wording.

A finding is not a description of what you did. It is an argument that some specific business
consequence follows from some specific technical fact, addressed to someone who must decide whether to
spend a sprint on it.

### Model finding

```markdown
### F-01 — Protected feature authorised by a client-evaluated integrity verdict

**Severity:** High
**CVSS-style rationale:** Local attack vector, low complexity, no privileges beyond
physical possession of a device the attacker already controls, no user interaction.
Impact is to the confidentiality of the protected asset and to the integrity of an
authorisation decision. It is not Critical because exploitation affects only the
attacker's own device and account, and does not reach other users' data or the
backend. It is not Medium because the control is the *only* thing standing between
the attacker and the asset, and because the asset in question is shipped to every
installation.

**Affected component:** com.archlab.gate — LocalIntegrityGate.evaluate(), consumed at
MainActivity$2.onClick (Smali: packed-switch on
$SwitchMap$com$archlab$gate$LocalIntegrityGate$Verdict)

**OWASP MASVS:** MASVS-RESILIENCE (anti-tampering and device binding),
MASVS-AUTH (an integrity verdict used as an authorisation input must be
verified where the attacker is not). MASTG: the test areas covering
anti-tampering, device binding and testing for client-side enforcement.

---

**Summary**

The application decides whether to release the contents of the protected vault by
evaluating nine device-state signals locally and comparing the resulting score
against a threshold. Both the evaluation and the decision execute inside the
application's own process, from data stored in memory the device owner can write.
The decision can therefore be changed at will, and the protected asset — which is
shipped inside the APK — can be recovered without interacting with the decision at
all.

**Technical detail**

The nine signals are read as follows:

| Signal | Source API | Forgeable by |
|---|---|---|
| ro.boot.verifiedbootstate | SystemProperties.get (reflection) | root, via resetprop; any process, via injection |
| ro.boot.flash.locked | SystemProperties.get | as above |
| ro.boot.veritymode | SystemProperties.get | as above |
| ro.debuggable, ro.secure | SystemProperties.get | as above |
| ro.crypto.state | SystemProperties.get | as above |
| Build.TAGS | static final field | injection (JNI SetStaticObjectField) |
| Build.VERSION.SECURITY_PATCH | static final field | injection |
| installer package | PackageManager.getInstallSourceInfo | injection; also settable at install time with `pm install -i` |

All property values are read from the shared property area mapped from
/dev/__properties__, which is writable by root. Both Build fields are ordinary
fields in the application's own heap.

Independently of the forgeability of the inputs, evaluate() returns a Java object
into the application's own address space; a single instrumentation hook replaces
the verdict without reference to any of the nine signals.

**Reproduction**

1. Install the release build on a rooted device. Confirm the vault is refused.
2. frida -U -f com.archlab.gate -l gate-c.js --no-pause   (script attached; 8 lines)
3. Tap "Unlock vault". The protected content is displayed.
4. Independently, with no device involved: unzip the APK, decompile with jadx, read
   the BLOB and PASSPHRASE constants from SecretVault, and decrypt on the host
   (script attached). The protected content is recovered without executing the
   application.

Step 4 is the material one. Steps 1-3 demonstrate that the control fails; step 4
demonstrates that the control was never load-bearing.

**Impact**

Any user of the application can read the protected asset. Because the asset is
identical in every installation, recovery by one user is recovery for all users:
this is a one-time break, not a per-device one. Any product logic that assumes the
vault contents are confidential — licensing, entitlement, or a shared key — is
void.

Where the same pattern gates a *transaction* rather than an asset, the impact is
that the transaction proceeds from a device the organisation believes it has
excluded, and the organisation's telemetry records it as having come from a healthy
device. The false assurance is frequently worse than the absent control, because
risk teams act on it.

**What the control does achieve** (state this; it is true, and omitting it costs
you the developer's cooperation)

The nine signals are individually well chosen and correctly read. Against an
opportunistic user with a rooted phone and no tooling, the gate is effective. It
raises the cost of casual access from zero to roughly ninety seconds for an
attacker with Frida. Retained as *telemetry*, these signals have real value.

**Remediation**

See the accompanying remediation section. In order of importance:

1. Move the asset. Serve the protected content from the backend on the authorised
   response. Nothing else in this finding matters if the asset ships in the APK.
2. Move the decision. Send the signals as evidence; let the server decide.
3. Add an unforgeable signal. A locally-read property asserts nothing; a Play
   Integrity token decoded server-side, or a key attestation certificate verified
   server-side, asserts something. Both require a server-issued nonce.
4. Keep the local signals as risk input and support diagnostics, and remove the
   local threshold comparison entirely.

**Retest criteria**

The finding is closed when (a) the protected content is not present in any form in
the distributed APK, and (b) with all client-side checks hooked to report a healthy
device, the backend still refuses to release it because the nonce or the token
signature does not verify.
```

### Three ways to write this badly

**Bad version 1 — the platform complaint.**

> "The application can be run on a rooted device, allowing an attacker to bypass security controls."

This is a statement about Android, not about the client's app. Every app can be run on a rooted
device. There is no remediation, so the developer cannot act on it, and correctly reads it as noise.
Chapter §11.2 lists this as the archetypal pentester mistake.

**Bad version 2 — the tool output.**

> "Using Frida we hooked `LocalIntegrityGate.evaluate` and forced it to return TRUSTED. See screenshot."

This describes an action, not a consequence. It gives no severity rationale, no impact, no
remediation, and no reason for anyone to fund a fix. It also invites the reply "we will add anti-Frida
detection", which is the wrong fix, and you have given the developer no way to know that.

**Bad version 3 — the overstatement.**

> "Critical: the application has no security. The integrity checks are useless and should be removed."

The checks are not useless; they are misplaced. Removing them loses genuine telemetry value. Calling
it Critical when the blast radius is the attacker's own device spends credibility you will need for a
finding that really is critical, and the first developer who points out that "useless" is false will
be right, in front of everyone, and the rest of your report will be read more sceptically.

> **Pentester's Note**
> The single sentence that makes this finding land is the one about the asset shipping in the APK. It
> converts the conversation from "how good are our checks" — which is unbounded, and which the
> developer will always want to continue — into "why is the secret on the attacker's disk", which has
> exactly one answer and a finite amount of work attached to it.

---

## Remediation, as code

A finding whose remediation is the phrase "validate server-side" has not been finished. You must be
able to hand the developer the code. Three changes, in the order they matter.

### 1. Move the asset

The vault content leaves the APK. It is returned by the backend in the *same response* that
authorises the operation, so a bypassed client receives an error body rather than a secret. See the
`payload` field in [`examples/integrity-backend.js`](../examples/integrity-backend.js).

### 2. Move the decision

Replace `LocalIntegrityGate` with [`examples/ServerVerifiedGate.kt`](../examples/ServerVerifiedGate.kt).
Read the diff rather than the file: the same nine signals are still collected, and there is no
comparison against an expected value anywhere in it. The client obtains a server-issued nonce, obtains
an opaque token, forwards both plus the evidence, and renders whatever the server returns.

### 3. Verify server-side, with the bindings

The five checks, in order, live in `authorise()` in
[`examples/integrity-backend.js`](../examples/integrity-backend.js), and as a standalone tool in
[`scripts/verify-integrity-token.py`](../scripts/verify-integrity-token.py). Run its self-test to see
each check stop its corresponding attack:

```bash
# host — run from a scratch directory; it writes a temporary nonce store
python3 /path/to/20-Security-Architecture/scripts/verify-integrity-token.py selftest
```

### What each change actually fixes

| Change | Stops altitude A | Stops B | Stops C | Stops D | Stops the host decrypt |
|---|---|---|---|---|---|
| Obfuscate the checks | No | No | No | No | No |
| Move checks to native code | No | Partly | No | No | No |
| Add more signals | No | No | No | No | No |
| Add Frida detection | No | Delays | Delays | Delays | No |
| **Move the decision to the server** | Yes | Yes | Yes | No | No |
| **Move the asset to the server** | Yes | Yes | Yes | **Yes** | **Yes** |
| **Add a server-verified token with a server-issued nonce** | Yes | Yes | Yes | Yes | Yes |

Read the bottom three rows against the top four. Everything a developer instinctively reaches for is
in the top half of that table.

> **Warning**
> Do not write "Play Integrity cannot be bypassed" in the remediation. Chapter §3.6's warning is
> explicit: hardware attestation spoofing and leaked keyboxes have produced `MEETS_DEVICE_INTEGRITY`
> on modified devices. The defensible claim is about *where verification happens*, not about
> invincibility: correct server-side verification with a server-issued nonce means an attacker must
> compromise something outside their own device, which is a categorically different and much larger
> problem than hooking a method in their own process.

---

## Debrief questions

Answer in writing. They are the point of the lab.

1. Rank altitudes A–D by (a) minutes to execute, (b) how much of the report they wrote for you,
   (c) how much of the device they disturbed. Explain why the ranking is different for each.
2. You ran the observer before hooking anything. Name three specific sentences in your finding that
   exist only because of that decision.
3. The developer replies: "we will move the checks into a native library with encrypted strings."
   Write your two-sentence answer. It must be accurate about what that buys them (it does buy
   something) and about what it does not.
4. The developer replies: "we will add Play Integrity." Write the three follow-up questions you must
   ask before you can tell whether that fixes anything.
5. A device with a `green` boot state, a locked bootloader, `enforcing` verity and a current patch
   level reports through this gate as `TRUSTED`. Describe a device for which every one of those is
   true and which you would still not trust — and say which chapter covers it.
6. Explain, to a product manager, why removing the checks entirely would be a worse outcome than
   leaving them in place unchanged. Then explain why that is not an argument against the finding.
7. Altitude D needed no bypass. Generalise: what property must a control have before "bypassing" it
   is even a meaningful notion?
8. Chapter §5.9 gives report language for the question "how secure is the platform our app runs on".
   Rewrite it in your own words for a client whose app is this one.

---

## Success criteria

- [ ] You built the target and confirmed both the refusal and (on a clean install with
      `-i com.android.vending`) the `TRUSTED` path
- [ ] You ran [`integrity-observer.js`](../scripts/integrity-observer.js) **before** writing any hook,
      and saved the output to a file
- [ ] You identified the checker, the aggregator and the consumer from the stack traces alone
- [ ] You noticed at least one signal the observer's default filter does *not* trace, and widened it
- [ ] You completed the nine-row inventory including the "where does the value physically live" column
- [ ] You can state where every `ro.*` value lives and which process wrote it
- [ ] You defeated the gate at all four altitudes and completed the comparison table
- [ ] You can name the two signals a `SystemProperties` hook can never reach, and why
- [ ] You explained why writing to a `public final` field works
- [ ] You verified at the decision rather than at the UI, using a separate script from the bypass
- [ ] You recovered the flag with no device and no instrumentation, and understand why that is the
      finding
- [ ] **You wrote the finding**, with a defensible severity rationale, an impact statement, a
      statement of what the control *does* achieve, and retest criteria
- [ ] Your remediation is code, not the phrase "server-side validation"
- [ ] You can explain why "add Frida detection" appears in the top half of the remediation table
- [ ] You answered all eight debrief questions in writing

---

## Next

[Lab 04 — CTF: The Lying Phone](lab-04-ctf-the-lying-phone.md) removes the diagnostics screen, adds
two more layers — a system-file hash and a Play-Integrity-style token — and then asks the only
question in this chapter that has a single correct answer: which of the three checks *could not* have
been defeated, had it been implemented correctly?
