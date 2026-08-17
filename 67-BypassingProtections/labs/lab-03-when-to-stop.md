# Lab 03 — When to stop bypassing

> **Objective.** Turn "I gave up and read the code" from an admission of defeat into a decision you
> make deliberately, early, and with reasons you can write down. You will run the same objective four
> different ways, measure each, and produce a rubric you can apply to the next target in under five
> minutes.

**Difficulty:** intermediate — the thinking is harder than the tooling
**Time:** 2–3 hours
**Root required:** no for parts A, C and D; part B is better with frida-server and gives a no-root
alternative
**Chapter sections this exercises:**
[README §3.8](../README.md#38-cost-and-detectability-quantified-as-far-as-honesty-allows),
[§3.13](../README.md#313-when-to-stop-bypassing-and-go-static),
[§5.6](../README.md#56-owasp-masvs--mastg-mapping-and-honest-severity),
[§8](../README.md#8-static-analysis)

---

## Why this lab exists

Almost everybody stops hooking eventually. Almost nobody stops *on purpose*. The usual sequence is:
three hours of increasingly desperate hooks, a growing suspicion that something is wrong, and finally
— out of exhaustion rather than judgement — opening the decompiler.

That is expensive twice over: you lost the three hours, and you never learned the signal that would
have saved them.

This lab makes you take the same objective four ways and **measure** each. The output is not a flag;
it is a filled-in table and a rubric in your own words.

---

## The objective

One sentence, fixed for all four approaches, so the comparison is honest:

> **Obtain the secret string that `com.pentest.ch67.guarded` protects, and be able to obtain it again
> next week on a rebuilt version of the app.**

The second clause is doing most of the work. An approach that gets the string once and cannot be
repeated has not met the objective.

---

## Setup

```bash
# host — device identity, recorded
adb devices -l && adb shell getprop ro.product.model && adb shell getprop ro.build.version.sdk

# host — build and install
cd 67-BypassingProtections
export ANDROID_HOME=~/Android/Sdk
OUTDIR=/tmp/ch67 ./examples/build.sh --install
```

Start a stopwatch for each part. You will need real numbers, not impressions. Write down the time
**including** the reading and the false starts — that is the number that matters.

---

## Part A — dynamic, at the verdict (seam 3)

The approach everyone reaches for first.

### Step 1

```bash
# host
frida -U -f com.pentest.ch67.guarded -l /tmp/a.js --no-pause
```

```javascript
// /tmp/a.js
'use strict';
Java.perform(function () {
    const G = Java.use('com.pentest.ch67.guarded.Guard');
    G.evaluate.overload('android.content.Context', 'java.lang.String')
        .implementation = function (ctx, sim) {
            const v = this.evaluate(ctx, sim);
            console.log('[real] trusted=' + v.trusted.value + ' score=' + v.score.value);
            v.trusted.value = true;
            v.score.value = 0;
            return v;
        };
    setTimeout(function () {
        Java.perform(function () {
            console.log('[secret] ' + Java.use('com.pentest.ch67.guarded.Vault').openUnchecked());
        });
    }, 2500);
});
```

**No frida?** Skip to part C and come back; note in your table that this approach was unavailable to
you, which is itself a data point about approach A.

**A1.** Time to first success, including writing the script.

**A2.** Now simulate the app being rebuilt. R8 would rename `Guard` and `evaluate`. Edit the class
name in your script to `com.pentest.ch67.guarded.a` and run again. What happens? How long would it
take you to find the new name in a real obfuscated build?

**A3.** Would this approach survive the developer computing the verdict in two places and comparing
them? Do not guess — read `Guard.evaluate` and describe what a second, native copy would see.

---

## Part B — dynamic, at the read (seam 2)

The approach the chapter recommends as a default.

### Step 2

```javascript
// /tmp/b.js — frida -U -f com.pentest.ch67.guarded -l /tmp/b.js --no-pause
'use strict';

const SUSPECT = /(^|\/)su$|magisk|frida|gum-js|gadget/i;

function hookInt(name, idx) {
    const p = Module.findExportByName('libc.so', name);
    if (p === null) { console.log('[-] absent: ' + name); return; }
    Interceptor.attach(p, {
        onEnter: function (a) { this.path = a[idx].readUtf8String(); },
        onLeave: function (r) {
            if (SUSPECT.test(this.path || '')) {
                console.log('[deny] ' + name + '("' + this.path + '")');
                r.replace(ptr(-1));
            }
        }
    });
    console.log('[+] ' + name);
}
['access', 'stat', 'lstat', 'open', 'open64'].forEach(function (n) { hookInt(n, 0); });
['faccessat', 'newfstatat', 'openat'].forEach(function (n) { hookInt(n, 1); });

Java.perform(function () {
    setTimeout(function () {
        Java.perform(function () {
            console.log('[secret] ' + Java.use('com.pentest.ch67.guarded.Vault').openUnchecked());
        });
    }, 2500);
});
```

**B1.** Time, including writing it.

**B2.** Rename the class in the final `Java.use` line as you did in A2. Which part of the script
breaks, and which part keeps working? What does that tell you about where the fragility actually
lives?

**B3.** Read the `[deny]` lines. List every path the app probed. **This list is your findings
section.** How much of it did approach A give you?

**B4.** Which of these two approaches would you rather hand to a colleague who has to repeat your
work on next month's build?

---

## Part C — static, patching

### Step 3

```bash
# host
mkdir -p /tmp/ch67-static && cd /tmp/ch67-static
cp /tmp/ch67/guarded-release/guarded-release.apk .
apktool d -f -o work guarded-release.apk

# find the responses first, then walk back to the branches
grep -rn 'Ljava/lang/System;->exit' work/smali/ | head
grep -rn 'Landroid/os/Process;->killProcess' work/smali/ | head
grep -rn 'enforce' work/smali/com/pentest/ch67/guarded/Guard.smali | head
```

Patch `Guard->enforce` to a no-op, then rebuild and re-sign:

```bash
# host
apktool b -o patched.apk work
BT="$(ls -d $ANDROID_HOME/build-tools/* | sort -V | tail -1)"
keytool -genkeypair -keystore ks -storepass android -keypass android -alias k \
    -dname "CN=CH67" -validity 10000 -keyalg RSA -keysize 2048 2>/dev/null
"$BT/zipalign" -f -p 4 patched.apk aligned.apk
"$BT/apksigner" sign --ks ks --ks-pass pass:android --key-pass pass:android \
    --out final.apk aligned.apk
adb install -r final.apk
```

**C1.** Time, including the false starts. (There will be false starts — see hint 2.)

**C2.** Did the app still run? If it threw a `VerifyError`, what did you get wrong?

**C3.** The APK is now signed with **your** key. Which class of control does that immediately trip,
and which chapter owns it?

**C4.** How long would it take you to redo this against a rebuilt app? Compare with A2 and B2.

---

## Part D — go around

### Step 4

```bash
# host
unzip -p /tmp/ch67/guarded-release/guarded-release.apk classes.dex | strings -a | grep -i CH67
```

**D1.** Time.

**D2.** What did you get? Compare with the answer from parts A and B.

**D3.** Now open [`examples/guarded-app/Vault.java`](../examples/guarded-app/Vault.java). The secret
is not stored as plaintext — it is XOR-obfuscated with a key and a position term. Why did `strings`
find something anyway, and what *exactly* did it find?

**D4.** Write ten lines of Python that reproduce `Vault.decrypt()` from the constants in the DEX.
Time it. You now have the secret with **no device involved at all**.

**D5.** Which of D3/D4 meets the objective's second clause — "again next week on a rebuilt version"?

---

## Part E — the rubric

### Step 5 — fill in your own numbers

| | A: verdict hook | B: read hook | C: patch | D: go around |
|---|---|---|---|---|
| Time to first success | | | | |
| Lines written | | | | |
| Survives a rebuild with renaming | | | | |
| Survives the developer adding two more checks | | | | |
| Detectable by the app | | | | |
| Requires root | | | | |
| Requires the device at all | | | | |
| Reproducible by a colleague from your notes | | | | |
| Tells you what the app checks | | | | |
| Tells you what the control protected | | | | |

**E1.** Which approach won on "time to first success"? Which won on the actual objective?

**E2.** Two of the ten rows are the ones that decide a real engagement. Which two, and why?

**E3.** Write the rubric in your own words: a short list of conditions under which you would go
static **before** trying to hook. Compare it afterwards with
[README §3.13](../README.md#313-when-to-stop-bypassing-and-go-static) and note any condition you
found that the chapter does not list.

---

## Part F — the honest severity conversation

You now have the secret, four different ways. Write the finding.

**F1.** In one sentence, what was the control protecting?

**F2.** Was the secret reachable without defeating any control? (You already know; say it plainly.)

**F3.** Given F1 and F2, what severity would you assign the bypass, and what severity would you
assign the underlying issue? They are **not** the same finding.

**F4.** Now do the same exercise against [`examples/server-app/`](../examples/server-app/):

```bash
# host — terminal 1
python3 -B examples/server-app/server.py
# host — terminal 2
adb reverse tcp:8767 tcp:8767
OUTDIR=/tmp/ch67 ./examples/build.sh --install-server
adb shell am start -n com.pentest.ch67.server/.MainActivity
```

Run parts A, B, C and D against it. What is the highest severity you can honestly justify?

**F5.** Write two paragraphs for a client report: one describing the resilience weakness in the
guarded app, one describing what the server-side design got right. Keep the second one — it is the
paragraph clients remember, and the one most testers never write.

---

## Hints

<details>
<summary>Hint 1 — A3, what a second copy would see</summary>

If the app computed the verdict again in native code and compared it with the Java result, your
seam-3 hook would produce `trusted=true` in Java and `trusted=false` in native. The comparison fails
and the app now knows not just that it is compromised but that it is being *actively lied to*, which
is a stronger signal than the original one and often triggers a harsher response.

A seam-2 hook has the opposite property: both copies read the same lie and agree.
</details>

<details>
<summary>Hint 2 — C2, the VerifyError</summary>

Three ways to break a Smali patch, all of which look like the protection working:

1. Making a method declared `Z` (boolean) `return-void`.
2. Reducing `.registers` below what the remaining code uses, or leaving a `p0` reference in a method
   you emptied.
3. Deleting an instruction that a `:label` still points at.

The symptom in all three is a `VerifyError` at class load, which crashes the app before your patched
code runs. `adb logcat -d | grep -i verify` will tell you in one line.
</details>

<details>
<summary>Hint 3 — D3, why `strings` finds something</summary>

`strings` will **not** find the flag itself — it is XOR-obfuscated in `Vault.BLOB`. What it finds is
everything *around* it: `CH67Guard`, `com.pentest.ch67.guarded`, `S1-input`, `SEAM_GATED`, the
response enum names, the su paths.

That is still enormously useful. It tells you the class to look at, the seam vocabulary the app uses,
and the fact that there is a `Vault`. Then you read `Vault.java` (or its decompilation) and see a
byte array and a key — at which point D4 takes ten minutes.

The lesson: `strings` rarely hands you the answer and very often hands you the *map*.
</details>

<details>
<summary>Hint 4 — E2, the two rows that decide an engagement</summary>

"Survives a rebuild" and "reproducible by a colleague from your notes".

Everything else is about your afternoon. Those two are about whether the work has any value after
you close the terminal. A finding that cannot be reproduced is a claim, and a claim that breaks on
the next build is not even that.
</details>

---

## Answers

<details>
<summary>Answers A1–A3</summary>

**A1.** Typically 5–10 minutes including writing the script. This is why everyone starts here and why
starting here is not wrong.

**A2.** The script throws `ClassNotFoundException` inside `Java.perform` and — this is the part that
catches people — execution simply stops there; later statements in the same `Java.perform` body never
run, and Frida does not always make that obvious. Finding the new name in a genuinely obfuscated
build means tracing by behaviour instead: `frida-trace -j`, or hooking a framework API the check must
use and taking a backtrace.

Budget 20–60 minutes per rebuild, every rebuild, forever.

**A3.** It would fail, and fail *loudly*: the two copies disagree, which is a stronger signal than the
original check. See hint 1.
</details>

<details>
<summary>Answers B1–B4</summary>

**B1.** Typically 15–25 minutes the first time; near zero afterwards, because
[37-RootDetection](../../37-RootDetection/scripts/native-root-bypass.js) ships the production version
of exactly this and you will reuse it.

**B2.** Only the final `Java.use('...Vault')` line breaks — and that line is not the bypass, it is
the *verification*. Every `Module.findExportByName('libc.so', ...)` call keeps working, because
bionic does not rename `access` for anybody.

The fragility lives entirely in the app-specific names, not in the technique.

**B3.** You get the full probe list — every suspicious path, in order, as the app asked for it. On
this app that is eight `su` paths, `/proc/self/status`, `/proc/self/maps`, `/proc/self/task/*/comm`.
Approach A gave you none of it: one boolean, and no idea what fed it.

**B4.** B. It survives renaming, it produces the findings section for free, and the parts that break
are trivially fixed.
</details>

<details>
<summary>Answers C1–C4</summary>

**C1.** Typically 45–90 minutes the first time, largely spent on the round trip and on at least one
`VerifyError`.

**C2.** See hint 2.

**C3.** Signature verification — the APK now carries your certificate, not the developer's. Any
self-signature check catches it immediately, and a **server-side** signature check catches it in a
way you cannot patch at all. `38-TamperDetection` owns this.

**C4.** Roughly the same time again. A patch is an offset into one specific binary; it does not
transfer. This is the row where patching loses badly to B.
</details>

<details>
<summary>Answers D1–D5</summary>

**D1.** Under a minute.

**D2.** Not the flag — see hint 3 — but the map: class names, the seam vocabulary, the probe paths,
and the existence of `Vault`.

**D3.** The flag is XOR-obfuscated with an 8-byte key plus a position term, so it is not a printable
string in the DEX. Everything around it is.

**D4.** Ten lines and about ten minutes:

```python
KEY  = [0x5A, 0x3C, 0x77, 0x11, 0x2E, 0xA9, 0x40, 0x08]
BLOB = [0x19, 0x73, 0x4F, 0x33, 0x49, 0xE9, 0x06, 0x08, 0x51, 0x6D, 0x45, 0x03,
        0x09, 0xC3, 0x46, 0x52, 0x75, 0x29, 0x39, 0xA4, 0xCE, 0x09, 0xBB, 0xC7,
        0xAD, 0xA2, 0xB2, 0xF3, 0x84, 0x52, 0xE6, 0x8E, 0xDB, 0x84, 0xF5, 0xD4,
        0xB1, 0xC1, 0x37]
print(''.join(chr(b ^ KEY[i % 8] ^ ((i * 7) & 0xFF)) for i, b in enumerate(BLOB)))
# CH67{cl13nt_s1d3_b00l3an_1s_n0t_a_l0ck}
```

**D5.** D4. It needs no device, no root, no Frida and no signing key; it is ten lines a colleague can
run; and it works on any build that ships the same constants. It is the only approach here that meets
both clauses of the objective without qualification.
</details>

<details>
<summary>Answers E1–E3</summary>

**E1.** A wins on time to first success. **D wins on the objective**, because the objective included
"again next week".

That gap — fastest-to-first-result is not best — is the entire content of this lab.

**E2.** See hint 4: "survives a rebuild" and "reproducible by a colleague".

**E3.** A reasonable rubric, and one that matches the chapter's:

Go static **before** hooking when:
- the thing you want is a **constant or an algorithm**, not a runtime value;
- you will need it more than twice;
- someone else has to reproduce it;
- the app has anti-instrumentation and you have not yet established that you can get in;
- the code you need to read is small (a decrypt routine, a key derivation, a check).

Keep hooking when:
- you need a runtime **value** — a derived key, a decrypted buffer, a live token;
- the logic is large and you need one branch of it;
- you are still exploring and do not know what you want yet.

A condition worth adding that the chapter does not spell out: **go static when the app is
cheap to rebuild but expensive to run.** If getting the app into the right state takes ten minutes of
tapping, every dynamic iteration costs ten minutes and static wins much earlier than the raw
complexity would suggest.
</details>

<details>
<summary>Answers F1–F5</summary>

**F1.** A string constant, obfuscated with a repeating XOR key, embedded in the APK.

**F2.** Yes. `Vault.openUnchecked()` reaches it with no control involved, and D4 reaches it with no
device involved.

**F3.** The bypass is **INFO to LOW** as a resilience observation: the controls are defeatable, which
they always are. The underlying issue is *"a secret is shipped in the APK and is recoverable
offline"*, and its severity is set entirely by **what the secret unlocks** — which for this demo is
nothing, so it too is INFO. If it were a production API key, the same technique would produce a HIGH.

The discipline is that the severity comes from the asset, never from the cleverness of the method.

**F4.** INFO. Every technique still works and none of them produces the secret, because the secret is
not on the device. The most you can honestly write is that the client-side signals are forgeable —
which the server already treats as telemetry, so it is not even a weakness in that design.

**F5.** Something like:

> **Resilience — client-side integrity controls are defeatable (LOW).** The application performs
> seven environment checks and aggregates them into a single boolean inside its own process. That
> boolean was modified at runtime with a four-line instrumentation script, and the same result was
> obtained without instrumentation by calling the protected routine directly and, separately, by
> reproducing the routine offline from constants in `classes.dex`. This is expected of any
> client-side control and is reported for completeness; no protected asset was exposed, because the
> protected value has no production significance.
>
> **What the alternative design got right.** The comparison build moves the decision to the server:
> the client reports the same seven signals but does not act on them, and the protected value is
> transmitted only when the server chooses to send it, gated on a single-use nonce the server itself
> issued. Every technique used above was applied to that build without effect — not because the
> client became harder to attack, but because there was nothing on the client left to attack. We
> recommend this pattern for any decision with a security consequence: **send the capability, never
> the permission.**
</details>

---

## Success criteria

- [ ] You completed all four approaches and recorded **real** times, including false starts
- [ ] Your table is filled in from your own measurements, not from the answers
- [ ] You can state which approach was fastest and which one actually met the objective
- [ ] You produced at least one `VerifyError` in part C and diagnosed it
- [ ] You reproduced the decryption offline, with no device involved
- [ ] You wrote the rubric in your own words before reading §3.13
- [ ] You wrote both report paragraphs, including the one about what the server-side design got right
- [ ] You can explain why the severity comes from the asset and not from the method

---

## Clean up

```bash
# host
cd 67-BypassingProtections
OUTDIR=/tmp/ch67 ./examples/build.sh --uninstall
adb reverse --remove-all
rm -rf /tmp/ch67-static /tmp/a.js /tmp/b.js
```

---

## Where to go next

- [Lab 04 — the CTF](lab-04-ctf-the-boolean-that-lied.md), where part D does **not** work, because
  the secret is a dependency rather than a gate.
- [52-StaticAnalysis](../../52-StaticAnalysis/README.md) for the discipline behind "a sweep produces
  leads, not findings".
- [README §5.6](../README.md#56-owasp-masvs--mastg-mapping-and-honest-severity) for the severity
  argument in full.
