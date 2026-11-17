# Lab 02 — The chain no chapter can host: static → dynamic → report

> **Objective.** Take one target from *"here is an APK"* to *"here is a report a developer can act
> on"*, crossing eight chapters without stopping. You will find four things statically, carry all
> four into a dynamic stage, watch **one of them die there**, watch a second one change severity in
> both directions, and write the finding up in a form that survives the two questions a developer
> will ask. The chain, not any individual step, is the subject.

**Difficulty:** Intermediate
**Time:** 3–5 hours. Do not compress it. The compression is the mistake this lab exists to prevent.
**Prerequisites:** [Lab 01](lab-01-the-capability-survey.md) — you must know what your setup can do.
Reading knowledge of [10-APK-Internals](../../10-APK-Internals/README.md),
[32-Manifest](../../32-Manifest/README.md), [26-Intent](../../26-Intent/README.md),
[27-ContentProviders](../../27-ContentProviders/README.md) and
[60-ADB](../../60-ADB/README.md). You do **not** need to have done their labs.
**Requires:** a device or emulator, a JDK and the SDK build-tools. **No Frida and no proxy.** Root is
**optional and used in §6.2 only**, to show that the same command has a different outcome from a
different vantage; the lab completes without it. `apktool` and `jadx` are convenient and neither is
required — §3.2 and §3.3 give an SDK-only route for both. That minimal requirement set is
deliberate: this lab was built to run on the setup Lab 01 measured, which has no working
`frida-server`.
**Device used to verify this lab:** AVD `sdk_gphone16k_x86_64` (`emulator-5554`), Android 15 / API
35, x86_64, `userdebug`. Every command output below was produced there on 2026-08-16 and is
reproduced verbatim, including the one that looked like a success and was not.

---

## 1. Why this lab exists

Every chapter in this repository teaches one stage of the work well. Chapter 52 teaches you to read
an app without running it. Chapter 51 teaches you to run it. Chapter 71 teaches you to classify what
you found. Each is correct and each is complete.

**Nothing teaches the handoffs**, and the handoffs are where findings die.

Consider what a handoff actually is. At the end of the static stage you have a list of things that
*look* wrong. Every one of them is a hypothesis. The dynamic stage exists to convert hypotheses into
observations, and it does so with a brutal conversion rate: on real engagements most static findings
either evaporate, shrink, or turn out to be a symptom of something else entirely. If you have never
watched that happen under controlled conditions, you will do one of two things in the field — report
the hypotheses as findings, or discard anything you cannot instantly prove. Both are bad, and the
second is worse, because it is invisible.

> **Mental Model.** A static finding is a *witness statement*: someone says they saw something.
> A dynamic confirmation is *the security footage*. Reports built only on witness statements get
> retracted. Reports built only on footage miss everything the camera did not point at. The work is
> the correlation, and the correlation is what no single chapter can teach you, because it needs
> both chapters at once.

### 1.1 The four things you will carry through the chain

The target has four planted defects. You do not yet know which is which, and you should not read the
sources until §8. What you will discover is that they behave in four different ways at the handoff:

| | Behaviour at the handoff | Why it matters |
|---|---|---|
| One | Confirms immediately and exactly as predicted | The easy case. It is also the rarest |
| Two | Confirms, but the dynamic stage **raises** the severity beyond what static analysis could see | Static analysis systematically under-rates data exposure, because it cannot see the data |
| Three | **Dies.** Reachable on paper, unreachable in practice | This is the false positive that a static-only report ships |
| Four | Confirms *and* dies, depending on who is asking | The finding whose severity is a function of the caller, which is most of them |

---

## 2. Setup

### 2.1 Build and install the target

The target is deliberately insecure and ships as **sources only** — this repository never commits an
APK. Build it out of tree:

```bash
# host — from the repository root
cd 73-Labs/examples
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
./build-chain-target.sh --install
```

Measured tail of that run:

```
=== built
-rw-r--r-- 1 harsh 197609 12683 Aug 17 13:41 /tmp/ch73-chain-build/chain-target.apk
  nothing was written inside the repository; everything is under /tmp/ch73-chain-build

=== install
Performing Incremental Install
Success
Install command complete in 241 ms

=== installed?
package:com.pentest.ch73.chain
```

> **Warning.** `chain-target.apk` is 12 KB and does nothing useful. It is a *specimen*, not a
> demonstration app. Uninstall it when you are finished:
> `./build-chain-target.sh --uninstall`.

### 2.2 If the build fails

Three failures were hit while writing this lab, on a stock Windows + Git Bash machine. All three are
handled by the script now, and all three are worth knowing because they recur in every no-Gradle
build in this repository.

| Failure | Cause | Fix |
|---|---|---|
| `javac: invalid flag: /c/Users/<you>/Desktop/Android` | The argfile listed source paths unquoted, and this repository's path contains a space | Quote every line of the argfile |
| `zip: command not found` | `zip` is **not** present on a default Windows + Git Bash install | The script falls back to Python's `zipfile`, then to the JDK's `jar` |
| `aapt2: failed to load XML file` on a file that exists | The SDK tools are native Windows binaries and do not understand `/c/Users/...` | Every path goes through `cygpath -w` |

### 2.3 The install floor, measured

Worth doing once, because it is the most common install refusal that is **not** an OEM policy:

```bash
# host
OUTDIR=/tmp/ch73-sdk23 ./build-chain-target.sh --target-sdk 23
adb install /tmp/ch73-sdk23/chain-target.apk
```

```
Failure [INSTALL_FAILED_DEPRECATED_SDK_VERSION: App package must target at least SDK version 24,
but found 23]
```

And past it:

```bash
# host
adb install --bypass-low-target-sdk-block /tmp/ch73-sdk23/chain-target.apk
adb shell "dumpsys package com.pentest.ch73.chain | grep -m1 targetSdk"
```

```
Success
    versionCode=0 minSdk=23 targetSdk=23
```

> **Pentester's Note.** Distinguish the three refusals, because the fixes are unrelated.
> `INSTALL_FAILED_DEPRECATED_SDK_VERSION` is the platform's own floor and
> `--bypass-low-target-sdk-block` lifts it. `INSTALL_FAILED_USER_RESTRICTED` is an **OEM** policy —
> this repository measured it on a MIUI handset, where the working route was a root install from the
> device shell. `INSTALL_FAILED_UPDATE_INCOMPATIBLE` is a signing-key mismatch and means you must
> uninstall first. This lab hit the third one too, by rebuilding with a fresh debug key; the
> keystore is regenerated per build directory, which is a feature for hygiene and a trap for
> upgrades.

Reinstall the normal build before continuing:

```bash
# host
adb uninstall com.pentest.ch73.chain
./build-chain-target.sh --install
```

### 2.4 Open your evidence ledger

Before you look at the target, open the ledger. Every row is a claim; every claim gets a stage, an
evidence type, and a verdict. Copy the template:

```bash
# host
cp ../examples/evidence-ledger.md ~/ch73-ledger.md
```

> **Warning.** Keep the ledger **outside** the repository. It is your working artefact, and it
> will contain paths and output from your machine.

The ledger is not bureaucracy. It is the mechanism that makes the handoff visible: a finding that
enters the dynamic stage and does not leave it has to be explained, and the ledger is where you
notice that it did not.

---

## 3. Stage 1 — Static, and nothing but static

**Do not run the app in this stage.** The discipline is the point: everything below is a hypothesis,
and the hypotheses you form when you have already seen the app run are contaminated by what you saw.

### 3.1 What is in the file

The chapter this belongs to is [10-APK-Internals](../../10-APK-Internals/README.md).

```bash
# host
cd /tmp/ch73-chain-build
python3 -B -c "
import zipfile
for i in zipfile.ZipFile('chain-target.apk').infolist():
    print('%9d  %s' % (i.file_size, i.filename))"
```

Measured:

```
     2948  AndroidManifest.xml
       40  resources.arsc
     7000  classes.dex
      412  META-INF/CH73.SF
     1292  META-INF/CH73.RSA
      285  META-INF/MANIFEST.MF
```

Two of those six matter. `AndroidManifest.xml` is the attack-surface declaration and `classes.dex`
is the code; the `META-INF` entries are the v1 signature and `resources.arsc` is a 40-byte stub
because this target has no resources.

> **Pentester's Note.** `unzip -l` does the same job and is what most write-ups use, but it is
> **not present on a default Windows + Git Bash machine** — `zip`/`unzip` are not part of Git for
> Windows. The Python form above works everywhere Python does, which is everywhere this repository's
> scripts already run. Prefer tools you have measured yourself to have, which is the whole argument
> of [Lab 01](lab-01-the-capability-survey.md).

### 3.2 The manifest

The chapter is [32-Manifest](../../32-Manifest/README.md). The manifest inside an APK is **binary
XML**, not text, so `cat` gives you nothing. Two ways to read it, and you should know both:

```bash
# host — the SDK's own decoder, no third-party tool needed
"$ANDROID_HOME/build-tools/35.0.1/aapt2" dump xmltree \
    --file AndroidManifest.xml chain-target.apk | head -60
```

```bash
# host — if you have apktool, which decodes resources as well
apktool d -f -o /tmp/ch73-apktool chain-target.apk
cat /tmp/ch73-apktool/AndroidManifest.xml
```

> **Pentester's Note.** Reach for `aapt2 dump xmltree` before `apktool`. It ships with the SDK
> you already have, it cannot fail on a resource table it does not understand, and it shows you the
> *resolved* attribute values including the integers behind constants. Lab 01's survey found
> `apktool` absent on the machine this lab was verified on, and the lab was completed anyway.

Measured head of the `aapt2` output:

```
N: android=http://schemas.android.com/apk/res/android (line=20)
  E: manifest (line=20)
    A: package="com.pentest.ch73.chain" (Raw: "com.pentest.ch73.chain")
      E: uses-sdk (line=23)
        A: minSdkVersion(0x0101020c)=24
        A: targetSdkVersion(0x01010270)=35
      E: permission (line=29)
        A: name(0x01010003)="com.pentest.ch73.chain.permission.ADMIN"
        A: protectionLevel(0x01010009)=0x00000002
```

> **Under the Hood.** `protectionLevel=0x00000002` is the value you must be able to read without
> looking it up, because it is the whole of §6. `0x0` is `normal`, `0x1` is `dangerous`, **`0x2` is
> `signature`**, `0x3` is `signatureOrSystem`. A decoded manifest from `apktool` would have shown
> you the word; `aapt2` shows you the integer, and the integer is what the package manager compares.

Record every exported component. There are three, and one of them carries a `permission` attribute.

**Hypothesis 1.** `VaultActivity` is exported with a `LAUNCHER` intent filter. Exported activities
are normal; this one is worth a second look only when you read the code.

**Hypothesis 2.** `NotesProvider` is exported with **no** `permission`, no `readPermission`, no
`writePermission` and no `<path-permission>`. Authority `com.pentest.ch73.chain.notes`.

**Hypothesis 3.** `AdminReceiver` is exported, listens for a `WIPE` action, and is guarded by
`com.pentest.ch73.chain.permission.ADMIN`. Note the permission's own declaration.

### 3.3 The code

The chapters are [52-StaticAnalysis](../../52-StaticAnalysis/README.md) and
[56-JADX](../../56-JADX/README.md).

```bash
# host
jadx -d /tmp/ch73-jadx chain-target.apk
grep -rn "UNLOCK\|getBooleanExtra" /tmp/ch73-jadx/sources/ | head
grep -rn "getCallingPackage\|getCallingUid\|checkPermission" /tmp/ch73-jadx/sources/ | head
```

If `jadx` is not available, the SDK's `dexdump` will get you far enough for this target:

```bash
# host
"$ANDROID_HOME/build-tools/35.0.1/dexdump" -d classes.dex | grep -i "const-string" | head -30
```

Read `VaultActivity`. Two things should stop you.

**Hypothesis 1, sharpened.** The activity's behaviour branches on
`getIntent().getBooleanExtra("com.pentest.ch73.chain.UNLOCK", false)`. There is no
`getCallingPackage()` check, no permission check, no signature check. The extra is the entire gate,
and an extra is attacker-controlled by definition.

**Hypothesis 4.** A sixteen-byte string constant is used as a key. Follow it: it feeds an XOR loop
and a Base64 encode. That is not encryption — see
[34-Cryptography](../../34-Cryptography/README.md) — and the key is in the DEX in the clear.

Read `NotesProvider`. `query()` accepts `selection` and never uses it. There is no caller check of
any kind.

Read `AdminReceiver`. It logs, and its comment says it would clear preferences.

### 3.4 Write the static stage down before you touch the device

Fill in the ledger now, with `stage=static` and `verdict=hypothesis` for all four. Force yourself to
predict:

| # | Component | Predicted severity, static only | Predicted dynamic result |
|---|---|---|---|
| 1 | `VaultActivity` unlock extra | Medium | Any app can open the vault |
| 2 | `NotesProvider` | Medium | Any app can read the notes table |
| 3 | `AdminReceiver` | **High** — exported, destructive action | Any app can trigger a wipe |
| 4 | XOR "encryption" | Low | The key recovers the secret |

**Write your own predictions, not these.** Then compare at the end. The gap between the two tables
is the thing this lab is trying to give you, and you cannot have it if you copy the answer.

> **Definition — hypothesis, in this context.** A statement about the target that is consistent
> with everything you have read and has not yet been tested against anything the target *does*. It
> is not a finding. Calling it one is the single most common failure in a junior report.

---

## 4. The handoff

Stop. Before running anything, answer three questions in your ledger, in writing:

1. **For each hypothesis, what observation would confirm it?** Not "I would see that it works" — the
   specific command and the specific output.
2. **For each hypothesis, what observation would refute it?** If you cannot name one, the hypothesis
   is unfalsifiable and it does not belong in a report.
3. **What is your vantage?** You are about to run commands as the `shell` user, uid 2000. That is
   not the same as an app, and it is not the same as root. Write down which one your claims will be
   about.

> **Warning — the vantage error.** This is the most-repeated methodology finding in this
> repository. `shell` holds permissions an ordinary app does not, and root holds permissions
> `shell` does not. A result measured from one chair and reported as though from another is wrong
> even when every command succeeded. §6 shows this happening, with output that is byte-identical
> between the two cases.

---

## 5. Stage 2 — Dynamic

The chapters are [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md),
[60-ADB](../../60-ADB/README.md), [26-Intent](../../26-Intent/README.md) and
[27-ContentProviders](../../27-ContentProviders/README.md).

Start a log stream in a second terminal and leave it running:

```bash
# host — terminal 2
adb logcat -c
adb logcat -s ch73chain
```

### 5.1 Hypothesis 2 — the provider

```bash
# host
adb shell "content query --uri content://com.pentest.ch73.chain.notes"
```

Measured:

```
Row: 0 _id=1, title=shopping, body=milk, bread, a 16 KiB page size
Row: 1 _id=2, title=session, body=Bearer ch73.eyJzdWIiOiJsYWItMDIifQ.not-a-real-token
Row: 2 _id=3, title=wrapped, body=ICAAAFYaBxEAAkUKDBcMSBBFQ1tIQwMRXhJCBRg=
```

And in terminal 2:

```
I ch73chain: query from uid 2000 selection=null
```

**Confirmed — and the severity went up.** Statically you could prove the provider was reachable. You
could not know what it contained. It contains a bearer credential.

> **Pentester's Note.** This asymmetry is systematic and worth internalising: **static analysis
> under-rates data exposure and over-rates reachability.** It sees the door and not the room. That
> is exactly backwards from how most people expect the two stages to differ, and it is why a
> report written from static analysis alone tends to have its severities wrong in *both* directions
> at once.

Now do the thing that separates a finding from an observation — establish the boundary:

```bash
# host — does the selection argument do anything at all?
adb shell "content query --uri content://com.pentest.ch73.chain.notes --where \"_id=1\""
```

You get all three rows again. The provider ignores `selection`. That is a second, smaller finding
riding inside the first, and it changes the remediation advice: fixing the export alone would leave
a provider that cannot filter, which will bite the developer the moment they add a permission and
assume the query is scoped.

### 5.2 Hypothesis 1 — the unlock extra, and a command that lied

```bash
# host
adb shell "am start -n com.pentest.ch73.chain/.VaultActivity"
adb shell "am start -n com.pentest.ch73.chain/.VaultActivity --ez com.pentest.ch73.chain.UNLOCK true"
```

Measured — read the second block carefully:

```
Starting: Intent { cmp=com.pentest.ch73.chain/.VaultActivity }

Starting: Intent { cmp=com.pentest.ch73.chain/.VaultActivity (has extras) }
Warning: Activity not started, intent has been delivered to currently running top-most instance.
```

And terminal 2:

```
I ch73chain: vault locked; launched by (unknown)
```

**One log line, not two.** The second `am start` printed `Starting:` and the word `Warning:`, and it
did nothing at all: the activity was already the top of its task, so the system delivered the intent
to the running instance — which never re-runs `onCreate` and therefore never reads your extra.

> **Warning — this is a false negative, and it is the most dangerous kind.** The command
> succeeded. It printed a line beginning `Starting:`. If you were watching the phone screen you
> would have seen the vault, still locked, and concluded the extra does not work and the hypothesis
> is refuted. **A refutation caused by your own tooling is indistinguishable from a real one unless
> you check that the code you are testing actually ran.** That is what the log line in terminal 2 is
> for, and it is why this lab has you start logcat before the first command rather than after the
> first surprise.

The fix is to give the activity nowhere to hide:

```bash
# host
adb shell "am force-stop com.pentest.ch73.chain"
adb shell "am start -n com.pentest.ch73.chain/.VaultActivity --ez com.pentest.ch73.chain.UNLOCK true"
```

```
I ch73chain: vault opened via extra; secret=CH73{the-chain-is-the-lesson}
```

**Confirmed, exactly as predicted.** Note in the ledger that it took two attempts and why — a
finding you reproduced only after changing your method is a finding whose reproduction steps must
include the change.

### 5.3 Hypothesis 4 — the key that is not a key

The wrapped row from §5.1 and the constant from §3.3 are all you need. No device:

```bash
# host
python3 -B -c "
import base64
key = b'ch73-not-a-key!!'
data = base64.b64decode('ICAAAFYaBxEAAkUKDBcMSBBFQ1tIQwMRXhJCBRg=')
print(bytes(c ^ key[i % len(key)] for i, c in enumerate(data)).decode())"
```

```
CH73{the-chain-is-the-lesson}
```

**Confirmed.** But stop and ask what was actually confirmed. You already had the plaintext from
§5.2, by a completely different route. What this step establishes is not *that the secret is
recoverable* — you knew that — but that **it is recoverable without running the app at all**, which
is a different and worse property. An attacker with a copy of the APK and one row of exported data
needs no device, no root and no execution.

That distinction is the severity argument, and it only exists because you ran both stages and
compared them.

---

## 6. Hypothesis 3 — the finding that dies, and then does not

This is the section the lab is really for.

### 6.1 Try it the obvious way

```bash
# host
adb shell "am broadcast -a com.pentest.ch73.chain.WIPE -n com.pentest.ch73.chain/.AdminReceiver"
```

```
Broadcasting: Intent { act=com.pentest.ch73.chain.WIPE flg=0x400000 cmp=com.pentest.ch73.chain/.AdminReceiver }
Broadcast completed: result=0
```

That looks like success. **It is not.** Check terminal 2:

```
(nothing)
```

The receiver never ran. Try without the explicit component, in case the filter is the problem:

```bash
# host
adb shell "am broadcast -a com.pentest.ch73.chain.WIPE"
```

```
Broadcasting: Intent { act=com.pentest.ch73.chain.WIPE flg=0x400000 }
Broadcast completed: result=0
```

Still nothing in the log. The receiver is guarded by a **`signature`**-level permission, so only a
package signed with the same certificate may deliver to it. No such package exists, and `shell` is
not one.

> **Warning.** `Broadcast completed: result=0` is printed **whether or not any receiver ran.**
> The result code is the ordered-broadcast result, not a delivery count. This is the single most
> misread output in `am`, and it is why the decoy in this lab is a broadcast rather than anything
> else.

### 6.2 Now try it as root, and watch the conclusion change

```bash
# host — this AVD's su takes `su 0 <cmd>`; see Lab 01 §3.2
adb shell "su 0 am broadcast -a com.pentest.ch73.chain.WIPE -n com.pentest.ch73.chain/.AdminReceiver"
```

```
Broadcasting: Intent { act=com.pentest.ch73.chain.WIPE flg=0x400000 cmp=com.pentest.ch73.chain/.AdminReceiver }
Broadcast completed: result=0
```

**Byte-identical output.** And terminal 2:

```
W ch73chain: AdminReceiver reached by uid 10210 action=com.pentest.ch73.chain.WIPE
W ch73chain: AdminReceiver would clear 1 preference entries (it does not, this is a lab)
```

The receiver ran.

Three things follow, and each is worth more than the finding itself:

1. **The command's own output distinguished nothing.** Identical text, opposite outcomes. If your
   evidence for a broadcast finding is the `am` output, you have no evidence.
2. **The severity is a function of the caller, not of the component.** Unreachable by an app.
   Unreachable by `shell`. Reachable by root. Those are three different rows in a report, and
   collapsing them into "exported receiver, high" is wrong in a way that will be caught.
3. **The honest verdict is not "not exploitable".** It is: *"unreachable by any caller we were able
   to construct — specifically, an unprivileged app and the `shell` user — because the guarding
   permission is `signature`-level and no co-signed package is present. Reachable by root, which is
   not a meaningful attacker for this control."* Write that sentence. It is the finding.

### 6.3 A trap inside the trap

Look again at the log line: `AdminReceiver reached by uid 10210`.

**10210 is the target app's own uid, not the broadcaster's.** `Binder.getCallingUid()` returns the
identity of the current incoming binder transaction, and a broadcast delivered by `system_server` to
`onReceive` is not one — so it falls back to the receiving process's own uid.

Verify it for yourself rather than believing this paragraph:

```bash
# host
adb shell "pm list packages -U com.pentest.ch73.chain"
```

```
package:com.pentest.ch73.chain uid:10213
```

> **Under the Hood.** Two things to take away. First, **`getCallingUid()` inside `onReceive` does
> not identify the sender**, so an app that "checks the caller" this way checks nothing — that is a
> real vulnerability class, not a lab artefact. Second, notice that the uid is `10213` and the log
> said `10210`: the app uid **changed between installs**. If you record a uid in a report, record
> the install it belonged to, or the developer will not be able to reproduce you.

---

## 7. Stage 3 — The report

The chapters are [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) and
[72-RealWorldFindings](../../72-RealWorldFindings/README.md).

### 7.1 Reconcile the ledger

Go back to your §3.4 predictions. On the verified run they resolved like this:

| # | Predicted | Actual | What moved it |
|---|---|---|---|
| 1 | Medium, confirms | **Confirms.** Medium | Nothing — but it took two attempts, and the first looked like a refutation |
| 2 | Medium, confirms | **Confirms, severity up.** The table holds a bearer credential | Static analysis could see the door, not the room |
| 3 | **High** | **Not a finding** as written. Unreachable by app or `shell`; reachable by root | The permission's protection level, which the manifest stated plainly and the prediction ignored |
| 4 | Low, confirms | **Confirms, severity up.** Recoverable with no device and no execution | The combination with finding 2, which neither finding has on its own |

Three of four predictions were wrong, and the one that was most confidently wrong was the one that
looked worst on paper. That ratio is not unusual and it is not a failure of your static analysis; it
is what the dynamic stage is *for*.

> **Mental Model.** Findings 2 and 4 are worth more together than apart, and nothing in either
> chapter's methodology would have combined them. **Composition is the aggregator's job**, and it is
> the reason a chain lab exists at all. A reader who does chapters 27 and 34 separately gets both
> facts and never gets the sentence that puts them together.

### 7.2 Write it up

Use the template in [`../examples/evidence-ledger.md`](../examples/evidence-ledger.md), and make each
finding answer the two questions a developer always asks:

- **"Can you show me?"** — the exact command, the exact output, the device it ran on.
- **"Who can actually do this?"** — the vantage. App, `shell`, or root. Say which, and say what you
  did not test.

A finding that answers both is actionable. A finding that answers neither is an accusation.

### 7.3 The sentence that must appear

Somewhere in your report, in writing:

> *Findings were established from the `shell` vantage (uid 2000) on an emulator running Android 15 /
> API 35. Finding 3 was additionally tested from root. No finding was established from an
> unprivileged third-party application, and the provider finding in particular should be re-tested
> from one before release.*

That paragraph costs you nothing and is the difference between a report that survives review and one
that is quietly discounted. It is also, precisely, the thing an aggregating chapter can teach and a
per-topic chapter structurally cannot: **the limits of a result are a property of the chain, not of
any step in it.**

---

## 8. Now read the sources

Only now. Everything you concluded above was reached without them, which is the point.

- [`../examples/chain-target/AndroidManifest.xml`](../examples/chain-target/AndroidManifest.xml)
- [`../examples/chain-target/src/com/pentest/ch73/chain/VaultActivity.java`](../examples/chain-target/src/com/pentest/ch73/chain/VaultActivity.java)
- [`../examples/chain-target/src/com/pentest/ch73/chain/NotesProvider.java`](../examples/chain-target/src/com/pentest/ch73/chain/NotesProvider.java)
- [`../examples/chain-target/src/com/pentest/ch73/chain/AdminReceiver.java`](../examples/chain-target/src/com/pentest/ch73/chain/AdminReceiver.java)

Check your decompiled output against them. In a 12 KB unobfuscated APK the two should agree almost
perfectly, and where they do not — synthetic methods, string constant handling, the shape of the
`switch` — you have just learned something about your decompiler that transfers to targets where you
will not have the sources.

---

## 9. Extensions

Ordered by how much they teach, not by difficulty.

1. **Do it from an app, not from `shell`.** Build a second package that queries the provider and
   starts the activity. This closes the vantage gap §7.3 admits to, and it is the single most
   valuable extension here. [30-Activities](../../30-Activities/README.md) has a working two-app
   build you can adapt.
2. **Rebuild the target with `android:exported="false"` on the provider** and re-run every command in
   §5. Watch which error you get, and whether it is distinguishable from "the app is not installed".
3. **Add R8 and try again.** [42-R8](../../42-R8/README.md). Does your static stage still find the
   XOR key? Does it still find the extra's name? One of those survives obfuscation and one does not,
   and the asymmetry is instructive.
4. **Do the whole chain against a system APK you pulled off the device** — `pm path`, then `adb
   pull`. Expect to find nothing. That experience is worth having in a controlled setting rather
   than on a client engagement, and it is what
   [74-CaseStudies](../../74-CaseStudies/README.md) case F is about.
5. **If you have a working Frida**, redo §5.2 by hooking the extra read instead of forcing a
   restart, and compare the evidence quality of the two approaches.

---

## 10. Success criteria

- [ ] You built and installed the target without writing any artefact inside the repository.
- [ ] You wrote four hypotheses and four predicted severities **before** running anything.
- [ ] You confirmed hypotheses 1, 2 and 4, and you can state what each confirmation added that the
      static stage could not have known.
- [ ] You reached the state where hypothesis 3 looked confirmed (`Broadcast completed: result=0`) and
      you did not accept it.
- [ ] You can explain why the same command produced identical output in two cases with opposite
      outcomes, and what you would use as evidence instead.
- [ ] You can state what `Binder.getCallingUid()` returns inside `onReceive`, and why.
- [ ] Your report names its vantage and states at least one thing you did not establish.
- [ ] You uninstalled the target and your ledger lives outside the repository.

---

## 11. Cleanup

```bash
# host
cd 73-Labs/examples
./build-chain-target.sh --uninstall
rm -rf /tmp/ch73-chain-build /tmp/ch73-sdk23 /tmp/ch73-jadx /tmp/ch73-apktool
adb logcat -c
```

Verify nothing of yours is left:

```bash
# host
adb shell "pm list packages | grep ch73"        # expect no output
git status --short                               # expect no output
```

> **Warning.** If you find files under `/data/local/tmp` that are not yours, **leave them.** A
> live workspace and abandoned residue look identical from outside, and this repository has a
> standing rule against sweeping another session's directory. Clean what you created; nothing else.

---

## 12. Where this goes next

| Next | Why |
|---|---|
| [Lab 03 — write a lab that survives](lab-03-write-a-lab-that-survives.md) | You have now consumed a lab critically. Write one |
| [Lab 04 — CTF: the gauntlet](lab-04-ctf-the-gauntlet.md) | The same chain, five flags, no hand-holding |
| [74-CaseStudies](../../74-CaseStudies/README.md) | Six investigations where the handoff is the whole story |
| [72-RealWorldFindings](../../72-RealWorldFindings/README.md) | Severity, defended under pushback |
