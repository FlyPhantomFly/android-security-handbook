# Lab 01 — The sixty-minute triage, using only the sheets

> **Difficulty:** Beginner → Intermediate
> **Time:** 60 minutes on the clock, then 30 minutes of review. The review is where the learning is.
> **Prerequisites:** [`../README.md`](../README.md) §2 and §4.1. An Android device or emulator, `adb`,
> `aapt2` (or `apktool`), and any APK you are authorised to analyse.
> **Constraint:** you may consult **only** cheat sheets — this chapter's, and the per-chapter ones
> reached through [`../references/cheatsheet-index.md`](../references/cheatsheet-index.md). No chapter
> READMEs, no web search, no asking anybody.

---

## 1. Why this lab exists

A cheat sheet is not tested by reading it. It is tested by being **under time pressure with it and
nothing else**, which is the only situation in which its omissions become visible.

You are going to discover three things about cheat sheets in this hour, and you will discover them
by being hurt by them rather than by being told:

1. **Where the sheets are enough.** More often than you expect. Most of a first-pass triage is
   mechanical, and mechanical is exactly what a sheet is for.
2. **Where a sheet silently assumes something you do not have.** Root, a physical device, a
   debuggable build, a tool you have not installed. The command runs and returns *something*.
3. **Where the sheet is right and you still cannot use it**, because you do not understand the
   output well enough to interpret it. This is the honest limit of reference material, and noticing
   it in yourself is worth more than any finding you will make today.

> **🧠 Mental Model**
> This lab is not scored on findings. It is scored on your **timing log** and on how honestly you
> classify what stopped you. A triage that produces two findings and an accurate account of what it
> did not cover is worth more than one that produces six unadjudicated leads.

---

## 2. Authorisation

You must have the right to analyse the APK you choose. Any of these is fine:

- An app **you wrote**, including a five-minute "hello world".
- A deliberately vulnerable training app licensed for that purpose — see
  [`../../80-Appendix/README.md`](../../80-Appendix/README.md) §3 for the canonical list.
- An APK pulled from your own device where the licence permits analysis.

Do not point this at a third-party production app you have no written authorisation for. The
techniques are identical; the legal position is not.

---

## 3. Setup — 5 minutes, not on the clock

```bash
# host — from 76-CheatSheets/
bash examples/03-session-preflight.sh --pkg <your-debuggable-package>
```

Copy its output into your notes file **before you start the timer**. Every claim you make today has
to name the device it was made on; capturing that afterwards from memory is how a report acquires a
wrong build fingerprint.

Create your notes file with this skeleton:

```
TARGET      : <package> <version>
APK SHA-256 : <hash>
DEVICE      : <from preflight>
START       : <hh:mm>

T+00
T+05
...

STOPPED BY  :
NOT COVERED :
```

The last two lines are the deliverable. Fill them in as you go, not at the end.

---

## 4. The run — 60 minutes on the clock

Work through §4.1 of [`../README.md`](../README.md) in order. The order is not decoration; it is
chosen so each step makes the next one cheaper. Log a line every five minutes even when the line is
"still reading jadx output".

### Phase A — Identity (target: 5 minutes)

```bash
# host
sha256sum app.apk
aapt2 dump badging app.apk | grep -E 'package|sdkVersion|targetSdkVersion'
```

Record `package`, `versionName`, `versionCode`, `minSdk`, `targetSdk`.

> **🔍 Pentester's Note**
> `targetSdk` — not the device's OS version — decides most of this app's security defaults. If it is
> low, you have found more than one issue: a low `targetSdk` re-enables implicitly exported
> providers, trusted user CAs, permitted cleartext, legacy external storage, and implicitly mutable
> `PendingIntent`s. Note the number now; you will come back to it.

**Checkpoint A.** You should have five facts. If `aapt2` is not on your PATH, this is your first
`STOPPED BY` entry — write it down and move to `apktool d` or `unzip` + a binary XML reader.

### Phase B — Manifest (target: 10 minutes)

```bash
# host
aapt2 dump xmltree app.apk --file AndroidManifest.xml > manifest.txt
grep -c 'E: activity' manifest.txt
grep -c 'E: service' manifest.txt
grep -c 'E: receiver' manifest.txt
grep -c 'E: provider' manifest.txt
grep -B4 'android:exported' manifest.txt | head -60
grep 'uses-permission' manifest.txt
```

Build a table:

| Component | Class | Exported | Permission | Intent filter |
|---|---|---|---|---|

**Checkpoint B.** How many components are reachable by another app? If the answer is "I cannot tell
because `exported` is absent", that is the correct answer and it is version-dependent — the default
changes with `targetSdk` and with whether an intent filter is present. The router will point you at
[`32-Manifest`](../../32-Manifest/cheatsheet.md), which has the matrix.

### Phase C — The authority (target: 5 minutes)

```bash
# host
adb install app.apk
adb shell "dumpsys package <pkg>" | grep -E 'flags=\[|targetSdk|versionName|userId='
adb shell "dumpsys package <pkg>" | sed -n '/Activity Resolver Table/,/^$/p' | head -40
```

Compare against Phase B. **If the manifest tools and `dumpsys package` disagree, the platform is
right and the disagreement is itself the finding** — a crafted binary XML can make `apktool` and
`jadx` display something different from what `PackageManager` actually parsed.

**Checkpoint C.** Note the flags line. `DEBUGGABLE` in a production build is a serious finding on its
own. `ALLOW_BACKUP` is the default and worth a row in any report.

### Phase D — Network policy (target: 5 minutes)

```bash
# host
unzip -p app.apk res/xml/network_security_config.xml | head -40
grep -A3 'networkSecurityConfig' manifest.txt
grep 'usesCleartextTraffic' manifest.txt
```

If the config is compiled binary XML, `unzip -p` gives you unreadable bytes. That is a `STOPPED BY`
entry unless a sheet gives you the decoding step. Look for it. (It exists.)

**Checkpoint D.** Three questions: does it permit cleartext, does it trust user-added CAs, and is
there a `<pin-set>`? Each has a different consequence for the rest of your hour.

### Phase E — Storage (target: 10 minutes)

```bash
# host
adb shell "run-as <pkg> ls -laR ." | head -60
adb shell "run-as <pkg> cat shared_prefs/*.xml" 2>/dev/null | head -40
```

Exercise the app first — log in if it has a login, open its main screens — then run these again and
diff. Data written at first launch and data written after authentication are different findings.

> **⚠️ Warning**
> If `run-as` refuses, read *which* refusal you got. `package not debuggable` and
> `package not an application` are different conditions, and treating the second as the first loses a
> genuine finding. The sheets say which is which.

**Checkpoint E.** Anything in `shared_prefs/`, any `.db`, any `.json`. And note the `-wal` files
beside any SQLite database — deleted rows survive there.

### Phase F — Traffic (target: 15 minutes)

Set up interception and exercise the app's main flow.

```bash
# host — before anything else
adb shell "mount | grep cacerts"
```

Work down the layers in §4.5 of [`../README.md`](../README.md) and **stop at the first one that
explains what you are seeing.** If traffic appears, you are done with this phase; do not spend
fifteen minutes bypassing a pinning implementation you have not confirmed exists.

**Checkpoint F.** Either you have traffic, or you have a specific named reason you do not.
"It didn't work" is not a checkpoint answer.

### Phase G — Code (target: 10 minutes, and it will not be enough)

```bash
# host
jadx -d out app.apk
```

Ten minutes buys you: the package structure, the names of the classes handling the two or three
things you found in Phases B–F, and nothing else. **That is the correct use of ten minutes.** Do not
start reading `MainActivity` top to bottom.

Target your searches at what you already found:

```bash
# host — targeted, not exploratory
grep -rn "<the exported class from Phase B>" out/sources/ | head
grep -rn "<the preference key from Phase E>" out/sources/ | head
grep -rn "<the hostname from Phase F>" out/sources/ | head
```

**Checkpoint G.** For each of your Phase B–F observations, do you now have a class name and a line?

---

## 5. Stop the clock

Do not finish the phase you are in. Stop.

Fill in the two summary lines honestly:

```
STOPPED BY  : (every point where a sheet did not carry you, and what you did)
NOT COVERED : (every phase you did not reach, named)
```

---

## 6. Review — 30 minutes, and this is the actual lab

### 6.1 Classify every `STOPPED BY` entry

Put each one in exactly one bucket. The buckets matter more than the entries.

| Bucket | Meaning | What to do about it |
|---|---|---|
| **Missing tool** | The sheet assumed something you had not installed | Install it, or find the sheet's alternative. Cheap to fix, once |
| **Missing privilege** | The command needed root, `dbg` or `sig` and you had none | The `Needs` column exists for this. Did you read it before running? |
| **Wrong device class** | An emulator could not answer, or an OEM build refused | Record which; the answer may not exist on your hardware |
| **Sheet omission** | The step genuinely was not on any sheet | **The most valuable bucket.** See 6.3 |
| **Comprehension gap** | The command worked and you could not interpret the output | Read the chapter. This is the sheet working correctly at its limit |

Count them. A typical first run produces two or three in each of the first two buckets and one or
two in the last.

### 6.2 The uncomfortable question

For every finding you wrote down, answer:

- Which **vantage** produced it — `adb shell`, root, or an app uid?
- Could you reproduce it from an app uid?

If you used `adb shell` for a reachability claim, you have not yet demonstrated it. `adb shell` runs
as uid 2000 with privileges an app does not have — `com.android.shell` requests 200 permissions, 183
granted at install and 16 runtime permissions pre-granted `SYSTEM_FIXED`. Use
[`../scripts/vantage.sh`](../scripts/vantage.sh) on each one:

```bash
# host — from 76-CheatSheets/
bash scripts/vantage.sh --file <the path your finding depends on> --pkg <pkg>
```

Findings that survive this are findings. Findings that do not are shell measurements, and saying so
is the difference between a report a client acts on and one they return.

### 6.3 Write the row you needed and did not have

Take your best **sheet omission** and write the row. Use the four-property checklist in
[`../examples/01-anatomy-of-a-sheet-row.md`](../examples/01-anatomy-of-a-sheet-row.md):

```
| <command> | <Needs> | <Device> | <what it does, and what failure looks like> |
```

Then run it. If you did not run it, mark it `unrun` — and notice how differently you feel about a row
you have not executed once you have to label it.

### 6.4 Check your own row against the linter

```bash
# host — from 76-CheatSheets/, pointed at your notes file
python3 -B scripts/lint-commands.py --path /path/to/your-notes.md --no-fail
```

Eight rules, every one a form this repository has measured to be broken. If your notes trip one, you
have just reproduced the defect this chapter exists to prevent, in your own writing, within an hour
of reading about it. That happens to most people.

---

## 7. Success criteria

You have completed this lab when you can produce all six:

- [ ] A timing log with an entry every five minutes.
- [ ] A component table from Phase B, with the `exported` column resolved or explicitly marked
      version-dependent.
- [ ] At least one observation from Phases C–F with a class name attached from Phase G.
- [ ] Every `STOPPED BY` entry classified into exactly one of the five buckets.
- [ ] Every finding annotated with the vantage that produced it, and at least one re-checked with
      `vantage.sh`.
- [ ] One new sheet row, written to the four-property standard, and either run or labelled `unrun`.

---

## 8. Hints

<details>
<summary>I ran out of time in Phase B.</summary>

That is the correct experience the first time, and it is why the phase order is what it is. The
manifest is where the findings are, so overrunning there is not a failure — overrunning in Phase G
is. Next run, cap Phase B at ten minutes by writing the component table *as you read*, rather than
reading everything and then tabulating.
</details>

<details>
<summary>`run-as` says "package not debuggable" and I need the app's data.</summary>

Then you need root, or a different target. This is a **missing privilege** stop, not a sheet
omission. Note it and move on; do not spend fifteen minutes on it.

If you do have root, the equivalent is `adb shell "su 0 ls -la /data/data/<pkg>"` — and check the
`su` form first, because on an AOSP `userdebug` build or an emulator, `su -c` fails in the shape of
"not rooted".
</details>

<details>
<summary>The network security config is unreadable binary.</summary>

`unzip -p` gives you the compiled AXML. You need a decoder. `apktool d` produces readable XML for
every resource, and `aapt2 dump xmltree app.apk --file res/xml/network_security_config.xml` does it
for one file without unpacking the whole APK. The second is much faster and is the one the sheets
prefer.
</details>

<details>
<summary>No traffic appears in my proxy at all.</summary>

Work the layers in order and do not skip layer 0. **Is the app making requests?** An app sitting on a
login screen it cannot reach makes no requests, and a void run looks exactly like a well-behaved app
doing nothing wrong.

Check the proxy log for a TLS handshake. A handshake that starts and fails tells you the app reached
you and rejected your certificate — that is layer 2 or 3. No handshake at all means the app is not
reaching you, which is layer 1 or a `cleartextTrafficPermitted` refusal, and no amount of pinning
bypass will help.
</details>

<details>
<summary>Everything worked and I have six findings.</summary>

Then §6.2 is your lab. Take each of the six and ask which vantage produced it. Historically, sweeps
in this repository have gone 16,836 raw hits → 168 leads → 2 survivors, and 132 hits → **132 false
positives**. Six unadjudicated observations in an hour is normal; six *findings* in an hour would be
unusual.

Adjudicate the strongest one properly: who is the attacker, what do they start with, does the server
compensate, and does it reproduce from an app uid?
</details>

<details>
<summary>I do not know what to write for "NOT COVERED".</summary>

Read your phase list and name the ones you did not reach. Then add the things no phase covers at all:
deep links, `PendingIntent` mutability, WebView configuration, biometric implementation, KeyStore key
properties, native libraries. A sixty-minute triage covers perhaps a fifth of a real engagement, and
saying which fifth is the professional part.
</details>

---

## 9. Variations

| Variation | What it teaches |
|---|---|
| Run it again in 30 minutes | Forces you to choose. Most people cut Phase G entirely and produce a *better* report |
| Run it on an unrooted device | Section 4.2 of the README becomes the whole lab |
| Run it on an emulator only | Three questions become unanswerable; find out which before you rely on one |
| Swap targets with someone and compare timing logs | The `STOPPED BY` buckets differ enormously by target, and that is itself information |
| Run it with the sheets **and** the chapters | Measure how much slower and how much better. Both numbers are useful |

---

## 10. What this lab is really measuring

Not your triage speed. **Your calibration** — whether you can tell the difference between "the sheet
did not have it", "I did not have the privilege", and "I did not understand the output".

Those three feel identical in the moment. They have completely different remedies, and mistaking the
third for the first is how people conclude that reference material is useless when the actual gap is
in them. A cheat sheet cannot close a comprehension gap; it was never trying to.

---

## See also

- [`lab-02-the-sheet-lies.md`](lab-02-the-sheet-lies.md) — where the sheet was there and wrong
- [`lab-03-build-your-own-sheet.md`](lab-03-build-your-own-sheet.md) — turning this hour into a
  reusable artefact
- [`../README.md`](../README.md) §4.1 — the triage order
- [`../examples/03-session-preflight.sh`](../examples/03-session-preflight.sh) — the setup step
- [`../../80-Appendix/README.md`](../../80-Appendix/README.md) §7 — the full engagement checklist,
  for scale
