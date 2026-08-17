# Lab 01 — Your first complete static pass

> **Objective.** Take a real APK off a real device and run all eight stages of the pipeline, ending
> with **one written finding that you have validated** and a **ledger of the leads you rejected**,
> with a reason against each.

**Difficulty:** beginner, but not short. Budget two to three hours the first time.
**Prerequisites:** [README §3](../README.md#3-deep-internal-working) read once. A device or emulator
with `adb` working. `jadx`, `unzip`, `python3`. `apktool` and `aapt2` if you have them; the lab tells
you what you lose without each.

---

## 0. What you will produce

Four artefacts. If you finish with fewer, you have not done the lab.

| Artefact | File |
|---|---|
| An evidence directory with the artefact hash and split list | `evidence/hashes.txt` |
| The raw sweeper output | `evidence/sweep.txt` |
| A ledger with a verdict and a reason for **every** lead | `evidence/ledger.csv` |
| One written finding, in the form a client would receive | `evidence/finding-01.md` |

The last two are the lab. The first two are the warm-up.

---

## 1. Choose a target

**Preferred:** `com.mobilehackinglab.FridaThree` — a public, deliberately vulnerable training
application. If you have it installed, use it, because every number in this lab was measured against
it and you can check your work.

**Alternatives, in order of preference:**

1. Any deliberately vulnerable training app you have permission to use (InsecureBankv2,
   DIVA, OWASP MASTG's UnCrackable series, another MobileHackingLab target).
2. An app **you** wrote and installed.
3. An open-source app from F-Droid, downloaded from F-Droid.

**Do not** use a random commercial app off your personal phone for a lab you are going to write up
and share. Analysing it privately for learning is one thing; publishing hostnames and tokens from
someone's product is another. If you must use one, anonymise as
[`examples/README.md`](../examples/README.md) does and say so.

> **⚠️ Warning**
> Everything in this lab is read-only with respect to the device: `pm path`, `pull`, `dumpsys`,
> `run-as`. Nothing installs, broadcasts, or modifies state. If a step in your own variation would
> change the device, stop and think about whether the device is yours to change.

---

## 2. Stage 1 — Acquire

```bash
# host
mkdir -p lab01/evidence && cd lab01
PKG=com.mobilehackinglab.FridaThree

adb shell pm path "$PKG"
```

**Write down every line it prints.** One line means no splits; several mean the app is an App Bundle
and its code is spread across them.

```bash
# host — pull each path it printed
adb pull /data/app/~~.../base.apk base.apk

sha256sum *.apk | tee evidence/hashes.txt
ls -l *.apk >> evidence/hashes.txt
```

Then establish who signed it:

```bash
# host
apksigner verify -v --print-certs base.apk | tee evidence/signer.txt
```

**Checkpoint 1.** You can answer, without looking anything up:

- How many APK files make up this application?
- What is the SHA-256 of each?
- Which signature schemes are present?
- Is the signer the Android debug key? (`CN=Android Debug, O=Android, C=US`)

> **Hint — no `apksigner`?** It ships with the Android SDK build-tools. Failing that,
> `unzip -l base.apk | grep META-INF` tells you whether a v1 (JAR) signature is present, and the
> presence of an `APK Signing Block` before the central directory tells you v2/v3 — but you lose the
> signer identity, which is the interesting part. Note the gap in your notes rather than skipping it
> silently.

---

## 3. Stage 2 — Unpack, and decide

Do **not** decompile yet. Two minutes here decides whether the next hour is worth spending.

```bash
# host
unzip -l base.apk | head -40
unzip -l base.apk | grep -cE '\.dex$'
unzip -l base.apk | grep -E 'lib/[^/]+/' | awk -F/ '{print $2}' | sort -u
unzip -l base.apk | grep -E 'assets/' | sort -k1 -rn | head -20
unzip -l base.apk | grep -cE 'META-INF/.*\.version$'
```

On the reference target you should see **three** `classes*.dex`, **no** `lib/` entries, and **no**
`assets/`. Sizes: `classes.dex` about 9.9 MB, `classes2.dex` about 513 KB, and `classes3.dex`
**4,180 bytes**.

**That 4 KB third DEX is the most informative number in the whole lab.** An application's own code is
usually the *last* DEX, because the build packs framework and library classes first. Four kilobytes
means this app's own code is three classes. Everything else in the APK is AndroidX and Kotlin.

**Checkpoint 2.** Answer in your notes:

- How many DEX files, and how big is each?
- Which ABIs does it ship native code for? (Here: none.)
- Is there anything executable-looking in `assets/`? (Here: no.)
- Is this a cross-platform framework app? Look for `index.android.bundle` (React Native),
  `flutter_assets/` (Flutter), `assets/bin/Data/` or `libil2cpp.so` (Unity).

> **Hint.** If your target *is* a framework app, stop and pick another one for this lab. Analysing a
> Flutter app is a valuable skill and it is not this pipeline; the DEX sweep will be complete and
> irrelevant.

---

## 4. Stage 3 — Decompile

Start the slow one first and do stage 4 while it runs.

```bash
# host
jadx -d out base.apk 2>&1 | tail -5 &
apktool d -f base.apk -o work
aapt2 dump xmltree --file AndroidManifest.xml base.apk > evidence/manifest-aapt2.txt
```

**Read jadx's last line when it finishes.** On the reference target it says
`finished with errors, count: 17`. Write that number down; it belongs in your report's methodology
section, because it is the number of classes whose decompiled Java you must not trust.

> **Hint — jadx "succeeds" instantly and produces nothing?**
> On Windows the `jadx` on your `PATH` may be the GUI launcher, which detaches and exits 0. Run the
> CLI class out of the shipped jar:
>
> ```bash
> java -Xmx6g -cp "/c/Program Files/jadx/lib/jadx-gui-1.5.3-all.jar" \
>      jadx.cli.JadxCLI -d out base.apk
> ```

> **Hint — no `apktool`?** You lose decoded `res/xml/`, which is where the network security config,
> FileProvider paths and backup rules live. jadx's `resources/` directory covers much of it. Note
> what you lost.

---

## 5. Stage 4 — Enumerate

### 5.1 Entry points

```bash
# host
awk '/<(intent-filter|meta-data|action|category)[ \t>\/]/{t=0}
     /<(activity|activity-alias|service|receiver|provider|application)([ \t>\/]|$)/{t=1}
     t && match($0,/android:name="[^"]+"/){print substr($0,RSTART+14,RLENGTH-15);t=0}' \
    work/AndroidManifest.xml | sort -u | tee evidence/entrypoints.txt
```

On the reference target this prints three names. Compare with the naive version:

```bash
# host — the WRONG way, so that you see why
grep -oE 'android:name="[^"]+"' work/AndroidManifest.xml | sort -u | wc -l
```

The naive version returns many more, because `<action>`, `<category>` and `<meta-data>` all carry
`android:name` too. `android.intent.action.MAIN` is not a class.

> **Hint.** If your awk prints nothing, you probably wrote `\b` in the pattern. POSIX awk has no
> word-boundary escape and gawk reads `\b` as a backspace character, so the pattern matches nothing
> and fails silently. This exact bug ate the entry-point list while this chapter's tooling was being
> written.

### 5.2 Which code is the app's own?

```bash
# host
grep -m1 -oE 'package="[A-Za-z0-9_.]+"' work/AndroidManifest.xml
# package="com.mobilehackinglab.FridaThree"

find out/sources -name '*.java' | wc -l
find out/sources/com/mobilehackinglab -type f | sed 's#^#  #'
```

**Checkpoint 3.** How many `.java` files are in the tree, and how many are the application's own?
On the reference target: **2,803 total, 3 of them the app's.**

Now do the experiment that makes the point:

```bash
# host
grep -rlEi 'password' --include='*.java' out/ | sed 's#^out/sources/##' \
    | awk -F/ '{print $1"/"$2"/"$3}' | sort | uniq -c | sort -rn
```

Count the hits and count how many are in the application's own package. Reference answer: **137 hits,
one of them in the app's package, and that one is `R.java`** — a resource identifier, not a password.

---

## 6. Stages 5 and 6 — Sweep and triage

```bash
# host
python3 -B ../scripts/static-sweep.py ./out --show-suppressed | tee evidence/sweep.txt
python3 -B ../scripts/static-sweep.py ./out --csv evidence/ledger.csv
```

Read the header block before the queue. On the reference target:

```
files scanned      3655
    app            3
    third-party    2759
    generated      42
    resource       850
raw hits           7346
killed by a rule's own validator  3591
distinct leads     9
Aggregation ratio: 7346 raw hits collapsed to 9 leads (816.2x).
```

**Checkpoint 4.** Explain, in one sentence each:

- Why 7,346 hits became 9 leads.
- What the 3,591 "killed by a validator" hits were. (`--print-catalogue` and the script's
  `v_base64ish` and `v_hostname` functions are the answer.)
- Why `--show-suppressed` exists at all rather than the tool simply deleting noise.

### Run the catalogue by hand, once

Do this once in your life and you will never again be unable to defend a tool's output:

```bash
# host
python3 -B ../scripts/static-sweep.py --print-catalogue | less
cd out
grep -rn -- '-----BEGIN' .            | wc -l
grep -rnE 'AIza[0-9A-Za-z_-]{35}' .   | wc -l
grep -rnoE 'http://[^"]+' . | sort -u | wc -l
cd ..
```

Compare your counts with the tool's. Where they differ, work out which is right — usually the tool,
because it deduplicates, but not always.

---

## 7. Stage 7 — Validate. This is the lab.

Open `evidence/ledger.csv`. It has a row per lead and two empty columns: `verdict` and `reason`.
**You are going to fill in every row, including the ones you are sure about.**

For each lead, in the order the tool ranked them:

```bash
# host
bash ../scripts/validate-lead.sh --tree ./out --value '<the value>' \
     --package "$PKG" --out evidence/L00N
```

Add `--reach` when reachability actually matters to your answer. Read the six sections it prints, and
then answer the four questions in the ledger's `reason` column.

### The four questions

| # | Question | Where the answer comes from |
|---|---|---|
| 1 | Is the construct really there? | Section 02 of the validator; Smali if the semantics matter |
| 2 | Is it reachable? | Section 03; or a runtime hook |
| 3 | Who can reach it? | Section 04 — exported? permission? |
| 4 | What does reaching it get them? | Your head, and sometimes the client |

### Work at least these three properly

**(a) The debuggable flag.** It should be your top lead.

```bash
# adb shell
dumpsys package com.mobilehackinglab.FridaThree | grep 'flags='
```

You are looking for `DEBUGGABLE` in that list. That is the platform agreeing with the file, and it is
the difference between "the manifest claims" and "the system enforces".

Then demonstrate the consequence:

```bash
# host
adb shell run-as com.mobilehackinglab.FridaThree ls -la /data/data/com.mobilehackinglab.FridaThree
```

**(b) The base64 literal.** Follow the next step the tool printed, which is "decode it":

```bash
# host
echo '<the base64 value>' | base64 -d
```

Now the important part. **It decodes to a string the app displays on screen.** Write the verdict that
follows from question four, not the verdict that follows from question one. If you wrote "hardcoded
secret", go back and read [README §9.2](../README.md#92-intermediate--a-base64-constant-and-honest-severity).

**(c) One lead you are certain is noise.** Pick `http://schemas.android.com/apk/res/android` and
write out the rejection anyway, with its reason. Time yourself: it takes under a minute, and it is
the row that shows a reviewer you worked the whole queue.

### Confirm one thing in bytecode

Decompiled Java is a reconstruction. Confirm your best lead against the bytecode at least once:

```bash
# host
mkdir -p dex && cd dex && unzip -o -q ../base.apk 'classes*.dex'
dexdump -d classes3.dex | grep -n 'const-string' | head -20
cd ..
```

Find the `const-string` that loads your value. Note its `string@NN` index and compare it with the
index that `dump-strings.py` gives you:

```bash
# host
python3 -B ../../04-Java/scripts/dump-strings.py base.apk --min-len 16 | grep -i '<part of your value>'
```

They are the same number, one in decimal and one in hexadecimal. That correspondence is how you
correlate strings to code at scale on a large or obfuscated app.

**Checkpoint 5.** Your ledger has a verdict and a reason on **every** row. Count them:

```bash
# host
awk -F, 'NR>1 {print $(NF-1)}' evidence/ledger.csv | sort | uniq -c
```

---

## 8. Stage 0 — Record the blind spots

The sweeper's last section lists which blind-spot markers fired. Verify two of them independently
rather than trusting the tool:

```bash
# host
grep -rl 'registerReceiver' out/sources/ | wc -l
grep -rl 'registerReceiver' out/sources/com/mobilehackinglab/ | wc -l
grep -rl 'DexClassLoader'   out/sources/ | wc -l
grep -rl 'loadLibrary'      out/sources/ | wc -l
```

On the reference target: receivers are registered at runtime in **three library files and none of the
app's own**; there is no dynamic DEX loading and no native code at all.

**Now write the limits paragraph.** Not later, now, while the numbers are in front of you:

> Static analysis of this artefact cannot observe broadcast receivers registered at runtime, native
> methods bound with `RegisterNatives`, reflective dispatch targets, code loaded after installation,
> or server-side behaviour. For this application, runtime receiver registration and reflection occur
> only in bundled framework libraries and not in the application's own code; there is no native code
> and no evidence of runtime DEX loading. On a comparable device, 69% of the broadcast actions in use
> by third-party applications had no manifest-declared receiver at all, so this limit is normally
> severe and is unusually narrow here.

---

## 9. Stage 8 — Write the finding

`evidence/finding-01.md`. Use this shape — it is the one [80-Appendix](../../80-Appendix/README.md)
expands on:

```markdown
# F-01 — <one line, stating the fact and not the fear>

**Severity:** <from the grid in cheatsheet.md, with the precondition named>
**Artefact:** base.apk, SHA-256 <hash>, pulled from <device> on <date>
**Location:** <file>:<line>

## What we found
<Two sentences. The construct, and where.>

## Evidence
<The commands, and their output. Include the platform's confirmation.>

## Impact
<What an attacker gets. Name the precondition. Demonstrate rather than assert.>

## Reproduction
<Numbered steps someone else can follow with only the artefact and a device.>

## Fix
<As code. Not "sanitise input" -- the actual configuration or the actual patch.>

## Validation notes
<Leads generated: N. Validated: M. Rejected: N-M, see ledger.
 Limits: the paragraph you wrote in section 8.>
```

---

## 10. Success criteria

You have completed this lab when **all** of these are true:

- [ ] `evidence/hashes.txt` contains a SHA-256 for every APK the app is made of.
- [ ] You can state how many DEX files there are and which one holds the app's own code.
- [ ] `evidence/entrypoints.txt` contains only component class names — no actions, no categories.
- [ ] You can say how many files in the tree are the app's own code, and what fraction that is.
- [ ] `evidence/sweep.txt` exists and you can explain the aggregation ratio in one sentence.
- [ ] `evidence/ledger.csv` has a **verdict and a reason on every row**, including the obvious ones.
- [ ] At least one lead was confirmed against **bytecode**, not just decompiled Java.
- [ ] At least one finding was confirmed against the **platform** (`dumpsys`), not just a file.
- [ ] At least one lead was correctly rejected with a reason a stranger could check.
- [ ] `evidence/finding-01.md` exists, names a precondition, and contains a fix as code.
- [ ] You wrote the limits paragraph, with this app's actual blind-spot usage in it.

---

## 11. Common ways this lab goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| jadx exits 0 in two seconds, `out/` is empty | The GUI launcher was on `PATH` | Run `jadx.cli.JadxCLI` from the jar |
| The entry-point awk prints nothing | `\b` in the pattern | awk has no word boundary; anchor on `[ \t>/]` |
| The sweeper reports everything as third-party | No manifest in the tree, so no package name | Pass `--app-package` |
| The sweeper takes six minutes | A large tree | `--files app` for the first pass |
| `validate-lead.sh` reports zero occurrences | The value was truncated when you copied it | Re-run the sweeper with `--verbose` and copy the line |
| Your ledger has three rows filled in | You only worked the leads you believed | Work the queue top-down; the rejections are the deliverable |
| Your finding says "hardcoded secret" | You answered question 1 and stopped | Question 4 is the severity |

---

## 12. Going further

- Run the pipeline against a **second** app and diff the two ledgers. The rules that fire on both are
  your noise floor.
- Re-run the sweep with `--min-confidence 0.5` and check what you would have missed. On the reference
  target the answer is "nothing"; on a large app it is usually "the best lead", because the best lead
  is often MEDIUM (see [README §9.4](../README.md#94-real-application--the-false-positive-arithmetic-measured)).
- Do [Lab 02](lab-02-false-positive-gauntlet.md) next. This lab taught you the pipeline; that one
  teaches you the part that makes the pipeline worth running.
