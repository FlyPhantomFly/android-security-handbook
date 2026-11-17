# Lab 01 — Build the base rate

> **Objective.** Turn a pile of manifests into a *defensible statistic*: run a corpus sweep, build
> the adjudication funnel yourself, and then write the one paragraph that most published mobile
> statistics are missing — the paragraph that says what your denominator cannot support.

**Difficulty:** beginner to intermediate.
**Time:** 60–90 minutes. Longer if you have a device and use it, which you should.
**Prerequisites:** [Chapter 72 §3.5](../README.md#35-a-corpus-measurement-of-the-largest-finding-class).
`python3`. A device is optional — Part A builds its own corpus if you have none.
**You will produce:** a funnel table, a base-rate table, and a written scope statement.

---

## 0. Why this lab exists

You have almost certainly read a sentence like this:

> "60% of Android apps expose components insecurely."

Ask three questions of it and it evaporates. Sixty per cent of *which* apps? What did "insecurely"
mean, mechanically? And who adjudicated — or did a scanner's raw output become the number?

This lab is about producing the version of that sentence you would be willing to defend in front of
the developer of one of the apps in it. That turns out to require three things, and only the first
is technical:

1. A sweep that prints its denominator next to every numerator.
2. A funnel, so a reader can see *where* the collapse happened and disagree with a specific step.
3. A scope statement that says, in plain words, what the corpus cannot support.

The third is the one people skip, and it is the one that makes the difference between a measurement
and a rumour.

> **The standard to beat.** [64-Xposed](../../64-Xposed/README.md) swept 237 APKs, found 1,141
> occurrences of a substring, and **explained every single one** — 1,141 accounted for, zero
> unexplained. The arithmetic closing exactly is what made it a measurement. Then it stated plainly
> that a zero result over four third-party packages supports nothing about banking apps. Copy both
> halves.

---

## 1. Setup

### 1.1 Check what you actually have

Do this first, every time, and write down what you see. Chapter 72's own measurements are labelled
with the device that produced them because the repository has been burned by version-gated claims
attributed to the wrong hardware.

```bash
# host
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
```

Record the output. If `adb devices -l` prints only the header line, you have no device — go to
Part A's offline path.

> **Warning — identify the device before trusting any version-gated claim.**
> This repository has had a phone silently swapped for a different phone mid-session, and has had
> `frida -U` select an emulator while the phone holding the corpus was attached. A wrong-device
> attach is the worst class of error, because every subsequent measurement is internally consistent
> and about the wrong target.

### 1.2 If you have a rooted emulator, know its quirks

The reference corpus for chapter 72 came from an AVD, and emulators differ from phones in ways that
have cost this repository real time:

| Quirk | What happens |
|---|---|
| `su` takes `su 0 <cmd>`, **not** `su -c <cmd>` | `su -c id` returns `su: invalid uid/gid '-c'`, which reads as "not rooted" |
| 16 KiB pages on some images | Naively-linked native binaries exit **139** (SIGSEGV); the fix is `-Wl,-z,max-page-size=16384` |
| No bootloader | `adb reboot bootloader` returns 0 and boots back into Android |

None of these affect this lab, which is pure manifest work — but write the device down anyway.

> **And never write `adb shell su -c '…'`.** <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- the broken form, quoted as the counter-example this warning teaches; covers the next line too -->
> The outer shell strips the quotes and `su` eats the flag, so `adb shell su -c 'magisk -v'` arrives
> as `su -c magisk -v` and `-v` is consumed by `su` — printing *su's* version while you believe you
> are reading Magisk's. Write `adb shell "su -c 'cmd'"`, or `su 0 cmd` on an emulator.

### 1.3 Locate the tooling

```bash
# host -- from the chapter directory
ls scripts/manifest-corpus-sweep.py
ls ../10-APK-Internals/examples/parse_axml.py     # the sweep imports this
python3 -B scripts/manifest-corpus-sweep.py --help
```

If the parser is missing, pass `--parser /path/to/parse_axml.py`.

---

## Part A — Acquire a corpus

Pick **one** path. The device path is much better if you have a device, because a synthetic corpus
cannot surprise you and a real one will.

### A1. From a device (preferred)

```bash
# host -- streams each manifest out over adb; writes NOTHING to the device
python3 -B scripts/manifest-corpus-sweep.py --from-device --out ./lab01-out
```

Watch the first two lines. On the reference device they read:

```
[*] 243 packages listed by the device
[*] extracted 243 manifests, 0 unreadable
```

**Record both numbers.** The gap between them is your first honest caveat: an APK the tool could not
read is not an app with nothing in it.

> **Pentester's Note — why `adb exec-out` and not a shell loop.**
> `adb` inherits stdin. Inside a `while read` loop it eats the loop's own input, and
> [64-Xposed](../../64-Xposed/README.md) measured the result: a thirteen-row probe printed **one
> row** and exited cleanly, reading exactly like a device with nothing on it. If you write your own
> extractor in bash, put `< /dev/null` on every `adb` invocation. The Python path avoids it by not
> using a shell loop at all.

### A2. From APKs you already have

```bash
# host
python3 -B scripts/manifest-corpus-sweep.py --apk-dir ~/corpus --out ./lab01-out
```

> **Sweeping `base.apk` measures `base.apk`.**
> Modern applications ship code in split APKs. [38-TamperDetection](../../38-TamperDetection/README.md)
> met an app showing **zero** controls in `base.apk` because its code was entirely in splits. If
> your corpus is `base.apk` files, your scope statement must say so.

### A3. No device — build a synthetic corpus

Save this as `build-corpus.sh` **outside the repository** and run it. It emits text manifests plus a
tiny builder that turns them into the binary XML the sweep expects.

```bash
#!/usr/bin/env bash
# build-corpus.sh -- create a small synthetic manifest corpus for lab 01.
# Run:  bash build-corpus.sh        (creates ./lab01-corpus)
# NOTE: no `set -o pipefail` here. It turns early-exit consumers like `head`
# and `grep -q` into spurious failures via SIGPIPE, which has cost this
# repository an hour of debugging at least twice.
set -eu
rm -rf lab01-corpus
mkdir -p lab01-corpus/src

emit() {  # emit <name> <targetSdk> <body>
    cat > "lab01-corpus/src/$1.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.lab01.$1">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="$2" />
$3
</manifest>
XML
}

# 1. clean app: nothing exported, safe defaults
emit clean 34 '  <application android:allowBackup="false">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <service android:name=".SyncService" android:exported="false"/>
  </application>'

# 2. the real lead: exported provider, no guard, no intent-filter
emit leaky 34 '  <application>
    <provider android:name=".DataProvider"
              android:authorities="com.lab01.leaky.provider"
              android:exported="true"/>
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter><action android:name="android.intent.action.MAIN"/></intent-filter>
    </activity>
  </application>'

# 3. exported but signature-guarded -- leaves at funnel step 2
emit guarded 34 '  <permission android:name="com.lab01.guarded.INTERNAL"
              android:protectionLevel="signature"/>
  <application>
    <service android:name=".AdminService" android:exported="true"
             android:permission="com.lab01.guarded.INTERNAL"/>
  </application>'

# 4. absent-attribute trap: no usesCleartextTraffic, targetSdk 28+ => default false
emit defaults 30 '  <application>
    <activity android:name=".MainActivity" android:exported="false"/>
  </application>'

# 5. legacy target: the ONLY place implicit export can still occur
emit legacy 25 '  <application>
    <receiver android:name=".BootReceiver">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
      </intent-filter>
    </receiver>
  </application>'

# 6. explicitly bad hygiene
emit sloppy 34 '  <application android:debuggable="true"
                   android:allowBackup="true"
                   android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true"/>
  </application>'

cat > lab01-corpus/build.py <<'PY'
#!/usr/bin/env python3
"""Turn the text manifests into APKs the sweep can read.
Requires aapt2 from the Android SDK build-tools on PATH."""
import glob, os, shutil, subprocess, sys, zipfile
os.makedirs("apks", exist_ok=True)
aapt2 = shutil.which("aapt2")
if not aapt2:
    sys.exit("aapt2 not on PATH -- add $ANDROID_HOME/build-tools/<ver> to PATH")
for src in sorted(glob.glob("src/*.xml")):
    name = os.path.splitext(os.path.basename(src))[0]
    out = os.path.join("apks", name + ".apk")
    # aapt2 link needs an android.jar; point at any platform you have.
    jar = os.environ.get("ANDROID_JAR")
    if not jar:
        sys.exit("set ANDROID_JAR=$ANDROID_HOME/platforms/android-35/android.jar")
    subprocess.run([aapt2, "link", "-I", jar, "--manifest", src,
                    "-o", out, "--auto-add-overlay"], check=True)
    print("built", out)
PY
echo "wrote lab01-corpus/  ->  run: cd lab01-corpus && python3 -B build.py"
```

Then:

```bash
# host
bash build-corpus.sh
cd lab01-corpus
export ANDROID_JAR="$ANDROID_HOME/platforms/android-35/android.jar"
python3 -B build.py
cd ..
python3 -B scripts/manifest-corpus-sweep.py --apk-dir ./lab01-corpus/apks --out ./lab01-out
```

> **XML comments must not contain `--`.**
> `aapt2` rejects them, and the error names the file rather than the reason. This repository has hit
> it five times, including with `--es`, `--uri` and an em-dash typed as two hyphens.

---

## Part B — Read the funnel, and disagree with it

Run the sweep and look only at the funnel block:

```bash
# host
python3 -B scripts/manifest-corpus-sweep.py --manifest-dir ./lab01-out/manifests --funnel-only
```

The reference run over 243 platform packages produced:

```
  stage                                        components   apps
  1. declared exported                               2674    137
  2. ...and not strongly guarded                     1990    116
  3. ...and carrying no <intent-filter>               410     67
  4. ...and being a ContentProvider                    83     38
```

### B1. Reproduce the arithmetic by hand

Do not take the tool's word for it. Pick **any five** components the tool placed at stage 3 and
verify each one yourself against the manifest:

```bash
# host -- dump one manifest as text and read it
python3 -B ../10-APK-Internals/examples/parse_axml.py \
    --extract /path/to/app.apk --json | python3 -m json.tool | head -60
```

For each of the five, answer on paper:

- Is `android:exported` genuinely `true`?
- Is there genuinely no `<intent-filter>` child?
- Is there genuinely no `permission` / `readPermission` / `writePermission`?

**If any of the five is wrong, stop and find out why before continuing.** A funnel you have not
spot-checked is a funnel you are trusting, and this lab's entire subject is not doing that.

### B2. Find the definition hiding inside step 2

Step 2 says "not strongly guarded". That phrase contains a decision, and the decision is *yours*, not
the tool's. Open `scripts/manifest-corpus-sweep.py` and find `STRONG_GUARDS`.

Now answer:

1. Why is `dangerous` in that set? A dangerous permission can be granted to a third-party app by the
   user. Is excluding those components correct, or convenient?
2. A `<provider>` has three guards — `permission`, `readPermission`, `writePermission`. Which one
   should a **read** probe test against?

> **The second question is not rhetorical, and getting it wrong is what happened here.** The first
> version of this chapter's sweep folded `writePermission` into a single guard field. A provider
> with a *write* guard and *no read guard* — readable by anybody — was therefore scored as guarded
> and dropped at step 2. It cost six providers, and it excluded **the only authority in the corpus
> that returned rows**. The measured lesson, from [§3.5](../README.md#35-a-corpus-measurement-of-the-largest-finding-class):
> **a funnel step is a definition, and a definition you have not written down is one you cannot
> check.**

**Exercise.** Change `STRONG_GUARDS` to remove `dangerous` and re-run. Record the new stage-2 and
stage-3 counts. You have just moved your own headline number by changing one set literal — which is
exactly what a reader of your report cannot see unless you tell them.

### B3. Write down the definition

Produce a table like this for your own run. It is the artefact this part exists for:

| Stage | Mechanical rule, stated exactly | Components | Apps |
|---|---|---:|---:|
| 1 | `android:exported="true"`, or absent with an `<intent-filter>` on `targetSdk` < 31 | | |
| 2 | …and the read guard's base protection level is not one of {signature, signatureOrSystem, internal, dangerous} | | |
| 3 | …and the component declares no `<intent-filter>` child | | |
| 4 | …and the component is a `<provider>` | | |

---

## Part C — The absent-attribute trap

This part is short and it is the highest-value fifteen minutes in the lab.

Run the full sweep and find the application-level block:

```bash
# host
python3 -B scripts/manifest-corpus-sweep.py --manifest-dir ./lab01-out/manifests
```

The reference run reported:

```
  usesCleartextTraffic  true=27  false=20  ABSENT=196  (of 243)
      of the 196 absent, 195 target API 28+ where the default is
      ALREADY false. A 'cleartext not disabled' check fires 196 times
      and is wrong 195 of them --  99.5% false positive.
```

### C1. Prove the default to yourself

Do not take the 99.5% on trust either. The claim rests on a platform behaviour:
`usesCleartextTraffic` defaults to **`false`** when `targetSdkVersion` is 28 or above, and to
`true` below it.

Confirm it from the platform documentation, and then reason about the consequence:

- A scanner that reports "cleartext traffic is not disabled" whenever the attribute is absent is
  testing for the *absence of an attribute*, not for a misconfiguration.
- On a corpus that targets API 28+, that check is wrong essentially every time it fires.

### C2. Find the other members of the family

`allowBackup` is the same shape with a different default. From the reference run:

```
  allowBackup           true=29  false=38  ABSENT=176  (of 243)
      counting the default as a finding reports 205 of 243 apps.
```

**Exercise.** List every manifest attribute you can find where a naive checker would treat *absent*
as *insecure*. For each one, write down the platform default and the API level at which it changed.
You should end with at least five. This list is worth more than the lab.

### C3. The rule

> **The absent-attribute finding.**
> A finding of the form "the app does not set X" is valid **only** if you have first established what
> the platform does when X is absent, **at the target's `targetSdkVersion`**. If the default is
> already safe, the correct output is nothing at all — not a Low, not an Informational.

---

## Part D — Find the class that has gone extinct

```bash
# host
python3 -B scripts/manifest-corpus-sweep.py --manifest-dir ./lab01-out/manifests | tail -12
```

Reference output:

```
  components with android:exported ABSENT        313  of 6465
    ...of those, carrying an <intent-filter>     0
  apps targeting API 31+                         237  of 243
```

**Zero.** Implicit export — the defining Android finding class of the 2010s — does not occur once in
6,465 components, because Android 12 made it a build error to declare an `<intent-filter>` without
an explicit `android:exported` on `targetSdk` 31+.

### D1. Verify the mechanism, not just the number

If you built the synthetic corpus in A3, you have a `legacy` app targeting API 25 with a receiver
that declares an intent-filter and no `android:exported`. Confirm the sweep counts it in the
`carrying an <intent-filter>` row while the modern apps do not. **A zero you cannot make non-zero on
demand is a zero you do not understand.**

### D2. The consequence for your methodology

**Exercise.** Go through your own Android checklist — whatever you actually use — and mark every
item that:

- has been closed by a platform default change,
- is only reachable below some `minSdkVersion` you no longer meet, or
- has a true-positive rate you have never measured.

Then delete them, or move them to a "historical" section with the API level that closed them.

> **Mental Model — finding classes have lifecycles, checklists do not.**
> A checklist item is written once and copied forever, while the platform keeps closing classes by
> changing defaults. Time spent on a closed class is taken from the client's budget.

---

## Part E — The scope statement

This is the deliverable.

Write one paragraph, no more than 120 words, that states what your corpus **can** and **cannot**
support. Here is the reference one for chapter 72's corpus, which you should treat as the standard
rather than the ceiling:

> These figures were measured on 243 packages — every application installed on a stock Android 15
> emulator image (API 35), extracted 2026-08-16. **Four of the 243 are third-party.** The corpus is
> therefore a *platform* corpus: it supports statements about how Android and Google's bundled
> applications are built, and supports nothing about banking, retail, or any category a commercial
> assessment targets. Manifests were read from `base.apk` only, so code and components shipped in
> split APKs are absent. The reachability figures in §7.3 were taken from `adb shell` (uid 2000),
> which is not an application vantage. Counts are a snapshot of one device on one date.

### E1. Grade your own

| # | Does your paragraph state… | Done |
|---|---|---|
| 1 | The exact N, and what one unit is (an app? an APK? a component?) | |
| 2 | The composition of the corpus, especially any skew | |
| 3 | The date, and the device or source | |
| 4 | The artefact analysed — `base.apk`? every split? a running app? | |
| 5 | The vantage of any runtime measurement | |
| 6 | At least one explicit "this supports nothing about X" | |
| 7 | Nothing that is not true | |

If you cannot tick 6, you have written a caveat rather than a scope statement. The difference is
that a caveat protects you and a scope statement informs the reader.

---

## Success criteria

You have completed this lab when:

1. You have a funnel table with your own numbers, and you spot-checked **five** stage-3 components
   by hand against the manifest.
2. You can state the mechanical rule for each funnel stage in one sentence, without reading the code.
3. You changed `STRONG_GUARDS` and can say how much your headline number moved.
4. You can explain why a `writePermission` must not satisfy a read probe.
5. You produced a list of at least five absent-attribute traps with their defaults and API levels.
6. You verified the implicit-export zero by making it non-zero with a legacy-target manifest.
7. You wrote a scope statement that ticks all seven boxes above.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `could not find parse_axml.py` | Running from outside the chapter directory | Pass `--parser /path/to/parse_axml.py` |
| `adb shell pm list packages -f` returns nothing | No device, or unauthorised | `adb devices -l`; accept the RSA prompt on the device |
| Many "unreadable" manifests | Some APKs are not readable as ZIPs at that path | Note the number and put it in the scope statement — do not hide it |
| `no device cross-check available` | No device attached | Expected offline. Guard levels then come from one reading, not two — say so |
| `aapt2: failed to load XML file` on a file that exists | On Git Bash, SDK tools need Windows paths | Run paths through `cygpath -w` |
| `aapt2` rejects a manifest you just wrote | An XML comment contains `--` | Remove it |
| Counts differ between two runs on the same device | Packages were installed or updated between runs | Timestamp every count; they are a snapshot, not a constant |

---

## What comes next

[Lab 02 — The severity clinic](lab-02-the-severity-clinic.md) takes the leads this lab produced and
makes you rate them, which is the part no tool can do for you.

Related reading:

- [Chapter 72 §3.5](../README.md#35-a-corpus-measurement-of-the-largest-finding-class) — the
  reference measurement.
- [52-StaticAnalysis](../../52-StaticAnalysis/README.md) — the sweep methodology this lab's
  statistics discipline is built on.
- [`../examples/corpus-sweep-output.txt`](../examples/corpus-sweep-output.txt) — the raw output to
  compare yours against.
