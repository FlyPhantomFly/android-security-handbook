# Lab 01 — Your first complete runtime pass

> **Objective.** Take a real application on a real device and run all eight stages of the pipeline
> **with no root and no `frida-server`**, ending with **one written finding you have validated** and a
> **coverage statement** that says what you did not look at.

**Difficulty:** beginner, but not short. Budget two to three hours the first time.
**Prerequisites:** [README §3](../README.md#3-deep-internal-working) read once. A device or emulator
with `adb` working. `aapt2` (from the Android SDK build-tools) if you have it; the lab tells you what
you lose without it.

---

## 0. What you will produce

Five artefacts. If you finish with fewer, the lab is not done.

| Artefact | Where it comes from |
|---|---|
| `evidence/device.txt` | Stage 1, the posture check |
| `evidence/control/DELTA.md` | Stage 2, a control run |
| `evidence/s01/DELTA.md` | Stages 4–5, a driven session |
| `evidence/s01/COVERAGE.md` | Stage 0 |
| `finding.md` | Stages 7–8, one validated finding — or a written statement that you found none, with the coverage figure attached |

> **⚠️ Warning — device etiquette**
> If this is your own daily driver, **observe only**. Every command below is read-only except the two
> marked **[MUTATES]**, and both are paired with a reversal. Do not instrument, modify or repackage a
> third-party application you were not authorised to touch. The chapter's own worked example was
> produced entirely by observation and still ended in a validated finding.

---

## 1. Choose a target

You need an application that is installed on your device and that you are allowed to test. In
descending order of preference:

1. **An app you wrote.** Best: you may do anything to it.
2. **A public, deliberately vulnerable training app** you installed for this purpose. Several exist;
   install one rather than reaching for something on your phone.
3. **A third-party app already on your device** — for **observation only**. This is what the chapter's
   own example used, and it worked, but the moment you want to hook or repackage, stop and go back to
   option 1.

```bash
# host — what is actually here
adb shell "pm list packages -3"
```

If that list is short, you are on a clean or vendor device and option 2 is the right choice.

**Checkpoint 0.** Write your target's package name down. Everything below uses `$PKG`.

```bash
# host
export PKG=com.example.target
mkdir -p evidence
```

---

## 2. Stage 1 — Prepare

### 2.1 The posture check

```bash
# host — forty seconds, and it gates every claim you will make today
adb devices -l                                        | tee    evidence/device.txt
adb shell "getprop ro.product.model"                  | tee -a evidence/device.txt
adb shell "getprop ro.product.manufacturer"           | tee -a evidence/device.txt
adb shell "getprop ro.build.version.release"          | tee -a evidence/device.txt
adb shell "getprop ro.build.version.sdk"              | tee -a evidence/device.txt
adb shell "getprop ro.build.version.security_patch"   | tee -a evidence/device.txt
adb shell "getprop ro.debuggable"                     | tee -a evidence/device.txt
adb shell "getenforce"                                | tee -a evidence/device.txt
adb shell "which su; su -c id"                        | tee -a evidence/device.txt
adb shell "ps -A -o NAME" | grep -i frida             | tee -a evidence/device.txt
adb shell "mount | grep cacerts"                      | tee -a evidence/device.txt
adb shell "dumpsys trust" | grep -o "deviceLocked=[01]" | tee -a evidence/device.txt
```

**Checkpoint 1.** You can answer, without looking anything up:

- What API level is this, and what is its security patch level? Are they consistent with each other?
- Is `su` present?
- Is `frida-server` running?
- **Has anything been mounted over `/system/etc/security/cacerts`?**

> **Hint — what the last one means.** If that command printed anything at all, your device's system CA
> store has been replaced or bind-mounted over. A successful TLS intercept on such a device proves
> nothing about whether an app trusts *user*-installed CAs, because your proxy CA is in the *system*
> store. This repository lost a day to exactly this. If you see a hit, you may still do this lab —
> just do not make any TLS claim at the end of it, and write that limitation into your report.

### 2.2 Record what you will need to revert

You are going to change nothing in this lab except two things, but recording is a habit worth building
now:

```bash
# host
adb shell "settings get global http_proxy"        > evidence/revert-proxy.txt
adb shell "dumpsys package $PKG | grep granted="  > evidence/revert-grants.txt
adb shell "ls /data/local/tmp"                    > evidence/revert-tmp.txt
```

---

## 3. Stage 1b — Identify the target from the platform

Not from the APK. From the platform's own record, which is authoritative about what it installed and
enforces.

```bash
# host
adb shell "pm path $PKG"
adb shell "dumpsys package $PKG" | grep -E \
  "versionName|versionCode|targetSdk|minSdk|^ *flags=|^ *privateFlags=|installerPackageName|userId=|codePath"
```

Then the two questions that decide how much of the rest of the lab is available to you:

```bash
# host — is anything on this device debuggable, and is it your target?
adb jdwp
adb shell "run-as $PKG id"
```

**Checkpoint 2.** Which of these three did `run-as` print?

| Output | Meaning | Consequence for this lab |
|---|---|---|
| `uid=10NNN(u0_aNNN) …` | Debuggable **and** an app uid | Channel 04 is open. Full lab |
| `run-as: package not debuggable: …` | `FLAG_DEBUGGABLE` is clear | Channel 04 is **closed**. Do the lab without it and record the gap |
| `run-as: package not an application: …` | It **is** debuggable, but it is a system app | Channel 04 is closed. Note this — it is a genuine device finding |

> **Hint — do not skip the "closed" cases.** A lab that only works on a debuggable app teaches you a
> lucky path. Section 9 of this lab is written for the closed case and it is the more common one.

---

## 4. Stage 1c — Build the coverage denominator

This is the step nobody does and it is what makes the coverage figure at the end honest.

```bash
# host — pull the artefact the platform is actually running
adb shell "pm path $PKG"          # note EVERY path; splits count
mkdir -p artefact
adb pull <each path printed> artefact/
sha256sum artefact/*.apk | tee evidence/hashes.txt
```

```bash
# host — the component inventory, from the platform's own parser
aapt2 dump xmltree --file AndroidManifest.xml artefact/base.apk > evidence/manifest.txt

awk '/E: (activity|activity-alias|service|receiver|provider) /{k=$2; next}
     /E: /{ if ($2 !~ /^(intent-filter|meta-data|action|category|data)$/) k=""; next }
     k != "" && /android:name\(0x01010003\)=/ {
        match($0,/="[^"]+"/); print substr($0,RSTART+2,RLENGTH-3)" kind="k; k="" }' \
    evidence/manifest.txt | sort -u > evidence/entrypoints.txt

cat evidence/entrypoints.txt
wc -l < evidence/entrypoints.txt
```

Now do it the *other* way and compare:

```bash
# host — the device's own view
adb shell "dumpsys package $PKG" | grep -oE "$PKG/[A-Za-z0-9_.\$]+" | sort -u
```

**Checkpoint 3.** Are the two lists the same length? They almost certainly are not.

> **Hint.** `dumpsys package`'s resolver tables index only components that carry an `<intent-filter>`,
> because those tables exist to answer "which component would win this Intent". An Activity started by
> explicit Intent from inside the app is real and is not in them. On the chapter's measured app: 4
> components in the manifest, 3 on the device. Write down both numbers — §8 asks you to use them.

> **Hint — no `aapt2`?** It ships in every Android SDK `build-tools` directory. Failing that,
> `apktool d` gives you a readable `AndroidManifest.xml` and the same `awk` idea applies to its XML.
> Failing *that*, use the device list and **mark your final coverage figure as an upper bound** — which
> is the honest thing to do and is a legitimate way to finish this lab.

---

## 5. Stage 2 — Baseline and a control run

```bash
# host
bash ../scripts/session-recorder.sh --package "$PKG" --out ./evidence/control --wait 45
cat evidence/control/DELTA.md
```

Read the whole report. Then answer:

**Checkpoint 4.**

- Which channels changed while you did **nothing**?
- What is the network floor on this device for a 45-second window — how many bytes on which
  interfaces?
- Which mode did the recorder use for channel 04, and does the report say why?

> **Hint.** On the chapter's test device the control run moved two interfaces — loopback by about
> 4 KB and `dummy0` by about 6 KB — and **every other channel was silent**. That silence is the
> valuable part: it means any filesystem, receiver, service or grant change in your next run is
> attributable rather than background.

If *your* control run shows a private-filesystem change, you have learned something important before
you started: this app writes while idle, and you will need narrower windows to attribute anything.

---

## 6. Stages 4 and 5 — Exercise and observe

### 6.1 Write the script first

Not a paragraph. A numbered list, one user-visible action per line, with rough timings. Something like:

```
T+00:00  cold start from the launcher
T+00:20  main screen: wait, do not tap
T+00:35  open the first screen the UI offers
T+01:00  background (HOME)
T+01:20  foreground from recents
```

Write yours into `evidence/s01-exercise.txt`. **You will need it in stage 6**; correlation needs a
timeline of your actions to line up against the timeline of observations.

### 6.2 Run it

```bash
# host — [MUTATES] force-stop restarts the app. It is reversible; the app comes back.
bash ../scripts/session-recorder.sh --package "$PKG" --out ./evidence/s01 \
  --exec "adb shell am force-stop $PKG; sleep 3;
          adb shell am start -W -n $PKG/<YOUR_LAUNCH_ACTIVITY>;
          sleep 30;
          adb shell input keyevent KEYCODE_HOME; sleep 10"
```

Find `<YOUR_LAUNCH_ACTIVITY>` with:

```bash
# host
adb shell "cmd package resolve-activity --brief $PKG" | tail -1
```

### 6.3 Did the exercise actually happen?

**This is the step that separates this lab from a tutorial.** Read the exercise log before you read
anything else:

```bash
# host
cat evidence/s01/exercise.log
```

**Checkpoint 5.** Find the `Activity:` line. Does it name **your** package?

| What you see | Verdict |
|---|---|
| `Activity: com.example.target/.MainActivity` | The exercise ran |
| `Activity: com.android.permissioncontroller/…GrantPermissionsActivity` | **Void.** A permission dialog absorbed the launch |
| `Warning: Activity not started, intent has been delivered to currently running top-most instance.` | **Void.** The app was already in that state |
| `Warning: Activity not started, its current task has been brought to the front` | Probably void — check `mCurrentFocus` |

```bash
# host — two more checks, both cheap
adb shell "dumpsys window" | grep -m1 mCurrentFocus
adb shell "pidof $PKG"
```

If the run was void, **do not analyse its delta report**. Dismiss whatever is on screen, and run 6.2
again. A void run and a clean negative produce identical reports, and telling them apart is entirely
on you.

> **Hint.** This is not a rare edge case. It happened on the chapter's own first two attempts against
> a real app, on a device that looked completely normal.

---

## 7. Stage 6 — Correlate. This is the lab.

```bash
# host — read them side by side, not one after the other
cat evidence/control/DELTA.md
cat evidence/s01/DELTA.md
```

### 7.1 The three subtractions

Go through **every** row of `s01/DELTA.md` and put it in one of four buckets. Write the table out; do
not do it in your head.

| Bucket | Test |
|---|---|
| **Background** | The control run shows it too |
| **Platform** | Vendor tags (`PowerHal`, `mtkpower`, `game_scn`), `UsageStatsService`, `InputManager-JNI`, lifecycle bookkeeping |
| **Your own tooling** | `from uid 2000`, `from pid <your shell>`, anything your proxy or scripts caused |
| **Attributable** | None of the above |

```bash
# host — the logcat capture is where most of the classification happens
wc -l evidence/s01/09-logcat.txt
grep -c 'uid 2000'                 evidence/s01/09-logcat.txt
grep -icE 'powerhal|mtkpower|game_scn|UsageStats|InputManager' evidence/s01/09-logcat.txt
```

**Checkpoint 6.** Of the log lines captured, how many were emitted **by the application itself**
rather than by the platform or by your own commands?

> **Hint.** On the chapter's measured run the answer was **zero out of 44**. That is a real result and
> it belongs in the report: the app logs nothing on the launch path. It is also a useful calibration —
> if you cannot tell which lines are the app's, you are not ready to claim anything about them.

### 7.2 The four questions, for every attributable row

| # | Question | If "no" |
|---|---|---|
| 1 | Did the control run show it too? | Discard: background |
| 2 | Does it line up in **time** with a line of your exercise script? | Re-run with a 60-second window around one action |
| 3 | Can you make it happen again? | Record it; do not report it |
| 4 | **Can you make it NOT happen?** | Your attribution is wrong |

Question 4 is the strongest and almost nobody runs it. Pick your single most interesting attributable
row and do it: run the *identical* session with that one step removed. If the change still occurs, you
had attributed it to the wrong thing.

---

## 8. Stage 0 — Coverage

```bash
# host — with the STATIC denominator
python3 -B ../scripts/coverage-reporter.py --package "$PKG" \
        --components evidence/entrypoints.txt \
        --logcat evidence/s01/09-logcat.txt \
        --markdown evidence/s01/COVERAGE.md --json evidence/s01/coverage.json

# host — and, for the comparison, with the DEVICE denominator
python3 -B ../scripts/coverage-reporter.py --package "$PKG" \
        --logcat evidence/s01/09-logcat.txt | head -20
```

**Checkpoint 7.** Write down both percentages. They will differ, and the device's will be higher.

Then read the section the tool prints titled **"Reached, but not in the inventory"**. Every name there
means your denominator is wrong — usually an entry-point list built from `base.apk` without its
splits, an inner class, or a component a library contributed at manifest-merge time. Fix it if you
can; record it if you cannot.

---

## 9. If channel 04 was closed

If `run-as` refused, you did the lab without private storage. That is normal and the report must say
so **precisely**:

> *"Private storage was **not captured**: the package is not debuggable (`run-as` reported
> `package not debuggable`) and the device is not rooted. No statement in this report addresses the
> contents of `/data/data/<pkg>`."*

Not: *"no sensitive data was found in storage"*, which claims a search you did not perform.

What you still have, and what it is worth:

| Channel | Still available | Worth |
|---|---|---|
| 05 external storage | yes | Anything here is outside the sandbox — a credential here is a finding on its own |
| 06 receivers | yes | The surface no manifest records |
| 02 grants | yes | What the app actually holds |
| 09 logcat | yes | Frequently the highest-yield channel there is |
| 07 services | yes | Including bound clients — a live cross-app reachability map |

Run the known-value sweep on the channels you *do* have:

```bash
# host — a value you know, in every unprivileged channel
VALUE='<a string you caused the app to hold>'
adb shell "grep -rl -- '$VALUE' /sdcard/Android/data/$PKG /sdcard/Download 2>/dev/null"
adb logcat -d -b all | grep -F -- "$VALUE"
adb shell uiautomator dump /sdcard/ui.xml && adb shell "grep -c -- '$VALUE' /sdcard/ui.xml"
adb shell rm /sdcard/ui.xml          # clean up after yourself
```

---

## 10. Stages 7 and 8 — Write the finding

Pick your strongest attributable observation and put it through the four validation questions. Then
write it in this form:

```markdown
### F-01 — <one-line title> (<Severity>)

**Observation.** <what you saw, on which channel, at what time relative to which exercise step>

**Evidence.**
  1. <the platform's own record, if there is one>
  2. <the delta or log line>
  3. <the demonstrated consequence>

**Question 1 — real?** <how you reproduced it, and how many times>
**Question 2 — reachable?** <during ordinary use, or only under conditions you created>
**Question 3 — who?** <from an app? from the network? or only from `adb shell` (uid 2000)?>
**Question 4 — so what?** <the asset. THIS is the severity>

**Precondition.** <e.g. ADB access to an unlocked device. State it; it makes the finding harder to argue with>

**Fix.** <as code, not as advice>

**Coverage.** <N of M components reached against the manifest inventory; these were not reached: ...>
```

**If you found nothing**, write that instead — and write it correctly:

> *"No attributable change was observed on the exercised paths. Component coverage was N of M against
> the manifest inventory; the following components were not exercised: … . Private storage
> [was captured / was not captured because …]. This is not a statement that the application is free of
> defects."*

That paragraph is a legitimate outcome of this lab and writing it well is the point.

---

## 11. Success criteria

- [ ] `evidence/device.txt` records model, API, security patch, SELinux mode, root, Frida and the
      `cacerts` check.
- [ ] You can state, from your own output, which of the three `run-as` outcomes applied and why.
- [ ] A control run exists and you can name the device's background floor from it.
- [ ] `evidence/entrypoints.txt` exists and you know how it differs from the device's component list.
- [ ] You verified the exercise actually ran — you can point at the `Activity:` line.
- [ ] Every row of `s01/DELTA.md` is classified into one of the four buckets, in writing.
- [ ] You ran question 4 (make it *not* happen) on at least one observation.
- [ ] `COVERAGE.md` exists, and you have both percentages and know which to quote.
- [ ] `finding.md` exists and contains either a validated finding or a correctly-worded negative.
- [ ] The device is as you found it: proxy reverted, nothing left in `/data/local/tmp`, the app running
      if it was running before.

---

## 12. Common ways this lab goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| Channel 04 is empty and the report says "no change" | `run-as` failed and you did not notice | The recorder prints `**Not captured.**` for a genuine gap. If it says "no change", the capture worked and the answer is real |
| Everything is "attributable" | No control run | Take one. It is one command |
| The delta is enormous | Your window was too wide, or you drove ten things at once | Narrow to one action and 60 seconds |
| `am start` fails with a security exception | Not an exported or launchable Activity | `cmd package resolve-activity --brief $PKG` gives the launcher one |
| Your finding says "the app is insecure" | You answered question 1 and stopped | Question 4 is the severity |
| Your finding starts "I used Frida to…" | You reported the tool, not the mechanism | The finding is what the app does, not what you did |
| Coverage is 100% and you feel finished | Component coverage is a floor | Say the grain. It means you drove every front door |
| Nothing at all happened | See [README §7.9](../README.md#79-when-nothing-happens) — five explanations, in order |

---

## 13. Going further

- Re-run the whole lab with a **narrower exercise**: one action, 60 seconds. Compare how much easier
  attribution becomes.
- Take a second control run and diff the two control runs against each other. How stable is the
  device's background?
- If your target is debuggable, attach `jdb` (`adb forward tcp:8700 jdwp:<pid>`) and enumerate its
  loaded classes. No injection, no root.
- Then go to [Lab 02](lab-02-the-loop.md), which takes a lead from a *static* pass and closes it at
  runtime — the loop this chapter and
  [52-StaticAnalysis](../../52-StaticAnalysis/README.md) describe from opposite sides.
