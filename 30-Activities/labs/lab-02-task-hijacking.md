# Lab 02 — Task hijacking, proved or disproved

> **Difficulty:** Intermediate
> **Time:** 60–90 minutes
> **You will need:** an Android device or emulator you own, `adb`, and the two apps from
> [`../examples/`](../examples/build.sh).
> **Prerequisite:** [Lab 01](lab-01-read-the-task-graph.md). You must be able to read
> `dumpsys activity activities` before this lab means anything.

---

## Why this lab exists, and why its outcome is not fixed

This is the only lab in this chapter whose **correct answer depends on your device**, and that is the
point.

Task hijacking — the StrandHogg class — is described in hundreds of articles, almost all of which
state a version number at which it was "fixed". Those statements disagree with each other. This
repository has itself carried a version-keyed claim forward from memory and been wrong about it —
an API 33 figure was repeated for weeks against a phone that had quietly been swapped for an API 30
one. So this lab does not teach you an answer. It teaches you the **measurement**,
and then asks you to report what your device did.

On the device this chapter was written against — Redmi M2101K6P, Android 11 / API 30, MIUI 12.5,
security patch 2021-12-01 — the attack **failed**, for a reason that is visible in the dump. Your
device may differ. Either outcome is a complete, correct lab result, provided you can show the
evidence.

> **⚠️ Authorised testing only**
> The attacker app in `../examples/hijacker-app/` deliberately declares a `taskAffinity` naming
> another package. Install it only on a device you own, only alongside the victim app that ships with
> it, and **never** point a `taskAffinity` at an application you do not own. Uninstall both when you
> are done.

---

## Objectives

1. Understand the attack as a **manifest** attack — no exploit, no code, no permission.
2. Arm and trigger it, and determine from evidence whether it worked.
3. Explain the mechanism that decided the outcome, by reading affinity strings.
4. Test the `allowTaskReparenting` variant **separately**, and say why separately.
5. Rate the finding honestly, including the precondition that caps its severity.
6. Write the remediation as an XML attribute and verify it.

---

## Background in sixty seconds

Every Activity has a `taskAffinity` — a string naming the task it prefers. It defaults to the
**package name**, which is public. An attacker declares the *victim's* package name as its own
affinity and sets `launchMode="singleTask"`, so that its Activity owns the task with that name.
Launch the attacker once and the task exists, parked, surviving process death. When the user later
taps the victim's icon, the system looks for a task matching the victim's affinity — and, in the
intended attack, finds the attacker's.

Nothing about the victim is modified, repackaged or exploited. See
[README §5.2](../README.md) for the full treatment.

---

## Setup

```bash
# host
cd 30-Activities/examples
./build.sh --install
```

If you meet `INSTALL_FAILED_USER_RESTRICTED`, that is an OEM "Install via USB" gate, not a fault in
the APK, and the message "Install canceled by user" is untrue. `build.sh` falls back to a root
install automatically. Details and the alternatives are in [README §7.8](../README.md).

Record the two uids — the whole lab turns on them:

```bash
# host
adb shell "dumpsys package com.pentest.ch30.victim   | grep userId=" | head -1
adb shell "dumpsys package com.pentest.ch30.attacker | grep userId=" | head -1
```

Convenience:

```bash
# host
ch30() { adb shell "dumpsys activity activities" \
         | grep -E "^\s+\* Task\{.*ch30|Hist #.*ch30|taskAffinity=.*ch30|ResumedActivity"; }
reset() { adb shell "am force-stop com.pentest.ch30.victim; am force-stop com.pentest.ch30.attacker"
          adb shell "input keyevent KEYCODE_HOME"; adb shell logcat -c; sleep 1; }
```

---

## Part 1 — Read the payload before you run it

```bash
# host
cat ../examples/hijacker-app/AndroidManifest.xml
```

Find the `HijackActivity` element.

> **Question 1.** Exactly which attributes constitute the attack? How many lines of **Java** are
> involved in it?
>
> **Question 2.** The attacker also declares a `MAIN`/`LAUNCHER` filter. Why does it need one — what
> does the attack require the user to do once?
>
> **Question 3.** Now read `../examples/victim-app/AndroidManifest.xml`. The victim is vulnerable
> because of something that is **absent**. What?
>
> **Question 4.** Nobody wrote `android:taskAffinity` in the victim's manifest. What is the victim's
> affinity, then, and where did it come from?

---

## Part 2 — Baseline: what does your platform do with affinities?

Before touching the attack, establish the mechanism.

```bash
# host
reset
adb shell "am start -n com.pentest.ch30.victim/.MainActivity"; sleep 2
adb shell "dumpsys activity activities" | grep -E "taskAffinity=|affinity=" | sort -u
```

> **Question 5.** Write down the victim's affinity string, exactly. Does it match the package name
> character for character, or is there something in front of it?
>
> **Question 6.** Now look at the affinities of some **system** apps in the same output. If there is a
> prefix, what is it? Cross-check one:
>
> ```bash
> adb shell "dumpsys package com.android.chrome | grep userId=" | head -1
> ```
>
> **Question 7.** Run the automated verdict and compare it with your own reading:
>
> ```bash
> cd .. && python3 -B scripts/task-affinity-map.py --check
> ```
>
> Record: device model, Android release, API level, verdict. All four, together.

---

## Part 3 — Arm the attack

```bash
# host
reset
# Launch the attacker exactly as tapping its icon would: MAIN + LAUNCHER.
adb shell "am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER \
    -n com.pentest.ch30.attacker/.HijackActivity"
sleep 2
ch30
```

> **Question 8.** A task now exists for the attacker. What is its `A=` affinity string? Which package
> name is in it, and whose **uid** is in it?
>
> **Question 9.** The attacker declared `taskAffinity="com.pentest.ch30.victim"`. Is that the string
> the platform stored? If not, what did the platform do to it, and where does
> [README §4.2 step 6](../README.md) say that happens?

Confirm the task is durable — the attack depends on it surviving:

```bash
# host
adb shell "am force-stop com.pentest.ch30.attacker"
sleep 1
adb shell "dumpsys activity recents" | grep -E "Recent #|affinity=" | head -8
```

> **Question 10.** Is the attacker's task still listed after its process was killed? Why does that
> matter to an attacker who wants to wait days for the user to open their banking app?

---

## Part 4 — Trigger it

**Do not** force-stop anything now. Simulate the user tapping the victim's icon:

```bash
# host
adb shell "am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER \
    -n com.pentest.ch30.victim/.MainActivity"
sleep 2
ch30
```

And, critically, look at the phone:

```bash
# host — capture what the user would actually see
adb shell screencap -p /sdcard/ch30-result.png
adb pull /sdcard/ch30-result.png .
adb shell rm /sdcard/ch30-result.png
```

The attacker's screen is **red** and says `ATTACKER`. The victim's is **white** and says `VICTIM`.

> **Question 11.** Which colour is on the screen?
>
> **Question 12.** How many `ch30` tasks exist now? Write down each task id with its affinity string
> and the package of its root Activity.
>
> **Question 13.** What does the `ResumedActivity:` line say?
>
> **Question 14.** Check logcat:
>
> ```bash
> adb shell "logcat -d -s CH30:I" | grep -i attacker
> ```
>
> Did `HijackActivity.onNewIntent` fire? If the hijack had succeeded, would you expect it to? (Recall
> its launch mode.)

### If the attack FAILED (two separate tasks, white screen)

> **Question 15.** Put the two affinity strings side by side. They contain the same package name.
> Explain, in one sentence, why `ActivityStarter.getReusableTask()` did not treat them as a match.
>
> **Question 16.** Could the attacker have declared anything in its manifest that would produce the
> victim's exact effective affinity? What would it need to control that it does not control?

### If the attack SUCCEEDED (one task, red screen)

> **Question 15a.** Record the single task id and both packages. Save the screenshot — it is the
> finding.
>
> **Question 16a.** Now apply the fix from Part 6 to the victim, rebuild, and re-run. Did it stop?
>
> **Question 17a.** Your device is a genuinely useful data point that this chapter did not have.
> Record its model, release, API level, build fingerprint and security patch level.

---

## Part 5 — The reparenting variant, tested separately

The second historical variant does not park a task. It gets the attacker's Activity started inside
some task and then asks the system to **move** it into a matching task later.

```bash
# host
cat ../examples/hijacker-app/AndroidManifest.xml | grep -A4 ReparentActivity
```

```bash
# host
reset
adb shell "am start -n com.pentest.ch30.victim/.MainActivity";   sleep 2
adb shell "am start -n com.pentest.ch30.attacker/.ReparentActivity"; sleep 2
ch30
echo "--- now background everything and bring the VICTIM forward ---"
adb shell "input keyevent KEYCODE_HOME"; sleep 2
adb shell "am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER \
    -n com.pentest.ch30.victim/.MainActivity"; sleep 2
ch30
```

> **Question 18.** Did the attacker's `ReparentActivity` move into the victim's task? What is the
> evidence, in terms of `Hist #` lines and task ids?
>
> **Question 19.** Why does this lab test the two variants separately rather than assuming that
> blocking one blocks the other?
>
> **Question 20.** Suppose reparenting had worked while the `singleTask` variant did not. What would
> the `dumpsys` output look like — describe the exact shape you would be looking for.

---

## Part 6 — The fix, written and verified

```xml
<!-- The one-line, app-wide hardening. Add to ../examples/victim-app/AndroidManifest.xml -->
<application
    android:label="CH30 Victim"
    android:allowBackup="false"
    android:taskAffinity="">
```

```bash
# host
# edit ../examples/victim-app/AndroidManifest.xml, then:
./build.sh --install
reset
adb shell "am start -n com.pentest.ch30.victim/.MainActivity"; sleep 2
adb shell "dumpsys activity activities" | grep -E "ch30.victim" -A3 | grep -E "affinity|Task\{"
```

> **Question 21.** What is the victim's affinity now? Compare with the launcher's, which also declares
> `taskAffinity=""`:
>
> ```bash
> adb shell "dumpsys activity activities" | grep -B2 "taskAffinity=null"
> ```
>
> **Question 22.** Re-run Parts 3 and 4 against the hardened victim. Does anything change on a
> namespacing device? On a non-namespacing one?
>
> **Question 23.** Start `MainActivity` and then `AlphaActivity`. Are they still in the same task,
> even though neither has an affinity? Explain why, referring to when affinity is consulted.
>
> **Question 24.** So what does `taskAffinity=""` actually cost the app? Would you recommend it
> unconditionally?

Remember to revert the manifest afterwards, or Lab 05 will behave differently from its answer key:

```bash
# host — undo the hardening
git checkout ../examples/victim-app/AndroidManifest.xml 2>/dev/null || \
  echo "restore android:taskAffinity=\"\" removal by hand"
./build.sh --install
```

---

## Part 7 — Write the finding

Draft the finding as you would submit it. It must contain, in this order:

1. **Title**, with the precondition in it. Compare:
   - *"Task hijacking (StrandHogg) — Critical"*
   - *"Launcher Activity does not set `taskAffinity=\"\"` (requires malicious app; mitigated on tested devices)"*
2. **Device and platform**: model, release, API level, build fingerprint, patch level.
3. **Measured outcome**: succeeded or failed, with the two affinity strings quoted.
4. **Evidence**: the `dumpsys` captures and the screenshot.
5. **Severity, with reasoning**, using the anchors in [README §5.4](../README.md).
6. **Remediation as code**: the XML above.

> **Question 25.** Which of the two titles above would you file, and why? What does the first one cost
> you if the triager reproduces it on a namespacing device?
>
> **Question 26.** Your client's support matrix includes devices from 2017. How does that change your
> severity, and what would you need to measure before deciding?
>
> **Question 27.** A scanner in the client's CI reports this at Critical on every build. Write the two
> sentences you would add to its output to make it useful.

---

## Hints

<details>
<summary>Hint for Question 9</summary>

Compare exactly these two:

```bash
aapt2 dump xmltree --file AndroidManifest.xml \
  "${TMPDIR:-/tmp}/ch30-build/hijacker-app/hijacker-app.apk" | grep -A1 taskAffinity
adb shell "dumpsys activity activities" | grep -A1 HijackActivity
```

Same install, same attribute, two different strings. The transformation is applied at runtime, in
`system_server`, when the `ActivityRecord` is created.
</details>

<details>
<summary>Hint for Question 14</summary>

`HijackActivity` is `launchMode="singleTask"`. If the victim's launch had been drawn into the
attacker's task, the system would have found the existing single instance and delivered to it —
which means `onNewIntent`. Its absence is corroborating evidence that no reuse happened.
</details>

<details>
<summary>Hint for Question 16</summary>

The prefix is a **uid**, assigned by the package manager at install time. An app does not choose its
own uid. The only way two packages share one is `sharedUserId`, which requires both APKs to be signed
by the same key — at which point they are the same trust domain and the attack is meaningless.
</details>

<details>
<summary>Hint for Question 20</summary>

You would be looking for a single task id whose `Hist #` lines name two different packages, with the
attacker's `ReparentActivity` appearing in a task rooted by the victim. That shape — two packages,
one task — is real and reachable, just not by this route; Lab 01 Part 7 produces it a different way.
</details>

<details>
<summary>Hint for Question 23</summary>

Affinity is consulted only when a task is being **chosen or created**. A `standard` Activity started
from another Activity of the same app joins the caller's task without any affinity lookup at all, so
removing the affinity changes nothing about ordinary in-app navigation.
</details>

---

## Success criteria

You have completed this lab when you can produce, as evidence:

- [ ] Device model, Android release, API level, build fingerprint, security patch level, and the
      affinity-namespacing verdict — recorded together.
- [ ] The attacker's manifest excerpt, with the two attributes that constitute the attack identified.
- [ ] A `dumpsys` capture of the **armed** state showing the attacker's task and its affinity string.
- [ ] Evidence that the attacker's task **survives** its process being killed.
- [ ] A `dumpsys` capture of the **triggered** state, with every `ch30` task id, affinity, and root
      package listed.
- [ ] The `ResumedActivity:` line after triggering.
- [ ] **A screenshot of the screen after triggering** — red or white. Without this you have a task
      graph, not a finding.
- [ ] A separate capture for the `allowTaskReparenting` variant, with its own conclusion.
- [ ] A written, one-sentence explanation of *why* the outcome was what it was, quoting both affinity
      strings.
- [ ] A `dumpsys` capture showing `taskAffinity=null` after applying the fix.
- [ ] Evidence that the fix does **not** break ordinary in-app navigation (Question 23).
- [ ] A finding write-up whose **title contains the precondition**.

---

## Clean up

```bash
# host
cd 30-Activities/examples
./build.sh --uninstall
adb shell "pm list packages | grep ch30"   # should print nothing
```

---

## Where to go next

- [Lab 03 — The deputy that launders a grant](lab-03-deputy-grant-laundering.md): an attack with a
  *much* lower precondition, and a correspondingly higher severity.
- [README §5.2](../README.md) has the measured captures from the reference device to compare against.
- [`../scripts/task-affinity-map.py`](../scripts/task-affinity-map.py) automates Parts 2 and 3, and
  conditions its severities on the verdict you established in Part 2.
