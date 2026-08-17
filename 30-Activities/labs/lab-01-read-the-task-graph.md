# Lab 01 — Read the task graph

> **Difficulty:** Beginner
> **Time:** 45–70 minutes
> **You will need:** an Android device or emulator with `adb`, the two apps from
> [`../examples/`](../examples/build.sh), and a terminal.

---

## Why this lab exists

Almost everything written about launch modes is written from the documentation. The documentation is
correct and routinely misread, and the misreadings are *systematic* — three of them appear in nearly
every blog post on the subject:

- that `singleTop` means "only one instance ever exists";
- that `singleTask` always creates a new task;
- that an Activity always ends up in its own app's task.

All three are wrong, and all three can be disproved in twenty minutes with a device and two commands.
This lab does not ask you to believe [README §3.4](../README.md); it asks you to reproduce it.

By the end you will be able to look at any `dumpsys activity activities` output and say what launch
mode each Activity has without opening its manifest.

---

## Objectives

1. Read the four fields in `dumpsys activity activities` that matter, and ignore the other few
   hundred lines.
2. Derive `standard`, `singleTop`, `singleTask` and `singleInstance` behaviour from evidence.
3. Demonstrate that `taskAffinity` splits tasks **within one app**.
4. Observe a **mixed-package task** — two applications in one task — and understand what created it.
5. Record the affinity-namespacing verdict for your device.

---

## Setup

```bash
# host — build both apps out of tree and install them
cd 30-Activities/examples
./build.sh --install
```

If the install fails with `INSTALL_FAILED_USER_RESTRICTED`, that is an OEM policy, not a broken APK.
`build.sh` will automatically try the root path (`su -c 'pm install -r ...'`). If neither works, see
[README §7.8](../README.md) — you need a device where you can enable "Install via USB", or one you
can root.

Confirm both are present and note their uids; you will need them:

```bash
# host
adb shell "pm list packages | grep ch30"
adb shell "dumpsys package com.pentest.ch30.victim   | grep userId=" | head -1
adb shell "dumpsys package com.pentest.ch30.attacker | grep userId=" | head -1
```

Set up two conveniences:

```bash
# host — a short alias for the only dumpsys view you need
tasks() {
  adb shell "dumpsys activity activities" \
    | grep -E "^\s+\* Task\{|Hist #|taskAffinity=|launchMode=" \
    | grep -v "^      \* Task"
}

# host — the app's own view
logs() { adb shell "logcat -d -s CH30:I"; }
```

Start from a clean slate before **every** exercise:

```bash
# host
adb shell "am force-stop com.pentest.ch30.victim; am force-stop com.pentest.ch30.attacker"
adb shell "input keyevent KEYCODE_HOME"
adb shell logcat -c
```

---

## Part 1 — Learning to read the dump

### Step 1.1 — Look at one task

```bash
# host
adb shell "am start -n com.pentest.ch30.victim/.MainActivity"
adb shell "dumpsys activity activities" | grep -A25 "ch30.victim"
```

You will get a great deal of output. Find these four things and ignore everything else:

| Line | What it tells you |
|---|---|
| `* Task{<hash> #<id> ... A=<affinity> ... sz=<n>}` | a task, its id, its affinity, how many Activities it holds |
| `* Hist #<n>: ActivityRecord{... pkg/cls t<taskid>}` | one Activity; `#0` is the **root**, higher numbers are higher in the stack |
| `taskAffinity=` on a `Hist` block | that Activity's **effective** affinity |
| `launchMode=<int>` | 0 standard, 1 singleTop, 2 singleTask, 3 singleInstance, 4 singleInstancePerTask |

> **Question 1.** What is the task id? What is the affinity string? Does the affinity string look like
> `com.pentest.ch30.victim`, or like `<some number>:com.pentest.ch30.victim`?

### Step 1.2 — Record the namespacing verdict

```bash
# host
cd 30-Activities
python3 -B scripts/task-affinity-map.py --check
```

Write the verdict down. It determines the answer to Lab 02 and it is the single most useful fact
about your device for this chapter.

On the device this chapter was written against (Redmi M2101K6P, Android 11 / API 30) it reads:

```text
verdict  : NAMESPACED   (17 of 17 affinity strings carry a uid prefix)
```

> **Question 2.** What is your device's release, API level, and verdict? Write all three down
> together — a verdict without a device is worthless.

### Step 1.3 — Understand why the dump looks duplicated

```bash
# host
adb shell "dumpsys activity activities" | grep -cE "\* Task\{"
adb shell "dumpsys activity activities" | grep -E "\* Task\{" | sort -u | wc -l
```

The first number is roughly twice the second.

> **Question 3.** Why? (Hint: the dump walks the display hierarchy, then prints a summary.) What does
> this mean for any one-liner you write that counts tasks?

---

## Part 2 — `standard`

### Step 2.1

```bash
# host
adb shell "am force-stop com.pentest.ch30.victim"; adb shell "input keyevent KEYCODE_HOME"
adb shell logcat -c
adb shell "am start -n com.pentest.ch30.victim/.MainActivity";  sleep 1
adb shell "am start -n com.pentest.ch30.victim/.AlphaActivity"; sleep 1
adb shell "am start -n com.pentest.ch30.victim/.AlphaActivity"; sleep 1
adb shell "am start -n com.pentest.ch30.victim/.AlphaActivity"; sleep 1
tasks
logs
```

`AlphaActivity` is declared `android:launchMode="standard"`.

> **Question 4.** How many `Hist #` entries are in the task? What is `sz=`?
>
> **Question 5.** In the logcat output, compare the `instance=` values for the three `AlphaActivity`
> lines. Are they the same or different? What does `System.identityHashCode` actually identify — the
> system's record or the app's Java object? Why does the distinction matter here?
>
> **Question 6.** Did `onNewIntent` fire even once?

**Expected shape** (yours will differ in ids and hashes):

```text
    * Task{... #270 ... A=<uid>:com.pentest.ch30.victim ... sz=4}
      * Hist #3: ... /.AlphaActivity t270
      * Hist #2: ... /.AlphaActivity t270
      * Hist #1: ... /.AlphaActivity t270
      * Hist #0: ... /.MainActivity  t270
```

---

## Part 3 — `singleTop`, including the half everybody forgets

### Step 3.1 — while it is on top

```bash
# host
adb shell "am force-stop com.pentest.ch30.victim"; adb shell "input keyevent KEYCODE_HOME"
adb shell logcat -c
adb shell "am start -n com.pentest.ch30.victim/.MainActivity"; sleep 1
adb shell "am start -n com.pentest.ch30.victim/.BetaActivity"; sleep 1
adb shell "am start -n com.pentest.ch30.victim/.BetaActivity"; sleep 1
adb shell "am start -n com.pentest.ch30.victim/.BetaActivity"; sleep 1
logs
```

> **Question 7.** How many distinct `instance=` values do you see for `BetaActivity`? How many
> `onNewIntent` lines?

### Step 3.2 — now push something on top of it

```bash
# host — do NOT force-stop; continue from step 3.1
adb shell "am start -n com.pentest.ch30.victim/.AlphaActivity"; sleep 1
adb shell "am start -n com.pentest.ch30.victim/.BetaActivity";  sleep 1
tasks
logs
```

> **Question 8.** Is the last `BetaActivity` line an `onCreate` or an `onNewIntent`? Is its
> `instance=` the same as the earlier one?
>
> **Question 9.** How many `BetaActivity` entries are now in the task? Write, in one sentence, what
> `singleTop` actually guarantees.
>
> **Question 10.** A developer sets `singleTop` on a login screen so that "there is only ever one
> login screen". What have they actually achieved, and what has been left reachable?

---

## Part 4 — `singleTask`, and the claim that is simply wrong

```bash
# host
adb shell "am force-stop com.pentest.ch30.victim"; adb shell "input keyevent KEYCODE_HOME"
adb shell logcat -c
for A in MainActivity AlphaActivity GammaActivity AlphaActivity GammaActivity; do
  adb shell "am start -n com.pentest.ch30.victim/.$A"
  sleep 1
done
tasks
logs
```

`GammaActivity` is `android:launchMode="singleTask"`.

> **Question 11.** Look at the `taskId=` in every log line. Did `GammaActivity` land in a **new** task
> or in the same one as `MainActivity`? Reconcile that with the claim "`singleTask` creates a new
> task".
>
> **Question 12.** Compare `sz=` after the fourth start and after the fifth. It goes **down**. Which
> Activity disappeared, and which line in the log tells you it was destroyed rather than merely
> stopped? (Look for `onDestroy ... isFinishing=true`.)
>
> **Question 13.** State the actual rule for when `singleTask` creates a new task.
>
> **Question 14 (security).** An attacker can trigger a `singleTask` start on an exported Activity.
> What can they destroy? Name a screen where destroying whatever is above it would be useful to an
> attacker.

---

## Part 5 — `singleInstance`

```bash
# host — continue from Part 4, do not reset
adb shell logcat -c
adb shell "am start -n com.pentest.ch30.victim/.DeltaActivity"; sleep 1
adb shell "am start -n com.pentest.ch30.victim/.AlphaActivity"; sleep 1
tasks
logs
```

> **Question 15.** Which task did `DeltaActivity` go into? What is that task's `sz=`?
>
> **Question 16.** `AlphaActivity` was started *while Delta was on screen*. Which task did it land in?
> What does that tell you about a `singleInstance` task's willingness to accept other Activities?
>
> **Question 17.** Note that Delta's task and Main's task have the **same** affinity string. Explain
> why they are nevertheless two different tasks.

---

## Part 6 — affinity splits tasks inside one app

```bash
# host
adb shell "am force-stop com.pentest.ch30.victim"; adb shell "input keyevent KEYCODE_HOME"
adb shell "am start -n com.pentest.ch30.victim/.MainActivity";    sleep 1
adb shell "am start -n com.pentest.ch30.victim/.EpsilonActivity"; sleep 1
tasks
```

`EpsilonActivity` is `launchMode="standard"` but declares
`android:taskAffinity="com.pentest.ch30.other"`.

> **Question 18.** Are Main and Epsilon in the same task? Both belong to the same package and the same
> uid.
>
> **Question 19.** `am start` supplies `FLAG_ACTIVITY_NEW_TASK` for you (see
> [README §3.3](../README.md)). Explain why that is *necessary* for this result — what would have
> happened without it?
>
> **Question 20.** Write the rule: what does the task boundary actually follow — the package, the uid,
> or the affinity string?

---

## Part 7 — a mixed-package task

This is the part that matters most, and it is the one you cannot do with `am` alone.

```bash
# host
adb shell "am force-stop com.pentest.ch30.victim; am force-stop com.pentest.ch30.attacker"
adb shell "input keyevent KEYCODE_HOME"; sleep 1

# The ATTACKER's Activity starts the VICTIM's Activity, WITHOUT FLAG_ACTIVITY_NEW_TASK.
adb shell "am start -n com.pentest.ch30.attacker/.CrossStartActivity --es target alpha --ez newtask false"
sleep 2
tasks
```

> **Question 21.** How many tasks contain a `ch30` Activity? How many packages are inside the task
> that holds `AlphaActivity`?
>
> **Question 22.** Read the `taskAffinity=` line under the victim's `AlphaActivity`. Whose uid is in
> it? Now read the task's own `A=` affinity. Whose uid is in **that**? Explain the discrepancy.
>
> **Question 23.** The user is looking at the victim's screen and presses Back. What appears?

Now the control:

```bash
# host — the identical start, WITH the flag
adb shell "am force-stop com.pentest.ch30.victim; am force-stop com.pentest.ch30.attacker"
adb shell "input keyevent KEYCODE_HOME"; sleep 1
adb shell "am start -n com.pentest.ch30.attacker/.CrossStartActivity --es target alpha --ez newtask true"
sleep 2
tasks
```

> **Question 24.** How many tasks now? What single flag accounts for the entire difference?
>
> **Question 25.** Run `python3 -B scripts/task-affinity-map.py` against the *first* state. What
> severity does it assign to `MIXED-PACKAGE-TASK`, and why is that higher than the severity it
> assigns to `AFFINITY-SQUAT` on a namespacing device? Do you agree?

---

## Part 8 — see it from inside the app

```bash
# host — requires frida-server on the device; see ../../53-Frida/README.md
frida -U -f com.pentest.ch30.victim -l ../scripts/activity-trace.js
```

With it attached, in another terminal:

```bash
# host
adb shell "am start -n com.pentest.ch30.victim/.BetaActivity"
adb shell "am start -n com.pentest.ch30.victim/.BetaActivity"
```

> **Question 26.** The script prints an identity block on every arrival. What does
> `Binder.getCallingUid()` return, and what does `Process.myUid()` return? Explain the result in one
> sentence.
>
> **Question 27.** `getReferrer()` shows something. What is it, and which of the three identity tiers
> in [README §3.6](../README.md) does it belong to? Could a malicious app set it to anything it liked?
>
> **Question 28.** Compare what `dumpsys` told you in Part 3 with what the Frida script tells you.
> Which one can see the difference between "a new Java object" and "a new activity record"?

---

## Hints

<details>
<summary>Hint for Question 5</summary>

`dumpsys` prints an `ActivityRecord{<hash> ...}` — that hash identifies the **system's** bookkeeping
object. `System.identityHashCode(this)` identifies the **app's** Java object. They are different
things and they can disagree: the system can destroy your Java object, keep the record, and rebuild
the object later from a `Bundle`. For reading launch modes you want the app-side identity, because
"reused the instance" is a statement about the Java object.
</details>

<details>
<summary>Hint for Question 12</summary>

Filter for destruction specifically:

```bash
adb shell "logcat -d -s CH30:I" | grep onDestroy
```

`isFinishing=true` means it is gone for good, not merely stopped.
</details>

<details>
<summary>Hint for Question 17</summary>

Affinity determines *which* task an Activity prefers. `singleInstance` overrides the "one task per
affinity" arrangement with a stronger rule: this Activity gets a task of its own regardless. Two
tasks may share an affinity string; what they may not do is both hold a `singleInstance` Activity.
</details>

<details>
<summary>Hint for Question 19</summary>

Without `FLAG_ACTIVITY_NEW_TASK`, a `standard` Activity started from another Activity joins the
caller's task and its affinity is not consulted at all. `am` runs in the shell process, which is not
an Activity, so the flag is mandatory and `am` adds it. That is why this experiment works from `am`
and Part 7's first experiment does not.
</details>

<details>
<summary>Hint for Question 23</summary>

Look at the `Hist #` indices. `#0` is the root and it is revealed when everything above it finishes.
</details>

---

## Success criteria

You have completed this lab when you can produce, as evidence:

- [ ] Your device's release, API level, and affinity-namespacing verdict, together in one line.
- [ ] A logcat capture showing three `standard` starts producing **three distinct** `instance=` values.
- [ ] A logcat capture showing `singleTop` producing `onNewIntent` on the **same** instance, and a
      later capture showing it producing a **new** instance after something was stacked above it.
- [ ] A `dumpsys` capture showing two `BetaActivity` entries in one task.
- [ ] A pair of `dumpsys` captures showing `sz=` **decreasing** when a `singleTask` Activity was
      re-entered, plus the `onDestroy ... isFinishing=true` line that explains it.
- [ ] A `dumpsys` capture showing `singleTask` in the **same** task as the Activity that started it.
- [ ] A `dumpsys` capture showing `singleInstance` alone in its own task, and a later start routed
      into a different task.
- [ ] A `dumpsys` capture showing two Activities of the **same package** in **different** tasks
      because of `taskAffinity`.
- [ ] A `dumpsys` capture showing two **different packages** in **one** task, and the corresponding
      capture with `FLAG_ACTIVITY_NEW_TASK` showing two tasks.
- [ ] A one-sentence written statement of what `singleTop` guarantees and what it does not.
- [ ] A one-sentence written statement of when `singleTask` creates a new task.

---

## Clean up

```bash
# host
cd 30-Activities/examples
./build.sh --uninstall
```

---

## Where to go next

- [Lab 02 — Task hijacking, proved or disproved](lab-02-task-hijacking.md) uses the affinity
  understanding from Parts 6 and 7 directly.
- [README §3.4](../README.md) has the measured captures to compare yours against.
- [`../scripts/task-affinity-map.py`](../scripts/task-affinity-map.py) automates everything in
  Parts 1, 6 and 7 — read its source after doing this by hand, not before.
