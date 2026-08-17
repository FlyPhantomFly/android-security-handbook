# Lab 01 — Triage the death

> **Objective.** Take an application that dies the instant you touch it, and say — with evidence, not
> with a guess — which control fired, at which seam, how it responded, and what to do next. You will
> do this without root, without Frida, and without reading the app's source.

**Difficulty:** introductory
**Time:** 60–90 minutes
**Root required:** no
**Frida required:** no
**Chapter section this exercises:** [README §3.9](../README.md#39-the-response--what-the-app-does-once-it-has-decided),
[§3.12](../README.md#312-timing-is-the-whole-game-init_array-jni_onload-and-why-attach-loses),
[§7.2](../README.md#72-the-triage-workflow-with-this-chapters-script),
[§7.3](../README.md#73-reading-the-exit-record--measured-signatures)

---

## Why this lab exists

[53-Frida](../../53-Frida/README.md) sends readers to chapter 67 with one specific symptom: *"I
attach and the app dies instantly."* Most people respond to that by immediately writing a bypass —
usually the wrong one, at the wrong seam, for a control that may not even be the one that fired.

The professional response is to **triage first**. Thirty seconds of reading an exit record tells you
more than an hour of speculative hooking, and it costs nothing. By the end of this lab you will be
able to look at a dead process and say, out loud:

> *"It aborted natively with SIGABRT, before any Activity lifecycle event, and the deciding frame was
> `libX.so (JNI_OnLoad+N)`. That is a load-time native check. Attaching cannot work. I need to spawn,
> and I need my hooks installed before `System.loadLibrary` returns."*

That sentence is the whole lab.

---

## Setup

### Step 0 — identify your device and write it down

Two physical devices are in play across this repository and **they get swapped without warning**.
Every version-gated claim you make is worthless if you do not know which device produced it.

```bash
# host
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.version.release
adb shell getenforce
```

Record the output. This lab was written against:

```
model=i9000S   Android 13 / API 33   arm64-v8a   Enforcing   not rooted   no frida-server
```

> **⚠️ `ApplicationExitInfo` is API 30+.** On API 29 and below the `dumpsys activity exit-info`
> section does not exist and this lab's central evidence source is unavailable. The triage script
> detects that and says so; if you are on an older device, you can still do steps 1–3 and the logcat
> half of steps 4–6.

### Step 1 — build and install the target

```bash
# host
cd 67-BypassingProtections
export ANDROID_HOME=~/Android/Sdk      # or wherever your SDK is
OUTDIR=/tmp/ch67 ./examples/build.sh --install
```

You should see three builds and one install:

```
=== building guarded-release ===
  native: built lib/arm64-v8a/libch67guard.so
=== building guarded-debuggable ===
  manifest: android:debuggable="true" patched in
  native: built lib/arm64-v8a/libch67guard.so
=== building server-app ===
installed com.pentest.ch67.guarded (release)
```

If the NDK is not found the native tier is skipped and the app reports `native tier absent`. That is
a legitimate state and steps 4 and 5 will behave differently — the lab notes where.

If `adb install` fails with `INSTALL_FAILED_USER_RESTRICTED`, that is an OEM "Install via USB"
policy, not a fault in the APK. The script detects it and tries a root path automatically.

### Step 2 — establish the baseline

**You cannot triage a death without knowing what life looks like.** This step is not optional and it
is the one people skip.

```bash
# host
python3 -B scripts/bypass-triage.py \
    --package com.pentest.ch67.guarded \
    --activity .MainActivity \
    --extra-bool auto_open=true \
    --json /tmp/ch67-baseline.json
```

**Q1.** What does the tool report for `activity lifecycle reached`, and what does
`reached RESUMED (UI alive)` say? Write both down.

**Q2.** Read the "verdict" block. The process did not die — the tool prints three possibilities
rather than declaring victory. What are they, and why does the tool refuse to pick one?

```bash
# host — what did the app actually produce?
adb logcat -d -s CH67Guard:V | grep SECRET
```

**Q3.** Record the exact secret string. You will need it in step 6, and you will not be able to
recognise a poisoned answer without it.

---

## Part A — the five death signatures

Before you triage an unknown death, you need to know what each response looks like. The demo app
implements six responses on purpose, and two of them produce **no exit record at all** — which is
itself the lesson.

### Step 3 — fire each response and record its signature

The app ships an explicitly labelled lab harness: `--es simulate <signal-id>` marks a named signal as
fired without changing what the read returned. It is the app lying to itself so that you can learn
the death signatures on a stock phone. It is **not** how any control is defeated in any lab here, and
step 4 uses a real trigger instead.

```bash
# host — run each of these and record reason / status / lifecycle
for s in debugger.jdwp debugger.tracerpid frida.threadnames frida.maps; do
  echo "########## $s"
  python3 -B scripts/bypass-triage.py -p com.pentest.ch67.guarded -a .MainActivity \
      --extra-bool auto_open=true --extra-str simulate=$s --wait 5 \
    | sed -n '/=== verdict/,/what to do next/p'
done
```

Fill this in from your own output before reading anything else:

| Simulated signal | App's response policy | `reason` | `status` | Lifecycle reached | Process died? |
|---|---|---|---|---|---|
| `debugger.jdwp` | | | | | |
| `debugger.tracerpid` | | | | | |
| `frida.threadnames` | | | | | |
| `frida.maps` | | | | | |

**Q4.** Two of the four did **not** kill the process. Which two, and what did each do instead? (Read
`adb logcat -d -s CH67Guard:V` for both.)

**Q5.** For `debugger.jdwp` the status is `42`. Where does that number come from? Is `42` meaningful
to Android in any way?

**Q6.** For `frida.threadnames` the status is `9`. Is `9` an exit code or something else? What
general rule does the difference between Q5 and Q6 establish about reading the `status` field?

**Q7.** Run the `frida.maps` case again and compare the app's output with the secret you recorded in
Q3. What happened? Would you have noticed if you had not written Q3 down?

---

## Part B — a real control, really firing

Simulation teaches you signatures. It does not teach you triage, because you already knew the answer.
Now make a control fire **honestly**, with no simulation and no root.

### Step 4 — the anti-Frida port check, fired for real

The app's `frida.port27042` control asks: *is anything listening on 127.0.0.1:27042?* On a stock
device the answer is no. You can make it genuinely yes without root and without frida-server:

```bash
# host — creates a REAL listening socket ON THE DEVICE, inside adbd.
adb reverse tcp:27042 tcp:27042
```

> **🧠 Mental Model**
> This is a seam-1 attack **in reverse**. Normally you change the world so a check passes; here you
> change the world so a check fires. Anything you can do in one direction you can do in the other,
> and that is what makes a control testable at all.

Now run the app with no simulation, no hooks, and nothing else changed:

```bash
# host
python3 -B scripts/bypass-triage.py -p com.pentest.ch67.guarded -a .MainActivity \
    --extra-bool auto_open=true --baseline /tmp/ch67-baseline.json
```

**Q8.** What `reason` and `status` did you get? Which of the four signatures from Part A does it
match — and does it match *any* of them?

**Q9.** What does `activity lifecycle reached` say? Compare with your Q1 answer. What does the
difference tell you about **when** the check ran?

**Q10.** The tool prints a line beginning `deciding frame:`. Quote it. Which library, which symbol,
what offset?

**Q11.** The first frame of the tombstone (`#00`) is `abort+180` inside `libc.so`. Why is that frame
useless, and why is frame `#01` the one that matters? State the general rule.

**Q12.** The tool reports `seam: S1-input/S2-read` rather than picking one. Read the explanation it
prints. Why can it not distinguish these two from outside the process, and what would you have to do
to distinguish them?

### Step 5 — read the raw evidence yourself

Do not let the tool be the only thing you can read. Everything it says is derived from two commands.

```bash
# host — the exit record, raw
adb shell dumpsys activity exit-info com.pentest.ch67.guarded | head -20

# host — the tombstone, in logcat
adb logcat -d | grep -E "F DEBUG|F/DEBUG" | head -30

# host — the app's own log, which in a real target you would not have
adb logcat -d -s CH67Guard:V | tail -20
```

**Q13.** Find the line `signal 6 (SIGABRT), code -1 (SI_QUEUE)`. What does `SI_QUEUE` tell you about
how the signal was raised? (Hint: compare with what you would expect from a segmentation fault.)

**Q14.** In the tombstone's backtrace, find the frame directly *below* `JNI_OnLoad`. Which platform
function called it? What does that confirm about the sequence in
[README §4.4](../README.md#44-systemloadlibrary--jni_onload)?

**Q15.** In a real engagement you would **not** have the `CH67Guard` log lines. Redo your reasoning
for Q8–Q12 using only `dumpsys activity exit-info` and the `F DEBUG` lines. Does any conclusion
change?

---

## Part C — the trap

### Step 6 — a death that is not a protection

Not every early death is a control, and a triage habit that assumes otherwise will send you hunting
for a bypass that does not exist.

```bash
# host — remove the tunnel first, so we are testing one thing
adb reverse --remove tcp:27042
```

The demo app's own history contains a real example. Its first build ran the socket probe on the main
thread, and StrictMode threw `NetworkOnMainThreadException` — the app died during `onCreate`, with
`reason=4 CRASH`, before any control had decided anything. The comment in
[`Guard.checkFridaPort()`](../examples/guarded-app/Guard.java) records it.

**Q16.** Read that comment. If you had triaged that death without reading the stack, what would you
have concluded? What is the general rule?

**Q17.** The triage script has a list of exception names it treats as "this looks like an ordinary
bug". Find it in [`scripts/bypass-triage.py`](../scripts/bypass-triage.py). Name three, and explain
for each why an ordinary bug produces it.

**Q18.** Is that list safe? Construct a scenario in which a protection deliberately throws one of
those exception types in order to look like a bug. How would you tell?

### Step 7 — the other trap: state that persists

```bash
# host — prove to yourself that the tunnel is gone
adb reverse --list

# host — run the app again
python3 -B scripts/bypass-triage.py -p com.pentest.ch67.guarded -a .MainActivity \
    --extra-bool auto_open=true --baseline /tmp/ch67-baseline.json
```

**Q19.** Suppose you had forgotten to remove the reverse tunnel and had then written a Frida hook to
"defeat" the port check. Your hook would appear to work. What would actually be happening, and how
would you have caught the error?

**Q20.** Name three other pieces of device state that persist between runs and silently do the work
you would credit to your bypass. (Hint: `resetprop`, Magisk DenyList, and one more that is specific
to this lab.)

---

## Hints

<details>
<summary>Hint 1 — Q6, the status field</summary>

Look at the `EXIT_REASONS` table in the triage script. Reason 1 is `EXIT_SELF`, and its status is the
value passed to `System.exit()`. Reason 2 is `SIGNALED` and reason 5 is `CRASH_NATIVE`; for both of
those, status is a **signal number**. 9 is SIGKILL, 6 is SIGABRT.

The rule: **read `reason` before you interpret `status`.** The same integer means two entirely
different things depending on which reason it accompanies. `status=6` after `reason=5` is SIGABRT;
`status=6` after `reason=1` would be `System.exit(6)`.
</details>

<details>
<summary>Hint 2 — Q9, what the lifecycle tells you</summary>

`activity lifecycle reached: NOTHING` means the process died before `ActivityThread` emitted even
`wm_on_create_called`. Since `MainActivity.onCreate` is where the Java tier runs, and since the
native library is loaded from within `onCreate`, a death with **zero** lifecycle events means the
decision was taken *inside* `System.loadLibrary` — either in an `.init_array` constructor or in
`JNI_OnLoad`.

Compare with your baseline, where the lifecycle read
`create -> start -> resume -> top_resumed_gained`.
</details>

<details>
<summary>Hint 3 — Q11, why frame #01</summary>

Every process that calls `abort()` has `abort+N` in `libc.so` as frame `#00`. It is the same frame in
every native abort on the planet and it identifies nothing.

Frame `#01` is the **caller** — the first frame that belongs to the application rather than to the
platform. Its module path (`/data/app/.../lib/arm64/libch67guard.so`) and symbol (`JNI_OnLoad+908`)
tell you which library took the decision and at what offset, which is a Ghidra address.

The general rule: in any stack, the interesting frame is the first one that belongs to the target
rather than to the runtime. This is equally true of Java stacks — see
[README §7.6](../README.md#76-finding-the-branch-kill-path-tracerjs).
</details>

<details>
<summary>Hint 4 — Q12, why the seam is ambiguous</summary>

From outside the process you observe **when** the decision was taken (load time) and **what** it did
(abort). You do not observe **what it read**.

A load-time abort is equally consistent with:
- an S1-input attack surface — the check connected to a port, and the port was open;
- an S2-read surface — the check read `/proc/self/maps` and found a string.

To distinguish them you must be inside the process at the moment of the read, which means spawning
with instrumentation installed before `System.loadLibrary`. That is exactly what
[`scripts/early-instrument.js`](../scripts/early-instrument.js) is for, and it is lab 02's subject.
</details>

<details>
<summary>Hint 5 — Q13, SI_QUEUE</summary>

`code -1 (SI_QUEUE)` means the signal was raised **deliberately by the process itself**, via
`raise()`/`tgkill()` — which is what `abort()` does internally. A segmentation fault would show
`SEGV_MAPERR` or `SEGV_ACCERR` with a fault address, because the kernel generated it.

That single field distinguishes "the app decided to die" from "the app was killed by a memory
error" — and therefore distinguishes a protection from a crash, before you have read a single line of
the backtrace.
</details>

<details>
<summary>Hint 6 — Q20, persistent state</summary>

Three that will bite you:
1. `resetprop` changes survive until reboot and affect **every** process.
2. A Magisk DenyList entry persists indefinitely.
3. `adb reverse` / `adb forward` tunnels persist until removed or until adbd restarts — this one is
   specific to this lab and it is the one that will catch you, because nothing about the app's
   behaviour hints that a tunnel exists.

Chapter 20's lab-03 makes "reboot between altitudes" an explicit step for exactly this reason.
</details>

---

## Answers

<details>
<summary>Answers Q1–Q3 — the baseline</summary>

**Q1.** `create -> start -> resume -> top_resumed_gained`, and `reached RESUMED (UI alive): True`.
The process is alive; the tool reports `process is STILL ALIVE, pid NNNNN`.

**Q2.** The three possibilities are: (1) no control fired; (2) a control fired and refused the
*operation* rather than killing the process; (3) a control fired and **poisoned** the session — no
crash, quietly wrong results.

The tool refuses to pick because it cannot distinguish them from outside. Case 3 produces no exit
record, no log line and no observable difference *unless you know what the right answer looks like*.
A tool that guessed here would be confidently wrong in the most expensive case.

**Q3.** `CH67{cl13nt_s1d3_b00l3an_1s_n0t_a_l0ck}`
</details>

<details>
<summary>Answers Q4–Q7 — the signature table</summary>

Measured on the i9000S, Android 13 / API 33:

| Simulated signal | Policy | reason | status | Lifecycle | Died? |
|---|---|---|---|---|---|
| `debugger.jdwp` | `EXIT_SELF` | 1 (EXIT_SELF) | 42 | full | yes |
| `debugger.tracerpid` | `THROW` | *(no record)* | — | full | **no** |
| `frida.threadnames` | `SIGKILL_SELF` | 2 (SIGNALED) | 9 | full | yes |
| `frida.maps` | `POISON` | *(no record)* | — | full | **no** |

**Q4.** `debugger.tracerpid` and `frida.maps`. The first **threw** a `SecurityException`, which
`MainActivity` catches — the operation failed, the process lived. The second **poisoned** the vault:
nothing failed at all.

**Q5.** `42` is the literal the developer passed to `System.exit(42)` in `Guard.react()`. It means
nothing to Android; it is a fingerprint of this one build. That is why the triage script says
"treat the status as a fingerprint of one build, not a standard" — and why grepping the DEX for
`const/16 vN, 0x2a` is a fast way to find the branch.

**Q6.** `9` is SIGKILL, a **signal number**, not an exit code. The rule: `status` is an exit code
when `reason=1` and a signal number when `reason` is 2 or 5. Never read `status` without `reason`.

**Q7.** The vault opened and returned `ch[CLNTSDBLANSNTALCK]` instead of the real flag. Nothing
crashed and nothing logged an error. Without Q3 recorded you would very plausibly have accepted it —
which is the entire point of the `POISON` response and the reason step 2 is not optional.
</details>

<details>
<summary>Answers Q8–Q12 — the real control</summary>

**Q8.** `reason=5 (CRASH_NATIVE) status=6 (SIGABRT)`. It matches **none** of the four Part A
signatures, because all four of those were Java-tier responses reached after the UI existed. This is
a fifth signature: the native tier.

**Q9.** `activity lifecycle reached: NOTHING`, against `create -> start -> resume ->
top_resumed_gained` in the baseline. The process died before `ActivityThread` emitted a single
lifecycle event, so the decision was taken during `System.loadLibrary` — before any of the app's own
Java ran.

**Q10.**
`deciding frame: libch67guard.so (JNI_OnLoad+908)`

**Q11.** `abort+180` in `libc.so` is present in every native abort ever recorded and identifies
nothing. Frame `#01` is the caller — the first frame belonging to the application. The general rule:
**in any stack, the first frame that belongs to the target rather than to the runtime is the one that
decided.**

**Q12.** From outside you can see *when* and *what it did*, never *what it read*. A load-time abort
is equally consistent with an input-surface check (a port) and a read-surface check (`/proc`). To
distinguish them you must be inside the process at the moment of the read — spawn with
instrumentation installed before `System.loadLibrary`, which is lab 02.
</details>

<details>
<summary>Answers Q13–Q15 — the raw evidence</summary>

**Q13.** `SI_QUEUE` means the signal was queued by the process itself — `abort()` raises it
deliberately. A genuine memory fault would report `SEGV_MAPERR`/`SEGV_ACCERR` with a fault address,
because the kernel generated it. So this single field separates "the app chose to die" from "the app
was killed by a bug", before you read the backtrace.

**Q14.** `art::JavaVMExt::LoadNativeLibrary`, and below it `JVM_NativeLoad` and
`art_jni_trampoline`. That confirms the AOSP sequence exactly: `System.loadLibrary` reached
`LoadNativeLibrary`, which opened the library and then called `JNI_OnLoad` **synchronously on the
calling thread** — which is why the abort carries the Java thread's stack.

**Q15.** Nothing changes. `dumpsys activity exit-info` gives you reason, status and timing;
`F DEBUG` gives you the signal, the code and the deciding frame. The `CH67Guard` lines are a
convenience of a target you own and are absent in real work — which is why the triage script never
depends on them.
</details>

<details>
<summary>Answers Q16–Q20 — the traps</summary>

**Q16.** You would have concluded that an anti-instrumentation control killed the app at launch, and
gone looking for a bypass for a control that had not decided anything. The app was crashed **by** its
own protection code, not **because of** its protection decision.

The rule: **`reason=4 CRASH` at launch is more often a bug than a control. Read the stack before you
believe the exit reason.**

**Q17.** From the script: `NetworkOnMainThread`, `NullPointer`, `IllegalState`, `ClassNotFound`,
`NoClassDefFound`, `OutOfMemory`, `UnsatisfiedLink`, `IndexOutOfBounds`. Each is the ordinary
signature of a coding error: I/O on the wrong thread, an unchecked reference, a missing class, a
missing native library, a bad index.

**Q18.** It is a heuristic and it is not safe. A hostile app could throw
`IllegalStateException("Session invalid")` from its refusal path precisely so that a triager
classifies it as a bug and moves on. You would tell by reading the stack: the *frames*, not the
exception type. If the top app frame is `Guard.enforce`, the type is irrelevant. This is why the
script prints the evidence line rather than only its conclusion — the conclusion is auditable.

**Q19.** Your hook would run, the check would return "port closed", and you would credit the hook.
What actually happened is that you removed the tunnel and the port genuinely closed. You would catch
it by testing the hook and the environment change **separately**, and by running `adb reverse --list`
as part of your setup check — which is why the chapter's workflow ends with `--remove`.

**Q20.** `resetprop` values (persist until reboot, affect every process), a Magisk DenyList entry
(persists indefinitely), and `adb reverse`/`adb forward` tunnels (persist until removed). The third
is this lab's specific hazard because nothing in the app's behaviour hints at it.
</details>

---

## Success criteria

- [ ] You recorded your device model, API level, SELinux mode and root status before starting
- [ ] You captured a baseline, including the exact correct secret string
- [ ] You produced the four Part A signatures yourself and can explain why two produced no exit record
- [ ] You can state the rule about reading `reason` before `status`, and give an example
- [ ] You fired a real control with no simulation, no root and no Frida
- [ ] You extracted the deciding frame from a tombstone and can say why frame `#00` is useless
- [ ] You can explain why the seam is reported as `S1-input/S2-read` rather than one of them
- [ ] You can name three kinds of persistent device state that would invalidate a later measurement
- [ ] You removed the reverse tunnel and uninstalled the app

---

## Clean up

```bash
# host
adb reverse --remove tcp:27042
adb reverse --list                       # should be empty
cd 67-BypassingProtections
OUTDIR=/tmp/ch67 ./examples/build.sh --uninstall
adb shell am clear-debug-app
```

**Leave the device as you found it.** Everything in this lab is reversible and none of it required
root; keep it that way.

---

## Where to go next

- [Lab 02 — the escalation ladder](lab-02-escalation-ladder.md): you now know *that* the check ran at
  load time. Lab 02 gets you in front of it.
- [README §3.12](../README.md#312-timing-is-the-whole-game-init_array-jni_onload-and-why-attach-loses)
  for the precise sequence you have just observed from the outside.
- [37-RootDetection/labs/lab-03](../../37-RootDetection/labs/lab-03-trace-and-neutralise.md) for the
  same discipline applied to root detection specifically.
