# Lab 02 — The sheet lies: six commands that answer confidently and wrongly

> **Difficulty:** Intermediate
> **Time:** 90 minutes.
> **Prerequisites:** [Lab 01](lab-01-sixty-minute-triage.md). An Android device or emulator with
> `adb`. **Root helps but is not required** — rounds 3, 4 and 5 work without it, and round 1 is more
> instructive if you have root and think you might not.
> **Constraint:** for each round, you must state *how you knew* the answer was wrong **before** you
> are allowed to look at the reveal.

---

## 1. The challenge

Every command in this lab is real, appears in published Android security cheat sheets, and runs
cleanly. Every one of them returns an answer that is **plausible, confidently formatted, and wrong**
— on the device in front of you, right now.

None of them errors. That is the entire point.

> **🧠 Mental Model**
> A command that fails loudly costs you five seconds. A command that returns a *plausible wrong
> answer* costs you an hour, and sometimes costs you a report. The skill this lab builds is not
> knowing these six specific commands — it is the reflex of asking *"what would this print if it were
> lying to me?"* before you write the answer down.

Six rounds. For each one:

1. Run the **obvious** command exactly as printed.
2. Write down the answer it gives.
3. **Before reading the reveal**, write down at least one way you could check it independently.
4. Run your check.
5. Then open the reveal.

Keep a log. The log is the deliverable.

```
ROUND n
  obvious command  :
  answer it gave   :
  my cross-check   :
  what it showed   :
  verdict          : TRUE / FALSE / UNDETERMINED
  how I could have known without the cross-check :
```

---

## 2. Setup

```bash
# host — from 76-CheatSheets/
bash examples/03-session-preflight.sh --pkg <a debuggable package>
```

Record the output. Several rounds depend on knowing the build type and page size, and one of the
lies is *only* visible because you know which device you are on.

If you have no debuggable package to hand, build a one-activity "hello world" and install it with
`adb install -t`. Rounds 3 and 4 need an app vantage.

---

## 3. Round 1 — "Is this device rooted?"

### The obvious command

```bash
# host — the form that appears in dozens of published sheets
adb shell "su -c id"    # lint:allow -- this IS the round
```

Run it. Write down what it printed and what you would conclude.

### Your cross-check goes here

Before reading on: what else could tell you whether this device has root? Think of at least two
answers and run them.

<details>
<summary>Reveal — Round 1</summary>

On the AVD used to write this chapter (`sdk_gphone16k_x86_64`, Android 15 / API 35, `userdebug`),
that command prints:

```
su: invalid uid/gid '-c'
```

and exits 1. Read as an answer, it says **"this device is not rooted."**

It is rooted. Magisk 30.7, `magiskd` running as root.

```
$ adb shell "su 0 id"
uid=0(root) gid=0(root) groups=0(root),1004(input),... context=u:r:su:s0
```

**Why the lie is so effective:** the message is about `su` — it looks like the kind of thing a
non-existent or restricted `su` would say. It does not say "wrong syntax". AOSP's `su`, which ships
on every `userdebug` build and every emulator, takes `su <uid> <cmd>`. The `-c` form belongs to
Magisk's `su` on a phone.

At least three chapters of this repository hit this independently, and one nearly recorded the device
as unrooted on that basis.

**Two independent cross-checks that need no root at all:**

```bash
# host
adb shell 'grep -c magisk /proc/self/mountinfo'   # returned 3
adb shell 'ls -l /debug_ramdisk/magisk'           # -rwxr-xr-x root root 428416
```

`/proc/self/mountinfo` is readable from **every** vantage — shell, root and an app uid all returned
3 — which is exactly what makes it a usable signal.

**The correct sheet row** lists both forms and marks one broken:

<!-- lint:allow -- the row deliberately lists the broken form so nobody re-derives it -->
```
| `adb shell "su 0 id"`   | `root` | `all`  | AOSP su: every userdebug build, every AVD |
| `adb shell "su -c id"`  | `root` | `phys` | Magisk su on a phone. FAILS on AOSP su, in the shape of "not rooted" |
```
</details>

---

## 4. Round 2 — "What version of Magisk is installed?"

Skip this round if the device is not rooted; go to Round 3.

### The obvious commands

```bash
# host — two published forms, run both
adb shell "su -c 'magisk -v'"     # lint:allow -- this IS the round
adb shell "su 0 magisk -v"
```

### Your cross-check

How would you get a version number you can actually trust?

<details>
<summary>Reveal — Round 2</summary>

<!-- lint:allow -- transcript of the failing forms; this IS Round 2 -->
```
$ adb shell "su -c 'magisk -v'"
su: invalid uid/gid '-c'

$ adb shell "su 0 magisk -v"
su: failed to exec magisk: No such file or directory

$ adb shell "su 0 /debug_ramdisk/magisk -v"
30.7:MAGISK:R
```

**Three distinct failures, and only the third command works.**

1. The `su -c` form, as in Round 1.
2. **Even on a device where `su -c` is accepted, the flag is eaten.** `adb shell` does not preserve
   quoting: the whole line arrives at the device as separate argv words, so
   `adb shell "su -c 'magisk -v'"` <!-- lint:allow --> becomes `su -c magisk -v` and **`-v` is
   consumed by `su`**. The row prints *`su`'s* version under a heading that says "Magisk version",
   and nothing in the output says so. This repository has that exact row, in that exact broken
   form, in its own sheets.
3. `su 0 magisk` fails for a third reason entirely: `magisk` is not on root's `PATH` here.

```
$ adb shell "su 0 sh -c 'echo $PATH'"
/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin
```

No `/debug_ramdisk`. The absolute path is mandatory.

**The generalisation worth keeping:** a command that takes flags, run through a wrapper that
re-splits argv, will hand your flags to the wrapper. It applies to `su`, to `run-as`, to
`am instrument`, and to anything else you nest inside `adb shell`. Quote the whole thing, and prefer
forms where the wrapper cannot consume anything.
</details>

---

## 5. Round 3 — "Is Frida working on this device?"

This is the best round in the lab, because the misleading output is long, detailed, and completely
genuine.

### The obvious command

```bash
# host
frida-ps -U
```

Run it. Do you have working instrumentation?

### Your cross-check

<details>
<summary>Reveal — Round 3</summary>

On the AVD, `frida-ps -U` returns a full, correct process list — dozens of rows, real PIDs, real
process names, `zygote64` at the bottom.

There is **no `frida-server` running.** Checked from both vantages:

```
$ adb shell 'ps -A' | grep -i frida
$ echo $?
1
$ adb shell 'su 0 ps -A' | grep -i frida
$ echo $?
1
```

And an actual attach fails:

```
$ frida -U -n zygote64 -e 'console.log("HOOKED")' -q
Failed to attach: unable to connect to remote frida-server: closed
$ echo $?
1
```

The `frida-server` binary is sitting on the device and will not load on this image:

```
$ adb shell "su 0 /data/local/tmp/frida-server --version"
CANNOT LINK EXECUTABLE "/data/local/tmp/frida-server": empty/missing DT_HASH/DT_GNU_HASH in
"/data/local/tmp/frida-server" (new hash type from the future?)

$ adb shell "su 0 sh -c '/data/local/tmp/frida-server --version >/dev/null 2>&1; echo devrc=$?'"
devrc=1
```

**Why `frida-ps` works anyway:** Frida's Android backend enumerates processes **over adb**. It needs
no agent, no injection and no server. A successful `frida-ps -U` proves your ADB connection works and
proves precisely nothing about instrumentation.

This is the first command almost everybody runs, and it is the most misleading "it's working" signal
in the Android tooling stack.

**The test for instrumentation is an attach.** Put this in your own preflight:

```bash
# host
frida -U -n <any running process> -e 'console.log("ok")' -q
```

**A second lesson hides in the same round.** The first time that attach was run through `| head`, the
pipeline reported exit 0 despite the failure. Exit status is not a reliable channel here either —
test the content.
</details>

---

## 6. Round 4 — "Does `/system/xbin/su` exist?"

### The obvious commands

```bash
# host
adb shell 'ls -l /system/xbin/su'
adb shell "run-as <your-debuggable-pkg> sh -c 'test -e /system/xbin/su && echo EXISTS || echo NO'"
```

Two commands, one question. Run both.

### Your cross-check

<details>
<summary>Reveal — Round 4</summary>

```
$ adb shell 'ls -l /system/xbin/su'
-rwsr-x--- 1 root shell 51224 2025-01-23 23:03 /system/xbin/su

$ adb shell "run-as com.example.debuggable sh -c 'test -e /system/xbin/su && echo EXISTS || echo NO'"
NO
```

**Same file, same instant, opposite answers.** `/system/xbin` is mode `0750 root:shell`. `adb shell`
is in the `shell` group; an application uid is not.

The consequence for real code is worse than "opposite", because `File.exists()` collapses three
different conditions into one boolean:

| Real condition | `errno` | `File.exists()` |
|---|---|---|
| Absent | `ENOENT` | `false` |
| Present but forbidden | `EACCES` | `false` |
| Ancestor directory unlistable | `EACCES` | `false` |

So `new File("/system/xbin/su").exists()` returns `false` **on a rooted device** — the only kind of
device where it could ever matter. The most-copied root check in Android security has zero
discriminating power exactly where it is needed.

And there is a second error stacked on the first. On a `userdebug` AVD, `/system/xbin/su` is **AOSP's
own `su`**, included in the build by design. It is not what grants root here:

```
$ adb shell 'ls -l /system/bin/su /debug_ramdisk/su'
ls: /system/bin/su: No such file or directory
lrwxrwxrwx 1 root root 8 ... /debug_ramdisk/su -> ./magisk
```

The probe fires from the shell on a harmless binary and misses the thing that actually grants root,
from the vantage that actually matters. Both errors at once.

Reproduce the whole table in one command:

```bash
# host — from 76-CheatSheets/
bash scripts/vantage.sh --file /system/xbin/su --pkg <your-debuggable-pkg>
```
</details>

---

## 7. Round 5 — "Did the pipeline succeed?"

No device needed. Run this on your host.

### The obvious script

<!-- lint:allow -- the buggy pipeline IS Round 5 -->
```bash
# host — careful, idiomatic shell
bash -c '
set -euo pipefail
seq 1 5000000 | head -3 > /dev/null || echo "no output — the producer failed"
echo "reached the end"
'
```

Does it print the fallback? Should it?

### Your cross-check

<details>
<summary>Reveal — Round 5</summary>

Measured:

<!-- lint:allow -- the failing pipelines are the point -->
```
$ bash -c 'set -o pipefail; yes | head -3 >/dev/null; echo $?'
141
$ bash -c 'set -o pipefail; seq 1 100000 | grep -q 5; echo $?'
141
$ bash -c 'set -o pipefail; seq 1 100000 | grep -c 5 >/dev/null; echo $?'
0
$ bash -c 'set -o pipefail; seq 1 10000 | head -3 >/dev/null; echo $?'
0
```

`head` and `grep -q` exit the instant they have what they need. That closes the pipe; the writer
upstream dies of `SIGPIPE` (128 + 13 = 141); `pipefail` promotes the writer's status to the
pipeline's. **The `||` fallback fires because the command succeeded.**

The last line is why this is so hard to diagnose. With a *small* producer the writer finishes before
the consumer closes the pipe, and the status is 0. The same script passes against a small library and
fails against a large one, and the error message always blames the data.

In one real script in this repository this printed **"not a JNI library" directly below a list of
that library's JNI exports.** It cost another author an hour on a different chapter, from the
opposite direction: `printf … | grep -q PATTERN || fallback` reporting failure against a binary that
plainly contained every string it was looking for.

**The fix is to test content, not status:**

```bash
# host
n=$(readelf --dyn-syms lib.so | grep -c '^Java_')     # grep -c reads ALL its input
if [ "$n" -eq 0 ]; then
    echo "no statically-registered JNI symbols (RegisterNatives is still possible)"
fi
```

Note the second change in that snippet. The negative branch stopped overclaiming — "no `Java_`
symbols" and "not a JNI library" are different statements, because dynamic registration through
`RegisterNatives` in `JNI_OnLoad` leaves no mangled symbols at all.
</details>

---

## 8. Round 6 — "Is this an emulator?"

### The obvious check

Here is the most-copied `isEmulator()` on the internet, reduced to the two lines that do the work:

```java
// The shape that appears in thousands of apps.
boolean isEmulator() {
    return Build.FINGERPRINT.startsWith("generic")
        || new java.io.File("/dev/qemu_pipe").exists();
}
```

Evaluate both halves from the shell:

```bash
# host
adb shell getprop ro.build.fingerprint
adb shell 'ls /dev/qemu_pipe'
```

### Your cross-check

<details>
<summary>Reveal — Round 6</summary>

On a stock current AVD:

```
$ adb shell getprop ro.build.fingerprint
google/sdk_gphone16k_x86_64/emu64xa16k:15/AE3A.240806.043/12960925:userdebug/dev-keys

$ adb shell 'ls /dev/qemu_pipe'
ls: /dev/qemu_pipe: No such file or directory

$ adb shell 'ls /dev/goldfish_pipe_dprctd'
/dev/goldfish_pipe_dprctd
```

The fingerprint does **not** begin with `generic`. The node has **moved**. Both halves return
`false`, so the function returns `false` on an emulator.

Two further inversions from the same family, worth knowing because they are worse than merely dead:

- **"A property whose name contains `qemu` means emulator."** A retail phone this repository has used
  sets `qemu.hw.mainkeys=0` and `ro.kernel.qemu.gles=0`; the AVD sets neither. The heuristic calls
  the phone an emulator and the emulator a phone.
- **"Emulators are slower."** Inverted by 1.47× — identical C, same NDK, same app uid: 2.398 ns/iter
  on the AVD against 3.516 on the phone. Modern AVDs virtualise on the host CPU; they do not
  interpret.

One signal *did* still work here, and reporting only the one you measured is the honest form:

```
$ adb shell getprop ro.kernel.qemu
1
```

Visible from all three vantages. But one working member does not rehabilitate the family, and the
strongest real signals are **populations and structure, not values** — sensor counts and their
vendors, the ABI list, the presence of a native bridge.
</details>

---

## 9. Review

### 9.1 Score your own detection, not your knowledge

For each round, one of three:

| | Meaning |
|---|---|
| **Caught it** | You wrote a cross-check that would have exposed the lie, before the reveal |
| **Suspected it** | You felt something was off but could not name the check |
| **Believed it** | You wrote the answer down |

Most people believe rounds 3 and 5 the first time. Round 3 in particular, because the output is so
detailed and so genuine.

### 9.2 The pattern behind all six

Write it out yourself before reading this.

<details>
<summary>What the six have in common</summary>

Every one of them **answers a narrower question than the one you asked**, and reports the answer in
the vocabulary of the wider one.

| You asked | It actually answered |
|---|---|
| Is this rooted? | Does this `su` accept `-c`? |
| What Magisk version? | What version does the binary that got the `-v` flag report? |
| Can Frida instrument? | Can adb enumerate processes? |
| Does the file exist? | Can *this uid* see the file? |
| Did the pipeline succeed? | What status did the writer exit with? |
| Is this an emulator? | Does this specific 2014-era artefact exist? |

That is also, precisely, the shape of the link-checker defect this repository recorded against itself
— a check reporting "no broken links" that meant "no broken links outside an excused category nobody
had audited", which hid 1,512 of them. And it is the shape of this repository's first `su -c`
detector, which found 79 of 376 occurrences because its pattern could not see the double-quoted form.

**A detector's blind spot is invisible in its output.** The only defence is to ask what narrower
question the command is really answering, and then to close the arithmetic — explain every hit, and
go looking for the ones you did not get.
</details>

### 9.3 Turn each round into a row

Six rounds, six rows, to the standard in
[`../examples/01-anatomy-of-a-sheet-row.md`](../examples/01-anatomy-of-a-sheet-row.md): the broken
form marked broken, the working form with its `Needs` and `Device`, and the failure shape stated.

Then lint your own file:

```bash
# host — from 76-CheatSheets/
python3 -B scripts/lint-commands.py --path /path/to/your-rows.md --no-fail
```

If you wrote the broken forms as counter-examples on purpose, mark them:

```
adb shell su -c 'id'        # lint:allow SU-DASH-C SU-DASH-C-BARE
```

Rule ids match **exactly** — `lint:allow SU-DASH-C` does not also silence `SU-DASH-C-BARE`. Use a
bare `lint:allow` when you mean the whole line, and a marker on the line above a fence to cover a
whole block.

---

## 10. Success criteria

- [ ] A log for all six rounds with a cross-check written **before** each reveal.
- [ ] Each round scored *caught it / suspected it / believed it*, honestly.
- [ ] The common pattern in §9.2 written in your own words before reading it.
- [ ] Six sheet rows produced, each naming the broken form as well as the working one.
- [ ] Your rows pass `lint-commands.py`, or every finding is a marked counter-example.
- [ ] One sentence in your notes naming a command you rely on **outside this lab** that might be
      answering a narrower question than you think.

That last one is the whole lab.

---

## 11. Extension — find a seventh

Somewhere in the sheets you use daily is a command with this shape. Candidates, all of which this
repository has measured:

| Candidate | The narrower question it really answers |
|---|---|
| `pm list instrumentation` | Which packages *declare* instrumentation — blind to residue. A stock 247-package device reported **zero rows**; a 38-APK structural scan of the same device found 1 declared and 1 residue |
| A `grep` over APKs for a short token | Does this byte sequence occur? `grep -i xposed` matched 1,141 times across 237 APKs, **all** of them the word "exposed" |
| jadx's `finished with errors, count: N` | How many errors did the console summariser count? The output tree held **2,104** refused methods against a console figure of 61 |
| `ls -l *.apk` after enabling shrinking | How big is the padded file? Three APKs were **byte-identical** at 12,757 B with DEX sizes of 7,384 / 2,920 / 7,180 |
| A key attestation chain that verifies | Is the chain well-formed? On an emulator every key is `SOFTWARE` and the chain still verifies perfectly |
| `ro.boot.verifiedbootstate` | What string did a property whose value is attacker-controllable return? One device read `green` while a TEE-signed attestation from the same device said `Unverified` |

Pick one you actually use. Reproduce it. Write the row.

---

## See also

- [`lab-01-sixty-minute-triage.md`](lab-01-sixty-minute-triage.md) — where the sheets *are* enough
- [`lab-03-build-your-own-sheet.md`](lab-03-build-your-own-sheet.md) — writing rows that do not lie
- [`lab-04-ctf-the-stale-sheet.md`](lab-04-ctf-the-stale-sheet.md) — the same skill, adversarial
- [`../README.md`](../README.md) §6 — thirty-three more of these
- [`../examples/02-vantage-transcript.md`](../examples/02-vantage-transcript.md) — the raw session
  behind rounds 1, 3 and 4
