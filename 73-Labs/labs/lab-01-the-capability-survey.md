# Lab 01 — The capability survey: what your setup can actually run

> **Objective.** Produce an evidence-backed manifest of which of this repository's labs the machine
> in front of you can run **today**, which are blocked, and — the part that matters — which of the
> blocks are purchases, which are installs, and which are impossibilities that no amount of effort
> will move. You will finish with a file you can re-generate in one command whenever your setup
> changes.

**Difficulty:** Beginner
**Time:** 60–90 minutes
**Prerequisites:** [Chapter 73 §1–§3.4](../README.md#1-introduction). A working toolchain — if you
do not have one yet, build it first with
[00-Introduction lab 01](../../00-Introduction/labs/lab-01-build-your-lab.md), which installs the
tools this lab **measures**.
**Device used to verify this lab:** AVD `sdk_gphone16k_x86_64` (`emulator-5554`), Android 15 / API
35, x86_64, `userdebug`, rooted with Magisk 30.7. Every block of output in §4 was produced on that
device on 2026-08-16, and §4.6 lists what it could *not* establish.

---

## 1. Why this lab exists

There are two very different documents you could write about a lab environment, and only one of them
is useful after the first week.

The first is an installation guide. It tells you to install a JDK, then the Android SDK, then Frida,
and it is finished when the last command prints a version number. That document already exists in
this repository, it is [00-Introduction lab 01](../../00-Introduction/labs/lab-01-build-your-lab.md),
and it is good. **This is not that document.**

The second answers a question the first cannot: *given the machine I actually have — with its
missing tools, its emulator instead of a phone, its Frida that half works — which of the 327 labs in
this repository can I do right now?* That question has no answer in any individual chapter, because
no chapter knows what the others require. It is the aggregator's question, and it is this one.

> **🧠 Mental Model.** An installation guide is a shopping list. A capability survey is an inventory.
> The shopping list is written once and thrown away; the inventory is re-taken every time the
> kitchen changes, and it is the only one of the two that can tell you what you are able to cook
> tonight.

The distinction has a practical edge. Roughly **59 % of this repository's labs are blocked on the
setup used to verify this chapter**, and almost all of that is one missing capability. If you do not
measure, you discover each block one lab at a time, forty minutes in, having already built the
target. Measuring costs ninety seconds.

### 1.1 What breaks without this

Three specific failures, all of which have happened to somebody writing this repository:

- **Reading a tool failure as a device fact.** `su -c id` fails on the API 35 AVD with
  `su: invalid uid/gid '-c'`. That is `su` rejecting a flag, not a device refusing root. A chapter
  nearly recorded that emulator as unrooted on exactly this evidence.
- **Reading a host version as a device capability.** `frida --version` on the host prints `16.1.6`
  on the machine used here, and `frida-ps -U` cheerfully lists processes. Neither fact means Frida
  works, and on this device it does not: the server binary fails to link. **A capability that spans
  two machines must be measured at both ends.**
- **Attempting something the hardware cannot do.** An AVD has no bootloader and no secure element.
  Labs about attestation or flashing are not *harder* there; they are unanswerable, and running them
  anyway teaches you a wrong answer with a straight face.

---

## 2. Setup

You need only this repository and a shell. A device is optional for the first half and required for
the second; the script degrades honestly when there is no device.

```bash
# host — from the repository root
cd 73-Labs
python3 -B scripts/lab-env-probe.py --help | head -20
```

> **⚠️ Warning.** Run every Python command in this chapter with `-B`. Without it, CPython writes
> `__pycache__` directories into the repository, and `.pyc` files are on the repository's artefact
> blocklist — the artefact sweep in [§8.2](../README.md#82-the-checks-this-repository-runs-on-itself)
> fails on them. **`PYTHONDONTWRITEBYTECODE=1` is not a substitute**: a script that uses
> `importlib.util.module_from_spec` writes bytecode regardless of it, which is how this repository
> acquired stray `__pycache__` directories twice. The habit is cheaper than the cleanup.

The probe changes nothing. Every device command it issues is a read; the most invasive is `su 0 id`,
and it runs that because there is no honest way to establish root without asking for it.

---

## 3. Part 1 — Establish the device before you trust anything it says

Do this **by hand first**, before running the script. The script automates it, but a number you have
never produced yourself is a number you cannot defend.

### 3.1 Identity

```bash
# host
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
adb shell getprop ro.product.cpu.abi
adb shell getprop ro.build.type
```

Measured here:

```
emulator-5554  device product:sdk_gphone16k_x86_64 model:sdk_gphone16k_x86_64 device:emu64xa16k
sdk_gphone16k_x86_64
15
35
x86_64
userdebug
```

> **🔍 Pentester's Note.** Record the serial, not just the model. This repository has had two
> physical devices swapped mid-session without warning, and an emulator answer attached to a phone's
> serial in a report is worse than no answer at all. If two devices are attached, every `adb`
> command in every lab needs `-s <serial>` and the labs mostly do not say so.

### 3.2 The `su` form — measure both, assume neither

This is the single most misread signal in the repository.

```bash
# host — run BOTH. One of them will fail, and that is not the finding.
adb shell "su 0 id"
adb shell "su -c id"
```

Measured here:

```
uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),... context=u:r:su:s0
su: invalid uid/gid '-c'
```

The device is rooted. The second command failed because this AVD's `su` is AOSP's, whose first
positional argument is a **uid**, so it parsed `-c` as a user name and rejected it. A Magisk `su` on
a typical phone accepts `-c` and would answer the other way round.

> **⚠️ Warning — the third form, which is broken everywhere.**
> <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- the broken form, quoted as the counter-example this warning teaches -->
> `adb shell su -c 'id'` is **not** a third option; it is a bug. The outer shell strips the quotes
> before `su` ever sees them, so `su` receives `-c` and `id` as separate words and, depending on
> which `su` you have, either runs only `id` or rejects the flag. If you must use the `-c` form,
> quote the whole remote command: `adb shell "su -c 'id'"`. On this AVD, use `su 0 <cmd>`.

Write down which form works. Every device-side command in every lab you do from here depends on it.

### 3.3 The three cheap facts that change what labs mean

```bash
# host — note the quotes on the third one. They are not optional; see below.
adb shell getenforce
adb shell getconf PAGE_SIZE
adb shell "ls /dev/block/by-name"
```

Measured here:

```
Enforcing
16384
metadata  super  vbmeta  vda  vdd
```

> **⚠️ Warning — this exact command, unquoted, is broken on Windows.** Under Git Bash/MSYS, an
> argument that looks like an absolute POSIX path is rewritten before `adb` ever sees it. Measured:
>
> ```
> $ adb shell ls /dev/block/by-name        # lint:allow MSYS-PATHCONV -- the broken form, on purpose
> ls: C:/Program: No such file or directory
> ls: Files/Git/dev/block/by-name: No such file or directory
> ```
>
> The device path became a *host* path. Quote the remote command — `adb shell "ls /dev/block/by-name"`
> — or set `MSYS_NO_PATHCONV=1`. The same trap eats `adb push`'s remote argument, which is why
> [`build-chain-target.sh`](../examples/build-chain-target.sh) wraps every `adb` call that carries a
> device path. **This defect was in the first draft of this very lab**, and it was found by
> [`76-CheatSheets/scripts/lint-commands.py`](../../76-CheatSheets/scripts/lint-commands.py) rather
> than by re-reading — which is the argument for mechanical checks in one sentence.

Each of these is load-bearing:

| Fact | Measured | What it changes |
|---|---|---|
| SELinux | `Enforcing` | Denials in the SELinux labs are real, not simulated. A `Permissive` device silently passes tests it should fail |
| Page size | `16384` | **16 KiB pages.** A naively linked native binary segfaults here. Every native lab needs `-Wl,-z,max-page-size=16384` |
| Partitions | no `boot`, no `recovery` | There is **no bootloader to talk to.** Every `fastboot flash` lab is unrunnable, at any privilege level |

> **🔬 Under the Hood.** The page-size result is not cosmetic. The kernel maps a shared object at
> page granularity; if a binary's program headers assume 4 KiB alignment and the kernel enforces
> 16 KiB, the segments cannot be placed as the linker intended and the process dies with SIGSEGV
> before `main`. This repository measured `int main(void){return 42;}` exiting **139** on this exact
> image. The failure has nothing to do with your code.

### 3.4 The two-ended capability: Frida

```bash
# host
frida --version
adb shell "su 0 ls -l /data/local/tmp"
adb shell "su 0 /data/local/tmp/frida-server --version"
```

Measured here — and read all three lines before drawing a conclusion:

```
16.1.6
-rwxr-xr-x 1 shell shell 108228344 2026-07-23 13:37 frida-server
...several hundred lines of: WARNING: linker: ... unused DT entry: unknown (type 0xa00010a arg 0x0)
CANNOT LINK EXECUTABLE "/data/local/tmp/frida-server": empty/missing DT_HASH/DT_GNU_HASH in
"/data/local/tmp/frida-server" (new hash type from the future?)
```

The host tool is fine. The binary is present, executable, and the right architecture. It still does
not run, because it was built with a toolchain newer than this image's dynamic linker understands.

> **🔍 Pentester's Note — the trap inside the trap.** `frida-ps -U` **still lists processes** on this
> device. The failure only appears when you try to attach. If you check Frida by running `frida-ps`,
> you will conclude it works and then spend an hour debugging a script that was never going to run.
> Check by executing the server.

**This single capability blocks 134 labs here.** It is also the cheapest to fix: replace the binary
with a release matching the image's linker. That is the difference between a block that is a
purchase and a block that is a download, and the whole point of the survey is to tell them apart.

---

## 4. Part 2 — Run the survey

### 4.1 The probe alone

```bash
# host — from 73-Labs
python3 -B scripts/lab-env-probe.py
```

This prints two blocks — host, then device — with a `yes`/`NO` per capability and the evidence for
each. Read it and check it against what you measured by hand in Part 1. **If the script and your
hands disagree, the script is wrong**; that is the direction the correction has always gone in this
repository, and there is a defect note in §7 about one such disagreement.

### 4.2 The probe matched against the corpus

```bash
# host
python3 -B scripts/lab-env-probe.py --match
```

Measured here, in full:

```
==============================================================================
HOST
==============================================================================
  [yes] adb                    Android Debug Bridge version 1.0.41
  [yes] JDK (javac)            javac 24.0.2
  [yes] Kotlin compiler        found at C:\Program Files\Android\Android Studio\plugins\Kotlin\kotlinc\bin\kotlinc.bat (not on PATH)
  [yes] Android SDK build-tools build-tools 34.0.0, 35.0.0, 35.0.1; platforms android-35
  [yes] Android NDK            C:\Users\harsh\AppData\Local\Android\Sdk\ndk\25.2.9519653
  [yes] Python 3               Python 3.13.3
  [yes] Frida (host)           16.1.6
  [yes] Objection              You have v1.11.0 and v1.12.5 is ready for download.
  [yes] jadx                   1.5.3
  [NO ] apktool                found on PATH but did not execute: no such executable
  [NO ] Ghidra                 not on PATH
  [NO ] radare2                not on PATH
  [yes] Docker                 Docker version 28.0.4, build b8034c0
  [NO ] mitmproxy              not on PATH

==============================================================================
DEVICE
==============================================================================
  [yes] attached               emulator-5554 (1 attached)
  [yes] identity               sdk_gphone16k_x86_64  Android 15 / API 35  x86_64  userdebug
  [yes] emulator               model=sdk_gphone16k_x86_64, qemu=1, serial=emulator-5554
  [yes] selinux                Enforcing
  [yes] pagesize               16384
  [yes] root                   uid=0(root) context=u:r:su:s0  [working form: su 0 <cmd>]
  [NO ] frida-server           present but does not run: CANNOT LINK EXECUTABLE
                               "/data/local/tmp/frida-server": empty/missing DT_HASH/DT_GNU_HASH
  [NO ] bootloader             ro.bootmode=unknown; by-name: metadata super vbmeta vda vdd

Capability tags satisfied: device, docker, jadx, jdk, ndk, no-device, no-root, objection,
                           python, root

==============================================================================
LABS
==============================================================================
  runnable here : 140 / 327
  blocked       : 187 / 327

  Blocked by:
    frida       128 labs
    apktool      72 labs
    ghidra       14 labs
    xposed       14 labs
    radare2       8 labs
    physical      8 labs
    proxy         6 labs
    mobsf         6 labs
    aosp          4 labs
    ida           4 labs
```

> **⚠️ Warning — your totals will not match these, and that is correct.** The denominator counts a
> repository that changes. Captured mid-write, this same block read `131 / 315`; two chapters landed
> and it now reads `140 / 327`. **A generated number is a measurement with a timestamp, not a
> constant.** If your run differs, compare the *shape* — which capability blocks the most — rather
> than the digits.

> **📖 Definition — capability tag.** A short identifier such as `root`, `frida` or `no-device`,
> derived from a lab's own text by
> [`build-lab-index.py`](../scripts/build-lab-index.py). A tag means *this lab issues a command
> using this thing, or names it in its own prerequisites block.* It does not mean the word appears
> somewhere in the file. See [§3.6 of the chapter README](../README.md#3-deep-internal-working) for
> why that distinction had to be made, and what it cost to get wrong.

### 4.3 Reading the number that matters

`140 / 327` is not the interesting figure. The interesting figure is the blocked table, because it
sorts into three classes that behave completely differently:

| Class | On this setup | What to do |
|---|---|---|
| **A download away** | `frida` (128), `apktool` (72), `radare2` (8), `mitmproxy` (6) | Do this before anything else. Measured below: it is by far the highest-leverage hour available |
| **A licence or a large install away** | `ghidra` (14), `xposed` (14), `mobsf` (6), `ida` (4), `aosp` (4) | Ghidra is free; IDA is not. MobSF wants Docker, which is present here. LSPosed needs Zygisk, which is off on this AVD. An AOSP checkout is hundreds of gigabytes and days of build time |
| **Not obtainable here at all** | `physical` (8), and everything needing a bootloader | Read the chapter, skip the lab, and **say so in your notes.** These are the ones people quietly fake |

Note the shape of that: **the great majority of blocked labs on this setup are blocked by things you
can download.** Without the survey you would not know that, and you would probably conclude the
emulator was the problem. It is not; the emulator accounts for 8 labs out of 187.

### 4.4 Ask the index *why*

Never accept a requirement claim you cannot audit. Every tag carries the line of the lab that
produced it:

```bash
# host
python3 -B scripts/build-lab-index.py --why 53-Frida/labs/lab-01-first-contact.md
```

Measured here:

```
53-Frida/labs/lab-01-first-contact.md
  title      : Lab 01 — First Contact
  difficulty : Beginner   (declared: Beginner)
  time       : 60–90 minutes
  lines      : 466
  tags:
    device       <- (the "AOSP" images) is rooted by default via `adb root`, which makes this lab friction-free:
    frida        <- python3 -m pip install --upgrade frida-tools
    python       <- python3 -m pip install --upgrade frida-tools
    root         <- a rooted device or emulator
```

Read those evidence lines critically, because one of them is weak. `frida` and `python` are both
justified by the same `pip install frida-tools` line, which is exactly right. `root` is justified by
the lab's own prerequisites line, which is the strongest kind of evidence there is. But `device` is
justified by a sentence in the middle of a paragraph that merely happens to contain `adb root` — the
tag is correct, and the evidence for it is nearly an accident.

> **🔍 Pentester's Note.** That is what an auditable index buys you: not certainty, but the ability
> to see *how* certain each claim is. A tag with a prerequisites line behind it and a tag with a
> passing prose mention behind it look identical in a table and are not the same claim. If a tag
> looks wrong, the evidence line tells you immediately whether the lab is ambiguous or the detector
> is. Both have happened; §7 records one of each.

### 4.5 List them

```bash
# host — what can I do right now
python3 -B scripts/lab-env-probe.py --match --list runnable

# host — what is blocked, and by exactly what
python3 -B scripts/lab-env-probe.py --match --list blocked

# host — one chapter
python3 -B scripts/lab-env-probe.py --match --chapter 27
```

### 4.6 What this survey did **not** establish

An honest inventory states its own gaps, and this one has four:

- **It did not test Burp.** Burp Suite is a GUI with no version flag that can be probed this way, so
  `proxy` reads absent on a machine that may well have it. Use `--assume proxy`. The script says so
  in its own output rather than quietly reporting zero.
- **It did not verify the system CA store.** This repository has measured a physical device whose
  system trust store had been modified by a rooting module, which invalidates every naive TLS test
  performed on it. The probe does not check for that; chapters 35 and 44 do.
- **It did not check the Frida *version match*.** It establishes that the server runs or does not.
  A server that runs but is a different major version from the host client will fail differently and
  later.
- **It did not decide whether a runnable lab is a good use of your time.** That is what
  [`references/learning-paths.md`](../references/learning-paths.md) is for.

---

## 5. Part 3 — Turn the survey into a manifest you keep

A survey you ran once and read is worth little. Write it down in a form you can diff.

```bash
# host — from 73-Labs. Note the output goes OUTSIDE the repository.
python3 -B scripts/lab-env-probe.py --match --json > "$HOME/android-lab-manifest.json"
```

Then, whenever anything changes — a new phone, a Frida upgrade, an SDK update — re-run it and
compare:

```bash
# host
python3 -B scripts/lab-env-probe.py --match --json > "$HOME/android-lab-manifest.new.json"
diff <(python3 -m json.tool "$HOME/android-lab-manifest.json") \
     <(python3 -m json.tool "$HOME/android-lab-manifest.new.json") | head -40
```

> **⚠️ Warning.** Write the manifest outside the repository, as above. It contains absolute paths
> from your machine, and it is a build artefact of exactly the kind the repository's checks reject.

### 5.1 Plan a purchase before you make it

`--assume` lets you ask what a capability would buy you, without owning it:

```bash
# host — what would a working frida-server unlock?
python3 -B scripts/lab-env-probe.py --match --assume frida

# host — and if I also installed apktool, Ghidra and radare2?
python3 -B scripts/lab-env-probe.py --match --assume frida,apktool,ghidra,radare2
```

Measured on the setup above: the first takes runnable from **140 to 210**; the second takes it to
**288 of 327**. That is the argument for spending the afternoon, stated as a number rather than as a
feeling — and note that a *working `frida-server`* alone is worth 70 labs, which is more than any
other single thing you could do to this machine.

---

## 6. Part 4 — The no-device case, taken seriously

Run the survey as though you had nothing but a laptop:

```bash
# host
python3 -B scripts/lab-env-probe.py --no-device --match
```

**58 labs in this repository carry the `no-device` tag.** That is not a consolation prize; it
includes much of chapters 10, 12, 32, 41, 42 and 56, which is to say much of static analysis. A
commute is enough for those.

The set is computed, not curated: a lab is tagged `no-device` only if it contains **no `adb`
invocation anywhere in the file**. That test is deliberately strict and it under-counts — a few labs
have an optional device section and would still be useful without it — but it never over-promises,
and for a filter that is the correct direction to be wrong in.

> **🔬 Under the Hood — why `--no-device --match` reports fewer than 58.** Measured here it reports
> **36 / 327**, not 58. The two numbers answer different questions. `no-device` counts labs that
> never touch a device; `--no-device --match` additionally requires every *other* tag to be
> satisfied, so a lab needing no device but needing Ghidra is still blocked. **A tag count is not a
> runnable count**, and conflating them is the same error as reading `frida --version` as a device
> capability.

```bash
# host — see the set, with the evidence for each
python3 -B scripts/build-lab-index.py --by requirement --out - | sed -n '/^## `no-device`/,/^## /p' | head -40
```

---

## 7. Two defects this lab found in its own tooling

Both are recorded because a lab that only shows its tools working is a demonstration, not a
measurement.

### 7.1 A tool reported present with the detail "not on PATH"

The first version of the probe printed:

```
  [yes] apktool                not on PATH
```

— a contradiction on one line. The cause: presence was decided by `shutil.which()`, which found an
`apktool` launcher on the **Windows** PATH that the Git Bash process could not actually execute, and
the code then discarded the exit status and returned `True` unconditionally. Presence is now decided
by **whether the process started**, and the output reads:

```
  [NO ] apktool                found on PATH but did not execute: no such executable
```

> **🧠 Mental Model.** *Finding a file is not the same as running a program.* This is the same shape
> as the repository's own encoding defect, where "it decodes as valid UTF-8" was mistaken for "it
> matches our convention". A check that answers a narrower question than the one it appears to
> answer is worse than no check, because it is trusted.

### 7.2 A device probe that read only the first line of output

The probe originally reduced every command's output to one line before inspecting it. That is right
for a version banner and catastrophic for `ls`: `ls /data/local/tmp` returned
`dalvik-cache  frida-server`, the reducer kept `dalvik-cache`, and the probe reported **"no
frida-server in /data/local/tmp"** on a device where it was plainly present. The same bug truncated
the partition listing to `metadata`.

The lesson generalises past this script: **decide what you need from a command's output before you
decide how to shorten it.** Version detection wants one line; presence detection wants all of them.

---

## 8. Success criteria

You have finished this lab when **all** of the following are true.

- [ ] You can state your device's model, API level, ABI, build type and serial from memory of having
      read them, not from an assumption.
- [ ] You know which `su` form your device accepts, and you have seen the other one fail.
- [ ] You have executed your `frida-server` on the device — not `frida --version` on the host — and
      know whether Frida actually works for you.
- [ ] `python3 -B scripts/lab-env-probe.py --match` runs and you can explain every `NO` in its output.
- [ ] You have sorted your blocked labs into the three classes in §4.3, and can name at least one
      lab in each class.
- [ ] You have a manifest file outside the repository, and you know the command to regenerate it.
- [ ] You can say, for one specific lab, **why** the index claims it needs what it claims — by
      quoting the evidence line from `--why`.
- [ ] You have written down at least one thing the survey did **not** establish about your setup.

The last one is the difference between a survey and a boast.

---

## 9. If it did not work

| Symptom | Most likely cause | Check |
|---|---|---|
| `no device in adb devices` | Emulator not started, or the daemon was restarted under you | `adb kill-server && adb devices`; start the AVD before probing |
| Every device probe times out | Device is at the lock screen, or `adbd` is wedged | `adb shell echo ok`; if that hangs, `adb reconnect` |
| `root` reads `NO` but you rooted the device | You are on the wrong `su` form | Run both forms by hand (§3.2). This is the single most common false negative |
| `frida` reads `NO` with a host version present | The two-ended trap (§3.4) | Execute the server on the device; do not trust `frida-ps` |
| Runnable count differs from §4.2 | Chapters have changed since this lab was written | Expected and correct. The index is generated; the count is a measurement of a moving repository, not a constant |
| `__pycache__` appears in `scripts/` | You omitted `-B` | Delete it, and add `-B` to your muscle memory |

If a *lab* rather than the survey fails to reproduce, that is a different problem with its own
procedure: [§11.4 of the chapter README](../README.md#11-common-mistakes) and
[Lab 03 §7](lab-03-write-a-lab-that-survives.md#7-when-your-own-lab-does-not-reproduce).

---

## 10. Where this goes next

| Next | Why |
|---|---|
| [Lab 02 — the chain no chapter can host](lab-02-the-chain-no-chapter-can-host.md) | You now know what you can run. Run the one thing no single chapter can hold |
| [`references/learning-paths.md`](../references/learning-paths.md) | Five ordered routes; pick the one matching your goal and your survey |
| [`references/lab-index-by-requirement.md`](../references/lab-index-by-requirement.md) | The full tag tables, with evidence lines |
| [00-Introduction lab 01](../../00-Introduction/labs/lab-01-build-your-lab.md) | If the survey told you to go install things |
