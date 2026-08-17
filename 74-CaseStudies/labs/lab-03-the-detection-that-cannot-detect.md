# Lab 03 — The detection that cannot detect

> **Level:** Intermediate · **Time:** 2 hours · **Needs:** a rooted device or AVD, and **one
> debuggable package**. Parts 1–3 work without root; Part 4 needs it.

---

## What this lab is

You will run the same command three times, as three different users, and get three different
answers. Then you will use that to demonstrate that the most-copied root-detection check in Android
returns the identical answer whether or not the thing it looks for is present.

Then — and this is the part that matters — you will apply the same method to a published measurement
of your own choosing, and find out whether it reproduces.

**Objective.** By the end you will never again verify a detection probe from `adb shell`, you will be
able to explain why `File.exists()` structurally cannot answer the question people ask it, and you
will have re-run at least one published claim yourself.

**Prerequisites.** [02-Linux-Basics](../../02-Linux-Basics/README.md) for file modes and `errno`;
[22-SELinux](../../22-SELinux/README.md) helps for Part 5 but is not required.

---

## Part 0 — Setup

```bash
# host
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.sdk
```

Find a debuggable package. You need one; without it there is no app vantage and the lab has no point.

```bash
# host -- the chapter ships this
./../scripts/vantage-diff.sh --find-package
```

If nothing is usable, build a minimal debuggable APK — any app with
`android:debuggable="true"` will do — or use `com.android.settings`-style AOSP debug builds if your
device is `userdebug`.

> **⚠️ Two traps, both of which this repository has paid for.**
> **First:** if you write your own enumeration loop, redirect stdin on every `adb` call. `adb shell`
> inherits stdin and will consume a surrounding `while read` loop's input, so the loop processes one
> item and exits cleanly — looking exactly like a device with nothing on it. Chapter 64 printed one
> row of a thirteen-row table this way and did not notice. Write `adb shell ... < /dev/null`.
> **Second:** determine your `su` convention before assuming you have no root. Physical devices with
> Magisk take `su -c '<cmd>'`; the AOSP emulator takes `su 0 <cmd>` and rejects `-c` with
> `su: invalid uid/gid '-c'`, which reads exactly like an unrooted device. Three chapters here have
> been caught by that.

| Record | Value |
|---|---|
| Model / API | |
| Root form | |
| Debuggable package | |

---

## Part 1 — The check, and the way people test it

Here is the check. It appears in an enormous amount of shipped code, essentially verbatim:

```java
if (new File("/data/adb/lspd").exists()) {
    // the device has a hooking framework installed
}
```

And here is how it gets tested, which is the whole problem:

```bash
# host -- the "verification" that convinces everybody
adb shell "ls -l /data/adb/lspd"
```

### ⏸ STOP 1

Before running anything:

1. What are the possible outcomes of `File.exists()`? How many distinct **realities** could produce
   each outcome?
2. Is `adb shell` a good proxy for an application? Write down one specific way it differs.

---

## Part 2 — Three vantages

Run the same probe three ways. Substitute your package and your `su` form.

```bash
# host
PKG=<your.debuggable.package>

echo "root :"; adb shell "su 0 ls -ld /data/adb/lspd"
echo "shell:"; adb shell "ls -ld /data/adb/lspd"
echo "app  :"; adb shell "run-as $PKG ls -ld /data/adb/lspd"
```

Now the parent directory, which is where the answer actually lives:

```bash
# host
echo "root :"; adb shell "su 0 ls -ld /data/adb"
echo "shell:"; adb shell "ls -ld /data/adb"
echo "app  :"; adb shell "run-as $PKG ls -ld /data/adb"
```

### ⏸ STOP 2

Fill this in from your own device:

| Path | root | `shell` | app | `File.exists()` from the app |
|---|---|---|---|---|
| `/data/adb` | | | | |
| `/data/adb/lspd` | | | | |

1. Do root and the app agree about whether `/data/adb/lspd` exists?
2. **Where does the refusal happen?** Not "at the file" — be precise.
3. What is the mode on `/data/adb`?

<details>
<summary><b>What the reference AVD shows — Magisk 30.7, LSPosed NOT installed</b></summary>

```
/data/adb
  root : drwx------ 6 root root 4096 /data/adb
  shell: ls: /data/adb: Permission denied
  app  : ls: /data/adb: Permission denied
/data/adb/lspd
  root : ls: /data/adb/lspd: No such file or directory
  shell: ls: /data/adb/lspd: Permission denied
  app  : ls: /data/adb/lspd: Permission denied
```

`/data/adb` is mode **0700, `root:root`**. The refusal happens **there — above the leaf.** The
application never gets far enough to learn anything about the file it asked about.

Root reports `ENOENT`: LSPosed is genuinely not installed. That is the ground truth, and it is what
makes the rest decisive.

</details>

---

## Part 3 — The consequence

`File.exists()` returns a `boolean`. Underneath, the native implementation performs a `stat`-family
syscall and treats every failure identically.

### ⏸ STOP 3 — the central question

On this device, LSPosed is **not** installed and the app-side check returns `false`.

**If someone installed LSPosed right now, what would the check return?**

<details>
<summary><b>Answer</b></summary>

**`false`.** Identically.

With LSPosed installed, `/data/adb/lspd` exists — and `/data/adb` is still mode 0700, so the
application still gets `EACCES`, and `File.exists()` still maps that to `false`.

> **The check returns the same answer whether or not LSPosed is installed.** It has **zero
> discriminating power on a rooted device**, which is the only kind of device where it could ever
> have mattered. On an unrooted device `/data/adb` does not exist and the check correctly returns
> `false` — so its output is uncorrelated with the thing it claims to detect, over exactly the
> population it was written for.

</details>

Now confirm the mechanism yourself. Add these three paths to your probe:

```bash
# host
for p in /data/adb/modules /system/xbin/su /debug_ramdisk/magisk; do
  echo "== $p"
  echo "  root : $(adb shell "su 0 ls -ld $p" 2>&1)"
  echo "  shell: $(adb shell "ls -ld $p" 2>&1)"
  echo "  app  : $(adb shell "run-as $PKG ls -ld $p" 2>&1)"
done
```

### ⏸ STOP 4

Three of your rows now yield `File.exists() == false` from the app **for three different reasons**.
Name them.

<details>
<summary><b>Answer</b></summary>

| Path | Reality | Why the app reads `false` |
|---|---|---|
| `/data/adb/lspd` | Genuinely absent | `EACCES` at the parent — and would read `false` if present too |
| `/data/adb/modules` | **Present** | `EACCES` at the parent. The check reports absence for something present |
| `/system/xbin/su` | **Present, setuid root** | `/system/xbin` is `0750 root:shell`, so `shell` sees it and the app cannot traverse |

That third row is the one to remember. **The classic `su` path probe returns `true` from `adb shell`
and `false` from the application that would actually run it.** And on this device the `su` it finds
is not even the one granting root: `/system/xbin/su` is AOSP's, shipped by every `userdebug` build,
while root actually comes from Magisk's `su` at `/debug_ramdisk/su`.

</details>

---

## Part 4 — What does work, and the trap inside it

Not everything is invisible. Try:

```bash
# host
adb shell "run-as $PKG grep magisk /proc/self/mountinfo"
adb shell "run-as $PKG grep -c magisk /proc/self/mountinfo"
adb shell "run-as $PKG grep -c ' magisk ' /proc/self/mountinfo"
```

And the 0711 case, which is a different lesson:

```bash
# host
adb shell "run-as $PKG ls /debug_ramdisk"                    # list
adb shell "run-as $PKG head -c 4 /debug_ramdisk/magisk" | od -c | head -1   # read
```

### ⏸ STOP 5

1. Your two `grep -c` results differ. **Why?** Read the actual lines.
2. You could not list `/debug_ramdisk` but you could read a file inside it. What is the mode, and
   what general rule does that give you?

<details>
<summary><b>Answers</b></summary>

**1.** On the reference device, `grep -c magisk` returns **3** and `grep -c ' magisk '` returns **2**.
The third line is:

```
58 56 0:27 / /debug_ramdisk/.magisk/pts rw,nosuid,noexec,relatime shared:15 - devpts devpts rw,...
```

Its mount **source** is `devpts`. The token `magisk` appears only in the mount **point path**.

[63-LSPosed](../../63-LSPosed/README.md) records "3 lines whose mount source is literally `magisk`".
By source it is two; by substring it is three. The signal is real and the conclusion is untouched —
but this is the chapter's case F in miniature, committed inside a chapter documenting its neighbours.
**A substring matched something other than what the sentence claimed.** Quote it as *"two
`magisk`-sourced mounts, three lines mentioning `magisk`"* and the ambiguity is gone.

**2.** `/debug_ramdisk` is mode **0711** — traverse, do not list. So `ls` is refused to both `shell`
and the app, while `/debug_ramdisk/magisk` reads back its ELF header (`177 E L F`) from an app uid.

> **A directory you cannot list is not a directory you cannot read from. Path-guessing beats
> directory listing.**

</details>

---

## Part 5 — The vantage caveat you must carry

`run-as` gives you the **`runas_app`** SELinux domain. A normally installed application gets
**`untrusted_app`**. They are not the same domain.

```bash
# host -- see it for yourself
adb shell "run-as $PKG id"
```

### ⏸ STOP 6

Given that `runas_app` and `untrusted_app` differ, **which of your results generalise to a real
application and which do not?** Think about the asymmetry.

<details>
<summary><b>Answer</b></summary>

| Result | Generalises? |
|---|---|
| **Refused** (`EACCES`) | **Yes.** A real app has no more access than `runas_app`, so a refusal here is a refusal there |
| **Succeeded** | **No.** Confirm with a purpose-built probe APK before publishing it as a detection signal |

Every "the app cannot see this" conclusion in Parts 2–4 is therefore sound — and those are the
conclusions the lab rests on. Every "the app can see this" result — the `/debug_ramdisk/magisk` read,
the `mountinfo` lines — is provisional. [63-LSPosed](../../63-LSPosed/README.md) labels its own
results the same way, which is the right handling.

**This asymmetry is why `run-as` is usable at all.** It cannot prove capability; it can prove
incapability, and incapability is what kills a detection check.

</details>

---

## Part 6 — The properties, and the finding hiding in a count

Detection code reads properties as well as paths. Run the chapter's differ:

```bash
# host
./../scripts/vantage-diff.sh -p $PKG --props
```

### ⏸ STOP 7

1. How many property **names** does each vantage see?
2. How many are visible to `shell` and not to the app? How many the other way?
3. Look at the shell-only list. **Do you recognise any of them?**

<details>
<summary><b>What the reference AVD showed, and why it matters more than the count</b></summary>

Names, not lines: **root 1052, shell 670, app 633.** Thirty-seven names visible to `shell` and not to
the app; **zero** the other way.

That zero is a free correctness control. The app domain holds strictly fewer property-read
permissions than `shell`, so its view must be a subset. A non-zero value there would mean the
*measurement* was broken, and you would want to know that before reading anything into the other
column.

Among the 37:

| Property | `shell` | app | SELinux type |
|---|---|---|---|
| `ro.debuggable` | `1` | **(empty)** | `userdebug_or_eng_prop` |
| `ro.secure` | `1` | **(empty)** | `userdebug_or_eng_prop` |
| `partition.system.verified` | `2` | **(empty)** | `verity_status_prop` |
| `ro.serialno` | `EMULATOR35X3X11X0` | **(empty)** | `serialno_prop` |
| `qemu.sf.lcd_density` | `560` | **(empty)** | `qemu_sf_lcd_density_prop` |

**Three of those are standard integrity checks, and the application cannot read any of them.**
`ro.debuggable` is genuinely `1` on this `userdebug` build. Written the usual way —
`"1".equals(SystemProperties.get("ro.debuggable"))` — the check gets the empty string and concludes
the device is fine. **It fails open, silently, on the only vantage that counts.**

Note the contrast in the same table: `ro.build.tags` reads `dev-keys` from all three vantages. Some
integrity signals are readable by an app and some are not, and **which is which is not guessable** —
it has to be measured, on the device you care about.

</details>

---

## Part 7 — Now do it to a claim you did not write

This is the part that turns a lab into a habit.

Pick **any measured claim** in this repository that you can reach with the hardware you have. Good
candidates, all of which state their command:

| Claim | Where |
|---|---|
| Shell sees N properties, an app M | [39-EmulatorDetection](../../39-EmulatorDetection/README.md) |
| `/proc/tty/drivers` is `EACCES` from an app | [39-EmulatorDetection](../../39-EmulatorDetection/README.md) |
| `/data/user/0` and `/data/data` share an inode | [33-Storage](../../33-Storage/README.md) |
| `shell` cannot read `adb_keys` despite the group bit | [60-ADB](../../60-ADB/README.md) |
| `/proc/self/mountinfo` magisk mounts | [63-LSPosed](../../63-LSPosed/README.md) |

Then:

1. **Run the documented command verbatim.** Not your improved version — theirs.
2. Record the raw output before interpreting it.
3. Compare. Verdict: **REPRODUCED**, **DIVERGED**, or **NOT RUNNABLE HERE**.
4. If it diverged, work the checklist before concluding anything:

| Rule out | Question |
|---|---|
| A different device | Model, API, ABI, page size, OEM build |
| **A different vantage** | Was the original root, shell, or app? This is the most common cause and the hardest to see, because the label is prose and the measurement was a command |
| A different tool version | Especially compilers |
| A different command | Is the printed command really the one that produced the number? |

5. If none of those explains it, the honest verdict is **"diverged, cause not established."** Write
   that. Do not guess, and do not edit the other chapter.

> **This is not a formality — it is where findings come from.** While writing chapter 74, checking a
> single citation this way produced an entirely new case study and two corrections. The yield on
> re-running published measurements is far higher than it feels like it should be, because almost
> nobody does it.

### ⏸ STOP 8

Write up your replication in the chapter's notation, then audit it:

```bash
# host
python3 -B ../scripts/claim-ledger.py --strict my-replication.md
```

---

## Part 8 — Write the finding

Write the Part 2–3 result as a report finding. Then compare.

<details>
<summary><b>A defensible version</b></summary>

> **Root-detection routine is non-functional — Low (informational)**
>
> The application probes a list of filesystem paths using `java.io.File.exists()`. Measured on a
> rooted test device (Android 15 / API 35, Magisk 30.7) from three vantages, the probed paths beneath
> `/data/adb` return `EACCES` to both the shell user and an application uid, because `/data/adb` is
> mode `0700 root:root` and the refusal occurs above the leaf. `File.exists()` maps `ENOENT` and
> `EACCES` alike to `false`, so the routine returns `false` on every rooted device — the only
> population it was written for. `/system/xbin/su` behaves the same way for an application, because
> `/system/xbin` is `0750 root:shell`.
>
> This is not a bypass; the routine has no detection capability to bypass. Remove it, or replace it
> with signals reachable from an application uid — `/proc/self/mountinfo` mount sources are readable
> without permissions — and note that any client-side signal is advisory. Where the answer must be
> trusted, use server-validated Play Integrity or key attestation.

Note what it avoids. Not "root detection can be bypassed" — nothing was bypassed, and that phrasing
invites the developer to add more paths, which fixes nothing. The correctness framing cannot be
answered that way. And it states the vantage and the device, so the claim is checkable.

</details>

---

## Success criteria

- [ ] You produced a three-vantage table on your own device, with ground truth from root.
- [ ] You can explain why `File.exists()` cannot answer "is this file present" — naming the two
      `errno` values and the API's return type.
- [ ] You can state which of your results generalise to `untrusted_app` and which do not, and **why
      the asymmetry runs that way**.
- [ ] You found at least one property that detection code commonly reads and that an app cannot.
- [ ] You re-ran one published claim you did not write, and recorded a verdict — including, if it
      applies, "diverged, cause not established".
- [ ] You can say why "root detection bypassed" is the wrong finding title here.

---

## What to carry into Lab 04

Three techniques so far: **find a source with a different trust story** (Lab 01), **check the
proposition you actually care about** (Lab 02), **change who is asking** (Lab 03).

Lab 04 gives you no device and no commands. You will be handed a finished, confident, six-finding
report and scored on which findings you **reject**. Every technique above is one of the tools.

---

## Related

| Chapter | Why |
|---|---|
| [63-LSPosed](../../63-LSPosed/README.md) | Owns the `/data/adb/lspd` result and the three-vantage table |
| [37-RootDetection](../../37-RootDetection/README.md) | Owns the `su` path catalogue and the vantage callout |
| [64-Xposed](../../64-Xposed/README.md) | Owns the classic-artefact probe; `ENOENT` to root is a third result |
| [39-EmulatorDetection](../../39-EmulatorDetection/README.md) | Owns the property-visibility claim you may be re-running in Part 7 |
| [22-SELinux](../../22-SELinux/README.md) | Why a domain that cannot read a property type does not see it at all |
