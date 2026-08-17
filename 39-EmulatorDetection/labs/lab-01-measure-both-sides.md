# Lab 01 — Measure both sides

> **Difficulty:** Beginner
> **Time:** 90–150 minutes
> **You will need:** an Android emulator you created, and — ideally — a physical
> Android device you own. The lab works with only an emulator, and says where
> the missing half changes the answer.

---

## Why this lab exists

Every table in [the chapter README](../README.md) came from running two programs on two devices. This
lab has you run the same two programs and build your own table.

That sounds like busywork. It is not, and here is the specific reason: **the chapter's numbers are
from two devices, and yours will be different.** A different phone, a different Android version, a
different AVD image. Some of this chapter's "DEAD" verdicts may not be dead for you. Some signals it
grades SOFT may be absent on your hardware entirely.

The skill being taught is not "read the table". It is **"produce the table"** — because the signal
set rots, and an analyst who can only recite last year's list will be wrong next year. By the end you
will have found at least one place where your measurement disagrees with this chapter, and you will
know which of you is right, because you will have the evidence.

> **⚠️ Authorised testing only**
> Everything here runs on your own emulator and your own phone. The probe app requests no
> permissions, opens no network connection and writes nothing outside its own private directory.
> Uninstall it when you are done (step 7).

---

## Objectives

By the end of this lab you will be able to:

1. Build and run a native probe for two ABIs and read its output.
2. Build and install an Android app **without Gradle or Android Studio**, using only build-tools and
   a JDK.
3. Explain the difference between what `adb shell` can see and what an **app** can see, with numbers
   you measured.
4. Produce your own grading table and defend each grade.
5. Identify at least one signal where your devices disagree with this chapter.

---

## Setup

### 0.1 What you need on the host

| Tool | Check it works | Where it comes from |
|---|---|---|
| `adb` | `adb version` | Android SDK platform-tools |
| Android NDK | see below | SDK Manager, "NDK (Side by side)" |
| `javac`, `keytool`, `jar` | `javac -version` | Any JDK 8–24 |
| `aapt2`, `d8`, `zipalign`, `apksigner` | see below | SDK build-tools |
| An AVD | `emulator -list-avds` | Android Studio's Device Manager |

Find your NDK and confirm the compilers exist:

```bash
# host
ls "$ANDROID_HOME/ndk/"
NDK="$ANDROID_HOME/ndk/25.2.9519653/toolchains/llvm/prebuilt/windows-x86_64/bin"
# On Linux:   .../prebuilt/linux-x86_64/bin
# On macOS:   .../prebuilt/darwin-x86_64/bin
ls "$NDK" | grep -E 'aarch64-linux-android21-clang$|x86_64-linux-android21-clang$'
```

On Windows/Git Bash the compilers are `.cmd` wrappers, so use
`aarch64-linux-android21-clang.cmd` in every command below.

### 0.2 Start the emulator and identify everything

```bash
# host
emulator -list-avds
emulator -avd <YourAvdName> -no-snapshot-load -no-boot-anim &

# wait, then:
adb devices -l
```

> **⚠️ Warning — with two devices attached, every unqualified `adb` command is ambiguous**
> From here on, **always** pass `-s <serial>`. `adb devices -l` gives you the serials. Getting this
> wrong produces results attributed to the wrong device, which is the single easiest way to ruin a
> whole afternoon's measurements.

Record what you have, because every later claim depends on it:

```bash
# host - run once per device, and WRITE THE OUTPUT DOWN
for S in <emulator-serial> <phone-serial>; do
  echo "===== $S"
  adb -s $S shell getprop ro.product.model
  adb -s $S shell getprop ro.build.version.release
  adb -s $S shell getprop ro.build.version.sdk
  adb -s $S shell getprop ro.product.cpu.abi
  adb -s $S shell getprop ro.build.type
done
```

Fill this in now — it is the header of your results table:

| | Emulator | Physical |
|---|---|---|
| Model | | |
| Android / API | | |
| ABI | | |
| Build type | | |

---

## Part 1 — The native probe

### 1.1 Compile it for both architectures

```bash
# host - from the chapter directory
NDK="$ANDROID_HOME/ndk/25.2.9519653/toolchains/llvm/prebuilt/windows-x86_64/bin"
mkdir -p /tmp/ch39 && cd /tmp/ch39

"$NDK/aarch64-linux-android21-clang" -Wall -Wextra -O2 \
    -Wl,-z,max-page-size=16384 \
    -o emu_probe.arm64 <chapter>/examples/emu_probe.c

"$NDK/x86_64-linux-android21-clang" -Wall -Wextra -O2 \
    -Wl,-z,max-page-size=16384 \
    -o emu_probe.x86_64 <chapter>/examples/emu_probe.c
```

**Both must compile with zero warnings.** `-Wall -Wextra` is not decoration: a file that has never
been through a compiler is not a verified example, and this repository has shipped such files before.

> **⚠️ Warning — `-Wl,-z,max-page-size=16384` is not optional, and omitting it is maximally confusing**
> NDK r25c defaults to 4 KiB ELF segment alignment. Android 15 emulator images tagged
> `page_size_16kb` — the `sdk_gphone16k_*` family — run a **16 KiB-page kernel**, and the loader
> cannot map a 4 KiB-aligned binary there. The binary dies with SIGSEGV *before reaching `main`*.
>
> Prove it to yourself, because the lesson is worth ten minutes:
>
> ```bash
> # host
> printf 'int main(void){return 42;}\n' > triv.c
> "$NDK/x86_64-linux-android21-clang" -o triv triv.c          # no page-size flag
> adb -s <emu> push triv /data/local/tmp/triv
> adb -s <emu> shell "chmod 755 /data/local/tmp/triv; /data/local/tmp/triv; echo \$?"
> ```
>
> A three-line program that cannot possibly be wrong exits **139** (SIGSEGV). Nothing in the output
> mentions page size, so you would blame your own code first. Rebuild with the flag and it works.
> If your AVD is not a 16 KiB image the trivial program returns 42 and the flag is harmless.

### 1.2 Run it on the emulator

```bash
# host
adb -s <emu> push emu_probe.x86_64 /data/local/tmp/emu_probe
adb -s <emu> shell "chmod 755 /data/local/tmp/emu_probe; /data/local/tmp/emu_probe" \
    | tee emu-shell.txt
```

If your AVD is arm64 (Apple silicon hosts), push `emu_probe.arm64` instead.

### 1.3 Run it on the phone

```bash
# host
adb -s <phone> push emu_probe.arm64 /data/local/tmp/emu_probe
adb -s <phone> shell "chmod 755 /data/local/tmp/emu_probe; /data/local/tmp/emu_probe" \
    | tee phone-shell.txt
```

> **🔍 If `execve` is refused**
> Some vendor builds block execution from `/data/local/tmp`. Invoke the loader directly:
> ```bash
> adb -s <phone> shell "/system/bin/linker64 /data/local/tmp/emu_probe"
> ```

### 1.4 Read the output properly

Compare the two files side by side:

```bash
# host
diff <(cut -f1-2 emu-shell.txt) <(cut -f1-2 phone-shell.txt)   # structure should match
paste emu-shell.txt phone-shell.txt | less -S                  # values side by side
```

**Questions to answer from your own output — write the answers down:**

1. Does `/dev/qemu_pipe` exist on your emulator? What does the probe report, and is it `ENOENT` or
   something else?
2. Which `/dev/goldfish*` nodes exist? Are the names the same as the chapter's?
3. What does the `proptrie` row report for each device — total, and emulator-named?
4. What is the `timing` row on each? **Which device is faster?**
5. Which rows say `UNKNOWN`, and why? (Look at the `errno` in the value column.)

> **🧠 Mental Model — `UNKNOWN` is a real answer**
> The probe reports three verdicts, not two. `UNKNOWN` means "the file might be there; I was not
> allowed to look". Java's `File.exists()` collapses that into `false`, which is a systematic bias
> toward "not an emulator" in every Java filesystem check ever written. Noticing which rows are
> `UNKNOWN` is the point of using a native probe at all.

---

## Part 2 — The app probe, and why it is different

`adb shell` is **not an app**. It runs as uid 2000 in the SELinux domain `u:r:shell:s0` with a pile of
supplementary groups. An app runs as an app uid in `u:r:untrusted_app:s0` and can see strictly less.
Every "an app can read X" claim has to be proved from an app.

### 2.1 Build and run it

```bash
# host - the script does aapt2 -> javac -> d8 -> zipalign -> apksigner
cd <chapter>/scripts
export OUTDIR=/tmp/ch39-app-emu
./build-probe-app.sh --install --run --serial <emu> | tee ../../../emu-app.txt

export OUTDIR=/tmp/ch39-app-phone
./build-probe-app.sh --install --run --serial <phone> | tee ../../../phone-app.txt
```

The script builds entirely **out of tree**: no `.apk`, `.dex` or `.class` is written next to the
sources, because those are on this repository's artefact blocklist.

> **🔍 If the install fails with `INSTALL_FAILED_USER_RESTRICTED`**
> That is an OEM policy ("Install via USB" disabled), not a problem with the APK. It is not a dead
> end: the script automatically retries through `su -c 'pm install'`, because root is not subject to
> the gate. If you have no root, enable the toggle in Developer options.

### 2.2 The measurement that matters

Now compare **the same signal, read two ways**:

```bash
# host - properties visible to the shell vs to the app
echo -n "shell: "; adb -s <emu> shell "getprop | wc -l"
echo -n "app:   "; adb -s <emu> shell "run-as com.pentest.ch39 getprop | wc -l"
```

On the API 35 AVD, re-measured: **~678 for the shell, ~638 for the app, ~1062 for root.** Four hundred
and nineteen properties the shell can see and an app cannot.

Now find out *why*, on a specific property:

```bash
# host
adb -s <emu> shell getprop ro.boottime.qemu-props
adb -s <emu> shell "run-as com.pentest.ch39 getprop ro.boottime.qemu-props"
adb -s <emu> shell getprop -Z ro.boottime.qemu-props
```

The third command prints the property's SELinux type. The chapter measured `boottime_prop`, which
`untrusted_app` has no read permission on — so a whole family of properties that names emulator-only
`init` services (`qemu-props`, `ranchu-net`, `goldfish-logcat`) looks like a goldmine from the shell
and is **completely unreachable from an app**.

### 2.3 Run the native probe under an app uid

The probe binary can be run inside the app's own sandbox, which gives you the native view from the
app's domain:

```bash
# host
adb -s <emu> shell "run-as com.pentest.ch39 sh -c \
    'cat /data/local/tmp/emu_probe > ./p; chmod 700 ./p; ./p'" | tee emu-app-native.txt
```

Compare the `proptrie` and `content` rows against `emu-shell.txt`. On the chapter's devices,
`/proc/modules` flips from readable (shell) to `EACCES` (app) — which kills a check that looks
perfect when tested from the shell.

---

## Part 3 — Build your own grading table

This is the deliverable. Fill it in from **your** output, not from the chapter.

| # | Signal | Your emulator | Your phone | Your grade | Chapter's grade | Agree? |
|---|---|---|---|---|---|---|
| 1 | `ro.kernel.qemu` | | | | SOFT | |
| 2 | `ro.hardware` | | | | SOFT | |
| 3 | `ro.build.characteristics` | | | | SOFT | |
| 4 | `Build.FINGERPRINT` has `generic` | | | | DEAD | |
| 5 | `/dev/qemu_pipe` | | | | DEAD | |
| 6 | `/dev/goldfish_sync` | | | | SOFT | |
| 7 | Sensor count | | | | HARD | |
| 8 | Sensors vendored AOSP | | | | HARD | |
| 9 | `SUPPORTED_ABIS` x86 + ARM | | | | HARD | |
| 10 | `/proc/cpuinfo` `hypervisor` | | | | HARD | |
| 11 | `/proc/tty/drivers` readable by app | | | | DEAD | |
| 12 | `/proc/modules` readable by app | | | | DEAD | |
| 13 | Timing, ns/iter | | | | INFO | |
| 14 | Properties: shell vs app | | | | — | |
| 15 | Any `qemu`-named property | | | | NOISY | |

Assign your grade using the chapter's vocabulary:

| Grade | Assign it when |
|---|---|
| HARD | The signal differs between your devices **and** you cannot see how to fake it with one value |
| SOFT | It differs, but it is one string an app reads through one API |
| DEAD | It **does not differ** — the "emulator" value appears on your emulator too, or not at all |
| NOISY | It fires on your **physical** device |
| INFO | It differs but is not reliably in one direction |

---

## Part 4 — Find a disagreement

**Success in this lab requires finding at least one row where your measurement disagrees with the
chapter.** There will be one. Some candidates, by likelihood:

| If your setup is… | Expect a disagreement in |
|---|---|
| An arm64 AVD (Apple silicon) | Row 9 and row 10 — no ABI mismatch, **no `hypervisor` flag at all**. Both HARD signals vanish |
| An older AVD (API 28–30) | Row 5 — `/dev/qemu_pipe` may genuinely exist. The chapter's DEAD is a *current-image* claim |
| A Google Play AVD image | `adb root` refused; `ro.build.type` may read `user` |
| A phone from another OEM | Row 15 — `qemu.hw.mainkeys` is a **Xiaomi** quirk; your phone may not have it |
| A rooted phone with Magisk | Rows 4 and 14 may shift depending on what modules are installed |

For your disagreement, answer:

1. **What did the chapter claim?** Quote the section.
2. **What did you measure?** Paste the output.
3. **Why do they differ?** Different API level, different ABI, different OEM, different image type?
4. **Which claim is more general?** Is the chapter wrong, or is it right about its devices and yours
   is a different case?

> **🧠 Mental Model**
> Point 4 is the one that separates an analyst from someone running commands. "The chapter is wrong"
> and "the chapter measured a different thing" are different conclusions with different consequences.
> A DEAD grade that was measured on API 35 is not a claim about API 28 — and a table that does not
> say which it measured is not usable evidence.

---

## Part 5 — The question the numbers answer

Using only your own data:

1. **If you had to write an emulator check today, which three signals would you use, and why those?**
   Justify each from your table, not from the chapter.
2. **Which single signal would you never use, even though it is famous?**
3. **Your phone's timing number versus your emulator's — what does that do to the "emulators are
   slow" claim?**
4. **A colleague tests a `/proc/modules` check from `adb shell` and reports it works perfectly. What
   is the one question you ask?**

---

## Success criteria

- [ ] Both binaries compiled with `-Wall -Wextra` and **zero warnings**.
- [ ] You demonstrated (or ruled out) the 16 KiB page-size SIGSEGV with the trivial program.
- [ ] The native probe ran on both devices, from the shell.
- [ ] The probe app built without Gradle and ran on both devices.
- [ ] You have the shell-versus-app property count for at least one device.
- [ ] You identified one property whose SELinux type blocks app access, and named the type.
- [ ] Your grading table is filled in from your own output, all 15 rows.
- [ ] You found **at least one disagreement** with the chapter and explained the cause.
- [ ] You can state, from your numbers, which device is faster.

---

## Part 6 — Clean up

Leave nothing behind. This matters both as courtesy and as method: state left on a device makes the
next tester's results irreproducible.

```bash
# host - for BOTH devices
for S in <emu> <phone>; do
    adb -s $S shell rm -f /data/local/tmp/emu_probe /data/local/tmp/triv
    adb -s $S uninstall com.pentest.ch39
done

# host - the app also wrote a copy of the probe into its own sandbox in 2.3;
# uninstalling removes the whole private directory, so that is already handled.

# host - and confirm
for S in <emu> <phone>; do
    echo "== $S"; adb -s $S shell "ls /data/local/tmp/ | grep -E 'emu_probe|triv'" || echo "clean"
    adb -s $S shell pm list packages | grep ch39 || echo "app removed"
done
```

Also remove your host build directory (`/tmp/ch39`, `/tmp/ch39-app-*`) — it contains APKs and native
binaries that must never reach the repository.

---

## Hints

<details>
<summary>The probe compiles but the emulator says "Segmentation fault"</summary>

Almost certainly the 16 KiB page size. Rebuild with `-Wl,-z,max-page-size=16384`. Confirm with the
three-line `int main(void){return 42;}` test in §1.1 — if that also exits 139, it is the loader and
not your code. Check with `adb shell getprop ro.product.model`: an `sdk_gphone16k_*` model name means
a 16 KiB image.
</details>

<details>
<summary>`run-as` says "unknown package" or "package not debuggable"</summary>

`run-as` needs the app to be installed **and** debuggable. The build script sets
`android:debuggable="true"`, so check the install actually succeeded:
`adb -s <serial> shell pm list packages | grep ch39`.

Note the three distinct refusals, because they mean different things: `package not debuggable` means
the flag is missing; `package not an application` means you targeted a system app; `unknown package`
means it is not installed for this user.
</details>

<details>
<summary>`aapt2` reports "failed to load XML file" on a file that plainly exists</summary>

Git Bash / MSYS path translation. The SDK tools are native Windows binaries and do not understand
`/c/Users/...`. The build script already handles this with `cygpath -w`; if you are running the steps
by hand, convert every path you pass to an SDK tool.
</details>

<details>
<summary>`adb push` fails with "remote secure_mkdirs() failed"</summary>

MSYS is rewriting `/data/local/tmp` into a Windows path before `adb` sees it. Prefix the command:

```bash
MSYS_NO_PATHCONV=1 adb -s <serial> push emu_probe /data/local/tmp/emu_probe
```
</details>

<details>
<summary>The emulator's sensor count is not 18</summary>

Expected — it varies by image and by AVD hardware profile, and `dumpsys sensorservice` reports
"h/w sensors" while `getSensorList(TYPE_ALL)` includes fused virtual sensors, so the two numbers
legitimately differ on the same device. What matters is not the number but the **vendor
distribution**: on any stock AVD essentially all of them are vendored to AOSP, and on a real phone
essentially none are. Grade the distribution, not the count.
</details>

<details>
<summary>I only have an emulator, no physical device</summary>

You can still do most of this. Every emulator-side measurement works, and the shell-versus-app
comparison in Part 2 is entirely emulator-side — it is arguably the most valuable part of the lab.

For the physical column, use the chapter's Redmi figures and **mark them as borrowed**. Then be
explicit about what you cannot conclude: without a real device you cannot verify the NOISY grades,
because NOISY means "fires on real hardware" and you have none to fire on. Recording that limit is
itself the right professional behaviour.
</details>

---

## What to take away

- The signal set is **measured, not recited**. Yours will differ from this chapter's, and that is
  correct behaviour by both of you.
- **`adb shell` is not an app.** A signal that reads perfectly from the shell may be `EACCES` from an
  app, and the difference is SELinux, not luck.
- Native code sees `errno`; Java sees `false`. **Three answers versus two.**
- The famous checks are the stale ones, for a structural reason: they are famous because they are old.

Next: [Lab 02 — Build a detector worth attacking](lab-02-build-a-detector.md), where you write the
thing you have just learned to measure.
