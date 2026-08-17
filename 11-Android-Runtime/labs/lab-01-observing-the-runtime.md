# Lab 01 — Observing the Runtime

> **Difficulty:** Beginner · **Time:** 45–75 minutes · **Chapter:** [11 — Android Runtime](../README.md)

Every app you attack is executed by something. That something is not the kernel directly and it is
not a plain `main()`. It is a managed runtime that was already running before your app existed, that
pre-compiled your app's code at install time, and that handed your app a ready-made process by
cloning itself. This lab makes all three facts visible on a live device using only `adb` and `/proc`.

---

## Objective

Produce evidence, pulled from a running device rather than from memory, for each of these questions.

| Question | Evidence you will produce |
|---|---|
| Is this app compiled ahead of time, or interpreted and JIT-compiled? | A `dumpsys package dexopt` line naming a compiler filter |
| Where does the compiled output physically live? | A listing of the package's `oat/` directory |
| How is the runtime configured here? | The `dalvik.vm.*` system properties |
| Which process created my app's process? | `PPid` in `/proc/<pid>/status` matching the Zygote's PID |
| What does the runtime map into an app? | `/proc/<pid>/maps` lines naming `base.odex`, `base.vdex`, boot image |

> **📖 Definition — runtime.** A *runtime* is the body of code that is already running before your
> program starts and that turns your program's instructions into work the CPU performs. On Android
> that runtime is **ART**, the Android Runtime. It loads bytecode, decides whether to interpret it,
> JIT-compile it, or use ahead-of-time compiled machine code, and it owns the heap and the garbage
> collector. This lab observes ART from outside; its internals are
> [13 — ART](../../13-ART/README.md).

---

## Prerequisites

- A working toolchain from
  [chapter 00, Lab 01](../../00-Introduction/labs/lab-01-build-your-lab.md): `adb` on your `PATH`.
- **A rooted device, or an emulator running a Google APIs (non-Play) image.** Several steps read
  `/proc/<pid>/maps` and `/data/app` directories owned by other UIDs, which the
  [app sandbox](../../21-App-Sandbox/README.md) forbids to an unprivileged shell. On an emulator,
  `adb root` suffices.
- Android 9 (API 28) or newer. Commands below were checked against Android 11 through 14.
- Comfort with a shell prompt; otherwise read [02 — Linux Basics](../../02-Linux-Basics/README.md).

> **⚠️ Warning.** Do not run this against a personal phone holding real data. `cmd package compile -f`
> rewrites files under `/data/app` and can take minutes, during which the app may be killed. Use a
> disposable emulator.

---

## Setup

```bash
# runs on your host machine
adb devices
adb root
adb shell id
```

`id` must print `uid=0(root)`. If it prints `uid=2000(shell)`, `adb root` was refused — that happens
on production and Play-store images. Switch to a Google APIs emulator image.

Choose a small pre-installed target and note its APK path.

```bash
# runs on your host machine
adb shell pm list packages | grep -iE "calculator|deskclock|settings"
adb shell pm path com.android.deskclock
```

`pm path` prints something shaped like
`package:/data/app/~~aB1c==/com.android.deskclock-Xy2==/base.apk`. The two random-looking directory
components were introduced in Android 11 so an app's install path is not guessable by other apps.

---

## Steps

### Step 1 — Ask the runtime what state each package is compiled in

```bash
# adb shell as root — runs on the device
dumpsys package dexopt | grep -A 4 "com.android.deskclock"
```

The `status=` value names a **compiler filter**, the knob that decides how much of the app is native
machine code before the app ever runs.

| Filter | What ART produces | Typical trigger |
|---|---|---|
| `assume-verified` | Nothing; verification assumed to pass | Some debug and system paths |
| `verify` | Verification results only, written to a `.vdex` | Freshly installed app, no profile yet |
| `speed-profile` | Native code for methods named in a collected profile | Background dexopt when idle and charging |
| `speed` | Native code for effectively every method | `-m speed`, some system apps |
| `everything` | Native code for every method, including ones normally skipped | Diagnostics |

> **📖 Definition — dexopt.** *Dexopt* is the ahead-of-time step in which ART reads your app's DEX
> bytecode and writes out verification results and, depending on the filter, compiled native code.
> The compiler is `dex2oat`, invoked by the package manager at install time and again in the
> background. The DEX container it consumes is
> [12 — DEX Internals](../../12-DEX-Internals/README.md).

On Android 14 and newer, dexopt is owned by **ART Service** inside the ART APEX, and a richer report
comes from `pm art dump com.android.deskclock`.

### Step 2 — Force compilation and watch the state change

```bash
# adb shell as root — runs on the device
cmd package compile -m speed -f com.android.deskclock
dumpsys package dexopt | grep -A 4 "com.android.deskclock"
```

`-m` selects the filter, `-f` forces recompilation even if the current state is considered good
enough. Re-run the query and confirm the status now names `speed` with a reason such as `cmdline`.
Restore the device afterwards:

```bash
# adb shell as root — runs on the device
cmd package compile --reset com.android.deskclock
```

> **🔍 Pentester's Note.** `cmd package compile -m everything -f <pkg>` forces an app's methods into a
> compiled `.odex` before static analysis of the native artefacts, and makes an app that behaves
> erratically under JIT behave deterministically. `--reset` removes your footprint before handing a
> client device back.

### Step 3 — Look at the compiled output on disk

```bash
# adb shell as root — runs on the device
APKDIR=$(dirname $(pm path com.android.deskclock | sed 's/^package://'))
ls -l $APKDIR/oat/*/
```

| File | Contents |
|---|---|
| `base.vdex` | Verified DEX data plus verification results, so verification is not repeated |
| `base.odex` | An ELF shared object holding compiled native code and metadata |
| `base.art` | Optional *app image*: a pre-initialised heap snapshot that speeds up startup |

```bash
# runs on your host machine — substitute the real randomised path
adb pull /data/app/~~aB1c==/com.android.deskclock-Xy2==/oat/arm64/base.odex .
file base.odex
```

It reports an ELF shared object. That is the concrete answer to "where did my Java go".

> **🔬 Under the Hood.** The `.odex` is a real ELF file but not a normal library. Its `.rodata`
> carries an OAT header and per-DEX class metadata; its `.text` holds compiled method bodies. ART
> finds a method's entry point by walking that metadata rather than by symbol lookup, which is why
> `nm base.odex` shows almost nothing useful.

### Step 4 — Read the runtime's configuration

```bash
# adb shell — runs on the device
getprop | grep dalvik.vm
```

The `dalvik.` prefix is a fossil: these names date from [Dalvik](../../14-Dalvik/README.md), the
runtime ART replaced, and were kept for compatibility.

| Property | Meaning |
|---|---|
| `dalvik.vm.heapgrowthlimit` | Heap ceiling for an ordinary app |
| `dalvik.vm.heapsize` | Higher ceiling granted when the manifest sets `android:largeHeap="true"` |
| `dalvik.vm.heapstartsize` | Initial heap size at process start |
| `dalvik.vm.usejit` | Whether the just-in-time compiler is enabled |
| `dalvik.vm.usejitprofiles` | Whether ART records profiles to drive `speed-profile` |
| `dalvik.vm.isa.arm64.variant` | CPU variant `dex2oat` targets when generating code |
| `dalvik.vm.image-dex2oat-filter` | Filter used for the boot image itself |

> **🧠 Mental Model.** Treat `dalvik.vm.*` as ignition settings chosen by the manufacturer before the
> engine turns over. Your app cannot change them. When an app appears to have more memory than the
> documentation suggests, the cause is almost always `android:largeHeap` promoting it from
> `heapgrowthlimit` to `heapsize`, not a leak.

### Step 5 — Find the Zygote

```bash
# adb shell — runs on the device
ps -A -o PID,PPID,USER,NAME | grep -i zygote
cat /proc/$(pidof zygote64)/cmdline | tr '\0' ' '; echo
```

On a 64-bit device with 32-bit support you see two entries, `zygote64` and `zygote`. Both are the
same executable, `app_process`, started by `init` with different arguments. The command line contains
`--zygote`, `--start-system-server`, and `--socket-name=zygote`; that socket is what the package
manager writes to when it wants a new app process.

> **📖 Definition — Zygote.** The *Zygote* starts during boot, loads the runtime and every framework
> class an app is likely to need, then sleeps on a socket. When the system needs a new app process it
> does not start one from scratch; it tells the Zygote to `fork()`. The child inherits the loaded
> classes and the mapped boot image, so startup skips work that would otherwise repeat thousands of
> times a day.

### Step 6 — Prove your app was forked from the Zygote

```bash
# adb shell — runs on the device
monkey -p com.android.deskclock -c android.intent.category.LAUNCHER 1
APP_PID=$(pidof -s com.android.deskclock)
grep -E "^(Name|Pid|PPid|Uid)" /proc/$APP_PID/status
echo "zygote64 = $(pidof zygote64)"
```

`PPid` equals the Zygote's PID. That single number is the whole Zygote model, observed rather than
believed.

> **🔬 Under the Hood.** On devices with the Unspecialized App Process pool enabled, the system keeps
> pre-forked, not-yet-specialised children waiting. Your app may be one of them, and its parent is
> still a Zygote because pool members are themselves Zygote children. If `PPid` names something else,
> you probably grabbed a helper process such as an isolated WebView renderer.

### Step 7 — See what the runtime mapped into the app

```bash
# adb shell as root — runs on the device
grep -E "\.(art|oat|odex|vdex)" /proc/$(pidof -s com.android.deskclock)/maps
grep "anon:dalvik" /proc/$(pidof -s com.android.deskclock)/maps | head -n 10
```

Three families appear. First, **boot image files** such as `boot.art` and `boot-framework.art`,
mapped read-only from `/apex/com.android.art/javalib/` or `/system/framework/` and shared by every
process on the device. Second, **your package's artefacts** from the `oat/` directory of Step 3.
Third, **anonymous ART regions** labelled `[anon:dalvik-main space]`, `[anon:dalvik-zygote space]`,
and `[anon:dalvik-LinearAlloc]`. The zygote space is the copy-on-write heap inherited at fork; the
main space is where your app's own allocations land. See [19 — Memory](../../19-Memory/README.md).

> **🔍 Pentester's Note.** `/proc/<pid>/maps` is the fastest way to catch an app loading code it did
> not ship with. A `.dex`, `.odex`, or `.so` mapped from a data or cache directory, or one suffixed
> `(deleted)`, means the app pulled executable content at runtime. That is exactly what
> [Lab 03](lab-03-dynamic-dex-loading-and-hooking.md) and
> [Lab 04](lab-04-ctf-the-vanishing-class.md) build and then attack.

---

## Hints

- `adb root` fails silently on Play-store emulator images and production phones. Check `adb shell id`
  rather than trusting the absence of an error.
- If `dumpsys package dexopt` prints nothing, the package name is wrong. Package names rarely match
  app titles; confirm with `pm list packages`.
- `cmd package compile` prints nothing while it works. Watch `adb logcat -s dex2oat` in a second
  terminal.
- On an x86-64 emulator the directory is `oat/x86_64/`, not `oat/arm64/`. Use `ls $APKDIR/oat/`.
- `pidof` returns several PIDs for multi-process apps. Use `pidof -s`, or list with `ps -A` and choose
  deliberately.
- "Permission denied" on another UID's `/proc/<pid>/maps` is the sandbox working correctly, not a bug.

---

## Success Criteria

1. Two `dumpsys package dexopt` lines for the same package showing **different** compiler filters,
   before and after `cmd package compile -m speed -f`.
2. A listing showing `base.odex` and `base.vdex` with non-zero sizes under `oat/<isa>/`.
3. The values of `dalvik.vm.heapgrowthlimit` and `dalvik.vm.heapsize`, plus a one-sentence
   explanation of why they differ.
4. Two equal numbers: the app's `PPid` and the PID of `zygote64`.
5. At least one `/proc/<pid>/maps` line naming `base.odex` or `base.vdex`, and one naming a boot
   image `.art`.
6. An explanation of the difference between `verify` and `speed` that does not rely on the word
   "faster" alone.

---

## Solution

<details>
<summary>Reveal solution</summary>

### Reading the evidence

**Why the filter change matters.** Under `verify`, ART has written a `.vdex` containing verification
results but no machine code, so every method starts in the interpreter and is promoted by the JIT
only once it becomes hot. Under `speed`, `dex2oat` has already emitted native code for essentially
every method into `base.odex`, so the interpreter is bypassed from the first call. For an analyst the
consequence is concrete: under `speed` the app's control flow exists as machine code on disk and can
be examined with a native disassembler, while under `verify` the only on-disk representation is DEX
bytecode.

**Why the two heap properties differ.** `heapgrowthlimit` is the ceiling ART enforces for an ordinary
app; `heapsize` is the higher ceiling it enforces when the manifest declares
`android:largeHeap="true"`. The manifest flag allocates nothing — it only selects which of the two
numbers becomes the app's limit.

**Why `PPid` equals the Zygote's PID.** The system server does not `exec()` a new program for your
app. It writes a request to the Zygote's socket, the Zygote calls `fork()`, and the child specialises
itself by setting its UID, its SELinux context, and its process name before loading the APK. Because
there is no `exec()`, the child keeps the parent's initialised runtime, mapped boot image, and loaded
framework classes. `PPid` is the kernel recording who called `fork()`, so it is direct proof.

**What the mappings tell you.** The boot image `.art` and `.oat` files are mapped read-only and shared
between every app, so hundreds of processes each "have" the framework loaded while costing physical
memory only once. `base.vdex` is mapped because ART reads DEX data straight out of it rather than
re-extracting from the APK. `base.odex` is mapped executable, and its presence at a non-trivial size
is ground truth that AOT compilation happened, whatever `dumpsys` claims.

### Expected shape of key outputs

```text
# example output — abbreviated; values differ on your device
[com.android.deskclock]
  path: /data/app/~~kQ2f==/com.android.deskclock-9Lm4==/base.apk
    arm64: [status=speed] [reason=cmdline] [primary-abi]

-rw-r--r-- 1 system all_a90  1425408 base.odex
-rw-r--r-- 1 system all_a90  2306048 base.vdex

  PID  PPID USER   NAME
  428     1 root   zygote64

Name:   ndroid.deskclock
Pid:    5312
PPid:   428
Uid:    10102  10102  10102
```

The `Name` field is truncated to fifteen characters by the kernel, which is why it reads
`ndroid.deskclock`. That truncation defeats naive grep-based process hunting and is worth
remembering.

</details>

---

**Next:** [Lab 02 — ClassLoader Archaeology](lab-02-classloader-archaeology.md) — stop looking at the
runtime from outside and start walking its object graph from inside a live process.
