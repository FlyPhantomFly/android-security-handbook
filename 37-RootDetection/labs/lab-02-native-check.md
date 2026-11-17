# Lab 02 — Native Check, No Java Surface

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-build-and-break.md) completed with a working target,
[Chapter 37 §3.12](../README.md#312-native-stat--access-checks-that-bypass-java-hooks),
[15-Native-Code](../../15-Native-Code/README.md), [16-JNI](../../16-JNI/README.md), the Android NDK
installed

---

## Objective

Add **one function of C** to the app you built in lab 01, watch your entire lab-01 bypass stop working,
and then understand precisely why. Then defeat the native check three ways in increasing cost: libc
interposition, `strace`-guided analysis with a runtime patch, and a static patch of the `.so`.

Finish by escalating the check to raw syscalls and discovering that libc interposition stops working
too.

## Why this matters

**This is the lab that teaches the lesson of the whole chapter.**

The most common incomplete bypass in existence is a Java-only one. It is what every tutorial shows, it
is what Objection's `android root disable` does, and it is what the majority of testers reach for
first. It covers exactly one of the two paths by which an app can ask the operating system a question,
and the failure mode is uniquely maddening: your hooks fire, your log fills with successful-looking
interceptions, everything appears to be working, **and the app still says the device is rooted**.

Most people meet this for the first time on a client engagement, under time pressure, and lose an
afternoon to it. Meeting it here — on an app whose source you wrote, where you know for certain there
is exactly one extra check and exactly where it is — converts a future afternoon into a future five
minutes.

The secondary lesson matters just as much for the developer's half of your job: this single function
is the difference between a control worth nothing and a control worth an hour of a competent
attacker's time. That is a real, if bounded, purchase, and it is the *only* place in this chapter where
extra client-side engineering buys anything measurable.

---

## Setup

### Add native support to the lab-01 project

**`app/build.gradle`** (module level) — add the NDK block:

```groovy
android {
    // ... existing config ...
    defaultConfig {
        // ... existing ...
        externalNativeBuild {
            cmake {
                cppFlags ""
                arguments "-DANDROID_STL=none"
            }
        }
        ndk {
            abiFilters "arm64-v8a", "armeabi-v7a"
        }
    }
    externalNativeBuild {
        cmake {
            path "src/main/cpp/CMakeLists.txt"
            version "3.22.1"
        }
    }
}
```

**`app/src/main/cpp/CMakeLists.txt`**

```cmake
cmake_minimum_required(VERSION 3.22.1)
project(integrity C)

add_library(integrity SHARED integrity.c)

# liblog so we can see what the native side is doing during the lab.
find_library(log-lib log)
target_link_libraries(integrity ${log-lib})
```

**`app/src/main/cpp/integrity.c`** — stage 1. Deliberately plain: no obfuscation yet, so that the
*only* variable in this experiment is the layer the check runs at.

```c
/*
 * integrity.c — the one function that defeats a Java-only bypass.
 *
 * Nothing clever happens here. It is ordinary C calling ordinary libc.
 * That is the point: the check is trivial, and it is invisible to every
 * Java.perform hook ever written, because it never enters the ART runtime.
 */
#include <jni.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <android/log.h>

#define TAG "ROOTLAB-NATIVE"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

static const char *kSuPaths[] = {
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/su/bin/su",
    "/vendor/bin/su",
    "/data/local/tmp/su",
    "/data/local/bin/su",
    NULL
};

/*
 * Two different syscalls per path, on purpose.
 *
 * access() answers "can I reach this path"; stat() answers "what is it".
 * They are distinct libc symbols reaching distinct kernel entry points
 * (faccessat and newfstatat on arm64). Hooking only one of them is a partial
 * bypass — which is exactly the mistake this lab is about, one layer down.
 */
JNIEXPORT jstring JNICALL
Java_com_rootlab_target_NativeCheck_findSu(JNIEnv *env, jclass clazz) {
    struct stat st;
    for (int i = 0; kSuPaths[i] != NULL; i++) {
        if (access(kSuPaths[i], F_OK) == 0) {
            LOGI("access() found %s", kSuPaths[i]);
            return (*env)->NewStringUTF(env, kSuPaths[i]);
        }
        if (stat(kSuPaths[i], &st) == 0) {
            LOGI("stat() found %s", kSuPaths[i]);
            return (*env)->NewStringUTF(env, kSuPaths[i]);
        }
    }
    LOGI("no su found");
    return NULL;
}
```

**`app/src/main/java/com/rootlab/target/NativeCheck.java`**

```java
package com.rootlab.target;

public final class NativeCheck {

    static {
        System.loadLibrary("integrity");
    }

    /** Signal 10 — the native one. Chapter §3.12 */
    public static native String findSu();

    private NativeCheck() { }
}
```

Wire it into `RootChecker.evaluate()` as a tenth signal:

```java
// in RootChecker.evaluate(), extend both arrays
String nativeSu;
try {
    nativeSu = NativeCheck.findSu();
    if (nativeSu != null) nativeSu = "native su at " + nativeSu;
} catch (Throwable t) {
    nativeSu = "native check unavailable: " + t;
}
// results[] gains nativeSu ; names[] gains "10 native-su"
```

Rebuild and install:

```bash
# host
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.rootlab.target/.MainActivity
adb logcat -s ROOTLAB ROOTLAB-NATIVE
```

Confirm signal 10 fires before continuing. If it does not, your device genuinely has no `su` at any of
those seven paths — add the path where your `su` actually lives (`adb shell "su -c 'which su'"` while
Magisk grants the request) to `kSuPaths` and rebuild.

---

## Steps

### Step 1 — Watch the lab-01 bypass fail

Run **exactly** the Java bypass you finished lab 01 with. Do not modify it.

```bash
# host
frida -U -f com.rootlab.target -l lab01-bypass.js --no-pause
```

**Q1.** Which signals now report clean, and which does not? Is your `File.exists` hook still firing —
check its log output — and does that firing have anything to do with signal 10?

**Q2.** Before reading further: write down, in one sentence, your hypothesis for why signal 10 survives
a hook that demonstrably works on signals 1, 2, 3 and 7.

**Q3.** Add `Java.use("java.io.File").exists` logging for *every* path, not just suspicious ones. Do
any of the seven paths in `kSuPaths` appear? Explain what that observation proves.

### Step 2 — Prove the mechanism, do not just accept it

An explanation you have only read is worth much less than one you have observed. Establish the two
call paths empirically.

```bash
# host — trace the JAVA path
frida-trace -U -f com.rootlab.target -j 'java.io.File!exists'

# host — trace the LIBC layer, which sits under both paths
frida-trace -U -f com.rootlab.target -i 'access' -i 'stat' -i 'faccessat' -i 'newfstatat'
```

**Q4.** How many `access`/`stat` calls does the libc trace show for `/system/xbin/su`, and how many
does the Java trace show? Reconcile the two numbers.

**Q5.** Draw the two call stacks — Java and native — from the app's line of code down to the kernel
boundary, and mark on your drawing the exact point at which a `Java.perform` hook can intervene and
the exact point at which an `Interceptor.attach` on libc can.

### Step 3 — Defeat it with libc interposition

```bash
# host
frida -U -f com.rootlab.target \
      -l lab01-bypass.js \
      -l ../scripts/native-root-bypass.js --no-pause
```

Then in the REPL:

```
nrb.status()
```

**Q6.** Which libc symbols does `nrb.status()` report as hooked, which as absent, and why is a long
"absent" list completely normal rather than a failure?

**Q7.** Signal 10 should now be clean. Check the log: were **both** `access` and `stat` denied, or only
one? What does the C source tell you about why both mattered?

**Q8.** Comment out the `stat` hook (use `nrb.observe()` then re-run with only `access` in the
`PATH_INT_ARG0` list, or reason it through from the C source). Does the check still fire?
Explain in terms of the "two syscalls per path" comment in `integrity.c`.

**Q9.** The script sets `errno = ENOENT` before returning `-1`. Write a three-line C function a
defender could add that distinguishes a real "file absent" from a naive hook that returns `-1` without
setting `errno`.

### Step 4 — Now do it the way you would with no source: `strace`

Pretend you do not have `integrity.c`. Get the ground truth from the kernel boundary.

```bash
# adb shell as root
adb shell
su
PID=$(pidof -s com.rootlab.target)
strace -f -p $PID -e trace=faccessat,newfstatat,openat -s 200 2>&1 | grep -i su
```

Catching it from process start is more useful and harder:

```bash
# adb shell as root — force-stop, then attach to zygote and follow the fork
am force-stop com.rootlab.target
strace -f -o /data/local/tmp/trace.log -e trace=faccessat,newfstatat,openat,execve \
    -p $(pidof -s zygote64) &
am start -n com.rootlab.target/.MainActivity
sleep 5
kill %1
grep -n 'su' /data/local/tmp/trace.log | head -40
```

**Q10.** What does `strace` show that Frida's `frida-trace` did not, or could not? Under what
circumstance is `strace` the only tool that will tell you the truth?

**Q11.** From the `strace` output alone — with no source and no decompiler — how would you determine
*which* library issued the call?

### Step 5 — Find it in Ghidra and patch the return

```bash
# host
unzip -o app-debug.apk 'lib/arm64-v8a/*' -d libs/
readelf --dyn-syms libs/lib/arm64-v8a/libintegrity.so | grep -E 'Java_|UND (access|stat)'
strings -a libs/lib/arm64-v8a/libintegrity.so | grep -E '^/'
```

Open the `.so` in Ghidra. Work the standard order from
[§6.4](../README.md#64-in-ghidra--ida-native): Imports, then `Java_*` Exports, then Strings with
cross-references.

**Q12.** What do the **imports** alone tell you about the technique, before you read a single
instruction of the function body?

**Q13.** The JNI export is named `Java_com_rootlab_target_NativeCheck_findSu`. Would R8 obfuscation of
the app rename it? Explain why, in terms of how the JNI linker resolves symbols.

Now patch it at runtime rather than on disk — no re-signing, no tamper-detection consequences:

```javascript
// patch.js — the function returns a jstring; returning NULL means "no su found"
var m = Process.findModuleByName("libintegrity.so");
if (m === null) {
    console.log("[!] libintegrity.so not mapped yet — hook android_dlopen_ext instead");
} else {
    var sym = Module.findExportByName("libintegrity.so",
                  "Java_com_rootlab_target_NativeCheck_findSu");
    if (sym === null) {
        console.log("[!] symbol not found; list exports:");
        m.enumerateExports().forEach(function (e) { console.log("    " + e.name); });
    } else {
        Interceptor.replace(sym, new NativeCallback(function (env, clazz) {
            console.log("[patch] findSu() -> NULL");
            return ptr(0);
        }, 'pointer', ['pointer', 'pointer']));
        console.log("[patch] installed at " + sym);
    }
}
```

**Q14.** Compare `Interceptor.replace` on the JNI export with the libc interposition of step 3. Which
is more durable against the app adding an eleventh check, and which is more durable against the app
adding string obfuscation? They are not the same answer.

**Q15.** Write the equivalent `Memory.patchCode` version using `Arm64Writer` to emit `MOV X0, #0; RET`
at the function's entry. What must you check about the address before patching, and what happens if
you get the register width wrong (`W0` versus `X0`) for a function returning a pointer?

### Step 6 — Escalate: raw syscalls

Now play the defender. Replace the libc calls with direct syscalls and watch step 3 stop working.

```c
/* integrity.c — stage 2. Add this and switch findSu() to use it. */
#include <sys/syscall.h>
#include <fcntl.h>

static int raw_access(const char *path) {
#if defined(__aarch64__)
    /* arm64 has no plain access(); faccessat(AT_FDCWD, path, F_OK, 0) */
    return (int) syscall(__NR_faccessat, AT_FDCWD, path, F_OK, 0);
#else
    return (int) syscall(__NR_access, path, F_OK);
#endif
}
```

Rebuild, reinstall, and re-run the step-3 bypass unchanged.

**Q16.** Does signal 10 fire again? Which of the two hooks in `native-root-bypass.js` was covering it
before, and why does neither cover it now?

**Q17.** `syscall()` is itself a libc export. Write a Frida hook for it that denies `__NR_faccessat`
calls whose path argument matches your pattern. Which argument index holds the path, and why does that
depend on the syscall number rather than being fixed?

**Q18.** A defender goes one step further and emits `svc #0` inline with assembly, so there is no
`syscall` symbol either. What tools remain? Rank them by cost.

### Step 7 — Measure and write it up

**Q19.** Total the time for each stage: Java-only (failed), libc interposition, `strace` plus runtime
patch, raw-syscall escalation. Produce the cost curve.

**Q20.** Using your own numbers, write the two-sentence honest assessment of a native root check for a
developer's ears, and the two-sentence version for a client report.

---

## Hints

<details>
<summary>Hint — Q3, logging every File.exists</summary>

```javascript
Java.perform(function () {
    var File = Java.use("java.io.File");
    File.exists.implementation = function () {
        console.log("[File.exists] " + this.getAbsolutePath());
        return this.exists();
    };
});
```

Now count. If a path never appears in this log but `strace` shows the kernel being asked about it, the
question was asked by something that is not Java.
</details>

<details>
<summary>Hint — Q6, why "absent" symbols are normal</summary>

`__xstat` and `__lxstat` are glibc-isms and have never existed on Android. `stat64` exists on 32-bit
and not on 64-bit. `statx` appeared later than some devices you will test. A script that treats a
missing symbol as fatal cannot run on more than one device configuration, which is why every lookup in
that script is guarded.
</details>

<details>
<summary>Hint — Q11, attributing a syscall to a library</summary>

`strace` gives you the syscall, not the caller. Two routes: attach `gdbserver`/`lldb-server` and break
on the syscall to read the stack; or use Frida's `Interceptor` on the libc wrapper with
`Thread.backtrace(this.context, Backtracer.FUZZY)` and `DebugSymbol.fromAddress`, which is exactly what
`native-root-bypass.js` prints in its `[deny]` lines. The second is far cheaper and is why the script
bothers to print backtraces at all.
</details>

<details>
<summary>Hint — Q17, syscall() argument layout</summary>

`long syscall(long number, ...)` — the syscall number is argument 0 and the *syscall's own* arguments
follow. For `faccessat(dirfd, path, mode, flags)` the path is at `args[2]`; for `access(path, mode)` it
would be at `args[1]`. You must read the syscall number first and branch on it. That is why a generic
`syscall` hook is more work than a specific `access` hook, and why it is worth writing once.
</details>

---

## Solution

<details>
<summary>Answers Q1–Q5 — why the Java bypass fails</summary>

**Q1.** Signals 1–9 report clean; signal 10 still fires. Your `File.exists` hook *is* firing — its log
shows denials for the Java-layer checks — and none of that firing has anything to do with signal 10,
because signal 10 never calls `File.exists`.

This is the exact experience that costs people an afternoon: a working hook plus a surviving check
looks like anti-Frida protection or a subtle bug in your script, and it is neither.

**Q2.** The correct hypothesis: the check does not execute Java code, so there is no Java method for a
Java hook to replace.

**Q3.** None of the seven paths appear in the `File.exists` log, even though `strace` (step 4) will
show the kernel being asked about all of them. That proves the questions are being asked by something
that never enters the ART runtime. It is direct, observational evidence rather than an explanation you
took on trust.

**Q4.** The libc trace shows roughly fourteen calls for the seven paths (two per path, `access` then
`stat`, stopping early once one succeeds). The Java trace shows the lab-01 paths only, and none of the
native ones. The reconciliation: libc sits *below* both paths, so it sees Java-originated calls and
native-originated calls; `File.exists` sits at the top of the Java path only.

**Q5.** The two stacks:

```
JAVA PATH                                   NATIVE PATH
new File(p).exists()      <-- Java.perform  access(p, F_OK)  in libintegrity.so
  UnixFileSystem.getBooleanAttributes           |
    BlockGuardOs.access                          |
      Posix.access (native method)               |
        libcore_io_Posix.cpp                     |
          bionic libc access()  <-- Interceptor.attach --------+
            kernel faccessat    <-- strace, inline-asm bypasses everything above
```

The single most important structural fact in the chapter is the shape of that diagram: **a hook placed
lower catches everything above it.**
</details>

<details>
<summary>Answers Q6–Q9 — libc interposition</summary>

**Q6.** Expect roughly fifteen to twenty-five hooked, and a similar number absent. `__xstat`,
`__lxstat`, `__fxstatat` never exist on Android (they are glibc names); `stat64`/`lstat64` exist on
32-bit only; `statx` and `execvpe` depend on the API level. A missing symbol is information about the
platform, not a failure, and any script that aborts on one is unusable across devices.

**Q7.** Only `access` was denied — because `access()` is tried first for each path and, once denied,
the code moves to the next path and tries `access` again. `stat` is only reached if `access` returns
non-zero for a path that nevertheless exists, which is a permissions case rather than an existence
case.

**Q8.** With only `access` hooked, the check still returns clean *in this implementation*, because the
loop's `stat` call is only reached after `access` fails and the file must then not exist for `stat` to
also fail... except that a hook returning `-1` from `access` for a path that genuinely exists leaves
`stat` free to succeed. Try it: deny `access` only, and `stat` finds `/system/xbin/su` and the check
fires. **That is the point of the comment in the C source**: using two syscalls per artefact means one
hook is a partial bypass, one layer down from where you learned that lesson in step 1. The pattern
repeats at every layer.

**Q9.** The defender's `errno` probe:

```c
/* A genuine ENOENT sets errno. A naive hook that only replaces the return
   value leaves errno holding whatever the previous call left there. */
static int access_looks_hooked(const char *path) {
    errno = 0xBEEF;                       /* poison */
    if (access(path, F_OK) == 0) return 0;
    return errno != ENOENT;               /* real failures set ENOENT */
}
```

This is precisely why `native-root-bypass.js` bothers with `__errno`. The rule generalises: **make the
lie indistinguishable from the truth**, and assume the defender checks the parts of the truth you
forgot about.
</details>

<details>
<summary>Answers Q10–Q11 — strace</summary>

**Q10.** `strace` observes at the kernel boundary via `ptrace`, so it sees what actually happened
regardless of what any user-space hook claims. `frida-trace` reports what *your instrumentation* saw —
if the app bypasses the symbol you instrumented, `frida-trace` shows nothing and reports no error.

`strace` is the only tool that tells the truth when: the check uses inline syscall assembly; the check
uses a statically linked copy of libc inside the app's own `.so`; the app has anti-Frida code that
detects and disables your hooks; or your hook has a bug you cannot see. When a bypass "mysteriously
fails", `strace` is the tool that ends the mystery.

Its cost is that the output is slower to read and it needs root plus, on some devices, SELinux
concessions — remember to record any device-state change you make.

**Q11.** `strace` alone cannot attribute the call. Attach a debugger and break on the syscall to read
the stack, or use Frida's `Thread.backtrace(this.context, Backtracer.FUZZY)` in an `Interceptor` on the
libc wrapper and resolve each frame with `DebugSymbol.fromAddress`. The second is what the chapter's
scripts print, and it is why the `[deny]` lines carry `module!symbol` — that line is the answer to
"where do I point Ghidra".
</details>

<details>
<summary>Answers Q12–Q15 — Ghidra and patching</summary>

**Q12.** The import table shows `access` and `stat` (or `__errno`, `fstatat`) in a library that has no
other reason to touch the filesystem. That combination *is* the finding: you know the technique before
reading any code. This is why §6.4 tells you to open Imports first — it is the highest
information-per-second step in native analysis.

**Q13.** No. JNI symbols are resolved **by name at runtime** by the JNI linker, using the mangled form
`Java_<package>_<class>_<method>`. If R8 renamed the Java class, the symbol would no longer match and
`UnsatisfiedLinkError` would be thrown at load time. So R8 either leaves such classes alone or the
build breaks. The consequence for you: **`Java_*` exports are a stable anchor that survives
obfuscation**, and they name the Java class and method they back. Same reasoning applies to
`librootbeer.so`'s `Java_com_scottyab_rootbeer_RootBeerNative_checkForRoot`.

**Q14.**

- Against an *eleventh check*: libc interposition wins. It is generic — any new check that calls
  `access`, `stat`, `fopen` and so on is covered the moment it is written, with no change to your
  script.
- Against *string obfuscation*: `Interceptor.replace` on the JNI export wins. It does not care what
  strings the function uses, because it never lets the function run. Libc interposition depends on your
  path regex matching the string, and an obfuscated build assembles paths at runtime specifically so
  your regex misses them.

The general principle: **generic hooks scale with the number of checks; targeted hooks scale with the
sophistication of each check.** Real engagements need both, which is why the chapter ships both scripts
and a tracer to tell you which to reach for.

**Q15.**

```javascript
var t = Module.findExportByName("libintegrity.so",
            "Java_com_rootlab_target_NativeCheck_findSu");
if (t !== null) {
    Memory.patchCode(t, 8, function (code) {
        var w = new Arm64Writer(code, { pc: t });
        w.putMovRegU64('x0', 0);   // return NULL — a POINTER, so X0, not W0
        w.putRet();
        w.flush();
    });
}
```

Check first that the address is in an executable range and that the module is actually mapped
(`Process.findModuleByName` returning non-null). `Memory.patchCode` handles the page protection change
for you, but patching an unmapped or non-executable address throws.

Register width matters because arm64 `W0` is the low 32 bits of `X0`. Writing `MOV W0, #0` zeroes the
whole of `X0` on arm64 (writes to a W register clear the upper 32 bits), so in this specific case it
happens to work — but the habit is dangerous: for a function returning a 64-bit value where the upper
bits must be preserved or set, the distinction is real, and you should write the width you mean.
</details>

<details>
<summary>Answers Q16–Q18 — the raw-syscall escalation</summary>

**Q16.** Signal 10 fires again. The `access` hook was covering it; now nothing does, because
`syscall(__NR_faccessat, ...)` never enters the `access` wrapper. There is no `access` call left to
intercept — the code goes straight from the app's `.so` into `syscall`, which is a different symbol
entirely.

**Q17.**

```javascript
var NR_faccessat = 48;   // arm64. Verify for your target arch.
var p = Module.findExportByName("libc.so", "syscall");
if (p !== null) {
    Interceptor.attach(p, {
        onEnter: function (args) {
            this.deny = false;
            var nr = args[0].toInt32();
            if (nr !== NR_faccessat) return;
            var path = null;
            // faccessat(dirfd, path, mode, flags) -> path is the SECOND
            // syscall argument, which is syscall()'s THIRD parameter.
            try { path = args[2].readUtf8String(); } catch (e) { return; }
            this.deny = /(^|\/)su$|magisk|busybox/i.test(path || "");
            this.path = path;
        },
        onLeave: function (retval) {
            if (this.deny) { retval.replace(ptr(-1)); }
        }
    });
}
```

The path index depends on the syscall number because each syscall has its own argument layout —
`faccessat` puts the path second, `access` puts it first, `openat` puts it second, `open` first. A
generic `syscall` hook must therefore switch on the number before it can even find the path. Note also
that syscall numbers differ between arm64 and arm32, so the constant must be selected per
architecture; hard-coding one is exactly the kind of brittleness the chapter's scripts avoid.

**Q18.** With no symbol at all, in increasing cost:

1. **`strace`** — still works, because it observes at the kernel boundary. Tells you what is probed and
   confirms the mechanism. Minutes.
2. **`Stalker`** (Frida's dynamic instrumentation of instruction streams) — can observe `svc`
   instructions being executed, at very high overhead. Tens of minutes, and painful on a whole app.
3. **Ghidra plus a runtime patch** — find the `svc` instruction, walk up to the comparison or the
   return, patch that. This is the answer in practice. One to three hours.
4. **Static patch of the `.so` plus repackage and re-sign** — when you need a persistent artefact or
   Frida is itself detected. Two to six hours, and it trips signature verification, so read
   [38-TamperDetection](../../38-TamperDetection/README.md) first.

steps 3 and 4 do not care how clever the check is. The check still ends in a comparison, and
the comparison is one instruction.
</details>

<details>
<summary>Answers Q19–Q20 — the cost curve and the assessment</summary>

**Q19.** Typical figures for a competent tester who has done this before:

| Stage | Cost |
|---|---|
| Java-layer checks (lab 01) | 20–30 minutes, or 30 seconds at the aggregation point |
| Native check via libc | 5–15 minutes with a prepared script; the script itself was an hour to write, once, ever |
| Raw syscalls | 30–90 minutes, mostly Ghidra |
| Inline `svc` assembly | 1–3 hours |

The shape is what matters. The curve is steep between "Java" and "native", flat-ish after that, and
every point on it is a **one-off** cost: once written, the bypass is reusable forever and shareable.

**Q20.** For the developer:

> Moving the check into native code with two syscalls per artefact took roughly a hundred lines and
> raised the bypass cost from thirty seconds to about fifteen minutes, and it defeats every
> copy-pasted "universal root bypass" script outright. Escalating to raw syscalls raised it to an hour
> or two — after which the bypass is written once and reused forever, so no further client-side
> investment changes the number.

For the client report:

> The application's native integrity check was defeated in approximately fifteen minutes using
> standard tooling, and the resulting bypass is reusable against all future versions of the check. The
> significant finding is not the bypass itself but that the `/api/v1/transfer` endpoint accepted the
> subsequent request without any independent server-side device-integrity validation, meaning the
> client-side check was the only control protecting that operation.

Notice that the second one barely mentions root detection. That is correct.
</details>

---

## Success criteria

- [ ] You added the native check and confirmed signal 10 fires
- [ ] You ran your lab-01 bypass unchanged and observed signal 10 survive it
- [ ] You can state, without hedging, why a `Java.perform` hook cannot see a native `access()` call
- [ ] You produced empirical evidence (a `File.exists` log with no native paths in it) rather than
      accepting the explanation
- [ ] You drew both call stacks and marked the two hook points
- [ ] You defeated the check with `native-root-bypass.js` and read `nrb.status()`
- [ ] You can explain why a long "absent symbols" list is normal
- [ ] You explained why the C code uses two syscalls per path, and what that costs a partial bypass
- [ ] You wrote the `errno` probe a defender could use to detect a naive hook
- [ ] You captured the check with `strace` and can state when `strace` is the only truthful tool
- [ ] You located the check in Ghidra starting from the import table
- [ ] You can explain why `Java_*` symbols survive R8
- [ ] You patched the function at runtime with `Interceptor.replace` and can write the
      `Memory.patchCode` equivalent
- [ ] You escalated to raw syscalls and watched libc interposition stop working
- [ ] You wrote a `syscall()` hook that branches on the syscall number
- [ ] You produced the cost curve and both versions of the assessment

---

## Next

[Lab 03 — Trace, identify, neutralise](lab-03-trace-and-neutralise.md) removes the source code. You get
a binary with twelve checks and no idea which one fires, and you learn to find out in twenty minutes
instead of guessing for three hours.
