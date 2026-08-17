# Lab 03 — Patch the platform

**Difficulty:** Advanced
**Time:** 3–4 hours (assuming Lab 02 is complete and you have a built tree)
**Chapter:** [07 — AOSP](../README.md) §3.10, §4.1, §9.3
**Prerequisite:** [Lab 02](lab-02-build-and-boot-aosp.md) — a built, booting `userdebug` Cuttlefish image

---

## Objective

Add Binder and permission tracing to the Android framework itself, rebuild with `m snod`, and capture a
complete IPC trace of an application's startup — produced by the operating system, below anything the
application can hook, detect or disable.

Then do the thing that separates a researcher from a hobbyist: keep the instrumentation as a reviewed
patch series, and reproduce a finding on a clean image.

---

## Why this matters

Every observation technique you have used so far runs inside user space, in a process the target can
influence. Frida hooks are in the traced process. `strace` is visible in `/proc`. An application with
competent anti-analysis logic can find all of them.

Instrumentation compiled into the platform is different in kind. It runs in `system_server`, in
`libbinder`, in the linker — processes the application does not control and cannot inspect. An app that
detects Frida, refuses to run under a debugger and verifies its own code integrity will produce a
complete trace anyway, and will never know.

The cost is that you must build, and that a patched image is not evidence. Part E is about that.

---

## Setup

```bash
# host
cd ~/aosp/android-15.0.0_r1
source build/envsetup.sh
lunch aosp_cf_x86_64_phone-trunk_staging-userdebug

# start from a known-clean tree
repo forall -pc 'git status --short' | head -20      # should be empty
```

Create a patch series directory. Keeping instrumentation here — rather than as loose edits — is the
whole discipline of this lab.

```bash
# host
mkdir -p ~/aosp-research-patches
```

---

## Part A — Trace every incoming Java Binder call

### A1. Find the current signature

Do not assume. AOSP moves.

```
# cs.android.com — with the branch set to your release
file:Binder.java function:execTransact
```

**Record:** the exact signature, and the file path.

```bash
# host
croot
grep -n "execTransact" frameworks/base/core/java/android/os/Binder.java
```

### A2. Understand why this method

Before editing, be able to state why this one method is worth instrumenting.

**Record:** From [§4.1 step 8](../README.md#4-source-code-walkthrough-aosp), what passes through
`execTransact`, in which processes, and what identity is already available inside it.

### A3. Apply the instrumentation

Use [`../examples/04-binder-trace.patch`](../examples/04-binder-trace.patch) as the model. Do **not**
apply it blindly — read it, then write the equivalent for your release.

The essential shape:

```java
// frameworks/base/core/java/android/os/Binder.java

    // ================== RESEARCH INSTRUMENTATION ==========================
    private static final String RESEARCH_TRACE_TAG = "BINDER_TRACE";
    private static final boolean RESEARCH_TRACE_ENABLED =
            SystemProperties.getBoolean("persist.research.binder_trace", false);

    private void researchTrace(int code, int flags) {
        // Must be exception-safe. This runs on the hot path of every IPC on
        // the device; a throw here takes down system_server.
        try {
            String iface = null;
            try { iface = getInterfaceDescriptor(); } catch (Throwable ignored) { }
            Slog.i(RESEARCH_TRACE_TAG,
                    "impl=" + getClass().getName()
                    + " iface=" + (iface == null ? "(none)" : iface)
                    + " code=" + code
                    + " flags=" + flags
                    + " uid=" + getCallingUid()
                    + " pid=" + getCallingPid()
                    + " myPid=" + Process.myPid());
        } catch (Throwable ignored) { }
    }
    // ================ END RESEARCH INSTRUMENTATION ========================
```

and, at the very top of `execTransact`'s body:

```java
        if (RESEARCH_TRACE_ENABLED) {
            researchTrace(code, flags);
        }
```

Three design decisions worth noticing, because they are why this is safe to run:

| Decision | Reason |
|---|---|
| Gated on a system property | The image stays usable normally; the trace costs one boolean read when off |
| The whole body wrapped in `try { } catch (Throwable) { }` | Instrumentation must never be able to crash `system_server` |
| `getInterfaceDescriptor()` in its own try | Some `Binder` subclasses have no descriptor; that is normal, not an error |

### A4. Build and deploy

```bash
# host
m framework
m snod
stop_cvd && launch_cvd --daemon
adb wait-for-device && adb root
```

**Record:** the time for `m framework` and for `m snod`.

### A5. Enable and capture

```bash
# host
adb root
adb shell setprop persist.research.binder_trace 1
adb shell stop && adb shell start          # restart the framework
sleep 20
adb logcat -s BINDER_TRACE | head -40
```

**Record:** the first ten lines. Identify one interface you recognise from
[Trace A](../README.md#41-trace-a--contextstartactivity-from-your-code-to-the-kernel-and-back).

---

## Part B — Trace an application's startup

### B1. Pick a target

Any app. A stock AOSP app such as Settings works, and so does one you install.

```bash
# adb shell
dumpsys package com.android.settings | grep userId
```

**Record:** the app's UID.

### B2. Capture

```bash
# host
adb logcat -c
adb shell am force-stop com.android.settings
adb shell am start -n com.android.settings/.Settings
sleep 5
adb logcat -d -s BINDER_TRACE > ~/trace-settings.txt
wc -l ~/trace-settings.txt
```

### B3. Analyse

```bash
# host
# which interfaces, how often
grep -oE 'iface=[^ ]+' ~/trace-settings.txt | sort | uniq -c | sort -rn | head -20

# only what OUR app asked for
grep "uid=<the UID you recorded>" ~/trace-settings.txt | wc -l

# the distinct (interface, code) pairs — the app's real API surface usage
grep -oE 'iface=[^ ]+ code=[0-9]+' ~/trace-settings.txt | sort -u | head -30

# a timeline
head -60 ~/trace-settings.txt
```

**Record:**
- Total transactions during a 5-second startup.
- The top five interfaces by frequency.
- The first five distinct interfaces touched, in order. Map each to what the app was doing.

### B4. Map a code back to a method

Pick one `(iface, code)` pair and identify the method.

```bash
# host — the generated Stub, after a build
find out/soong -name "IActivityTaskManager.java" | head -1
grep -n "TRANSACTION_" $(find out/soong -name "IActivityTaskManager.java" | head -1) | head -30
```

**Record:** the method name for your chosen code. Then note **why transaction codes are
release-specific** — they are assigned in AIDL declaration order, so adding a method shifts everything
after it.

---

## Part C — Trace permission decisions

### C1. Find the current location

Class names in the permission subsystem have moved between releases. Practise the procedure.

```
# cs.android.com
path:frameworks/base/services/core/java/com/android/server/pm/permission function:checkPermission
```

**Record:** the file and method you found, and the branch you were reading.

### C2. Instrument the decision

Add a log at the point where the final grant/deny is returned:

```java
        Slog.i("PERM_TRACE", "perm=" + permName
                + " pkg=" + packageName
                + " uid=" + Binder.getCallingUid()
                + " pid=" + Binder.getCallingPid()
                + " user=" + userId
                + " result=" + (result == PackageManager.PERMISSION_GRANTED
                                   ? "GRANTED" : "DENIED"));
```

```bash
# host
m services
m snod
stop_cvd && launch_cvd --daemon
```

### C3. Capture a real decision

```bash
# host
adb logcat -c
# Trigger something that needs a dangerous permission — e.g. open the camera
adb shell am start -a android.media.action.IMAGE_CAPTURE
sleep 3
adb logcat -d -s PERM_TRACE | head -40
```

**Record:** the permission names checked, by whom, and the results.

### C4. Watch a denial

```bash
# host
adb shell pm revoke com.android.settings android.permission.CAMERA 2>/dev/null || true
adb logcat -c
# trigger the feature again
adb logcat -d -s PERM_TRACE | grep DENIED
```

**Record:** the exact log line for the denial. Then answer: **is this the same thing as the app's
`checkSelfPermission` call, or a different one?** (Trace C, [§4.3](../README.md#43-trace-c--a-permission-check-from-checkselfpermission-to-the-enforcement-point).)

---

## Part D — Save the patch series

This is what turns an afternoon of edits into a reproducible environment.

```bash
# host
croot

# Produce one patch per project, named so a script can map it back
git -C frameworks/base diff > ~/aosp-research-patches/frameworks_base.binder-perm-trace.patch

# Verify it applies cleanly to a clean tree
git -C frameworks/base stash
git -C frameworks/base apply --check ~/aosp-research-patches/frameworks_base.binder-perm-trace.patch \
  && echo "applies cleanly"
git -C frameworks/base stash pop
```

Write a `README.md` in the patch directory describing each patch: what it instruments, which property
enables it, what the log tag is, and which AOSP tag it was written against.

**Record:** why keeping these as files in git — rather than as edits in a tree — matters. Three reasons
are in [§9.5](../README.md#95-enterprise--a-reproducible-aosp-research-environment).

---

## Part E — Reproduce on a clean image

The discipline that makes any of this usable in a report.

### E1. Build a clean image

```bash
# host
cd ~/aosp
~/path/to/07-AOSP/examples/05-research-env/setup.sh -t android-15.0.0_r1 --clean
```

Or by hand: sync a second tree at the same tag, apply nothing, build.

### E2. Reproduce

Take one observation from Part B or C — for example "the app queries `IPackageManager` seventeen times
during startup" or "permission X is checked before Y" — and confirm it on the clean image using only
tools that exist there: `logcat`, `dumpsys`, `strace`, kernel binder tracepoints, Frida.

```bash
# adb shell as root, on the CLEAN image — the unpatched equivalent
mount -t debugfs none /sys/kernel/debug 2>/dev/null
echo 1 > /sys/kernel/debug/tracing/events/binder/enable
cat /sys/kernel/debug/tracing/trace_pipe | head -40
echo 0 > /sys/kernel/debug/tracing/events/binder/enable
```

**Record:** whether the observation held, and what the clean-image method could **not** show you that
the patch could.

> **⚠️** A patched platform is a **research instrument**, not evidence. Every finding demonstrated on a
> patched image must be reproduced on an unmodified one before it goes in a report, and the report must
> state which image each piece of evidence came from. The failure mode is embarrassing and common: a
> "vulnerability" that exists only because a check was commented out three weeks earlier and forgotten.

---

## Part F — Prove it is undetectable from user space

The payoff.

### F1. Install something that looks

Build a small app that performs the usual anti-analysis checks: scan `/proc/self/maps` for injected
libraries, check for the Frida server port, check `TracerPid` in `/proc/self/status`, verify its own DEX
checksum.

```kotlin
// A minimal version of what real anti-analysis code does
fun looksInstrumented(): Boolean {
    val maps = java.io.File("/proc/self/maps").readText()
    if (maps.contains("frida") || maps.contains("gum-js-loop")) return true
    val status = java.io.File("/proc/self/status").readText()
    if (Regex("TracerPid:\\s*([1-9]\\d*)").containsMatchIn(status)) return true
    return false
}
```

### F2. Run it under both

```bash
# host — with Frida attached
frida -U -f com.example.antianalysis -l ../scripts/binder-trace.js --no-pause
# the app's check should fire

# host — with the PLATFORM patch, no Frida
adb shell am start -n com.example.antianalysis/.MainActivity
adb logcat -d -s BINDER_TRACE | grep "uid=<app uid>"
# the app's check does NOT fire, and you still have the complete trace
```

**Record:** the difference. Write one paragraph explaining, in terms of *where the instrumentation
lives*, why the app can find one and not the other.

---

## Success criteria

- [ ] `execTransact` is instrumented, gated on a system property, and exception-safe.
- [ ] `m framework && m snod && relaunch` completes in under five minutes and you recorded the time.
- [ ] You captured a full Binder trace of an app's startup and produced a ranked interface list.
- [ ] You mapped at least one transaction code back to a method name from the generated Stub.
- [ ] Permission decisions are instrumented and you captured both a GRANTED and a DENIED line.
- [ ] The instrumentation exists as patch files that apply cleanly to a fresh tree, with a README.
- [ ] You reproduced one observation on a **clean** image and recorded what the clean method could not
      show.
- [ ] You demonstrated that an anti-analysis app detects Frida and does not detect the platform patch,
      and can explain why.

---

## Extension patches

Each of these is a one-liner once you know where to look. Add them to the series.

| Goal | Where | Log tag |
|---|---|---|
| Every native Binder transaction, including from processes with no Java | `frameworks/native/libs/binder/IPCThreadState.cpp` → `transact()` | `BINDER_NATIVE` |
| Every `dlopen` | `bionic/linker/linker.cpp` | `DLOPEN_TRACE` |
| Every Keystore operation with its purposes and auth bindings | `system/security/keystore2/` | `KS_TRACE` |
| Every broadcast delivered | `frameworks/base/services/core/java/com/android/server/am/` broadcast paths | `BCAST_TRACE` |
| Every `ContentProvider` query, with the calling package | `frameworks/base/core/java/android/content/ContentProvider.java` | `CP_TRACE` |
| Every SQLite statement | `frameworks/base/core/java/android/database/sqlite/` | `SQL_TRACE` |

---

## Discussion questions

1. Your instrumentation is inside `system_server`, which is UID 1000. What would happen if
   `researchTrace` threw an uncaught exception, and why is the `try { } catch (Throwable) { }` not
   optional?
2. The trace is gated on `persist.research.binder_trace`. Why gate it at all, rather than always
   logging? Consider both performance and the fact that `logd` is readable by more processes than you
   might assume.
3. You can now see every Binder call on the device. Name two findings this makes reachable that would be
   very hard to find any other way — and one class of finding it does **not** help with at all.
4. Compare three ways to observe Binder traffic: this patch, Frida on `execTransact`, and kernel
   binder tracepoints. For each, state what it sees, what it misses, and what an adversarial application
   could do about it.
