# Lab 02 — `ArtMethod` Entrypoints

**Difficulty:** Intermediate
**Time:** 90–120 minutes
**Prerequisites:** [Lab 01](lab-01-runtime-anatomy.md), [Chapter 81 §3.5–3.7](../README.md#35-artmethod-the-structure-every-java-hook-edits),
Frida on the host and `frida-server` on the device

---

## Objective

Derive the `ArtMethod` entrypoint offset at run time, classify a method's execution state, and prove
that the same method changes state as it becomes hot. You will not install a hook. You will learn to
read the field that every hook writes.

## Why this matters

"Which code is this method running?" is the first question in every hook investigation. The answer is
not "compiled" or "interpreted" globally; it is a per-method pointer that changes. A script that
hard-codes the offset answers the question for one build and lies on the next. This lab makes the
pointer visible and the state transition measurable.

---

## Setup

### 1. Host tooling

```bash
# host — confirm Frida
frida --version
python3 -c "import frida; print(frida.__version__)"
```

### 2. Device server

```bash
# host — check the device ABI
adb shell "getprop ro.product.cpu.abi"

# host — push a matching frida-server (replace the version and ABI)
# Download the release for your host Frida version from:
# https://github.com/frida/frida/releases
adb push frida-server-<version>-android-arm64 /data/local/tmp/frida-server
adb shell "su 0 chmod 755 /data/local/tmp/frida-server"
adb shell "su 0 /data/local/tmp/frida-server &"
```

Verify:

```bash
# host
frida-ps -U | head
```

If the server cannot link, check the ABI and the Android version. A host binary and a device binary
from different Frida releases will not talk.

### 3. A target you control

The lab uses a tiny `app_process` program, so you do not need to build an APK. Save this as
`Target.java`:

```java
package com.artlab.runtime;

public final class Target {
    // Deliberately small: a prime candidate for inlining and JIT.
    public static int check(int x) {
        return (x * 31) ^ 0x5A17;
    }

    public static void main(String[] args) throws Exception {
        long acc = 0;
        for (int i = 0; i < 5_000_000; i++) {
            acc += check(i);
        }
        System.out.println("done " + acc);
        Thread.sleep(600_000);
    }
}
```

Build it with the SDK's `d8`:

```bash
# host — build a DEX that app_process can run
javac -source 8 -target 8 -d out Target.java
d8 --output out out/com/artlab/runtime/Target.class
adb push out/classes.dex /data/local/tmp/target.dex
```

Run it as shell:

```bash
# host — start the target and keep it alive
adb shell "CLASSPATH=/data/local/tmp/target.dex app_process /system/bin com.artlab.runtime.Target" &
adb shell "pidof app_process"
```

The process name is `app_process`. Record its PID.

---

## Steps

### 1. Confirm the method is reachable

```bash
# host — attach and list the class
frida -U -p <pid> -e 'Java.perform(function(){ var T = Java.use("com.artlab.runtime.Target"); console.log(T.check.overload("int")); });'
```

If the class is not found, the DEX is not on the class path or the process has already exited. Fix
that before continuing.

### 2. Run the entrypoint classifier

```bash
# host — from the repository root
frida -U -p <pid> -l 81-Android-Runtime-Internals/scripts/art-entrypoints.js
```

Then, at the Frida prompt:

```text
art.inspect("com.artlab.runtime.Target", "check")
```

The script prints the `ArtMethod` address, the entrypoint address, the mapping that owns it, and a
state label. On a cold process, the state is often the interpreter or a resolution stub. On a process
that has run the loop, it is often JIT code.

### 3. Warm the method and inspect again

The target is already running its loop. Wait a few seconds, then inspect again:

```text
art.inspect("com.artlab.runtime.Target", "check")
```

Record the before and after entrypoint addresses and mappings. If the method was already JIT-compiled
before your first inspection, restart the target and inspect earlier.

### 4. Change the compiler filter and compare

```bash
# host — force verify-only compilation for the target's DEX is not possible
# because app_process is not an installed package. Use the runtime flags instead:
adb shell "CLASSPATH=/data/local/tmp/target.dex app_process -Xint /system/bin com.artlab.runtime.Target" &
```

`-Xint` forces interpreter-only execution. Inspect again. The entrypoint should be an interpreter
entry, not JIT code. This is the control condition: it proves the classifier is reading the state, not
guessing from the method name.

### 5. Compare with a boot-classpath method

```text
art.inspect("java.lang.String", "hashCode")
```

Boot-classpath methods are commonly AOT-compiled in the boot image. The entrypoint should map to
`boot.art` or `boot.odex`, not to the JIT cache. The contrast with your target is the lesson.

### 6. Prove that the offset is derived, not hard-coded

Read the first 80 lines of [`scripts/art-entrypoints.js`](../scripts/art-entrypoints.js). Identify:

- how it obtains the `ArtMethod` pointer from a `java.lang.reflect.Method`;
- how it finds the entrypoint field offset;
- how it maps an address to a module.

Then change one thing — for example, inspect a different method — and confirm the script still works
without editing an offset. If it only works for one method, the derivation is wrong.

---

## Hints

- If `Java.perform` cannot find the class, the process may have been started before the DEX was
  pushed. Restart it.
- If the script reports "unknown mapping", print `/proc/<pid>/maps` and look for the address. The
  mapping may be `[anon:jit-code]`, `[anon:dalvik-...]` or an injected library.
- If the entrypoint looks like a small integer or an obviously invalid pointer, the offset derivation
  is wrong. Do not patch anything based on that value.
- If Frida detaches when the target exits, keep the target alive with the `Thread.sleep` in `main`.

---

## Success criteria

You can show, with output:

1. The `ArtMethod` address and entrypoint address for `Target.check`.
2. The mapping that owns the entrypoint, and a state label.
3. A before/after pair showing the method change state after it became hot.
4. A control run with `-Xint` showing an interpreter entry.
5. A boot-classpath method whose entrypoint is in the boot image, for contrast.
6. An explanation of why the script derives the offset instead of hard-coding it.

---

## Cleanup

```bash
# host
adb shell "su 0 pkill -f frida-server"
adb shell "rm /data/local/tmp/target.dex"
adb shell "rm /data/local/tmp/frida-server"
```

If you used a disposable emulator, revert the snapshot instead.
