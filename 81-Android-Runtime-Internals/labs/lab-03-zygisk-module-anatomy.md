# Lab 03 — Zygisk Module Anatomy

**Difficulty:** Advanced
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-runtime-anatomy.md), [Chapter 81 §3.10–3.11](../README.md#310-zygisk-the-module-abi),
NDK r21 or newer, a rooted lab device with Magisk Zygisk or ZygiskNext

---

## Objective

Build a minimal Zygisk module, inspect its ELF exports, package it correctly, and prove the callback
order on a real device: `onLoad` and `preAppSpecialize` run while the child is still privileged;
`postAppSpecialize` runs with the app's UID and SELinux domain. You will not hook a method. The
module only logs, because the lifecycle is the lesson.

## Why this matters

Most "my Zygisk module does nothing" reports are packaging or lifecycle mistakes, not C++ mistakes.
The library is built for the wrong ABI, placed at the wrong path, loaded into the wrong process, or
it assumes root in `postAppSpecialize`. This lab makes each of those visible before you add a hook.

---

## Setup

### 1. Toolchain

```bash
# host — confirm the NDK and the compiler
echo "$ANDROID_NDK_HOME"
ls "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin" | grep aarch64
```

If `ANDROID_NDK_HOME` is unset, set it to your NDK path. The exact host tag (`linux-x86_64`,
`darwin-x86_64`) depends on your machine.

### 2. Zygisk header

The canonical header is in the official sample:

```bash
# host — fetch the self-documented Zygisk API header
curl -L -o zygisk.hpp \
  https://raw.githubusercontent.com/topjohnwu/zygisk-module-sample/master/module/jni/zygisk.hpp
```

The header is 0BSD-licensed. Read the comments at the top: they define the API version and the
callback contract.

### 3. Device

You need one of:

- Magisk with Zygisk enabled;
- KernelSU or APatch with ZygiskNext installed, and Magisk's built-in Zygisk disabled if Magisk is
  also present.

```bash
# host — confirm root and the loader
adb shell "su 0 id"
adb shell "ls /data/adb/modules" 2>/dev/null
adb shell "getprop ro.product.cpu.abi"
```

Record the ABI. The module library must match it.

---

## Steps

### 1. Build the module

The source is [`examples/01-minimal-zygisk-module.cpp`](../examples/01-minimal-zygisk-module.cpp).
Build it for the device ABI:

```bash
# host — arm64-v8a; change the target triple for another ABI
"$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang++" \
  -shared -fPIC -std=c++17 -fno-exceptions -fno-rtti -fvisibility=hidden \
  -o arm64-v8a.so \
  81-Android-Runtime-Internals/examples/01-minimal-zygisk-module.cpp \
  -I. -llog
```

The `-fvisibility=hidden` is deliberate: the loader finds the module entry, not every symbol you
happen to export.

### 2. Inspect the exports before installing

```bash
# host — the loader needs the module entry symbol
readelf -Ws arm64-v8a.so | grep -E "zygisk_module_entry|JNI_OnLoad"

# host — confirm the architecture and the dependencies
file arm64-v8a.so
readelf -d arm64-v8a.so | grep NEEDED
```

A module with no `zygisk_module_entry` will not load. A module built for `x86_64` on an arm64 device
will be marked incompatible (`zygisk/unloaded`).

### 3. Package the module

A Zygisk module is a Magisk module with a `zygisk/` directory. The library is named after the ABI,
not `libexample.so`:

```text
runtime-lab/
├── module.prop
└── zygisk/
    └── arm64-v8a.so
```

`module.prop`:

```text
id=runtime_lab
name=Runtime Lab
version=v1.0
versionCode=1
author=you
description=Minimal Zygisk lifecycle logger
```

```bash
# host — build the installable zip
cd runtime-lab
zip -r ../runtime-lab.zip .
cd ..
```

### 4. Install and reboot

Install the zip with your root manager's module installer, or copy it into
`/data/adb/modules/runtime_lab` on a device where that is appropriate. Reboot.

```bash
# host — after reboot, confirm the module is present and not disabled
adb shell "ls /data/adb/modules/runtime_lab"
adb shell "cat /data/adb/modules/runtime_lab/module.prop"
```

If `zygisk/unloaded` exists, the loader rejected the library. Check the ABI, the entry symbol and the
API version.

### 5. Watch the callbacks

```bash
# host — clear the log, launch an app, and filter the module's tag
adb logcat -c
adb shell "am start -a android.settings.SETTINGS"
adb logcat -v threadtime -s RuntimeLab
```

Expected order for one app process:

```text
onLoad
pre-specialize uid=0
post-specialize uid=<app uid>
```

The exact UID is the app's, not 0. If both callbacks report 0, the module is logging before
specialization or the process is not the one you think. If `post` never appears, the app may have
been forked through a path that did not load the module, or the module requested unload too early.

### 6. Prove the privilege difference

Add a temporary line to `preAppSpecialize` that reads a root-only path, and one to
`postAppSpecialize` that reads the same path. Rebuild, reinstall, reboot, and compare. The `pre` read
should succeed; the `post` read should fail with `EACCES` or be blocked by SELinux. If both succeed,
you are not looking at the app process, or SELinux is not enforcing.

Restore the source after the experiment.

### 7. Static fallback

If you do not have a Zygisk-compatible loader, do steps 1–2 and answer:

- What symbol does the loader look for?
- Which ABI name would the library have on an x86_64 emulator?
- Why does `-fvisibility=hidden` not hide the module entry?
- What happens if the module is built against API 5 but the loader only supports API 4?

The last question is answered by the header's versioning comments, not by guessing.

---

## Hints

- `zygisk/unloaded` is the loader telling you it rejected the library. Read the loader's log before
  changing the code.
- On Magisk with ZygiskNext, the built-in Zygisk must be off. Two loaders fighting over the same
  process produce confusing results.
- A module that calls `setOption(DLCLOSE_MODULE_LIBRARY)` too early can unload itself before `post`.
  Read the option's comment in the header.
- Do not use the NDK's C++ STL in a Zygisk module unless you understand the ABI conflict. The sample
  uses `APP_STL := none` for a reason.

---

## Success criteria

You can show:

1. A built `arm64-v8a.so` with a `zygisk_module_entry` export.
2. A packaged module with `module.prop` and `zygisk/arm64-v8a.so`.
3. A log showing `onLoad`, `pre` with UID 0, and `post` with the app's UID.
4. An explanation of why `pre` can do privileged work and `post` cannot.
5. A static explanation of what `zygisk/unloaded` means and how to fix it.
6. The exact API version the header declares, and what that implies for compatibility.

---

## Cleanup

```bash
# host — remove the module and reboot
adb shell "su 0 rm -rf /data/adb/modules/runtime_lab"
adb reboot
```

Keep the source and the build command; you will reuse them in Lab 04 if you choose the module route.
