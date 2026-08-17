# Lab 03 — Scope, timing, and the five ways a module fails

> **Difficulty:** Intermediate → Advanced
> **Time:** 2–3 hours
> **Needs LSPosed installed?** Sections 1–5 do. **Section 6 runs entirely on the host** and is the
> one that teaches the diagnostic discipline, so do it even if you have no rooted device.
> **Prerequisite:** [Lab 02](lab-02-your-first-module.md) — you need the vault app and a working
> module.

---

## Objective

You will be given **five modules**. Every one compiles. Every one loads. Every one installs a hook
that the framework accepts without complaint. **None of them does anything.**

Your job is to diagnose each, in the fewest steps, and to end with a diagnostic order you can run
from memory. That order is the deliverable — not the five fixes.

This is the LSPosed counterpart of [65-Hooking Lab 03](../../65-Hooking/labs/lab-03-where-hooks-fail.md),
which does the same exercise for native hooks. The failures rhyme and the diagnostics do not, which
is exactly why both labs exist.

---

## Why "correct and useless" is the interesting case

A module that throws is easy: read the exception, fix the signature, move on. A module that installs
cleanly and changes nothing gives you no information at all, and the temptation is to start guessing —
change the class, change the method, add a second hook, rebuild, wait, look again. Each cycle is
three minutes with a module, and after ten of them you have learned nothing and lost half an hour.

**The cure is an ordered diagnostic where each step rules out a whole class of cause.** Below is the
order. Learn it, then earn it on the five broken modules.

### The order

| # | Question | How to answer it in one step | Rules out |
|---|---|---|---|
| 1 | Did the target process restart? | `ps -A \| grep <pkg>`, note the pid, force-stop, compare | Everything downstream. A module loads at **process start** |
| 2 | Is the module enabled and **scoped** to this package? | The manager | Scope |
| 3 | Is the target on Magisk's **DenyList**? | `magisk --denylist ls` | LSPosed skips DenyListed processes |
| 4 | Did the framework load the module at all? | LSPosed's log lists module loads | Bad `assets/xposed_init`, missing `xposedmodule` |
| 5 | Did `handleLoadPackage` run? | An **unconditional** log on its first line | Everything above versus everything below |
| 6 | Are you in the right **process**? | Log `lpparam.processName` | `android:process` components |
| 7 | Did the installation throw? | A `catch` that logs | Signature, class loader, renaming |
| 8 | Was the method **inlined**? | `cmd package compile -m verify -f`, force-stop, retry | AOT inlining |
| 9 | Is the class defined by a loader you cannot see? | Enumerate loaders; hook `loadClass` | Packers, plugins, feature modules |
| 10 | Does anything call the method? | jadx, look for the call site | A perfect hook on dead code |

Steps **5 and 7** are the two that people skip, and they are the two that split the search space in
half. Everything below them is wasted effort until they are answered.

---

## Setup

You need the vault app from Lab 02 installed, and a module project you can rebuild quickly. Add a
second `record`-style hook target to the vault app for section 5:

`app/src/main/java/com/pentest/ch63/vault/SyncService.java`, and declare it in the manifest with
`android:process=":worker"`:

```java
package com.pentest.ch63.vault;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

/** Runs in com.pentest.ch63.vault:worker -- a DIFFERENT process. */
public class SyncService extends Service {
    @Override public int onStartCommand(Intent i, int flags, int id) {
        Log.i("SyncService", "sync in process " + android.os.Process.myPid());
        boolean ok = new VaultGate().isUnlocked("whatever");
        Log.i("SyncService", "worker isUnlocked -> " + ok);
        return START_NOT_STICKY;
    }
    @Override public IBinder onBind(Intent i) { return null; }
}
```

```xml
<service android:name=".SyncService"
         android:process=":worker"
         android:exported="true"/>
```

Drive it with:

```bash
adb shell am startservice -n com.pentest.ch63.vault/.SyncService
```

---

## Failure 1 — The process that never restarted

**The module:**

```java
public class Broken1 implements IXposedHookLoadPackage {
    @Override public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!"com.pentest.ch63.vault".equals(lpparam.packageName)) return;
        XposedHelpers.findAndHookMethod("com.pentest.ch63.vault.VaultGate",
                lpparam.classLoader, "isUnlocked", String.class,
                new XC_MethodHook() {
                    @Override protected void beforeHookedMethod(MethodHookParam p) {
                        XposedBridge.log("B1 isUnlocked(" + p.args[0] + ")");
                    }
                });
    }
}
```

That module is **correct**. Install it, enable it, scope it, open the app — and nothing appears in
the log.

**Task 1.1.** Before reading on, run step 1:

```bash
adb shell 'ps -A -o PID,NAME' | grep pentest
# note the pid
adb shell am force-stop com.pentest.ch63.vault
adb shell am start -n com.pentest.ch63.vault/.MainActivity
adb shell 'ps -A -o PID,NAME' | grep pentest
# is the pid different?
```

**The diagnosis.** The app was already running when you enabled the module. **A module is loaded at
process start**, in `postAppSpecialize`, right after the `fork()`. There is no mechanism by which it
could enter a process that already exists — that is the whole architectural difference from Frida,
which attaches to running processes.

Android also keeps app processes alive long after the user leaves the app, so "I closed it and
reopened it" is not the same as "the process restarted".

**Task 1.2.** How would you make this failure *impossible* to make again in your own workflow? (One
good answer: a shell function that force-stops before every launch. Another: read the pid every time.)

> **⚠️ Some changes need more than a force-stop.** Enabling the framework itself, and scope changes
> involving `android`, generally need a reboot. If a force-stop does not do it and everything else
> checks out, reboot before you start doubting your code.

---

## Failure 2 — The wrong process

**The module** is identical to Broken1, and this time you force-stopped correctly. The app's UI
works, the hook fires there — but the log line never appears when you drive `SyncService`.

```bash
adb shell am force-stop com.pentest.ch63.vault
adb shell am startservice -n com.pentest.ch63.vault/.SyncService
adb logcat -d -s SyncService
```

**Task 2.1.** Run step 6. Add this to the top of `handleLoadPackage`, above every filter:

```java
XposedBridge.log("B2 loaded: pkg=" + lpparam.packageName
        + " process=" + lpparam.processName
        + " isFirst=" + lpparam.isFirstApplication);
```

**Expected:** `handleLoadPackage` fires **twice** — once with
`process=com.pentest.ch63.vault` and once with `process=com.pentest.ch63.vault:worker`.

**The diagnosis.** `packageName` is the same in both; `processName` is not. If your module's filter
compares `processName` against the package name, or if it installs a hook that only makes sense in
the UI process, the worker process gets nothing.

**Task 2.2.** Which of these three filters is right, and why are the other two wrong?

```java
if (!"com.pentest.ch63.vault".equals(lpparam.packageName)) return;                 // A
if (!"com.pentest.ch63.vault".equals(lpparam.processName)) return;                 // B
if (!lpparam.processName.startsWith("com.pentest.ch63.vault")) return;             // C
```

**Task 2.3.** A real one from practice: an application does its network setup in a `:remote`
process and its UI in the main one. You hook the TLS path and see nothing. Which line of your log
would have told you immediately?

---

## Failure 3 — The wrong class loader

**The module:**

```java
XposedHelpers.findAndHookMethod("com.pentest.ch63.vault.VaultGate",
        null,                                  // <-- the bug
        "isUnlocked", String.class, cb);
```

**Task 3.1.** Predict the exception before you build it. Then build it and read the actual one.

**Expected:** `XposedHelpers$ClassNotFoundError` naming `com.pentest.ch63.vault.VaultGate`.

**The diagnosis.** `null` means the **boot class loader**, which knows `android.*` and `java.*` and
has never heard of an application's classes. Neither has your module's own loader. Only
`lpparam.classLoader` has.

**Task 3.2.** Now the harder half. Why does this work?

```java
XposedHelpers.findAndHookMethod("android.app.Application", null,
        "attachBaseContext", Context.class, cb);
```

**Task 3.3.** Draw the loader graph for a scoped process: boot loader, the app's `PathClassLoader`,
and the module's loader. Mark which arrows exist and which do not. Check it against chapter §3.5's
diagram.

**Task 3.4 — the important one.** This failure had a *loud* symptom. What would have happened if the
module had swallowed it?

```java
try {
    XposedHelpers.findAndHookMethod(..., null, ...);
} catch (Throwable ignored) { }       // <-- never do this
```

You would have converted a five-second diagnosis into failure 5's search. **Every hook installation
belongs in a `try`/`catch` that logs.** A silent `catch` is worse than no `catch`.

---

## Failure 4 — The method that was inlined away

This one needs a small change to the vault app so the compiler has something to inline. Add:

```java
// in VaultGate
private boolean postureOk() { return sDeviceOk != null && sDeviceOk.booleanValue(); }

public boolean isUnlockedFast(String pin) {
    if (!postureOk()) return false;                  // small, hot, private, final-ish
    return matches(pin, loadExpectedPin());
}
```

Hook `postureOk`:

```java
XposedHelpers.findAndHookMethod("com.pentest.ch63.vault.VaultGate",
        lpparam.classLoader, "postureOk", new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam p) {
                XposedBridge.log("B4 postureOk -> " + p.getResult());
                p.setResult(Boolean.TRUE);
            }
        });
```

**Task 4.1.** Install it, force-stop, exercise `isUnlockedFast`. Does the hook fire?

**Task 4.2.** If it does not, run step 8:

```bash
adb shell cmd package compile -m verify -f com.pentest.ch63.vault
adb shell am force-stop com.pentest.ch63.vault
adb shell am start -n com.pentest.ch63.vault/.MainActivity
```

Now does it fire?

**The diagnosis.** `cmd package compile -m verify -f` discards the ahead-of-time-compiled code and
leaves only the DEX, which still contains a real `invoke-direct` to `postureOk`. If the hook fires
after that command and not before, **the method was inlined into its caller** and there was no
dispatch through its `ArtMethod` to intercept.

[13-ART](../../13-ART/README.md) owns this and its three siblings; the four causes are inlined
callee, AOT-compiled caller with the result baked in, target not resolved yet, and wrong class
loader.

> **🔍 The finding is not "my hook did not work".** The finding is *"the posture check is inlined at
> the app's compilation level, so a hook on it has no effect — you have to hook the caller"*, and on
> the defensive side, *"a small private check being inlined is why this control is harder to hook
> than the developer's threat model assumed"*. Chapter 65's §5.4 records the native twin of this
> exact result: a function patched to `return 1`, verified returning 1, and the caller still refused —
> because clang had inlined it and the patched copy is called by nothing.

**Task 4.3.** Confirm it statically. In jadx, does `isUnlockedFast` contain an `invoke-direct` to
`postureOk`, or a copy of its body?

**Task 4.4.** Fix the module without `cmd package compile`. (Hook the caller.)

---

## Failure 5 — The class that does not exist yet

Add a packed class to the vault app. In `MainActivity.onCreate`, after a delay:

```java
new android.os.Handler().postDelayed(() -> {
    try {
        // Simulates a plugin/packer: a class loaded by a loader the app builds.
        ClassLoader child = new dalvik.system.PathClassLoader(
                getApplicationInfo().sourceDir, getClassLoader());
        Class<?> c = child.loadClass("com.pentest.ch63.vault.LateGate");
        Log.i("VaultMain", "LateGate loaded by " + c.getClassLoader());
    } catch (Exception e) {
        Log.w("VaultMain", "late load failed", e);
    }
}, 3000);
```

with a trivial `LateGate`:

```java
package com.pentest.ch63.vault;
public class LateGate {
    public boolean verify(String token) { return "open-sesame".equals(token); }
}
```

**Task 5.1.** Hook `com.pentest.ch63.vault.LateGate.verify` from `handleLoadPackage` using
`lpparam.classLoader` and `findClass` (not `findClassIfExists`). What happens?

**Task 5.2.** Now use `findClassIfExists` and log the `null`. Better?

**Task 5.3.** Read [`../examples/LateClassHookModule.java`](../examples/LateClassHookModule.java) and
adapt it. Three details in that file are load-bearing; find them:

1. Why `hookAllMethods(ClassLoader.class, "loadClass", ...)` rather than `findAndHookMethod` with a
   signature.
2. Why the guard is `compareAndSet` and not a plain `if (!installed) { installed = true; ... }`.
3. Why the callback does the cheapest possible rejection first.

**Task 5.4.** Instrument the callback with a counter and log how many `loadClass` calls happen before
your class appears.

**Expected:** a number in the hundreds or thousands. That is why point 3 above matters: you are on
the hot path of every class load in the process, and a detector that times class loading can notice
an expensive callback there.

**Task 5.5.** In this lab the class was loaded by a `PathClassLoader` over the app's *own* APK, which
is the friendly case. Name two real-world cases where the DEX is not on disk at all, and say what
changes about your approach. (Hint: `InMemoryDexClassLoader`, and chapter §4.5's note about why it
exists.)

---

## Section 6 — Do the whole diagnostic on the host, with no device

If you have no rooted device, this section is where the lab's value is, and it is worth doing even if
you do.

**Task 6.1.** For each of the five failures above, write the **single shortest command or log line**
that distinguishes it from the other four. You should end with five entries. Compare them with the
ten-step table at the top.

**Task 6.2.** Build all five broken modules with the offline path:

```bash
./scripts/build-xposed-module.sh --src /path/to/broken --out /tmp/broken --keep --decompile
```

Which of the five failures does the compiler catch? Which does the *disassembly* reveal? Which are
invisible until the module runs on a device?

**Expected:** none of the five is a compile error, and only failure 3 is visible in the disassembly —
`const/4 v0, 0x0` passed where a `ClassLoader` should be. **Four of five are runtime-only, and that
is the honest reason the diagnostic order matters more than any amount of code review.**

**Task 6.3.** Write the diagnostic order out from memory. Then check it against the table. Note which
steps you left out — those are the ones you will skip under time pressure, and they are usually 5 and
7.

---

## Section 7 — The failure the table does not cover

There is a sixth failure mode, and it is worth ending on because it is the one that wastes the most
time when it happens.

**The module works. The hook fires. The behaviour does not change.**

```java
XposedHelpers.findAndHookMethod(..., "isUnlocked", String.class, new XC_MethodHook() {
    @Override protected void afterHookedMethod(MethodHookParam p) {
        XposedBridge.log("fired!");           // this prints
        p.setResult(Boolean.TRUE);            // and the UI still says "denied"
    }
});
```

**Task 7.1.** Give two reasons this can happen. Then check the vault app for whichever applies.

Two good answers:

- **The caller ignores the return value on some paths.** `MainActivity` calls
  `gate.isUnlocked(...)` and uses the result, but `SyncService` logs it and does nothing. Hooking a
  producer changes every consumer *that consults it*.
- **Another hook at a higher priority already called `setResult` in `before`**, which skipped the
  original body and every lower-priority `before` — including yours, if yours was a `before`. Nothing
  logs this.

**Task 7.2.** Add a second module that hooks the same method with `PRIORITY_HIGHEST` and calls
`setResult` in `before`. Observe what happens to the first module's callbacks. Write down what you
would have concluded if you did not know the second module existed.

> **🧠 Mental Model.** Chapter 65 states this for native hooks and it is identical here: **"never
> fired" and "fired but did nothing" are different problems with different fixes**, and an
> unconditional log on entry is the one line that tells them apart. Everything in this lab is
> downstream of that distinction.

---

## Success criteria

- [ ] You can state the ten-step diagnostic order from memory.
- [ ] You diagnosed each of the five failures using **at most two** steps of it.
- [ ] You can explain why a module cannot enter an already-running process, in terms of `fork`.
- [ ] You can explain why `processName` and `packageName` are different, and name a real case where
      it matters.
- [ ] You can explain what `null` means as a class loader and when it is correct.
- [ ] You ran `cmd package compile -m verify -f` and can say precisely what it changed.
- [ ] You wrote the finding for the inlining case as a sentence about the *application*, not about
      your tooling.
- [ ] You can name the sixth failure mode and its two causes.
- [ ] You never again write `catch (Throwable ignored) { }` around a hook installation.

---

## Next

[Lab 04 — CTF: The Invisible Module](lab-04-ctf-the-invisible-module.md). Four layered defences, one
approach that walks past all of them, and a Gold solution that needs no module at the end.

---

| | |
|---|---|
| **Chapter** | [63-LSPosed](../README.md) — §3.5 class loaders, §3.11 deoptimisation, §7.4 the diagnostic |
| **Example** | [`../examples/LateClassHookModule.java`](../examples/LateClassHookModule.java) |
| **See also** | [65-Hooking Lab 03](../../65-Hooking/labs/lab-03-where-hooks-fail.md) — the same exercise for native hooks · [13-ART](../../13-ART/README.md) — the four causes, owned |
