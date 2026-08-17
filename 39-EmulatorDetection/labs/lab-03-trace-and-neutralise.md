# Lab 03 — Trace and neutralise

> **Difficulty:** Advanced
> **Time:** 3–5 hours
> **Prerequisites:** [Lab 01](lab-01-measure-both-sides.md), [Lab 02](lab-02-build-a-detector.md),
> and working Frida ([53-Frida](../../53-Frida/README.md)).
> **You will need:** an emulator you own, Frida, jadx or apktool.

---

## Why this lab exists

In labs 01 and 02 you had the source. Here you do not.

That is the actual job. A client hands you an APK; it refuses to start on your emulator; you have a
day. The temptation — and it is overwhelming — is to open Frida and start hooking things. That
approach reliably burns two hours neutralising `File.exists()` in an app whose real check was the
sensor list.

This lab drills the opposite discipline: **trace before you hook, and neutralise exactly one thing at
a time.** The constraint is deliberately harsh — you may not use a blanket bypass, and you must be
able to name the signal that fired before you touch it.

> **⚠️ Authorised testing only**
> The target is an app you build yourself in Part 0, on an emulator you own. The method transfers to
> client work; the target must always be something you are authorised to test.

---

## Objectives

1. Determine which emulator signal an app reads **without reading its source**.
2. Distinguish a Java-layer check from a native one, from evidence.
3. Neutralise exactly one signal and prove the neutralisation is minimal.
4. Handle an app with **multiple independent checks at different call sites**.
5. Rewrite file *content*, not just file *existence* — the point where one hook stops being enough.
6. Write the finding up in terms of impact rather than activity.

---

## Part 0 — Build the target (then forget how it works)

You need a target with checks you did not choose. Build the one below **without reading it
carefully**, install it, and then work from the binary only.

> **🧠 How to make this honest**
> Copy the source into a scratch directory, build it, then **close the file and do not reopen it
> until Part 6**. If you find yourself tempted, ask a colleague to pick three of the seven signals
> below at random and delete the rest before you build. Working from a binary you wrote is a skill in
> self-discipline as much as tooling.

Save as `Target.java`, package `com.lab39.target`:

```java
package com.lab39.target;

import android.app.Activity;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.FileReader;
import java.lang.reflect.Method;
import java.util.List;

public class Target extends Activity {

    static { System.loadLibrary("guard"); }
    private static native int nativeGuard();

    // Deliberately unhelpful names. Real obfuscated apps look like this.
    private static String p(String k) {
        try {
            Method m = Class.forName("android.os.SystemProperties")
                            .getMethod("get", String.class);
            return (String) m.invoke(null, k);
        } catch (Throwable t) { return ""; }
    }

    private boolean a() { return "ranchu".equals(p("ro.hardware")); }

    private boolean b() {
        SensorManager sm = (SensorManager) getSystemService(SENSOR_SERVICE);
        if (sm == null) return false;
        List<Sensor> l = sm.getSensorList(Sensor.TYPE_ALL);
        if (l.isEmpty()) return false;
        int n = 0;
        for (Sensor s : l) {
            String v = s.getVendor();
            if (v != null && v.contains("AOSP")) n++;
        }
        return n * 2 > l.size();
    }

    private boolean c() {
        // Content, not existence. This is the one that needs a read() hook.
        try (BufferedReader r = new BufferedReader(new FileReader("/proc/cpuinfo"))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.contains("hypervisor")) return true;
            }
        } catch (Throwable t) { /* unreadable: not evidence either way */ }
        return false;
    }

    @Override protected void onCreate(Bundle s) {
        super.onCreate(s);
        TextView tv = new TextView(this);
        setContentView(tv);

        // GATE 1 -- startup. Loud.
        if (a()) {
            Log.e("TGT", "startup gate refused");
            tv.setText("Device not supported");
            return;
        }
        tv.setText("Welcome. Tap PAY to continue.");
        Log.i("TGT", "startup ok");

        // GATE 2 -- deferred, on the sensitive action. Quiet.
        tv.setOnClickListener(v -> {
            if (b() || c() || nativeGuard() != 0) {
                Log.e("TGT", "payment gate refused");
                tv.setText("Payment unavailable on this device");
                return;
            }
            tv.setText("FLAG{" + Integer.toHexString(("ok" + Build.MODEL).hashCode()) + "}");
        });
    }
}
```

And `guard.c`:

```c
/* guard.c
 * Build (host):
 *   $NDK/x86_64-linux-android21-clang -Wall -Wextra -O2 -shared -fPIC \
 *       -Wl,-z,max-page-size=16384 -o lib/x86_64/libguard.so guard.c
 */
#include <jni.h>
#include <string.h>
#include <sys/system_properties.h>

JNIEXPORT jint JNICALL
Java_com_lab39_target_Target_nativeGuard(JNIEnv *env, jclass c)
{
    char buf[PROP_VALUE_MAX + 1];
    (void)env; (void)c;
    memset(buf, 0, sizeof(buf));
    /* A property NOT read anywhere in the Java code. */
    if (__system_property_get("ro.boot.qemu", buf) > 0 && buf[0] == '1') {
        return 1;
    }
    memset(buf, 0, sizeof(buf));
    if (__system_property_get("ro.build.characteristics", buf) > 0 &&
        strstr(buf, "emulator") != NULL) {
        return 2;
    }
    return 0;
}
```

Build with the recipe from [Lab 02 §3.2](lab-02-build-a-detector.md), install on your emulator, and
**stop looking at the source**.

---

## Part 1 — Triage without tools

Five minutes, no Frida.

```bash
# host
adb -s <emu> logcat -c
adb -s <emu> shell am start -W -n com.lab39.target/.Target
sleep 1
adb -s <emu> logcat -d | grep -iE 'tgt|emulator|support|refus|denied'
```

Record:

1. What does the screen say?
2. What is in logcat?
3. Did the process die, or is it still running? (`adb shell pidof com.lab39.target`)
4. Any tombstone? (`adb shell ls -t /data/tombstones | head -3` — needs root)

> **🔍 Pentester's Note**
> A refusal that leaves the process alive and shows a message is a **Java-layer** decision the app
> handled gracefully. A process that vanishes with a tombstone naming a `.so` is a **native** check
> calling `abort()`. You have narrowed the search before opening a single tool, and that inference
> is worth practising until it is automatic.

---

## Part 2 — Map the surface statically

```bash
# host
python3 -B ../scripts/emu-signal-map.py target.apk | tee map.txt
```

From `map.txt` answer:

1. How many distinct signals? How many are graded DEAD?
2. Are any hits marked `NATIVE`? Which?
3. Which library holds them?

Then confirm the native surface directly:

```bash
# host
unzip -o target.apk -d unpacked/
llvm-readelf --dyn-syms unpacked/lib/*/libguard.so | grep -E 'system_property|access|stat|open'
strings -a unpacked/lib/*/libguard.so | grep -aiE 'qemu|goldfish|ranchu|emulator'
```

> **⚠️ Warning — a string is not a check**
> The map gives you **leads**. An analytics SDK reads `ro.hardware` too. Chapter 52 measured this
> funnel at 16,836 hits → 168 leads → **2 survivors**. Do not go hooking every hit; go find out which
> ones execute.

---

## Part 3 — Trace, and only then hook

```bash
# host - spawn, do NOT attach
frida -U -f com.lab39.target -l ../scripts/emu-trace.js -o trace-startup.txt
```

> **⚠️ `-f`, not `-p`**
> Gate 1 runs in `onCreate`, and `System.loadLibrary` (with any `JNI_OnLoad`) runs even earlier, in
> a static initialiser. Attaching to a running process means the decision was made before you got
> there, and your trace comes back empty and you conclude the app has no checks. This is the single
> most common failure in this lab.

### 3.1 The startup gate

From `trace-startup.txt`, answer:

1. Which signal fired **first**?
2. Is it `[prop]` (Java) or `[native-prop]` (libc)? Both?
3. What did `caller()` report?

Record it, then run `summary()` in the REPL and note the tally.

### 3.2 Neutralise exactly that one

Not everything. **One signal.** Write the minimal hook yourself:

```javascript
// minimal.js -- ONE signal. If it takes more than five lines you are over-reaching.
Java.perform(function () {
    var SP = Java.use("android.os.SystemProperties");
    SP.get.overload("java.lang.String").implementation = function (k) {
        if (k === "<the ONE key your trace showed>") { return "qcom"; }
        return this.get(k);
    };
});
```

```bash
# host
frida -U -f com.lab39.target -l minimal.js
```

**Success criterion for this part: the app starts, and your script hooks exactly one property key.**
If you had to add a second, your trace was incomplete — go back to §3.1 rather than adding hooks.

### 3.3 Now drive the sensitive flow

The app started. That is not the finding. Tap the button.

It refuses again. **This is the most important moment in the lab.** A tester who declares victory at
the launch screen has missed gate 2 entirely, and gate 2 is the one guarding the thing that matters.

Re-trace with the app running and the button tapped:

```bash
# host
frida -U -f com.lab39.target -l ../scripts/emu-trace.js -o trace-payment.txt
# start it, tap PAY, then in the REPL:
# > summary()
```

Diff the two traces:

```bash
# host
diff <(sort trace-startup.txt) <(sort trace-payment.txt) | grep '^>'
```

Everything in that diff is a signal gate 2 reads and gate 1 did not.

---

## Part 4 — The three-check problem

Gate 2 is a short-circuit `||` of three independent checks. That structure has a consequence you must
reason about rather than brute-force:

> **🧠 Mental Model — short-circuit evaluation hides the checks behind the first `true`**
> `b() || c() || nativeGuard() != 0` stops at the first `true`. If `b()` fires, `c()` and
> `nativeGuard()` **never execute** — so they never appear in your trace, and you will believe there
> are fewer checks than there are. Every time you neutralise one, the next becomes visible for the
> first time.
>
> This is why "peel one layer, re-trace" is the method and "hook everything" is not. Hooking
> everything gets the app running and leaves you unable to describe the app's posture, which is what
> the report needs.

Work through it:

| Round | Neutralised so far | New signal revealed | Layer |
|---|---|---|---|
| 1 | (nothing) | | |
| 2 | | | |
| 3 | | | |

### 4.1 The sensor check

Trace shows `getSensorList`. Two options — try the wrong one first, deliberately:

```javascript
// Option A: fake the COUNT. Tempting, and it is the wrong lever here.
// Option B: fake the VENDOR strings, which is what the check actually reads.
Java.perform(function () {
    var S = Java.use("android.hardware.Sensor");
    S.getVendor.implementation = function () {
        var v = this.getVendor();
        return (v && v.indexOf("AOSP") >= 0) ? "qualcomm" : v;
    };
});
```

**Which works, and why?** Answer from your trace, not from the source. The general lesson: hook what
the check *reads*, not what you assume it reads. The trace tells you which.

### 4.2 The `/proc/cpuinfo` check

This is the step-change. The check reads *content*, so hiding a file does nothing and
`File.exists` is irrelevant. You must change the bytes.

The Java route, if the app uses `FileReader`/`BufferedReader`:

```javascript
// Intercept at the reader. Works ONLY if the read goes through Java.
Java.perform(function () {
    var BR = Java.use("java.io.BufferedReader");
    BR.readLine.overload().implementation = function () {
        var line = this.readLine();
        if (line !== null && line.indexOf("hypervisor") >= 0) {
            // Return the line with the flag removed rather than null:
            // returning null would truncate the file and can change behaviour
            // in ways that look like a different bug.
            return line.replace(/\bhypervisor\b/g, "");
        }
        return line;
    };
});
```

The native route, if it does not:

```javascript
// Substitute CONTENT at the syscall. Track fds, because a caller may read in
// chunks and a closed fd number gets recycled.
var watched = {};
Interceptor.attach(Module.findExportByName("libc.so", "openat"), {
    onEnter: function (a) { try { this.p = a[1].readCString(); } catch (e) {} },
    onLeave: function (r) {
        var fd = r.toInt32();
        if (this.p === "/proc/cpuinfo" && fd >= 0) { watched[fd] = 0; }
    }
});
Interceptor.attach(Module.findExportByName("libc.so", "close"), {
    onEnter: function (a) { delete watched[a[0].toInt32()]; }
});
// Hooking read() and rewriting the buffer is the remaining piece.
// Deliberately left to you: it is where the lab stops being about tools.
```

**Time this step.** Compare it to how long §3.2 took. That ratio is the honest argument for writing a
check against file content rather than file existence, and it is a number worth carrying into a
report.

### 4.3 The native guard

Your Java hooks are invisible to it. It reads a property the Java code never touches, so it will not
appear in a Java trace at all — only in the `[native-prop]` lines.

```javascript
Interceptor.attach(Module.findExportByName("libc.so", "__system_property_get"), {
    onEnter: function (a) {
        this.k = null; this.buf = a[1];
        try { this.k = a[0].readCString(); } catch (e) {}
    },
    onLeave: function (ret) {
        if (this.k === "<the key from your NATIVE trace>") {
            this.buf.writeUtf8String("");
            ret.replace(ptr(0));
        }
    }
});
```

> **⚠️ Warning — if your hook installs and nothing changes**
> Before assuming the hook is broken, check that the function is actually *called*. Chapter 65
> measured a perfectly installed hook on an exported symbol changing nothing because **zero `bl`
> instructions targeted it** — the compiler had inlined the body into the caller. Chapter 18 patched
> a check to `return 1`, verified it returned 1, and the caller still refused, for the same reason.
> `frida-trace` reporting no hits on a symbol that exists is the signature of inlining, not of a
> broken hook.

---

## Part 5 — Minimality

Now consolidate into one script and **make it as small as possible**.

```bash
# host
frida -U -f com.lab39.target -l my-bypass.js
```

Then delete hooks one at a time and re-test. For each, record whether the app still works.

| Hook | Needed? | Evidence |
|---|---|---|
| | | |

**Every hook that can be deleted and still leave the app working was never load-bearing.** A bypass
script with unnecessary hooks in it is a script whose author did not trace — and it is fragile,
because each unnecessary hook is a chance to break unrelated app behaviour.

> **🔍 Pentester's Note**
> This is why the chapter's [`emu-bypass.js`](../scripts/emu-bypass.js) has a `CONFIG` block with
> every family independently switchable, and why its default has `sensors`, `native` and `verdict`
> **off**. A bypass tool that does everything at once is a tool that cannot answer "which check
> mattered?" — and that question is what the client is paying for.

---

## Part 6 — Compare against the source

**Only now** reopen `Target.java` and `guard.c`.

| | You found | Actually there | Missed? |
|---|---|---|---|
| Gate 1 signals | | 1 | |
| Gate 2 signals | | 3 | |
| Native signals | | 2 keys | |
| Total | | | |

Answer:

1. Did you find all of them? Which did you miss and why?
2. Did you hook anything that was **not** a check? (Over-hooking is as much an error as under-hooking.)
3. `nativeGuard()` checks **two** properties. Did your trace show both, or only the first? Why?
4. What would `emu-signal-map.py` have told you about gate 2 that the trace did not — and vice versa?

Question 3 is the short-circuit lesson again, one level down: `nativeGuard` returns on the first
match, so the second property is only read when the first does not fire.

---

## Part 7 — Write the finding

Write it as you would for a client. Two versions:

**The bad version (do not submit this):**

> Emulator detection was bypassed using Frida.

**The version that describes impact.** Include:

- What the checks were, at which layer, and how many.
- **How long** the bypass took, at each altitude.
- **Which checks were DEAD** before you started — from `map.txt`. This is often the highest-value
  sentence in the report, because the developer does not know.
- **What the bypass gave access to** — the flag, in this lab; a payment flow, in reality.
- **What the server did about it.** In this lab: nothing, because there is no server. Say so
  explicitly, and say what you would have tested.
- A severity, justified with the rubric in
  [README §5.7](../README.md#57-honest-severity-how-to-rate-a-missing-or-broken-emulator-check).

---

## Success criteria

- [ ] You identified the startup gate signal **from the trace**, before reading source.
- [ ] Your first bypass hooked exactly **one** property key.
- [ ] You found gate 2 by driving the sensitive flow, not by reading source.
- [ ] You identified all three gate-2 checks by peeling one at a time.
- [ ] You handled the `/proc/cpuinfo` **content** rewrite and timed it.
- [ ] You neutralised the native guard through a libc hook.
- [ ] Your final script is minimal — every hook proven load-bearing by deletion.
- [ ] Part 6's comparison table is filled in honestly, including what you missed.
- [ ] The finding is written in terms of impact, and names the DEAD checks.

---

## Clean up

```bash
# host
adb -s <emu> uninstall com.lab39.target
adb -s <emu> shell rm -rf /data/local/tmp/lab39-*
```

Delete your scratch build directory. No APKs or `.so` files in the repository.

---

## Hints

<details>
<summary>emu-trace.js prints nothing at all</summary>

In order of likelihood: you used `-p` instead of `-f`; frida-server is not running or is the wrong
version (`frida-ps -U` to check); or the app crashed before the hooks installed — look at
`adb logcat -b crash`.

If the Java trace is genuinely empty but the app still refuses, the check is native and ran in
`JNI_OnLoad`. Confirm with `CONFIG.native = true` and look for `[native-prop]` lines.
</details>

<details>
<summary>I neutralised the property and the app still refuses at startup</summary>

Either it reads the same value a second way — `Build.HARDWARE` is `ro.hardware` latched into a static
final, so hooking `SystemProperties.get` does not touch it — or there is a second check you have not
seen. Add `Build` field writes and re-trace. The trace's `Build fields as the app will read them`
block prints exactly what the app sees.
</details>

<details>
<summary>The sensor hook makes the app crash</summary>

Returning `null` or an unexpected type from `getVendor` will do that. Return a `String` always. If
you hooked `getSensorList` and rebuilt the list, you probably broke the object identity the framework
expects — hook the accessor (`getVendor`) rather than the collection.
</details>

<details>
<summary>My openat/read hook corrupts the app or produces garbage</summary>

Three classic causes: you wrote more bytes than the caller's buffer holds; you did not adjust the
return value to the new length; or you rewrote on every `read()` call, so a caller reading in 4 KiB
chunks got your substitute text repeatedly. Track a per-fd offset, serve your substitute once, and
return 0 thereafter to signal EOF.
</details>

<details>
<summary>How do I know whether the native check even ran?</summary>

```javascript
Interceptor.attach(Module.findExportByName("libguard.so", "Java_com_lab39_target_Target_nativeGuard"), {
    onEnter: function () { console.log("[+] nativeGuard entered"); },
    onLeave: function (r) { console.log("[+] nativeGuard -> " + r.toInt32()); }
});
```

If `onEnter` never fires, the check is not being reached — perhaps an earlier `||` clause
short-circuited it, which means you have not neutralised what you thought you had.
</details>

---

## What to take away

- **Trace before you hook.** The trace tells you which of twenty possible checks the app actually
  performs, and that is usually two or three.
- **Short-circuit evaluation hides checks.** Every one you defeat reveals the next. Peel, re-trace,
  repeat.
- **The launch screen is not the sensitive flow.** Apps re-check where it matters.
- **Content is harder than existence**, and you now know by how much because you timed both.
- **A minimal bypass is evidence you understood the app.** A maximal one is evidence you did not.

Next: [Lab 04 — CTF: The Honest Emulator](lab-04-ctf-honest-emulator.md), where the check that kills
the app is not the check that matters.
