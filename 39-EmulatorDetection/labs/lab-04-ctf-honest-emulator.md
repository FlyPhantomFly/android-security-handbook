# Lab 04 — CTF: The Honest Emulator

> **Difficulty:** CTF
> **Time:** 3–6 hours
> **Prerequisites:** Labs [01](lab-01-measure-both-sides.md), [02](lab-02-build-a-detector.md) and
> [03](lab-03-trace-and-neutralise.md).
> **You will need:** an emulator you own, Frida, jadx or apktool, the NDK.

---

## The brief

`com.lab39.ctf` is a toy "secure vault". It holds one flag.

Run it on an emulator and it says **"Emulator detected — vault locked"** and greys out the button.
Obvious. Bypass that check and the button lights up, the vault opens, and it prints a flag in the
correct format.

**That flag is wrong.**

Your job is to get the right one.

```
Flag format:   FLAG{<16 lowercase hex characters>}

Verify your answer against this SHA-256 of the correct flag string:

    8e147f8a7cb7107f2091b0fd2b038214c3b92abce24c8488512648e62b34f007

If your flag hashes to this, you have it. If it hashes to
fea9a9963b46520ab22b67c2eb616f0e39263c9200be5b9c05cda2d788126d02
you have found the decoy — which means the visible check was not the one that mattered.
```

Check your answer on the host:

```bash
# host
printf '%s' 'FLAG{...}' | sha256sum
```

> **⚠️ Authorised testing only**
> You build this target yourself, from the source below, and run it on an emulator you own. It is
> deliberately vulnerable and exists only as a teaching artefact. Do not install it on a device that
> is not yours, and uninstall it when you are done.

---

## Why this CTF is shaped this way

Every other lab in this chapter fails **loudly**. You bypass a check, the app runs, you know you
succeeded.

This one fails **quietly and plausibly**, which is the failure mode that actually costs people their
findings. A successful, verified bypass of the visible control produces a well-formed, believable
answer that is simply not correct. Nothing errors. Nothing logs. The only way to know you are wrong
is to check — and in a real engagement, there is often nothing to check against.

It is deliberately built on a different primitive from
[37-RootDetection](../../37-RootDetection/README.md)'s decoupling CTF. There, the detection result
feeds a key derivation consumed much later, so the crash you are debugging is not the check. Here,
both paths **succeed immediately** and produce output of the same shape. The lie is not in the timing;
it is in the *value*.

> **🧠 Mental Model**
> "The bypass worked" and "the bypass produced the right result" are different claims, and only the
> second matters. A tester who cannot distinguish them will eventually report a working exploit that
> does nothing, or — worse — miss a control they never noticed was there.

---

## Part 0 — Build the target

Build it, then work from the binary. Do not study the sources; you will compare against them in
Part 6.

### `Vault.java` — package `com.lab39.ctf`

```java
package com.lab39.ctf;

import android.app.Activity;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.util.List;

public class Vault extends Activity {

    static { System.loadLibrary("vault"); }

    /** Returns 0 for "looks like real hardware", non-zero otherwise. */
    private static native int envClass();

    private static final String SALT = "ch39-honest-emulator";

    private TextView out;
    private Button open;

    private static String p(String k) {
        try {
            Method m = Class.forName("android.os.SystemProperties")
                            .getMethod("get", String.class);
            Object v = m.invoke(null, k);
            return v == null ? "" : (String) v;
        } catch (Throwable t) {
            return "";
        }
    }

    // ------------------------------------------------------------------ //
    // THE LOUD ONE. Fails visibly. Trivial to find, trivial to defeat.
    // ------------------------------------------------------------------ //
    private boolean gate() {
        return "1".equals(p("ro.kernel.qemu"))
            || "ranchu".equals(Build.HARDWARE)
            || "goldfish".equals(Build.HARDWARE);
    }

    // ------------------------------------------------------------------ //
    // THE QUIET ONE. Never branches to an error. Only selects a key.
    // Java half: the sensor population.
    // ------------------------------------------------------------------ //
    private boolean synthetic() {
        SensorManager sm = (SensorManager) getSystemService(SENSOR_SERVICE);
        if (sm == null) {
            return false;
        }
        List<Sensor> l = sm.getSensorList(Sensor.TYPE_ALL);
        if (l.isEmpty()) {
            return false;
        }
        int n = 0;
        for (Sensor s : l) {
            String v = s.getVendor();
            if (v != null && (v.contains("AOSP")
                    || v.contains("The Android Open Source Project"))) {
                n++;
            }
        }
        return n * 2 > l.size();
    }

    private static String sha256hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(s.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Throwable t) {
            return "";
        }
    }

    /**
     * Note what this does NOT do: it never throws, never returns null, never
     * logs a warning. Both branches produce a correctly formatted flag.
     */
    private String derive() {
        boolean fake = synthetic() || (envClass() != 0);
        String mode = fake ? "emu" : "real";
        return "FLAG{" + sha256hex(mode + SALT).substring(0, 16) + "}";
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        out = new TextView(this);
        open = new Button(this);
        open.setText("OPEN VAULT");
        root.addView(out);
        root.addView(open);
        setContentView(root);

        if (gate()) {
            out.setText("Emulator detected — vault locked");
            open.setEnabled(false);
            Log.e("VAULT", "gate: refused");
            return;
        }
        out.setText("Vault ready.");
        Log.i("VAULT", "gate: passed");

        open.setOnClickListener(v -> {
            String f = derive();
            out.setText(f);
            Log.i("VAULT", "issued " + f);
        });
    }
}
```

### `vault.c`

```c
/* vault.c -- native half of the quiet check.
 *
 * Build (host), for the ABI your emulator runs:
 *   $NDK/x86_64-linux-android21-clang -Wall -Wextra -O2 -shared -fPIC \
 *       -Wl,-z,max-page-size=16384 -o lib/x86_64/libvault.so vault.c
 *   $NDK/aarch64-linux-android21-clang -Wall -Wextra -O2 -shared -fPIC \
 *       -Wl,-z,max-page-size=16384 -o lib/arm64-v8a/libvault.so vault.c
 */
#include <jni.h>
#include <stdio.h>
#include <string.h>
#include <sys/system_properties.h>

#if defined(__aarch64__)
#  define BUILD_ARCH "arm64-v8a"
#elif defined(__x86_64__)
#  define BUILD_ARCH "x86_64"
#elif defined(__arm__)
#  define BUILD_ARCH "armeabi-v7a"
#else
#  define BUILD_ARCH "unknown"
#endif

static int cpuinfo_has(const char *needle)
{
    FILE *f = fopen("/proc/cpuinfo", "r");
    char buf[8192];
    size_t n;

    if (!f) {
        return 0;
    }
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0) {
        return 0;
    }
    buf[n] = '\0';
    return strstr(buf, needle) != NULL;
}

/* 0 means "looks like real hardware". Non-zero identifies which signal fired,
 * which is useful for the writeup and useless to the app. */
JNIEXPORT jint JNICALL
Java_com_lab39_ctf_Vault_envClass(JNIEnv *env, jclass c)
{
    char buf[PROP_VALUE_MAX + 1];

    (void)env;
    (void)c;

    /* Read through libc: a Java hook on SystemProperties.get never sees this,
     * and this key is not referenced anywhere in the Java code. */
    memset(buf, 0, sizeof(buf));
    if (__system_property_get("ro.build.characteristics", buf) > 0 &&
        strstr(buf, "emulator") != NULL) {
        return 1;
    }

    /* The compiled architecture against the platform's claim. */
    memset(buf, 0, sizeof(buf));
    if (__system_property_get("ro.product.cpu.abi", buf) > 0 &&
        strcmp(BUILD_ARCH, buf) != 0) {
        return 2;
    }

    /* The CPUID hypervisor bit. x86 only; harmless on arm64. */
    if (cpuinfo_has("hypervisor")) {
        return 3;
    }
    return 0;
}
```

### Build and install

Use the recipe from [Lab 02 §3.2](lab-02-build-a-detector.md), or adapt
[`../scripts/build-probe-app.sh`](../scripts/build-probe-app.sh): change `PKG` to `com.lab39.ctf`,
the activity to `.Vault`, and add the `lib/` directory to the APK before signing.

```bash
# host
adb -s <emu> install -r ctf.apk
adb -s <emu> shell am start -n com.lab39.ctf/.Vault
```

You should see **"Emulator detected — vault locked"**.

---

## Part 1 — The obvious move (do it, and watch it betray you)

Find and defeat the visible gate. It should take you ten minutes.

```bash
# host
python3 -B ../scripts/emu-signal-map.py ctf.apk
frida -U -f com.lab39.ctf -l ../scripts/emu-trace.js
```

Then neutralise:

```javascript
// obvious.js
Java.perform(function () {
    var SP = Java.use("android.os.SystemProperties");
    SP.get.overload("java.lang.String").implementation = function (k) {
        return (k === "ro.kernel.qemu") ? "" : this.get(k);
    };
    Java.use("android.os.Build").HARDWARE.value = "qcom";
    console.log("[+] gate neutralised");
});
```

Run it. The vault opens. Tap the button. You get a flag.

**Hash it.**

```bash
# host
printf '%s' 'FLAG{...}' | sha256sum
```

It matches `fea9a996…`, the decoy hash. **You have a working bypass and the wrong answer.**

Stop and sit with that for a moment. Everything you would normally use to confirm success has
confirmed it: the check no longer fires, the UI changed, the app produced correctly formatted output,
nothing errored, nothing logged a warning. In a real engagement with no verification hash, you would
have written this up.

---

## Part 2 — Find the check that has no failure branch

The visible gate produced an error message. The real one does not. So you cannot find it by looking
for refusals — there are none.

Reframe the question:

> Not *"what makes the app refuse?"* but **"what does the app read between the button press and the
> output?"**

### 2.1 Trace the button press specifically

```bash
# host
frida -U -f com.lab39.ctf -l ../scripts/emu-trace.js -o ctf-trace.txt
# neutralise the gate in the REPL, tap OPEN VAULT, then:
# > summary()
```

Compare what is read **at startup** with what is read **on the tap**. Anything in the second set and
not the first is part of the derivation.

### 2.2 Read the derivation statically

```bash
# host
jadx -d ctf-out ctf.apk
grep -rn "FLAG\|sha256\|MessageDigest\|substring" ctf-out/sources/
```

Two questions the source answers immediately:

1. Is there **any** branch that produces an error, or do both paths return a flag?
2. What exactly goes into the digest?

> **🔍 Pentester's Note**
> `MessageDigest` next to a boolean is the shape to learn. When a check's result feeds a
> **derivation** rather than a **branch**, there is no `if (bad) { fail(); }` to find, no exception to
> catch and no log line to grep. The control is invisible to every technique that looks for failures.
> Search for where the boolean is *consumed*, not where it is *computed*.

### 2.3 There are two quiet signals, not one

Your trace shows a Java one. There is also a native one.

```bash
# host
llvm-readelf --dyn-syms ctf-out/../unpacked/lib/*/libvault.so | grep -E 'system_property|fopen'
strings -a unpacked/lib/*/libvault.so | grep -aiE 'qemu|emulator|hypervisor|cpuinfo|characteristics'
```

Note that the native check reads a property key that **appears nowhere in the DEX**. If you only
grepped the Java sources you missed it entirely.

Also note the `||` in `synthetic() || (envClass() != 0)`: short-circuit evaluation means that while
`synthetic()` returns `true`, `envClass()` **is never called** — so it will not appear in your native
trace at all. You must defeat the Java half before the native half becomes visible. This is
[Lab 03 §4](lab-03-trace-and-neutralise.md)'s lesson, and here it hides an entire signal.

---

## Part 3 — Defeat the quiet signals

Three separate things to fix, and the third only appears after the second.

| # | Signal | Layer | Visible when? |
|---|---|---|---|
| 1 | Sensor vendor population | Java | Immediately |
| 2 | `ro.build.characteristics` | Native | After you fix 1 |
| 3 | ABI mismatch **or** `hypervisor` flag | Native | After you fix 2 |

Which of 3 applies depends on how you packaged the library and what your host CPU is — work it out
from `envClass()`'s return value:

```javascript
// Which native signal fired? The return value tells you, and the app ignores it.
Interceptor.attach(
    Module.findExportByName("libvault.so", "Java_com_lab39_ctf_Vault_envClass"), {
    onLeave: function (r) { console.log("[envClass] -> " + r.toInt32()); }
});
```

`1` is the property, `2` is the ABI, `3` is `/proc/cpuinfo`. **Use this.** It is the single most
useful five lines in the whole lab, and it exists because the developer returned a diagnostic code
the app throws away.

> **🧠 Mental Model**
> A function that returns more information than its caller uses is a gift. `envClass()` could have
> returned a boolean; it returns *which signal fired*, and the app collapses it to `!= 0`. Look for
> this pattern — richly-typed internals feeding boolean call sites — because it turns a black box
> into an oracle.

Now defeat each. The sensor half:

```javascript
Java.perform(function () {
    var S = Java.use("android.hardware.Sensor");
    S.getVendor.implementation = function () {
        var v = this.getVendor();
        return (v && (v.indexOf("AOSP") >= 0 ||
                      v.indexOf("The Android Open Source Project") >= 0))
               ? "qualcomm" : v;
    };
});
```

The native property half — note this must be a **libc** hook, not a Java one:

```javascript
Interceptor.attach(Module.findExportByName("libc.so", "__system_property_get"), {
    onEnter: function (a) {
        this.k = null; this.buf = a[1];
        try { this.k = a[0].readCString(); } catch (e) {}
    },
    onLeave: function (ret) {
        if (this.k === "ro.build.characteristics") {
            this.buf.writeUtf8String("default");
            ret.replace(ptr(7));
        }
        // ... and ro.product.cpu.abi, if envClass returned 2
    }
});
```

The `/proc/cpuinfo` half, if `envClass()` returned 3, is the `read()`-rewriting problem from
[Lab 03 §4.2](lab-03-trace-and-neutralise.md). This is the hardest step and it is the intended
difficulty spike.

---

## Part 4 — Verify

```bash
# host
printf '%s' 'FLAG{...}' | sha256sum
```

Target: `8e147f8a7cb7107f2091b0fd2b038214c3b92abce24c8488512648e62b34f007`

If you still get the decoy, one signal is still firing. Add the `envClass` probe from Part 3 and
check it returns **0**, and confirm `synthetic()` returns `false`:

```javascript
Java.perform(function () {
    var V = Java.use("com.lab39.ctf.Vault");
    V.synthetic.implementation = function () {
        var r = this.synthetic();
        console.log("[synthetic] -> " + r);
        return r;
    };
});
```

> **⚠️ Do not "solve" it by hooking `derive()`**
> You can of course hook `derive` to return the right string — but you would have to know the right
> string first, which is the entire problem. Hooking the digest inputs is equally circular. The
> intended solution makes the **environment** produce the correct derivation, which is exactly what a
> real attacker must do when a check feeds key material.
>
> This is the same structural point as
> [README §3.15](../README.md#315-the-only-signal-that-actually-holds-attestation): when a check's
> result becomes a **dependency** rather than a **gate**, there is no branch to flip. Chapter 67 draws
> the same distinction with KeyStore, the one control whose verdict and branch columns are both empty.

---

## Part 5 — Bonus objectives

| # | Objective | Why it is worth doing |
|---|---|---|
| B1 | Get the correct flag with **no Frida at all** — only [`harden-avd.sh`](../scripts/harden-avd.sh) and emulator configuration | Forces you to confront which signals are not properties |
| B2 | Produce the correct flag on a **physical device** with no hooks | The control working as designed; the honest baseline |
| B3 | Write the minimal script — delete every hook that is not load-bearing | The Lab 03 minimality discipline |
| B4 | Patch the APK statically so the correct flag comes out with no runtime instrumentation | Then explain why re-signing would break a real app ([38-TamperDetection](../../38-TamperDetection/README.md)) |
| B5 | Explain why B1 is impossible on a stock AVD, precisely | This is the real lesson — see below |

**B5 is the important one.** Attempt B1 honestly and you will find that `harden-avd.sh` fixes
`ro.build.characteristics` and leaves the sensor HAL and the `hypervisor` bit untouched. Property
spoofing cannot reach either. Write down exactly which signals survive and why each is out of reach
of `resetprop` — that paragraph is the chapter's thesis in your own words.

---

## Part 6 — Compare with the source

Reopen `Vault.java` and `vault.c`.

| Question | Your answer |
|---|---|
| How many checks are there in total? | |
| How many produce a visible failure? | |
| How many did you find before reading the source? | |
| Which did you find last, and what revealed it? | |
| Did you notice `envClass()`'s return code was diagnostic? | |
| How long between "working bypass" and "correct flag"? | |

That last row is the number this whole lab exists to produce.

---

## Part 7 — The writeup

Write it for a client, and make these points explicitly:

1. There were **two** controls: one visible, one silent. Bypassing the visible one appeared to
   succeed completely.
2. The silent control feeds a **derivation**, not a branch — so no amount of looking for failures
   would have found it.
3. The native check read a property that **appears nowhere in the DEX**. A DEX-only review misses it.
4. Short-circuit evaluation hid one signal entirely until another was defeated.
5. What this means for **methodology**: a bypass is not verified by the app appearing to work. It is
   verified by the *output being correct* — and if you have no way to check the output, say so in the
   report rather than implying you do.

Point 5 is the transferable one. Most engagements have no verification hash.

---

## Success criteria

- [ ] You obtained the decoy flag first and recognised it as wrong **by checking**.
- [ ] You found the quiet Java signal from a trace, not from the source.
- [ ] You found the native signal, and noticed it reads a key absent from the DEX.
- [ ] You used `envClass()`'s return value as an oracle.
- [ ] You explained why short-circuit evaluation hid a signal.
- [ ] Your flag hashes to `8e147f8a…`.
- [ ] At least two bonus objectives, including **B5**.
- [ ] Writeup makes all five points in Part 7.

---

## Clean up

```bash
# host
adb -s <emu> uninstall com.lab39.ctf
adb -s <emu> shell rm -rf /data/local/tmp/lab39*
../scripts/harden-avd.sh --revert --serial <emu>
```

Delete your host build directory: no `.apk`, `.so`, `.dex` or `.class` in the repository.

---

## Hints

<details>
<summary>Hint 1 — I bypassed it and got a flag. Is that it?</summary>

Hash it. There are two hashes in the brief for a reason. If yours matches the second one you have the
decoy, and the fact that everything *looked* like success is the entire point of the exercise.
</details>

<details>
<summary>Hint 2 — Where do I even look for a check with no error branch?</summary>

Stop looking for refusals. Look at what happens **between the button press and the text appearing**.
Decompile and read `derive()`: does anything in it throw, return null, or log? If both paths return a
flag, the check is choosing *which* flag, and you should be searching for where a boolean enters a
string operation rather than where it enters an `if`.
</details>

<details>
<summary>Hint 3 — I fixed the sensor check and the flag did not change</summary>

Two possibilities. Either your sensor hook did not take effect — verify by hooking `synthetic()` and
printing its return value — or there is a second signal that was previously hidden by short-circuit
evaluation and has now become reachable. Hook `envClass` and print its return code.
</details>

<details>
<summary>Hint 4 — envClass keeps returning 3</summary>

Return code 3 is `/proc/cpuinfo` containing `hypervisor`. This is the hardest one because it is file
**content**, not file existence, and it is read through libc rather than Java. You need to intercept
`openat` to identify the descriptor, then `read` to substitute the bytes, then `close` to stop
tracking that descriptor. Lab 03 §4.2 has the skeleton.

If your emulator is arm64 (Apple silicon) there is no `hypervisor` flag and you should never see a 3
— in which case check whether you are seeing a 2 (ABI mismatch) because you packaged only one ABI.
</details>

<details>
<summary>Hint 5 — Full walkthrough (open only when stuck)</summary>

1. Defeat the loud gate: `ro.kernel.qemu` and `Build.HARDWARE`. Vault opens, decoy flag appears.
2. Decompile. `derive()` calls `synthetic() || (envClass() != 0)` and neither branch fails — the
   boolean selects the string `"emu"` or `"real"` that goes into the digest.
3. Hook `Sensor.getVendor` to return a real-silicon vendor for AOSP-vendored sensors. `synthetic()`
   now returns `false`.
4. `envClass()` now runs for the first time. Hook it and print the return value.
5. If **1**: hook `__system_property_get` in libc for `ro.build.characteristics`, return `default`.
6. If **2**: same hook for `ro.product.cpu.abi`, return the ABI your library was compiled for. Or
   package the library for the emulator's own ABI so there is no mismatch.
7. If **3**: intercept `openat`/`read` on `/proc/cpuinfo` and remove the `hypervisor` token.
8. `envClass()` returns 0 and `synthetic()` returns `false`. Tap OPEN VAULT.
9. Hash it. `8e147f8a…`.
</details>

---

## Instructor notes

<details>
<summary>Design rationale and expected failure modes</summary>

**The primitive.** The detection result feeds a *key derivation* rather than a *branch*. There is no
failure path to find, no exception, no log. This is deliberately different from
`37-RootDetection/labs/lab-04`, where the decoupling is **temporal** (the consequence arrives much
later than the check); here both paths complete immediately and identically, and the decoupling is in
the **value**.

**Why a decoy flag rather than a crash.** A crash teaches "the bypass was incomplete", which testers
already know how to handle. A plausible wrong answer teaches "your success criteria were wrong",
which is much harder and much more common in real work. The verification hash exists so the lesson
lands in a lab; the writeup requirement in Part 7 exists so students notice that real engagements
usually have no such hash.

**Three layers of concealment**, each with a distinct lesson:
1. The loud gate absorbs the first hour and provides false confidence.
2. Short-circuit `||` hides `envClass()` entirely until `synthetic()` is defeated — students
   frequently conclude there is only one quiet check.
3. The native check reads `ro.build.characteristics`, a key that appears **nowhere in the DEX**, so a
   DEX-only review cannot find it even in principle.

**`envClass()`'s diagnostic return value is intentional.** It models a real and common developer
habit: returning a rich code to aid debugging, then collapsing it to a boolean at the call site. It
makes the lab solvable in reasonable time and teaches students to look for over-informative
internals.

**Expected sticking points**, in observed order of frequency: not hashing the first flag at all;
hooking `SystemProperties.get` and expecting `Build.HARDWARE` to change; not realising `envClass` was
never called; and the `/proc/cpuinfo` content rewrite, which is a genuine difficulty spike and where
most of the time goes.

**If the CTF proves too hard**, the fairest reduction is to package the native library for both ABIs
(removing return code 2) and to run on an arm64 AVD (removing return code 3), leaving only the
property check. The lesson survives intact; only the final difficulty spike is removed.

**Verify the build before assigning it.** `derive()` must produce
`FLAG{190daa573882939b}` on a stock emulator and `FLAG{002a2557c3908028}` on real hardware. If your
build produces different values, `SALT` or the `substring(0, 16)` length has drifted; regenerate the
two hashes in the brief to match, or the lab is unsolvable as written.
</details>

---

## What to take away

- **A bypass that appears to work may not have worked.** The app running is not the success criterion;
  the output being correct is.
- When a check feeds a **derivation** instead of a **branch**, there is nothing to find by looking for
  failures. Search for where the boolean is consumed.
- **Short-circuit evaluation conceals whole signals** until you defeat the ones in front of them.
- A property read in native code that never appears in the DEX is invisible to a source review.
- The strongest form of this pattern is the one you cannot defeat at all: hardware-backed key
  material, where there is no verdict and no branch —
  [README §3.15](../README.md#315-the-only-signal-that-actually-holds-attestation).
