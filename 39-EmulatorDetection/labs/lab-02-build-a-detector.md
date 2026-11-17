# Lab 02 — Build a detector worth attacking

> **Difficulty:** Intermediate
> **Time:** 3–5 hours
> **Prerequisites:** [Lab 01](lab-01-measure-both-sides.md) — you need your own grading table.
> **You will need:** an emulator you own, the NDK, and ideally a physical device.

---

## Why this lab exists

Lab 01 taught you to measure. This lab teaches you to **build**, and then to **break your own work**
— which is the only honest way to learn what a control is worth.

Most people learn emulator detection by reading a checklist and copying a function. That produces the
eight-clause `isEmulator()` in [README §6.2](../README.md#62-in-jadx), every clause of which was
measured to be false on a current AVD. You are going to do it the other way round: start from your
own measurements, build something defensible, then attack it and find out exactly how long your
defence survives.

The number you produce at the end — **how many minutes it took you to defeat your own detector** — is
the single most useful thing in this lab. It is the number you will quote in reports for the rest of
your career, and it is the number that makes the "cost, not prevention" argument in
[README §1.3](../README.md#13-why-applications-care) concrete instead of rhetorical.

> You are building and attacking an app you wrote, on devices you own. See
> [SECURITY.md](../../SECURITY.md) for authorised-testing scope.

---

## Objectives

1. Write a detector that accumulates **evidence with provenance**, not a boolean.
2. Add a **native** layer that a Java hook cannot see, and prove it cannot.
3. Verify every signal fires — with a **positive test**, on a real emulator.
4. Deliberately include one DEAD and one NOISY signal, and watch what they do.
5. Attack your own detector at four escalating altitudes and **time each one**.
6. Explain, with numbers, why the client-side version cannot be made to work.

---

## Part 1 — Design before code

### 1.1 The shape

Refer to [README §3.2](../README.md#32-why-a-single-boolean-is-the-wrong-shape). Your detector must
**not** return a boolean. It returns:

- a **score**, and
- the **list of signals that fired**.

The second is what makes false positives diagnosable and what a server actually needs. A boolean has
thrown away the evidence and kept the conclusion, which is exactly backwards.

### 1.2 Choose your signals

From **your** Lab 01 table, pick:

| Count | Grade | Weight | Purpose |
|---|---|---|---|
| 3 | SOFT | 10 | The bread and butter |
| 2 | HARD | 40 | The ones that cost the attacker real time |
| 1 | NOISY | 3 | **Deliberately.** To watch it misbehave |
| 1 | DEAD | 10 | **Deliberately.** To watch it never fire |

Threshold: **40**. Note what that arithmetic guarantees — no combination of the NOISY and SOFT
signals alone can reach it without a HARD signal or three SOFT ones. That is a design decision, not
an accident, and you should be able to defend it.

> **Mental Model — why include signals you know are broken**
> A detector containing a DEAD signal and a NOISY one is not a badly built detector; it is an
> *instrumented* one. You will get to watch a check that never fires and a check that fires on the
> wrong device, in your own code, where you can see exactly why. That is far more instructive than
> reading that it happens. Real apps contain both, and you need to recognise the symptoms.

### 1.3 Write down your predictions first

Before any code. This is the part people skip and it is where the learning is:

| Signal | Grade | Will fire on emulator? | Will fire on phone? | Minutes to defeat? |
|---|---|---|---|---|
| | | | | |

Keep this. You will grade yourself against it in Part 5, and being wrong is the point.

---

## Part 2 — Build the Java layer

### 2.1 Skeleton

Create `Detector.java` in your own working directory (not in the repository).

```java
package com.lab39;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.Build;
import java.io.File;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

public final class Detector {

    /** Evidence, not a verdict. The caller gets to see WHICH signals fired. */
    public static final class Evidence {
        public final int score;
        public final List<String> fired;
        Evidence(int s, List<String> f) { score = s; fired = f; }

        @Override public String toString() {
            return "score=" + score + " fired=" + fired;
        }
    }

    private static final int W_HARD = 40, W_SOFT = 10, W_NOISY = 3;
    public  static final int THRESHOLD = 40;

    private final List<String> fired = new ArrayList<>();
    private int score = 0;

    private void add(String name, boolean present, int weight) {
        if (present) {
            fired.add(name + "(" + weight + ")");
            score += weight;
        }
    }

    public static Evidence evaluate(Context ctx) {
        Detector d = new Detector();

        // ---- SOFT ---------------------------------------------------------
        // TODO: three signals from YOUR table, weight W_SOFT.
        // Suggested starting point, but use what YOU measured:
        d.add("ro.kernel.qemu", "1".equals(prop("ro.kernel.qemu")), W_SOFT);
        d.add("ro.hardware",
              "ranchu".equals(Build.HARDWARE) || "goldfish".equals(Build.HARDWARE), W_SOFT);
        d.add("characteristics",
              "emulator".equals(prop("ro.build.characteristics")), W_SOFT);

        // ---- HARD ---------------------------------------------------------
        d.add("abi:both", abiMismatch(), W_HARD);
        d.add("sensors:aosp", sensorsSynthetic(ctx), W_HARD);

        // ---- NOISY (deliberately) -----------------------------------------
        // Measured firing on a RETAIL Redmi. Watch it flag your real phone.
        d.add("bootloader:unknown", "unknown".equals(Build.BOOTLOADER), W_NOISY);

        // ---- DEAD (deliberately) ------------------------------------------
        // Weighted as if it were SOFT, so that when it silently never fires you
        // can see exactly how much detection capability was quietly lost.
        d.add("qemu_pipe", new File("/dev/qemu_pipe").exists(), W_SOFT);

        return new Evidence(d.score, d.fired);
    }

    // ---- helpers -----------------------------------------------------------

    static String prop(String key) {
        try {
            Method m = Class.forName("android.os.SystemProperties")
                            .getMethod("get", String.class);
            Object v = m.invoke(null, key);
            return v == null ? "" : (String) v;
        } catch (Throwable t) {
            // Do NOT return "" here silently in production code: "could not ask"
            // and "no value" are different, and conflating them is how a check
            // stops working without anyone noticing.
            return "<reflection-failed>";
        }
    }

    static boolean abiMismatch() {
        boolean x86 = false, arm = false;
        for (String a : Build.SUPPORTED_ABIS) {
            if (a.startsWith("x86")) { x86 = true; }
            if (a.startsWith("arm")) { arm = true; }
        }
        return x86 && arm;
    }

    static boolean sensorsSynthetic(Context ctx) {
        SensorManager sm = (SensorManager) ctx.getSystemService(Context.SENSOR_SERVICE);
        if (sm == null) { return false; }
        List<Sensor> all = sm.getSensorList(Sensor.TYPE_ALL);
        // An EMPTY list is not evidence of an emulator -- a TV box has no
        // sensors either. Require a non-empty list AND a majority.
        if (all.isEmpty()) { return false; }
        int aosp = 0;
        for (Sensor s : all) {
            String v = s.getVendor();
            if (v != null && (v.contains("AOSP")
                    || v.contains("The Android Open Source Project"))) { aosp++; }
        }
        return aosp * 2 > all.size();
    }
}
```

### 2.2 Build and run it

Adapt [`../scripts/build-probe-app.sh`](../scripts/build-probe-app.sh) — copy it, change the package
name to `com.lab39` and point it at your sources. Or, simpler for a first pass, **add your `Detector`
class to the chapter's probe app** and call it from `onCreate`, so you inherit a working build.

Run on both devices and record:

| | Emulator | Phone |
|---|---|---|
| `score` | | |
| `fired` | | |
| Over threshold? | | |

### 2.3 The two deliberate signals

Check your output against these questions:

1. **Does `qemu_pipe` appear in `fired` on the emulator?** It should not — that is the DEAD signal
   behaving as measured.your detector lost 10 points of capability and told you nothing.
   In a real app, nobody would ever find out.
2. **Does `bootloader:unknown` appear in `fired` on the PHONE?** It should. Your detector just scored
   3 points against a real customer's device. It is below threshold on its own, which is exactly why
   the weighting matters — but imagine it weighted at 40.

> **Pentester's Note**
> You have now reproduced, in your own code, the two most common defects in production emulator
> detection: a check that cannot fire, and a check that fires on the wrong device. When you meet them
> in a real assessment you will recognise the symptoms instantly, because you built them on purpose.

---

## Part 3 — Add a native layer

A Java-only detector falls to a single `Java.use` hook. Move the two strongest signals into C.

### 3.1 The native check

Create `detector_jni.c`:

```c
/* detector_jni.c -- the native half of the lab 02 detector.
 *
 * Build (host):
 *   $NDK/aarch64-linux-android21-clang -Wall -Wextra -O2 -shared -fPIC \
 *       -Wl,-z,max-page-size=16384 -o libdetector.so detector_jni.c
 *   $NDK/x86_64-linux-android21-clang  -Wall -Wextra -O2 -shared -fPIC \
 *       -Wl,-z,max-page-size=16384 -o libdetector.so detector_jni.c
 */
#include <jni.h>
#include <string.h>
#include <stdio.h>
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

static int file_contains(const char *path, const char *needle)
{
    FILE *f = fopen(path, "r");
    char buf[8192];
    size_t n;
    int found = 0;

    if (!f) { return 0; }              /* EACCES and ENOENT both land here */
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0) { return 0; }
    buf[n] = '\0';
    found = (strstr(buf, needle) != NULL);
    return found;
}

/* Returns a SCORE, not a boolean -- same reasoning as the Java layer. */
JNIEXPORT jint JNICALL
Java_com_lab39_Detector_nativeScore(JNIEnv *env, jclass clazz)
{
    char buf[PROP_VALUE_MAX + 1];
    int score = 0;

    (void)env; (void)clazz;

    /* Read through libc. A Java hook on SystemProperties.get is blind to this. */
    memset(buf, 0, sizeof(buf));
    if (__system_property_get("ro.kernel.qemu", buf) > 0 && buf[0] == '1') {
        score += 10;
    }

    memset(buf, 0, sizeof(buf));
    if (__system_property_get("ro.hardware", buf) > 0 &&
        (strcmp(buf, "ranchu") == 0 || strcmp(buf, "goldfish") == 0)) {
        score += 10;
    }

    /* HARD: our own compiled architecture against the platform's claim.
     * BUILD_ARCH is a compile-time constant in .rodata. There is no INPUT to
     * spoof here -- only the comparison to patch, which is a different and
     * more expensive kind of attack. */
    memset(buf, 0, sizeof(buf));
    if (__system_property_get("ro.product.cpu.abi", buf) > 0 &&
        strcmp(BUILD_ARCH, buf) != 0) {
        score += 40;
    }

    /* HARD on x86 only. The guest cannot clear the CPUID hypervisor bit.
     * On arm64 there is no equivalent, so a 0 here proves nothing -- which is
     * why this contributes to a score rather than deciding anything. */
    if (file_contains("/proc/cpuinfo", "hypervisor")) {
        score += 40;
    }

    return (jint)score;
}
```

Add to `Detector.java`:

```java
    static { System.loadLibrary("detector"); }
    public static native int nativeScore();
```

and fold it in:

```java
        int nat = 0;
        try {
            nat = nativeScore();
        } catch (UnsatisfiedLinkError e) {
            // The library did not load for this ABI. Say so rather than
            // scoring 0 and pretending the check ran.
            d.fired.add("native:UNAVAILABLE");
        }
        if (nat > 0) { d.fired.add("native(" + nat + ")"); d.score += nat; }
```

### 3.2 Package the `.so`

The library must land at `lib/<abi>/libdetector.so` inside the APK. With the manual build:

```bash
# host - build for both ABIs into the right layout, then add to the APK
mkdir -p out/lib/arm64-v8a out/lib/x86_64
"$NDK/aarch64-linux-android21-clang" -Wall -Wextra -O2 -shared -fPIC \
    -Wl,-z,max-page-size=16384 -o out/lib/arm64-v8a/libdetector.so detector_jni.c
"$NDK/x86_64-linux-android21-clang"  -Wall -Wextra -O2 -shared -fPIC \
    -Wl,-z,max-page-size=16384 -o out/lib/x86_64/libdetector.so detector_jni.c

( cd out && jar uf unsigned.apk lib/ )
# then zipalign and re-sign, exactly as build-probe-app.sh does
```

> **Warning — ship BOTH ABIs, and understand why**
> If you ship only `arm64-v8a`, then on the x86_64 emulator your library runs under
> `libndk_translation.so` — and your ABI-mismatch check fires **because of how you packaged the app**,
> not because of anything it detected. That is a self-fulfilling check. Shipping both ABIs means the
> x86_64 emulator loads the x86_64 library, `BUILD_ARCH` matches, and the mismatch signal correctly
> stays quiet. Then verify it the other way round in §3.3.

### 3.3 Prove the native layer is invisible to a Java hook

This is the measurement that justifies the whole native layer:

```javascript
// frida -U -f com.lab39 -l java-only.js
Java.perform(function () {
    var SP = Java.use("android.os.SystemProperties");
    SP.get.overload("java.lang.String").implementation = function (k) {
        if (k === "ro.kernel.qemu") { return ""; }
        if (k === "ro.hardware")    { return "qcom"; }
        return this.get(k);
    };
    console.log("[+] Java property hook installed");
});
```

Run it and read your own output. **The Java score drops; the native score does not.** Record both
numbers — that difference is the value of the native layer, expressed as points.

To confirm the ABI signal really works, force the mismatch deliberately:

```bash
# host - repackage with ONLY the arm64 library, then run on the x86_64 emulator
# The native score should jump by 40. If it does not, your .so is not loading --
# check `adb logcat | grep -i detector` for an UnsatisfiedLinkError.
```

---

## Part 4 — The positive test

**A detection control with no test against a positive sample is not a control.** This is the step
that would have prevented all nine DEAD signals in
[README §3.14](../README.md#314-the-grading-table-every-signal-measured-on-both-devices).

### 4.1 Write it

```bash
#!/usr/bin/env bash
# positive-test.sh -- fail loudly if the detector does not fire on an emulator.
#
# Run this in CI on every release, against the CURRENT emulator system image.
# A green build with a detector that no longer fires is worse than a red one.
set -eu

SERIAL="${1:?usage: positive-test.sh <emulator-serial>}"

# Refuse to run against anything that is not an emulator: a "pass" measured on
# real hardware is meaningless and dangerously reassuring.
HW="$(adb -s "$SERIAL" shell getprop ro.hardware | tr -d '\r')"
case "$HW" in
    ranchu|goldfish) ;;
    *) echo "FAIL: $SERIAL is not an emulator (ro.hardware=$HW)"; exit 2 ;;
esac

adb -s "$SERIAL" logcat -c
adb -s "$SERIAL" shell am start -W -n com.lab39/.MainActivity >/dev/null
sleep 2
OUT="$(adb -s "$SERIAL" logcat -d -s LAB39:I -v raw)"
echo "$OUT"

SCORE="$(echo "$OUT" | grep -oE 'score=[0-9]+' | head -1 | cut -d= -f2)"
[ -n "${SCORE:-}" ] || { echo "FAIL: no score in logcat"; exit 1; }

if [ "$SCORE" -lt 40 ]; then
    echo "FAIL: detector scored $SCORE on an EMULATOR (threshold 40)."
    echo "      One or more signals have stopped firing. This is exactly how"
    echo "      /dev/qemu_pipe checks quietly died in a thousand apps."
    exit 1
fi
echo "PASS: scored $SCORE on an emulator"
```

### 4.2 The negative test matters just as much

```bash
# host - on your PHYSICAL device, the score must be BELOW threshold
./positive-test.sh <phone-serial>   # should FAIL its emulator guard, by design
```

Then write the real negative test: run on the phone and assert `score < 40`. If your phone scores 40
or more you have a **false positive**, which — per
[README §5.7](../README.md#57-honest-severity-how-to-rate-a-missing-or-broken-emulator-check) —
usually costs more than missing an emulator.

Record both:

| Device | Score | Expected | Pass? |
|---|---|---|---|
| Emulator | | ≥ 40 | |
| Phone | | < 40 | |

---

## Part 5 — Attack your own detector, and time it

Now break it. **Use a stopwatch.** The times are the deliverable.

| # | Altitude | What you do | Your time |
|---|---|---|---|
| 1 | Verdict | Hook `Detector.evaluate` to return a zero-score `Evidence` | |
| 2 | Java inputs | Hook `SystemProperties.get`, write the `Build` fields, hook `getSensorList` | |
| 3 | Native inputs | `Interceptor.attach` on `__system_property_get`; fake `/proc/cpuinfo` | |
| 4 | Environment | `resetprop` on the AVD — no hooks in the app process at all | |

### 5.1 Altitude 1 — the verdict

```javascript
// frida -U -f com.lab39 -l kill-verdict.js
Java.perform(function () {
    var D = Java.use("com.lab39.Detector");
    var E = Java.use("com.lab39.Detector$Evidence");
    var AL = Java.use("java.util.ArrayList");
    D.evaluate.implementation = function (ctx) {
        console.log("[!] evaluate() neutralised");
        return E.$new(0, AL.$new());
    };
});
```

Should take under two minutes. **Everything you built in Parts 2 and 3 is gone.** That is the
[README §3.2](../README.md#32-why-a-single-boolean-is-the-wrong-shape) argument, demonstrated against
your own work: effort spent adding checks *behind* a single entry point buys nothing.

### 5.2 Altitude 2 — the Java inputs

Use [`../scripts/emu-bypass.js`](../scripts/emu-bypass.js) with `properties`, `build` and `sensors`
enabled, `native` off. Note which signals stop firing and which do not.

> **The Build-field trap, and you should hit it deliberately**
> Try hooking **only** `SystemProperties.get` and observe that `Build.HARDWARE` still reads `ranchu`.
> That is [README §4.1](../README.md#41-build--where-the-fields-come-from): the field is
> `static final`, latched at class-init long before you attached. You must write the field. Spending
> ten minutes confused here is worth more than reading the warning.

### 5.3 Altitude 3 — the native inputs

Enable `native: true`. The property half will fall. `/proc/cpuinfo` will not, unless you intercept
`read()` on the returned descriptor:

```javascript
// The harder half: substitute file CONTENT, not just existence.
var openat = Module.findExportByName("libc.so", "openat");
var watched = {};
Interceptor.attach(openat, {
    onEnter: function (a) { try { this.p = a[1].readCString(); } catch (e) {} },
    onLeave: function (r) {
        if (this.p === "/proc/cpuinfo" && r.toInt32() >= 0) {
            watched[r.toInt32()] = true;
            console.log("[+] watching fd " + r.toInt32() + " for /proc/cpuinfo");
        }
    }
});
// then hook read() and rewrite the buffer for a watched fd.
// Left as the exercise: it is the point where "one hook" stops being enough.
```

**Time how long this one takes you.** It is a step-change from the previous altitudes, and that
step-change is the honest justification for writing the check in C.

### 5.4 Altitude 4 — the environment

No hooks at all. Fix the emulator instead:

```bash
# host
../scripts/harden-avd.sh --apply --serial <emu>
# then run your app with NO Frida
```

Read the script's "WHAT THIS DID NOT FIX" section against your own results. Your SOFT signals should
be gone and your HARD ones should survive — sensors and the `hypervisor` flag are not properties.

### 5.5 The table you actually came for

| Altitude | Your time | Signals defeated | Signals surviving |
|---|---|---|---|
| 1 Verdict | | all | none |
| 2 Java inputs | | | |
| 3 Native inputs | | | |
| 4 Environment | | | |

---

## Part 6 — Conclusions

Answer in writing:

1. **How long did the fastest complete bypass take?** That is the real-world value of your control,
   measured in analyst-minutes.
2. **Which signals survived altitude 4?** Why could properties not reach them?
3. **Compare your Part 1 predictions to your Part 5 results.** Where were you wrong, and why?
4. **Your DEAD signal never fired.** How would a developer with no emulator in CI ever find out?
5. **Your NOISY signal fired on your phone.** What would it have cost at weight 40 instead of 3?
6. **Rewrite `evaluate()` so the client never decides.** Sketch the request body it sends and what the
   server does with it. See [README §5.8](../README.md#58-the-correct-architecture).
7. Given all of the above — **is this control worth building?** Argue both sides. There is a good case
   each way and [README §1.3](../README.md#13-why-applications-care) makes it.

---

## Success criteria

- [ ] The detector returns evidence with provenance, never a bare boolean.
- [ ] At least 7 signals, including one deliberately DEAD and one deliberately NOISY.
- [ ] Native layer compiles for **both** ABIs with `-Wall -Wextra`, zero warnings.
- [ ] You demonstrated the native score surviving a Java-only hook, with both numbers recorded.
- [ ] The positive test passes on an emulator and the negative test passes on a phone.
- [ ] The positive test **refuses to run** on non-emulator hardware.
- [ ] All four attack altitudes attempted, each timed.
- [ ] You hit the `Build`-field latching trap and can explain it.
- [ ] All seven questions in Part 6 answered in writing.

---

## Clean up

```bash
# host
for S in <emu> <phone>; do
    adb -s $S uninstall com.lab39 2>/dev/null
    adb -s $S shell rm -f /data/local/tmp/libdetector.so
done
../scripts/harden-avd.sh --revert --serial <emu>    # reboots; restores properties
```

Delete your host build directory. No `.apk`, `.so`, `.dex` or `.class` may reach the repository.

---

## Hints

<details>
<summary>UnsatisfiedLinkError on System.loadLibrary</summary>

Three usual causes. The `.so` is not at `lib/<abi>/libdetector.so` inside the APK — check with
`unzip -l yourapp.apk | grep '\.so'`. Or the JNI function name does not match: it must be exactly
`Java_<package with dots replaced by underscores>_<Class>_<method>`, so `com.lab39.Detector.nativeScore`
becomes `Java_com_lab39_Detector_nativeScore`. Or you built for an ABI the device does not run.

Check what the linker actually said: `adb logcat | grep -iE 'dlopen|UnsatisfiedLink'`.
</details>

<details>
<summary>The native ABI check fires on my physical device</summary>

You shipped only the x86_64 library and the phone is running it under translation — or, more likely,
you shipped only arm64 and are reading a stale result. Verify which library actually loaded:

```bash
adb -s <phone> shell "run-as com.lab39 cat /proc/self/maps" | grep detector
```
</details>

<details>
<summary>My sensor check fires on my physical device</summary>

Check the vendor strings your device actually reports:

```bash
adb -s <phone> shell dumpsys sensorservice | grep -oE '\| [A-Za-z ]+ +\| ver' | sort -u
```

Some OEMs do vendor fused sensors to "AOSP" because they use the AOSP fusion implementation. If so,
your majority test needs to look at *hardware* sensors specifically, or at the vendor **diversity**
(how many distinct vendors) rather than the AOSP count. Diversity is the stronger signal: an
emulator has one or two, a phone has five or six.
</details>

<details>
<summary>Hooking SystemProperties.get does not change Build.HARDWARE</summary>

Correct, and you have just found the trap deliberately. `Build.HARDWARE` is `public static final`,
assigned in a static initialiser that ran during process startup — before Frida attached. The value
is a constant in the class's static storage now. Write the field instead:

```javascript
Java.use("android.os.Build").HARDWARE.value = "qcom";
```
</details>

<details>
<summary>How do I fake /proc/cpuinfo content properly?</summary>

Hook `openat` to learn which fd corresponds to `/proc/cpuinfo`, then hook `read` and, for that fd,
overwrite the destination buffer with your substitute text and adjust the return value to its length.
Two things bite: the caller may read in several chunks, so you must track an offset per fd; and you
must handle `close` to stop watching a recycled descriptor. That complexity **is** the finding — this
is the altitude where a one-line hook stops working.
</details>

---

## What to take away

- A boolean is one hook. Evidence with provenance is a hook per call site — and, more importantly,
  something a server can act on.
- A native layer is a **real** escalation, and you measured it in minutes rather than asserting it.
- **A detection control with no positive test rots silently.** You built a DEAD check on purpose and
  watched it contribute nothing while looking perfectly healthy in the source.
- Property spoofing defeats the checks people write, not the checks that are available.
- The honest output of this lab is a number: how long your best defence delayed you.

Next: [Lab 03 — Trace and neutralise](lab-03-trace-and-neutralise.md), where the app is not yours and
you do not get the source.
