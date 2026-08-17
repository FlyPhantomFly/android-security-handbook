# Lab 02 — Compiler Filters and Hook Reliability

**Difficulty:** Intermediate
**Time:** 90–120 minutes
**Prerequisites:** [Lab 01](lab-01-reading-art-artifacts.md),
[Chapter 13 §3.8–3.17](../README.md#3-deep-internal-working), Frida installed and working

---

## Objective

Prove **experimentally**, on your own device, that method inlining defeats a Frida hook and that
forcing the `verify` compiler filter fixes it. Build the target yourself so there is no ambiguity about
what the code does.

## Why this matters

"My hook doesn't fire" is the most common complaint in Android dynamic analysis, and inlining is the
most common cause. Almost everyone learns this the hard way, after hours of blaming Frida, blaming the
device, or concluding the app has anti-hooking protection it does not have.

Running this experiment once converts that from folklore into something you have personally observed.
After this lab, `cmd package compile -m verify -f` becomes reflex.

---

## Setup

You need a target app you control. Either build the one below, or use any app whose source you have.

### Build the target

Create a minimal app with a deliberately inline-able method.

**`MainActivity.java`**

```java
package com.artlab.target;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import android.widget.TextView;

public class MainActivity extends Activity {
    private static final String TAG = "ARTLAB";
    private final Check check = new Check();
    private int iterations = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView tv = new TextView(this);
        setContentView(tv);

        // Call describe() repeatedly so the method becomes hot and the JIT
        // compiles (and likely inlines) it. Without heat, nothing is compiled
        // and the experiment shows nothing.
        final Handler h = new Handler();
        h.post(new Runnable() {
            @Override public void run() {
                for (int i = 0; i < 100000; i++) {
                    String result = check.describe();
                    if (i % 20000 == 0) {
                        Log.i(TAG, "iteration " + i + " -> " + result);
                    }
                }
                iterations++;
                tv.setText("round " + iterations + ": " + check.describe());
                h.postDelayed(this, 2000);   // keep going so you can hook mid-run
            }
        });
    }
}
```

**`Check.java`**

```java
package com.artlab.target;

public class Check {

    // Deliberately tiny. The optimizing compiler will happily inline this
    // into describe(), which is exactly what we want to demonstrate.
    public boolean isSecure() {
        return true;
    }

    // The observable output. If isSecure() is inlined, a hook on isSecure()
    // will not affect what this returns.
    public String describe() {
        return isSecure() ? "secure" : "insecure";
    }
}
```

Build and install:

```bash
# host
./gradlew assembleRelease
adb install -r app/build/outputs/apk/release/app-release.apk
```

> **Important.** Build **release**, not debug. A debuggable app forces interpretation in many paths,
> which suppresses the very effect you are trying to observe.

### The hook

**`hook.js`**

```javascript
// frida -U -f com.artlab.target -l hook.js
//
// Hooks Check.isSecure() to return false. If describe() still reports "secure",
// isSecure() was inlined and this hook is not being consulted.

Java.perform(function () {
    var Check = Java.use("com.artlab.target.Check");

    Check.isSecure.implementation = function () {
        console.log("[+] isSecure() called — returning false");
        return false;
    };

    console.log("[*] Hook installed on Check.isSecure()");
});
```

---

## Steps

### Step 1 — Baseline: fresh install, nothing compiled

```bash
# host
adb shell cmd package compile --reset com.artlab.target
adb shell dumpsys package dexopt | grep -A5 "com.artlab.target"
```

**Record** the compiler filter. It should be `verify` or similar.

```bash
# host
adb logcat -c
frida -U -f com.artlab.target -l hook.js
```

In a second terminal:

```bash
# host
adb logcat -s ARTLAB
```

**Record:** does the hook fire? What does `describe()` return?

**Expected:** the hook fires, and the log shows `insecure`.

### Step 2 — Force full AOT compilation

```bash
# host
adb shell am force-stop com.artlab.target
adb shell cmd package compile -m speed -f com.artlab.target
adb shell dumpsys package dexopt | grep -A5 "com.artlab.target"
```

Confirm the filter now reads `speed`.

```bash
# host
adb logcat -c
frida -U -f com.artlab.target -l hook.js
```

**Record:** does the hook fire now? What does `describe()` return?

**Expected:** the hook may not fire at all, or may fire while `describe()` still returns `secure`,
because `isSecure()` was inlined into `describe()` at compile time.

> **Note.** Inlining is a compiler *decision*, not a guarantee. Depending on your ART version and the
> exact shape of the code, you may need to make `isSecure()` even simpler, or make `describe()` hotter,
> to reliably observe the effect. If Step 2 behaves identically to Step 1, see Hint 3.

### Step 3 — Confirm inlining in the compiled code

This is the step that turns an observation into proof.

```bash
# adb shell as root
APK=$(pm path com.artlab.target | head -1 | sed 's/package://')
DIR=$(dirname $APK)
oatdump --oat-file=$DIR/oat/arm64/base.odex \
        --class-filter=com.artlab.target.Check \
        --method-filter=describe > /data/local/tmp/describe.txt
wc -l /data/local/tmp/describe.txt
```

```bash
# host
adb pull /data/local/tmp/describe.txt
```

**Examine the native code for `describe()`.** If `isSecure()` was inlined, you will **not** see a call
instruction (`bl`) to `isSecure` — instead you will see the constant `true` folded directly into the
comparison, or the whole branch eliminated.

**Question 1.** Is there a `bl` to `isSecure` in the disassembly of `describe()`? What does its
presence or absence tell you?

### Step 4 — The fix

```bash
# host
adb shell am force-stop com.artlab.target
adb shell cmd package compile -m verify -f com.artlab.target
adb shell dumpsys package dexopt | grep -A5 "com.artlab.target"
```

```bash
# host
adb logcat -c
frida -U -f com.artlab.target -l hook.js
```

**Record:** does the hook fire? What does `describe()` return?

**Expected:** the hook fires on every call, and `describe()` returns `insecure`.

### Step 5 — Verify the compiled code is gone

```bash
# adb shell as root
oatdump --oat-file=$DIR/oat/arm64/base.odex --header-only | grep -i compiler-filter
oatdump --oat-file=$DIR/oat/arm64/base.odex \
        --class-filter=com.artlab.target.Check --method-filter=describe | head -40
```

**Question 2.** What does the output show now, and why does that explain the hook working?

### Step 6 — Hook the caller instead

Now solve the problem *without* changing the compiler filter — the technique you need when you cannot
recompile the target.

```bash
# host
adb shell cmd package compile -m speed -f com.artlab.target
```

**`hook-caller.js`**

```javascript
// frida -U -f com.artlab.target -l hook-caller.js
//
// When the callee has been inlined, hook the CALLER instead. describe() is
// large enough that it will not itself be inlined into its caller.

Java.perform(function () {
    var Check = Java.use("com.artlab.target.Check");

    Check.describe.implementation = function () {
        var original = this.describe();
        console.log("[+] describe() returned '" + original + "' — overriding");
        return "insecure";
    };

    console.log("[*] Hook installed on Check.describe()");
});
```

**Question 3.** Why does this work when the hook on `isSecure()` did not?

### Step 7 — Observe the overnight effect

```bash
# host
adb shell cmd package compile --reset com.artlab.target
adb shell dumpsys package dexopt | grep -A5 "com.artlab.target"
```

Now run the app for several minutes so it builds a profile, then:

```bash
# host — simulate what happens overnight while charging
adb shell cmd package bg-dexopt-job
adb shell dumpsys package dexopt | grep -A5 "com.artlab.target"
```

**Question 4.** What did the filter change to, and what would that have done to a hook you had working
before you went home?

### Step 8 — Restore

```bash
# host
adb shell cmd package compile -m speed-profile -f com.artlab.target
```

---

## Hints

<details>
<summary>Hint 1 — the hook fires but nothing changes</summary>

That is the interesting case, and exactly what the lab is about. The hook is installed on the
`ArtMethod` for `isSecure()`, and *some* call sites still go through it — but the compiled `describe()`
no longer contains a call, so its behaviour is unaffected. See §3.17.
</details>

<details>
<summary>Hint 2 — Frida cannot spawn the app</summary>

Check version alignment first:

```bash
frida --version
adb shell "su -c '/data/local/tmp/frida-server --version'"
```

They must match exactly. See [53-Frida](../../53-Frida/README.md).
</details>

<details>
<summary>Hint 3 — Step 2 behaves the same as Step 1</summary>

Inlining is a heuristic decision. Try these, in order:

1. Make `isSecure()` even smaller — `return true;` with no other statements.
2. Increase the iteration count so `describe()` becomes genuinely hot.
3. Mark `isSecure()` `final` or `private` so the compiler knows it cannot be overridden.
4. Confirm you built **release**, not debug.
5. Check the OAT actually contains compiled code for `describe()` (Step 3).

If `oatdump` shows no native code for `describe()` at all, the method was never compiled and the
premise of the experiment has not been met.
</details>

<details>
<summary>Hint 4 — reading ARM64 disassembly</summary>

You are looking for a branch-with-link instruction:

```
bl  #0x...   ; a call
```

Its absence, combined with the constant `1` appearing directly in a comparison, indicates the callee
was inlined and constant-folded. See [18-ARM](../../18-ARM/README.md) for the instruction reference.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.** With `speed`, there should be **no** `bl` to `isSecure` in `describe()`'s disassembly. The
optimizing compiler inlined the body, saw that it unconditionally returns `true`, constant-folded the
ternary, and emitted code that simply returns the `"secure"` string reference. The call site your hook
was waiting for does not exist in the compiled code. Its absence is the direct, physical explanation
for the hook having no effect.

**2.** Under `verify`, `oatdump` shows the DEX bytecode for `describe()` and **no** native code. The
method therefore executes in the interpreter, which dispatches each `invoke-virtual` through the
callee's `ArtMethod` entry point at every single call — and that entry point is what your hook
overwrote. Interpretation restores the indirection that compilation removed.

**3.** `describe()` is larger and is called from a loop in `MainActivity`, so it is far less likely to
be inlined into its caller. Hooking it means you intercept at a boundary that still exists in the
compiled code. The general principle: **when the callee has been inlined, move your hook up the call
stack to the nearest boundary that survived compilation.**

**4.** The filter changes from `verify` to `speed-profile`. Methods recorded as hot in the profile —
which will include `describe()` and probably `isSecure()` — are now compiled, with inlining. A hook
that worked the previous evening on a freshly installed, uncompiled app may silently stop firing. This
is precisely the "it worked yesterday" scenario, and it happens to people constantly because leaving a
test device on charge overnight is the normal thing to do.

</details>

---

## Success criteria

- [ ] You built and installed a release target with a deliberately inline-able method
- [ ] You observed the hook working under `verify`
- [ ] You observed the hook failing (or having no effect) under `speed`
- [ ] You **proved** inlining from `oatdump` disassembly rather than inferring it
- [ ] You restored hook reliability with `cmd package compile -m verify -f`
- [ ] You solved the same problem a second way, by hooking the caller
- [ ] You reproduced the overnight effect with `bg-dexopt-job`
- [ ] You can explain, in two sentences, why interpretation makes hooks reliable
- [ ] `cmd package compile -m verify -f` is now the first thing you reach for when a hook misbehaves
