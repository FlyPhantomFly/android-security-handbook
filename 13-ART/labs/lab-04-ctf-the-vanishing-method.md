# Lab 04 — CTF: The Vanishing Method

**Difficulty:** Advanced
**Time:** 2–4 hours
**Prerequisites:** [Lab 03](lab-03-artmethod-archaeology.md), all of
[Chapter 13 §3](../README.md#3-deep-internal-working)

---

## The challenge

You are given an app that asks for a flag. Somewhere inside, a method decides whether the flag you
entered is correct.

Your usual reflex — hook the validation method and force it to return `true` — does not work. Neither
does hooking `String.equals`. The app does not appear to have any anti-Frida protection: there is no
`/proc/self/maps` scanning, no `TracerPid` check, no thread-name enumeration. It simply does not
respond to your hooks.

**Recover the flag.**

There are at least four independent solutions. Find one. Then find a second, because the point of this
lab is that ART gives you multiple angles on the same problem.

---

## Rules

- No decompiling and reading the flag out of a string constant. That works, and it is not the lesson.
  (The flag is not a plaintext constant anyway.)
- No brute force.
- You must be able to **explain the mechanism** that defeated your first attempt.

---

## Building the challenge

The challenge app is specified below so you can build it yourself. Building it is part of the lab —
you will understand the defence better having implemented it.

### `FlagChecker.java`

```java
package com.artlab.ctf;

public final class FlagChecker {

    // Deliberately tiny and final: a prime inlining candidate.
    private static boolean matches(int a, int b) {
        return a == b;
    }

    // Derives the expected value at runtime; no plaintext constant exists.
    private static int expected() {
        int acc = 0x5A17;
        for (int i = 0; i < 7; i++) {
            acc = (acc * 31) ^ (i * 0x9E37);
        }
        return acc;
    }

    private static int hash(String s) {
        int acc = 0x5A17;
        for (int i = 0; i < s.length(); i++) {
            acc = (acc * 31) ^ (s.charAt(i) * 0x9E37);
        }
        return acc;
    }

    // The method you will reflexively try to hook.
    public static boolean check(String candidate) {
        return matches(hash(candidate), expected());
    }

    // Only reachable if check() returns true.
    public static String reveal(String candidate) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < candidate.length(); i++) {
            sb.append((char) (candidate.charAt(i) ^ 0x00));
        }
        return "ARTLAB{" + sb + "}";
    }
}
```

### `MainActivity.java`

```java
package com.artlab.ctf;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import android.widget.*;

public class MainActivity extends Activity {
    private static final String TAG = "CTF";

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        final EditText in = new EditText(this);
        Button go = new Button(this);
        final TextView out = new TextView(this);
        go.setText("Check");
        root.addView(in); root.addView(go); root.addView(out);
        setContentView(root);

        // Warm the checker so the JIT compiles and inlines it BEFORE the user
        // can interact. This is the whole defence.
        final Handler h = new Handler();
        h.post(new Runnable() {
            int n = 0;
            @Override public void run() {
                for (int i = 0; i < 200000; i++) {
                    FlagChecker.check("warmup" + (i & 0xFF));
                }
                if (++n < 5) h.postDelayed(this, 300);
                else Log.i(TAG, "warmup complete");
            }
        });

        go.setOnClickListener(v -> {
            String s = in.getText().toString();
            out.setText(FlagChecker.check(s) ? FlagChecker.reveal(s) : "nope");
        });
    }
}
```

### Build and install

```bash
# host — RELEASE build, then force full AOT compilation
./gradlew assembleRelease
adb install -r app/build/outputs/apk/release/app-release.apk
adb shell cmd package compile -m speed -f com.artlab.ctf
adb shell am force-stop com.artlab.ctf
```

That last `compile -m speed` is what makes this a challenge rather than a five-second hook.

---

## Your first attempt (which will fail)

```javascript
// naive.js — frida -U -f com.artlab.ctf -l naive.js
Java.perform(function () {
    var FC = Java.use("com.artlab.ctf.FlagChecker");
    FC.check.implementation = function (s) {
        console.log("[+] check('" + s + "') hooked");
        return true;
    };
});
```

Type anything, press Check. Observe what happens.

**Question 1.** Did the hook fire? Did the app accept your input? If the hook fired but the app still
said "nope", what does that tell you?

---

## Investigation

Work through these before looking at the solutions.

### Establish the execution state

```bash
# adb shell
dumpsys package dexopt | grep -A5 "com.artlab.ctf"
```

### Look at the compiled code

```bash
# adb shell as root
APK=$(pm path com.artlab.ctf | head -1 | sed 's/package://')
DIR=$(dirname $APK)
oatdump --oat-file=$DIR/oat/arm64/base.odex \
        --class-filter=com.artlab.ctf.FlagChecker > /data/local/tmp/fc.txt
```

```bash
# host
adb pull /data/local/tmp/fc.txt && less fc.txt
```

**Question 2.** Look at the disassembly for `check()`. Do you see `bl` instructions calling `matches`,
`hash` and `expected`? What happened to them?

### Classify the entry points

Use the classifier you wrote in [Lab 03](lab-03-artmethod-archaeology.md) Step 4 against
`FlagChecker.check`, `.matches`, `.hash` and `.expected`.

**Question 3.** What state is each method in?

---

## Solutions

Do not read these until you have made a genuine attempt.

<details>
<summary>Solution A — force interpretation (the intended first solution)</summary>

The defence is entirely dependent on compilation. Remove it:

```bash
# adb shell
cmd package compile -m verify -f com.artlab.ctf
am force-stop com.artlab.ctf
```

Now the naive hook works, because every call dispatches through the `ArtMethod` entry point.

Better still, hook `hash()` and `expected()` to *read* the values rather than forcing the result:

```javascript
// solve-a.js
Java.perform(function () {
    var FC = Java.use("com.artlab.ctf.FlagChecker");

    FC.expected.implementation = function () {
        var e = this.expected();
        console.log("[+] expected() = " + e + " (0x" + (e >>> 0).toString(16) + ")");
        return e;
    };

    FC.hash.implementation = function (s) {
        var h = this.hash(s);
        console.log("[+] hash('" + s + "') = " + h);
        return h;
    };
});
```

Now you know the target hash. Solve for an input that produces it — the hash is
`acc = (acc * 31) ^ (c * 0x9E37)` over seven iterations starting from `0x5A17`, and `expected()` uses
`i` in place of `charAt(i)`, so the answer is the seven characters whose code points are `0..6`.

Cleaner: just make `check()` return true after forcing `verify`, then read what `reveal()` prints.
</details>

<details>
<summary>Solution B — hook the caller</summary>

You cannot hook the inlined callees, but `onCreate`'s click listener calls `check()` from a lambda
that was *not* inlined into it. Hook at the boundary that survived.

```javascript
// solve-b.js — no recompilation needed
Java.perform(function () {
    var FC = Java.use("com.artlab.ctf.FlagChecker");

    // reveal() is only called when check() returns true, and reveal() is large
    // enough not to be inlined. Call it directly.
    var flag = FC.reveal("\u0000\u0001\u0002\u0003\u0004\u0005\u0006");
    console.log("[+] " + flag);
});
```

The insight: **you do not have to make the app take the right branch — you can call the method
yourself.** `Java.use` gives you the class; static methods can be invoked directly.
</details>

<details>
<summary>Solution C — patch the entry point by hand</summary>

Using the technique from [Lab 03](lab-03-artmethod-archaeology.md) Step 6, patch `check()`'s entry
point to a stub returning 1.

This works even under `speed`, **provided the call site you care about still dispatches through the
entry point.** The click listener's call to `check()` does — only `check()`'s own internal calls to
`matches`/`hash`/`expected` were inlined.

```javascript
// solve-c.js — see labs/lab-03 step 6 for the full stub construction
// Patch FlagChecker.check to return true.
```

**This is the solution that teaches the most**, because it forces you to distinguish "the method was
inlined" from "the method's callers were inlined" — two different things that produce the same symptom.
</details>

<details>
<summary>Solution D — read the answer out of the profile and the compiled code</summary>

Purely static, no hooking at all.

`expected()` has no inputs, so the compiler may have **constant-folded it entirely**. Look at the
`oatdump` output for `check()`:

```bash
oatdump --oat-file=$DIR/oat/arm64/base.odex \
        --class-filter=com.artlab.ctf.FlagChecker --method-filter=check
```

If `expected()` was folded, the target constant appears as an immediate in the disassembly — the
compiler computed it for you at build time. Extract it, then solve for the input.

This is a genuinely important lesson: **AOT compilation can leak computed secrets into the binary that
were never present in the source or the DEX.**
</details>

---

## Debrief questions

Answer these in writing; they are the actual point of the lab.

1. Why did the naive hook on `check()` fail under `speed` but succeed under `verify`?
2. What is the difference between "`check()` was inlined into its caller" and "`check()`'s callees were
   inlined into `check()`"? Which was happening here, and how did you determine it?
3. Solution B never hooked anything. Why is calling the method directly often better than forcing a
   branch?
4. Solution D found a value that exists nowhere in the source. Explain how, and describe a real-world
   situation where this would matter.
5. The app has no anti-Frida code whatsoever. Would you report "the app resists instrumentation" as a
   resilience finding? Justify your answer with reference to
   [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md).
6. If you were the developer and wanted this defence to be *real* rather than accidental, what would
   you actually have to do?

---

## Success criteria

- [ ] You recovered the flag
- [ ] You solved it a **second** way, by a different mechanism
- [ ] You can explain precisely why the first naive hook failed
- [ ] You distinguished callee-inlining from caller-inlining and determined which applied
- [ ] You examined the compiled code with `oatdump` rather than guessing
- [ ] You answered all six debrief questions in writing
- [ ] You can articulate why this app's "protection" is accidental, not designed — and what a real
      defence would require

---

## Note for instructors

The flag is `ARTLAB{` followed by the seven characters with code points `0x00`–`0x06`, which renders as
control characters. If you are running this as a group exercise, change `reveal()` to map the input
through a printable alphabet so the flag is quotable — for example
`(char)('a' + candidate.charAt(i))`, which yields `ARTLAB{abcdefg}`.

The pedagogical goal is **not** the flag. It is that participants encounter a hook failure whose cause
is purely a compiler decision, with no adversarial code involved — and learn to diagnose it
structurally instead of assuming protection.
