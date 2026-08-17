# Lab 03 — Trace, Identify, Neutralise

**Difficulty:** Advanced
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-build-and-break.md), [Lab 02](lab-02-native-check.md),
[Chapter 37 §7.3](../README.md#73-the-tracer--find-out-which-check-fires),
[`scripts/root-check-tracer.js`](../scripts/root-check-tracer.js) available,
[56-JADX](../../56-JADX/README.md)

---

## Objective

Given a build with twelve checks, R8 renaming, and **no source you are allowed to read**, use
[`root-check-tracer.js`](../scripts/root-check-tracer.js) to determine exactly which checks fire, at
which layer, from which class. Then neutralise **only those**, with the smallest hook set that works —
and prove it is minimal by removing hooks one at a time until the app detects again.

The deliverable is not a working bypass. It is a working bypass **plus a written account of which
twelve checks exist, which of them ran, which of them were dead, and which single hook would have been
sufficient**.

## Why this matters

Step 5 of the bypass ladder in [§3.14](../README.md#314-magisk-denylist-zygisk-and-the-arms-race) —
"run the tracer to identify which check fires" — is the step juniors skip and seniors do first.

Skipping it means writing hooks by guesswork. Guesswork in this area is expensive because the search
space is large (five layers, twelve mechanisms, two languages) and the feedback is binary and slow: you
change something, restart the app, and learn only "still detected". That loop is where afternoons go.

Running the tracer converts an open-ended fight into a specific task in about twenty minutes, and it
produces something guesswork never does: **a list of what the app actually checks**, which is the
material your report is made of. A bypass is a step in your methodology. The inventory of controls,
including the ones that silently never ran, is the deliverable.

There is also a professional-hygiene reason. A shotgun bypass — hook everything, deny everything —
frequently *breaks the app*, and a broken app is indistinguishable from a detected app. Testers report
"the root check could not be bypassed" when what actually happened is that their own script corrupted
the app's startup. Minimal, evidence-led hooks do not have that failure mode.

---

## Setup

### Build the target so that you do not know the answer

The value of this lab depends on genuinely not knowing which checks are enabled. Build it with a
randomised mask and do not read the generated file.

**`app/src/main/java/com/rootlab/target/Gauntlet.java`** — twelve checks behind a bitmask.

```java
package com.rootlab.target;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;

/**
 * Twelve checks. Which ones run is decided at BUILD time by MASK, which is
 * generated randomly (see build-gauntlet.sh). Each enabled check contributes
 * to a score; the score decides the app's behaviour.
 *
 * Do not read the generated Mask.java. That is the entire point of the lab.
 */
public final class Gauntlet {

    public static int score(Context ctx) {
        int m = Mask.VALUE;      // generated; do not look
        int s = 0;
        if ((m & (1 << 0))  != 0 && suPaths())          s += 40;
        if ((m & (1 << 1))  != 0 && busybox())          s += 20;
        if ((m & (1 << 2))  != 0 && suOnPath())         s += 25;
        if ((m & (1 << 3))  != 0 && whichSu())          s += 15;
        if ((m & (1 << 4))  != 0 && execSu())           s += 45;
        if ((m & (1 << 5))  != 0 && rootPkgs(ctx))      s += 30;
        if ((m & (1 << 6))  != 0 && testKeys())         s += 25;
        if ((m & (1 << 7))  != 0 && props())            s += 35;
        if ((m & (1 << 8))  != 0 && mounts())           s += 35;
        if ((m & (1 << 9))  != 0 && selinux())          s += 10;
        if ((m & (1 << 10)) != 0 && adbEnabled(ctx))    s += 10;
        if ((m & (1 << 11)) != 0 && NativeCheck.findSu() != null) s += 40;
        return s;
    }

    /* 0 */ static boolean suPaths() {
        String[] p = {"/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
                      "/vendor/bin/su", "/data/local/su", "/cache/su"};
        for (String x : p) if (new File(x).exists()) return true;
        return false;
    }

    /* 1 */ static boolean busybox() {
        String[] p = {"/system/xbin/busybox", "/system/bin/busybox", "/sbin/busybox"};
        for (String x : p) if (new File(x).exists()) return true;
        return false;
    }

    /* 2 */ static boolean suOnPath() {
        String path = System.getenv("PATH");
        if (path == null) return false;
        for (String d : path.split(":")) if (new File(d, "su").exists()) return true;
        return false;
    }

    /* 3 */ static boolean whichSu() {
        Process p = null;
        try {
            p = Runtime.getRuntime().exec(new String[]{"which", "su"});
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String l = r.readLine();
            return l != null && !l.isEmpty();
        } catch (Exception e) {
            return false;
        } finally { if (p != null) p.destroy(); }
    }

    /* 4 */ static boolean execSu() {
        Process p = null;
        try {
            p = Runtime.getRuntime().exec(new String[]{"su", "-c", "id"});
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String l = r.readLine();
            return l != null && l.contains("uid=0");
        } catch (Exception e) {
            return false;
        } finally { if (p != null) p.destroy(); }
    }

    /* 5 */ static boolean rootPkgs(Context ctx) {
        String[] pkgs = {"com.topjohnwu.magisk", "eu.chainfire.supersu",
                         "com.noshufou.android.su", "com.dimonvideo.luckypatcher"};
        PackageManager pm = ctx.getPackageManager();
        for (String s : pkgs) {
            try { pm.getPackageInfo(s, 0); return true; }
            catch (PackageManager.NameNotFoundException ignored) { }
        }
        return false;
    }

    /* 6 */ static boolean testKeys() {
        return Build.TAGS != null && Build.TAGS.contains("test-keys");
    }

    /* 7 */ static boolean props() {
        if ("1".equals(prop("ro.debuggable"))) return true;
        if ("0".equals(prop("ro.secure"))) return true;
        String v = prop("ro.boot.verifiedbootstate");
        if (v != null && !v.isEmpty() && !"green".equals(v)) return true;
        return "0".equals(prop("ro.boot.flash.locked"));
    }

    /* 8 */ static boolean mounts() {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader("/proc/self/mounts"));
            String l;
            while ((l = r.readLine()) != null) {
                if (l.contains("magisk") || l.contains("/data/adb")) return true;
                if (l.contains("tmpfs /sbin") || l.contains("overlay /system")) return true;
            }
        } catch (Exception ignored) {
        } finally { try { if (r != null) r.close(); } catch (Exception ignored) { } }
        return false;
    }

    /* 9 */ static boolean selinux() {
        FileInputStream in = null;
        try {
            in = new FileInputStream("/sys/fs/selinux/enforce");
            return in.read() == '0';
        } catch (Exception e) {
            return false;
        } finally { try { if (in != null) in.close(); } catch (Exception ignored) { } }
    }

    /* 10 */ static boolean adbEnabled(Context ctx) {
        return Settings.Global.getInt(ctx.getContentResolver(),
                Settings.Global.ADB_ENABLED, 0) == 1;
    }

    static String prop(String k) {
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            Method g = sp.getMethod("get", String.class, String.class);
            return (String) g.invoke(null, k, "");
        } catch (Throwable t) { return ""; }
    }

    private Gauntlet() { }
}
```

**`build-gauntlet.sh`** — generates the mask. Run it, then **do not open `Mask.java`**.

```bash
#!/bin/sh
# host — generate a random 12-bit mask with roughly 7 bits set, then build.
# Do NOT cat the generated file. Knowing the answer destroys the exercise.
set -e
OUT=app/src/main/java/com/rootlab/target/Mask.java

MASK=0
for BIT in 0 1 2 3 4 5 6 7 8 9 10 11; do
  # ~60% chance each check is enabled
  if [ $(( $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % 10 )) -lt 6 ]; then
    MASK=$(( MASK | (1 << BIT) ))
  fi
done

cat > "$OUT" <<EOF
package com.rootlab.target;
final class Mask { static final int VALUE = ${MASK}; private Mask() { } }
EOF

# Record the answer where you will not accidentally see it.
echo "$(date -u +%FT%TZ) mask=${MASK}" >> ../gauntlet-answers.txt
chmod 600 ../gauntlet-answers.txt

./gradlew assembleRelease
echo "built. answer stored in ../gauntlet-answers.txt — open it only at step 7."
```

**Enable R8** so the class and method names are gone, matching a real target.
`app/build.gradle`:

```groovy
buildTypes {
    release {
        minifyEnabled true
        shrinkResources false
        proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        signingConfig signingConfigs.debug   // so you can install it
    }
}
```

**`MainActivity`** — behaviour driven by the score, with **no message naming the reason**:

```java
int s = Gauntlet.score(this);
if (s >= 60) {
    // No dialog, no log line naming root. Just a degraded state.
    tv.setText("Service temporarily unavailable. Please try again later.");
} else {
    tv.setText("Welcome. Balance: 1,204.55");
}
```

Build and install:

```bash
# host
sh build-gauntlet.sh
adb install -r app/build/outputs/apk/release/app-release.apk
adb shell am start -n com.rootlab.target/.MainActivity
```

You should see "Service temporarily unavailable". Now forget everything you know about the source.

---

## Steps

### Step 1 — Do the cheap things first, in order

Before any instrumentation.

```bash
# host — 1. logs
adb logcat -c
adb shell am force-stop com.rootlab.target
adb shell am start -n com.rootlab.target/.MainActivity
adb logcat -v threadtime -d | grep -iE "root|magisk|su |integrity|security|tamper"
```

Then Magisk DenyList: enable Zygisk, add the package, force-stop, relaunch.

**Q1.** Did the logs reveal anything? Did DenyList alone change the outcome? If it did, what does that
tell you about which *category* of check the app relies on — and would you stop here on a real
engagement?

### Step 2 — Static triage, five minutes, no decompiler yet

```bash
# host
mkdir -p triage && cd triage && unzip -o ../app-release.apk >/dev/null
for d in classes*.dex; do strings -a "$d"; done | sort -u | grep -aE \
  '(^|/)su$|/system/(bin|xbin)/su|magisk|busybox|test-keys|ro\.[a-z.]+|/proc/self/mounts|/sys/fs/selinux|adb_enabled|which'
readelf --dyn-syms lib/arm64-v8a/*.so 2>/dev/null | grep -E 'Java_|UND (access|stat|fopen|__system_property_get)'
aapt2 dump xmltree ../app-release.apk --file AndroidManifest.xml | grep -A6 queries
```

**Q2.** List every check you can infer from strings alone. How many of the twelve did you find, and
which categories are invisible to this technique?

**Q3.** The manifest has no `<queries>` block. What does that tell you, before you run anything, about
check 5 on an app targeting API 30+?

**Q4.** Strings tell you a check *exists in the binary*. What do they emphatically **not** tell you?

### Step 3 — Run the tracer

```bash
# host
frida -U -f com.rootlab.target -l ../scripts/root-check-tracer.js --no-pause
```

Let the app reach its final screen, then capture the output to a file and read it properly.

**Q5.** Separate the tracer output into `[J]` (Java), `[N]` (native) and `[L]` (library load) lines.
How many distinct checks fired at each layer?

**Q6.** For each `[J]` line, the tracer prints a Java stack trace. What class name appears in all of
them? What does the fact that it is the *same* class in every trace tell you about the app's structure,
and what does it suggest about the cheapest possible intervention?

**Q7.** Compare the tracer's list against your step-2 string list. Name at least one check whose
strings are present in the DEX but which **never fired**. Give two possible explanations, and describe
how you would distinguish them.

**Q8.** Set `FILTER_NOISE = false` at the top of the tracer and re-run. What appears that you did not
see before? Is any of it a check you missed, and what is the cost of running this way by default?

### Step 4 — Build the inventory before you build the bypass

Produce a table with one row per check, before writing a single hook:

| # | Check | Layer | Fired? | Evidence | Where implemented |
|---|---|---|---|---|---|

**Q9.** Which rows say "did not fire"? For each, decide: disabled by the build mask, or present but
broken? What evidence distinguishes them, and which of the two is a reportable finding?

**Q10.** Which single row has the highest score weight, and how do you know without reading the source?

### Step 5 — Neutralise precisely

Now write hooks for the rows marked "fired", and **only** those. Do not paste in
`java-root-bypass.js` wholesale.

**Q11.** Write your minimal hook set. How many distinct hooks did it take, and how does that compare
with the number of checks that fired?

**Q12.** Remove one hook at a time and relaunch. Which hooks are load-bearing and which turn out to be
unnecessary? Explain any surprises — for example a hook you thought covered one check but which
actually covered three.

**Q13.** Now find the aggregation point and hook that instead. How much smaller is the resulting
script, and what have you lost by taking the shortcut?

### Step 6 — Verify like a professional

**Q14.** The app now shows the welcome screen. Name three ways that could still be a false success, and
describe how you would rule each one out.

**Q15.** Exercise every screen and every action in the app, not just the launch path. Does anything
re-check? How would you have found out if it did, given that the app never says the word "root"?

### Step 7 — Score yourself

Only now, open `gauntlet-answers.txt` and decode the mask.

```bash
# host
python3 -c "m=int(input('mask: ')); print([i for i in range(12) if m>>i & 1])"
```

**Q16.** Which enabled checks did your tracer-driven inventory correctly identify? Which did you miss,
and why? Which did you *believe* were enabled that were not?

**Q17.** For every check you missed, work out what would have caught it. Is the gap in the tracer's
instrumentation, in your reading of its output, or in your methodology?

---

## Hints

<details>
<summary>Hint — Q6, reading Java stack traces from the tracer</summary>

The tracer prints frames like `<- com.a.b.c(SourceFile:41)`. After R8 the names are meaningless, but
the **shape** is not: if every filesystem, property and subprocess hit is called from frames inside the
same obfuscated class, that class is the checker. If they all further share a caller one frame up, that
caller is the aggregation point.

Note the line numbers too. Several hits from `SourceFile:41` and several from `SourceFile:88` tells you
there are at least two methods in that class.
</details>

<details>
<summary>Hint — Q7, present-but-never-fired</summary>

Three questions to distinguish the explanations:

1. Would the check fire on *this* device even if enabled? (`test-keys` will not fire on a stock image.)
2. Is the check reachable at all? (No `<queries>` kills the package check silently.)
3. Did the code path run? Hook the *method* rather than the API it calls — if your hook on the method
   never fires, the method was never called and the check is disabled, not broken.

That third technique is the decisive one, and it is worth internalising: instrument the *caller*, not
the callee, when you want to know whether code ran.
</details>

<details>
<summary>Hint — Q13, finding the aggregation point after R8</summary>

```javascript
Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (name) {
            if (name.indexOf("com.rootlab") !== 0) return;
            var C = Java.use(name);
            C.class.getDeclaredMethods().forEach(function (m) {
                var s = m.toString();
                if (s.indexOf(" int ") !== -1 || s.indexOf(" boolean ") !== -1) {
                    console.log(name + " :: " + s);
                }
            });
        },
        onComplete: function () { }
    });
});
```

A static method taking a `Context` and returning `int`, called once from the launch path, is not hard
to spot even when it is called `a.b`.
</details>

<details>
<summary>Hint — Q14, ruling out false success</summary>

Consider: did the app succeed because you defeated the checks, or because your hooks broke the code
that computes the score and it defaulted to zero? Did it succeed because Magisk DenyList (from step 1)
is still enabled and you forgot? Did it succeed on the launch path while a second evaluation exists
behind a button you did not press?
</details>

---

## Solution

<details>
<summary>Answers Q1–Q4 — cheap steps and static triage</summary>

**Q1.** The build deliberately logs nothing and names nothing, which is the *correct* developer
behaviour (logging the detection hands the attacker a map — see §11 of the chapter) and the annoying
one for you. On a real engagement it is still always the first thing to try, because plenty of
developers do log.

DenyList may flip the outcome if the enabled mask happens to be dominated by filesystem and mount
checks, since those become honestly clean in a reverted namespace. On a real engagement you would
**not** stop there: a DenyList-only bypass tells you nothing about what the app checks, and your report
needs the inventory. Also, DenyList is a device configuration your client cannot rely on you having
had — findings must reproduce.

**Q2.** Strings typically reveal: su paths (0), busybox (1), `which`/`su` command strings (3, 4),
package names (5), `test-keys` (6), `ro.*` property names (7), `/proc/self/mounts` (8),
`/sys/fs/selinux/enforce` (9), `adb_enabled` (10). That is ten of twelve.

Invisible to strings: check 2 (PATH-walking builds the path with `new File(dir, "su")`, so no literal
path appears) and check 11 if its strings live in the `.so` — you need `strings` on the library
separately, and if they were obfuscated you would get nothing at all.

**Q3.** With no `<queries>` and `targetSdk` 30 or above, `getPackageInfo` is filtered by `AppsFilter`
and always throws `NameNotFoundException`. **Check 5 is dead code even when the mask enables it.** You
know this before running anything, and it is a finding.

**Q4.** Strings tell you a check exists in the binary. They do not tell you that it **runs** — it may
be behind a feature flag, a build mask, a remote config, a dead branch, or a `catch` that swallows the
result. Nor do they tell you which check the app actually *acts* on. This gap between "present" and
"executed" is exactly why MobSF findings must be verified dynamically before they enter a report.
</details>

<details>
<summary>Answers Q5–Q8 — reading the tracer</summary>

**Q5.** A typical run with a mask of around seven enabled checks yields six to ten `[J]` lines (some
checks produce several — the su-path check produces one per path probed), zero to two `[N]` lines
(only if check 11 is enabled), and one `[L]` line if `libintegrity.so` is loaded.

The `[L]` line is worth calling out separately: `System.loadLibrary("integrity")` tells you a native
library exists *and* names it, which is where you point Ghidra. That single line saves you the entire
"is there a native component" question.

**Q6.** After R8 every trace lands in the same one- or two-letter class, for example
`com.rootlab.target.a`. The same class in every trace means the checks are **co-located** — one checker
class, not twelve scattered call sites. That immediately suggests the cheapest intervention: find the
method in that class that everything reports to, and hook that one thing.

**Q7.** The most common example: `test-keys` strings are present in the DEX (R8 does not remove string
constants from reachable code) but the check never fires because `Build.TAGS` on a stock, release-signed
image is `release-keys`. Second common example: package names present, check never fires, because of
the missing `<queries>`.

Two explanations to distinguish: **(a)** the check ran and returned false honestly; **(b)** the check
never ran. Distinguish by hooking the *method* rather than the API. If your hook on `Gauntlet.testKeys`
(or its obfuscated name) never fires, the method was never invoked, which means the mask disabled it.
If it fires and returns false, it ran and was honestly clean.

Instrumenting the caller rather than the callee to determine reachability is a general technique worth
keeping.

**Q8.** With `FILTER_NOISE = false` you see every filesystem probe the app and the framework make —
hundreds of lines: resource caches, `SharedPreferences`, ART profiles, WebView directories. Occasionally
a check hides there, using a path your `SUSPECT` regex does not match (a defender who reads §3.1's
"probe unlikely paths" advice will have arranged exactly that). The cost is that the signal is buried,
which is why it is not the default. The right workflow is: run filtered first, and if the app still
detects after you neutralise everything the filtered run showed, run unfiltered and read carefully.
</details>

<details>
<summary>Answers Q9–Q10 — the inventory</summary>

**Q9.** A completed inventory usually contains three kinds of "did not fire":

| Kind | Evidence | Reportable? |
|---|---|---|
| Disabled by the build | A hook on the method itself never fires | No — an artefact of this lab; in the wild, the equivalent is a feature flag or dead branch, which *is* worth noting |
| Present, ran, honestly clean | Method hook fires, returns false, and the device genuinely lacks the artefact | No — the check works |
| Present, ran, **cannot ever fire** | Method hook fires, but the API it depends on is filtered/absent (`<queries>`, `/system/xbin/which`, `listFiles()` on `/data/local/tmp`) | **Yes.** The developer believes they have coverage they do not have |

The third row is free value. It costs you nothing to produce and it is the kind of finding a developer
can fix the same day.

**Q10.** You cannot read the weights, but you can *measure* them. Neutralise one check at a time and
observe when the app flips from degraded to working: the check whose removal alone crosses the
threshold is the heaviest, and if no single removal is sufficient, the smallest set whose combined
removal works tells you about the weighting.

This is differential analysis, and it generalises far beyond this lab: when a program's decision is
opaque, vary one input at a time and watch the output. It is often much cheaper than reading the code.
</details>

<details>
<summary>Answers Q11–Q13 — minimal neutralisation</summary>

**Q11.** Typically **three to five hooks** cover seven to nine fired checks:

```javascript
// minimal.js — write this from your inventory, not from memory
Java.perform(function () {
    // covers checks 0, 1, 2 (and 9's FileInputStream sibling if you extend it)
    var File = Java.use("java.io.File");
    var BAD = /(^|\/)su$|busybox|magisk|\/data\/adb/i;
    File.exists.implementation = function () {
        var p = this.getAbsolutePath();
        return BAD.test(p) ? false : this.exists();
    };

    // covers checks 3 and 4
    var Runtime = Java.use("java.lang.Runtime");
    var IOE = Java.use("java.io.IOException");
    var CMD = /(^|\s|\/)su(\s|$)|which\s+su/i;
    Runtime.exec.overloads.forEach(function (ov) {
        ov.implementation = function () {
            var j = "";
            for (var i = 0; i < arguments.length; i++) {
                var a = arguments[i];
                if (a === null) continue;
                j += (typeof a === "object" && a.length !== undefined)
                     ? Array.prototype.join.call(a, " ") : a.toString();
                j += " ";
            }
            if (CMD.test(j)) throw IOE.$new("No such file or directory");
            return ov.apply(this, arguments);
        };
    });

    // covers check 7
    var SAFE = { "ro.debuggable": "0", "ro.secure": "1",
                 "ro.boot.verifiedbootstate": "green", "ro.boot.flash.locked": "1" };
    var SP = Java.use("android.os.SystemProperties");
    SP.get.overloads.forEach(function (ov) {
        ov.implementation = function () {
            var k = arguments[0] === null ? "" : arguments[0].toString();
            return Object.prototype.hasOwnProperty.call(SAFE, k) ? SAFE[k]
                                                                 : ov.apply(this, arguments);
        };
    });

    // covers check 8
    var BR = Java.use("java.io.BufferedReader");
    var MBAD = /magisk|\/data\/adb|tmpfs \/sbin|overlay \/system/i;
    BR.readLine.overload().implementation = function () {
        var l = this.readLine();
        while (l !== null && MBAD.test(l.toString())) l = this.readLine();
        return l;
    };
});
```

Plus [`native-root-bypass.js`](../scripts/native-root-bypass.js) **only if** the tracer produced `[N]`
lines. The ratio — four hooks for eight checks — is the durable insight: **the number of checks is not
the number of mechanisms, and you only pay for mechanisms.**

**Q12.** The usual surprises, in order of how often they catch people out:

- The `File.exists` hook covers three checks at once, because path-list probing, PATH walking and
  Magisk-artefact probing are all the same mechanism with different constants.
- The `BufferedReader.readLine` hook was **not** needed, because the mount check was disabled by the
  mask — you added it from habit rather than from evidence. Removing it changes nothing, and it was the
  hook most likely to break the app.
- One hook you were sure was load-bearing turns out to be irrelevant because the score threshold was
  already met without it.

That second bullet is the whole lab in one line. Hooks you add from habit rather than from evidence
cost you both risk and time.

**Q13.** Hooking the aggregation point — the method returning the score — reduces the script to five
lines:

```javascript
Java.perform(function () {
    // name recovered by enumerating loaded classes; see the hint
    Java.use("com.rootlab.target.a").b.implementation = function (ctx) { return 0; };
});
```

What you lose is **everything your report is made of**. The aggregation hook tells you nothing about
which checks exist, which ran, which are broken, or where they are implemented. It is the right tool
when your goal is access; it is the wrong tool when your goal is an assessment. In practice, do both:
trace to build the inventory, then use the aggregation hook to make the rest of the engagement fast.
</details>

<details>
<summary>Answers Q14–Q17 — verification and scoring</summary>

**Q14.** Three ways the welcome screen can be a false success:

1. **You broke the scoring code.** A hook that throws inside `score()` may leave the caller with a
   default of zero. Verify by logging the score's actual return value, not by looking at the UI.
2. **Residual device state.** DenyList from step 1, a `setenforce 0`, a hiding module. Turn each off
   and re-verify; a finding that only reproduces on your specific device configuration is not a
   finding.
3. **You only tested the launch path.** The evaluation you defeated may not be the one that matters.

The general rule: **verify at the decision, not at the UI.** Hook the function whose return value
drives the behaviour and log what it returns, so success is something you observed rather than
inferred.

**Q15.** Exercise every screen, every button, every network-triggering action. Apps very commonly
re-evaluate immediately before a sensitive operation rather than at startup, precisely because
attaching at startup is the obvious attack.

Because this app never says "root", you find a re-check the same way you found the first one: leave the
tracer running (it does not bypass anything) and watch for new `[J]`/`[N]` lines appearing as you
navigate. A check that fires on the transfer screen but not at launch is immediately visible as new
tracer output at the moment you tap the button.

**Q16 / Q17.** Score yourself honestly, and categorise every miss:

| Miss category | What it means | Fix |
|---|---|---|
| Check enabled, tracer showed it, you did not notice | Reading error | Save tracer output to a file and read it methodically, not in a scrolling terminal |
| Check enabled, tracer did not show it | Instrumentation gap | The check used an API the tracer does not hook. Extend the tracer — this is why the chapter's assignment is to write your own |
| Check enabled, fired only on a screen you never visited | Methodology gap | Exercise the whole app, always |
| You believed a check was enabled and it was not | Inference from strings, not evidence | Strings prove presence, not execution |

The last row is the most common and the most instructive. Nearly everyone lists checks in their
inventory that the mask never enabled, because the strings were there and the inference felt safe.
Presence is not execution. Writing "observed" versus "present in binary" as separate columns in your
inventory is a small discipline that prevents a whole class of wrong statements in reports.
</details>

---

## Success criteria

- [ ] You built the target with a randomised mask and did not read `Mask.java`
- [ ] You tried logs and DenyList before any instrumentation
- [ ] You produced a static string inventory and identified at least one check invisible to it
- [ ] You identified the missing `<queries>` and its consequence before running the app
- [ ] You ran the tracer and separated `[J]`, `[N]` and `[L]` output
- [ ] You identified the checker class from the Java stack traces despite R8 renaming
- [ ] You produced the full twelve-row inventory table with a "fired / evidence" column
- [ ] You distinguished "disabled" from "present but can never fire", using method-level hooks as
      evidence rather than inference
- [ ] Your bypass used fewer hooks than there were checks, and you can explain the ratio
- [ ] You removed hooks one at a time and identified which were load-bearing
- [ ] You hooked the aggregation point as well, and can state what that approach loses
- [ ] You verified at the decision (the score) rather than at the UI
- [ ] You exercised every screen and confirmed whether a re-check exists
- [ ] You opened the answer file only at step 7 and scored your inventory
- [ ] For every miss, you categorised the gap as instrumentation, reading, or methodology

---

## Next

[Lab 04 — CTF: The decoupled check](lab-04-ctf-decoupled.md) removes the last comfort: the app does not
react to detection at all. It notices, says nothing, and fails somewhere else entirely, ten screens
later.
