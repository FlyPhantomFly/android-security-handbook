# Lab 01 — Build and Break Your Own Root Check

**Difficulty:** Beginner
**Time:** 90–150 minutes
**Prerequisites:** [Chapter 37 §3.1–3.11](../README.md#3-deep-internal-working), a rooted test device
or emulator with Magisk, Frida installed and working ([53-Frida](../../53-Frida/README.md)),
Android Studio or a command-line Gradle setup

---

## Objective

Write a nine-signal root checker yourself, in Java, covering the catalogue in §3 of the chapter. Then
defeat each of the nine signals in turn with Frida, and **record what each bypass cost you in
minutes**. Finish by writing the honest assessment you would hand the developer.

You are playing both sides deliberately. The point is not the bypass — bypasses are on the internet.
The point is that you will never again over-value a control whose implementation you have written with
your own hands and destroyed in an afternoon.

## Why this matters

Two failure modes are cured by this lab, and only by this lab.

The first is the developer's: spending sprint capacity on root check number twenty-seven. A developer
who has watched their own nine checks die one by one, in order, in ninety minutes, stops asking for
check number ten and starts asking about server-side enforcement. That conversation is worth more
than any report you will write.

The second is the tester's: treating "root detection bypassed" as a finding. Once you have measured
that a `File.exists` check costs twenty seconds and a `PackageManager` check costs three minutes, you
stop reporting the bypass and start reporting what the bypass gave you access to.

There is a third, smaller benefit: you will discover that at least one of your own nine checks does
not work, for one of the reasons in §11 of the chapter. Finding a broken check in code you wrote
yourself is the fastest possible way to learn to spot them in code you did not.

---

## Setup

### Device

```bash
# host — confirm the device is genuinely rooted, or nothing in this lab happens
adb shell "su -c id"
# expect: uid=0(root) gid=0(root) ...

adb shell getprop ro.build.tags
adb shell getprop ro.boot.verifiedbootstate
adb shell "ls -l /system/xbin/su /system/bin/su /sbin/su 2>&1"
```

Record what you see. If `ro.build.tags` already says `release-keys` and there is no `su` on a
conventional path, you are on a modern Magisk install and some of your checks will legitimately not
fire — which is itself part of the lesson and is discussed in the solution.

Make sure the target app is **not** in Magisk's DenyList for this lab. You want the checks to fire.

```bash
# host — frida-server must be running as root on the device
adb shell "su -c '/data/local/tmp/frida-server &'"
frida-ps -U | head
```

### Build the target

Create a standard empty-activity Android project with package `com.rootlab.target`, `minSdk 24`,
`targetSdk 34`. Three files follow.

**`AndroidManifest.xml`** — note the `<queries>` block. Leaving it out is the single most common reason
a package check silently never fires on API 30+ ([§3.4](../README.md#34-root-manager-packages-via-packagemanager)).

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">

    <!-- Without this, getPackageInfo() on any of these throws
         NameNotFoundException on API 30+ even when the package IS installed,
         and check 4 becomes dead code. -->
    <queries>
        <package android:name="com.topjohnwu.magisk" />
        <package android:name="com.topjohnwu.magisk.debug" />
        <package android:name="eu.chainfire.supersu" />
        <package android:name="com.noshufou.android.su" />
        <package android:name="com.koushikdutta.superuser" />
        <package android:name="com.dimonvideo.luckypatcher" />
        <package android:name="de.robv.android.xposed.installer" />
    </queries>

    <application
        android:label="RootLab"
        android:theme="@style/Theme.AppCompat.Light">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

**`RootChecker.java`** — the nine signals. Each returns a human-readable reason or `null`.

```java
package com.rootlab.target;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Nine independent root signals, each reported separately so that the lab can
 * measure them one at a time.
 *
 * This is written the way a real, competent-but-client-side developer would
 * write it. It is deliberately NOT hardened: hardening is lab 02.
 */
public final class RootChecker {

    private static final String[] SU_PATHS = {
        "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
        "/sbin/su", "/su/bin/su", "/system/bin/su", "/system/bin/.ext/su",
        "/system/bin/failsafe/su", "/system/sd/xbin/su",
        "/system/usr/we-need-root/su", "/system/xbin/su",
        "/vendor/bin/su", "/product/bin/su", "/system_ext/bin/su",
        "/cache/su", "/data/su", "/dev/su"
    };

    private static final String[] BUSYBOX_PATHS = {
        "/system/xbin/busybox", "/system/bin/busybox", "/data/local/busybox",
        "/sbin/busybox"
    };

    private static final String[] MAGISK_PATHS = {
        "/sbin/magisk", "/sbin/magiskinit", "/sbin/magiskpolicy",
        "/sbin/.magisk", "/sbin/.core",
        "/data/adb/magisk", "/data/adb/modules", "/data/adb/magisk.db",
        "/cache/magisk.log", "/init.magisk.rc",
        "/system/addon.d/99-magisk.sh"
    };

    private static final String[] ROOT_PACKAGES = {
        "com.topjohnwu.magisk", "com.topjohnwu.magisk.debug",
        "eu.chainfire.supersu", "com.noshufou.android.su",
        "com.koushikdutta.superuser", "com.dimonvideo.luckypatcher",
        "de.robv.android.xposed.installer"
    };

    /** Signal 1 — su binary on disk. Chapter §3.1 */
    public static String checkSuBinary() {
        for (String p : SU_PATHS) {
            if (new File(p).exists()) return "su binary at " + p;
        }
        return null;
    }

    /** Signal 2 — busybox on disk. Chapter §3.1 */
    public static String checkBusybox() {
        for (String p : BUSYBOX_PATHS) {
            if (new File(p).exists()) return "busybox at " + p;
        }
        return null;
    }

    /** Signal 3 — su reachable through PATH. Chapter §3.2 */
    public static String checkSuOnPath() {
        String path = System.getenv("PATH");
        if (path == null) return null;
        for (String dir : path.split(":")) {
            if (new File(dir, "su").exists()) return "su on PATH in " + dir;
        }
        return null;
    }

    /** Signal 4 — root manager package installed. Chapter §3.4 */
    public static String checkRootPackages(Context ctx) {
        PackageManager pm = ctx.getPackageManager();
        for (String p : ROOT_PACKAGES) {
            try {
                pm.getPackageInfo(p, 0);
                return "package installed: " + p;
            } catch (PackageManager.NameNotFoundException ignored) {
                // not installed, or not visible to us — see the manifest note
            }
        }
        return null;
    }

    /** Signal 5 — build signed with AOSP test keys. Chapter §3.7 */
    public static String checkTestKeys() {
        String tags = Build.TAGS;
        if (tags != null && tags.contains("test-keys")) {
            return "Build.TAGS = " + tags;
        }
        return null;
    }

    /** Signal 6 — dangerous system properties. Chapter §3.7 */
    public static String checkDangerousProps() {
        if ("1".equals(getProp("ro.debuggable")))  return "ro.debuggable = 1";
        if ("0".equals(getProp("ro.secure")))      return "ro.secure = 0";

        String type = getProp("ro.build.type");
        if (type != null && !type.isEmpty() && !"user".equals(type)) {
            return "ro.build.type = " + type;
        }

        String vbs = getProp("ro.boot.verifiedbootstate");
        if (vbs != null && !vbs.isEmpty() && !"green".equals(vbs)) {
            return "ro.boot.verifiedbootstate = " + vbs;
        }

        if ("0".equals(getProp("ro.boot.flash.locked"))) {
            return "ro.boot.flash.locked = 0";
        }
        return null;
    }

    /** Signal 7 — Magisk artefacts on disk. Chapter §3.5 */
    public static String checkMagiskPaths() {
        for (String p : MAGISK_PATHS) {
            if (new File(p).exists()) return "magisk artefact at " + p;
        }
        return null;
    }

    /** Signal 8 — suspicious mount table. Chapter §3.8 */
    public static String checkMounts() {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader("/proc/self/mounts"));
            String line;
            while ((line = r.readLine()) != null) {
                if (line.contains("magisk"))    return "mount: magisk";
                if (line.contains("/data/adb")) return "mount: /data/adb";

                String[] f = line.split(" ");
                if (f.length < 4) continue;
                String dst = f[1], type = f[2], opts = f[3];

                if ("tmpfs".equals(type) &&
                    (dst.startsWith("/sbin") || dst.startsWith("/system"))) {
                    return "mount: tmpfs on " + dst;
                }
                if (("overlay".equals(type) || "overlayfs".equals(type)) &&
                    dst.startsWith("/system")) {
                    return "mount: overlay on " + dst;
                }
                if (("/system".equals(dst) || "/".equals(dst)) && opts.startsWith("rw")) {
                    return "mount: " + dst + " is rw";
                }
            }
        } catch (Exception ignored) {
        } finally {
            try { if (r != null) r.close(); } catch (Exception ignored) { }
        }
        return null;
    }

    /** Signal 9 — `which su` in a subprocess. Chapter §3.2 */
    public static String checkWhichSu() {
        Process p = null;
        try {
            // NOTE: this path is deliberately the one from a 2016 blog post.
            // Part of this lab is discovering what that costs.
            p = Runtime.getRuntime().exec(new String[]{"/system/xbin/which", "su"});
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(p.getInputStream()));
            String line = in.readLine();
            if (line != null && !line.isEmpty()) return "which su -> " + line;
        } catch (Exception ignored) {
        } finally {
            if (p != null) p.destroy();
        }
        return null;
    }

    /** Run everything and return every reason that fired, in order. */
    public static List<String> evaluate(Context ctx) {
        List<String> hits = new ArrayList<>();
        String[] results = {
            checkSuBinary(), checkBusybox(), checkSuOnPath(),
            checkRootPackages(ctx), checkTestKeys(), checkDangerousProps(),
            checkMagiskPaths(), checkMounts(), checkWhichSu()
        };
        String[] names = {
            "1 su-binary", "2 busybox", "3 su-on-PATH", "4 root-package",
            "5 test-keys", "6 dangerous-props", "7 magisk-paths",
            "8 mounts", "9 which-su"
        };
        for (int i = 0; i < results.length; i++) {
            hits.add(names[i] + ": " + (results[i] == null ? "clean" : results[i]));
        }
        return hits;
    }

    private static String getProp(String key) {
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            Method get = sp.getMethod("get", String.class, String.class);
            return (String) get.invoke(null, key, "");
        } catch (Throwable t) {
            return "";
        }
    }

    private RootChecker() { }
}
```

**`MainActivity.java`** — prints every signal individually rather than a single boolean, so you can
watch them fall one at a time.

```java
package com.rootlab.target;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.List;

public class MainActivity extends Activity {

    private static final String TAG = "ROOTLAB";

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TextView tv = new TextView(this);
        tv.setTextSize(13f);
        tv.setPadding(24, 24, 24, 24);
        ScrollView sv = new ScrollView(this);
        sv.addView(tv);
        setContentView(sv);

        List<String> results = RootChecker.evaluate(this);

        int fired = 0;
        StringBuilder sb = new StringBuilder();
        for (String r : results) {
            if (!r.endsWith("clean")) fired++;
            sb.append(r).append('\n');
            Log.i(TAG, r);
        }
        sb.append('\n').append(fired).append(" of 9 signals fired");
        Log.i(TAG, fired + " of 9 signals fired");
        tv.setText(sb.toString());
    }
}
```

Build and install:

```bash
# host
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.rootlab.target/.MainActivity
adb logcat -s ROOTLAB
```

---

## Steps

### Step 1 — Establish the baseline

Launch the app and record which of the nine signals fire on your device.

**Q1.** How many of the nine fired? Which ones did **not**, and for each of those, is it because your
device genuinely lacks that artefact, or because the check itself is broken?

**Q2.** Signal 9 (`which su`) uses the hardcoded path `/system/xbin/which`. Run
`adb shell "ls -l /system/xbin/which /system/bin/which"`. What do you find, and what does that mean
for signal 9 on your device?

**Q3.** If signal 5 (`test-keys`) did not fire on your rooted device, explain why. What does that tell
you about the durability of checks written before systemless root existed?

### Step 2 — Kill signals 1, 2, 3 and 7 with one hook

All four are `File.exists()` on a path list. One Java hook covers them, and you should be able to
write it from memory by the end of this lab.

```javascript
// step2.js — frida -U -f com.rootlab.target -l step2.js --no-pause
Java.perform(function () {
    var File = Java.use("java.io.File");
    var BAD = /(^|\/)su$|busybox|magisk|supersu|superuser|\/sbin\/|\/data\/adb/i;

    File.exists.implementation = function () {
        var p = this.getAbsolutePath();
        if (BAD.test(p)) {
            console.log("[deny] File.exists(" + p + ")");
            return false;
        }
        return this.exists();
    };
});
```

Start a stopwatch **before** you run it. Stop it when the app reports those four as clean.

**Q4.** How long did that take, in minutes, including reading the output and confirming?

**Q5.** Now try the lazy version: make `File.exists` return `false` unconditionally. What happens to
the app, and why is the symptom easy to misdiagnose as "the root check is still firing"?

### Step 3 — Kill signal 4 (packages)

**Q6.** Hook `android.content.pm.PackageManager` first. Does your hook fire? Explain precisely why
not, in terms of what `Context.getPackageManager()` actually returns.

Then do it correctly, on the concrete class, throwing the exception the framework itself would throw.

**Q7.** Why is throwing `NameNotFoundException` a better lie than returning `null`?

**Q8.** Temporarily delete the `<queries>` block from the manifest, rebuild, and re-run **without any
Frida hook**. What happens to signal 4, and what would you write in a report if you found this in a
production app?

### Step 4 — Kill signals 5 and 6 (properties)

Signal 5 reads a static field; signal 6 reads through reflection into a hidden class. They need
different treatment.

**Q9.** `Build.TAGS` is a `public static final String`. It is a compile-time constant candidate. Does
`Java.use("android.os.Build").TAGS.value = "release-keys"` work here, and would it still work if the
comparison had been written as `"test-keys".equals(Build.TAGS)` inside a class compiled in the same
module? Explain what constant inlining would do.

**Q10.** Signal 6 calls `android.os.SystemProperties.get(String, String)` reflectively. Which overload
must you hook, and how do you find out how many overloads exist?

### Step 5 — Kill signal 8 (mounts)

There are at least three places to intervene: the `FileReader` construction, `BufferedReader.readLine`,
and the libc `open`. Try the `readLine` filter from
[§3.8](../README.md#38-procselfmounts-and-procmounts) of the chapter.

**Q11.** The `readLine` hook affects every line-oriented read in the whole app. Name one concrete way
that could break a real application, and describe how you would narrow the hook once you know which
file the check reads.

### Step 6 — Kill signal 9, and then measure the whole thing

**Q12.** Which hook kills signal 9, and did you need it at all on your device? (Compare with your
answer to Q2.)

**Q13.** Total the times. Which single signal cost you the most minutes, and why?

### Step 7 — The shortcut, and what it teaches

Now throw all of that away and hook the aggregation point instead:

```javascript
// step7.js
Java.perform(function () {
    var RC = Java.use("com.rootlab.target.RootChecker");
    var ArrayList = Java.use("java.util.ArrayList");
    RC.evaluate.implementation = function (ctx) {
        console.log("[bypass] RootChecker.evaluate() -> empty");
        return ArrayList.$new();
    };
});
```

**Q14.** How long did that take compared with the sum of steps 2–6? What does the difference tell you
about where a developer's checks should *not* converge?

**Q15.** Now suppose the app is obfuscated and `RootChecker` is called `a.b.c` with a method `d`. What
would you do to find the aggregation point, and does obfuscation change the *cost* of this shortcut or
only the *lookup*?

### Step 8 — Write the assessment

Produce a short table: signal, what it detects, bypass used, minutes spent, and your honest verdict on
its value. Then write three sentences of advice to the developer.

**Q16.** Does your advice contain the word "add"? If so, rewrite it.

---

## Hints

<details>
<summary>Hint — Q6, the PackageManager class</summary>

Ask the runtime what class you actually have:

```javascript
Java.perform(function () {
    var ctx = Java.use("android.app.ActivityThread").currentApplication();
    console.log(ctx.getPackageManager().$className);
});
```

Whatever it prints is the class to hook. Do not assume.
</details>

<details>
<summary>Hint — Q10, enumerating overloads</summary>

```javascript
Java.perform(function () {
    var SP = Java.use("android.os.SystemProperties");
    SP.get.overloads.forEach(function (ov) { console.log(ov); });
});
```

Then hook each one in a loop rather than picking one by hand. Hooking `get(String)` while the app
calls `get(String, String)` produces exactly the "my hook never fires" symptom.
</details>

<details>
<summary>Hint — Q5, why blanket denial breaks things</summary>

Think about what else in an Android app calls `File.exists()` during startup. Resource caching,
`SharedPreferences`, the ART profile, `getCacheDir()`, multidex extraction. Denying all of them does
not throw a recognisable error; it produces odd downstream behaviour that looks like something else.
</details>

<details>
<summary>Hint — Q15, finding the aggregation point in an obfuscated app</summary>

Three approaches, in increasing cost: search for surviving string literals near the checks
(`/system/xbin/su` is still there after R8); enumerate loaded classes and look for a method returning
`boolean` or `List` that is called once from `onCreate`; or run the tracer and read the Java stack
traces it prints — the common frame in all of them *is* the aggregation point.
</details>

---

## Solution

Read only after a genuine attempt.

<details>
<summary>Answers Q1–Q3 — the baseline</summary>

**Q1.** On a modern Magisk device with Zygisk, a typical result is four or five of nine: mounts
(signal 8) and Magisk paths (signal 7) are the reliable ones, `su` on disk (1) may or may not appear
depending on how Magisk exposes it in your namespace, `verifiedbootstate` (6) fires because the
bootloader is unlocked, and `test-keys` (5) usually does **not** because most people root a stock,
release-signed image.

The distinction the question is really asking for: a signal that does not fire because the artefact is
genuinely absent (5, on a stock image) is a *correct* negative; a signal that does not fire because
the code cannot work (9, see below) is a *broken* check. Confusing the two is how testers miss
findings.

**Q2.** On most modern devices, `which` is toybox and lives in `/system/bin/which`;
`/system/xbin/which` does not exist. `Runtime.exec` therefore throws `IOException`, the `catch`
swallows it, and the method returns `null`. **Signal 9 has never worked.** This exact bug ships in
production applications, and reporting it is free value: the developer believes they have a control
they do not have.

**Q3.** Signal 5 tests whether the *system image* was signed with the public AOSP test keys, which is a
custom-ROM signal. Magisk is systemless: it patches the boot image and leaves the release-signed
system image alone, so `Build.TAGS` stays `release-keys`. The check was written when rooting meant
flashing a modified system image. It is a 2014 check being asked a 2024 question, and it correctly
answers a question nobody is asking any more. Durability of a detection is inversely proportional to
how specific it is to one root implementation.
</details>

<details>
<summary>Answers Q4–Q5 — the File.exists hook</summary>

**Q4.** Expect one to three minutes for a first attempt, including a typo. Write the number down; it
is the entire point of the exercise. Four independent checks — 1, 2, 3 and 7 — each of which took a
developer time to research and write, all fall to one hook you can type from memory.

Note *why* one hook covers four checks: they are the same mechanism (`File.exists` on a path list) with
different string constants. The number of checks is not the number of mechanisms, and only mechanisms
cost you anything.

**Q5.** Blanket denial breaks app startup in confusing ways. Android itself calls `File.exists()`
constantly — multidex extraction, `SharedPreferences` loading, cache directory setup, WebView data
directories. The app may crash, hang, or silently lose state, and none of the symptoms says "your
Frida script did this". Testers routinely spend twenty minutes concluding the app has anti-Frida
protection when in fact they broke it themselves.

The rule this teaches: **surgical, never blanket.** Lie about the smallest set of inputs that changes
the decision.
</details>

<details>
<summary>Answers Q6–Q8 — PackageManager</summary>

**Q6.** `android.content.pm.PackageManager` is abstract. `Context.getPackageManager()` returns an
`android.app.ApplicationPackageManager`, which marshals a Binder call to `PackageManagerService` in
`system_server`. Frida replaces a method implementation on a specific class; the abstract declaration
is never executed, so the hook is installed correctly and sits on code that never runs.

Correct version:

```javascript
Java.perform(function () {
    var APM  = Java.use("android.app.ApplicationPackageManager");
    var NNFE = Java.use("android.content.pm.PackageManager$NameNotFoundException");
    var BAD  = /magisk|supersu|superuser|luckypatcher|xposed|substrate|rootcloak/i;

    APM.getPackageInfo.overloads.forEach(function (ov) {
        ov.implementation = function (name) {
            if (name !== null && BAD.test(name.toString())) {
                console.log("[deny] getPackageInfo(" + name + ")");
                throw NNFE.$new(name.toString());
            }
            return ov.apply(this, arguments);
        };
    });
});
```

**Q7.** Because `NameNotFoundException` is what the framework genuinely throws when a package is
absent, so the app's existing `catch` block handles it and execution continues exactly as it would on
a clean device. Returning `null` reaches code that immediately dereferences the result — the app
crashes with an NPE, which is loud, plainly artificial, and in an anti-tamper-aware app may itself be
treated as evidence of tampering.

The general rule: **make the lie indistinguishable from the truth.** That is also why the native
script sets `errno = ENOENT` rather than merely returning `-1`.

**Q8.** Without `<queries>`, signal 4 never fires on API 30+ even with Magisk Manager installed,
because `AppsFilter` in `PackageManagerService` filters the package out before the client ever sees it.

Report wording: *"The application checks for root-manager packages using `getPackageInfo`, but targets
API 34 without declaring a `<queries>` element. Package visibility filtering means these checks have
never fired in production. The control provides no coverage and its presence in the codebase may give
false assurance."* That is a finding a developer can act on in ten minutes, and it costs you nothing to
produce.
</details>

<details>
<summary>Answers Q9–Q10 — properties</summary>

**Q9.** `Java.use("android.os.Build").TAGS.value = "release-keys"` works here, because
`RootChecker.checkTestKeys()` reads the field at runtime from the `android.os.Build` class in the
framework.

It would **not** necessarily work if the constant were inlined. `public static final String` fields
whose initialiser is a compile-time constant expression get copied into the *calling* class's constant
pool by `javac`. `Build.TAGS` is assigned from a native property read at class-initialisation time, so
it is not a compile-time constant and is not inlined — but the general trap is real, and you will meet
it with genuinely constant fields. When a field hook has no effect, check whether the value was
inlined at compile time; if it was, there is no field read left to intercept and you must patch the
comparison instead.

**Q10.** Hook every overload rather than choosing:

```javascript
Java.perform(function () {
    var SAFE = { "ro.debuggable": "0", "ro.secure": "1", "ro.build.type": "user",
                 "ro.boot.verifiedbootstate": "green", "ro.boot.flash.locked": "1" };
    var SP = Java.use("android.os.SystemProperties");
    SP.get.overloads.forEach(function (ov) {
        ov.implementation = function () {
            var k = arguments[0] === null ? "" : arguments[0].toString();
            if (Object.prototype.hasOwnProperty.call(SAFE, k)) {
                console.log("[spoof] " + k + " -> " + SAFE[k]);
                return SAFE[k];
            }
            return ov.apply(this, arguments);
        };
    });
});
```

`SP.get.overloads` enumerates them. Guessing `get(String)` when the app calls `get(String, String)` is
the classic "my hook never fires" cause, and it is indistinguishable from a native check unless you
check.
</details>

<details>
<summary>Answers Q11–Q13 — mounts, and the totals</summary>

**Q11.** `BufferedReader.readLine` is used by essentially every text-parsing path in an app: JSON
responses read line by line, CSV imports, log files, config files bundled in assets. A filter that
silently drops lines containing `su` as a whole word will corrupt any of them, and the corruption is
silent — you get a truncated list, not an exception.

Narrow it by keying on the reader's source. Hook `FileReader`/`FileInputStream` construction, remember
the object identity for the ones opened on `/proc/*/mounts`, and only filter `readLine` on those. Or
better, move down to the libc `open`/`openat` layer and substitute a scrubbed file, which is what
[`../scripts/native-root-bypass.js`](../scripts/native-root-bypass.js) does.

**Q12.** The `Runtime.exec` hook from
[§3.2](../README.md#32-su-on-path-and-which-su), throwing `IOException`. On most modern devices you
did not need it at all, because signal 9 was already dead (Q2). Notice how easily you could have spent
ten minutes bypassing a check that was never running — which is precisely why the tracer, not
guesswork, is the right first move.

**Q13.** Typically signal 8 (mounts) or signal 4 (packages) — signal 8 because the naive hook breaks
things and you have to narrow it, signal 4 because of the abstract-class trap. Both cost is
*mechanism* cost, not *check* cost. Nine checks, four mechanisms, perhaps twenty-five minutes total on
a second attempt.
</details>

<details>
<summary>Answers Q14–Q16 — the shortcut and the assessment</summary>

**Q14.** Thirty seconds versus twenty-five minutes. The lesson for the developer is not "do not
aggregate" — aggregation is good engineering — but that **an aggregation point is a single point of
failure for the entire control**, and no amount of effort spent on the individual checks changes the
cost of hooking the one function they all report to. A developer who understands this stops adding
checks.

The corresponding lesson for the tester: **always look for the aggregation point first.** There is
usually exactly one, it is usually called from `onCreate`, and it is usually the cheapest place to
intervene.

**Q15.** Obfuscation changes the *lookup*, not the *cost*. Run the tracer, read the Java stack traces
it prints for each hit, and find the frame common to all of them — that is the aggregation point, by
construction. Or enumerate loaded classes for a method returning `boolean`/`List` called once from the
launch path. Either takes minutes, after which the hook is the same thirty seconds it always was.

**Q16.** If your advice says "add a native check" or "add certificate pinning to the check", rewrite
it. The advice that follows from this lab is about **placement**, not quantity:

> The nine local signals provide a useful risk input and should be reported to the server rather than
> acted on in the app. The decision they currently gate must move server-side, bound to a Play
> Integrity token with a server-issued nonce and request binding, failing closed. Signal 9 has never
> functioned; either fix it or delete it, but do not count it as coverage.

Three sentences, no new checks, and every one of them is actionable.
</details>

---

## Success criteria

- [ ] You built the target and recorded which of the nine signals fired on your device
- [ ] You identified at least one signal that is **broken** rather than merely clean, and explained why
- [ ] You defeated signals 1, 2, 3 and 7 with a single `File.exists` hook and timed it
- [ ] You observed what blanket denial does to the app, and can describe the symptom
- [ ] You hooked `ApplicationPackageManager`, not the abstract `PackageManager`, and can explain the difference
- [ ] You threw `NameNotFoundException` rather than returning `null`, and can justify it
- [ ] You demonstrated that removing `<queries>` silently kills the package check on API 30+
- [ ] You enumerated `SystemProperties.get.overloads` rather than guessing one
- [ ] You defeated the mount check and can name one way the naive `readLine` hook breaks real apps
- [ ] You hooked the aggregation point and compared the cost with the sum of the individual bypasses
- [ ] You produced the signal/bypass/minutes/verdict table
- [ ] Your three sentences of developer advice contain no new checks

---

## Next

[Lab 02 — Native check, no Java surface](lab-02-native-check.md) adds a single line of C to this same
app and watches every hook you just wrote stop working. That is the lab that teaches the lesson this
one sets up.
