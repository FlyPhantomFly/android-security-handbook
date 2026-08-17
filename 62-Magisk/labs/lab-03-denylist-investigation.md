# Lab 03 — DenyList Investigation

**Difficulty:** Intermediate
**Time:** 3–5 hours
**Prerequisites:** [Lab 02](lab-02-write-a-module.md) with both modules still installed,
[Chapter 62 §2.2](../README.md#22-the-overlay-illusion),
[§3.9](../README.md#39-denylist--what-it-really-does),
[§7.2](../README.md#72-confirming-what-a-target-process-actually-sees),
[02-Linux-Basics](../../02-Linux-Basics/README.md) for mount namespaces,
[21-App-Sandbox](../../21-App-Sandbox/README.md) for what a process can see of another

---

## Objective

Determine, **by measurement rather than by reading the documentation**, exactly what Magisk's
DenyList removes from a process's view of the system, exactly what it leaves behind, and exactly
when in the process's life it happens.

At the end you will have a table of observed facts about your own device, an `nsenter`-based
technique you will use on every engagement afterwards, and a precise answer to the question that
brings most people to this chapter: *"I enabled DenyList and the app still detects root — why?"*

## Why this matters

DenyList is the most misunderstood feature in the Android rooting ecosystem, and the
misunderstanding is specific: people believe it *hides* Magisk. It does not. It **retreats** —
it removes Magisk's modifications from one process's mount namespace, so that the process sees a
system that looks untouched. Anything Magisk cannot remove stays exactly where it was.

The difference is not pedantry. It predicts, correctly, every one of the following:

- Why a banking app still detects root after you tick its box in DenyList.
- Why your Burp interception dies the moment you add the target app to DenyList.
- Why hiding the Magisk Manager package is a *separate* action with a separate mechanism.
- Why nothing you do in DenyList affects a Play Integrity verdict.

And the technique that establishes all of it is one command: `nsenter` into the target's mount
namespace and look at the same paths the app looks at. Chapter §7.2 calls it "the single most useful
diagnostic in this chapter". This lab is where you learn to trust it.

> **🧠 Mental Model**
> Two processes on the same device, at the same instant, asking `stat("/system/bin/su")`, can get
> different answers. Not "sometimes", not "with a race" — deterministically, by design, because the
> path is resolved against each process's own mount namespace. Until that sentence feels obvious
> rather than surprising, root hiding will keep producing results that look like magic. It is not
> magic; it is `CLONE_NEWNS`, and containers are built on the same primitive.

> **🔍 Boundary note**
> This lab is about **mount namespaces and module mechanics**. The catalogue of root *detection*
> techniques, and how to defeat each of them, belongs to
> [37-RootDetection](../../37-RootDetection/README.md) — go there for the checks themselves. Here,
> the probe app is an instrument, not a target: it exists to report what it can see, not to be
> outwitted.

---

## Setup

### Requirements

```bash
# adb shell as root — confirm the ground state
magisk -v
magisk --path                      # note this; you will need it
ls /data/adb/modules/              # systemca and pentestprep from lab 02 should be here
grep -ic magisk /proc/self/mountinfo
```

Zygisk must be enabled, because DenyList's unmount runs in the Zygisk specialise hook:

```
Magisk app > Settings > Zygisk = ON  > reboot
Magisk app > Settings > Configure DenyList  (this entry only appears when Zygisk is on)
```

```bash
# adb shell — confirm Zygisk is actually on after the reboot
su -c 'magisk --sqlite "SELECT * FROM settings"'
# Look for a zygisk row. Value 1 = enabled.
```

### `nsenter`

`nsenter` enters another process's namespaces. Recent Android toyboxes include it; older ones do
not. Magisk ships a full busybox, which does.

```bash
# adb shell as root — find a working nsenter, in preference order
command -v nsenter || echo "no toybox nsenter"
ls -la /data/adb/magisk/busybox && /data/adb/magisk/busybox nsenter --help 2>&1 | head -3
```

For the rest of this lab, `NS=` is whichever of these works:

```bash
# adb shell as root
NS="nsenter"
command -v nsenter >/dev/null 2>&1 || NS="/data/adb/magisk/busybox nsenter"
echo "using: $NS"
```

> **📖 Definition — mount namespace**
> A per-process view of the filesystem hierarchy. Processes in the same mount namespace see the same
> set of mounts; a process in its own namespace can add or remove mounts without any other process
> noticing. Created with `unshare(CLONE_NEWNS)` or `clone(CLONE_NEWNS)`. The identity of a process's
> namespace is exposed as a symlink at `/proc/<pid>/ns/mnt`, whose target is a string like
> `mnt:[4026532285]` — two processes with the same target are in the same namespace.

---

## Part 1 — Build the probe

You need an app that reports what it can see, honestly and completely. Nothing off the shelf does
exactly this, because every off-the-shelf root checker is trying to produce a verdict; you want
observations.

### `AndroidManifest.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.magisklab.probe">

    <!-- API 30+ package visibility: without this, a PackageManager query for another
         package returns "not installed" even when it IS installed. Getting this wrong
         would make the probe lie to you. See 32-Manifest. -->
    <queries>
        <package android:name="com.topjohnwu.magisk" />
        <package android:name="io.github.huskydg.magisk" />
    </queries>

    <application
        android:label="NS Probe"
        android:name=".ProbeApplication"
        android:allowBackup="false">
        <activity android:name=".ProbeActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

### `ProbeApplication.java` — probe before the app's own code runs

The point of this class is timing. `Application`'s static initialiser is close to the earliest
Java code an app can run, and it is *after* Zygisk's `postAppSpecialize`. Probing here and again in
the Activity tells you whether the DenyList unmount had already happened before your app's first
instruction.

```java
package com.magisklab.probe;

import android.app.Application;
import android.util.Log;

public class ProbeApplication extends Application {

    public static String STATIC_INIT_SNAPSHOT;

    static {
        // Earliest practical Java probe point in an app process.
        STATIC_INIT_SNAPSHOT = Probe.quickSnapshot("static-init");
        Log.i("NSPROBE", STATIC_INIT_SNAPSHOT);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i("NSPROBE", Probe.quickSnapshot("application-oncreate"));
    }
}
```

### `Probe.java` — the observations

```java
package com.magisklab.probe;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Process;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Reports what THIS process can see. Deliberately makes no verdict: every method
 * returns an observation, and interpretation is the analyst's job.
 *
 * Nothing here is novel as a root check -- the catalogue of checks belongs to
 * chapter 37. What matters here is that every observation is namespace-scoped,
 * so the same code run inside and outside the app's mount namespace gives
 * different answers, and the difference IS the measurement.
 */
public final class Probe {

    private static final String[] SU_PATHS = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
        "/vendor/bin/su", "/data/local/tmp/su"
    };

    /** One-line snapshot for logcat, cheap enough to run in a static initialiser. */
    public static String quickSnapshot(String tag) {
        return "[" + tag + "]"
             + " pid=" + Process.myPid()
             + " uid=" + Process.myUid()
             + " ns=" + readLink("/proc/self/ns/mnt")
             + " mounts=" + countMountLines(null)
             + " magiskMounts=" + countMountLines("magisk")
             + " su=" + anySuPath()
             + " cacerts=" + countDir("/system/etc/security/cacerts");
    }

    /** The full report, written to the app's own files directory. */
    public static String fullReport(Context ctx) {
        StringBuilder b = new StringBuilder();

        b.append("# namespace-probe report\n");
        b.append("pid=").append(Process.myPid()).append('\n');
        b.append("uid=").append(Process.myUid()).append('\n');
        b.append("mnt_ns=").append(readLink("/proc/self/ns/mnt")).append('\n');
        b.append("net_ns=").append(readLink("/proc/self/ns/net")).append('\n');

        b.append("\n## filesystem visibility\n");
        for (String p : SU_PATHS) {
            File f = new File(p);
            b.append("path ").append(p)
             .append(" exists=").append(f.exists())
             .append(" canRead=").append(f.canRead())
             .append(" errnoClass=").append(classifyAccess(p))
             .append('\n');
        }
        b.append("dir /system/etc/security/cacerts count=")
         .append(countDir("/system/etc/security/cacerts")).append('\n');
        b.append("dir /apex/com.android.conscrypt/cacerts count=")
         .append(countDir("/apex/com.android.conscrypt/cacerts")).append('\n');
        b.append("path /data/adb errnoClass=").append(classifyAccess("/data/adb")).append('\n');

        b.append("\n## mounts\n");
        b.append("mountinfo_lines=").append(countMountLines(null)).append('\n');
        for (String needle : new String[]{"magisk", "worker", "debug_ramdisk", "overlay", "tmpfs"}) {
            b.append("mountinfo_matching_").append(needle).append('=')
             .append(countMountLines(needle)).append('\n');
        }

        b.append("\n## maps\n");
        for (String needle : new String[]{"zygisk", "magisk", "frida", "memfd"}) {
            b.append("maps_matching_").append(needle).append('=')
             .append(countFileLines("/proc/self/maps", needle)).append('\n');
        }

        b.append("\n## properties (framework API, i.e. what an ordinary app can read)\n");
        b.append("Build.TAGS=").append(Build.TAGS).append('\n');
        b.append("Build.TYPE=").append(Build.TYPE).append('\n');
        b.append("Build.FINGERPRINT=").append(Build.FINGERPRINT).append('\n');

        b.append("\n## packages\n");
        for (String pkg : new String[]{"com.topjohnwu.magisk", "io.github.huskydg.magisk"}) {
            b.append("package ").append(pkg).append(" installed=")
             .append(isInstalled(ctx, pkg)).append('\n');
        }

        b.append("\n## selinux\n");
        b.append("selinux_policy_readable=")
         .append(new File("/sys/fs/selinux/policy").canRead()).append('\n');
        b.append("enforce_node_readable=")
         .append(new File("/sys/fs/selinux/enforce").canRead()).append('\n');

        b.append("\n## raw mountinfo\n");
        b.append(readAll("/proc/self/mountinfo"));

        return b.toString();
    }

    // ---- primitives ------------------------------------------------------

    private static boolean anySuPath() {
        for (String p : SU_PATHS) if (new File(p).exists()) return true;
        return false;
    }

    /**
     * Distinguishes "not there" from "there but forbidden". A path that reports
     * NOT_FOUND on a stock device and FORBIDDEN here is itself a signal, and it
     * is a signal DenyList cannot remove.
     */
    private static String classifyAccess(String path) {
        File f = new File(path);
        if (f.exists()) return f.canRead() ? "READABLE" : "EXISTS_UNREADABLE";
        File parent = f.getParentFile();
        if (parent != null && parent.exists() && !parent.canRead()) return "PARENT_UNREADABLE";
        return "NOT_FOUND";
    }

    private static int countDir(String path) {
        String[] kids = new File(path).list();
        return kids == null ? -1 : kids.length;
    }

    private static int countMountLines(String needle) {
        return countFileLines("/proc/self/mountinfo", needle);
    }

    private static int countFileLines(String path, String needle) {
        int n = 0;
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader(path));
            String line;
            while ((line = r.readLine()) != null) {
                if (needle == null || line.toLowerCase().contains(needle)) n++;
            }
        } catch (IOException e) {
            return -1;
        } finally {
            close(r);
        }
        return n;
    }

    private static String readLink(String path) {
        try {
            return new File(path).getCanonicalPath();
        } catch (IOException e) {
            return "<unreadable>";
        }
    }

    private static String readAll(String path) {
        StringBuilder b = new StringBuilder();
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader(path));
            String line;
            while ((line = r.readLine()) != null) b.append(line).append('\n');
        } catch (IOException e) {
            b.append("<unreadable: ").append(e.getMessage()).append(">\n");
        } finally {
            close(r);
        }
        return b.toString();
    }

    private static boolean isInstalled(Context ctx, String pkg) {
        PackageManager pm = ctx.getPackageManager();
        try {
            pm.getPackageInfo(pkg, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    private static void close(BufferedReader r) {
        if (r != null) try { r.close(); } catch (IOException ignored) { }
    }

    private Probe() { }
}
```

### `ProbeActivity.java`

```java
package com.magisklab.probe;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class ProbeActivity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        final TextView out = new TextView(this);
        out.setTextSize(10f);
        out.setTypeface(android.graphics.Typeface.MONOSPACE);

        Button run = new Button(this);
        run.setText("Probe and write report");
        run.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String report = Probe.fullReport(ProbeActivity.this);
                out.setText(report);
                Log.i("NSPROBE", "----- report begin -----");
                for (String line : report.split("\n")) Log.i("NSPROBE", line);
                Log.i("NSPROBE", "----- report end -----");
                write(report);
            }
        });

        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(16, 64, 16, 16);
        col.addView(new TextView(this) {{ setText(ProbeApplication.STATIC_INIT_SNAPSHOT); }});
        col.addView(run);

        ScrollView sv = new ScrollView(this);
        sv.addView(out);
        col.addView(sv);
        setContentView(col);
    }

    private void write(String report) {
        File f = new File(getFilesDir(), "probe-report.txt");
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(f);
            fos.write(report.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            Log.e("NSPROBE", "write failed", e);
        } finally {
            if (fos != null) try { fos.close(); } catch (IOException ignored) { }
        }
        Log.i("NSPROBE", "report written to " + f.getAbsolutePath());
    }
}
```

### Build and install

```bash
# host
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.magisklab.probe/.ProbeActivity
adb logcat -s NSPROBE:I -d | tail -5
```

**Q1.** Before you run anything else: predict, in writing, what each of the following will be with
DenyList **off** and with it **on**. You are grading your own model, and getting a prediction wrong
here is worth more than getting them all right.

| Observation | Predicted, DenyList off | Predicted, DenyList on |
|---|---|---|
| `magiskMounts` | | |
| `su` path exists | | |
| `cacerts` count | | |
| `mnt_ns` value | | |
| `package com.topjohnwu.magisk installed` | | |
| `Build.TAGS` | | |
| `maps_matching_zygisk` | | |
| `/data/adb` errnoClass | | |

---

## Part 2 — Baseline with DenyList off

```bash
# host
adb shell "su -c 'ls /data/adb/modules/'"        # confirm systemca is installed and enabled
adb shell am force-stop com.magisklab.probe
adb logcat -c
adb shell am start -n com.magisklab.probe/.ProbeActivity
# tap "Probe and write report"
adb logcat -s NSPROBE:I -d > baseline-denylist-off.txt
adb shell "su -c 'cat /data/data/com.magisklab.probe/files/probe-report.txt'" > report-off.txt
```

Now take the same measurements **from outside**, three ways, and see whether they agree.

```bash
# adb shell as root
PID=$(pidof -s com.magisklab.probe); echo "pid=$PID"

# (a) the global view -- root shell's own namespace
grep -ic magisk /proc/self/mountinfo
ls /system/etc/security/cacerts | wc -l
ls -l /system/bin/su 2>&1

# (b) the target's namespace, read through /proc
grep -ic magisk /proc/$PID/mountinfo

# (c) the target's namespace, entered
$NS --mount=/proc/$PID/ns/mnt -- sh -c 'grep -ic magisk /proc/self/mountinfo; ls /system/etc/security/cacerts | wc -l; ls -l /system/bin/su 2>&1'
```

**Q2.** Do (b) and (c) agree with each other? Do they agree with what the app itself reported? If
any of the three disagrees, you have found either a bug in your method or something genuinely
interesting — resolve it before continuing, because everything after this depends on these three
being interchangeable.

**Q3.** Compare `/proc/$PID/ns/mnt` with `/proc/1/ns/mnt` and with the namespace of a second,
unrelated app. Are all apps in one namespace, or does each have its own? What does your answer imply
about *whose* view DenyList is modifying?

```bash
# adb shell as root
readlink /proc/1/ns/mnt
readlink /proc/$(pidof -s com.magisklab.probe)/ns/mnt
readlink /proc/$(pidof -s com.android.settings)/ns/mnt
readlink /proc/$(pidof -s zygote64)/ns/mnt
```

---

## Part 3 — Turn DenyList on and measure again

```
Magisk app > Settings > Configure DenyList > tick "NS Probe" (com.magisklab.probe)
```

DenyList takes effect when the process is next forked from zygote, so the app must be fully stopped:

```bash
# host
adb shell am force-stop com.magisklab.probe
adb shell "su -c 'pidof com.magisklab.probe'"   # expect nothing
adb logcat -c
adb shell am start -n com.magisklab.probe/.ProbeActivity
# tap "Probe and write report"
adb logcat -s NSPROBE:I -d > after-denylist-on.txt
adb shell "su -c 'cat /data/data/com.magisklab.probe/files/probe-report.txt'" > report-on.txt
```

```bash
# host — the diff that is the entire lab
diff report-off.txt report-on.txt
```

**Q4.** Fill in the *observed* column of your Q1 table. Which predictions were wrong? For each wrong
prediction, write one sentence explaining the mechanism you had misunderstood.

---

## Part 4 — Enumerate exactly which mounts were removed

The diff above tells you *how many* mounts vanished. Now find out *which*.

Use the chapter's script, which does the comparison properly — it normalises the mount IDs and
parent IDs that differ between namespaces for uninteresting reasons, so the output is signal:

```bash
# host — push and run the namespace diff helper
adb push ../scripts/ns-diff.sh /data/local/tmp/
adb shell "su -c 'chmod 755 /data/local/tmp/ns-diff.sh'"
adb shell "su -c '/data/local/tmp/ns-diff.sh com.magisklab.probe'" > ns-diff-output.txt
cat ns-diff-output.txt
```

Or do it by hand, which is worth doing once so the script is not a black box:

```bash
# adb shell as root
PID=$(pidof -s com.magisklab.probe)
# field 5 of mountinfo is the mount point; sort it so we can diff sets
awk '{print $5}' /proc/self/mountinfo     | sort -u > /data/local/tmp/global.mnt
awk '{print $5}' /proc/$PID/mountinfo     | sort -u > /data/local/tmp/target.mnt
diff /data/local/tmp/global.mnt /data/local/tmp/target.mnt
```

And for a structured comparison on the host, where you can keep the artefacts:

```bash
# host
adb shell "su -c 'cat /proc/1/mountinfo'"  > global-mountinfo.txt
PID=$(adb shell pidof -s com.magisklab.probe | tr -d '\r')
adb shell "su -c 'cat /proc/$PID/mountinfo'" > target-mountinfo.txt
python3 ../scripts/mountinfo-diff.py global-mountinfo.txt target-mountinfo.txt
```

**Q5.** Produce the complete list of mount points present in the global namespace and absent from
the app's. Group them into categories: module overlays, Magisk's own tmpfs, `su` bind mounts,
anything else. How many are there in total?

**Q6.** Are there any mounts present in the app's namespace and **absent** from the global one? If
so, what are they, and are they Magisk's doing or Android's? (Storage and `sdcardfs`/FUSE mounts are
the usual innocent answer; do not report them as findings.)

**Q7.** Now the question that matters for detection: a stock, unrooted device has a certain number
of mounts with a certain shape. Your app's namespace has had mounts *removed*. Is the result
identical to a stock device's namespace, or merely free of Magisk's additions? How would you find
out, and what would you need in order to be certain?

> **🔍 Pentester's Note**
> Q7 is the whole modern detection game in one question. Detection has moved from "is `su` present"
> to "does this namespace look like a namespace that was never modified". The second is much harder
> to satisfy, because removing a mount is not the same as never having made it — reference counts,
> mount IDs, ordering and the parent-ID chain all carry traces. You cannot fix that from userspace,
> which is the honest reason kernel-side roots have a detection advantage
> ([§3.11](../README.md#311-magisk-versus-kernelsu-versus-apatch)).

---

## Part 5 — The CA collision, measured

This is the interaction that surprises people every single engagement.

```bash
# adb shell as root
PID=$(pidof -s com.magisklab.probe)

echo "== global namespace =="
ls /system/etc/security/cacerts | wc -l
ls /system/etc/security/cacerts | grep -c "^${HASH}\.0$"      # your lab-02 certificate

echo "== the app's namespace =="
$NS --mount=/proc/$PID/ns/mnt -- ls /system/etc/security/cacerts | wc -l
$NS --mount=/proc/$PID/ns/mnt -- ls /system/etc/security/cacerts | grep -c "^${HASH}\.0$"
```

**Q8.** State the two counts. Your certificate is present in one namespace and absent from the
other. Explain in one sentence why, and then explain why "reinstall the module" cannot fix it.

**Q9.** You have a target app that (a) detects root through mount inspection and (b) uses the system
trust store with no pinning. You need both root hiding and interception. Enumerate every option you
can think of, with its cost:

| Option | Does it give hiding? | Does it give interception? | Cost |
|---|---|---|---|
| DenyList only | | | |
| CA module only | | | |
| Both | | | |
| CA module + hook the app's TLS verification with Frida instead of DenyList | | | |
| DenyList + a bind mount you create yourself inside the app's namespace after it starts | | | |
| Neither; use a device without hardware attestation and negotiate scope | | | |

The last row of that table is not a joke, and the second-to-last row is the seed of lab 05.

---

## Part 6 — What DenyList does not touch

Measure each of these with DenyList **on**, and record the result. Every "still visible" row is a
detection vector DenyList does nothing about.

```bash
# adb shell as root — the SELinux policy still contains Magisk's domain
strings /sys/fs/selinux/policy 2>/dev/null | grep -c magisk
# ... but can the APP read that file? The probe already answered this:
grep selinux_policy_readable report-on.txt
```

```bash
# adb shell — properties are unchanged by DenyList
getprop ro.boot.verifiedbootstate
getprop ro.boot.flash.locked
getprop ro.build.tags
```

```bash
# adb shell — is the Manager package visible to the probe?
grep '^package ' report-on.txt
pm list packages | grep -i magisk
```

Then use the Magisk app's **Hide the Magisk app** setting (it repackages the Manager under a random
package name), force-stop the probe, and re-run:

```bash
# host
adb shell am force-stop com.magisklab.probe
adb shell am start -n com.magisklab.probe/.ProbeActivity
adb shell "su -c 'cat /data/data/com.magisklab.probe/files/probe-report.txt'" | grep '^package '
```

**Q10.** Complete this table from your own measurements. Mark each cell **removed**, **still
visible**, or **not applicable**, and add a note saying *how you determined it*:

| Signal | DenyList off | DenyList on | Determined how |
|---|---|---|---|
| `/system/bin/su` exists | | | |
| Magisk mounts in `/proc/self/mountinfo` | | | |
| Extra entries in `/system/etc/security/cacerts` | | | |
| `com.topjohnwu.magisk` visible to `PackageManager` | | | |
| Same, after "Hide the Magisk app" | | | |
| `ro.boot.verifiedbootstate` | | | |
| `Build.TAGS` | | | |
| `magisk` string in `/sys/fs/selinux/policy` | | | |
| Whether the app can *read* `/sys/fs/selinux/policy` at all | | | |
| `zygisk`-related entries in `/proc/self/maps` | | | |
| `/data/adb` classified as `NOT_FOUND` vs `PARENT_UNREADABLE` | | | |
| A Play Integrity verdict | | | |

**Q11.** The `/data/adb` row is subtle. On a stock device, what does a normal app get when it stats
`/data/adb`? On your rooted device with DenyList on, what does it get? If those differ, you have
found a signal that survives DenyList entirely — describe it precisely enough that a developer could
implement the check.

---

## Part 7 — When does the unmount happen?

Your probe logs a snapshot from `ProbeApplication`'s static initialiser, which is about as early as
Java code can run in an app process, and another from `onCreate`.

```bash
# host
grep 'static-init' after-denylist-on.txt
grep 'application-oncreate' after-denylist-on.txt
```

**Q12.** Are the two snapshots identical in their `magiskMounts` count? What does that tell you
about whether the unmount happens before or after the app's first line of code?

**Q13.** Draw the ordering, from `fork()` in zygote to `ActivityThread.main()`, marking where the
unmount occurs. Use [§2.4](../README.md#24-zygisk--injection-into-every-app) and
[§4.2](../README.md#42-tracing-the-zygote-fork--the-path-zygisk-intercepts). Then answer: could an
app defeat DenyList by taking its measurement *earlier*? What is the earliest point an app's own
code runs, and is anything of the app's running before `preAppSpecialize`?

**Q14.** A native library's `.init_array` constructor runs when the library is loaded. Is that
earlier or later than `ProbeApplication`'s static initialiser? (Chapter
[17-Libraries](../../17-Libraries/README.md) has the ordering; its lab 04 is built entirely on this
question.) Does the answer change your conclusion in Q13?

---

## Part 8 — Write the finding

You now have measurements. Turn them into the two paragraphs you would actually put in a report.

**Paragraph 1 — the methodology note.** Two or three sentences stating that testing was performed on
a rooted device, that root was your instrument and not a finding, which hiding measures were applied,
and what was verified about the app's view of the system. This is the paragraph that stops a client's
engineer from dismissing your results.

**Paragraph 2 — the honest limit.** If the app detected root anyway, say what it was looking at,
what you measured, and what it would cost to defeat. If you could not defeat it, say that, and say
what you did instead. "The application's device-integrity control could not be bypassed from the
client; testing therefore proceeded on <alternative> and the following areas were not covered" is a
sentence worth more to a client than a week of failed hiding attempts.

**Q15.** Write both paragraphs. Then re-read them and delete every sentence that asserts something
you did not measure in this lab.

---

## Hints

<details>
<summary>Hint 1 — nsenter says "Operation not permitted"</summary>

Three usual causes, in order of likelihood:

1. You are not root. `nsenter` needs `CAP_SYS_ADMIN`. `su -c '...'` — and remember that
   `adb shell su -c "a; b"` loses the quoting on the way to the device; wrap multi-command payloads <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- the broken form, named as the cause being diagnosed -->
   in `sh -c` as this lab does.
2. SELinux. Check `dmesg | grep avc` immediately after the failure. A targeted
   `magiskpolicy --live "allow ..."` derived from the denial is the fix; `setenforce 0` is not.
3. The process died between `pidof` and `nsenter`. Apps get killed. Re-check the PID.
</details>

<details>
<summary>Hint 2 — the app is on the DenyList but nothing changed</summary>

- Zygisk must be **on**; the DenyList entry does nothing without it. Check the Magisk app's settings
  and reboot after enabling.
- The app must be **fully stopped and re-forked**. `am force-stop`, then confirm with
  `pidof` that nothing remains, then start it. A process that was already running keeps the
  namespace it was given at fork time.
- Some apps run several processes (`:remote`, `:push`). Ticking the package in the DenyList UI
  expands to a list of processes — make sure the one you are measuring is ticked. `ps -A | grep
  <pkg>` shows you how many there are.
</details>

<details>
<summary>Hint 3 — mountinfo fields, so you can read it without guessing</summary>

```
36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
1  2  3    4     5     6           7        8 9    10       11
```

| # | Field |
|---|---|
| 1 | mount ID — unique per mount, **differs between namespaces** |
| 2 | parent mount ID |
| 3 | major:minor of the device |
| 4 | root of the mount within the filesystem — this is where a bind mount's *source* shows up |
| 5 | mount point — the path as seen in **this** namespace |
| 6 | mount options |
| 7 | optional fields (`shared:`, `master:`, `propagate_from:`) terminated by a single `-` |
| 9 | filesystem type |
| 10 | mount source |
| 11 | superblock options |

Fields 1 and 2 are why a naive `diff` of two mountinfo files is unreadable: they legitimately differ
between namespaces. Diff on fields 4, 5, 9 and 10 instead. That is exactly what
[`../scripts/mountinfo-diff.py`](../scripts/mountinfo-diff.py) does.
</details>

<details>
<summary>Hint 4 — the probe reports -1 for a count</summary>

`-1` is the probe's encoding for "could not read". Distinguish the causes:

- `countDir` returns `-1` when `File.list()` returns null, which means the directory does not exist
  **or** the app cannot read it. That ambiguity is itself informative — `classifyAccess` exists to
  resolve it.
- `countFileLines` returns `-1` on `IOException`. For `/proc/self/maps` that essentially never
  happens; for `/sys/fs/selinux/policy` it happens routinely and correctly, because an app is not
  permitted to read the policy. Note the distinction between "DenyList removed it" and "the sandbox
  never allowed it in the first place" — chapter
  [21-App-Sandbox](../../21-App-Sandbox/README.md) owns the second.
</details>

---

## Solutions and expected answers

<details>
<summary>Q2, Q3 — namespaces per process</summary>

Reading `/proc/<pid>/mountinfo` and entering the namespace with `nsenter` give the same answer,
because both resolve against the target's namespace. The app's own report agrees, because the app is
that process. If they disagree, you have the wrong PID (multi-process app) or the process restarted.

On modern Android each app process gets its own mount namespace — this predates Magisk entirely and
exists so that per-user and per-app storage views (`/storage/emulated/...`) can differ. Magisk did
not invent the per-app namespace; it *exploits* one that Android already creates. That is worth
saying out loud, because it explains why DenyList is cheap: there is no unsharing to do.

zygote's namespace and `init`'s namespace are the interesting comparison points. The app's namespace
descends from zygote's at `fork()` time, and everything Magisk unmounts is unmounted from that
descendant copy only.
</details>

<details>
<summary>Q5–Q7 — what is removed</summary>

You should see, removed from the app's namespace: every bind mount whose source is under
`/data/adb/modules`, the tmpfs directory clones Magisk created (the cacerts directory being the
obvious one after lab 02), Magisk's own tmpfs at whatever `magisk --path` reported, and the `su`
bind mount if your Magisk version installs one.

You should **not** see the app's storage mounts removed — those are Android's, not Magisk's.

Q7's answer is the important one: the result is *free of Magisk's additions*, which is not the same
as *identical to a device that was never modified*. Establishing the difference requires a genuine
stock device of the same build to compare against, which is precisely the artefact most testers do
not have and which is why this class of detection is hard to reason about from a rooted device
alone. If you want to be certain, you need the stock baseline — capture one *before* you root the
next device you build, which is why lab 01 Step 0 exists.
</details>

<details>
<summary>Q8, Q9 — the CA collision</summary>

The global namespace shows the original CA count plus one; the app's namespace shows the original
count. Your certificate is delivered by a bind mount, DenyList removes Magisk's bind mounts from the
target's namespace, and yours is one of them. Reinstalling the module cannot help, because the
module is fine — it is being unmounted *for that process*, after it was mounted correctly.

The options table, filled honestly:

| Option | Hiding | Interception | Cost |
|---|---|---|---|
| DenyList only | yes (mount-based checks) | **no** | free |
| CA module only | no | yes | free |
| Both | yes | **no** — they conflict | free, and does not work |
| CA module + Frida hook on TLS verification | partially, and Frida is itself detectable | yes | moderate; see [53-Frida](../../53-Frida/README.md) |
| DenyList + your own bind mount inside the app's namespace | yes | yes | moderate, fragile, and the subject of lab 05 |
| Different device / negotiated scope | n/a | n/a | a conversation, which is often cheaper than a week of hiding |

The row that people miss is the third: doing both does not give you both. That is the finding of
this lab.
</details>

<details>
<summary>Q12–Q14 — ordering</summary>

Both snapshots show the same (reduced) mount count, because the DenyList unmount happens in the
Zygisk specialise hook, which runs after `fork()` and before control returns to Java in the child.
By the time *any* of the app's own code runs — static initialiser, `attachBaseContext`, `onCreate` —
the unmount is already complete.

That is also the answer to "could the app measure earlier": no, not in Java, and not in a native
constructor either, because a native library is loaded by the app's own code, which is later still.
The only code that runs earlier belongs to zygote and to Zygisk itself.

Which is exactly why detection has moved away from "look at the mounts" toward "look at what cannot
be unmounted": the SELinux policy, the attestation chain, the shape of the namespace rather than its
contents. See [37-RootDetection](../../37-RootDetection/README.md) for the current catalogue.
</details>

---

## Success criteria

- [ ] You built and ran the probe app and it reports from both a static initialiser and `onCreate`
- [ ] You wrote down predictions **before** measuring, and recorded which ones were wrong
- [ ] You confirmed that `/proc/<pid>/mountinfo` and `nsenter` into the same namespace agree
- [ ] You established whether each app has its own mount namespace, by measurement
- [ ] You produced the complete list of mount points DenyList removed, grouped by category
- [ ] You checked for mounts present in the app's namespace but not the global one, and correctly
      attributed them to Android rather than Magisk
- [ ] You measured the cacerts count in both namespaces and can explain the difference in one
      sentence
- [ ] You filled in the "what DenyList does not touch" table entirely from your own measurements
- [ ] You determined whether `/data/adb` is distinguishable from a stock device by errno class
- [ ] You established when the unmount happens relative to the app's first line of code
- [ ] You can state why removing mounts is not the same as never having made them
- [ ] You wrote the two report paragraphs and deleted every unmeasured claim from them
- [ ] You answered Q1–Q15 in writing

---

## Next

[Lab 04 — Module supply-chain audit](lab-04-module-audit.md) changes role: you stop being the person
installing modules and become the person deciding whether a module is safe to install.

Then [Lab 05 — CTF: The invisible mount](lab-05-ctf-invisible-mount.md) turns everything you
measured here into an offensive technique. The answer to Q9's fifth row is the whole challenge, so
do not read lab 05 until you have written your own answer to it.
