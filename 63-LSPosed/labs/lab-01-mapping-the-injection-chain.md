# Lab 01 — Mapping the injection chain

> **Difficulty:** Beginner → Intermediate
> **Time:** 60–90 minutes
> **Needs LSPosed installed?** **No.** This lab measures the *substrate* LSPosed sits on, and it is
> deliberately designed to be valuable on a device where LSPosed is absent — which is the situation
> most readers are actually in.
> **Needs root?** Sections 2–4 do. Sections 5–7 do **not**, and they are the ones that produce the
> results you can publish as detection signals.

---

## Objective

Answer four questions about the device in front of you, with evidence rather than assumption:

1. **What is the rooting stack, exactly?** Which implementation, which version, which `su` calling
   convention.
2. **Is Zygisk enabled?** LSPosed cannot exist without it, and the check most people run gives the
   wrong answer.
3. **What does the module store contain?**
4. **What can an ordinary application actually see of all this?** — which is a different question
   from what `adb shell` can see, and the one every published detection list gets wrong.

By the end you will have a posture block you can paste into a report's methodology section, and you
will have built a probe application that closes the one measurement gap this chapter could not close
on its own.

---

## Why this lab comes first

Every claim in chapter 63 is version- and configuration-gated. This repository has a documented case
where a device whose posture had not been established taught the exact *opposite* of the truth: a
modified system CA store made an API 24 trust rule appear not to exist at all.

The discipline is not paranoia. It is that **a measurement on an unidentified device is not a
measurement.** You will do this before every engagement for the rest of your career, so do it slowly
once.

---

## Setup

You need:

- A device or emulator you own, with `adb` working.
- Optionally root. If you have none, do sections 1 and 5–7; they still work and section 7 is the
  interesting one.
- This chapter's [`../scripts/lsposed-footprint.sh`](../scripts/lsposed-footprint.sh).
- Android Studio, or the SDK command-line tools, for section 6.

```bash
# host
cd 63-LSPosed/scripts
chmod +x lsposed-footprint.sh
adb devices -l
```

> **If more than one device is attached, pass `--serial` to everything.** A silent wrong-device
> attach is the worst kind of error, because every subsequent measurement is internally consistent
> and about the wrong target. This repository has a recorded case of `frida.get_usb_device()`
> returning an emulator while a phone was attached, and the whole corpus that came out of it was
> against the wrong machine.

---

## Section 1 — Identify the device

```bash
# host
adb -s <serial> shell getprop ro.product.model
adb -s <serial> shell getprop ro.build.version.release
adb -s <serial> shell getprop ro.build.version.sdk
adb -s <serial> shell getprop ro.product.cpu.abi
adb -s <serial> shell getprop ro.build.type
adb -s <serial> shell getprop ro.build.fingerprint
```

Write the answers down. Not in your head — in the file where the rest of this lab's output goes.

**Measured on the device used to write this chapter:**

```
ro.product.model      sdk_gphone16k_x86_64
ro.build.version.release  15
ro.build.version.sdk      35
ro.product.cpu.abi        x86_64
ro.build.type             userdebug
ro.build.fingerprint      google/sdk_gphone16k_x86_64/emu64xa16k:15/AE3A.240806.043/12960925:userdebug/dev-keys
```

Two things follow from that block alone, before any root check:

- **`userdebug`, not `user`.** A userdebug build has `ro.debuggable=1`, ships `su` in `/system/xbin`,
  and behaves differently from a retail phone in ways that will bite you. Note it.
- **`x86_64`.** Anything you build natively must match. This is an emulator, and chapter 39 measured
  that a modern AVD is *faster* than the reference phone, so "it felt slow, must be an emulator" is
  not a signal.

---

## Section 2 — Root, and the trap in it

Run **both** forms. This is not belt and braces.

```bash
# host
adb -s <serial> shell 'su -c id'
adb -s <serial> shell 'su 0 id'
```

**Measured:**

```
$ adb -e shell 'su -c id'
su: invalid uid/gid '-c'

$ adb -e shell 'su 0 id'
uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),... context=u:r:su:s0
```

The device is rooted. The first command says it is not, in a way that looks exactly like the message
an unrooted device produces if you are skimming.

> **The AOSP emulator's `su` takes a uid as its first argument.** `su 0 <command>` runs as root;
> `su -c <command>` is parsed as "run as the user named `-c`" and fails. Magisk's `su` on a physical
> device takes `-c`. A chapter in this repository nearly recorded a rooted emulator as unrooted on
> exactly this basis, and it is worth internalising because the same class of mistake — a tool
> failing for a reason unrelated to the thing you are testing — is most of what goes wrong in
> dynamic analysis.

**Task 2.1.** Which form works on your device? Record it. Every root command for the rest of this lab
uses it.

**Task 2.2.** Identify the implementation, not just the presence of `su`:

```bash
# host, adjusting the su form
adb -s <serial> shell 'su 0 sh -c "ls -d /data/adb/magisk /data/adb/ksu /data/adb/ap 2>/dev/null"'
adb -s <serial> shell 'su 0 sh -c "for c in /debug_ramdisk/magisk /sbin/magisk /data/adb/magisk/magisk; do [ -x \$c ] && echo FOUND \$c; done"'
```

**Measured:**

```
/data/adb/magisk
FOUND /debug_ramdisk/magisk
```

Note the discrepancy that is *not* a discrepancy: `/data/adb/magisk` **exists and is empty**, while
the actual binary lives in a tmpfs at `/debug_ramdisk/magisk`. Modern Magisk mounts its own tmpfs and
runs from there; `/data/adb/magisk` is a leftover directory. A detector looking for
`/data/adb/magisk/magisk` finds nothing on a fully rooted device.

**Task 2.3.** Version:

```bash
adb -s <serial> shell 'su 0 /debug_ramdisk/magisk -v'
adb -s <serial> shell 'su 0 /debug_ramdisk/magisk -V'
adb -s <serial> shell 'su 0 /debug_ramdisk/magisk --list'
```

**Measured:**

```
30.7:MAGISK:R
30700
su
resetprop
```

Magisk 30.7. **Zygisk requires Magisk 24 or later**, so on version alone this device could run
LSPosed. Section 3 asks whether it is actually turned on.

> **Note the applet list.** `magisk --list` printed `su` and `resetprop`. That is what the binary
> can be invoked as, not what is enabled. Do not read it as a feature list.

---

## Section 3 — Is Zygisk on? Two checks, because one is not enough

This is the section that teaches the most, because the obvious check is ambiguous.

**Check A — the settings database:**

```bash
adb -s <serial> shell 'su 0 /debug_ramdisk/magisk --sqlite "select * from settings"'
```

**Measured:**

```
key=bootloop|value=0
```

There is **no `zygisk` row at all**. Now: does that mean Zygisk is off?

**No. It means the default is in force.** An absent row is not a value. Reading "no row" as "off" is
a guess, and guesses have a way of becoming facts in a report.

**Check B — is a Zygisk library actually mapped into Zygote?**

```bash
adb -s <serial> shell 'su 0 sh -c "pidof zygote64"'
adb -s <serial> shell 'su 0 sh -c "grep -icE \"zygisk\" /proc/<pid>/maps"'
```

**Measured:**

```
1885
0
```

Zero. Nothing named `zygisk` is mapped into Zygote. Combined with the absent settings row, the
conclusion is safe: **Zygisk is off on this device, and therefore LSPosed cannot be running on it.**

> **Watch the quoting.** The inner pattern uses **double** quotes. Writing
> `grep -icE 'zygisk|magisk' ...` inside a `su 0 sh -c '...'` terminates the outer single quote
> early, and the device shell then reads `|` as a **pipe** — turning your grep into
> `grep -icE zygisk` piped into `magisk`. The error message that comes back is
> `magisk: inaccessible or not found`, which looks like a missing binary and is not. This exact bug
> occurred while writing `lsposed-footprint.sh` and is now a comment in its source.

**Task 3.1.** Run both checks on your device. If they disagree — a row saying `1` with no mapping, or
a mapping with no row — you have found something worth understanding before you go further.

**Task 3.2.** Predict, before you run it, what section 5's app-uid probe will show for
`/proc/self/maps`. Then check.

---

## Section 4 — The module store

```bash
adb -s <serial> shell 'su 0 sh -c "ls -la /data/adb/modules"'
adb -s <serial> shell 'su 0 sh -c "cat /data/adb/modules/*/module.prop 2>/dev/null"'
adb -s <serial> shell 'su 0 sh -c "ls -la /data/adb/"'
```

**Measured:**

```
total 16
drwxr-xr-x 2 root root 4096 ... .
drwx------ 6 root root 4096 ... ..
```

Empty. **No Magisk or Zygisk modules are installed**, which is consistent with Zygisk being off and
independently confirms that LSPosed is absent.

And the parent:

```
drwx------  6 root   root    4096 /data/adb
----------  1 root   root   40960 /data/adb/magisk.db
drwxr-xr-x  2 root   root    4096 /data/adb/magisk        <- empty
drwxr-xr-x  2 root   root    4096 /data/adb/modules       <- empty
drwxr-xr-x  2 root   root    4096 /data/adb/post-fs-data.d
drwxr-xr-x  2 root   root    4096 /data/adb/service.d
```

Note `/data/adb` is mode `0700` and owned by root. **No application can read it, ever.** Hold that
thought; section 7 is built on it.

**Task 4.1.** If LSPosed *were* installed, what would appear here? Predict, then check against
chapter §3.17's structural table. You should expect a Zygisk module directory and LSPosed's own
database and log.

---

## Section 5 — What `adb shell` sees, and why that is the wrong question

```bash
# host — note: NO su
adb -s <serial> shell id
for p in /data/adb /data/adb/modules /debug_ramdisk /debug_ramdisk/magisk /system/xbin/su; do
    printf '%-26s ' "$p"; adb -s <serial> shell "ls -ld $p"
done
adb -s <serial> shell 'grep -cE "magisk|zygisk" /proc/self/mountinfo'
```

**Measured:**

```
uid=2000(shell) gid=2000(shell) groups=... context=u:r:shell:s0

/data/adb                  ls: /data/adb: Permission denied
/data/adb/modules          ls: /data/adb/modules: Permission denied
/debug_ramdisk             drwx--x--x 3 root root 160 /debug_ramdisk
/debug_ramdisk/magisk      -rwxr-xr-x 1 root root 428416 /debug_ramdisk/magisk
/system/xbin/su            -rwsr-x--- 1 root shell 51224 /system/xbin/su
3
```

Now the important part. **`shell` is uid 2000 in the SELinux domain `u:r:shell:s0`. It is not an
app.** Chapter 60 quantified the difference: the `com.android.shell` package requests **200
permissions**, 183 granted at install and 16 runtime permissions pre-granted `SYSTEM_FIXED`. Chapter
39 measured (after correction) **~1,062 properties visible to root, ~678 to `shell` and ~638 to `untrusted_app`** on this same AVD.

Every published root-detection list you will read was written from `adb shell`. Most of them are
therefore describing a viewpoint no application has.

**Task 5.1.** `/system/xbin/su` is readable by `shell` and mode `4750 root:shell` — the
group is literally `shell`. Predict what an app uid sees. Then measure it in section 6.

---

## Section 6 — Build a probe that runs as an app

This is the section that makes the lab worth doing, because it closes the gap the chapter itself
could not close.

### 6.1 The intermediate step: `run-as`

If you have a **debuggable** third-party app on the device, `run-as` gets you closer:

```bash
adb -s <serial> shell 'run-as <your.debuggable.pkg> id'
```

**Measured:**

```
uid=10207(u0_a207) gid=10207(u0_a207) groups=... context=u:r:runas_app:s0:c207,c256,c512,c768
```

Look at that context. The uid and the MCS categories are an app's; the **domain is `runas_app`, not
`untrusted_app`**. It is a different SELinux domain with its own rules. Closer than `shell`, still
not an app.

Run the probe set through it:

```bash
RA="run-as <your.debuggable.pkg>"
for p in /data/adb /debug_ramdisk /debug_ramdisk/magisk /system/xbin/su; do
    printf '%-26s ' "$p"; adb -s <serial> shell "$RA ls -ld $p"
done
adb -s <serial> shell "$RA sh -c 'head -c 20 /debug_ramdisk/magisk | od -An -c'"
adb -s <serial> shell "$RA ls -la /debug_ramdisk"
adb -s <serial> shell "$RA sh -c 'grep -cE \"magisk|zygisk\" /proc/self/mountinfo'"
adb -s <serial> shell "$RA sh -c 'ls -l /sys/fs/selinux/policy; wc -c < /sys/fs/selinux/policy'"
```

**Measured, and every line of this is worth reading twice:**

```
/data/adb                  ls: /data/adb: Permission denied
/debug_ramdisk             drwx--x--x 3 root root 160 /debug_ramdisk
/debug_ramdisk/magisk      -rwxr-xr-x 1 root root 428416 /debug_ramdisk/magisk
/system/xbin/su            ls: /system/xbin/su: Permission denied

$ head -c 20 /debug_ramdisk/magisk | od -An -c
 177   E   L   F 002 001 001  \0  \0  \0  \0  \0  \0  \0  \0  \0
 003  \0   >  \0

$ ls -la /debug_ramdisk
ls: /debug_ramdisk: Permission denied

$ grep -cE 'magisk|zygisk' /proc/self/mountinfo
3

$ ls -l /sys/fs/selinux/policy
-r--r--r-- 1 root root 746805 /sys/fs/selinux/policy
$ wc -c < /sys/fs/selinux/policy
sh: can't open /sys/fs/selinux/policy: Permission denied
```

Five findings, and they contradict a lot of published advice:

| Finding | Why it matters |
|---|---|
| **`/debug_ramdisk/magisk` is readable from an app uid** — the ELF header came back — while **`ls /debug_ramdisk` is refused** | Mode `0711`: traverse, do not list. **Path-guessing beats directory listing.** A directory you cannot list is not a directory you cannot read from |
| `/system/xbin/su` gives `EACCES` to the app and `PRESENT` to `shell` | The file is `4750 root:shell`, and `shell` is in the group. An app is not. So `new File("/system/xbin/su").exists()` returns **false** on a rooted device |
| `/data/adb` gives `EACCES` | And a non-existent sibling gives `ENOENT` — the two *are* distinguishable at the syscall level, and `File.exists()` throws that distinction away |
| `/proc/self/mountinfo` shows **3** lines matching `magisk`, **2** of them by mount *source* | Readable by any uid, needs no permission, no path guessing. **The loudest signal on this device** |
| `/sys/fs/selinux/policy` is DAC `0444` and **SELinux refuses the read from an app** | Both layers must allow an operation. Chapter 60 captured the same shape with `adb_keys`: the group bit says yes, SELinux says no |

**Task 6.1.** Reproduce all five on your device. Any that differ are worth a note — a vendor build
changes these.

### 6.2 The real thing: a probe application

`run-as` is `runas_app`. A real app is `untrusted_app`. Build one.

Create a new Android Studio project, minimum SDK 27, one Activity, and put this in it. It writes
everything to `logcat` under the tag `CH63PROBE`.

```java
package com.pentest.ch63.probe;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;

public class ProbeActivity extends Activity {

    private static final String T = "CH63PROBE";

    private static final String[] PATHS = {
        "/data/adb", "/data/adb/modules", "/data/adb/lspd",
        "/debug_ramdisk", "/debug_ramdisk/magisk",
        "/system/xbin/su", "/system/bin/su", "/sbin/su",
        "/system/framework/XposedBridge.jar",
        "/sys/fs/selinux/policy",
        "/data/adb/definitely-not-here"          // the ENOENT control
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        Log.i(T, "uid=" + android.os.Process.myUid());

        // 1. exists() -- what a naive detector does
        for (String p : PATHS) {
            File f = new File(p);
            Log.i(T, String.format("exists  %-38s %s", p, f.exists()));
        }

        // 2. Can we actually READ it?  exists() and readable are different
        //    questions and the answer differs on /debug_ramdisk/magisk.
        for (String p : PATHS) {
            String verdict;
            FileInputStream in = null;
            try {
                in = new FileInputStream(p);
                byte[] head = new byte[4];
                int n = in.read(head);
                verdict = "READ " + n + " bytes, first=" + String.format("%02X", head[0]);
            } catch (Exception e) {
                verdict = e.getClass().getSimpleName() + ": " + e.getMessage();
            } finally {
                try { if (in != null) in.close(); } catch (Exception ignored) { }
            }
            Log.i(T, String.format("read    %-38s %s", p, verdict));
        }

        // 3. The signal that needs no permissions at all.
        try {
            BufferedReader r = new BufferedReader(new FileReader("/proc/self/mountinfo"));
            String line; int hits = 0;
            while ((line = r.readLine()) != null) {
                if (line.contains("magisk") || line.contains("zygisk")
                        || line.contains("lsposed")) {
                    hits++;
                    Log.i(T, "mountinfo " + line);
                }
            }
            r.close();
            Log.i(T, "mountinfo hits = " + hits);
        } catch (Exception e) {
            Log.i(T, "mountinfo unreadable: " + e);
        }

        // 4. Is a hooking framework in OUR process?  This is the check that
        //    actually distinguishes "installed on the device" from "hooking me".
        for (String c : new String[]{
                "de.robv.android.xposed.XposedBridge",
                "de.robv.android.xposed.XposedHelpers",
                "io.github.libxposed.api.XposedInterface"}) {
            try {
                Class.forName(c, false, getClassLoader());
                Log.w(T, "IN-PROCESS FRAMEWORK CLASS PRESENT: " + c);
            } catch (ClassNotFoundException expected) {
                Log.i(T, "absent (clean): " + c);
            }
        }

        // 5. Our own class loader chain.  A foreign loader names a module APK.
        ClassLoader cl = getClassLoader();
        int i = 0;
        while (cl != null && i++ < 16) {
            Log.i(T, "loader[" + i + "] " + cl);
            cl = cl.getParent();
        }
    }
}
```

Build, install, run, and read the log:

```bash
# host
adb -s <serial> install -r app-debug.apk
adb -s <serial> shell am start -n com.pentest.ch63.probe/.ProbeActivity
adb -s <serial> logcat -d -s CH63PROBE
```

> **If `adb install` fails with `INSTALL_FAILED_USER_RESTRICTED`** — a MIUI behaviour this
> repository has hit repeatedly — push the APK and install it as root instead:
> ```bash
> adb push app-debug.apk /data/local/tmp/probe.apk
> adb shell "su -c 'pm install -r /data/local/tmp/probe.apk'"   # or su 0 pm install -r ...
> ```
> `30-Activities/examples/build.sh` detects this exact failure and falls back automatically. Copy
> that function rather than re-deriving it.

**Task 6.2.** Compare the app's answers with the `run-as` answers from 6.1. Record every difference.
Two are likely and both matter:

- Does a genuine `untrusted_app` still read `/debug_ramdisk/magisk`?
- Does it still see the `mountinfo` lines?

**If the answers differ from `run-as`, the app is right and `run-as` was misleading you.** That is
the whole reason this section exists, and it is why chapter §3.17 labels its own `run-as` results as
indicative rather than final.

---

## Section 7 — What a naive detector would conclude

Run the whole thing through the chapter's script and read the last block:

```bash
# host
./lsposed-footprint.sh --serial <serial> --as-package <your.debuggable.pkg>
```

**Measured output, section 6 of the report:**

```
  PATH                                     ROOT       SHELL      APP
  ----                                     ----       -----      ---
  /data/adb                                PRESENT    EACCES     EACCES
  /data/adb/modules                        PRESENT    EACCES     EACCES
  /data/adb/lspd                           ENOENT     EACCES     EACCES
  /debug_ramdisk                           PRESENT    PRESENT    PRESENT
  /debug_ramdisk/magisk                    PRESENT    PRESENT    PRESENT
  /sbin/su                                 ENOENT     ENOENT     ENOENT
  /system/xbin/su                          PRESENT    PRESENT    EACCES
  /system/bin/su                           ENOENT     ENOENT     ENOENT
  /system/framework/XposedBridge.jar       ENOENT     ENOENT     ENOENT
```

Stare at the `/data/adb/lspd` row until it is uncomfortable.

**Root says `ENOENT` — LSPosed is genuinely not installed. Both unprivileged viewpoints say
`EACCES`,** because the refusal happens at `/data/adb`, above the leaf. `File.exists()` maps both to
`false`.

> **The most-copied LSPosed detection check in existence —
> `new File("/data/adb/lspd").exists()` — returns the same answer, `false`, whether or not LSPosed is
> installed.** It has zero discriminating power on a rooted device, which is the only kind of device
> where it could ever have mattered.

**Task 7.1.** Write down, in one sentence each, why each of these four published checks fails:

1. `new File("/data/adb/lspd").exists()`
2. `pm.getPackageInfo("org.lsposed.manager", 0)`
3. `new File("/system/framework/XposedBridge.jar").exists()`
4. `new File("/system/xbin/su").exists()`

Answers are in chapter §5.5, but write yours first.

**Task 7.2.** Now write down the one signal from this whole lab that an application with **zero
permissions** can read and that is not defeated by any of the above. Then say precisely what it
proves — and, more importantly, what it does *not* prove.

---

## Success criteria

You are done when you can produce, from your own device, a block like this and defend every line:

```
DEVICE     sdk_gphone16k_x86_64  Android 15 / API 35  x86_64  userdebug
ROOT       Magisk 30.7 (30700), binary /debug_ramdisk/magisk, su form: `su 0 <cmd>`
ZYGISK     OFF   (no settings row AND no mapping in zygote64 pid 1885)
MODULES    /data/adb/modules empty
LSPOSED    not installed (root: /data/adb/lspd ENOENT)
APP VIEW   /data/adb EACCES; /debug_ramdisk/magisk READABLE; mountinfo 3 magisk-matching lines (2 by source);
           /system/xbin/su EACCES (mode 4750 root:shell -- an app is not in the group)
CAVEAT     app-uid figures via run-as (domain runas_app, not untrusted_app) unless
           section 6.2's probe app was built, in which case say so
```

And when you can answer these without looking:

- [ ] Which `su` convention does your device take, and what does the wrong one look like?
- [ ] Why is an absent `zygisk` settings row not the same as Zygisk being off?
- [ ] Why can an app read `/debug_ramdisk/magisk` but not list `/debug_ramdisk`?
- [ ] Why does `new File("/system/xbin/su").exists()` return `false` from an app on a rooted device?
- [ ] Why is `run-as` not the same as an app, and what did you do about it?
- [ ] What does `/proc/self/mountinfo` prove, and what does it not prove?

---

## What you have not learned here

This lab measured the **substrate**. It has told you nothing about what LSPosed does once it is
running, because on the reference device it never was. Chapter §7.1 states that gap explicitly rather
than smoothing over it, and so should your notes.

If you have a device with Zygisk enabled and LSPosed installed, every structural claim in chapter
§3.17 becomes measurable and the numbers you get are better than the ones printed here. Write them
down. A measurement beats a citation.

---

## Next

[Lab 02 — Your first module, built offline](lab-02-your-first-module.md) builds the target
application this chapter's modules attack, and then builds a module, with no network connection at
any point.

---

| | |
|---|---|
| **Chapter** | [63-LSPosed](../README.md) — §3.17 footprint, §5.5 detection, §7.1 posture |
| **Script** | [`../scripts/lsposed-footprint.sh`](../scripts/lsposed-footprint.sh) |
| **See also** | [62-Magisk](../../62-Magisk/README.md) §3.9 DenyList · [37-RootDetection](../../37-RootDetection/README.md) · [22-SELinux](../../22-SELinux/README.md) for the DAC-versus-MAC result in section 6.1 |
