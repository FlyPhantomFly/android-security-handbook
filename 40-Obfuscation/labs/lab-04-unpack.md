# Lab 04 — Unpack a Packed App

**Difficulty:** Advanced
**Time:** 3–4 hours
**Prerequisites:** [Lab 01](lab-01-obfuscation-triage.md),
[Chapter 40 §3.7](../README.md#37-packers-and-commercial-protectors) especially
[§3.7.3](../README.md#373-the-general-unpacking-methodology),
[12-DEX-Internals](../../12-DEX-Internals/README.md), [13-ART](../../13-ART/README.md),
[16-JNI](../../16-JNI/README.md), Frida, `jadx`, `apktool`

---

## Objective

Build a working packer — stub `Application`, encrypted DEX in `assets/`, `ClassLoader` surgery — and
then defeat it three ways:

1. **Hook the loader.** Catch the `ByteBuffer` at the moment of handover.
2. **Scan memory.** Carve the DEX out of the process's address space with header validation.
3. **Statically.** Find the key in the stub and decrypt the asset offline, with no device at all.

Then add anti-debug in `.init_array` and watch method 1 stop working until you fix your timing.

## Why this matters

Packers are the most intimidating protection to encounter and the most mechanically defeatable, and
understanding *why* both are true is the point of this lab.

Intimidating: `jadx` opens the APK and shows you forty meaningless classes. There is no code to read.
The app plainly works, so the code exists, but not anywhere you can see. People stall here for hours.

Mechanically defeatable: the packer must hand ART a complete, valid, **plaintext** DEX, because that
is the only thing ART can execute. That constraint is absolute and it is not negotiable by any amount
of cleverness on the vendor's side. Section 3.7.3 states the consequence as a mental model worth
memorising:

> **Unpacking is not code-breaking. It is TIMING.** The whole skill is choosing the moment at which
> the data you want is in its most complete, least protected state, and being present at that moment
> with a way to write it down. Everything else — the specific hook, the specific tool — is detail.

The second reason this matters is **shared fate**. A packer is a product, deployed identically across
thousands of applications. The first person to defeat it publishes a method; from then on every app
using that packer costs one command. A developer choosing a packer is buying a protection whose
lifetime is set by the most-targeted customer of that vendor, not by their own risk profile. That is
the single most useful thing you can tell a client who is evaluating one.

---

## Setup

You are building the packer yourself. There is no substitute: writing the `attachBaseContext`
gymnastics is what makes the runtime sequence in §3.7.1 stop being a diagram and start being something
you know.

The complete, buildable version is in [`../examples/PackerStub.java`](../examples/PackerStub.java) and [`../examples/pack.py`](../examples/pack.py). The essentials
follow so you can read them here.

### Part 1 — the payload app

Build a normal, unprotected app first. Use variant A from
[lab 01](lab-01-obfuscation-triage.md) — `MainActivity`, `ApiClient`, `Classifier` — but change its
`Application` class to something identifiable:

```java
package com.obflab.target;

import android.app.Application;
import android.util.Log;

public class RealApplication extends Application {
    @Override public void onCreate() {
        super.onCreate();
        Log.i("OBFLAB", "RealApplication.onCreate — the real app is running");
    }
}
```

Build it, then extract its `classes.dex`. **That file is what you are going to hide.**

```bash
# host
./gradlew assembleRelease
unzip -o app/build/outputs/apk/release/app-release.apk classes.dex -d payload/
ls -l payload/classes.dex
```

### Part 2 — encrypt the payload

```python
#!/usr/bin/env python3
# host — pack.py. Run from a scratch directory.
# Deliberately weak: a fixed XOR key, exactly like the low-tier packers whose
# behaviour this lab is teaching you to recognise.
import sys

KEY = bytes([0x5A, 0xA5, 0x3C, 0xC3, 0x17, 0x71, 0x2E, 0xE2])

data = open(sys.argv[1], "rb").read()
out = bytearray(len(data))
for i, b in enumerate(data):
    out[i] = b ^ KEY[i % len(KEY)]

# A short header the stub can sanity-check, so a corrupt asset fails loudly
# rather than producing a mysterious VerifyError. Real packers do the same.
blob = b"OBFP" + len(data).to_bytes(4, "little") + bytes(out)
open(sys.argv[2], "wb").write(blob)
print(f"packed {len(data)} bytes -> {sys.argv[2]} ({len(blob)} bytes)")
```

```bash
# host
python3 pack.py payload/classes.dex payload.dat
```

### Part 3 — the stub

A new, minimal Android project, package `com.obflab.target` (the **same** package — the stub
impersonates the app).

**`StubApplication.java`** — this is the whole packer.

```java
package com.obflab.stub;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;

import dalvik.system.InMemoryDexClassLoader;

/**
 * A minimal but genuine packer stub.
 *
 * Runtime sequence (chapter 40 section 3.7.1):
 *   1. ActivityThread.handleBindApplication instantiates THIS class, because
 *      the manifest's <application android:name> points here.
 *   2. attachBaseContext runs FIRST — before onCreate, before any Activity.
 *   3. We read the encrypted asset, decrypt it, and hand the plaintext DEX to
 *      an InMemoryDexClassLoader.
 *   4. We reflectively replace LoadedApk.mClassLoader so that all subsequent
 *      class resolution finds the real code.
 *   5. We instantiate the REAL Application (whose name we stashed in
 *      <meta-data>) and forward the lifecycle to it.
 *
 * Every one of those five steps is observable, and each is a place you can be
 * standing when the plaintext exists.
 */
public class StubApplication extends Application {

    private static final String TAG = "STUB";
    private static final String ASSET = "payload.dat";
    private static final String META_REAL_APP = "obflab.real.application";

    private static final byte[] KEY = {
        (byte) 0x5A, (byte) 0xA5, (byte) 0x3C, (byte) 0xC3,
        (byte) 0x17, (byte) 0x71, (byte) 0x2E, (byte) 0xE2
    };

    private Application realApplication;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        try {
            byte[] dex = decryptAsset(base);
            Log.i(TAG, "decrypted " + dex.length + " bytes of DEX");

            ClassLoader parent = base.getClassLoader();
            ClassLoader real = new InMemoryDexClassLoader(ByteBuffer.wrap(dex), parent);

            installClassLoader(base, real);
            startRealApplication(base, real);
        } catch (Throwable t) {
            Log.e(TAG, "unpack failed", t);
        }
    }

    private byte[] decryptAsset(Context ctx) throws Exception {
        InputStream in = ctx.getAssets().open(ASSET);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        in.close();

        byte[] blob = bos.toByteArray();
        if (blob.length < 8 || blob[0] != 'O' || blob[1] != 'B'
                || blob[2] != 'F' || blob[3] != 'P') {
            throw new IllegalStateException("bad payload header");
        }
        int len = (blob[4] & 0xFF) | ((blob[5] & 0xFF) << 8)
                | ((blob[6] & 0xFF) << 16) | ((blob[7] & 0xFF) << 24);

        byte[] dex = new byte[len];
        for (int i = 0; i < len; i++) {
            dex[i] = (byte) (blob[8 + i] ^ KEY[i % KEY.length]);
        }
        return dex;
    }

    /**
     * Replace the ClassLoader the framework will use for this app.
     *
     * ContextImpl -> LoadedApk (field mPackageInfo) -> mClassLoader.
     * The field names have been stable for many releases, but they are private
     * framework internals: a real packer probes several candidates and falls
     * back. See chapter section 4.3.
     */
    private void installClassLoader(Context base, ClassLoader real) throws Exception {
        Field mPackageInfo = base.getClass().getDeclaredField("mPackageInfo");
        mPackageInfo.setAccessible(true);
        Object loadedApk = mPackageInfo.get(base);

        Field mClassLoader = loadedApk.getClass().getDeclaredField("mClassLoader");
        mClassLoader.setAccessible(true);
        mClassLoader.set(loadedApk, real);

        Log.i(TAG, "mClassLoader replaced with " + real);
    }

    private void startRealApplication(Context base, ClassLoader real) throws Exception {
        ApplicationInfo ai = base.getPackageManager().getApplicationInfo(
                base.getPackageName(), PackageManager.GET_META_DATA);
        String realName = ai.metaData.getString(META_REAL_APP);
        if (realName == null) return;

        Class<?> c = real.loadClass(realName);
        realApplication = (Application) c.newInstance();

        // Application.attach(Context) is hidden; a real packer calls it
        // reflectively, and so do we.
        java.lang.reflect.Method attach =
                Application.class.getDeclaredMethod("attach", Context.class);
        attach.setAccessible(true);
        attach.invoke(realApplication, base);

        Log.i(TAG, "real Application instantiated: " + realName);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        if (realApplication != null) realApplication.onCreate();
    }
}
```

**Stub `AndroidManifest.xml`:**

```xml
<application
    android:name="com.obflab.stub.StubApplication"
    android:label="ObfLab">

    <!-- Where the ORIGINAL Application class name went. The packer MUST keep
         this somewhere, and that necessity is what makes it recoverable. -->
    <meta-data android:name="obflab.real.application"
               android:value="com.obflab.target.RealApplication" />

    <activity android:name="com.obflab.target.MainActivity" android:exported="true">
        <intent-filter>
            <action android:name="android.intent.action.MAIN" />
            <category android:name="android.intent.category.LAUNCHER" />
        </intent-filter>
    </activity>
</application>
```

Put `payload.dat` in `app/src/main/assets/`, build, and install:

```bash
# host
cp payload.dat app/src/main/assets/
./gradlew assembleRelease
adb install -r app/build/outputs/apk/release/app-release.apk
adb shell am start -n com.obflab.target/com.obflab.target.MainActivity
adb logcat -s STUB OBFLAB
```

You should see the stub log, then `RealApplication.onCreate`. If you do, you have a working packer.

---

## Steps

### Step 1 — Confirm it looks packed from the outside

```bash
# host
./../scripts/apk-obfuscation-triage.sh app-release.apk
jadx -d packed_jadx --no-res app-release.apk >/dev/null 2>&1
find packed_jadx/sources -name '*.java' | wc -l
```

**Q1.** Which of the §3.7.2 indicators does your own APK trigger? Which does it *not*, and what would
a commercial packer add that yours does not?

**Q2.** From `jadx` alone, find the name of the real `Application` class without looking at your own
source. Where is it, and why did you have to keep it there?

**Q3.** Someone hands you this APK cold. Estimate how long it takes to go from "opened it" to "know it
is packed". Now estimate the same for "know how it decrypts". Which of the two estimates is the one
that matters?

### Step 2 — Method 1: hook the loader

```bash
# host — SPAWN PAUSED. Not optional.
frida -U -f com.obflab.target -l ../scripts/frida-classloader-dump.js --pause
```

In the REPL, once you see "hooks installed":

```
%resume
```

Then:

```
cld.timeline()
cld.status()
cld.loaders()
```

**Q4.** Read the timeline. Write out the sequence of stages you observed, and match each to the prose
description in [§3.7.1](../README.md#371-how-a-packer-works-mechanically).

**Q5.** How many milliseconds elapsed between `attachBaseContext` starting and the
`InMemoryDexClassLoader` construction? Now answer the question that number exists to answer: could you
have attached (`frida -U -n`) in that window?

**Q6.** `cld.loaders()` before and after unpacking. What changed, and why does an entry with **no path**
tell you the load was in-memory?

```bash
# host
adb pull /data/local/tmp/dexdump
jadx -d unpacked_jadx dexdump/*.dex
find unpacked_jadx/sources -name '*.java' | head -20
```

**Q7.** Section 6.1 Phase 3 gives a success criterion for unpacking. State it, and confirm you have
met it. What specifically would you check in the manifest?

### Step 3 — Method 2: scan memory

Now pretend the loader hook did not work — because on a packer that builds the DEX in native code, it
will not.

```bash
# host — deliberately ATTACH, after the UI is up. Timing is the point.
adb shell am force-stop com.obflab.target
adb shell am start -n com.obflab.target/com.obflab.target.MainActivity
# wait for the Activity to be visible
frida -U -n com.obflab.target -l ../scripts/frida-dexdump-lite.js
```

```
dd.probe()
dd.sweep()
dd.stats()
```

**Q8.** How many raw `dex\n` magic hits did `probe()` find, and how many survived validation? List the
top three rejection reasons.

**Q9.** Which single header check eliminated the most false positives? Explain, from the DEX
specification, why that field is such a good filter.

**Q10.** `sweep()` found more than one valid DEX. Identify each one — which is the stub, which is the
payload, and which (if any) is a framework DEX? What distinguishes them at a glance?

**Q11.** Sweep too early — force-stop the app, start it, and sweep within the first half-second. What do
you get? Now sweep after the UI appears. State the general rule about timing in your own words.

**Q12.** `jadx` complains about a checksum on one of your carved files. Run `dd.repair()` and follow it.
Why is recomputing the Adler-32 and SHA-1 a legitimate thing to do rather than a cheat?

### Step 4 — Method 3: statically, with no device

Now do it with no phone at all, as you would for malware you refuse to run.

```bash
# host
unzip -o app-release.apk 'assets/*' -d packed_assets
ls -l packed_assets/assets/
xxd packed_assets/assets/payload.dat | head -3
```

**Q13.** The first four bytes are `OBFP`. What have you learned, and what is the *next* thing you look
for in the stub?

```bash
# host
jadx -d packed_jadx --no-res app-release.apk >/dev/null 2>&1
grep -rn 'payload.dat\|getAssets\|InMemoryDexClassLoader' packed_jadx/sources/
```

**Q14.** Find the key. Write the offline decryptor and produce a valid DEX.

```python
#!/usr/bin/env python3
# host — unpack.py
import sys
KEY = bytes([...])                       # recovered from the stub
blob = open(sys.argv[1], "rb").read()
assert blob[:4] == b"OBFP"
n = int.from_bytes(blob[4:8], "little")
body = blob[8:8+n]
open(sys.argv[2], "wb").write(bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(body)))
print("wrote", n, "bytes")
```

**Q15.** Verify your output is a real DEX before decompiling it. Which four header fields do you check,
and what are their expected values?

**Q16.** Compare the three methods on: time taken, generality to the *next* packed app you meet, and
robustness if the packer adds anti-debug. They do not rank the same way on all three.

### Step 5 — Add anti-debug and watch method 1 break

Add a native library to the stub whose `.init_array` kills the process when traced.

```c
/* app/src/main/cpp/protect.c */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <android/log.h>

#define TAG "PROTECT"

/* __attribute__((constructor)) puts a pointer to this function in .init_array,
 * which the dynamic linker calls during dlopen — BEFORE JNI_OnLoad and before
 * any Java code observes the library. That ordering is the whole point. */
__attribute__((constructor))
static void early_check(void) {
    __android_log_print(ANDROID_LOG_INFO, TAG, ".init_array running");

    /* 1. Is anyone already tracing us? */
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof line, f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int pid = atoi(line + 10);
                if (pid != 0) {
                    __android_log_print(ANDROID_LOG_ERROR, TAG,
                                        "traced by pid %d", pid);
                    fclose(f);
                    exit(1);
                }
            }
        }
        fclose(f);
    }

    /* 2. Claim the tracer slot for ourselves. If someone already has it,
     *    this fails, and that failure is itself the signal. */
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "PTRACE_TRACEME failed");
        exit(1);
    }
}
```

Load it at the very top of `attachBaseContext`, before the decryption:

```java
static { System.loadLibrary("protect"); }
```

Rebuild, reinstall, and re-run method 1 exactly as before.

**Q17.** What happens? At which point in `cld.timeline()` does the process die?

**Q18.** Set `cld.cfg.neutralisePtrace = true` before `%resume` and try again. Does it work? Which of
the two checks did that fix, and which did it not?

**Q19.** Write the hook that defeats the `/proc/self/status` check as well. Which layer do you hook,
and why is hooking `fopen` a better choice here than hooking `BufferedReader.readLine`?

**Q20.** Now try method 2 (memory scan) against the anti-debug build, attaching after the UI is up.
Does the anti-debug affect it? Explain why, in terms of *when* each technique operates.

**Q21.** A packer's `.init_array` check runs before `JNI_OnLoad`. Explain, mechanically, why hooking
`JNI_OnLoad` to catch the decryption is guaranteed to be too late, and name the two things you can hook
instead.

### Step 6 — Assess it

**Q22.** Price this packer for a developer. What did it cost to build and ship? What did it cost you,
the first time? What would it cost you the *second* time, against a different app using the same
packer?

**Q23.** Explain "shared fate" to a client evaluating a commercial packer, in three sentences.

---

## Hints

<details>
<summary>Hint — Q5, why attaching cannot work</summary>

Look at the timestamps in `cld.timeline()`. Everything from `attachBaseContext` to the
`InMemoryDexClassLoader` construction typically happens in single-digit or low-tens of milliseconds.
`frida -U -n` must find the process, enumerate the runtime, and install hooks — orders of magnitude
longer than that. The race is not close.
</details>

<details>
<summary>Hint — Q9, the decisive header field</summary>

`header_size` at offset 0x24 is fixed at 0x70 by the specification and has never changed for any DEX
version. Combined with `endian_tag` at 0x28 (`0x12345678`), that is 64 bits of known-constant value.
Random data matches by chance about once in four billion.
</details>

<details>
<summary>Hint — Q19, which layer to hook</summary>

The check is `fopen("/proc/self/status", ...)` in native code from `.init_array`. There is no Java
involved at all, so a `BufferedReader` hook cannot see it — the same structural point that
[37-RootDetection §3.12](../../37-RootDetection/README.md#312-native-stat--access-checks-that-bypass-java-hooks)
makes about Java-only bypasses.
</details>

---

## Solution

<details>
<summary>Answers Q1–Q3 — recognition</summary>

**Q1.** Your APK triggers: tiny `classes.dex` with very few classes; a large asset with entropy near
8.0; a foreign `<application android:name>`; and a `<meta-data>` holding a class name.

What a commercial packer adds that yours does not: a native library doing the decryption instead of
Java (so the key is not in the DEX at all); anti-debug in `.init_array`; encrypted or mangled
resources; multiple layers of loading; often method-level rather than whole-DEX protection; and
deliberate format abuse to break `apktool`. Yours is a teaching packer, and knowing exactly which
parts are missing is what makes it useful.

**Q2.** In the `<meta-data>` element, value `com.obflab.target.RealApplication`. `aapt2 dump xmltree`
or `apktool` shows it in seconds.

Why it has to be there: the stub must eventually instantiate the real `Application` and forward the
lifecycle to it. It can obfuscate the name, encrypt it, or compute it, but the name must be
*derivable* inside the process, and anything derivable inside the process is derivable by you. This is
the packer's version of the same constraint that makes string encryption defeatable.

**Q3.** "It is packed": under two minutes, from the file listing alone. "How it decrypts": anywhere
from ten minutes (Java stub, fixed key, as here) to days (native, obfuscated, anti-analysis).

The estimate that matters is the **first** one, because it decides your entire approach. Knowing it is
packed sends you to Phase 3 and stops you reading a stub. Knowing *how* it decrypts is optional —
methods 1 and 2 never require it, and that is exactly why they are preferred.
</details>

<details>
<summary>Answers Q4–Q7 — hooking the loader</summary>

**Q4.** The observed sequence, matched to §3.7.1:

| Timeline | §3.7.1 |
|---|---|
| `attachBaseContext on com.obflab.stub.StubApplication` | `handleBindApplication` instantiated the class named in the manifest — the stub |
| `System.loadLibrary(...)` / `dlopen ENTER` / `dlopen LEAVE` | the native runtime arriving; `.init_array` runs between those two lines |
| `InMemoryDexClassLoader(ByteBuffer)` + `[DUMP]` | **the handover** — plaintext DEX exists here |
| `reflective set of mClassLoader` | the `LoadedApk` surgery |
| `attachBaseContext returned` | the real `Application` has been instantiated; the app now runs normally |

**Q5.** Typically 5–40 ms on a modern device. No, you could not have attached in that window: `-n`
must locate the process, attach, enumerate the Java runtime and install hooks, which takes hundreds of
milliseconds at best. This is not a close race, and it is why every packer instruction in the chapter
says spawn-gate.

**Q6.** Before: one loader whose `DexPathList` names the base APK. After: an additional
`InMemoryDexClassLoader` whose element list has **no path**.

No path means the DEX was never a file. `InMemoryDexClassLoader` (API 26+) takes a `ByteBuffer`
directly, so there is nothing on disk to find afterwards — which is precisely why packers moved to it.
The compensating weakness is that there is a `ByteBuffer` right there in the constructor, and that is
what the hook takes.

**Q7.** The criterion: *`jadx` opens your dumped DEX and you can see classes whose names correspond to
the manifest's component names.* Until that is true you have not unpacked, you have merely dumped
something.

Specifically check that `com.obflab.target.MainActivity` — the activity named in the manifest — exists
in the dumped DEX. That is the closing of the loop between the two artefacts, and it rules out the
failure mode where you dumped the stub a second time and did not notice.
</details>

<details>
<summary>Answers Q8–Q12 — memory scanning</summary>

**Q8.** Typically 30–200 raw magic hits, of which two to four survive validation. Top rejection
reasons, in the usual order:

1. `header_size != 0x70` — the decisive filter.
2. `bad version bytes` — the four bytes matched but what follows is not `NNN\0`.
3. `file_size implausible` or `file_size exceeds mapping`.

**Q9.** `header_size` at offset 0x24. The DEX specification fixes it at 0x70 for every version ever
published, so it is a 32-bit known constant sitting at a known offset. Combined with `endian_tag` at
0x28 (`0x12345678`), that is 64 bits of fixed value, and random data satisfies both roughly once in
four billion. Meanwhile a genuine DEX satisfies them always, by definition.

That asymmetry — a check that costs nothing, never rejects a true positive, and rejects essentially
every false one — is what a good validator looks like. See
[12-DEX-Internals lab 04](../../12-DEX-Internals/labs/lab-04-ctf-the-lying-dex.md), which uses the
same check for the opposite purpose.

**Q10.** Distinguish by size and by `string_ids_size`, both of which `dd.stats()` prints:

- The **payload** is the large one with hundreds or thousands of strings, and it contains
  `MainActivity`.
- The **stub** is small with very few strings.
- Framework DEX may appear if you scanned file-backed mappings; it is excluded by default via
  `skipFileBacked`, which is why the default sweep is both faster and cleaner.

The one with the most strings is nearly always the real app. That heuristic holds up remarkably well.

**Q11.** Too early: you get the stub only, or nothing at all — the payload has not been decrypted yet.
After the UI appears: you get the payload.

The rule: **sweep at the moment the data is most complete and least protected.** For a whole-DEX
packer that is any time after the first Activity is visible. For a packer that decrypts lazily, per
class or per method, there is no single such moment, and the answer is to exercise more of the app and
sweep repeatedly — sweeps are deduplicated, so repeated sweeps accumulate coverage rather than
duplicating it.

**Q12.** Because the Adler-32 checksum and SHA-1 signature in the DEX header are **unkeyed integrity
fields**, not cryptographic signatures. Anyone can compute them; they exist to detect accidental
corruption, not tampering. The in-memory image legitimately differs from the on-disk original because
ART patches fields in place, so recomputing them restores a file that is *correct* rather than one
that is forged.

The APK's real signature — the one that is a security control — lives in the APK Signing Block and is
a different thing entirely. See [38-TamperDetection](../../38-TamperDetection/README.md).
</details>

<details>
<summary>Answers Q13–Q16 — static unpacking</summary>

**Q13.** You have learned there is a custom container format with a four-byte magic, which means the
stub must contain code that recognises `OBFP` — a string constant you can grep for, and a length field
you can locate. Next you look in the stub for: the asset filename, `getAssets().open`, the magic
comparison, and whatever loop or `Cipher` call follows. That chain leads to the key.

**Q14.** The key is a `byte[]` literal in `StubApplication`. In `jadx` it appears as a hex or decimal
array initialiser; in Smali as a `fill-array-data` payload. Recovered, the offline decryptor is ten
lines.

**Q15.** Check, in this order:

| Offset | Field | Expected |
|---|---|---|
| 0x00 | magic | `64 65 78 0a` then three ASCII digits then `00` |
| 0x24 | `header_size` | `0x70` |
| 0x28 | `endian_tag` | `0x12345678` |
| 0x20 | `file_size` | equal to the actual file length |

```bash
# host
xxd -l 16 unpacked.dex
python3 -c "
import struct,sys,os
d=open('unpacked.dex','rb').read()
print('magic     ', d[:8])
print('file_size ', struct.unpack_from('<I',d,0x20)[0], 'actual', len(d))
print('header    ', hex(struct.unpack_from('<I',d,0x24)[0]))
print('endian    ', hex(struct.unpack_from('<I',d,0x28)[0]))
print('classes   ', struct.unpack_from('<I',d,0x60)[0])
"
```

The `class_defs_size` at 0x60 is the final confirmation: if it reads in the hundreds rather than the
tens, you have the payload rather than the stub.

**Q16.**

| | Time (this app) | Generality to the next packer | Robustness to anti-debug |
|---|---|---|---|
| 1. Hook the loader | ~2 min | High — every packer must use *some* loader, though native ones bypass the Java constructors | **Low** — it runs during `attachBaseContext`, exactly when `.init_array` anti-debug fires |
| 2. Scan memory | ~3 min | **Highest** — depends on no symbol, no API, no name; only on ART needing a plaintext DEX | **High** — you attach afterwards, so the early checks have already passed |
| 3. Static | ~15 min | **Lowest** — every packer's key handling is different, and a native decryptor may be genuinely hard | **Highest** — no device involved at all |

They deliberately do not rank the same way. Method 1 gives the cleanest artefact and the most
information about the packer's structure; method 2 is the one that keeps working; method 3 is the one
you use when running the sample is unacceptable. Knowing which axis matters for the engagement in front
of you is the actual skill.
</details>

<details>
<summary>Answers Q17–Q21 — anti-debug</summary>

**Q17.** The process dies. In `cld.timeline()` you see `System.loadLibrary` and `dlopen ENTER`, then
nothing — no `dlopen LEAVE`, no `InMemoryDexClassLoader`. The gap between ENTER and the missing LEAVE
is exactly where `.init_array` ran, which is why the script logs both sides of `dlopen` rather than
just one.

**Q18.** It fixes the `PTRACE_TRACEME` check (call 2), because `Interceptor.replace` makes the call
return 0 as though it had succeeded. It does **not** fix the `/proc/self/status` `TracerPid` check
(call 1), which does not go through `ptrace` at all. Depending on which runs first you may see the
process die at the same point.

That partial success is the instructive part: neutralising the famous check is not the same as
neutralising the checks.

**Q19.** Hook `fopen`, or `open`/`openat` one level lower, in libc:

```javascript
// Frida REPL — return NULL for /proc/self/status so the TracerPid loop never runs.
// Better: substitute a clean copy, since a missing /proc/self/status is itself
// anomalous. Simplest correct version shown.
var f = Module.findExportByName("libc.so", "fopen");
if (f !== null) {
    Interceptor.attach(f, {
        onEnter: function (args) {
            this.p = null;
            try { this.p = args[0].readUtf8String(); } catch (e) { }
            this.deny = this.p === "/proc/self/status";
        },
        onLeave: function (retval) {
            if (this.deny) {
                console.log("[anti-debug] fopen(/proc/self/status) -> NULL");
                retval.replace(ptr(0));
            }
        }
    });
}
```

Why libc rather than `BufferedReader`: the check is in C, called from `.init_array`, and never enters
the ART runtime. There is no Java method for a Java hook to replace. This is the same structural fact
as
[37-RootDetection §3.12](../../37-RootDetection/README.md#312-native-stat--access-checks-that-bypass-java-hooks),
and meeting it in two different chapters is not a coincidence — it is the single most important
layering fact in Android instrumentation.

**Q20.** No effect at all. The anti-debug runs once, during `dlopen`, in the first tens of milliseconds
of the process. You attach minutes later, after the UI is up. There is nothing left to detect and
nothing left to run.

That is the generalisable insight: **anti-debug is a check at a moment, and a technique that operates
at a different moment is unaffected by it.** Method 2's robustness is not an accident of
implementation; it is a property of *when* it operates.

**Q21.** `.init_array` is an ELF section holding function pointers that the dynamic linker invokes
during `dlopen`, after relocations are applied and **before `dlopen` returns**. `JNI_OnLoad` is called
by the runtime *after* `dlopen` has returned. So by the time any hook on `JNI_OnLoad` could fire, every
`.init_array` constructor has already run to completion — and if one of them called `exit(1)`, your
process is already gone.

The two things to hook instead:

1. **`android_dlopen_ext`** (which `System.loadLibrary` ultimately calls) — you are then present on
   both sides of the `.init_array` execution and can install hooks in `onEnter`, before it runs.
2. **Frida's spawn gating** (`frida -f pkg --pause`) — you are attached before the process's first
   instruction, which is earlier than anything the app can do.

This single detail explains most "my Frida script never fired" confusion against packed apps.
</details>

<details>
<summary>Answers Q22–Q23 — assessment</summary>

**Q22.**

- **Cost to the developer:** one stub class, an asset, a build step. A commercial packer is a purchase
  order and a CI integration. Ongoing costs are real though: unreadable crash reports, broken
  profiling, incompatibility with some devices, and a hard dependency on a vendor.
- **Cost to you, first time:** two to fifteen minutes with the scripts in this chapter, and perhaps an
  hour if you had to work out the anti-debug from scratch.
- **Cost to you, second time, same packer:** **one command.** The dump script does not care which app
  it is pointed at.

That last row is the number that matters and the one developers consistently do not know.

**Q23.**

> A packer is a product deployed identically across thousands of applications, so its protection has a
> shared fate: the first analyst to defeat it publishes a general method, and from that point every
> application using it costs an attacker one command rather than a day. Your app's protection level is
> therefore set by the attention the vendor's most-targeted customer attracts, not by your own risk
> profile. Packing meaningfully raises the cost of *casual* analysis and automated bulk processing,
> which is a real benefit; it does not raise the cost for anyone who has already met that packer, and
> you should assume the population that matters has.
</details>

---

## Success criteria

- [ ] You built a working packer and confirmed the real `Application` runs behind the stub
- [ ] You identified which §3.7.2 indicators your APK triggers and which a commercial packer adds
- [ ] You recovered the real `Application` class name from the manifest and explained why it must exist
- [ ] You captured the DEX with the ClassLoader hook and read the full timeline
- [ ] You measured the `attachBaseContext`-to-handover window and can justify spawn-gating with a number
- [ ] You met Phase 3's success criterion by finding a manifest-named component in the dumped DEX
- [ ] You carved the DEX from memory and can state which header check does the most work, and why
- [ ] You demonstrated the too-early / too-late timing failure and stated the rule
- [ ] You repaired a carved DEX and can explain why recomputing its checksum is legitimate
- [ ] You unpacked statically with no device and validated four header fields
- [ ] You compared all three methods on time, generality and robustness, and explained the different rankings
- [ ] You added `.init_array` anti-debug and located the exact point of death in the timeline
- [ ] You defeated `PTRACE_TRACEME` and separately the `TracerPid` read, at the right layer
- [ ] You can explain why the memory scan is unaffected by anti-debug, in terms of timing
- [ ] You can explain mechanically why hooking `JNI_OnLoad` is always too late
- [ ] You priced the packer for a developer and can explain shared fate in three sentences

---

## Next

[Lab 05 — CTF: The Vault](lab-05-ctf-the-vault.md) stacks every technique in this chapter into one
target and asks you to run the whole methodology, in order, under time pressure.
