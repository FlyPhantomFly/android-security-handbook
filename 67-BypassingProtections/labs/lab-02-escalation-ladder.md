# Lab 02 — The escalation ladder, end to end

> **Objective.** Build a detector. Defeat it. Harden it. Defeat it again. Four full rounds, each one
> written by you, so that you experience the adversarial back-and-forth rather than reading a list of
> tricks. By the end you will be able to predict where round five goes before you build it — and to
> explain why rounds one to four were all, in an important sense, the same round.

**Difficulty:** the core lab of this chapter
**Time:** 3–5 hours, best split across two sittings (rounds 1–2, then 3–4)
**Root required:** rounds 3 and 4 want frida-server. A no-root path is given for each.
**Chapter sections this exercises:** [README §2.4](../README.md#24-the-escalation-ladder-drawn),
[§3.1](../README.md#31-seam-1--the-input)–[§3.7](../README.md#37-why-the-verdict-is-usually-the-wrong-seam),
[§3.12](../README.md#312-timing-is-the-whole-game-init_array-jni_onload-and-why-attach-loses),
[§3.14](../README.md#314-the-escalation-ladder-round-by-round)

---

## Why this lab exists

You can read a table of detections and their bypasses in ten minutes. It will not stay with you,
because the table has no *causality*: it does not tell you why the third row exists, and the third
row exists because somebody defeated the second.

This lab makes you play both sides. You will write the detector, then take off that hat and defeat
it, then put the hat back on and close the hole you just used. The most valuable moments are the ones
where **your own defence surprises you** — where you close a hole and discover you have opened a
different one.

**You are attacking software you wrote, on a device you own.** That is the only configuration in
which any of this is appropriate. See [README §1.3](../README.md#13-scope-and-ethics-stated-once-and-precisely).

---

## Setup

### Step 0 — device identity

```bash
# host
adb devices -l && adb shell getprop ro.product.model && adb shell getprop ro.build.version.sdk
adb shell getenforce
```

Write it down. This lab was developed against **i9000S, Android 13 / API 33, arm64-v8a, Enforcing,
not rooted**. Where a step needs root or frida-server, the lab says so and gives the alternative.

### Step 1 — a scratch workspace

Everything you build in this lab lives **outside the repository**. Do not edit
`examples/guarded-app/` — you want a clean reference to diff against.

```bash
# host
mkdir -p /tmp/ch67-ladder && cd /tmp/ch67-ladder
export ANDROID_HOME=~/Android/Sdk
export SDK="$ANDROID_HOME"
export BT="$(ls -d $SDK/build-tools/* | sort -V | tail -1)"
export AJ="$(ls -d $SDK/platforms/*/android.jar | sort -V | tail -1)"
export NDKCC="$(ls -d $SDK/ndk/*/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android21-clang | tail -1)"
echo "$BT"; echo "$AJ"; echo "$NDKCC"
```

If `$NDKCC` is empty you can still do rounds 1 and 4-static; rounds 2 and 3 need a native tier and
the lab flags where.

### Step 2 — the build harness

Rather than re-deriving a build for each round, reuse the chapter's, which already handles the
Windows/Git-Bash path conversion, the throwaway signing key, and the OEM install fallback:

```bash
# host
cp "$OLDPWD"/67-BypassingProtections/examples/build.sh /tmp/ch67-ladder/build-ladder.sh 2>/dev/null \
  || cp ~/Android-Security-Handbook/67-BypassingProtections/examples/build.sh /tmp/ch67-ladder/build-ladder.sh
```

You will point it at a directory you create per round. Read the script's header once before you use
it; the "what this will not do for you" section saves an hour.

---

## Round 0 — no protection

Start from nothing so that every later round is a measurable delta.

Create `/tmp/ch67-ladder/round0/AndroidManifest.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.pentest.ch67.ladder">
    <application android:label="CH67 Ladder" android:extractNativeLibs="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

Create `/tmp/ch67-ladder/round0/MainActivity.java`:

```java
package com.pentest.ch67.ladder;

import android.app.Activity;
import android.graphics.Typeface;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public class MainActivity extends Activity {
    static final String TAG = "CH67Ladder";

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        TextView tv = new TextView(this);
        tv.setTypeface(Typeface.MONOSPACE);
        setContentView(tv);

        String out = secret();
        tv.setText(out);
        Log.i(TAG, "RESULT: " + out);
    }

    /** Round 0: no protection at all. */
    static String secret() {
        return "LADDER{r0_nothing_to_defeat}";
    }
}
```

Build and install:

```bash
# host
cd /tmp/ch67-ladder
OUTDIR=/tmp/ch67-ladder/out ./build-ladder.sh 2>/dev/null || true
# The chapter's build.sh expects its own directory names; for this lab it is
# simpler to call the tools directly. Do that once, as a function you reuse:
cat > /tmp/ch67-ladder/mk.sh <<'EOF'
#!/usr/bin/env bash
# Build one round of the ladder. Usage: ./mk.sh roundN [native]
set -u
R="$1"; NATIVE="${2:-}"
W="/tmp/ch67-ladder/out/$R"; rm -rf "$W"; mkdir -p "$W/src/com/pentest/ch67/ladder" "$W/classes"
p() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
BTB="$BT"; [ -x "$BTB/aapt2" ] || BTB="$BT"
cp /tmp/ch67-ladder/$R/*.java "$W/src/com/pentest/ch67/ladder/"
"$BT/aapt2" link -o "$(p "$W/base.apk")" -I "$(p "$AJ")" \
    --manifest "$(p "/tmp/ch67-ladder/$R/AndroidManifest.xml")" \
    --min-sdk-version 21 --target-sdk-version 33 || exit 1
javac --release 8 -nowarn -classpath "$(p "$AJ")" -d "$(p "$W/classes")" \
    "$W/src/com/pentest/ch67/ladder"/*.java 2>&1 | grep -vE 'obsolete|warning' || true
CF=(); while IFS= read -r f; do CF+=("$(p "$f")"); done < <(find "$W/classes" -name '*.class')
"$BT/d8" --lib "$(p "$AJ")" --min-api 21 --output "$(p "$W")" "${CF[@]}" || exit 1
HAVE=0
if [ -n "$NATIVE" ] && [ -n "${NDKCC:-}" ]; then
  mkdir -p "$W/lib/arm64-v8a"
  "$NDKCC" -shared -fPIC -O2 -Wall -Wextra -o "$W/lib/arm64-v8a/libladder.so" \
      /tmp/ch67-ladder/$R/native.c -llog || exit 1
  HAVE=1
fi
( cd "$W" && HAVE_NATIVE=$HAVE python3 -B -c "
import os, shutil, zipfile
shutil.copy('base.apk','unaligned.apk')
z=zipfile.ZipFile('unaligned.apk','a',zipfile.ZIP_DEFLATED)
z.write('classes.dex','classes.dex')
if os.environ.get('HAVE_NATIVE')=='1': z.write('lib/arm64-v8a/libladder.so','lib/arm64-v8a/libladder.so')
z.close()" ) || exit 1
KS=/tmp/ch67-ladder/out/ks
[ -f "$KS" ] || keytool -genkeypair -keystore "$(p "$KS")" -storepass android -keypass android \
    -alias l -dname "CN=CH67 Ladder" -validity 10000 -keyalg RSA -keysize 2048 >/dev/null 2>&1
"$BT/zipalign" -f -p 4 "$(p "$W/unaligned.apk")" "$(p "$W/a.apk")" || exit 1
"$BT/apksigner" sign --ks "$(p "$KS")" --ks-pass pass:android --key-pass pass:android \
    --out "$(p "$W/$R.apk")" "$(p "$W/a.apk")" 2>&1 | grep -v WARNING
echo "built $W/$R.apk"
EOF
chmod +x /tmp/ch67-ladder/mk.sh
```

```bash
# host
/tmp/ch67-ladder/mk.sh round0
adb install -r /tmp/ch67-ladder/out/round0/round0.apk
adb shell am start -n com.pentest.ch67.ladder/.MainActivity
adb logcat -d -s CH67Ladder:V | tail -3
```

**Q1.** Record the flag. Nothing was defeated; there was nothing to defeat. Why is it still worth
running this round?

---

## Round 1 — one Java check

### 1a. Build the detector

Copy round0 to round1 and add a check.

```bash
# host
cp -r /tmp/ch67-ladder/round0 /tmp/ch67-ladder/round1
```

Edit `/tmp/ch67-ladder/round1/MainActivity.java` — replace `secret()` and add the check:

```java
    static final String[] SU_PATHS = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/data/local/bin/su", "/data/adb/magisk"
    };

    /** Round 1: a single Java check. The textbook version. */
    static boolean isCompromised() {
        for (String p : SU_PATHS) {
            if (new java.io.File(p).exists()) {
                Log.w(TAG, "detected: " + p);
                return true;
            }
        }
        return false;
    }

    static String secret() {
        if (isCompromised()) { return "REFUSED (round 1 fired)"; }
        return "LADDER{r1_java_file_exists}";
    }
```

```bash
# host
/tmp/ch67-ladder/mk.sh round1
adb install -r /tmp/ch67-ladder/out/round1/round1.apk
adb shell am start -n com.pentest.ch67.ladder/.MainActivity
adb logcat -c; adb shell am force-stop com.pentest.ch67.ladder
adb shell am start -n com.pentest.ch67.ladder/.MainActivity; sleep 2
adb logcat -d -s CH67Ladder:V | tail -3
```

**Q2.** On an unrooted device this check does not fire and you get the flag. **That is a problem for
the lab, not for the app.** How will you demonstrate a bypass of a check that never fires? Think
before reading the hint — the answer is a technique you will use constantly.

### 1b. Make it fire

You need the check to fire honestly so that defeating it means something.

**With root:** you already have `su`, so it fires.

**Without root** — invert the check for the lab so it fires on a clean device. Change one line:

```java
        for (String p : SU_PATHS) {
            // LAB INVERSION: fire when the path is ABSENT, so the control is
            // exercised on a clean device. The mechanism under test -
            // File.exists() reaching libcore reaching libc - is identical.
            if (!new java.io.File(p).exists()) {
                Log.w(TAG, "detected (inverted): " + p);
                return true;
            }
        }
```

**Q3.** Is this inversion cheating? Argue both sides. What exactly is preserved, and what is not?

Rebuild, reinstall, confirm it refuses.

### 1c. Bypass it — seam 2, Java

```javascript
// /tmp/ch67-ladder/r1.js
// frida -U -f com.pentest.ch67.ladder -l r1.js --no-pause
'use strict';
Java.perform(function () {
    const F = Java.use('java.io.File');
    F.exists.implementation = function () {
        const p = this.getAbsolutePath();
        if (/\/su$|magisk/.test(p)) {
            console.log('[lie] exists("' + p + '") -> true');
            return true;      // inverted check: claim it IS there
        }
        return this.exists();
    };
});
```

**No frida?** Use seam 1 instead — create the files the check looks for. On an unrooted device you
cannot write to `/system`, but you can point the check somewhere writable: change `SU_PATHS` to
include `/data/local/tmp/su` and `adb shell touch /data/local/tmp/su`. The *mechanism* under test —
a path probe through `File.exists()` — is unchanged.

**Q4.** Which seam did each of those two bypasses attack? Which one would survive the developer
renaming `isCompromised()` to `a()`?

**Q5.** How many lines was the bypass? How long did it take? Write both numbers down; you are
building a cost curve.

---

## Round 2 — the check moves to native

You are now the developer. The Java hook was free. Close it.

### 2a. Harden

```bash
# host
cp -r /tmp/ch67-ladder/round1 /tmp/ch67-ladder/round2
```

Create `/tmp/ch67-ladder/round2/native.c`:

```c
#include <jni.h>
#include <sys/stat.h>
#include <string.h>
#include <android/log.h>

#define TAG "CH67Ladder"

static const char *SU_PATHS[] = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su",
    "/data/local/bin/su", "/data/adb/magisk", NULL
};

JNIEXPORT jboolean JNICALL
Java_com_pentest_ch67_ladder_MainActivity_nativeCompromised(JNIEnv *env, jclass c) {
    (void) env; (void) c;
    struct stat st;
    for (int i = 0; SU_PATHS[i]; i++) {
        /* LAB INVERSION, as in round 1: fire when ABSENT so the control is
           exercised on a clean device. The mechanism is identical. */
        if (stat(SU_PATHS[i], &st) != 0) {
            __android_log_print(ANDROID_LOG_WARN, TAG,
                                "native detected (inverted): %s", SU_PATHS[i]);
            return JNI_TRUE;
        }
    }
    return JNI_FALSE;
}
```

Edit `/tmp/ch67-ladder/round2/MainActivity.java`:

```java
    static { System.loadLibrary("ladder"); }
    static native boolean nativeCompromised();

    static String secret() {
        // BOTH tiers now. The Java one is left in place deliberately: a real
        // app rarely removes a check, it adds one.
        if (isCompromised() || nativeCompromised()) { return "REFUSED (round 2 fired)"; }
        return "LADDER{r2_native_stat}";
    }
```

```bash
# host
/tmp/ch67-ladder/mk.sh round2 native
adb install -r /tmp/ch67-ladder/out/round2/round2.apk
```

### 2b. Watch your round-1 bypass fail

Run `r1.js` against round 2.

**Q6.** What happens? Read the Frida console carefully — does your hook still fire? Does the app still
refuse? Describe the symptom in one sentence, and confirm that this is **exactly** the symptom described
in the header of
[`37-RootDetection/scripts/native-root-bypass.js`](../../37-RootDetection/scripts/native-root-bypass.js).

**Q7.** Why does hooking `java.io.File.exists()` have no effect on `stat()` in a `.so`? Draw the two
call paths and mark where they meet.

### 2c. Bypass — seam 2, libc

```javascript
// /tmp/ch67-ladder/r2.js
// frida -U -f com.pentest.ch67.ladder -l r2.js --no-pause
'use strict';

const SUSPECT = /(^|\/)su$|magisk/i;

function hookStat(name, argIndex) {
    const p = Module.findExportByName('libc.so', name);
    if (p === null) { console.log('[-] ' + name + ' not present'); return; }
    Interceptor.attach(p, {
        onEnter: function (args) {
            this.path = args[argIndex].readUtf8String();
            this.lie = SUSPECT.test(this.path || '');
        },
        onLeave: function (retval) {
            if (!this.lie) return;
            console.log('[lie] ' + name + '("' + this.path + '") -> success');
            retval.replace(0);          // inverted check: claim the file EXISTS
        }
    });
    console.log('[+] hooked ' + name);
}

// stat/lstat take the path at 0; the *at family takes a dirfd first, so the
// path is at 1. Getting this wrong reads garbage and is the classic bug.
['stat', 'stat64', 'lstat', 'lstat64', 'access', 'open', 'open64'].forEach(function (n) {
    hookStat(n, 0);
});
['newfstatat', 'fstatat', 'fstatat64', 'faccessat', 'openat'].forEach(function (n) {
    hookStat(n, 1);
});
```

**Q8.** Run it. Does it defeat **both** tiers, or only the native one? Why?

**Q9.** On a modern arm64 Android, which of the symbols in those two lists actually resolved? Add a
`console.log` for the ones that did not. What does the pattern tell you about which libc function
`stat()` compiles to?

**Q10.** How many lines was this bypass, and how long did it take? Add the point to your cost curve.

---

## Round 3 — anti-instrumentation, and the check moves to load time

You are the developer again. Two changes, because a competent developer makes them together: detect
the instrumentation, and run before it can be installed.

### 3a. Harden

```bash
# host
cp -r /tmp/ch67-ladder/round2 /tmp/ch67-ladder/round3
```

Replace `/tmp/ch67-ladder/round3/native.c` with:

```c
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <android/log.h>

#define TAG "CH67Ladder"
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

static int g_flag = 0;

static int maps_has(const char *needle) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, needle)) { fclose(f); return 1; }
    }
    fclose(f);
    return 0;
}

static int thread_named(const char *needle) {
    DIR *d = opendir("/proc/self/task");
    if (!d) return 0;
    struct dirent *e;
    int hit = 0;
    while (!hit && (e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char path[128], comm[64] = {0};
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", e->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        if (fgets(comm, sizeof(comm), f) && strstr(comm, needle)) hit = 1;
        fclose(f);
    }
    closedir(d);
    return hit;
}

static int port_open(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short) port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int rc = connect(fd, (struct sockaddr *) &sa, sizeof(sa));
    close(fd);
    return rc == 0;
}

/* Runs INSIDE dlopen(), before dlopen returns. */
__attribute__((constructor))
static void ctor(void) {
    if (maps_has("frida") || maps_has("gum-js") || maps_has("gadget")) {
        LOGW("ctor: injected mapping - refusing");
        g_flag = 1;
    }
}

/* Runs inside System.loadLibrary, before any of the app's Java sees us. */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;

    if (thread_named("gum-js") || thread_named("gmain")) {
        LOGW("JNI_OnLoad: instrumentation thread - aborting");
        abort();
    }
    if (port_open(27042)) {
        LOGW("JNI_OnLoad: 27042 open - aborting");
        abort();
    }
    return JNI_VERSION_1_6;
}

JNIEXPORT jboolean JNICALL
Java_com_pentest_ch67_ladder_MainActivity_nativeCompromised(JNIEnv *env, jclass c) {
    (void) env; (void) c;
    if (g_flag) return JNI_TRUE;
    struct stat st;
    static const char *P[] = { "/system/bin/su", "/system/xbin/su",
                               "/sbin/su", "/data/adb/magisk", NULL };
    for (int i = 0; P[i]; i++) {
        if (stat(P[i], &st) != 0) { return JNI_TRUE; }   /* lab inversion */
    }
    return JNI_FALSE;
}
```

```bash
# host
/tmp/ch67-ladder/mk.sh round3 native
adb install -r /tmp/ch67-ladder/out/round3/round3.apk
```

### 3b. Watch round 2's bypass fail — differently

```bash
# host — try ATTACHING, the way most people reach for first
adb shell am start -n com.pentest.ch67.ladder/.MainActivity
frida -U -n com.pentest.ch67.ladder -l /tmp/ch67-ladder/r2.js
```

**Q11.** What happens, and does your script get to run at all?

Now triage the death **before** you write anything:

```bash
# host
python3 -B 67-BypassingProtections/scripts/bypass-triage.py \
    -p com.pentest.ch67.ladder --postmortem
```

**Q12.** Quote the `reason`, `status`, lifecycle and deciding frame. Which of the two new checks
fired — the maps scan in the constructor, or one of the two in `JNI_OnLoad`? How do you know from
the evidence alone?

**No frida?** Fire the port check honestly instead, exactly as in lab 01:

```bash
# host
adb reverse tcp:27042 tcp:27042
adb shell am force-stop com.pentest.ch67.ladder
adb shell am start -n com.pentest.ch67.ladder/.MainActivity
python3 -B 67-BypassingProtections/scripts/bypass-triage.py -p com.pentest.ch67.ladder --postmortem
adb reverse --remove tcp:27042
```

### 3c. Bypass, part one — timing

```bash
# host — spawn, and get in front of the library load
frida -U -f com.pentest.ch67.ladder \
      -l 67-BypassingProtections/scripts/early-instrument.js \
      -l /tmp/ch67-ladder/r2.js --no-pause
```

**Q13.** Read the harness banner. Did it report `TIMING OK` or a `TIMING PROBLEM`? Then run
`ei.timeline()` in the REPL and paste the output. In milliseconds, how much time separates
`dlopen-enter` from `dlopen-leave`, and what ran in that gap?

**Q14.** The app still dies. Which check is killing you now, and why did spawning not fix it?

### 3d. Bypass, part two — seam 1, three times

This is the round's real lesson. Three of the new detections are defeated **without writing a single
hook**:

```bash
# host — 1. the port check: do not lie about the port, change it
adb shell "/data/local/tmp/frida-server -l 127.0.0.1:1337 --directory /data/local/tmp/.x &"

# host — 2 and 3. the maps scan and thread-name scan see the AGENT, whose path
# and thread names come from the server's --directory and build. Renaming the
# unpack directory removes the '/data/local/tmp/re.frida.server' string from
# /proc/self/maps.
frida -H 127.0.0.1:1337 -f com.pentest.ch67.ladder \
      -l 67-BypassingProtections/scripts/early-instrument.js \
      -l /tmp/ch67-ladder/r2.js --no-pause
```

**Q15.** Which of the three checks does the port change defeat? Which does `--directory` defeat?
Which one survives both, and why?

**Q16.** For the one that survives, write the seam-2 hook. You need to intercept the read of
`/proc/self/task/*/comm`. Which libc function does `opendir`/`readdir` use, and is hooking `fopen`
enough? (Try it and find out; the answer is more interesting than the guess.)

**Q17.** Update your cost curve. Round 3 cost you how long? Note **which part** of that time was the
first-time setup and which part would recur on a second app.

---

## Round 4 — inline syscalls and a self-checksum

You are the developer for the last time. Everything you have done so far was defeated by hooking a
symbol. Remove the symbols.

### 4a. Harden

```bash
# host
cp -r /tmp/ch67-ladder/round3 /tmp/ch67-ladder/round4
```

Add this to the top of `/tmp/ch67-ladder/round4/native.c` and use it in place of `stat`:

```c
#include <stdint.h>

/*
 * faccessat(AT_FDCWD, path, F_OK, 0) issued inline. No libc symbol is
 * involved, so nothing that hooks a symbol can see this call.
 *
 * arm64 Linux syscall convention: number in x8, arguments in x0..x5,
 * result in x0. __NR_faccessat is 48 on arm64.
 */
static long sys_faccessat_inline(const char *path) {
#if defined(__aarch64__)
    register long x8 __asm__("x8") = 48;
    register long x0 __asm__("x0") = -100;          /* AT_FDCWD */
    register long x1 __asm__("x1") = (long) path;
    register long x2 __asm__("x2") = 0;             /* F_OK */
    register long x3 __asm__("x3") = 0;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
                     : "memory", "cc");
    return x0;
#else
    /* Fall back to libc on other architectures; the lab targets arm64. */
    extern int faccessat(int, const char *, int, int);
    return faccessat(-100, path, 0, 0);
#endif
}
```

Replace the body of `Java_com_pentest_ch67_ladder_MainActivity_nativeCompromised` to call
`sys_faccessat_inline(P[i]) != 0` instead of `stat(...)`.

```bash
# host
/tmp/ch67-ladder/mk.sh round4 native
adb install -r /tmp/ch67-ladder/out/round4/round4.apk
```

### 4b. Watch every hook you have written stop working

```bash
# host
frida -H 127.0.0.1:1337 -f com.pentest.ch67.ladder \
      -l 67-BypassingProtections/scripts/early-instrument.js \
      -l /tmp/ch67-ladder/r2.js --no-pause
```

**Q18.** Your libc hooks report nothing for the path probes. The app still refuses. Confirm with
`frida-trace -U -f com.pentest.ch67.ladder -i 'stat*' -i '*faccessat*'` that the functions are
genuinely not being called. What does that prove?

**Q19.** Could you hook the *syscall* rather than the libc wrapper? Name two mechanisms that operate
at that level and say why neither is a Frida one-liner.

### 4c. Stop hooking

This is the decision the chapter is built around. Verify it against
[README §3.13](../README.md#313-when-to-stop-bypassing-and-go-static):

**Q20.** Go through the six "stop hooking" signals in §3.13. How many are now true? Which is the
decisive one?

Now do it three ways and compare.

**(i) Patch the binary.**

```bash
# host — find the comparison
llvm-objdump -d /tmp/ch67-ladder/out/round4/lib/arm64-v8a/libladder.so \
  | sed -n '/nativeCompromised/,/^$/p' | head -60
```

Find the `svc #0` and the branch that consumes `x0`. Patch the conditional (or `mov w0, #0` before
the return) with a hex editor, rebuild the APK, re-sign.

**Q21.** Did it work first time? If not, read
[18-ARM §5.4](../../18-ARM/README.md) and check whether the compiler inlined anything. **Verify at
the branch, not at the function you patched.**

**(ii) Read it and reimplement it.** The routine is ten lines of C. Write down what it checks, in
order, and what it returns. You now own the algorithm permanently and no bypass is required.

**Q22.** Which of (i) and (ii) would still be valid after the developer ships a new build? Which one
could a colleague reproduce from your report alone?

**(iii) Go around.** The flag is a string constant in the DEX.

```bash
# host
unzip -p /tmp/ch67-ladder/out/round4/round4.apk classes.dex | strings -a | grep LADDER
```

**Q23.** How long did (iii) take? What does that tell you about rounds 1 through 4?

---

## Round 5 — the developer stops playing

There is no code to write for this round; there is a design to understand.

Install and run the chapter's server-side example:

```bash
# host — terminal 1
python3 -B 67-BypassingProtections/examples/server-app/server.py

# host — terminal 2
adb reverse tcp:8767 tcp:8767
cd 67-BypassingProtections && OUTDIR=/tmp/ch67 ./examples/build.sh --install-server
adb shell am start -n com.pentest.ch67.server/.MainActivity
```

Tap **"Ask the server (honest report)"**, then **"Ask the server (forged clean report)"**.

**Q24.** Search the server app's APK for the secret, as you did in Q23. What do you find?

**Q25.** Read the server's log for the forged request. Did the forgery change the outcome? Read
`handle_unlock()` in [`server.py`](../examples/server-app/server.py) and explain **why not**, in one
sentence.

**Q26.** Write down every technique from rounds 1–4 and, for each, say what it would achieve against
this app. Be precise: "nothing" is a legitimate answer and appears more than once.

**Q27.** The server is not invulnerable. Name three attacks that *do* apply to it, and say which of
them `server.py` defends against and which it explicitly does not (its comments will tell you).

---

## The whole ladder, on one page

Fill this in from your own numbers before reading anyone's answers.

| Round | Detection | Seam you attacked | Lines of bypass | Your time | Would it survive a rebuild? |
|---|---|---|---|---|---|
| 1 | Java `File.exists` | | | | |
| 2 | native `stat` | | | | |
| 3 | maps + threads + port, at load time | | | | |
| 4 | inline `svc #0` | | | | |
| 5 | decision on the server | | | | |

**Q28.** Plot your times. Where is the discontinuity, and what happens at it?

**Q29.** Rounds 1 to 4 are described in the chapter as "all the same round". Argue for and against
that claim using your own numbers.

**Q30.** You are now the security architect. You have budget for exactly **one** of these five
rounds. Which do you build, and what do you say to the engineer who wants to build round 4?

---

## Hints

<details>
<summary>Hint 1 — Q2, a check that never fires</summary>

You have three options and you will use all three at different times:

1. **Get a device where it fires.** Correct, expensive, and not always available.
2. **Invert the check for the lab.** The mechanism under test — a path probe travelling
   `File.exists` → libcore → libc — is byte-for-byte the same code path whether you fire on presence
   or absence. What you lose is realism in the *signal*, not in the *mechanism*.
3. **Change the world so the check fires** — the `adb reverse tcp:27042` trick from lab 01. This is
   the best option when it is available, because nothing about the app is altered.

Recognising which of the three is available is a skill in itself.
</details>

<details>
<summary>Hint 2 — Q7, the two call paths</summary>

```
Java:   File.exists()
          -> UnixFileSystem.getBooleanAttributes
            -> BlockGuardOs.access
              -> Linux.access (JNI)
                -> libcore_io_Linux.cpp
                  -> bionic access()  ------+
                                            |
Native: stat("/system/xbin/su", &st) -------+---> kernel
```

They meet **in bionic**, not before. A hook on `java.io.File` sits at the very top of the first path
and is not on the second. A hook in libc is on both.
</details>

<details>
<summary>Hint 3 — Q9, which symbols resolve</summary>

On a modern arm64 bionic, `stat` and `lstat` are usually inline wrappers around `fstatat`, and the
symbol that actually exists and gets called is `newfstatat` (or `fstatat64` on 32-bit). `__xstat`
and `__lxstat` are glibc names and have **never** existed on Android.

The pattern: hook the `*at` family and you catch the classic names for free. Hook only the classic
names and you may catch nothing at all. This is exactly why chapter 37's script hooks both lists and
treats a missing symbol as information rather than as an error.
</details>

<details>
<summary>Hint 4 — Q14, why spawning was not enough</summary>

Spawning got you in front of `.init_array` and `JNI_OnLoad` — your libc hooks were installed before
the library loaded. But the checks in round 3 are not path probes; they look at
`/proc/self/maps`, `/proc/self/task/*/comm` and a TCP port, and they are looking for **you**.

Winning the race gets your hooks in. It does not make your agent invisible. Those are two different
problems, and conflating them is why people spawn, still die, and conclude spawning does not work.
</details>

<details>
<summary>Hint 5 — Q16, hooking the thread-name read</summary>

`opendir`/`readdir` do not go through `fopen`. `opendir` calls `open` with `O_DIRECTORY` and
`readdir` issues `getdents64`. Hooking `fopen` catches the read of each `comm` file but not the
enumeration of the task directory — so you can lie about a thread's name but not hide its existence,
which is usually enough here because the check reads the name.

Hook `fopen`/`open` on paths matching `/proc/self/task/\d+/comm` and rewrite the returned content, or
simpler: run the agent with renamed threads so there is nothing to find. The second is seam 1 and
costs nothing per app.
</details>

<details>
<summary>Hint 6 — Q19, hooking below libc</summary>

Two mechanisms exist and neither is a one-liner:

1. **`ptrace`-based syscall interception** (`PTRACE_SYSCALL`, or `strace` itself). It sees every
   syscall regardless of how it was issued — and it sets `TracerPid`, so any anti-debug check
   detects you immediately. You have traded one detection for another.
2. **seccomp-bpf with `SECCOMP_RET_TRACE`/`USER_NOTIF`**, which requires installing a filter on the
   process before it starts and a supervisor to handle the notifications. Powerful, and a
   multi-day engineering project rather than a script.

Frida's `Stalker` can also observe `svc` instructions by rewriting the instruction stream, at heavy
performance cost and with its own detectability profile. All three are the point at which "just hook
it" stops being the cheap answer — which is the lesson of round 4.
</details>

---

## Answers

<details>
<summary>Answers Q1–Q5 — rounds 0 and 1</summary>

**Q1.** Round 0 is the baseline. Without it you cannot say what "working" looks like, cannot detect a
poisoned result later, and cannot measure the cost of anything. It is the same discipline as lab 01's
step 2.

**Q3.** It is not cheating, and the reason matters. The **mechanism** under test is a path probe that
travels `File.exists` → libcore → `libcore_io_Linux.cpp` → bionic `access`/`faccessat` → kernel. That
path is identical whether the check fires on presence or on absence; your bypass hooks exactly the
same function and lies in exactly the same place.

What is **not** preserved is the realism of the *signal*: on a real rooted device the check would fire
because `su` exists, and a real bypass must also handle the mount table, the package list and the
properties. The inversion tests the plumbing, not the completeness of the detection.

State this in your notes. An honest lab says which half it is exercising.

**Q4.** The Frida hook is **seam 2** (the read). The `touch /data/local/tmp/su` variant is **seam 1**
(the input). Both survive renaming `isCompromised()` to `a()`, because neither refers to it — which
is the whole argument of [README §3.7](../README.md#37-why-the-verdict-is-usually-the-wrong-seam).

A hook on `isCompromised` itself, which most people write first, would break instantly.

**Q5.** Typically 8 lines and under five minutes. Record it; the curve is the point.
</details>

<details>
<summary>Answers Q6–Q10 — round 2</summary>

**Q6.** Your hook still fires — the console fills with `[lie] exists(...)` lines — and the app still
refuses. That combination is the single most misleading symptom in this discipline, because
everything *looks* like it is working. It is exactly the symptom
`37-RootDetection/scripts/native-root-bypass.js` describes in its header.

**Q7.** See Hint 2. The paths meet in bionic. A Java-level hook is not on the native path at all.

**Q8.** It defeats **both**, because libcore's `Linux.access` calls bionic's `access`, which is the
same function the native tier calls. That is why libc interposition is the default technique and the
Java hook is the convenience, not the other way round.

**Q9.** See Hint 3. Expect `newfstatat`, `faccessat`, `openat` to resolve; `__xstat`/`__lxstat` never
will. Treat a missing symbol as information.

**Q10.** Typically 30 lines and 15–30 minutes the first time, near zero afterwards because chapter
37 already ships the production version.
</details>

<details>
<summary>Answers Q11–Q17 — round 3</summary>

**Q11.** The app dies immediately and your script never gets to install anything useful — or Frida
reports that the process vanished during attach. Attaching cannot work here: `.init_array` and
`JNI_OnLoad` already ran.

**Q12.** `reason=5 (CRASH_NATIVE) status=6 (SIGABRT)`, lifecycle `NOTHING`, deciding frame
`libladder.so (JNI_OnLoad+N)`. It was one of the two `JNI_OnLoad` checks and **not** the constructor,
because the constructor sets `g_flag` and returns — it does not abort. The deciding frame naming
`JNI_OnLoad` rather than the constructor is the evidence.

That distinction is available from the tombstone alone, with no source and no reversing.

**Q13.** `TIMING OK` if you spawned. The `dlopen-enter` to `dlopen-leave` gap is typically a few
milliseconds, and what ran in that gap is the `.init_array` constructor — which is precisely why you
cannot hook a constructor by hooking `dlopen`.

**Q14.** The thread-name check or the port check, both in `JNI_OnLoad`. Spawning installed your hooks
in time; it did not make your agent invisible. Winning the race and being undetectable are two
different problems.

**Q15.** The port change (`-l 127.0.0.1:1337`) defeats the **port check**. `--directory` removes the
`re.frida.server` path from `/proc/self/maps`, defeating the **maps scan** in most configurations.
The **thread-name check** survives both, because the agent's thread names are compiled into the agent
and are not affected by either flag. Defeating it needs either a seam-2 hook on the `comm` reads or a
rebuilt agent — which is genuinely more expensive, and is why it appears in this round rather than
round 1.

**Q17.** Typically 20–40 minutes the first time; about a minute on a second app, because the setup
(a non-default port, a renamed directory, the early harness) is reusable.
</details>

<details>
<summary>Answers Q18–Q23 — round 4</summary>

**Q18.** It proves that the path probe is not going through libc at all. `frida-trace` shows zero
calls to `stat*`/`*faccessat*` from the app's own library while the check is demonstrably running.
There is no symbol to attach to; the syscall is issued inline.

**Q19.** See Hint 6: `ptrace`-based interception (which sets `TracerPid` and is therefore
self-defeating against an anti-debug check) and seccomp-bpf with `SECCOMP_RET_TRACE`/`USER_NOTIF`
(which needs a supervisor process and installation before the target starts). Frida's `Stalker` is a
third, at heavy cost.

**Q20.** Two are decisively true: *"the check uses inline syscalls with no libc symbol"* and *"each
round costs more than the last"*. The first is the decisive one — it is not a matter of effort, it is
that the technique category no longer applies.

**Q21.** Often not first time. `nativeCompromised` is small and the compiler may have inlined the
helper, so the copy you patched is called by nothing — the exact failure
[18-ARM §5.4](../../18-ARM/README.md) measured. Verify by running the app, not by re-reading the
patched bytes.

**Q22.** (ii), the reimplementation, survives a rebuild: it captures the algorithm, not an offset.
It is also the only one a colleague can reproduce from your report, because a patch is an offset into
one specific binary. This is what "static analysis buys the answer" means.

**Q23.** Seconds. And the point is uncomfortable: the flag was extractable by `strings` at every
round. Every bypass you wrote was defeating a control that protected something already reachable by
other means — which is [README §3.5](../README.md#35-seam-5--the-gated-code), seam 5, and it is why
"what was the control protecting?" is the first question in the severity checklist.
</details>

<details>
<summary>Answers Q24–Q30 — round 5 and the whole ladder</summary>

**Q24.** Nothing. The secret is not in the APK. It exists only in the server process on your machine.

**Q25.** The forgery changed nothing, because the self-report was **never load-bearing**. `server.py`
records it as telemetry and gates on a nonce it issued itself — something the client cannot forge,
hook or patch, because none of it runs on the client.

**Q26.** Round 1 hook: nothing. Round 2 libc interposition: nothing. Round 3 early instrumentation
and seam-1 configuration: nothing. Round 4 patch or reimplementation: nothing — there is no
algorithm on the client that produces the secret. Every technique still *works* in the sense that it
does what it says; none of them produces the flag.

**Q27.** Three that do apply: (a) replaying a captured successful response — defended against by the
single-use nonce, and `server.py` says so explicitly; (b) the endpoint requiring no authentication —
**not** defended against, and the code says so in a comment, because authentication is chapter 47's
subject; (c) the server trusting the client's self-report — deliberately not done, with a comment
explaining that doing so would move the decision back to the client in name only.

**Q28.** The discontinuity is between rounds 4 and 5. Rounds 1–4 cost you minutes, then tens of
minutes, then hours — an increasing but finite curve. Round 5 is not on the curve at all: no amount
of client-side effort produces the flag.

**Q29.** **For:** rounds 1–4 all end with you getting the flag; they differ only in how long it took,
and every one of them was defeated by the same person with the same tools in one sitting. The
developer's total investment across four rounds bought hours.
**Against:** the *kind* of work changed at round 4 — hooking stopped applying and static techniques
took over — and that shift genuinely locks out an attacker whose only skill is running public Frida
scripts. Against unattended fraud automation, that is a real filter.
Both are true. The chapter's position is that they are the same round *for the outcome* and different
rounds *for the cost*, and that a defender should be honest about which of those they are buying.

**Q30.** Build round 5. What you say to the engineer who wants round 4: *"Your work is good and it
buys us hours against a serious attacker and weeks against a scripted one. But it has no terminal
state — every round we add, they add one back, and the flag was extractable with `strings` the whole
time. Build the smallest client-side layer that feeds our telemetry, and spend the rest of the
quarter making the server send the data instead of a permission."*
</details>

---

## Success criteria

- [ ] You built all five rounds yourself, and each one was a delta on the previous
- [ ] You watched your round-1 bypass fail against round 2 and can explain the call paths
- [ ] You watched your round-2 bypass fail against round 3 for a **different** reason
- [ ] You triaged round 3's death from the exit record alone, before writing any bypass
- [ ] You defeated at least two of round 3's checks at seam 1, with no hook at all
- [ ] You reached the point in round 4 where hooking stopped applying, and recognised it as a
      decision rather than a failure
- [ ] You completed the ladder table with **your own** times and line counts
- [ ] You can explain why round 5 is not on the same curve
- [ ] You extracted the flag with `strings` and understand what that says about rounds 1–4

---

## Clean up

```bash
# host
adb uninstall com.pentest.ch67.ladder
adb uninstall com.pentest.ch67.server
adb reverse --remove-all
adb shell "pkill -f frida-server" 2>/dev/null
rm -rf /tmp/ch67-ladder
```

Everything you built lived outside the repository. Confirm:

```bash
# host — should print nothing
find 67-BypassingProtections -name '*.apk' -o -name '*.dex' -o -name '*.so' -o -name '*.class'
```

---

## Where to go next

- [Lab 03 — when to stop](lab-03-when-to-stop.md) turns round 4's decision into a rubric you can
  apply without having to reach exhaustion first.
- [Lab 04 — the CTF](lab-04-ctf-the-boolean-that-lied.md) is round 5 in miniature: a secret that is a
  dependency rather than a gate.
- [40-Obfuscation](../../40-Obfuscation/README.md) is the same ladder applied to code rather than to
  checks, and its packer section is where round 3 goes when the developer has a budget.
