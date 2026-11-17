# Lab 04 — CTF: The Decoupled Check

**Difficulty:** CTF
**Time:** 3–5 hours
**Prerequisites:** [Lab 02](lab-02-native-check.md), [Lab 03](lab-03-trace-and-neutralise.md),
[Chapter 37 §9.3](../README.md#93-advanced--native-check-with-obfuscated-strings-and-no-java-surface),
[34-Cryptography](../../34-Cryptography/README.md), [57-Ghidra](../../57-Ghidra/README.md) or
[59-radare2](../../59-radare2/README.md)

---

## The challenge

You are given an APK. On a clean device it works: you tap **Unlock Vault** and it shows a flag. On your
rooted test device it shows:

```
Vault unavailable. Please check your connection and try again.
```

There is no root dialog. There is no "device not supported" message. Nothing in logcat mentions root,
Magisk, or security. Aeroplane mode makes no difference — the app never touches the network. Every
root-hiding tool you own changes nothing, and the tracer prints almost nothing interesting.

**Recover the flag on the rooted device, and explain the mechanism precisely enough that you could
implement it yourself.**

The flag has the form `ROOTLAB{...}`.

---

## Objective

Recognise, locate and defeat a root check whose **detection is decoupled from its consequence**: the
app notices root, does not react, and allows the observation to perturb a value that fails, silently
and generically, much later and somewhere else entirely.

## Why this matters

Every other lab in this chapter has given you a *signal*: a dialog, an exit, a score, a degraded
screen — something that happens close in time and space to the check, so that "find the check" and
"find the reaction" are nearly the same task.

Decoupling breaks that. It is described in
[§9.3](../README.md#93-advanced--native-check-with-obfuscated-strings-and-no-java-surface) as *"the
single most effective anti-tamper design pattern in this entire chapter, and almost nobody implements
it"*, and both halves of that sentence matter to you.

It is the most effective because it attacks your **methodology** rather than your tools. Your normal
loop is: observe the reaction, work backwards to the cause, neutralise the cause, verify the reaction
stops. Decoupling severs the link between reaction and cause, so working backwards leads you into a
crypto routine that is functioning perfectly and has nothing wrong with it. Testers can burn a full
day inside that routine.

Almost nobody implements it, which means when you *do* meet it you will not have seen it before, will
not recognise the shape, and will be under time pressure. Meeting it once here, deliberately, is the
entire value of this lab.

The developer's half is just as important. If you advise on client-side hardening at all, this is the
one pattern worth recommending — not because it cannot be beaten, but because it converts a
thirty-second bypass into a two-hour reverse-engineering task, and it does so without a single extra
check.

---

## Rules

- **No reading the flag from a clean device.** That works and teaches nothing.
- **No brute force** on the key or the flag.
- **No blanket `finish()`/`exit()` hooks.** There is nothing to block; the app does not exit.
- You must be able to explain, in terms of specific instructions or values, **why** your first three
  approaches failed.
- Solve it twice, by two different mechanisms. The comparison is where the learning is.

---

## Building the challenge

Build it yourself. Implementing the deception is half the education, and you cannot recognise the
pattern in the wild until you have written it once.

Start from your lab-02 project (package `com.rootlab.target`, NDK configured).

### Part 1 — the native check that returns a number, not a boolean

**`app/src/main/cpp/vault.c`**

```c
/*
 * vault.c — detection decoupled from consequence.
 *
 * Nothing here says "root". Nothing returns a boolean. The function's job,
 * as far as any caller can tell, is to produce a salt for key derivation.
 *
 * On a clean device it produces the correct salt.
 * On a rooted device it produces a different salt, and every downstream
 * operation fails with a generic error that has no relationship to root.
 */
#include <jni.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

/* ---- string obfuscation: nothing greppable in .rodata ------------------ */

static void deobf(const unsigned char *in, size_t n, char *out, unsigned char key) {
    for (size_t i = 0; i < n; i++) out[i] = (char) (in[i] ^ key);
    out[n] = '\0';
}

/* "/system/xbin/su"  XOR 0x5A */
static const unsigned char P0[] = {
    0x75,0x29,0x23,0x29,0x2e,0x3f,0x37,0x75,0x22,0x38,0x33,0x34,0x75,0x29,0x2f
};
/* "/system/bin/su"   XOR 0x5A */
static const unsigned char P1[] = {
    0x75,0x29,0x23,0x29,0x2e,0x3f,0x37,0x75,0x38,0x33,0x34,0x75,0x29,0x2f
};
/* "/data/adb/magisk" XOR 0x5A */
static const unsigned char P2[] = {
    0x75,0x3e,0x3b,0x2e,0x3b,0x75,0x3b,0x3e,0x38,0x75,0x37,0x3b,0x3d,0x33,0x29,0x31
};

/* ---- raw syscall: no libc symbol to intercept -------------------------- */

static int probe(const char *path) {
#if defined(__aarch64__)
    return (int) syscall(__NR_faccessat, AT_FDCWD, path, F_OK, 0);
#else
    return (int) syscall(__NR_access, path, F_OK);
#endif
}

/*
 * Returns the salt used for PBKDF2. The name, the signature and the return
 * type all say "key derivation". Nothing says "integrity".
 */
JNIEXPORT jint JNICALL
Java_com_rootlab_target_Vault_deriveSalt(JNIEnv *env, jclass clazz, jint base) {
    char buf[64];
    int dirty = 0;

    deobf(P0, sizeof P0, buf, 0x5A); if (probe(buf) == 0) dirty = 1;
    deobf(P1, sizeof P1, buf, 0x5A); if (probe(buf) == 0) dirty = 1;
    deobf(P2, sizeof P2, buf, 0x5A); if (probe(buf) == 0) dirty = 1;

    /* The consequence. One XOR, far from anything that looks like security. */
    return dirty ? (base ^ 0x5EED) : base;
}
```

Add it to `CMakeLists.txt`:

```cmake
add_library(vault SHARED vault.c)
target_link_libraries(vault ${log-lib})
```

### Part 2 — the crypto that consumes the salt

**`app/src/main/java/com/rootlab/target/Vault.java`**

```java
package com.rootlab.target;

import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Ordinary, correct, boring cryptography. There is no bug here, and that is
 * exactly why it wastes an analyst's afternoon: the code is not lying, it is
 * being lied TO.
 */
public final class Vault {

    static { System.loadLibrary("vault"); }

    /** Native. Looks like key derivation. Is also the root check. */
    private static native int deriveSalt(int base);

    private static final int SALT_BASE = 0x1234;

    // AES-128-CBC ciphertext of the flag, base64. Generate with the script below.
    private static final String BLOB =
        "REPLACE_ME_WITH_GENERATED_BASE64";

    private static final String IV_B64 = "REPLACE_ME_WITH_GENERATED_IV";

    public static String open() {
        try {
            int salt = deriveSalt(SALT_BASE);

            KeySpec spec = new PBEKeySpec(
                    "rootlab-vault".toCharArray(),
                    saltBytes(salt),
                    10000,
                    128);
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            SecretKeySpec key = new SecretKeySpec(f.generateSecret(spec).getEncoded(), "AES");

            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, key,
                   new IvParameterSpec(Base64.decode(IV_B64, Base64.NO_WRAP)));

            byte[] out = c.doFinal(Base64.decode(BLOB, Base64.NO_WRAP));
            String s = new String(out, StandardCharsets.UTF_8);

            // Sanity check, so a wrong key produces a clean failure rather
            // than mojibake on screen.
            if (!s.startsWith("ROOTLAB{")) return null;
            return s;

        } catch (Throwable t) {
            // Every failure path looks identical, and none of them mentions
            // root, integrity, or tampering.
            return null;
        }
    }

    private static byte[] saltBytes(int salt) {
        return new byte[] {
            (byte) (salt >>> 24), (byte) (salt >>> 16),
            (byte) (salt >>> 8),  (byte) salt,
            0x52, 0x4F, 0x4F, 0x54          // "ROOT" — a red herring, deliberately
        };
    }

    private Vault() { }
}
```

### Part 3 — the UI that says nothing useful

**`MainActivity.java`** — two screens, so the check and the failure are separated in *time* as well as
in code.

```java
package com.rootlab.target;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        final TextView tv = new TextView(this);
        tv.setTextSize(16f);
        tv.setPadding(32, 32, 32, 32);
        tv.setText("Welcome.");

        Button unlock = new Button(this);
        unlock.setText("Unlock Vault");
        unlock.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String s = Vault.open();
                tv.setText(s != null ? s
                    : "Vault unavailable. Please check your connection and try again.");
            }
        });

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24, 96, 24, 24);
        root.addView(tv);
        root.addView(unlock);
        setContentView(root);
    }
}
```

### Part 4 — generate the ciphertext

Run this **on the host**, with the *clean* salt, and paste the two base64 strings into `Vault.java`.

```python
#!/usr/bin/env python3
# host — make-blob.py. Produces BLOB and IV for Vault.java.
# Uses the CLEAN salt (dirty = 0), so decryption only succeeds when the
# native check finds nothing.
import base64, hashlib, os, struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SALT_BASE = 0x1234
FLAG = b"ROOTLAB{consequence_far_from_cause}"

salt = struct.pack(">I", SALT_BASE) + b"ROOT"
key  = hashlib.pbkdf2_hmac("sha1", b"rootlab-vault", salt, 10000, 16)

iv  = os.urandom(16)
pad = 16 - (len(FLAG) % 16)
pt  = FLAG + bytes([pad]) * pad

enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
ct  = enc.update(pt) + enc.finalize()

print("BLOB   =", base64.b64encode(ct).decode())
print("IV_B64 =", base64.b64encode(iv).decode())
```

> **Warning**
> Run this script from a scratch directory, not from inside the repository, and do not commit the
> generated `.pyc` or any build artefacts. The script writes nothing to disk by itself.

Build, install, verify:

```bash
# host
./gradlew assembleRelease
adb install -r app/build/outputs/apk/release/app-release.apk
adb shell am start -n com.rootlab.target/.MainActivity
# Tap "Unlock Vault" -> "Vault unavailable..."
```

If you have an unrooted device or a clean AVD, confirm the flag appears there. Then put that device
away; you are not allowed to use it again.

---

## Your first three attempts (all of which will fail)

Do these. Failing deliberately is faster than reading about failure.

### Attempt 1 — the reflex bypass

```bash
# host
frida -U -f com.rootlab.target \
      -l ../scripts/java-root-bypass.js \
      -l ../scripts/native-root-bypass.js --no-pause
```

**Q1.** Did the flag appear? Did `nrb.status()` report **any** denials at all? What does an empty
denial list tell you, and what are the three possible explanations for it?

### Attempt 2 — the tracer

```bash
# host
frida -U -f com.rootlab.target -l ../scripts/root-check-tracer.js --no-pause
```

**Q2.** How many `[J]` lines? How many `[N]` lines? Set `FILTER_NOISE = false` and try again — does
anything appear that mentions `su`?

**Q3.** The tracer instruments `access`, `stat`, `openat` and friends in libc. Given the C source in
Part 1, explain in one sentence why it sees nothing.

### Attempt 3 — work backwards from the error

Open the APK in JADX. Find the string
`Vault unavailable. Please check your connection and try again.` and follow it to its source.

**Q4.** Which method produces that string, and what is the immediate cause of it being shown?

**Q5.** Read `Vault.open()`. Is there a bug in the cryptography? Is the code doing anything it should
not? State precisely what is and is not wrong with it.

**Q6.** You are now inside a correct AES/PBKDF2 routine that is failing. Write down, before continuing,
the list of *inputs* to that routine and which of them you have verified. This list is the answer to
the lab.

---

## Investigation

### Step 1 — Enumerate the inputs, not the code

The decryption has exactly four inputs: the passphrase, the iteration count, the ciphertext, and the
**salt**. Three of them are constants visible in the DEX.

**Q7.** Which input is not a constant? Where does it come from?

**Q8.** `deriveSalt` is a `private static native int` taking an `int` and returning an `int`. Judging by
its name and signature alone, would you have flagged it during a routine review? What does that tell
you about naming as an anti-analysis technique?

### Step 2 — Watch the value

```javascript
// watch.js
Java.perform(function () {
    var V = Java.use("com.rootlab.target.Vault");
    // Note: private native methods are hookable exactly like any other.
    V.deriveSalt.implementation = function (base) {
        var r = this.deriveSalt(base);
        console.log("[salt] deriveSalt(0x" + base.toString(16) + ") -> 0x" + r.toString(16));
        return r;
    };
});
```

**Q9.** What does it return on your rooted device? What is `returned XOR base`, in hex, and why is that
number interesting on its own?

**Q10.** Force the function to return `base` unchanged. Does the flag appear? Write down the flag.

### Step 3 — Now do it without knowing the answer

Hooking the Java-declared native method was easy *because you had the source*. On a real target you
would not. Do it the hard way.

```bash
# host
unzip -o app-release.apk 'lib/arm64-v8a/*' -d libs/
readelf --dyn-syms libs/lib/arm64-v8a/libvault.so | grep -E 'Java_|UND '
strings -a libs/lib/arm64-v8a/libvault.so | grep -E '^/|su|magisk'
```

**Q11.** What do the strings show? What does the **imports** list show — specifically, is `access` or
`stat` there? What single imported symbol is the tell?

**Q12.** Open `libvault.so` in Ghidra. Find `Java_com_rootlab_target_Vault_deriveSalt`. Describe its
structure: how many calls, to what, and what is the last arithmetic operation before the return?

**Q13.** Recover the obfuscated strings statically. What XOR key is used, and how did you determine it
without running the app?

**Q14.** Patch the function so it always returns `base`. Give both the runtime `Memory.patchCode`
version and the on-disk byte patch, and state which instruction you are changing and why you chose that
one rather than the comparison.

### Step 4 — The `strace` route

Pretend you have no decompiler.

```bash
# adb shell as root
am force-stop com.rootlab.target
strace -f -o /data/local/tmp/v.log -e trace=faccessat,newfstatat,openat \
    -p $(pidof -s zygote64) &
am start -n com.rootlab.target/.MainActivity
# tap Unlock Vault
grep -n 'su\|magisk' /data/local/tmp/v.log
```

**Q15.** Does `strace` see the probe? At what moment in the app's lifecycle does it occur — process
start, activity creation, or the button tap? Why does the timing matter to how you would have
investigated?

**Q16.** `strace` proves a probe happened. It does not tell you what the app *did* with the answer.
Describe the technique you would use to follow the value from the syscall's return to the point where
it changes program behaviour.

---

## Hints

<details>
<summary>Hint 1 — you are looking in the wrong place</summary>

Stop looking for a check. Start looking for a **difference**. Something in this process behaves
differently on a rooted device than on a clean one, and the difference is not a boolean and not a
branch you can see.

Enumerate everything that flows into the failing operation and verify each one. One of them is not what
you assume it is.
</details>

<details>
<summary>Hint 2 — the tracer's blind spot is documented</summary>

Re-read the tracer's own header comment:

> *If you see NEITHER but the app still detects root, you are looking at inline syscall assembly —
> switch to strace and static patching.*

`syscall(__NR_faccessat, ...)` is one step short of inline assembly, and it produces exactly the same
symptom. The `syscall` symbol itself is hookable; the tracer does not instrument it, because
doing so requires branching on the syscall number to find the path argument.
</details>

<details>
<summary>Hint 3 — read the ARM, not the C</summary>

In `deriveSalt`, look for an `eor` (exclusive-or) instruction near the end of the function, or a
`csel`/`cinc` selecting between two values before the return. That single instruction is the entire
consequence of the check. Everything before it is theatre.
</details>

<details>
<summary>Hint 4 — recovering the XOR key statically</summary>

You know one plaintext: any of these paths starts with `/`, which is `0x2F`. The first byte of `P0` is
`0x75`. `0x75 ^ 0x2F = 0x5A`. Confirm by XORing the whole array with `0x5A` and reading the result.

Known-plaintext recovery of a single-byte XOR key is a two-minute job and it works far more often than
its simplicity suggests. See [40-Obfuscation](../../40-Obfuscation/README.md).
</details>

---

## Solutions

Do not read until you have made a genuine attempt.

<details>
<summary>Solution A — differential analysis on the value (the intended route)</summary>

The methodology, stated generally: **when the reaction is decoupled from the check, stop chasing the
reaction and start auditing the inputs.**

The failing operation is an AES decryption. Its inputs are the passphrase (constant), the iteration
count (constant), the ciphertext (constant), the IV (constant), and the salt (computed by a native
call). Four of five are visible in the DEX and identical on every device. The fifth is not.

```javascript
// solve-a.js — frida -U -f com.rootlab.target -l solve-a.js --no-pause
Java.perform(function () {
    var V = Java.use("com.rootlab.target.Vault");
    V.deriveSalt.implementation = function (base) {
        var real = this.deriveSalt(base);
        console.log("[salt] base=0x" + base.toString(16) +
                    " returned=0x" + real.toString(16) +
                    " delta=0x" + (real ^ base).toString(16));
        return base;                       // <- the fix: pass it through
    };
});
```

Output on a rooted device:

```
[salt] base=0x1234 returned=0x4cd9 delta=0x5eed
```

`delta = 0x5EED` — a *constant* delta, which is the giveaway. A key derivation that legitimately varied
would not differ by a fixed value; a fixed XOR delta means "one branch chose a different constant",
which is a decision, not a computation.

Returning `base` unchanged yields:

```
ROOTLAB{consequence_far_from_cause}
```

**Why the first three attempts failed:**

- The libc bypass denied nothing because the code never calls a libc path function — it calls
  `syscall()` directly, so `access` and `stat` are never entered.
- The tracer showed nothing for the same reason. Its instrumentation is a *list of symbols*, and the
  target avoided every symbol on the list.
- Working backwards from the error led into `Vault.open()`, which contains no bug. The code is correct
  and is being fed a wrong input. Debugging correct code is unbounded work, which is exactly the trap.
</details>

<details>
<summary>Solution B — static analysis and a binary patch (the route you would use on a real target)</summary>

Start where §6.4 says to start: imports.

```bash
# host
readelf --dyn-syms libs/lib/arm64-v8a/libvault.so | grep UND
```

There is no `access`, no `stat`, no `fopen`. There **is** `syscall`. A library whose only
filesystem-adjacent import is `syscall` is announcing that it deliberately avoided the wrappers, and
that is the finding before you read one instruction.

`strings -a libvault.so | grep '^/'` returns nothing, because the paths are XOR-obfuscated. Recover
them with known plaintext: every path starts with `/` (`0x2F`), the first stored byte is `0x75`, so the
key is `0x5A`.

```python
# host — scratch directory, not the repo
P0 = bytes([0x75,0x29,0x23,0x29,0x2e,0x3f,0x37,0x75,0x22,0x38,0x33,0x34,0x75,0x29,0x2f])
print(bytes(b ^ 0x5A for b in P0).decode())   # /system/xbin/su
```

In Ghidra, `Java_com_rootlab_target_Vault_deriveSalt` decompiles to roughly:

```c
int deriveSalt(JNIEnv *env, jclass c, int base) {
    char buf[64];
    int dirty = 0;
    deobf(P0, 15, buf, 0x5A);
    if (syscall(48, -100, buf, 0, 0) == 0) dirty = 1;
    /* ... twice more ... */
    return dirty ? (base ^ 0x5EED) : base;
}
```

The last arithmetic operation before the return is an `eor` against `#0x5EED`, usually selected by a
`csel`. That single instruction is the entire consequence.

**Which instruction to patch, and why.** Patch the *consequence*, not the check:

- Patching the `syscall` calls means three edits and depends on the compiler's layout.
- Patching the comparison means understanding the `csel`'s condition flags.
- Patching the function to `return base` is **one edit** and is correct regardless of what the check
  does.

Runtime version:

```javascript
// solve-b.js
var sym = Module.findExportByName("libvault.so",
              "Java_com_rootlab_target_Vault_deriveSalt");
if (sym === null) {
    console.log("[!] not mapped yet — hook android_dlopen_ext and retry from onLeave");
} else {
    // JNI signature: (JNIEnv*, jclass, jint) -> jint. The third argument is
    // `base`, in W2 on arm64. We want: MOV W0, W2 ; RET
    Memory.patchCode(sym, 8, function (code) {
        var w = new Arm64Writer(code, { pc: sym });
        w.putMovRegReg('w0', 'w2');
        w.putRet();
        w.flush();
    });
    console.log("[patch] deriveSalt now returns base unchanged");
}
```

On-disk version: assemble `MOV W0, W2` (`E0 03 02 2A`) and `RET` (`C0 03 5F D6`), write those eight
bytes at the function's file offset, repackage, `zipalign`, re-sign. Remember that re-signing changes
the APK signature and will trip anything in
[38-TamperDetection](../../38-TamperDetection/README.md) — on a real target you patch both or neither.
</details>

<details>
<summary>Solution C — the syscall hook (generic, and reusable forever)</summary>

If you would rather not patch, extend your instrumentation down one level. This is the version worth
keeping in your toolkit, because it generalises to every target that uses `syscall()`.

```javascript
// solve-c.js — deny path-probing syscalls made through syscall()
var NR = (Process.arch === 'arm64')
    ? { faccessat: 48, openat: 56, newfstatat: 79, readlinkat: 78 }
    : { faccessat: 334, openat: 322, fstatat64: 327, readlinkat: 332, access: 33 };

// Which syscall() parameter holds the path, per syscall number.
// syscall(nr, a0, a1, a2, ...) -> args[0]=nr, args[1]=a0, ...
var PATH_INDEX = {};
PATH_INDEX[NR.faccessat] = 2;      // faccessat(dirfd, path, mode, flags)
PATH_INDEX[NR.openat]    = 2;      // openat(dirfd, path, flags, mode)
if (NR.newfstatat) PATH_INDEX[NR.newfstatat] = 2;
if (NR.access)     PATH_INDEX[NR.access]     = 1;   // access(path, mode)

var BAD = /(^|\/)su$|magisk|busybox|\/data\/adb/i;
var p = Module.findExportByName("libc.so", "syscall");
if (p === null) {
    console.log("[!] no syscall symbol — the target is using inline asm; patch instead");
} else {
    Interceptor.attach(p, {
        onEnter: function (args) {
            this.deny = false;
            var nr = args[0].toInt32();
            var idx = PATH_INDEX[nr];
            if (idx === undefined) return;
            var path = null;
            try { path = args[idx].readUtf8String(); } catch (e) { return; }
            if (path !== null && BAD.test(path)) {
                console.log("[deny] syscall(" + nr + ', "' + path + '")');
                this.deny = true;
            }
        },
        onLeave: function (retval) {
            if (this.deny) retval.replace(ptr(-1));
        }
    });
    console.log("[*] syscall() filter installed");
}
```

Run it, tap Unlock Vault, and the flag appears — because `dirty` stays `0` and the salt is never
perturbed.

**Why this is the most valuable of the three solutions:** it is generic. Solutions A and B are specific
to this binary. This one covers any future target that calls `syscall()` to probe paths, which is the
next rung on the escalation ladder after libc interposition. Note the two things it must get right that
a libc hook does not: branching on the syscall **number**, and knowing that the path's argument index
**varies per syscall**, because each syscall has its own argument layout.

Note also its own limit, stated honestly: an app that emits `svc #0` inline has no `syscall` symbol
either, and then only patching remains.
</details>

<details>
<summary>Solution D — following the value with a watchpoint (when you cannot see the consequence)</summary>

The hardest variant is one where the perturbed value is stored in a struct and consumed thousands of
instructions later. Then neither reading the function nor hooking its return is enough — you need to
know *who reads it*.

Approach: hook the producing function, capture the address where the result is stored, and set a
hardware memory watchpoint (`MemoryAccessMonitor`, or a `Process.setExceptionHandler` on a page you
mark non-readable) so the next read traps and gives you a backtrace to the consumer.

That is heavier machinery than this lab needs and it is covered in
[68-ReverseEngineering](../../68-ReverseEngineering/README.md), but knowing it exists is the point:
when detection is decoupled from consequence, the general tool is **data-flow tracking**, not
control-flow tracking. Your instinct to look for branches is what the pattern defeats.
</details>

---

## Debrief questions

Answer in writing. They are the actual point of the lab.

1. Name the three specific properties of this check that defeated, respectively, the Java bypass, the
   libc bypass, and the tracer. Which one was the load-bearing design decision?
2. Your normal loop is "observe reaction → find cause → neutralise → verify". Write down the loop you
   used instead, in the same form. When would you reach for it?
3. `delta = 0x5EED` was a constant. Explain why a constant delta is diagnostic, and describe what the
   developer could have done to remove that tell.
4. The developer named the function `deriveSalt` and gave it a plausible signature. Estimate the cost
   of that decision to an attacker in minutes, and compare it with the cost of adding three more root
   checks.
5. You reported this app. Write the finding, in two sentences, to a developer who is proud of this
   design. Be accurate about what it bought them.
6. Now write the *other* finding: what would you say to the same developer about where the flag
   actually lives, and about the fact that a client-side decryption of a client-side blob protects
   nothing at all?
7. Rank solutions A, B and C by (a) speed on this target, (b) reusability against the next target,
   (c) robustness if the app also detected Frida.
8. This pattern is described as effective and rarely implemented. Give one plausible reason developers
   avoid it, drawn from what it would do to their own debugging.

---

## Success criteria

- [ ] You recovered the flag on a rooted device
- [ ] You solved it a **second** time by a different mechanism
- [ ] You ran the reflex bypass and the tracer first, and can explain precisely why each produced
      nothing
- [ ] You can state, in one sentence, why hooking `access` and `stat` did not help
- [ ] You enumerated the inputs to the failing operation instead of debugging the operation
- [ ] You identified the constant XOR delta and explained why a constant delta is diagnostic
- [ ] You recovered the obfuscated path strings **statically**, and can state the key-recovery method
- [ ] You located the consequence instruction in Ghidra and can name it
- [ ] You patched the function to return `base`, at runtime and (optionally) on disk
- [ ] You wrote a `syscall()` filter that branches on the syscall number and knows the per-syscall path
      index
- [ ] You confirmed the probe with `strace` and noted **when** in the lifecycle it occurs
- [ ] You can describe the data-flow technique for the harder variant where the value is consumed far
      away
- [ ] You answered all eight debrief questions in writing
- [ ] Your finding to the developer is accurate about what the design bought them — neither dismissive
      nor overstated

---

## Note for instructors

The pedagogical goal is **not** the flag. It is that participants experience their standard methodology
failing silently, and learn that the failure was methodological rather than tooling.

Run it in this order. Give participants only the APK, and do not tell them it is about root detection —
tell them "the vault does not open on this device, find out why". The most instructive twenty minutes
of the session are the ones where they are inside `Vault.open()` convinced the crypto is broken.

Bring them back with a single question: *"Is the code wrong, or is the code being lied to?"* That
question is the transferable skill, and it applies far beyond root detection — to licence checks, to
feature flags, to anything where a correct routine produces a wrong answer.

Participants who reach for Frida immediately should be required to also solve it statically, and vice
versa. The comparison in debrief question 7 is where the learning consolidates.

Finally, make sure the session ends on debrief question 6. The flag in this lab is decrypted on the
client from a blob shipped in the APK, which means that no matter how good the check is, the secret was
always on the attacker's device. That is the chapter's thesis restated as a concrete artefact, and it
is worth more than the bypass.
