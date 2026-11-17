# Lab 04 — CTF: Three Routes to One Secret

**Difficulty:** Advanced
**Time:** 3–6 hours
**Prerequisites:** [Lab 01](lab-01-first-contact-so.md),
[Lab 02](lab-02-dynamic-jni-recovery.md), [Lab 03](lab-03-jnienv-retyping.md),
[53-Frida §7](../../53-Frida/README.md#7-dynamic-analysis)

> **Provenance.** Ghidra **is** installed on the machine this chapter was written on (12.1.2 PUBLIC,
> Java 24.0.2) and was run headless against the chapter's own target, so the tool behaviour this lab
> relies on is **Measured**. Any decompiler listing quoted below as an *expected result* is
> **Illustrative** — it shows the shape to look for, not a capture from a specific binary, and
> your addresses and variable names will differ. Build the real target with
> [`../examples/build.sh`](../examples/build.sh) and check your findings against its source. See
> [the chapter's provenance statement](../README.md#read-this-before-you-read-anything-else-what-is-measured-here-and-what-is-not).

---

## The challenge

An app has a single field and a **Reveal** button. Enter the right passphrase and it prints a flag of
the form `GHIDRA{...}`.

The flag is not a string constant. It is derived from a key that the library holds, and the library
holds that key in a form designed to be annoying.

**Recover the flag three independent ways:**

| Route | Method | What it teaches |
|---|---|---|
| **A** | `strings` and pure command-line work | How much you get for nothing, and where that stops |
| **B** | Static analysis in Ghidra | How the algorithm works — the thing only static analysis gives you |
| **C** | Runtime instrumentation | How to get the answer without understanding the algorithm |

Then write the comparison: how long each took, what each told you that the others did not, and which
one you would use first on a real engagement and why.

---

## Rules

1. All three routes must actually be completed. Route C is the fastest and finding it first is fine —
   but you must still do A and B.
2. No brute force over the passphrase space.
3. For each route, you must be able to state **the exact point at which that route would have failed**
   if the developer had made one more design choice. Naming that choice is the deliverable.

---

## Building the challenge

### `vault.cpp`

```cpp
// Build for arm64-v8a with the NDK, stripped.
//
// Four deliberate design choices, each defeating a different naive approach:
//   1. Dynamic JNI registration    -> no Java_* symbols for nm to find
//   2. XOR-obfuscated key material -> `strings` finds nothing directly
//   3. Key derived, not stored     -> no plaintext key exists in the file
//   4. Flag computed from BOTH the key and the input -> forcing the check to
//      pass yields a flag, but not THE flag
#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>

#define TAG "LAB04"

// ---- obfuscated material -------------------------------------------------
//
// The passphrase and the key seed are stored XOR'd, so `strings` shows noise.
// Note that the XOR key itself must be present somewhere, which is the flaw
// this whole lab is about.

static const unsigned char kXorKey = 0x5C;

// "vault-master-2024" XOR 0x5C
static const unsigned char kSeedEnc[] = {
    0x2a, 0x3d, 0x39, 0x30, 0x28, 0x71, 0x31, 0x3f, 0x2f, 0x28, 0x3e, 0x2c,
    0x71, 0x6e, 0x6c, 0x6e, 0x68, 0x00
};

// "open-sesame-42" XOR 0x5C
static const unsigned char kPassEnc[] = {
    0x33, 0x39, 0x3a, 0x32, 0x71, 0x2f, 0x39, 0x2f, 0x3d, 0x31, 0x39, 0x71,
    0x68, 0x6e, 0x00
};

static void decode(const unsigned char *src, char *dst, size_t n) {
    for (size_t i = 0; i < n; i++) {
        dst[i] = (char) (src[i] ^ kXorKey);
    }
    dst[n] = 0;
}

// ---- the derived key -----------------------------------------------------
//
// Never stored as a constant. Computed on first use from the decoded seed.

static unsigned int g_key = 0;

static unsigned int derive_key(void) {
    if (g_key != 0) return g_key;

    char seed[32];
    decode(kSeedEnc, seed, sizeof(kSeedEnc) - 1);

    unsigned int acc = 0x811C9DC5u;              // FNV-1a offset basis
    for (size_t i = 0; i < strlen(seed); i++) {
        acc = (acc ^ (unsigned char) seed[i]) * 0x01000193u;
    }
    // Wipe the decoded seed from the stack.
    memset(seed, 0, sizeof(seed));

    g_key = acc;
    return g_key;
}

// ---- the implementations -------------------------------------------------

static jboolean impl_check(JNIEnv *env, jobject thiz, jstring pass) {
    const char *s = env->GetStringUTFChars(pass, nullptr);
    if (s == nullptr) return JNI_FALSE;

    char expected[32];
    decode(kPassEnc, expected, sizeof(kPassEnc) - 1);

    // Constant-time-ish comparison, so a timing side channel is not the route.
    int diff = (int) (strlen(s) ^ strlen(expected));
    for (size_t i = 0; i < strlen(expected) && i < strlen(s); i++) {
        diff |= (s[i] ^ expected[i]);
    }

    memset(expected, 0, sizeof(expected));
    env->ReleaseStringUTFChars(pass, s);
    return diff == 0 ? JNI_TRUE : JNI_FALSE;
}

static jstring impl_reveal(JNIEnv *env, jobject thiz, jstring pass) {
    if (!impl_check(env, thiz, pass)) {
        return env->NewStringUTF("denied");
    }

    const char *s = env->GetStringUTFChars(pass, nullptr);
    if (s == nullptr) return env->NewStringUTF("denied");

    // The flag depends on BOTH the derived key and the passphrase, so forcing
    // impl_check to return true with a wrong passphrase yields the wrong flag.
    unsigned int k = derive_key();
    unsigned int h = k;
    for (size_t i = 0; i < strlen(s); i++) {
        h = (h ^ (unsigned char) s[i]) * 0x01000193u;
    }
    env->ReleaseStringUTFChars(pass, s);

    char buf[64];
    snprintf(buf, sizeof(buf), "GHIDRA{%08x-%08x}", k, h);
    return env->NewStringUTF(buf);
}

static jint impl_version(JNIEnv *env, jobject thiz) {
    return 0x00020401;
}

// ---- dynamic registration ------------------------------------------------

static JNINativeMethod kMethods[] = {
    { "check",   "(Ljava/lang/String;)Z",                    (void *) impl_check   },
    { "reveal",  "(Ljava/lang/String;)Ljava/lang/String;",   (void *) impl_reveal  },
    { "version", "()I",                                      (void *) impl_version }
};

extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass c = env->FindClass("com/ghidralab/vault/Native");
    if (c == nullptr) return JNI_ERR;
    env->RegisterNatives(c, kMethods, 3);
    __android_log_print(ANDROID_LOG_INFO, TAG, "ready");
    return JNI_VERSION_1_6;
}
```

### `CMakeLists.txt`

```cmake
cmake_minimum_required(VERSION 3.22)
project(vault)
add_library(vault SHARED vault.cpp)
find_library(log-lib log)
target_link_libraries(vault ${log-lib})
set_target_properties(vault PROPERTIES LINK_FLAGS "-Wl,--strip-all")
```

### The Java side

```java
package com.ghidralab.vault;

public class Native {
    static { System.loadLibrary("vault"); }
    public native boolean check(String pass);
    public native String reveal(String pass);
    public native int version();
}
```

```java
package com.ghidralab.vault;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.*;

public class MainActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        final Native n = new Native();
        final EditText in = new EditText(this);
        in.setHint("passphrase");
        final TextView out = new TextView(this);
        Button go = new Button(this);
        go.setText("Reveal");
        go.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                out.setText(n.reveal(in.getText().toString()));
            }
        });
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.addView(in); root.addView(go); root.addView(out);
        setContentView(root);
    }
}
```

```bash
# host
./gradlew assembleRelease
adb install -r app/build/outputs/apk/release/app-release.apk
unzip -o -d raw app/build/outputs/apk/release/app-release.apk 'lib/*'
```

---

## Route A — command line only

**Budget yourself fifteen minutes. Stop when the budget runs out, whether or not you succeeded.**

```bash
# host
SO=raw/lib/arm64-v8a/libvault.so

strings -a -n 4 "$SO" | head -60
strings -a -n 4 "$SO" | grep -iE 'flag|key|pass|secret|GHIDRA'
readelf --dyn-syms "$SO" | grep ' Java_'
readelf --dyn-syms "$SO" | grep JNI_OnLoad
```

You will find the format string `GHIDRA{%08x-%08x}` and the log tag, and nothing else useful. The
passphrase and the seed are XOR-obfuscated, so they are not printable.

Now push further, still on the command line. The XOR key is a single byte, so you can brute-force all
256 possibilities over the whole file and look for printable runs:

```bash
# host — try every single-byte XOR key and look for plausible English
for k in $(seq 0 255); do
  python3 - "$SO" "$k" <<'PY'
import sys, re
data = open(sys.argv[1], 'rb').read()
k = int(sys.argv[2])
dec = bytes(b ^ k for b in data)
for m in re.finditer(rb'[\x20-\x7e]{10,}', dec):
    s = m.group().decode('ascii')
    if re.search(r'[aeiou]{1}.*[aeiou]{1}', s) and '-' in s:
        print(k, hex(k), m.start(), s)
PY
done | sort -u | head -40
```

**Record what you found and what you did not.** You should recover the passphrase and the seed string
this way. You will *not* recover the flag, because the flag is computed — and knowing that is Route
A's real lesson.

**The design choice that would have defeated Route A:** name it. (Hint: what if the XOR key were
derived rather than a constant, or the obfuscation were a real cipher?)

### If Route A gave you the passphrase

Enter it in the app. You now have the flag — but you do not know *why* it is that flag, and you could
not have produced it without the app. Routes B and C fix each of those, differently.

---

## Route B — static analysis

**Goal: produce the flag without running the app at all.** That is what static analysis uniquely
gives you.

### B1. Recover the registration table

```bash
# host
$GHIDRA_HOME/support/analyzeHeadless /tmp/lab04 Vault \
    -import raw/lib/arm64-v8a/libvault.so \
    -processor AARCH64:LE:64:v8A \
    -scriptPath "$(pwd)/../scripts" \
    -postScript RecoverRegisterNatives.py \
    -deleteProject
```

You should get three entries: `check`, `reveal`, `version`, each with an offset.

### B2. Read `impl_reveal`

Import the library into the GUI, import `jni_all.gdt`, apply the names, and set signatures:

```c
jstring jni_reveal(JNIEnv *env, jobject thiz, jstring pass)
```

Read it. Identify:

1. The call to `jni_check` (which you should also rename).
2. The call to `derive_key` — a function with no arguments that caches its result in a global.
3. The FNV-1a loop: `h = (h ^ c) * 0x01000193`.
4. The `snprintf` format string, which tells you the flag's exact shape and that it contains two
   32-bit values.

### B3. Recover the seed and the passphrase statically

Follow the data references in `decode`. You will find `kSeedEnc` and `kPassEnc` as byte arrays in
`.rodata`, and `kXorKey` as an immediate in the decode loop.

In Ghidra:
- Go to the array, select the bytes, and use *Data → Create Array* of `byte` to render them.
- Right-click → *Copy Special → Byte String* to get them out.

Or from the command line, once you know the addresses:

```bash
# host — dump the bytes at a file offset.Ghidra shows VIRTUAL
# addresses; convert to a file offset with readelf's program headers.
readelf -l "$SO" | head -20
xxd -s <file_offset> -l 32 "$SO"
```

### B4. Compute the flag by hand

Now reimplement the algorithm. You have everything:

```python
#!/usr/bin/env python3
# host — reproduce the flag with no device involved.
# Fill in the byte arrays you recovered from .rodata.

XOR = 0x5C

seed_enc = bytes([0x2a,0x3d,0x39,0x30,0x28,0x71,0x31,0x3f,0x2f,0x28,
                  0x3e,0x2c,0x71,0x6e,0x6c,0x6e,0x68])
pass_enc = bytes([0x33,0x39,0x3a,0x32,0x71,0x2f,0x39,0x2f,0x3d,0x31,
                  0x39,0x71,0x68,0x6e])

def dec(b):
    return bytes(x ^ XOR for x in b).decode()

def fnv1a(data, basis=0x811C9DC5):
    h = basis
    for c in data.encode():
        h = ((h ^ c) * 0x01000193) & 0xFFFFFFFF
    return h

seed = dec(seed_enc)
passphrase = dec(pass_enc)
print("seed       :", seed)
print("passphrase :", passphrase)

k = fnv1a(seed)
h = fnv1a(passphrase, basis=k)
print("flag       : GHIDRA{%08x-%08x}" % (k, h))
```

**This is the moment Route B pays off.** You produced the flag on a machine with no device attached,
from a file, and you can now produce the flag for *any* passphrase or *any* seed — because you
understand the algorithm rather than just having observed one output.

**The design choice that would have defeated Route B:** name it. (Consider: what if the seed came from
the server, or from the device's hardware keystore?)

---

## Route C — runtime

**Goal: get the flag without understanding any of the above.**

```bash
# host
adb shell cmd package compile -m verify -f com.ghidralab.vault
adb shell am force-stop com.ghidralab.vault
```

### C1. Recover the table at runtime

```bash
frida -U -f com.ghidralab.vault \
      -l ../../53-Frida/scripts/native-tracer.js --no-pause
```

```javascript
nat.table()
```

### C2. Force the check and observe

```javascript
// Frida REPL — make check() always succeed, and see what reveal() produces
Java.perform(function () {
  var N = Java.use("com.ghidralab.vault.Native");
  N.check.implementation = function (p) {
    console.log("[check] " + p + " -> forced true");
    return true;
  };
  N.reveal.implementation = function (p) {
    var r = this.reveal(p);
    console.log("[reveal] " + p + " -> " + r);
    return r;
  };
});
```

Type any passphrase and press Reveal. **You get a flag — but not the flag.** Explain why in one
sentence before continuing. (Look at `impl_reveal`: the second half of the flag depends on the
passphrase.)

### C3. Recover the derived key

The first half of the flag is `k`, the derived key, which does not depend on the passphrase. Get it
directly:

```javascript
// Frida REPL — hook derive_key by its offset from Route B, and read its return
const m = Process.findModuleByName("libvault.so");
Interceptor.attach(m.base.add(0x1234), {       // ← derive_key's offset
  onLeave(retval) {
    console.log("[derive_key] -> 0x" + retval.toInt32().toString(16));
  }
});
```

Or, if you would rather not find the offset, read the decoded strings as they are produced:

```javascript
// Frida REPL — catch the decoded seed and passphrase on the stack.
// `decode` writes plaintext into its dst buffer; hook its return.
Interceptor.attach(m.base.add(0x1100), {        // ← decode's offset
  onEnter(args) { this.dst = args[1]; },
  onLeave() {
    const s = this.dst.readCString();
    if (s && s.length > 3) console.log("[decode] -> " + s);
  }
});
```

That prints both the seed and the passphrase, in plaintext, as the library produces them. Enter the
real passphrase and you have the real flag.

### C4. Or: use the app as an oracle

The purest form of Route C. You do not need any offsets at all:

```javascript
// Frida REPL — call reveal() yourself with the passphrase Route A gave you
Java.perform(function () {
  var N = Java.use("com.ghidralab.vault.Native").$new();
  console.log(N.reveal("open-sesame-42"));
});
```

**The design choice that would have defeated Route C:** name it. (Consider: what if the process
detected instrumentation and refused to run? What would that actually cost the attacker — and is
"cost" the same as "prevented"?)

---

## The comparison

Fill this in. It is the actual deliverable of the lab.

| | Route A (strings) | Route B (Ghidra) | Route C (Frida) |
|---|---|---|---|
| Time taken | | | |
| Gave me the flag? | | | |
| Gave me the passphrase? | | | |
| Gave me the algorithm? | | | |
| Would work if the seed came from the server | | | |
| Would work if the key were in the TEE | | | |
| Would work with no device available | | | |
| Would work with anti-instrumentation present | | | |
| Effort to repeat on version 2 of the app | | | |

Then write three short paragraphs:

1. **Which route would you use first on a real engagement, and why?** (There is a defensible answer in
   both directions; what matters is that you argue from the *question you are trying to answer*.)
2. **What does static analysis give you that runtime never can?** Be specific — this is the argument
   for Ghidra existing at all.
3. **What does runtime give you that static analysis never can?** Same.

---

## Hints

<details>
<summary>Hint — Route A, my XOR brute force finds nothing</summary>

The heuristic in the sample script is deliberately crude. Loosen it: drop the vowel test, lower the
minimum run length to 8, and print everything for keys where the count of printable runs jumps. Or use
`xortool` if you have it. Or read the decode loop in Ghidra, which shows you the key directly —
that is Route B leaking into Route A, which is fine as long as you notice it happening.
</details>

<details>
<summary>Hint — Route B, I cannot find the byte arrays</summary>

Find `decode` (a tight loop doing `dst[i] = src[i] ^ imm`), then look at its callers. Each caller
passes a different `.rodata` address as `src`. Follow both.

If Ghidra has typed the arrays as strings and shows garbage, clear the data (`C`) and re-create it as
a byte array.
</details>

<details>
<summary>Hint — Route B, converting a virtual address to a file offset</summary>

```bash
readelf -l libvault.so
```

Find the `LOAD` segment containing your virtual address `V`. Then
`file_offset = V - segment_vaddr + segment_offset`. For a typical Ghidra image base of `0x100000`,
subtract that first.

Or just let Ghidra do it: select the bytes and *Copy Special → Byte String*.
</details>

<details>
<summary>Hint — Route C, nat.table() is empty</summary>

`RegisterNatives` fires inside `System.loadLibrary`, which runs in `Native`'s static initialiser. You
must spawn with `-f`, and the Activity must actually construct a `Native`. Press the button once.

See [53-Frida §7.4.4](../../53-Frida/README.md#744-failure-4--attaching-instead-of-spawning).
</details>

<details>
<summary>Hint — I forced check() true and got a flag that the app rejects</summary>

That is the intended lesson and it is worth sitting with. Read `impl_reveal` again: the second value
in the flag is `fnv1a(passphrase, basis=k)`. Forcing the gate open does not tell you the passphrase;
it tells you what the flag *would be* for whatever you typed.

The general principle: bypassing a check gets you past the check. It does not get you the data the
check was protecting, when that data depends on the thing being checked.
</details>

---

## Success criteria

- [ ] You recovered the flag by all three routes and they agree.
- [ ] You completed the comparison table with real times, not estimates.
- [ ] You named, for each route, the one design choice that would have defeated it.
- [ ] You can explain why forcing `check` to return true produces a flag but not *the* flag.
- [ ] You produced the flag from Route B with no device attached.
- [ ] You wrote the three comparison paragraphs.
- [ ] You can state which of the four defensive choices in this library actually raised the attacker's
      cost, and by roughly how much.

---

## The write-up

Finish by writing this as a finding, as you would for a client. It must contain:

1. The **mechanism**: the passphrase and the key seed are present in the binary in a trivially
   reversible encoding, and the flag derivation is entirely local.
2. The specific location: library, function offsets, and the `.rodata` addresses.
3. An honest assessment of each defensive measure — XOR obfuscation, dynamic registration, derived
   rather than stored key, stripping — in terms of *analyst hours added*, not in terms of
   "prevented".
4. A remediation that would actually change the outcome. It is not "use a stronger XOR". Think about
   where the seed and the derivation would have to live.

The fourth point is what separates a report from a stunt.

---

## Cleanup

```bash
adb shell cmd package compile --reset com.ghidralab.vault
adb shell am force-stop com.ghidralab.vault
adb uninstall com.ghidralab.vault
```
