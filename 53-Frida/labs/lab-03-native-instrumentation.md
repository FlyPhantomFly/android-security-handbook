# Lab 03 — Native Instrumentation

**Difficulty:** Advanced
**Time:** 3–5 hours
**Prerequisites:** [Lab 02](lab-02-four-failure-modes.md),
[Chapter 53 §7.5–§7.9](../README.md#75-interceptorattach-versus-interceptorreplace),
[15-Native-Code](../../15-Native-Code/README.md), [16-JNI](../../16-JNI/README.md),
[18-ARM](../../18-ARM/README.md)

---

## Objective

Take a stripped native library with dynamically registered JNI methods and, without a disassembler,
determine what it does. Specifically you will:

1. Recover the `RegisterNatives` table and map Java method names to `module+offset`.
2. Hook the recovered function and read its arguments through the JNI calling convention.
3. Hook the crypto primitives the library must call, and recover a key.
4. Call the function yourself with `NativeFunction`, turning it into an oracle.
5. Use `Stalker` block coverage to find the exact basic block that decides success or failure, and
   convert that into an offset you could open in [57-Ghidra](../../57-Ghidra/README.md).

Item 5 is the payoff. Coverage diffing is the technique that turns a hopeless binary into a
three-line answer.

---

## The target app

### `app/src/main/java/com/fridalab/native/Signer.java`

```java
package com.fridalab.nativelab;

public final class Signer {

    static {
        System.loadLibrary("signer");
    }

    // No `Java_com_fridalab_nativelab_Signer_*` symbol will exist for these:
    // JNI_OnLoad registers them dynamically.
    public native byte[] sign(byte[] payload);
    public native boolean verify(String license);
    public native String info();
}
```

### `app/src/main/cpp/signer.cpp`

```cpp
// Build with the NDK. CMakeLists.txt is below.
//
// Two deliberate design choices make this realistic:
//   1. RegisterNatives instead of Java_* naming, so `nm` reveals nothing.
//   2. The functions are `static`, so they are not exported at all.
#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define TAG "NATIVELAB"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

// Derived at runtime so it is not a plaintext constant in .rodata.
static unsigned char g_key[32];
static int g_key_ready = 0;

static void derive_key() {
    if (g_key_ready) return;
    const char *seed = "fridalab-seed-2024";
    for (int i = 0; i < 32; i++) {
        g_key[i] = (unsigned char)((seed[i % 18] * 31 + i * 17) & 0xff);
    }
    g_key_ready = 1;
}

static jbyteArray native_sign(JNIEnv *env, jobject thiz, jbyteArray payload) {
    derive_key();

    jsize len = env->GetArrayLength(payload);
    jbyte *buf = env->GetByteArrayElements(payload, nullptr);

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outLen = 0;

    // HMAC_Init_ex / HMAC_Update / HMAC_Final are EXPORTED by libcrypto.so
    // even though our own functions are not. That asymmetry is the lesson.
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, g_key, sizeof(g_key), EVP_sha256(), nullptr);
    HMAC_Update(ctx, (const unsigned char *)buf, (size_t)len);
    HMAC_Final(ctx, out, &outLen);
    HMAC_CTX_free(ctx);

    env->ReleaseByteArrayElements(payload, buf, JNI_ABORT);

    jbyteArray result = env->NewByteArray((jsize)outLen);
    env->SetByteArrayRegion(result, 0, (jsize)outLen, (const jbyte *)out);
    return result;
}

static jboolean native_verify(JNIEnv *env, jobject thiz, jstring license) {
    const char *s = env->GetStringUTFChars(license, nullptr);
    if (s == nullptr) return JNI_FALSE;

    // A deliberately branchy check, so Stalker coverage has something to show.
    int score = 0;
    size_t n = strlen(s);

    if (n == 19)                        score++;    // block A
    if (n > 3 && s[4] == '-')           score++;    // block B
    if (n > 9 && s[9] == '-')           score++;    // block C
    if (n > 14 && s[14] == '-')         score++;    // block D

    unsigned int acc = 0x5A17;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '-') continue;
        acc = (acc * 31u) ^ (unsigned int)(s[i] * 0x9E37u);
    }
    if ((acc & 0xffffu) == 0x4C3Bu)     score += 4;  // block E — the real check

    env->ReleaseStringUTFChars(license, s);
    LOGI("verify score=%d", score);
    return score >= 8 ? JNI_TRUE : JNI_FALSE;
}

static jstring native_info(JNIEnv *env, jobject thiz) {
    return env->NewStringUTF("signer v1.3");
}

// ---- dynamic registration -------------------------------------------------

static JNINativeMethod kMethods[] = {
    { "sign",   "([B)[B",                  (void *) native_sign },
    { "verify", "(Ljava/lang/String;)Z",   (void *) native_verify },
    { "info",   "()Ljava/lang/String;",    (void *) native_info }
};

extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;

    jclass c = env->FindClass("com/fridalab/nativelab/Signer");
    if (c == nullptr) return JNI_ERR;

    if (env->RegisterNatives(c, kMethods,
                             sizeof(kMethods) / sizeof(kMethods[0])) != JNI_OK) {
        return JNI_ERR;
    }
    LOGI("JNI_OnLoad: registered %zu methods",
         sizeof(kMethods) / sizeof(kMethods[0]));
    return JNI_VERSION_1_6;
}
```

### `app/src/main/cpp/CMakeLists.txt`

```cmake
cmake_minimum_required(VERSION 3.22)
project(signer)

add_library(signer SHARED signer.cpp)

find_library(log-lib log)
# Link against the NDK's prebuilt BoringSSL-compatible crypto if available;
# otherwise vendor a static libcrypto. The lab works either way — if HMAC is
# statically linked, part 3 becomes harder and more interesting.
target_link_libraries(signer ${log-lib} crypto)

# Strip symbols so `nm` gives you nothing useful.
set_target_properties(signer PROPERTIES LINK_FLAGS "-Wl,--strip-all")
```

### `MainActivity` — exercises all three

```java
package com.fridalab.nativelab;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.*;

public class MainActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        final Signer signer = new Signer();
        final EditText in = new EditText(this);
        in.setHint("licence key");
        final TextView out = new TextView(this);
        Button sign = new Button(this); sign.setText("Sign");
        Button check = new Button(this); check.setText("Verify");

        sign.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                byte[] sig = signer.sign("hello world".getBytes());
                StringBuilder sb = new StringBuilder();
                for (byte x : sig) sb.append(String.format("%02x", x));
                out.setText(sb.toString());
            }
        });
        check.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                out.setText(signer.verify(in.getText().toString()) ? "VALID" : "invalid");
            }
        });

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.addView(in); root.addView(sign); root.addView(check); root.addView(out);
        setContentView(root);
    }
}
```

```bash
# host
./gradlew assembleRelease
adb install -r app/build/outputs/apk/release/app-release.apk
```

---

## Steps

### Step 1 — Confirm that static analysis gives you nothing

```bash
# host
unzip -o -d raw app-release.apk
ls raw/lib/*/
nm -D --defined-only raw/lib/arm64-v8a/libsigner.so | grep "Java_"
# (empty)
nm -D --defined-only raw/lib/arm64-v8a/libsigner.so | head -20
readelf --dyn-syms raw/lib/arm64-v8a/libsigner.so | grep FUNC | head
```

You should find `JNI_OnLoad` and nothing else useful. Note that `native_sign`, `native_verify` and
`native_info` are `static` in C++ terms, so they are not in the dynamic symbol table at all.

Write down what a purely static analyst knows at this point: that the library exists, that it links
against `libcrypto`, and nothing about which Java method maps to which address.

### Step 2 — Recover the JNI table

```bash
# host — MUST spawn: RegisterNatives fires inside System.loadLibrary,
# which runs in Signer's static initialiser.
frida -U -f com.fridalab.nativelab -l ../scripts/native-tracer.js --no-pause
```

The script arms the `RegisterNatives` hook at load time. Press nothing; the table should print as the
Activity constructs `Signer`.

```javascript
// REPL
nat.table()
```

Expected output shape:

```
[jni] RegisterNatives  class=com.fridalab.nativelab.Signer  count=3
      sign([B)[B
        -> libsigner.so+0x3e40  (0x7b1a2c3e40)
      verify(Ljava/lang/String;)Z
        -> libsigner.so+0x3f10  (0x7b1a2c3f10)
      info()Ljava/lang/String;
        -> libsigner.so+0x4020  (0x7b1a2c4020)
```

**Record those offsets.** They are stable across runs (ASLR changes the base, not the offset), and
they are exactly what you would type into Ghidra's "Go To" box.

<details>
<summary>If no RegisterNatives symbol resolves on your device</summary>

The mangled name differs across ART Mainline versions. Fall back:

```javascript
nat.onload("libsigner.so")     // hook JNI_OnLoad, then inspect memory
```

From `JNI_OnLoad`'s `onEnter`, the `kMethods` array is a static in the library's `.data.rel.ro`. You
can find it by scanning the module for three consecutive pointer triples whose first two entries point
into `.rodata` and whose third points into `.text`. Write that scanner — it is a genuinely useful
exercise.
</details>

### Step 3 — Hook the recovered function and read JNI arguments

```javascript
// REPL
nat.jniHookAll()
```

Press **Sign**. Now write a targeted hook that understands the JNI convention:

```javascript
// jni-sign.js
Java.perform(function () {
  // Get the offset from step 2.
  var mod = Process.findModuleByName("libsigner.so");
  var signAddr = mod.base.add(0x3e40);           // ← YOUR offset

  Interceptor.attach(signAddr, {
    onEnter: function (args) {
      // JNI convention: args[0]=JNIEnv*, args[1]=jobject (this),
      // args[2]=first declared parameter (jbyteArray payload)
      this.env = args[0];
      this.payload = args[2];
      console.log("[sign] env=" + args[0] + " this=" + args[1] +
                  " payload=" + args[2]);

      // Read the jbyteArray THROUGH the Java bridge — much simpler than
      // decoding ART's array layout by hand.
      try {
        var arr = Java.cast(ptr(args[2]), Java.use("[B"));
        console.log("[sign] payload length = " + arr.length);
      } catch (e) {
        console.log("[sign] could not cast jbyteArray: " + e.message);
      }
    },
    onLeave: function (retval) {
      console.log("[sign] -> jbyteArray " + retval);
    }
  });
});
```

> **Note.** Reading a `jbyteArray` through raw memory requires knowing ART's array header layout,
> which differs across versions. Casting through the Java bridge is both easier and version-safe. This
> is a recurring theme: use the highest-level mechanism that answers your question.

### Step 4 — Recover the key from the crypto primitives

The library's own functions are stripped, but `libcrypto.so` exports `HMAC_Init_ex`, and the key is
its second argument.

```javascript
// hmac.js
'use strict';

function resolve(mod, name) {
  try {
    if (typeof Process.findModuleByName === 'function') {
      var m = Process.findModuleByName(mod);
      if (m !== null && typeof m.findExportByName === 'function') {
        var a = m.findExportByName(name);
        if (a !== null) return a;
      }
    }
  } catch (e) { /* fall through */ }
  try { return Module.findExportByName(mod, name); } catch (e) { return null; }
}

['libcrypto.so', 'libssl.so', 'libsigner.so'].forEach(function (lib) {
  var addr = resolve(lib, 'HMAC_Init_ex');
  if (addr === null) { console.log('[.] ' + lib + ' has no HMAC_Init_ex'); return; }

  Interceptor.attach(addr, {
    onEnter: function (args) {
      // int HMAC_Init_ex(HMAC_CTX*, const void* key, size_t len,
      //                  const EVP_MD*, ENGINE*)
      var keyPtr = args[1];
      var keyLen = args[2].toInt32();
      if (keyPtr.isNull() || keyLen <= 0 || keyLen > 1024) return;
      console.log('[HMAC_Init_ex] via ' + lib + '  key length = ' + keyLen);
      console.log(hexdump(keyPtr, { length: keyLen, ansi: false }));
    }
  });
  console.log('[+] hooked ' + lib + '!HMAC_Init_ex');
});
```

```bash
# host
frida -U -f com.fridalab.nativelab -l hmac.js --no-pause
```

Press **Sign**. You should see the 32 derived key bytes.

<details>
<summary>If HMAC is statically linked and no symbol exists</summary>

Then you have the realistic hard case. Two approaches:

1. Trace `libsigner.so`'s *imports* rather than exports:
   `Process.getModuleByName("libsigner.so").enumerateImports()` — if `HMAC_Init_ex` is imported, it is
   dynamic after all.
2. Use Stalker (step 6) to find the block that reads `g_key`, then set a memory watch on that address.

Record which case you are in — it changes the whole workflow, and that is worth knowing.
</details>

### Step 5 — Turn `verify` into an oracle with `NativeFunction`

Calling the native function directly lets you test thousands of candidate licences without touching
the UI. But `native_verify` takes a `JNIEnv*` and a `jstring`, so calling it raw is awkward. Two
routes:

**Route A — call the Java method, which is simplest and correct:**

```javascript
// oracle-java.js
Java.perform(function () {
  var Signer = Java.use("com.fridalab.nativelab.Signer");
  var s = Signer.$new();

  var candidates = ["AAAA-BBBB-CCCC-DDDD", "1234-5678-9012-3456", "TEST-TEST-TEST-TEST"];
  candidates.forEach(function (c) {
    console.log(c + " -> " + s.verify(c));
  });
});
```

**Route B — call the native function directly, which is the lesson:**

```javascript
// oracle-native.js
Java.perform(function () {
  var mod = Process.findModuleByName("libsigner.so");
  var verifyAddr = mod.base.add(0x3f10);        // ← YOUR offset

  // jboolean verify(JNIEnv*, jobject, jstring)
  var fn = new NativeFunction(verifyAddr, 'uint8',
                              ['pointer', 'pointer', 'pointer'],
                              { exceptions: 'propagate' });

  // We need a real JNIEnv* for the current thread and a real jstring.
  var env = Java.vm.getEnv();
  var Signer = Java.use("com.fridalab.nativelab.Signer");
  var instance = Signer.$new();

  function tryLicence(text) {
    var jstr = Java.use("java.lang.String").$new(text);
    try {
      // .$h is the handle (a jobject) of a Java wrapper object.
      var r = fn(env.handle, instance.$h, jstr.$h);
      return r !== 0;
    } catch (e) {
      console.log("[-] native call failed: " + e.message);
      return null;
    }
  }

  console.log("AAAA-BBBB-CCCC-DDDD -> " + tryLicence("AAAA-BBBB-CCCC-DDDD"));
});
```

> **⚠️ Warning**
> Route B must run on a thread attached to the VM, which is why it is inside `Java.perform`. Getting
> the signature wrong here is a segmentation fault, not an exception — `exceptions: 'propagate'` gives
> you a fighting chance of seeing it as a JS error instead.

Write a loop that brute-forces the last four characters using Route A, and time it. Then reason about
what makes this a *client-side* weakness rather than a cryptographic one.

### Step 6 — Stalker coverage: find the deciding block

This is the technique worth learning.

```javascript
// coverage.js
// Collect the set of basic blocks executed inside libsigner.so during ONE call
// to verify(). Run it twice with different inputs and diff the sets.
'use strict';

var mod = Process.findModuleByName("libsigner.so");
if (mod === null) throw new Error("libsigner.so not loaded yet — spawn with -f");

var lo = mod.base;
var hi = mod.base.add(mod.size);
var blocks = new Set();
var following = false;

// Exclude the noise. Without this, Stalker instruments libc and libart too and
// the app becomes unusable.
["libc.so", "libart.so", "libandroid_runtime.so", "libm.so", "libcrypto.so"]
  .forEach(function (n) {
    var m = Process.findModuleByName(n);
    if (m !== null) Stalker.exclude(m);
  });

Java.perform(function () {
  var Signer = Java.use("com.fridalab.nativelab.Signer");

  Signer.verify.implementation = function (licence) {
    var tid = Process.getCurrentThreadId();
    blocks.clear();

    Stalker.follow(tid, {
      events: { compile: true },      // once per basic block, first execution
      onReceive: function (events) {
        Stalker.parse(events).forEach(function (e) {
          if (e[0] !== 'compile') return;
          var start = e[1];
          if (start.compare(lo) >= 0 && start.compare(hi) < 0) {
            blocks.add(start.sub(lo).toString(16));
          }
        });
      }
    });

    var result = this.verify(licence);

    Stalker.unfollow(tid);
    Stalker.flush();

    console.log("[cov] verify(\"" + licence + "\") = " + result +
                "  blocks=" + blocks.size);
    console.log("      " + Array.from(blocks).sort().join(" "));
    send({ kind: "coverage", input: licence, result: result,
           blocks: Array.from(blocks) });

    return result;
  };
});

Stalker.trustThreshold = 0;   // re-instrument every time so `compile` fires again
```

```bash
# host
frida -U -f com.fridalab.nativelab -l coverage.js --no-pause
```

Now, in the app, try several licences and record the block sets:

| Input | Result | Blocks (offsets) |
|---|---|---|
| `A` | invalid | |
| `AAAA-BBBB-CCCC-DDDD` | invalid | |
| `AAAAABBBBCCCCDDDDDD` (19 chars, no dashes) | invalid | |

Diff the sets. The offsets that appear when the length is 19 but not when it is 1 correspond to
`block A`. The offsets that appear only when the dashes are in the right places correspond to blocks
B–D. And the block that appears only when the hash matches is `block E` — the real check.

**Take the offset of block E and note it down.** That single number is what you would open in Ghidra,
and it took you no disassembly to find.

### Step 7 — From coverage to a patch

Having found the deciding block, prove you understand it by neutralising it two different ways:

```javascript
// Way 1 — replace the whole native function
var verifyAddr = Process.findModuleByName("libsigner.so").base.add(0x3f10);
var KEEP = [];
var cb = new NativeCallback(function (env, thiz, jstr) {
  console.log("[replace] verify -> always true");
  return 1;
}, 'uint8', ['pointer', 'pointer', 'pointer']);
KEEP.push(cb);
Interceptor.replace(verifyAddr, cb);
```

```javascript
// Way 2 — leave the function alone and change only the return value
Interceptor.attach(verifyAddr, {
  onLeave: function (retval) {
    console.log("[attach] verify real=" + retval.toInt32() + " -> 1");
    retval.replace(ptr(1));
  }
});
```

Explain, in one paragraph, when you would prefer each. (Hint: what if the function has an important
side effect? What if the app hashes its own `.text`?)

---

## Hints

<details>
<summary>Hint — `nat.table()` prints nothing</summary>

`RegisterNatives` fires during `System.loadLibrary`, which runs in `Signer`'s static initialiser —
which runs the first time `Signer` is touched, inside `MainActivity.onCreate`. That is *after* your
script loads, so it should be caught. If nothing prints:

1. Confirm you used `-f`, not `-n`.
2. Confirm the RegisterNatives symbol resolved — the script prints which candidate matched.
3. Try `nat.onload("libsigner.so")` to at least see `JNI_OnLoad` run.
</details>

<details>
<summary>Hint — Stalker produces no `compile` events on the second call</summary>

`compile` fires once per block *per instrumentation*. Set `Stalker.trustThreshold = 0` so blocks are
re-instrumented on every execution, or `unfollow` and `garbageCollect` between runs.
</details>

<details>
<summary>Hint — the app hangs when Stalker is following</summary>

You are almost certainly following the main thread while `console.log`-ing from `onReceive` on a hot
path. Follow only during the `verify` call (as the script above does), exclude `libc`/`libart`, and
accumulate into a `Set` rather than logging per event.
</details>

<details>
<summary>Hint — `NativeFunction` call segfaults</summary>

Check three things: the type strings match the C signature exactly (`jboolean` is `uint8`, not `int`);
you are inside `Java.perform` so the thread is attached; and you passed `env.handle` and `.$h`
handles, not the JavaScript wrapper objects.
</details>

---

## Success criteria

- [ ] You confirmed with `nm`/`readelf` that no `Java_*` symbols exist.
- [ ] You recovered all three JNI registrations with their `module+offset` values.
- [ ] You hooked a recovered function and correctly identified `args[0]`, `args[1]` and `args[2]`.
- [ ] You recovered the 32-byte HMAC key, or documented why the static-linking case blocked you and
      what you would do instead.
- [ ] You called `verify` as an oracle by both routes and can explain why Route B needs `Java.perform`.
- [ ] You collected block coverage for at least three inputs and identified the deciding block's offset.
- [ ] You neutralised the check with both `replace` and `attach`, and can argue for each.
- [ ] You can explain why coverage diffing found in minutes what reading the disassembly would have
      taken an hour to find.

---

## Going further

1. Export the coverage sets in `drcov` format and load them into Ghidra or Lighthouse to visualise
   which functions ran.
2. Write a `transform` callback that logs every `cmp`/`subs` inside the `verify` range with its
   register values, and read off the comparison constants directly.
3. Set `Stalker.trustThreshold = -1` and measure the speed difference. Explain the trade-off.
4. Modify the library to verify its own `.text` hash at startup, confirm that `Interceptor.attach`
   trips it, and confirm that Stalker does not.

---

## Cleanup

```bash
adb shell am force-stop com.fridalab.nativelab
adb uninstall com.fridalab.nativelab
```
