# Lab 02 — Recovering a Dynamic JNI Registration Table

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-first-contact-so.md),
[Chapter 57 §3.8–§3.9](../README.md#38-the-jnienv-problem-and-how-to-solve-it),
[16-JNI](../../16-JNI/README.md), a rooted device or emulator for the runtime half

> **Provenance.** Ghidra **is** installed on the machine this chapter was written on (12.1.2 PUBLIC,
> Java 24.0.2) and was run headless against the chapter's own target, so the tool behaviour this lab
> relies on is **✅ Measured**. Any decompiler listing quoted below as an *expected result* is
> **📘 Illustrative** — it shows the shape to look for, not a capture from a specific binary, and
> your addresses and variable names will differ. Build the real target with
> [`../examples/build.sh`](../examples/build.sh) and check your findings against its source. See
> [the chapter's provenance statement](../README.md#-read-this-before-you-read-anything-else-what-is-measured-here-and-what-is-not).

---

## Objective

You are given a library where `nm -D` shows no `Java_*` symbols at all, yet the Java code clearly
declares `native` methods. Recover the mapping — which Java method corresponds to which address —
three independent ways:

1. **Statically, structurally.** Scan read-only data for `JNINativeMethod`-shaped pointer triples.
2. **Statically, by reading `JNI_OnLoad`.** Define `JNIEnv`, find the `RegisterNatives` call, follow
   its third argument.
3. **Dynamically.** Hook `RegisterNatives` in the live process and read the table it receives.

Then reconcile the three. They should agree; when they do not, understanding why is the lesson.

---

## Why this matters

Static registration is a convention: name the symbol `Java_com_example_C_m` and ART finds it.
Dynamic registration is a call: `JNI_OnLoad` hands ART a table at runtime. The second is chosen
*specifically* because it defeats the first thing every analyst does, which is
`readelf --dyn-syms | grep Java_`.

It is extremely common. If you cannot recover a dynamic table, a large fraction of real Android
native code is opaque to you.

---

## The target library

### `hidden.cpp`

```cpp
// Build for arm64-v8a with the NDK. Stripped, and every implementation is
// `static`, so nothing useful appears in the dynamic symbol table.
#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>

#define TAG "LAB02"

// ---- the implementations -------------------------------------------------
// All static: not exported, no symbol, and after stripping they are FUN_...

static jstring impl_version(JNIEnv *env, jobject thiz) {
    return env->NewStringUTF("engine-2.4.1");
}

static jbyteArray impl_transform(JNIEnv *env, jobject thiz, jbyteArray in) {
    jsize n = env->GetArrayLength(in);
    jbyte *buf = env->GetByteArrayElements(in, nullptr);
    if (buf == nullptr) return nullptr;

    jbyte *out = (jbyte *) malloc((size_t) n);
    for (jsize i = 0; i < n; i++) {
        out[i] = (jbyte) (buf[i] ^ (0x5A + (i & 0x0f)));
    }
    env->ReleaseByteArrayElements(in, buf, JNI_ABORT);

    jbyteArray result = env->NewByteArray(n);
    env->SetByteArrayRegion(result, 0, n, out);
    free(out);
    return result;
}

static jboolean impl_authorise(JNIEnv *env, jobject thiz, jstring token) {
    const char *s = env->GetStringUTFChars(token, nullptr);
    if (s == nullptr) return JNI_FALSE;

    unsigned int acc = 0x2B1F;
    for (size_t i = 0; i < strlen(s); i++) {
        acc = (acc * 33u) + (unsigned int)(unsigned char) s[i];
    }
    env->ReleaseStringUTFChars(token, s);

    __android_log_print(ANDROID_LOG_INFO, TAG, "authorise acc=0x%08x", acc);
    return (acc == 0x6F1A22C3u) ? JNI_TRUE : JNI_FALSE;
}

static jint impl_configure(JNIEnv *env, jobject thiz, jint flags) {
    return flags | 0x40;
}

// ---- the registration table ----------------------------------------------
//
// This array lives in .data.rel.ro: three pointers per entry, the first two
// into .rodata (the name and signature strings), the third into .text.
// That shape is what makes it findable structurally.

static JNINativeMethod kMethods[] = {
    { "version",   "()Ljava/lang/String;", (void *) impl_version   },
    { "transform", "([B)[B",               (void *) impl_transform },
    { "authorise", "(Ljava/lang/String;)Z",(void *) impl_authorise },
    { "configure", "(I)I",                 (void *) impl_configure }
};

extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass c = env->FindClass("com/ghidralab/hidden/Engine");
    if (c == nullptr) return JNI_ERR;

    if (env->RegisterNatives(c, kMethods,
                             sizeof(kMethods) / sizeof(kMethods[0])) != JNI_OK) {
        return JNI_ERR;
    }

    __android_log_print(ANDROID_LOG_INFO, TAG, "registered %zu methods",
                        sizeof(kMethods) / sizeof(kMethods[0]));
    return JNI_VERSION_1_6;
}
```

### `CMakeLists.txt`

```cmake
cmake_minimum_required(VERSION 3.22)
project(hidden)
add_library(hidden SHARED hidden.cpp)
find_library(log-lib log)
target_link_libraries(hidden ${log-lib})
set_target_properties(hidden PROPERTIES LINK_FLAGS "-Wl,--strip-all")
```

### The Java side

```java
package com.ghidralab.hidden;

public class Engine {
    static { System.loadLibrary("hidden"); }

    public native String version();
    public native byte[] transform(byte[] in);
    public native boolean authorise(String token);
    public native int configure(int flags);
}
```

```java
package com.ghidralab.hidden;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.*;

public class MainActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        final Engine e = new Engine();
        final EditText in = new EditText(this);
        in.setHint("token");
        final TextView out = new TextView(this);
        Button go = new Button(this);
        go.setText("Authorise");
        go.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                out.setText(e.version() + " / " +
                            (e.authorise(in.getText().toString()) ? "OK" : "DENIED"));
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

## Steps

### Step 1 — Confirm the diagnosis

Do not assume. Prove it.

```bash
# host
SO=raw/lib/arm64-v8a/libhidden.so

readelf --dyn-syms "$SO" | grep ' Java_'         # expect: nothing
readelf --dyn-syms "$SO" | grep 'JNI_OnLoad'     # expect: one line
nm -D --defined-only "$SO" | grep ' T '          # what IS exported?
strings -a -n 3 "$SO" | grep -E '^\(|^\[|^\(\)' # JNI signature fragments
```

The last command is a useful tell: the signature strings (`()Ljava/lang/String;`, `([B)[B`) are in
`.rodata` in plain text even though nothing references them by name. Their presence, combined with no
`Java_*` exports, is near-conclusive evidence of a dynamic table.

**Write down the four signature strings you found.** You are going to match them against addresses.

### Step 2 — Route A: structural recovery

Import `libhidden.so` into Ghidra as in Lab 01 (`AARCH64:LE:64:v8A`), let analysis finish, and import
`jni_all.gdt`.

Now run the script:

```bash
# host — headless, so you can see it work end to end
$GHIDRA_HOME/support/analyzeHeadless /tmp/lab02proj Lab02 \
    -import raw/lib/arm64-v8a/libhidden.so \
    -processor AARCH64:LE:64:v8A \
    -scriptPath "$(pwd)/../scripts" \
    -postScript RecoverRegisterNatives.py \
    -deleteProject
```

Or in the GUI: *Window → Script Manager*, add `../scripts` to the script directories, run
`RecoverRegisterNatives.py`.

Expected output shape:

```
PASS A - structural scan for JNINativeMethod arrays
  scanning .data.rel.ro   00102000 - 001020ff (256 bytes)

  [+] candidate table at 00102040 with 4 entries
      version    ()Ljava/lang/String;    -> 00101a10  FUN_00101a10
      transform  ([B)[B                  -> 00101a60  FUN_00101a60
      authorise  (Ljava/lang/String;)Z   -> 00101b20  FUN_00101b20
      configure  (I)I                    -> 00101bd0  FUN_00101bd0
```

**Understand why this works before moving on.** A `JNINativeMethod` is three consecutive pointers.
The first two must point into readable, non-executable memory and must be printable ASCII; the second
must additionally match a JNI signature grammar; and the third must point into an executable section.
Those constraints together are strong enough that false positives are rare. Read the `looks_like_entry`
function in the script and confirm you can explain each check.

### Step 3 — Route B: read `JNI_OnLoad` yourself

Do this by hand even though the script did it. The manual route is what you will need when the script
fails.

1. Go to `JNI_OnLoad` (Symbol Tree → Exports, or `G` and type the name).
2. Read the decompilation **before** typing anything. You will see something like:

```c
undefined8 JNI_OnLoad(long *param_1, undefined8 param_2)
{
  int iVar1;
  long lVar2;
  undefined8 uVar3;

  iVar1 = (**(code **)(*param_1 + 0x30))(param_1, &local_18, 0x10006);
  if (iVar1 != 0) return 0xffffffff;
  lVar2 = (**(code **)(*local_18 + 0x30))(local_18, "com/ghidralab/hidden/Engine");
  ...
  iVar1 = (**(code **)(*local_18 + 0x6b8))(local_18, lVar2, &DAT_00102040, 4);
  ...
}
```

3. **Find `0x6b8`.** That is `RegisterNatives` on a 64-bit target — index 215 × 8 bytes. Note the four
   arguments: the env, the class, `&DAT_00102040`, and the count `4`.
4. Note `0x30` appearing twice with different receivers. The first is `JavaVM->GetEnv`; the second is
   `JNIEnv->FindClass`. Read the string argument to the second one — it names the Java class, which
   tells you exactly which Java file to open in [JADX](../../56-JADX/README.md).
5. Now set the signature to make it readable:

```c
jint JNI_OnLoad(JavaVM *vm, void *reserved)
```

You will also need to retype the local `JNIEnv *`. Click it, `Ctrl+L`, `JNIEnv *`.

6. Go to `0x00102040` (press `G`). This is the table. Confirm it matches what Route A found.

### Step 4 — Apply the type and make it permanent

Recovering it in the console is temporary. Recording it in the project is not.

1. At `00102040`, check the Data Type Manager for `JNINativeMethod`. If it is not there (some `.gdt`
   builds omit it), define it:
   - Data Type Manager → right-click your program's category → *New → Structure*
   - Name it `JNINativeMethod`, and add three fields of type `char *`, `char *`, `void *`.
2. Click at `00102040`, press `T`, and choose `JNINativeMethod`.
3. Select the whole table (four entries × 24 bytes = 96 bytes) and press `[` to create an array — or
   *Data → Create Array*, count 4.

The Listing pane now renders the table as structured data with the strings resolved. That is what you
want in a project someone else will open.

4. **Rename each target function.** Go to each `fnPtr` address and press `L`:
   `FUN_00101b20` → `jni_authorise`, and so on.
5. **Set signatures.** For `jni_authorise`:

```c
jboolean jni_authorise(JNIEnv *env, jobject thiz, jstring token)
```

6. Read `jni_authorise`. What constant is the accumulator compared against? What is the hash function?

### Step 5 — Route C: recover it at runtime

Now prove the static work was right, using a completely independent method.

```bash
# host
adb shell cmd package compile -m verify -f com.ghidralab.hidden
adb shell am force-stop com.ghidralab.hidden

# MUST spawn: RegisterNatives fires inside System.loadLibrary, which runs in
# Engine's static initialiser.
frida -U -f com.ghidralab.hidden \
      -l ../../53-Frida/scripts/native-tracer.js --no-pause
```

```javascript
// in the REPL, after the app has constructed an Engine
nat.table()
```

Expected:

```
[*] Recovered JNI registrations (4):
  [0] com.ghidralab.hidden.Engine.version()Ljava/lang/String;
       libhidden.so+0x1a10   0x7b2c101a10
  [1] com.ghidralab.hidden.Engine.transform([B)[B
       libhidden.so+0x1a60   0x7b2c101a60
  ...
```

### Step 6 — Reconcile the three routes

Fill in this table:

| Java method | Route A offset | Route B offset | Route C `module+offset` | Agree? |
|---|---|---|---|---|
| `version` | | | | |
| `transform` | | | | |
| `authorise` | | | | |
| `configure` | | | | |

They should agree. If Route C's offsets differ from A and B, check your arithmetic: Ghidra's addresses
include the image base (typically `0x100000`), while Frida reports offsets from the module base. So:

```
ghidra_address = image_base + frida_offset
0x00101a10     = 0x100000   + 0x1a10
```

**This arithmetic is the single most important thing in this lab.** Write it out explicitly.

### Step 7 — Use what you recovered

Set a signature on `jni_authorise` and read it. Then confirm your reading dynamically:

```javascript
// Frida REPL — hook the function you found statically, using its offset
const m = Process.findModuleByName("libhidden.so");
Interceptor.attach(m.base.add(0x1b20), {     // ← your offset
  onEnter(args) {
    // JNI convention: args[0]=JNIEnv*, args[1]=jobject, args[2]=jstring token
    console.log("[authorise] token jstring=" + args[2]);
  },
  onLeave(retval) {
    console.log("[authorise] -> " + retval.toInt32());
  }
});
```

Type a token in the app and confirm the hook fires. That closes the loop: a function with no name, no
symbol, and no static reference from Java is now something you can watch.

Finally, find a token that returns true. You know the hash (`acc = acc*33 + c`, starting `0x2B1F`) and
the target (`0x6F1A22C3`). This is arithmetic, not brute force.

---

## The harder variant

Modify `hidden.cpp` so the table is built at runtime rather than being a static array:

```cpp
extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;

    // Names are XOR-obfuscated in .rodata and decoded on the stack, so no
    // plaintext signature strings exist for a structural scan to find.
    char name[16], sig[32];
    static const char enc_name[] = { 0x1e,0x4a,0x59,0x5c,0x58,0x4f,0x4d,0x4a,0x00 };
    for (int i = 0; enc_name[i]; i++) name[i] = enc_name[i] ^ 0x2B;
    name[8] = 0;
    strcpy(sig, "(Ljava/lang/String;)Z");

    JNINativeMethod m[1];
    m[0].name = name;
    m[0].signature = sig;
    m[0].fnPtr = (void *) impl_authorise;

    jclass c = env->FindClass("com/ghidralab/hidden/Engine");
    env->RegisterNatives(c, m, 1);
    return JNI_VERSION_1_6;
}
```

Rebuild and repeat. Route A now finds nothing — the table exists only on the stack at runtime.
Route B still works if you can read the decompilation. Route C works unchanged.

**Write one paragraph** explaining why Route C is immune to this, and what that tells you about the
relationship between static and dynamic analysis.

---

## Hints

<details>
<summary>Hint — RecoverRegisterNatives.py finds nothing</summary>

Check three things. Is the table in a section the script scans (initialised, readable,
non-executable)? Some toolchains put it in `.data` rather than `.data.rel.ro`. Is the pointer size
right (`Process.arch` versus the imported language)? And is it the runtime-built variant, in which
case there is nothing to find and that is the correct answer.

Run it with `dryrun` as an argument first if you do not want it renaming things.
</details>

<details>
<summary>Hint — I cannot find 0x6b8 in the decompilation</summary>

Three possibilities. `JNIEnv` may already be defined, in which case Ghidra printed `RegisterNatives`
by name and there is no `0x6b8` to find — search for the name instead. The offset may have been folded
into a register-relative access the text search missed; look at the disassembly rather than the C.
Or `JNI_OnLoad` may tail-call a helper — follow the `b`/`bl` at the end.
</details>

<details>
<summary>Hint — nat.table() is empty</summary>

`RegisterNatives` fires during `System.loadLibrary`, which runs in `Engine`'s static initialiser — the
first time `Engine` is touched, inside `MainActivity.onCreate`. Confirm you used `-f` and not `-n`
(see [53-Frida §7.4.4](../../53-Frida/README.md#744-failure-4--attaching-instead-of-spawning)), and
that the Activity has actually started.

If the script reports "No RegisterNatives symbol", your ART build does not export the mangled name it
tried. Fall back to `nat.onload("libhidden.so")`.
</details>

<details>
<summary>Hint — Route C offsets do not match Ghidra</summary>

Image base. Ghidra loaded the library at `0x100000` (check *Window → Memory Map*); Frida reports
offsets from the module base. `ghidra_addr = image_base + frida_offset`. If you skipped writing down
the image base in Lab 01, this is why that step existed.
</details>

---

## Success criteria

- [ ] You proved, with `readelf`, that no `Java_*` symbols exist and `JNI_OnLoad` does.
- [ ] You recovered the table structurally and can explain each constraint the scanner applies.
- [ ] You found the `RegisterNatives` call by hand and can say why the offset is `0x6b8`.
- [ ] You applied a `JNINativeMethod` array type and renamed all four target functions in the project.
- [ ] You recovered the same table at runtime with Frida.
- [ ] You filled in the reconciliation table and wrote out the image-base arithmetic explicitly.
- [ ] You hooked one recovered function by offset and saw it fire.
- [ ] You found a token for which `authorise` returns true, by arithmetic.
- [ ] You built the runtime-table variant and can explain why Route C is immune to it.

---

## Cleanup

```bash
adb shell am force-stop com.ghidralab.hidden
adb uninstall com.ghidralab.hidden
```

Keep the Ghidra project — the renamed functions are the input to any further work on this library.
