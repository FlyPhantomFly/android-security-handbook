# Lab 01 — First Contact With a `.so`

**Difficulty:** Beginner
**Time:** 90–120 minutes
**Prerequisites:** [Chapter 57 §1–§3.7](../README.md#1-introduction),
[15-Native-Code](../../15-Native-Code/README.md), [16-JNI](../../16-JNI/README.md)

> **Provenance.** Ghidra **is** installed on the machine this chapter was written on (12.1.2 PUBLIC,
> Java 24.0.2) and was run headless against the chapter's own target, so the tool behaviour this lab
> relies on is **Measured**. Any decompiler listing quoted below as an *expected result* is
> **Illustrative** — it shows the shape to look for, not a capture from a specific binary, and
> your addresses and variable names will differ. Build the real target with
> [`../examples/build.sh`](../examples/build.sh) and check your findings against its source. See
> [the chapter's provenance statement](../README.md#read-this-before-you-read-anything-else-what-is-measured-here-and-what-is-not).

---

## Objective

Take a native library you have never seen, and in under two hours:

1. Triage it on the command line **before** opening any GUI, and be able to say what you know.
2. Import it into Ghidra with the correct processor and confirm the import worked.
3. Navigate by exports, strings and cross-references rather than by scrolling.
4. Read one `Java_*` function end to end, and say what it does in one sentence.
5. Record what you learned **in the project**, by renaming and commenting.

The habit this lab builds is the ordering. Most people open the GUI first and are immediately lost.
Two minutes of `readelf` tells you what kind of problem you have.

---

## Setup

### Ghidra

```bash
# host — check the JDK requirement of the release you downloaded first
java -version
unzip ghidra_11.x_PUBLIC_*.zip -d /opt
/opt/ghidra_11.x_PUBLIC/ghidraRun
```

```properties
# /opt/ghidra_11.x_PUBLIC/support/launch.properties
# Android libraries are large. The default heap will thrash.
VMARGS=-Xmx8G
```

### Command-line tools

```bash
# host — Debian/Ubuntu
sudo apt install binutils file unzip xxd
# macOS
brew install binutils
```

### The JNI type archive — do this now, not later

Download `jni_all.gdt` from the JNIAnalyzer project
(<https://github.com/Ayrx/JNIAnalyzer>) and keep it somewhere permanent. You will import it into every
Android project you ever create, and doing it now removes the single biggest obstacle to readable
output.

---

## The target library

Build it yourself. The whole point of the first lab is that you know the answer, so you can check
whether the tool told you the truth.

### `native-lib.cpp`

```cpp
// Build with the NDK for arm64-v8a. See the CMakeLists.txt below.
//
// Deliberately mixed: some functions are statically registered (exported
// Java_* symbols), and the library is stripped, so internal helpers appear
// only as FUN_...
#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>

#define TAG "LAB01"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

// An internal helper. `static`, so it is not exported, and stripped, so it has
// no name in the symbol table. This is what a FUN_... is.
static unsigned int mix(const char *s, size_t n) {
    unsigned int acc = 0x1337;
    for (size_t i = 0; i < n; i++) {
        acc = (acc * 31u) ^ (unsigned int)(unsigned char)s[i];
    }
    return acc;
}

// A string the analyst will find with `strings` and follow by cross-reference.
static const char *kEndpoint = "https://api.lab01.example/v1/verify";

extern "C" JNIEXPORT jstring JNICALL
Java_com_ghidralab_first_Native_getEndpoint(JNIEnv *env, jobject thiz) {
    return env->NewStringUTF(kEndpoint);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_ghidralab_first_Native_hashOf(JNIEnv *env, jobject thiz, jstring input) {
    const char *s = env->GetStringUTFChars(input, nullptr);
    if (s == nullptr) return 0;
    unsigned int h = mix(s, strlen(s));
    env->ReleaseStringUTFChars(input, s);
    LOGI("hashOf -> 0x%08x", h);
    return (jint) h;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_ghidralab_first_Native_checkLicence(JNIEnv *env, jobject thiz,
                                             jstring licence) {
    const char *s = env->GetStringUTFChars(licence, nullptr);
    if (s == nullptr) return JNI_FALSE;

    // Three separate conditions, so the control-flow graph has something to show.
    int score = 0;
    size_t n = strlen(s);
    if (n == 16)                       score++;
    if (n > 0 && s[0] == 'L')          score++;
    if (mix(s, n) == 0x4C3B0A21u)      score += 2;

    env->ReleaseStringUTFChars(licence, s);
    return score >= 4 ? JNI_TRUE : JNI_FALSE;
}

// An overloaded native method: note the mangled symbol name this produces.
extern "C" JNIEXPORT jint JNICALL
Java_com_ghidralab_first_Native_hashOf__Ljava_lang_String_2I(
        JNIEnv *env, jobject thiz, jstring input, jint seed) {
    const char *s = env->GetStringUTFChars(input, nullptr);
    if (s == nullptr) return 0;
    unsigned int acc = (unsigned int) seed;
    for (size_t i = 0; i < strlen(s); i++) {
        acc = (acc * 31u) ^ (unsigned int)(unsigned char)s[i];
    }
    env->ReleaseStringUTFChars(input, s);
    return (jint) acc;
}
```

### `CMakeLists.txt`

```cmake
cmake_minimum_required(VERSION 3.22)
project(lab01)

add_library(lab01 SHARED native-lib.cpp)

find_library(log-lib log)
target_link_libraries(lab01 ${log-lib})

# Strip symbols, as a release build would. This is what makes internal helpers
# appear as FUN_... and is the normal state of anything you will be given.
set_target_properties(lab01 PROPERTIES LINK_FLAGS "-Wl,--strip-all")
```

### The Java side

```java
package com.ghidralab.first;

public class Native {
    static { System.loadLibrary("lab01"); }

    public native String getEndpoint();
    public native int hashOf(String input);
    public native int hashOf(String input, int seed);
    public native boolean checkLicence(String licence);
}
```

```bash
# host
./gradlew assembleRelease
unzip -o -d raw app/build/outputs/apk/release/app-release.apk 'lib/*'
ls -l raw/lib/*/
```

---

## Steps

### Step 1 — Triage before you open anything

Run each of these and **write down what each one told you**. That written list is the deliverable of
this step.

```bash
# host
SO=raw/lib/arm64-v8a/liblab01.so

file "$SO"
readelf -h "$SO"                                   # class, machine, type, entry
readelf -d "$SO" | grep NEEDED                     # what it links against
readelf -S "$SO" | grep -E 'symtab|init_array|text|rodata'
readelf --dyn-syms "$SO" | grep ' Java_'           # static JNI entry points
readelf --dyn-syms "$SO" | grep 'JNI_OnLoad'       # dynamic registration?
readelf --dyn-syms "$SO" | grep ' UND ' | awk '{print $8}' | sort -u
strings -a -n 6 "$SO" | head -40
sha256sum "$SO"
```

Or, all at once:

```bash
# host
../scripts/so-triage.sh app/build/outputs/apk/release/app-release.apk
cat so-triage-out/inventory.csv
```

**Questions to answer before proceeding:**

| Question | Your answer |
|---|---|
| Is it 32- or 64-bit, and which architecture? | |
| Is it stripped? How do you know? | |
| How many `Java_*` exports are there? | |
| Is `JNI_OnLoad` present? What does its presence or absence tell you? | |
| Which of the imported functions are interesting, and why? | |
| Which strings are worth following? | |

one of the exports has a strange name with a `__` in it. Decode it before you move on. What
Java method does `Java_com_ghidralab_first_Native_hashOf__Ljava_lang_String_2I` correspond to, and why
does that one need the suffix when `..._hashOf` does not?

### Step 2 — Import into Ghidra

1. *File → New Project… → Non-Shared Project*, name it `Lab01`.
2. *File → Import File…*, select `liblab01.so`.
3. In the import dialog, confirm:
   - **Format:** `Executable and Linking Format (ELF)`
   - **Language:** `AARCH64:LE:64:v8A`
   - **Destination folder:** the project root
4. Click *Options…* and note the **Image Base**. Leave it at Ghidra's default. Write the value down —
   you will need it in Lab 04.
5. Import, then double-click to open in the CodeBrowser. Say **Yes** to analysis.
6. In the analysis options, confirm these are ticked: *Decompiler Parameter ID*, *Demangler GNU*,
   *Non-Returning Functions*. Leave *Aggressive Instruction Finder* **off** for now.

**Verify the import worked before you do anything else.** Go to any `Java_*` export and look at the
first few instructions in the Listing pane. On ARM64 a function prologue looks something like:

```
stp   x29, x30, [sp, #-0x20]!
mov   x29, sp
str   x19, [sp, #0x10]
```

If instead you see a jumble of unrelated operations on nonsensical registers, the processor or base is
wrong. Stop and re-import. Debugging the decompiler when the disassembly is wrong is an hour wasted.

### Step 3 — Import the JNI types

1. In the **Data Type Manager** pane (bottom left), click the small down-arrow menu.
2. *Open File Archive…* and select `jni_all.gdt`.
3. Expand it and confirm you can see `JNIEnv`, `JNINativeInterface`, `jstring`, `jobject`,
   `JNINativeMethod`.

Do this in every Android project, always, before reading a single function.

### Step 4 — Navigate by exports

Open **Symbol Tree** (left pane) → **Exports**. You should see the four `Java_*` functions.

Click `Java_com_ghidralab_first_Native_getEndpoint`. Look at the Decompiler pane (`Ctrl+E` if it is
not open).

**Before typing anything, copy the decompilation into your notes.** You will compare it in a moment.
It should look roughly like:

```c
undefined8 Java_com_ghidralab_first_Native_getEndpoint(long param_1)
{
  undefined8 uVar1;
  uVar1 = (**(code **)(*(long *)param_1 + 0x538))(param_1, &DAT_00102010);
  return uVar1;
}
```

### Step 5 — Set the signature and watch the output change

Right-click the function name in the Decompiler → *Edit Function Signature* (or press `F`), and enter:

```c
jstring Java_com_ghidralab_first_Native_getEndpoint(JNIEnv *env, jobject thiz)
```

The decompilation re-runs immediately. It should now read:

```c
jstring Java_com_ghidralab_first_Native_getEndpoint(JNIEnv *env, jobject thiz)
{
  jstring jVar1;
  jVar1 = (*env)->NewStringUTF(env, "https://api.lab01.example/v1/verify");
  return jVar1;
}
```

**Write down what changed and why.** Nothing about the binary was modified. The offset `0x538` was
always `NewStringUTF`; Ghidra did not know that `param_1` was a `JNIEnv *`. That single fact is
the whole of §3.8.

### Step 6 — Read a real function

Set the signature on `Java_com_ghidralab_first_Native_checkLicence`:

```c
jboolean Java_com_ghidralab_first_Native_checkLicence(JNIEnv *env, jobject thiz, jstring licence)
```

Now read it. Work through these in order:

1. Which JNI functions does it call, and in what order? (`GetStringUTFChars` then something then
   `ReleaseStringUTFChars` is the shape of "read a Java string, do work, clean up".)
2. There is a call to an unnamed `FUN_...`. What is it? Double-click to follow it. Read it. It is a
   loop over the string doing `acc = acc * 31 ^ c`. **Rename it** (`L`) to `mix` and give it a
   signature: `uint mix(char *s, size_t n)`.
3. Go back (`Alt+←`). Notice that `checkLicence` is now readable because its callee has a name. That
   is the compounding effect: every name you assign makes the callers easier.
4. What are the three conditions? What constant is the hash compared against?
5. What is the minimum score required, and can you satisfy it without the hash condition?

**Write the answer in one sentence**, of the form: "`checkLicence` returns true only when …".

### Step 7 — Follow a string

*Search → For Strings…* → *Search*. Find `https://api.lab01.example/v1/verify`.

Click it in the results, then press `Ctrl+Shift+F` (references to). Ghidra shows you the exact
instruction that loads its address, and therefore the function that uses it.

This is the fundamental navigation technique in a stripped binary: you do not know function names, but
you do know what the code *talks about*. Strings are the index.

Try it with the format string `"hashOf -> 0x%08x"`.it leads you to
`Java_..._hashOf`, and that the format string itself tells you the return type is being printed as a
32-bit hex value. Debug logging left in native code is a narrated walkthrough of the algorithm — a
point worth remembering when you read §11's developer mistakes.

### Step 8 — Record what you learned

Do all of these before finishing:

- Rename every `FUN_...` you understood.
- Set the signature on all four `Java_*` functions.
- Add a plate comment (`Ctrl+;`) on `checkLicence` recording the three conditions and the magic
  constant.
- Add an EOL comment (`;`) on the comparison instruction saying what it is comparing.

Then close and reopen the project. Everything you recorded is still there; everything you only *knew*
is gone. That difference is the point of the step.

---

## Hints

<details>
<summary>Hint — the disassembly at an export looks like nonsense</summary>

Wrong language selection. Re-import and check: `AARCH64:LE:64:v8A` for `arm64-v8a`,
`ARM:LE:32:v8` for `armeabi-v7a`. On 32-bit ARM there is an additional trap: a Thumb function
disassembled as ARM produces plausible-looking but entirely wrong instructions.
</details>

<details>
<summary>Hint — I do not have jni_all.gdt</summary>

Route 2 works: *File → Parse C Source…*, create a profile, add
`$ANDROID_NDK/toolchains/llvm/prebuilt/<host>/sysroot/usr/include/jni.h`, add the sysroot include
path, and parse to a new archive. Expect to add a few `-D` definitions before the preprocessor is
happy. Save the result as your own `.gdt` so you never repeat it.

Route 3 also works and is instructive once: define a struct with pointer fields at the offsets you
actually meet (`0x538` `NewStringUTF`, `0x548` `GetStringUTFChars`, `0x550`
`ReleaseStringUTFChars`) and typedef `JNIEnv` as a pointer to it.
</details>

<details>
<summary>Hint — Edit Function Signature rejects `jstring`</summary>

The type is not in your Data Type Manager. Either import `jni_all.gdt` (Step 3), or use the
underlying types for now: `jstring` is a pointer, so `void *` works and loses only the label.
</details>

<details>
<summary>Hint — the mangled overload name</summary>

`Java_com_ghidralab_first_Native_hashOf__Ljava_lang_String_2I` decodes as:
`Java_` + `com_ghidralab_first_Native` (dots → underscores) + `_hashOf` + `__` + the encoded argument
signature. In the signature, `_2` is `;` and `_3` would be `[`. So the arguments are
`Ljava/lang/String;` and `I` — that is, `hashOf(String, int)`.

The suffix appears only when the Java method is **overloaded**, because otherwise the plain name would
be ambiguous. See §3.9.
</details>

---

## Success criteria

- [ ] You completed the triage table in Step 1 and can state what each command told you.
- [ ] You can explain what "stripped" means and how you checked.
- [ ] You decoded the mangled overload symbol and can say why the suffix exists.
- [ ] You verified the import by reading a function prologue in the disassembly.
- [ ] You imported `jni_all.gdt` and can find `JNIEnv` in the Data Type Manager.
- [ ] You recorded the before/after decompilation of `getEndpoint` and can explain the difference
      without the word "somehow".
- [ ] You can state in one sentence what `checkLicence` returns true for.
- [ ] You renamed `mix`, set its signature, and observed the caller become more readable.
- [ ] You used *references to* on a string to find its user.
- [ ] Your project contains renames and comments that survive a close and reopen.

---

## Going further

1. Import the `armeabi-v7a` build of the same library into the same project. Compare the two
   decompilations of `checkLicence`. Which is easier to read, and why?
2. Rebuild **without** `-Wl,--strip-all` and import that. Note how much you get for free, and reflect
   on it as a developer mistake.
3. Find an input for which `checkLicence` returns true. You know the hash function and the target
   constant, so this is arithmetic, not brute force.
4. Run `../scripts/FindJNI.py` headlessly over the library and compare its output with what you found
   by hand.

---

## Cleanup

Keep the Ghidra project. It is the input to [Lab 03](lab-03-jnienv-retyping.md).
